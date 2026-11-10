//! Daemon-side handlers for `profile/bootstrap` and `profile/login`.
//!
//! Both methods are streaming: the daemon sends `notifications/progress` lines before the
//! final response so the client can display device-code info, prompt for account/role
//! selection, and handle MFA without knowing which provider is in use.
//!
//! Streaming infrastructure:
//!
//! - `notif_tx`: an `mpsc::Sender<Vec<u8>>` that routes encoded notification and response
//!   bytes through a single ordered writer task in `serve_connection`.
//! - `respond_slot`: an `Arc<Mutex<Option<oneshot::Sender<String>>>>` the handler installs
//!   a sender into when it needs a client selection (account id, role name, MFA code).
//!   `serve_connection` takes the sender out and delivers the selection when a
//!   `profile/bootstrap/respond` notification arrives from the client.
//!
//! Auto-provisioning: a first-time bootstrap caller has no `callers/<uid>/owner` yet.
//! `authorize_for_bootstrap` detects `Denied(NoRoot)` and provisions the caller root
//! before proceeding, since the daemon owns `callers/` and is the sole writer.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use crate::server::dispatch::{authorized_uid, replaced_aside_name, Daemon};
use crate::server::integrity::{precheck_for_write, verify_for_write, Verified, BOTH};
use crate::server::presence::Op;
use crate::server::process_tree::ancestry_field;
use crate::server::routes::{CallerAuth, DenyReason, PeerInfo};
use crate::server::write_lock::Held;
use credsd_core::bootstrap::append_env_credential;
use credsd_core::config::credentials::{CredentialSource, CredentialSources};
use credsd_core::config::platform::caller_root;
#[cfg(feature = "jwt-bearer")]
use credsd_core::config::JwtBearerConfig;
use credsd_core::config::{
    AwsLoginConfig, AwsWebIdentityConfig, DaemonConfig, IamUserConfig, IdentityType, OauthConfig,
    OauthGrant, RolesAnywhereConfig, SsoConfig, StaticSecretConfig,
};
use credsd_core::log::escape_log;
use credsd_core::presence::Challenge;
use credsd_core::providers::aws_login::AwsLoginProvider;
use credsd_core::providers::iam_user::SessionTokenProvider;
use credsd_core::providers::oauth::AwsWebIdentityProvider;
use credsd_core::providers::roles_anywhere::persist_ingested;
use credsd_core::providers::sso::SsoProvider;
use credsd_core::providers::{CredentialProvider, Renewed, Renewer};
use credsd_core::rpc::{
    codec, DomainCode, ImportOutcome, ImportParams, ImportResult, ImportStatus, Notification,
    OkResult, ProfileBootstrapParams, ProfileLoginParams, ProgressParams, ProviderParams, Request,
    RpcError, NOTIFICATION_PROGRESS,
};

/// A user's selection delivered via `profile/bootstrap/respond`.
pub type RespondSlot = Arc<Mutex<Option<oneshot::Sender<String>>>>;

// ──────────────────────────────────────────────────────────────────────────────
// Public entry points called from serve_connection
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum number of credentials a single uid may store.
const MAX_CREDENTIALS_PER_UID: usize = 50;

/// How long one step of an interactive flow may take: entering a device code, picking an account
/// or role, typing an MFA code. Bounds both the wait for the client's answer and, through
/// [`LOGIN_LOCK_BUDGET`], how long a login may hold the caller's write lock while doing it — the
/// two must come from one number, or a login could outlive the step it is waiting on and still
/// hold the lock, or be cut off while a step it was told to allow is still legitimately running.
pub(crate) const INTERACTIVE_STEP_LIMIT: Duration = Duration::from_secs(300);

/// A login's claim on the caller's write lock. The hold bound is the interactive step bound: a
/// login is one such step plus local token writes, so a login still running past it is not
/// waiting on a user, and the other writers queued behind it should not keep waiting either.
///
/// The wait bound is short because nothing legitimate holds this lock for long when a login wants
/// it: `claim_login` already caps a uid to one bootstrap or login in flight, and every other
/// holder (config set/unset, remove, approval commit, import, renewal) does local file work.
#[cfg(not(test))]
pub(crate) const LOGIN_LOCK_BUDGET: crate::server::write_lock::Budget =
    crate::server::write_lock::Budget {
        wait: Duration::from_secs(10),
        hold: INTERACTIVE_STEP_LIMIT,
    };
/// Shorter under test so both bounds are reachable without a five-minute test. Same code path.
#[cfg(test)]
pub(crate) const LOGIN_LOCK_BUDGET: crate::server::write_lock::Budget =
    crate::server::write_lock::Budget {
        wait: Duration::from_millis(50),
        hold: Duration::from_millis(250),
    };

/// Refuse bootstrap when the uid has reached the per-uid credential cap.
///
/// Counts subdirectories of `callers/<uid>/credentials/`. A directory that was created
/// for a credential that later failed leaves an empty slot; those count toward the cap
/// rather than being silently excluded, so the cap is always a reliable upper bound on
/// stored-state size.
fn check_credential_quota(uid: u32) -> Result<(), RpcError> {
    let creds_dir = caller_root(uid).join("credentials");
    let count = match std::fs::read_dir(&creds_dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).count(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(RpcError::domain(DomainCode::Internal, e.to_string())),
    };
    if count >= MAX_CREDENTIALS_PER_UID {
        return Err(RpcError::domain(
            DomainCode::ProviderUnavailable,
            format!(
                "credential limit reached ({MAX_CREDENTIALS_PER_UID}); \
                 remove unused credentials before adding new ones"
            ),
        ));
    }
    Ok(())
}

/// Handle `profile/bootstrap`. Streams `notifications/progress` lines via `notif_tx` and
/// awaits user selections through `respond_slot`.
///
/// Auto-provisions `callers/<uid>/owner` when the caller has never bootstrapped before
/// (`Denied(NoRoot)`) — the daemon owns `callers/` and is the sole writer.
pub async fn handle_profile_bootstrap(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
    respond_slot: RespondSlot,
) -> Result<Value, RpcError> {
    let uid = authorize_for_bootstrap(peer)?;
    let params: ProfileBootstrapParams = request.params_as()?;

    let credential = params
        .credential
        .as_deref()
        .unwrap_or(params.environment.as_str())
        .to_string();

    check_credential_quota(uid)?;

    // The built-in gate (presence-gated-operations Requirement 1.7). A first bootstrap writes over
    // nothing and runs ungated; one that would replace an existing credential, or bind a new
    // identity into an existing environment, needs presence. Approval grants a one-use
    // authorization for exactly these params against exactly this state, which this re-send
    // spends. The decision is taken twice: here, so an overwrite is refused before any provider
    // flow runs, and again under the write lock at commit, because the records can change while
    // a flow waits on a person for minutes.
    let digest = params_digest("environment/bootstrap", &params)?;
    let kind = provider_kind(&params.provider);
    let subject = Subject {
        environment: &params.environment,
        credential: &credential,
        kind: &kind,
    };
    // Refused before any provider flow runs, so nobody signs in for a write that drift would stop
    // at commit. Not the authoritative check: that is the commit's, under the write lock.
    let files =
        TomlFiles::read(uid).map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    precheck_for_write(daemon, uid, &files, BOTH)?;
    let admitted = match overwrite_reason(uid, &params.environment, &credential)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?
    {
        None => None,
        Some(reason) => {
            let base = records_base(uid, &[credential.as_str()])?;
            let Some(approved) = daemon.presence.spend(uid, &digest, &base) else {
                let identity_change = identity_type_change(
                    uid,
                    &params.environment,
                    provider_identity_type(&params.provider),
                )?;
                let challenge = bootstrap_challenge(
                    peer,
                    uid,
                    &subject,
                    &reason,
                    Admission {
                        digest,
                        base,
                        identity_change,
                    },
                    daemon,
                );
                let remediation = format!(
                    "sudo creds request approve {id}, then re-run the same bootstrap",
                    id = challenge.id
                );
                return Err(RpcError::approval_required(&challenge, remediation));
            };
            info!(
                event = "presence.spent",
                pending_operation = approved.as_str(),
                environment = %params.environment,
                credential = %credential,
                "presence gate: approved bootstrap authorization spent"
            );
            Some(Admitted {
                pending_operation: approved,
                base,
            })
        }
    };

    // Every provider seals into a private staging directory, invisible to every reader, and the
    // result becomes the credential only at commit. No lock is held across the flow — SSO device
    // auth can take minutes, and holding it would block every other mutation from this uid.
    //
    // `handle_profile_login` cannot use this same staging+install shape: a login's target
    // directory already holds other state a fresh bootstrap doesn't (e.g. SSO client
    // registration, `ra_public.json`), and `Staging::install` replaces the whole directory, so
    // it would discard that state rather than updating one file within it. Login instead holds
    // the uid's bootstrap lock across its own flow — a real cost (see the comment there), kept
    // for now rather than reshaping every provider's persist path to stage-then-install.
    let staging = Staging::create(uid)?;
    let data_dir = staging.path().to_path_buf();
    let staged = match params.provider {
        ProviderParams::AwsIdcSso(sso) => {
            bootstrap_sso(&data_dir, &credential, sso, daemon, notif_tx, respond_slot).await
        }
        ProviderParams::AwsIamUser(iam) => bootstrap_iam_user(&data_dir, iam, daemon),
        ProviderParams::AwsRolesAnywhere(ra) => bootstrap_ra(&data_dir, ra, daemon),
        ProviderParams::AwsWebIdentity(oauth) => {
            bootstrap_aws_web_identity(&data_dir, &credential, oauth, daemon, notif_tx).await
        }
        ProviderParams::AwsLogin(aws) => {
            bootstrap_aws_login(&data_dir, &credential, aws, daemon, notif_tx, respond_slot).await
        }
        ProviderParams::Jwt(jwt) => bootstrap_jwt(&data_dir, jwt, daemon),
        ProviderParams::Oauth(p) => bootstrap_oauth(&data_dir, p, daemon),
        #[cfg(feature = "jwt-bearer")]
        ProviderParams::JwtBearer(p) => bootstrap_jwt_bearer(&data_dir, p, daemon),
        #[cfg(not(feature = "jwt-bearer"))]
        ProviderParams::JwtBearer(_) => Err(RpcError::domain(
            DomainCode::ProviderUnavailable,
            "jwt-bearer is not in this build; rebuild with --features jwt-bearer",
        )),
        ProviderParams::StaticSecret(p) => bootstrap_static_secret(&data_dir, p, daemon),
        ProviderParams::Unknown => Err(RpcError::invalid_params("unknown provider type")),
    }?;

    commit_bootstrap(
        uid,
        peer,
        &subject,
        Gate { digest, admitted },
        staging,
        &staged,
        daemon,
    )
    .await?;
    record_mutation(
        peer,
        uid,
        "environment/bootstrap",
        &params.environment,
        &credential,
    );
    // Invalidate the cached CallerState so the next get reloads config+providers from the
    // freshly written files. Without this the stale registry entry would serve the old
    // env_to_credentials/providers indefinitely, mis-routing requests to wrong credentials.
    daemon.evict_caller(uid);
    // A static secret's declared expiry is the security-relevant fact about it, so it is
    // recorded; nothing caller-supplied (such as `secret_source`) is.
    let expires_at = match &staged.source {
        CredentialSource::StaticSecret(c) => c
            .expires_at
            .map_or_else(|| "never".to_owned(), |at| at.to_rfc3339()),
        _ => "-".to_owned(),
    };
    info!(
        environment = %params.environment,
        credential = %credential,
        provider = kind.as_str(),
        expires_at = expires_at.as_str(),
        "bootstrap complete"
    );
    match staged.source {
        CredentialSource::AwsWebIdentity(config) => {
            confirm_aws_web_identity_federates(
                uid,
                &params.environment,
                &credential,
                config,
                daemon,
            )
            .await
        }
        _ => to_value(OkResult {}),
    }
}

/// Federate a committed `aws-web-identity` credential once and report the outcome.
async fn confirm_aws_web_identity_federates(
    uid: u32,
    environment: &str,
    credential: &str,
    config: AwsWebIdentityConfig,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    // Req 1.5: federate once and report. A token that seals but cannot reach AWS means a wrong
    // `role_arn` or a trust policy that does not accept this issuer — failing here says so while
    // the user still has the command in their scrollback, rather than at the next `creds get`.
    // The token is already sealed either way, which is why the message says to retry login rather
    // than to re-bootstrap.
    let provider = AwsWebIdentityProvider::new(
        credential.to_string(),
        config,
        daemon.encryption.clone(),
        caller_root(uid).join("credentials").join(credential),
    )
    .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    match provider.renew().await {
        Ok(Renewed::Ready(creds)) => {
            info!(
                environment = %environment,
                credential = %credential,
                // Rendered rather than passed as an `Option` so the audit line carries a
                // value a reader can act on; aws-web-identity always federates with a stated expiry.
                expires_at = %creds
                    .expires_at
                    .map_or_else(|| "never".to_owned(), |at| at.to_string()),
                "aws-web-identity bootstrap complete and federated"
            );
            to_value(OkResult {})
        }
        Ok(Renewed::ReauthRequired(_)) => Err(RpcError::domain(
            DomainCode::ReauthRequired,
            format!(
                "credential '{credential}' was saved but its token could not federate to AWS; run login again"
            ),
        )),
        Err(e) => Err(RpcError::domain(
            DomainCode::ProviderUnavailable,
            format!(
                "credential '{credential}' was saved but federating to AWS failed: {}. Check role_arn and the role's trust policy, then run login again",
                e.detail()
            ),
        )),
    }
}

/// What the entry check decided, for the commit to hold the bootstrap to.
pub(crate) struct Gate {
    /// The digest of these params, for a challenge raised at commit.
    pub(crate) digest: [u8; 32],
    /// The approval entry spent, or `None` when the entry check found nothing to overwrite.
    pub(crate) admitted: Option<Admitted>,
}

pub(crate) struct Admitted {
    pub(crate) pending_operation: String,
    /// The base state the approval covered.
    pub(crate) base: [u8; 32],
}

/// The refusal for a spent approval whose records will not read: they cannot be confirmed to
/// still be in the base state it was given against, so it is discarded unperformed.
pub(crate) fn records_unreadable(pending_operation: &str) -> RpcError {
    RpcError::approval_refused(
        credsd_core::presence::RefusalReason::BaseStateChanged,
        format!(
            "{pending_operation}: the records this would change could not be read, so the \
             approval cannot be confirmed to still describe them; discarded unperformed"
        ),
        "check the daemon's data directory, then re-run the original command",
    )
}

/// Make `staged` the credential, under the per-uid write lock, if and only if the gate still
/// covers what it would overwrite. The check runs again here because the records can change
/// while a provider flow waits on a person: a name absent at entry can exist by now, and an
/// approved base state can have moved. In either case nothing staged is kept and a challenge for
/// the state as it now stands is returned.
pub(crate) async fn commit_bootstrap(
    uid: u32,
    peer: &PeerInfo,
    subject: &Subject<'_>,
    gate: Gate,
    staging: Staging,
    staged: &Staged,
    daemon: &Daemon,
) -> Result<(), RpcError> {
    let guard = daemon.write_guard(uid).await;
    let read = TomlFiles::read(uid)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))
        .and_then(|files| {
            // The shared write check (drift-detection Requirement 5.8), under the lock the write
            // below holds, against the bytes it writes from.
            let verified = verify_for_write(daemon, &guard.held(), uid, &files, BOTH)?;
            let gated = match overwrite_reason(uid, subject.environment, subject.credential)
                .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?
            {
                None => None,
                Some(reason) => Some((
                    reason,
                    records_base_of(uid, &files, &[subject.credential])
                        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?,
                )),
            };
            Ok((files, verified, gated))
        });
    let (files, mut verified, gated) = match (read, &gate.admitted) {
        (Ok(read), _) => read,
        (Err(e), None) => return Err(e),
        // Entry already spent the approval, so an unreadable record here is the approve path's
        // case: the approval is discarded with a record, not lost behind an internal error
        // (Requirement 2.6). Drift found here discards it too, and is returned as the drift
        // check's own refusal rather than as an unreadable record, since a re-read is not what
        // the owner has to do next. Each condition keeps its own code, so its remedy survives
        // (drift-detection Requirement 11.2).
        (Err(e), Some(admitted)) => {
            info!(
                event = "presence.discarded",
                pending_operation = admitted.pending_operation.as_str(),
                environment = %subject.environment,
                credential = %subject.credential,
                error = %escape_log(&e),
                outcome = "discarded: the records it would change could not be read or verified",
                "presence gate"
            );
            if matches!(
                e.domain_code(),
                Some(
                    DomainCode::ConfigDrifted
                        | DomainCode::IntegrityUnverifiable
                        | DomainCode::CustodyBroken
                )
            ) {
                return Err(e);
            }
            return Err(records_unreadable(&admitted.pending_operation));
        }
    };
    if let Some((reason, base)) = gated {
        if gate.admitted.as_ref().map(|a| a.base) != Some(base) {
            let identity_change =
                identity_type_change(uid, subject.environment, staged.identity_type)?;
            let challenge = bootstrap_challenge(
                peer,
                uid,
                subject,
                &reason,
                Admission {
                    digest: gate.digest,
                    base,
                    identity_change,
                },
                daemon,
            );
            // The provider flow has already run, so the user signed in for nothing. Say so, or
            // the second sign-in the re-run asks for reads as a bug.
            let remediation = format!(
                "the credential changed while you were signing in, so that sign-in was \
                 discarded. sudo creds request approve {id}, then re-run the same bootstrap and sign in \
                 again",
                id = challenge.id
            );
            return Err(RpcError::approval_required(&challenge, remediation));
        }
    }
    staging
        .install(
            &caller_root(uid)
                .join("credentials")
                .join(subject.credential),
            &daemon.encryption,
        )
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    write_caller_state_locked(
        subject.environment,
        subject.credential,
        staged,
        &files,
        &mut verified,
        &daemon.encryption,
    )?;
    daemon.integrity.write(verified)
}

/// What a provider flow produced: sealed material in staging, and the source entry that will
/// describe it once committed.
pub(crate) struct Staged {
    pub(crate) source: CredentialSource,
    pub(crate) identity_type: Option<IdentityType>,
}

/// A private directory beside the credentials a bootstrap seals into before commit. Its name
/// cannot be a credential name — names may not start with '.' — so no reader resolves it, and it
/// is removed on every path that does not install it.
///
/// Material written here is moved, not re-sealed, into the credential's directory. A record
/// format that binds a sealed record to its location must therefore bind the location the record
/// is sealed *for* — its destination — rather than the path it is first written at; otherwise
/// every installed credential would fail to open.
pub(crate) struct Staging {
    path: std::path::PathBuf,
    installed: bool,
}

impl Staging {
    pub(crate) fn create(uid: u32) -> Result<Self, RpcError> {
        let path = caller_root(uid).join("credentials").join(format!(
            ".staging-{}",
            credsd_core::presence::new_request_id()
        ));
        std::fs::create_dir_all(&path)
            .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
        Ok(Self {
            path,
            installed: false,
        })
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Make the staged material the credential at `target`, replacing what was there. Both
    /// renames are within one directory, so each is atomic; an existing credential is moved aside
    /// first and restored if the second rename fails, so a failure leaves the old one in place.
    /// Replacing the whole directory, not file by file, also drops caches minted under the old
    /// binding.
    fn install(
        mut self,
        target: &std::path::Path,
        enc: &credsd_core::encryption::EncryptionService,
    ) -> std::io::Result<()> {
        // Re-bind each sealed file to its final path's AAD before the directory rename.
        // Files were sealed with the staging path as AAD; after rename the path changes,
        // so open_from_file at the final location would derive a different AAD and fail.
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            let staging_file = entry.path();
            if staging_file.extension().and_then(|e| e.to_str()) == Some("enc") {
                let final_file = target.join(entry.file_name());
                enc.rebind_file(&staging_file, &final_file)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
        }
        if target.exists() {
            let name = target.file_name().unwrap_or_default().to_string_lossy();
            let aside = target.with_file_name(replaced_aside_name(
                &name,
                &credsd_core::presence::new_request_id(),
            ));
            std::fs::rename(target, &aside)?;
            if let Err(e) = std::fs::rename(&self.path, target) {
                // Restore failing too leaves the old credential only under its aside name, so
                // name it: that is what an operator needs to put it back by hand.
                if let Err(restore) = std::fs::rename(&aside, target) {
                    error!(
                        aside = %aside.display(),
                        target = %target.display(),
                        "could not restore the replaced credential after a failed install: {restore}"
                    );
                }
                return Err(e);
            }
            if let Err(e) = std::fs::remove_dir_all(&aside) {
                warn!(dir = %aside.display(), "could not remove replaced credential material: {e}");
            }
        } else {
            std::fs::rename(&self.path, target)?;
        }
        self.installed = true;
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.installed {
            if let Err(e) = std::fs::remove_dir_all(&self.path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(dir = %self.path.display(), "could not remove staged material: {e}");
                }
            }
        }
    }
}

/// The names a bootstrap's challenge is about.
pub(crate) struct Subject<'a> {
    pub(crate) environment: &'a str,
    pub(crate) credential: &'a str,
    /// The provider being bootstrapped, as [`provider_kind`] renders it.
    pub(crate) kind: &'a str,
}

/// What the entry check (or the commit recheck) found, for the challenge it raises.
struct Admission {
    /// The digest of the request params this challenge's approval would spend.
    digest: [u8; 32],
    /// The base state the approval must still match at spend time.
    base: [u8; 32],
    /// The identity_type rewrite this write would carry, if any (Requirement 4.1).
    identity_change: Option<(IdentityType, IdentityType)>,
}

/// Raise the challenge for a bootstrap that would overwrite `reason`. Callers word the
/// remediation, because what the user has to redo depends on where the gate stopped them.
fn bootstrap_challenge(
    peer: &PeerInfo,
    uid: u32,
    subject: &Subject<'_>,
    reason: &Overwrite,
    admission: Admission,
    daemon: &Daemon,
) -> Challenge {
    daemon.presence.raise(
        peer,
        uid,
        Op::Bootstrap {
            environment: subject.environment.to_owned(),
            credential: subject.credential.to_owned(),
            params: admission.digest,
            base: admission.base,
        },
        describe_overwrite(reason, subject, admission.identity_change),
    )
}

/// What an existing subject would lose to this bootstrap, or `None` for a first bootstrap that
/// writes over nothing.
#[derive(Debug, PartialEq, Eq)]
enum Overwrite {
    /// The credential already has a source entry or sealed material.
    Credential,
    /// The environment exists and does not yet bind this credential.
    EnvironmentBinding,
}

/// What a bootstrap would overwrite, or `None` for a first bootstrap that writes over nothing.
/// Asked only of records the shared write check has verified: content no snapshot vouches for is
/// refused there as drift, never offered for approval here, because revalidation is the only way
/// to ratify it (drift-detection Requirements 3.9, 4).
fn overwrite_reason(
    uid: u32,
    environment: &str,
    credential: &str,
) -> std::io::Result<Option<Overwrite>> {
    let root = caller_root(uid);
    // Only `ENOENT` proves the credential holds no sealed material. Any other error leaves it
    // unknown, and unknown must gate: reading it as empty would skip the gate on exactly the
    // material the gate exists to protect.
    let sealed = match read_dir_or_absent(&root.join("credentials").join(credential))? {
        Some(mut entries) => match entries.next() {
            Some(entry) => {
                entry?;
                true
            }
            None => false,
        },
        None => false,
    };
    if sealed {
        return Ok(Some(Overwrite::Credential));
    }
    Ok(match DaemonConfig::load_from(&root) {
        Ok((config, credentials)) => {
            if credentials.contains_key(credential) {
                Some(Overwrite::Credential)
            } else if config.envs.get(environment).is_some_and(|env| {
                !env.credential_list(environment)
                    .iter()
                    .any(|c| c == credential)
            }) {
                Some(Overwrite::EnvironmentBinding)
            } else {
                None
            }
        }
        // Files that exist but do not load must not read as "nothing to overwrite": that would
        // turn a malformed file into a gate-free path to replacing what it describes. `try_exists`
        // rather than `exists`, which answers false to a stat failure and would reopen that path
        // for a file that is there but unstattable.
        Err(_) => {
            let present = root.join("credentials.toml").try_exists()?
                || root.join("config.toml").try_exists()?;
            present.then_some(Overwrite::Credential)
        }
    })
}

/// The identity_type an existing environment would lose to this write — the fact
/// `describe_overwrite`'s bind-only wording omitted (Requirement 4.1). `None` when the write
/// carries no identity_type, the environment has none on record yet, or the value is unchanged:
/// only an actual privilege-tier change is disclosed, matching `config/set`'s wording for the
/// same field. A config that will not load is an error, not `None`: the gate still raises for
/// it (`overwrite_reason`), and a challenge that silently drops the rewrite would ask the
/// approver to sign for a privilege-tier change they were never shown.
fn identity_type_change(
    uid: u32,
    environment: &str,
    new: Option<IdentityType>,
) -> Result<Option<(IdentityType, IdentityType)>, RpcError> {
    let Some(new) = new else { return Ok(None) };
    let (config, _) = DaemonConfig::parse_from(&caller_root(uid))
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    Ok(config
        .envs
        .get(environment)
        .map(|env| env.identity_type)
        .filter(|current| *current != new)
        .map(|current| (current, new)))
}

/// SHA-256 of `params` as this daemon re-serializes them, so the digest depends on their values
/// and not on the client's key order, prefixed with the method so an approval for one operation
/// can never be spent on another. `request_id` is excluded: it is per-attempt.
fn params_digest<T: serde::Serialize>(method: &str, params: &T) -> Result<[u8; 32], RpcError> {
    let mut value = serde_json::to_value(params).map_err(|e| RpcError::internal(e.to_string()))?;
    if let Some(map) = value.as_object_mut() {
        map.remove("request_id");
    }
    let mut bytes = format!("{method}\0").into_bytes();
    bytes.extend(serde_json::to_vec(&value).map_err(|e| RpcError::internal(e.to_string()))?);
    Ok(credsd_core::presence::sha256(&bytes))
}

/// SHA-256 of every record a gated operation on `credentials` could change: both config files,
/// and each sealed file under each credential's directory, by name and content. Absent records
/// hash as empty, so absence is a base state distinct from every present one. The operation's
/// own arguments are bound by the challenge digest, so they are not repeated here.
///
/// A record that is present but unreadable is an error, never the empty hash: were the two the
/// same, anything that made reads fail would collapse every base to one value, and an approval
/// raised under that condition would keep matching after its subject records moved. Absence is
/// the one state that hashes as empty, and it is proven by `ENOENT`, not assumed from a failure.
pub(crate) fn records_base(uid: u32, credentials: &[&str]) -> Result<[u8; 32], RpcError> {
    let files =
        TomlFiles::read(uid).map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    records_base_of(uid, &files, credentials)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))
}

/// `std::fs::read`, with `None` for a record that is absent. Absence is a base state, so it is
/// not an error; every other failure is, because a record that exists but will not read has no
/// base state this daemon can honestly report.
///
/// The one place that decides what absence is, for every base-state read. Were each read to
/// decide for itself, one of them answering "absent" to a failure would be enough to collapse
/// every base to the empty-state value.
pub(crate) fn read_or_absent(path: &std::path::Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(body) => Ok(Some(body)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// `read_or_absent` for a directory: `None` when it is not there.
fn read_dir_or_absent(path: &std::path::Path) -> std::io::Result<Option<std::fs::ReadDir>> {
    match std::fs::read_dir(path) {
        Ok(entries) => Ok(Some(entries)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The two load-bearing toml files, read once. A base check hashes these bytes, and the edit it
/// guards is made from the same bytes, so an edit cannot apply to a file changed after the check.
#[derive(Default, PartialEq)]
pub(crate) struct TomlFiles {
    pub(crate) credentials: Vec<u8>,
    pub(crate) config: Vec<u8>,
}

impl TomlFiles {
    /// An absent file is empty. Any other read error is returned, so an unreadable file cannot
    /// pass a check as empty and then be edited.
    pub(crate) fn read(uid: u32) -> std::io::Result<Self> {
        let root = caller_root(uid);
        let read = |name: &str| read_or_absent(&root.join(name)).map(Option::unwrap_or_default);
        Ok(Self {
            credentials: read("credentials.toml")?,
            config: read("config.toml")?,
        })
    }
}

/// `records_base` over toml bytes the caller has already read. An absent sealed directory is an
/// empty one; any other read failure is an error, never a file that hashes as empty.
pub(crate) fn records_base_of(
    uid: u32,
    files: &TomlFiles,
    credentials: &[&str],
) -> std::io::Result<[u8; 32]> {
    use credsd_core::presence::{hex, sha256};
    let root = caller_root(uid);
    let mut preimage = b"v1\n".to_vec();
    for (name, body) in [
        ("credentials.toml", &files.credentials),
        ("config.toml", &files.config),
    ] {
        preimage.extend_from_slice(format!("{name}={}\n", hex(&sha256(body))).as_bytes());
    }
    let mut credentials = credentials.to_vec();
    credentials.sort_unstable();
    credentials.dedup();
    for credential in credentials {
        let mut sealed = match read_dir_or_absent(&root.join("credentials").join(credential))? {
            Some(entries) => entries
                .map(|entry| entry.map(|e| e.path()))
                .collect::<std::io::Result<Vec<_>>>()?,
            None => Vec::new(),
        };
        sealed.sort();
        for path in sealed {
            // An entry that vanished between the listing and this read is absent by the end of
            // the enumeration, which is a base state; the daemon's own `seal_to_file` writes a
            // temp sibling here and renames it away, so this is reached without an attacker.
            // Any other failure is not absence and propagates.
            let Some(body) = read_or_absent(&path)? else {
                continue;
            };
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            preimage.extend_from_slice(
                format!("sealed.{credential}/{name}={}\n", hex(&sha256(&body))).as_bytes(),
            );
        }
    }
    Ok(sha256(&preimage))
}

/// The provider being bootstrapped, as a challenge names it: its kind and the target it binds,
/// never a secret.
fn provider_kind(provider: &ProviderParams) -> String {
    match provider {
        ProviderParams::AwsIdcSso(p) => format!(
            "aws-idc-sso ({} → account {}, role {})",
            escape_log(&p.start_url),
            escape_log(p.account_id.as_deref().unwrap_or("chosen at sign-in")),
            escape_log(p.role_name.as_deref().unwrap_or("chosen at sign-in"))
        ),
        ProviderParams::AwsIamUser(p) => {
            format!("iam-user (access key {})", escape_log(&p.access_key_id))
        }
        ProviderParams::AwsRolesAnywhere(p) => format!(
            "roles-anywhere (role {}, trust anchor {}, profile {}, region {}, endpoint {})",
            escape_log(&p.role_arn),
            escape_log(&p.trust_anchor_arn),
            escape_log(&p.profile_arn),
            escape_log(
                p.region
                    .as_deref()
                    .unwrap_or("derived from trust anchor ARN")
            ),
            escape_log(
                p.endpoint_url
                    .as_deref()
                    .unwrap_or("default for that region")
            )
        ),
        ProviderParams::AwsWebIdentity(p) => {
            format!(
                "aws-web-identity (authorize {}, token {}, client {}, scopes {}, role {}, region {})",
                escape_log(&p.authorization_endpoint),
                escape_log(&p.token_endpoint),
                escape_log(&p.client_id),
                // Debug, not join: ["a b"] and ["a", "b"] are different approvals.
                escape_log(&format!("{:?}", p.scopes)),
                escape_log(&p.role_arn),
                escape_log(&p.region),
            )
        }
        ProviderParams::AwsLogin(p) => format!("aws-login (region {})", escape_log(&p.region)),
        ProviderParams::Jwt(_) => "jwt".to_owned(),
        ProviderParams::Oauth(p) => format!(
            "oauth ({}, client {}, scope {})",
            escape_log(&p.token_url),
            escape_log(&p.client_id),
            escape_log(p.scope.as_deref().unwrap_or("none"))
        ),
        ProviderParams::JwtBearer(p) => format!(
            "jwt-bearer ({}, client {}, scope {})",
            escape_log(&p.token_url),
            escape_log(p.client_id.as_deref().unwrap_or("none")),
            escape_log(p.scope.as_deref().unwrap_or("none"))
        ),
        ProviderParams::StaticSecret(_) => "static-secret".to_owned(),
        ProviderParams::Unknown => "unknown provider".to_owned(),
    }
}

/// The identity_type a bootstrap's provider params carry, before the provider-specific flow
/// parses and validates it — every `ProviderParams` variant carries the same field. An
/// unparseable value reads as `None` here; the provider flow still rejects it on its own, this
/// is only used to disclose a change the entry-check challenge raises before that flow runs.
fn provider_identity_type(provider: &ProviderParams) -> Option<IdentityType> {
    let raw = match provider {
        ProviderParams::AwsIdcSso(p) => p.identity_type.as_deref(),
        ProviderParams::AwsIamUser(p) => p.identity_type.as_deref(),
        ProviderParams::AwsRolesAnywhere(p) => p.identity_type.as_deref(),
        ProviderParams::AwsWebIdentity(p) => p.identity_type.as_deref(),
        ProviderParams::AwsLogin(p) => p.identity_type.as_deref(),
        ProviderParams::Jwt(p) => p.identity_type.as_deref(),
        ProviderParams::Oauth(p) => p.identity_type.as_deref(),
        ProviderParams::JwtBearer(p) => p.identity_type.as_deref(),
        ProviderParams::StaticSecret(p) => p.identity_type.as_deref(),
        ProviderParams::Unknown => None,
    };
    parse_identity_type(raw).ok().flatten()
}

/// Requirement 4.1's suffix for an identity_type an approval would also rewrite, appended to both
/// bootstrap's and import's overwrite wording — phrased like `config/set`'s explicit
/// `key = value` text for the same field, so the ride-along is as visible as the explicit path.
/// Names `environment` explicitly rather than saying "its": the preceding wording's last-named
/// subject is sometimes the credential, not the environment, and the identity_type here is
/// always the environment's.
fn describe_identity_type_change(
    environment: &str,
    change: Option<(IdentityType, IdentityType)>,
) -> String {
    match change {
        Some((old, new)) => {
            format!(
                ", and change environment '{environment}''s identity_type from '{old}' to '{new}'"
            )
        }
        None => String::new(),
    }
}

/// The challenge's description (Requirement 4.1): what would be replaced, never the new secret.
fn describe_overwrite(
    reason: &Overwrite,
    subject: &Subject<'_>,
    identity_change: Option<(IdentityType, IdentityType)>,
) -> String {
    let Subject {
        environment,
        credential,
        kind,
    } = subject;
    let base = match reason {
        Overwrite::Credential => format!(
            "replace existing credential '{credential}' (source and sealed material) with a new \
             {kind}, served by environment '{environment}'"
        ),
        Overwrite::EnvironmentBinding => format!(
            "bind new credential '{credential}' ({kind}) into existing environment '{environment}'"
        ),
    };
    format!(
        "{base}{}",
        describe_identity_type_change(environment, identity_change)
    )
}

/// Handle `profile/login`. Re-authenticates using saved provider config. SSO re-runs the
/// device flow; IAM-user with MFA asks for a code; unattended sources are no-ops. A `jwt`
/// credential named explicitly is the one refusal: nothing here can mint its token.
pub async fn handle_profile_login(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
    respond_slot: RespondSlot,
) -> Result<Value, RpcError> {
    let uid = authorized_uid(peer)?;
    let params: ProfileLoginParams = request.params_as()?;
    // `claim_login` already caps this uid to one bootstrap/login in flight at a time, so this
    // lock is never contended by a second login or a concurrent bootstrap for the same uid — it
    // is for everything claim_login does NOT cover: commit_bootstrap, profile/import,
    // config/set, config/unset, credential/remove, env/remove, request/approve, and this uid's
    // own background/on-demand renewals, all of which write into the same per-credential
    // directory a login seals into. Taken per credential around that credential's own
    // login_one call below, not once for the whole sweep, so those operations interleave
    // between credentials in a multi-credential sweep instead of waiting out the entire sweep.
    //
    // Login seals fresh material for whatever the records name, so it must not run over records
    // in drift: a planted start URL or role would be sealed and served. Checked here to refuse
    // before any flow starts, and again under the lock for each credential, which is the check
    // the seal relies on (drift-detection Requirement 5.8, design Decision 6).
    let files =
        TomlFiles::read(uid).map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    precheck_for_write(daemon, uid, &files, BOTH)?;
    let caller_root = credsd_core::config::platform::caller_root(uid);

    let (config, _) = DaemonConfig::load_from(&caller_root)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;

    // Target: explicit credential, or all credentials the profile composes. Which of the two it
    // was decides what a source with no interactive flow reports: skipping it is right in a sweep
    // and wrong when the caller named it.
    let targeted = params.credential.is_some();
    let targets: Vec<String> = if let Some(ref cred) = params.credential {
        vec![cred.clone()]
    } else {
        config
            .envs
            .get(&params.environment)
            .ok_or_else(|| {
                RpcError::domain(
                    DomainCode::EnvironmentNotFound,
                    format!("environment '{}' not found", params.environment),
                )
            })?
            .credential_list(&params.environment)
    };

    for cred in targets {
        let resealed = crate::server::write_lock::under(
            &daemon.bootstrap_lock(uid),
            uid,
            LOGIN_LOCK_BUDGET,
            async |held| {
                // The sources the login reads are the bytes this check verified, under the lock
                // its seal holds, not the ones read before the lock was taken.
                let files = TomlFiles::read(uid)
                    .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
                // The provider seals inside `login_one`, in credsd-core, where no token reaches;
                // what the type enforces here is that this check ran under the hold it seals in.
                let _verified = verify_for_write(daemon, &held, uid, &files, BOTH)?;
                let credentials = credsd_core::config::credentials::from_text(
                    crate::server::dispatch::checked_text(&files.credentials)?,
                )
                .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
                login_one(
                    uid,
                    &cred,
                    &credentials,
                    daemon,
                    notif_tx.clone(),
                    respond_slot.clone(),
                    targeted,
                )
                .await
            },
        )
        .await
        .map_err(|expired| login_lock_error(&expired, &cred))??;
        if resealed {
            record_mutation(peer, uid, "environment/login", &params.environment, &cred);
        }
    }

    to_value(OkResult {})
}

/// Handle `profile/import`: seal a batch of discovered static-key profiles into the caller's
/// per-uid tree under one write lock, with a single caller-cache eviction after the batch.
///
/// Non-streaming — routed through the normal dispatch path, not the streaming interceptor.
/// Additive: an invalid name or one that already exists is a per-profile skip, never a batch
/// abort (Req 2.4). `dry_run` evaluates the same decision against the real tree and writes
/// nothing (Req 2.5). Auto-provisions `callers/<uid>/owner` for a first-time caller, matching
/// bootstrap (Req 2.7).
pub async fn handle_profile_import(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let uid = authorize_for_bootstrap(peer)?;
    let params: ImportParams = request.params_as()?;

    // Validate every profile before writing anything: an empty secret or a bad identity_type is a
    // request error, and validating up front means it aborts the batch before the first write
    // rather than mid-loop with earlier profiles already on disk.
    let identity_types = validate_import_profiles(&params.profiles)?;

    // One lock across the whole batch (vs N acquire/release cycles). `files` is the dedupe view
    // and the gate's base, read once under the lock; each seal below both checks against and
    // folds its write into these same bytes, so no step re-opens either file independently.
    let guard = daemon.write_guard(uid).await;
    let mut files =
        TomlFiles::read(uid).map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    // The shared write check (drift-detection Requirement 5.8). A dry run takes it too: it
    // reports the decision a real run would reach, and a real run would stop here. Each profile
    // written below runs it again for its own write, so each record write follows its own check.
    precheck_for_write(daemon, uid, &files, BOTH)?;
    let mut existing = credsd_core::config::credentials::from_text(
        std::str::from_utf8(&files.credentials)
            .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?,
    )
    .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;

    // The built-in gate (presence-gated-operations Requirement 1.7). Import never replaces a credential
    // entry — an existing name is skipped — but each imported profile also writes a same-named
    // environment, which can bind a new identity into one already in use, and its seal can land
    // on sealed material left behind. One challenge covers the whole batch: an import run is one
    // decision, and approving it profile by profile would only train the approver to click.
    if !params.dry_run {
        gate_import(
            uid,
            peer,
            &params,
            &identity_types,
            &existing,
            &files,
            daemon,
        )?;
    }

    let mut outcomes = Vec::with_capacity(params.profiles.len());
    let mut wrote = false;
    let mut state = ImportState {
        existing: &mut existing,
        files: &mut files,
        held: guard.held(),
    };
    let result = seal_import_batch(
        uid,
        &params,
        &identity_types,
        daemon,
        &mut state,
        &mut outcomes,
        &mut wrote,
    );

    // Evict whenever a write was attempted — `wrote` is set before each seal, so a mid-batch
    // abort (a filesystem error partway through persist/write) still evicts and cannot leave a
    // partially written batch behind a stale cache. Idempotent: a re-run reloads and skips the
    // names already sealed. The abort path is not unit-tested — the only failures reachable here
    // are fs errors that cannot be provoked deterministically without fragile manipulation — but
    // the eviction is unconditional on any attempted write, so it holds by construction.
    if wrote {
        daemon.evict_caller(uid);
    }
    // Recorded before `result?`, so the profiles an aborted batch already sealed are recorded too.
    // Each imported profile also writes a same-named environment.
    for outcome in outcomes
        .iter()
        .filter(|o| o.status == ImportStatus::Imported)
    {
        record_mutation(
            peer,
            uid,
            "environment/import",
            &outcome.name,
            &outcome.name,
        );
    }
    result?;
    to_value(ImportResult { outcomes })
}

/// One profile `gate_import` would overwrite: what it would replace, the identity_type rewrite
/// that replacement would carry, if any, and the access key id the challenge must name
/// (Requirement 4.1) — the only fact that distinguishes a benign re-import from a key
/// substitution, and non-secret by AWS's own definition of an access key id.
struct ImportOverwrite<'a> {
    name: &'a str,
    reason: Overwrite,
    identity_change: Option<(IdentityType, IdentityType)>,
    access_key_id: &'a str,
}

/// Refuse an import that would overwrite, unless an approval for exactly this batch against
/// exactly this state is waiting to be spent.
fn gate_import(
    uid: u32,
    peer: &PeerInfo,
    params: &ImportParams,
    identity_types: &[Option<IdentityType>],
    existing: &CredentialSources,
    files: &TomlFiles,
    daemon: &Daemon,
) -> Result<(), RpcError> {
    let mut overwrites: Vec<ImportOverwrite<'_>> = Vec::new();
    for (profile, &identity_type) in params.profiles.iter().zip(identity_types) {
        let fresh = matches!(
            credsd_core::import::decide(&profile.name, &profile.region, existing),
            credsd_core::import::Decision::Import
        );
        if fresh && !overwrites.iter().any(|o| o.name == profile.name) {
            if let Some(reason) = overwrite_reason(uid, &profile.name, &profile.name)
                .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?
            {
                // Each imported profile writes a same-named environment (Req 2.7), so the
                // identity_type ride-along applies here exactly as it does to bootstrap.
                let identity_change = identity_type_change(uid, &profile.name, identity_type)?;
                overwrites.push(ImportOverwrite {
                    name: profile.name.as_str(),
                    reason,
                    identity_change,
                    access_key_id: profile.access_key_id.as_str(),
                });
            }
        }
    }
    if overwrites.is_empty() {
        return Ok(());
    }
    let names: Vec<&str> = overwrites.iter().map(|o| o.name).collect();
    let digest = params_digest("environment/import", params)?;
    let base = records_base_of(uid, files, &names)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    if let Some(approved) = daemon.presence.spend(uid, &digest, &base) {
        info!(
            event = "presence.spent",
            pending_operation = approved.as_str(),
            profiles = names.len(),
            "presence gate: approved import authorization spent"
        );
        return Ok(());
    }
    let parts: Vec<String> = overwrites
        .iter()
        .map(|o| {
            let (name, key, change) = (o.name, escape_log(o.access_key_id), o.identity_change);
            let base = match &o.reason {
                Overwrite::EnvironmentBinding => format!(
                    "bind new credential '{name}' (iam-user, access key {key}) into existing \
                     environment '{name}'"
                ),
                Overwrite::Credential => format!(
                    "replace sealed data left on disk for credential '{name}' with a new \
                     iam-user (access key {key})"
                ),
            };
            format!("{base}{}", describe_identity_type_change(name, change))
        })
        .collect();
    let challenge = daemon.presence.raise(
        peer,
        uid,
        Op::Import {
            environments: names.iter().map(|n| (*n).to_owned()).collect(),
            params: digest,
            base,
        },
        format!("import: {}", parts.join("; ")),
    );
    let remediation = format!(
        "sudo creds request approve {id}, then re-run the same import",
        id = challenge.id
    );
    Err(RpcError::approval_required(&challenge, remediation))
}

/// Validate every profile up front — non-empty secret and a well-formed `identity_type` — before
/// any write. Returns the parsed `identity_type` per profile in order. Failing here aborts the
/// batch before the first seal, so a bad value can never leave the batch half-written.
fn validate_import_profiles(
    profiles: &[credsd_core::rpc::ImportProfile],
) -> Result<Vec<Option<IdentityType>>, RpcError> {
    let mut identity_types = Vec::with_capacity(profiles.len());
    for (i, profile) in profiles.iter().enumerate() {
        if profile.secret_access_key.is_empty() {
            // Positional, not by name: the name is caller-supplied and may not be log-safe.
            return Err(RpcError::invalid_params(format!(
                "profile #{i}: secret_access_key must not be empty"
            )));
        }
        identity_types.push(parse_identity_type(profile.identity_type.as_deref())?);
    }
    Ok(identity_types)
}

/// The import batch's running state. `existing` reserves a name the moment its profile is
/// decided `Import` — in a dry run that is the only record of it, since nothing is written — so
/// it is not simply derived from `files` on each iteration. `files` holds the bytes actually
/// persisted so far; a seal failure aborts the batch via `?` before reassigning it, so no later
/// profile ever reads a `files` that is stale relative to disk.
struct ImportState<'a> {
    existing: &'a mut CredentialSources,
    files: &'a mut TomlFiles,
    /// The batch's hold on the caller's write lock. Each profile's write checks under it, and
    /// writes the record after each one, so an aborted batch leaves it naming what was sealed.
    held: Held<'a>,
}

/// The per-profile seal loop of [`handle_profile_import`], factored out so the caller can evict
/// the caller cache on the error path too (`wrote` is observable after an abort). `identity_types`
/// is the pre-validated parse from [`validate_import_profiles`], aligned to `params.profiles`. The
/// per-uid write lock is assumed already held.
fn seal_import_batch(
    uid: u32,
    params: &ImportParams,
    identity_types: &[Option<IdentityType>],
    daemon: &Daemon,
    state: &mut ImportState<'_>,
    outcomes: &mut Vec<ImportOutcome>,
    wrote: &mut bool,
) -> Result<(), RpcError> {
    for (profile, &identity_type) in params.profiles.iter().zip(identity_types) {
        let decision = credsd_core::import::decide(&profile.name, &profile.region, state.existing);
        let (status, reason) = match decision {
            credsd_core::import::Decision::Skip(reason) => {
                let status = if params.dry_run {
                    ImportStatus::WouldSkip
                } else {
                    ImportStatus::Skipped
                };
                (status, Some(reason))
            }
            credsd_core::import::Decision::Import => {
                let config = IamUserConfig {
                    region: profile.region.clone(),
                    duration_seconds: None,
                    mfa_serial: None,
                    identity_type: identity_type.unwrap_or_default(),
                };
                if !params.dry_run {
                    // Mark the batch as written *before* the seal: persist_iam_user_locked can
                    // fail partway (the key file sealed, or credentials.toml written, before an
                    // error), and the caller must still evict the cache on that abort. Setting the
                    // flag only after full success would skip eviction for a partial write. A false
                    // positive (persist fails before touching disk) only forces a harmless reload.
                    *wrote = true;
                    let staged = Staged {
                        source: CredentialSource::AwsIamUser(config.clone()),
                        identity_type,
                    };
                    // Same-named 1:1 env — the same seal+write bootstrap uses. `files` carries
                    // forward each write's result, so the next profile in the batch edits from
                    // what this one just wrote, not the snapshot read before the batch started.
                    let mut verified =
                        verify_for_write(daemon, &state.held, uid, state.files, BOTH)?;
                    persist_iam_user_locked(
                        &profile.name,
                        &profile.name,
                        IamUserKey {
                            access_key_id: &profile.access_key_id,
                            secret_access_key: &profile.secret_access_key,
                        },
                        &staged,
                        state,
                        &mut verified,
                        &daemon.encryption,
                    )?;
                    daemon.integrity.write(verified)?;
                }
                // Reserve the name so a duplicate later in the same batch skips, in both real
                // and dry runs.
                state
                    .existing
                    .insert(profile.name.clone(), CredentialSource::AwsIamUser(config));
                let status = if params.dry_run {
                    ImportStatus::WouldImport
                } else {
                    ImportStatus::Imported
                };
                (status, None)
            }
        };
        // Names the credential and outcome only — never the secret (Req 6.3).
        info!(credential = %profile.name, ?status, "profile import outcome");
        outcomes.push(ImportOutcome {
            name: profile.name.clone(),
            status,
            reason,
        });
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Bootstrap sub-handlers
// ──────────────────────────────────────────────────────────────────────────────

async fn bootstrap_sso(
    data_dir: &std::path::Path,
    credential: &str,
    params: credsd_core::rpc::ProviderParamsSso,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
    respond_slot: RespondSlot,
) -> Result<Staged, RpcError> {
    let temp_config = SsoConfig {
        start_url: params.start_url.clone(),
        sso_region: params.sso_region.clone(),
        account_id: String::new(),
        role_name: String::new(),
        identity_type: Default::default(),
    };
    let provider = SsoProvider::new(
        credential.to_string(),
        temp_config,
        daemon.encryption.clone(),
        data_dir.to_path_buf(),
    );

    // Start the device-authorization flow (no UI — the daemon sends a notification).
    let auth_start = provider
        .start_auth()
        .await
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;

    send_notif(
        &notif_tx,
        &ProgressParams::DeviceCode {
            verification_uri: auth_start.verification_uri.clone(),
            user_code: auth_start.user_code.clone(),
        },
    )
    .await?;

    // Poll for the token (up to 5 minutes). The client silently waits.
    let cached_token = provider
        .complete_auth(auth_start)
        .await
        .map_err(auth_failure)?;

    // Account/role resolution: use params if provided, otherwise ask the client.
    let (account_id, role_name) = match (params.account_id, params.role_name) {
        (Some(aid), Some(rn)) => (aid, rn),
        _ => {
            let accounts = provider
                .list_accounts(&cached_token.access_token)
                .await
                .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
            // Slice patterns carry the emptiness check, so there is no separate `is_empty` guard
            // for a later index to fall out of step with.
            let account_id = match accounts.as_slice() {
                [] => {
                    return Err(RpcError::domain(
                        DomainCode::ProviderUnavailable,
                        "no accounts available",
                    ))
                }
                [(id, ..)] => {
                    info!(account = %id, "single account, auto-selecting");
                    id.clone()
                }
                _ => {
                    let items: Vec<credsd_core::rpc::AccountInfo> = accounts
                        .iter()
                        .map(|(id, name, email)| credsd_core::rpc::AccountInfo {
                            id: id.clone(),
                            name: name.clone(),
                            email: email.clone(),
                        })
                        .collect();
                    await_selection(
                        &notif_tx,
                        &respond_slot,
                        &ProgressParams::SelectAccount { accounts: items },
                    )
                    .await?
                }
            };

            let roles = provider
                .list_roles(&cached_token.access_token, &account_id)
                .await
                .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
            let role_name = match roles.as_slice() {
                [] => {
                    return Err(RpcError::domain(
                        DomainCode::ProviderUnavailable,
                        format!("no roles available in account {account_id}"),
                    ))
                }
                [only] => {
                    info!(role = %only, "single role, auto-selecting");
                    only.clone()
                }
                _ => {
                    await_selection(
                        &notif_tx,
                        &respond_slot,
                        &ProgressParams::SelectRole {
                            roles: roles.clone(),
                        },
                    )
                    .await?
                }
            };

            (account_id, role_name)
        }
    };

    let identity_type = parse_identity_type(params.identity_type.as_deref())?;
    let final_config = SsoConfig {
        start_url: params.start_url,
        sso_region: params.sso_region,
        account_id,
        role_name,
        identity_type: identity_type.unwrap_or_default(),
    };
    Ok(Staged {
        source: CredentialSource::AwsIdcSso(final_config),
        identity_type,
    })
}

fn bootstrap_iam_user(
    data_dir: &std::path::Path,
    params: credsd_core::rpc::ProviderParamsIamUser,
    daemon: &Daemon,
) -> Result<Staged, RpcError> {
    if params.secret_access_key.is_empty() {
        return Err(RpcError::invalid_params(
            "secret_access_key must not be empty",
        ));
    }
    let identity_type = parse_identity_type(params.identity_type.as_deref())?;
    let config = IamUserConfig {
        region: params.region.clone(),
        duration_seconds: params.duration_seconds,
        mfa_serial: params.mfa_serial.clone(),
        identity_type: identity_type.unwrap_or_default(),
    };
    credsd_core::providers::iam_user::persist_key_pair(
        &daemon.encryption,
        data_dir,
        &params.access_key_id,
        &params.secret_access_key,
    )
    .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    Ok(Staged {
        source: CredentialSource::AwsIamUser(config),
        identity_type,
    })
}

/// An iam-user access key and its secret, kept as one named pair. Two adjacent `&str` arguments
/// would let a `(secret, access_key_id)` transposition compile silently and seal the wrong
/// credentials; the named fields make that a type error at the call site.
struct IamUserKey<'a> {
    access_key_id: &'a str,
    secret_access_key: &'a str,
}

/// Seal an iam-user key pair and write its credential + wrapping env, with the per-uid write lock
/// assumed already held. The shared seal+write both `bootstrap_iam_user` (one credential) and the
/// `profile/import` batch (N under one lock) use, so the persist/upsert/env-append sequence lives
/// in one place (design.md §2). Advances `state.files` to the bytes written and pins what was
/// sealed in `state.record`; the caller persists the record.
fn persist_iam_user_locked(
    environment: &str,
    credential: &str,
    key: IamUserKey<'_>,
    staged: &Staged,
    state: &mut ImportState<'_>,
    verified: &mut Verified,
    encryption: &credsd_core::encryption::EncryptionService,
) -> Result<(), RpcError> {
    let data_dir = caller_root(verified.uid())
        .join("credentials")
        .join(credential);
    credsd_core::providers::iam_user::persist_key_pair(
        encryption,
        &data_dir,
        key.access_key_id,
        key.secret_access_key,
    )
    .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    *state.files = write_caller_state_locked(
        environment,
        credential,
        staged,
        state.files,
        verified,
        encryption,
    )?;
    Ok(())
}

/// Bootstrap an `aws-web-identity` credential: run the authorization-code flow, then seal the tokens.
///
/// The daemon owns both halves of the flow it can own — it binds the loopback listener and does
/// the token exchange — and delegates the one it cannot: opening a browser. It has no display
/// session, so the authorization URL goes to the client as a notification.
///
/// `respond_slot` is deliberately unused. Unlike account/role selection, the answer here does not
/// come back over the socket: it arrives as the IdP's redirect to the daemon's own listener. That
/// also means this flow is bounded by `CALLBACK_TIMEOUT` rather than by the unbounded
/// `await_selection` wait.
async fn bootstrap_aws_web_identity(
    data_dir: &std::path::Path,
    credential: &str,
    params: credsd_core::rpc::ProviderParamsAwsWebIdentity,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
) -> Result<Staged, RpcError> {
    let config = AwsWebIdentityConfig {
        authorization_endpoint: Some(params.authorization_endpoint.clone()),
        token_endpoint: Some(params.token_endpoint.clone()),
        client_id: Some(params.client_id.clone()),
        scopes: params.scopes.clone(),
        role_arn: params.role_arn.clone(),
        region: params.region.clone(),
        duration_seconds: params.duration_seconds,
        role_session_name: params.role_session_name.clone(),
        callback_port: params.callback_port,
        identity_type: Default::default(),
    };
    if let Some(port) = config.callback_port {
        use credsd_core::providers::oauth::callback::{CALLBACK_PORT_MAX, CALLBACK_PORT_MIN};
        if !(CALLBACK_PORT_MIN..=CALLBACK_PORT_MAX).contains(&port) {
            return Err(RpcError::invalid_params(format!(
                "callback_port must be {CALLBACK_PORT_MIN}–{CALLBACK_PORT_MAX}; \
                 omit the field for an ephemeral port",
            )));
        }
    }

    run_aws_web_identity(data_dir, credential, &config, daemon, notif_tx).await?;

    let identity_type = parse_identity_type(params.identity_type.as_deref())?;
    Ok(Staged {
        source: CredentialSource::AwsWebIdentity(config),
        identity_type,
    })
}

/// The interactive half, shared by bootstrap and re-login: bind, report the URL, wait, exchange.
async fn run_aws_web_identity(
    data_dir: &std::path::Path,
    credential: &str,
    config: &AwsWebIdentityConfig,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), RpcError> {
    let provider = AwsWebIdentityProvider::new(
        credential.to_string(),
        config.clone(),
        daemon.encryption.clone(),
        data_dir.to_path_buf(),
    )
    .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;

    // Bind first: the URL embeds the port, so it cannot be built before the listener exists.
    let pending = provider
        .begin_interactive_login()
        .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;

    send_notif(
        &notif_tx,
        &ProgressParams::AuthorizeUrl {
            url: pending.authorize_url().to_string(),
        },
    )
    .await?;

    provider
        .finish_interactive_login(pending)
        .await
        .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))
}

async fn bootstrap_aws_login(
    data_dir: &std::path::Path,
    credential: &str,
    params: credsd_core::rpc::ProviderParamsAwsLogin,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
    respond_slot: RespondSlot,
) -> Result<Staged, RpcError> {
    let identity_type = parse_identity_type(params.identity_type.as_deref())?;
    let config = AwsLoginConfig {
        region: params.region,
        callback_port: params.callback_port,
        remote: params.remote,
        identity_type: identity_type.unwrap_or_default(),
    };
    if let Some(port) = config.callback_port {
        use credsd_core::providers::oauth::callback::{CALLBACK_PORT_MAX, CALLBACK_PORT_MIN};
        if !(CALLBACK_PORT_MIN..=CALLBACK_PORT_MAX).contains(&port) {
            return Err(RpcError::invalid_params(format!(
                "callback_port must be {CALLBACK_PORT_MIN}–{CALLBACK_PORT_MAX}; \
                 omit the field for an ephemeral port",
            )));
        }
    }

    run_aws_login(
        data_dir,
        credential,
        &config,
        daemon,
        notif_tx,
        respond_slot,
    )
    .await?;

    Ok(Staged {
        source: CredentialSource::AwsLogin(config),
        identity_type,
    })
}

/// The interactive half of `aws-login`, shared by bootstrap and re-login.
///
/// A `remote` credential takes the cross-device branch: nothing is listening for a redirect, so
/// the authorization result comes back through `respond_slot` as the user's paste.
async fn run_aws_login(
    data_dir: &std::path::Path,
    credential: &str,
    config: &AwsLoginConfig,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
    respond_slot: RespondSlot,
) -> Result<(), RpcError> {
    let provider = AwsLoginProvider::new(
        credential.to_string(),
        config.clone(),
        daemon.encryption.clone(),
        data_dir.to_path_buf(),
    )
    .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;

    if config.remote {
        let pending = provider
            .begin_remote_login()
            .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;
        let paste = Zeroizing::new(
            await_selection(
                &notif_tx,
                &respond_slot,
                &ProgressParams::AuthorizeCode {
                    url: pending.authorize_url().to_string(),
                },
            )
            .await?,
        );
        return provider
            .finish_remote_login(pending, &paste)
            .await
            .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()));
    }

    let pending = provider
        .begin_interactive_login()
        .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;

    send_notif(
        &notif_tx,
        &ProgressParams::AuthorizeUrl {
            url: pending.authorize_url().to_string(),
        },
    )
    .await?;

    provider
        .finish_interactive_login(pending)
        .await
        .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))
}

/// Bootstrap a `jwt` credential: seal the JWT and write the source config, in that order so a
/// failed seal never leaves a config entry referring to material that is not there. Follows the
/// iam-user / roles-anywhere shape: the secret rides in the bootstrap params (with Debug
/// redaction) and the daemon persists it inline via the provider's `persist_token`, which
/// validates the JWT's `exp` before writing so a token with no readable expiry never reaches
/// disk. To refresh an expired JWT, re-run bootstrap with the new token.
fn bootstrap_jwt(
    data_dir: &std::path::Path,
    params: credsd_core::rpc::ProviderParamsJwt,
    daemon: &Daemon,
) -> Result<Staged, RpcError> {
    let jwt = Zeroizing::new(params.jwt.clone());
    credsd_core::providers::jwt::persist_token(&daemon.encryption, data_dir, &jwt)
        .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;

    let identity_type = parse_identity_type(params.identity_type.as_deref())?;
    let config = credsd_core::config::JwtConfig {
        env_var: params.env_var.clone(),
        identity_type: identity_type.unwrap_or_default(),
    };
    Ok(Staged {
        source: CredentialSource::Jwt(config),
        identity_type,
    })
}

/// Seal a user-supplied secret and record its config entry.
///
/// Secret first, then config — the same order `bootstrap_jwt` uses, and for the same reason: a
/// failure between the two must never leave a config entry naming a credential with no sealed
/// material, which would read as bootstrapped and fail only at first fetch.
pub(crate) fn bootstrap_static_secret(
    data_dir: &std::path::Path,
    params: credsd_core::rpc::ProviderParamsStaticSecret,
    daemon: &Daemon,
) -> Result<Staged, RpcError> {
    if let Some(at) = params.expires_at {
        if at <= chrono::Utc::now() {
            return Err(RpcError::invalid_params(format!(
                "secret expired at {at}; bootstrap again with a fresh secret (static-secret)"
            )));
        }
    }
    let secret = Zeroizing::new(params.secret.clone());
    credsd_core::providers::static_secret::persist_secret(&daemon.encryption, data_dir, &secret)
        .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;

    let identity_type = parse_identity_type(params.identity_type.as_deref())?;
    let config = StaticSecretConfig {
        env_var: params.env_var.clone(),
        expires_at: params.expires_at,
        secret_source: params.secret_source.clone(),
        identity_type: identity_type.unwrap_or_default(),
    };
    Ok(Staged {
        source: CredentialSource::StaticSecret(config),
        identity_type,
    })
}

fn bootstrap_ra(
    data_dir: &std::path::Path,
    params: credsd_core::rpc::ProviderParamsRa,
    daemon: &Daemon,
) -> Result<Staged, RpcError> {
    let (cert_der, key_der_bytes, chain_der) = params
        .decode_der()
        .map_err(|e| RpcError::invalid_params(format!("base64 decode failed: {e}")))?;
    let key_der = Zeroizing::new(key_der_bytes);
    persist_ingested(
        &daemon.encryption,
        data_dir,
        &key_der,
        &params.key_tag,
        &cert_der,
        &chain_der,
    )
    .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;

    let identity_type = parse_identity_type(params.identity_type.as_deref())?;
    let config = RolesAnywhereConfig {
        trust_anchor_arn: params.trust_anchor_arn.clone(),
        profile_arn: params.profile_arn.clone(),
        role_arn: params.role_arn.clone(),
        region: params.region.clone(),
        duration_seconds: params.duration_seconds,
        role_session_name: params.role_session_name.clone(),
        endpoint_url: params.endpoint_url.clone(),
        identity_type: identity_type.unwrap_or_default(),
    };
    Ok(Staged {
        source: CredentialSource::AwsRolesAnywhere(config),
        identity_type,
    })
}

fn bootstrap_oauth(
    data_dir: &std::path::Path,
    params: credsd_core::rpc::ProviderParamsOauth,
    daemon: &Daemon,
) -> Result<Staged, RpcError> {
    if params.client_secret.as_deref() == Some("") {
        return Err(RpcError::invalid_params("client_secret must not be empty"));
    }
    if params.client_secret.is_none() && params.private_key_pem.is_none() {
        return Err(RpcError::invalid_params(
            "oauth bootstrap requires either --client-secret or --private-key-pem",
        ));
    }
    let identity_type = parse_identity_type(params.identity_type.as_deref())?;
    // Seal private key if provided; it never touches credentials.toml.
    if let Some(pem) = &params.private_key_pem {
        let pkcs8 = credsd_core::providers::oauth::dpop::pkcs8_from_pem(pem)
            .map_err(|e| RpcError::invalid_params(format!("private_key_pem: {}", e)))?;
        daemon
            .encryption
            .seal_to_file(&data_dir.join("oauth_client_key.enc"), &pkcs8)
            .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    }
    // Seal client_secret if provided.
    if let Some(secret) = &params.client_secret {
        credsd_core::providers::client_credentials::persist_secret(
            data_dir,
            secret,
            &daemon.encryption,
        )
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    }
    let config = OauthConfig {
        token_url: params.token_url.clone(),
        client_id: params.client_id.clone(),
        scope: params.scope.clone(),
        grant: OauthGrant::ClientCredentials,
        identity_type: identity_type.unwrap_or_default(),
    };
    Ok(Staged {
        source: CredentialSource::Oauth(config),
        identity_type,
    })
}

#[cfg(feature = "jwt-bearer")]
fn bootstrap_jwt_bearer(
    data_dir: &std::path::Path,
    params: credsd_core::rpc::ProviderParamsJwtBearer,
    daemon: &Daemon,
) -> Result<Staged, RpcError> {
    let identity_type = parse_identity_type(params.identity_type.as_deref())?;
    let config = JwtBearerConfig {
        token_url: params.token_url.clone(),
        client_id: params.client_id.clone(),
        scope: params.scope.clone(),
        identity_type: identity_type.unwrap_or_default(),
    };
    let assertion = Zeroizing::new(params.assertion.clone());
    credsd_core::providers::jwt_bearer::persist_assertion(&daemon.encryption, data_dir, &assertion)
        .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;
    Ok(Staged {
        source: CredentialSource::JwtBearer(config),
        identity_type,
    })
}

/// Emit the audit record naming the caller for a bootstrap, import or login that wrote sealed
/// material. Emitted at commit, so a flow that fails leaves none. A gated write also has the gate's
/// own records, at raise and at approval; this one is what an ungated create or a login has.
fn record_mutation(
    peer: &PeerInfo,
    uid: u32,
    operation: &str,
    environment: &str,
    credential: &str,
) {
    info!(
        event = "mutation.applied",
        operation,
        environment,
        credential,
        owner_uid = uid,
        owner_login_uid = peer.login_uid,
        owner_pid = peer.pid,
        owner_executable = peer.executable.as_deref(),
        owner_ancestry = ancestry_field(peer.pid).as_deref(),
        "mutation applied"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Login sub-handlers
// ──────────────────────────────────────────────────────────────────────────────

/// Map a login's write-lock expiry onto the client's error. The two are distinct outcomes: a wait
/// expiry sealed nothing and is worth retrying, while a hold expiry cut the login off mid-flow, so
/// it reads as the timeout it is. Neither leaves partial sealed material a later login cannot
/// overwrite — each provider's persist step is a whole-file seal.
fn login_lock_error(expired: &crate::server::write_lock::Expired, credential: &str) -> RpcError {
    use crate::server::write_lock::Expired;
    let seconds = expired.limit(LOGIN_LOCK_BUDGET).as_secs();
    match expired {
        Expired::Wait => RpcError::domain(
            DomainCode::ProviderUnavailable,
            format!(
                "another operation held this user's write lock for longer than {seconds}s, so \
                 '{credential}' was not logged in; nothing was written, retry"
            ),
        ),
        Expired::Hold => RpcError::domain(
            DomainCode::AuthTimeout,
            format!("login for '{credential}' did not finish within {seconds}s"),
        ),
    }
}

/// Log in one credential; `Ok(true)` when it sealed fresh material, `Ok(false)` when there was
/// nothing to do.
async fn login_one(
    uid: u32,
    credential: &str,
    credentials: &CredentialSources,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
    respond_slot: RespondSlot,
    // True when the caller named this credential with `--credential` rather than reaching it
    // through an env sweep.
    targeted: bool,
) -> Result<bool, RpcError> {
    match credentials.get(credential) {
        Some(CredentialSource::AwsIdcSso(sso)) => {
            login_sso(uid, credential, sso, daemon, notif_tx, respond_slot)
                .await
                .map(|()| true)
        }
        Some(CredentialSource::AwsIamUser(iam)) => {
            login_iam_user(uid, credential, iam, daemon, notif_tx, respond_slot).await
        }
        Some(CredentialSource::AwsRolesAnywhere(_))
        | Some(CredentialSource::Oauth(_))
        | Some(CredentialSource::JwtBearer(_))
        | Some(CredentialSource::Unsupported) => {
            // Unattended sources need no interactive login.
            Ok(false)
        }
        // A JWT source has no interactive flow and no way to mint: only a re-bootstrap seals a
        // fresh token. A sweep skips it like any other unattended source, but a caller that named
        // it gets told what does work — an `Ok` there reads as "refreshed", which is how an
        // expired token becomes a mystery.
        Some(CredentialSource::Jwt(_)) if targeted => Err(RpcError::domain(
            DomainCode::ProviderUnavailable,
            format!(
                "credential '{credential}' is a jwt source: it has no interactive login. Seal a \
                 fresh token with '{}'.",
                credsd_core::providers::jwt::reseal_command(credential)
            ),
        )),
        Some(CredentialSource::Jwt(_)) => Ok(false),
        // Same shape as `jwt`, and for a stronger reason: there is no issuer at all, so the only
        // path to a different secret is a human supplying one. A sweep skips it; a caller that
        // named it is told what actually works, because an `Ok` here would read as "refreshed".
        Some(CredentialSource::StaticSecret(_)) if targeted => Err(RpcError::domain(
            DomainCode::ProviderUnavailable,
            format!(
                "credential '{credential}' is a static-secret source: it has no interactive \
                 login. Seal a fresh secret with '{}'.",
                credsd_core::providers::static_secret::reseal_command(credential)
            ),
        )),
        Some(CredentialSource::StaticSecret(_)) => Ok(false),
        Some(CredentialSource::AwsWebIdentity(oauth)) => {
            let data_dir = caller_root(uid).join("credentials").join(credential);
            run_aws_web_identity(&data_dir, credential, oauth, daemon, notif_tx)
                .await
                .map(|()| true)
        }
        Some(CredentialSource::AwsLogin(aws)) => {
            let data_dir = caller_root(uid).join("credentials").join(credential);
            run_aws_login(&data_dir, credential, aws, daemon, notif_tx, respond_slot)
                .await
                .map(|()| true)
        }
        None => Err(RpcError::domain(
            DomainCode::EnvironmentNotFound,
            format!("credential '{credential}' not found"),
        )),
    }
}

async fn login_sso(
    uid: u32,
    credential: &str,
    sso: &SsoConfig,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
    _respond_slot: RespondSlot, // SSO login uses device-code flow; no selection needed
) -> Result<(), RpcError> {
    let data_dir = caller_root(uid).join("credentials").join(credential);
    let provider = SsoProvider::new(
        credential.to_string(),
        sso.clone(),
        daemon.encryption.clone(),
        data_dir,
    );

    // Try unattended renewal first; only run the device flow when the token is spent.
    if let Some(renewer) = provider.renewer() {
        match renewer.renew().await {
            Ok(Renewed::Ready(_)) => {
                info!(credential = %credential, "SSO token renewed unattended");
                return Ok(());
            }
            Ok(Renewed::ReauthRequired(_)) => {}
            Err(e) => {
                warn!(credential = %credential, error = %escape_log(&e), "unattended SSO renew failed, running device flow");
            }
        }
    }

    // Device authorization flow (same as bootstrap, no selection needed — account/role
    // are already stored in the SsoConfig).
    let auth_start = provider
        .start_auth()
        .await
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;

    send_notif(
        &notif_tx,
        &ProgressParams::DeviceCode {
            verification_uri: auth_start.verification_uri.clone(),
            user_code: auth_start.user_code.clone(),
        },
    )
    .await?;

    provider
        .complete_auth(auth_start)
        .await
        .map_err(auth_failure)?;

    info!(credential = %credential, "SSO login complete");
    Ok(())
}

/// A device-code poll that failed, as the client will see it. The wire carries the error's detail
/// alone: the client renders the category, so relaying the rendered error would show it twice.
fn auth_failure(e: credsd_core::error::DaemonError) -> RpcError {
    let msg = e.detail();
    if msg.contains("timed out") {
        RpcError::domain(DomainCode::AuthTimeout, msg)
    } else {
        RpcError::domain(DomainCode::Internal, msg)
    }
}

/// `Ok(true)` when it sealed a new session; `Ok(false)` for a key with no MFA, which needs no login.
async fn login_iam_user(
    uid: u32,
    credential: &str,
    iam: &IamUserConfig,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
    respond_slot: RespondSlot, // used for MFA code collection via await_selection
) -> Result<bool, RpcError> {
    let Some(ref serial) = iam.mfa_serial else {
        // Unattended key — no login needed.
        return Ok(false);
    };

    let data_dir = caller_root(uid).join("credentials").join(credential);
    let provider = SessionTokenProvider::new(
        credential.to_string(),
        iam.clone(),
        daemon.encryption.clone(),
        data_dir,
    );

    let code = await_selection(
        &notif_tx,
        &respond_slot,
        &ProgressParams::MfaRequired {
            serial: serial.clone(),
        },
    )
    .await?;

    let creds = provider
        .mint_with_mfa(&code)
        .await
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    provider
        .persist_session(&creds)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;

    info!(credential = %credential, "IAM-user MFA login complete");
    Ok(true)
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Authorize a bootstrap request. Accepts an already-authorized caller or auto-provisions
/// `callers/<uid>/owner` for a `Denied(NoRoot)` caller (first-time bootstrap). All other
/// deny reasons are still refused as not-found.
fn authorize_for_bootstrap(peer: &PeerInfo) -> Result<u32, RpcError> {
    match peer.auth {
        CallerAuth::Authorized { uid, .. } => Ok(uid),
        CallerAuth::Denied(DenyReason::NoRoot) => {
            let uid = peer.uid.ok_or_else(not_found)?;
            credsd_core::config::platform::provision_caller_for_uid(uid)
                .map(|_| uid)
                .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))
        }
        _ => Err(not_found()),
    }
}

/// The credentials.toml + config.toml write, with the per-uid lock assumed already held. Pins
/// both snapshots it seals in `record`; the caller writes the record, after this returns, so the
/// order is file, snapshot, record (drift-detection Requirement 5.6).
///
/// The batch `profile/import` handler calls it N times under a single lock held across the whole
/// batch; bootstrap calls it once from its commit step, under the same lock as the commit's
/// re-check. Credential is written first so the env that references it is always valid on
/// reload.
///
/// Writes from `files`, the bytes a base check already verified, instead of re-opening either
/// file: a hand edit landing between that check and this write is overwritten, never folded into
/// the committed state (the same residual, narrowed-not-removed window `write_config_file`'s
/// tempfile-and-rename already carries for every other gated write). Returns the post-write
/// bytes, so a caller writing several credentials under one lock hold (`profile/import`) threads
/// each write's result into the next, rather than overwriting its own prior write with the
/// snapshot read before the batch started.
fn write_caller_state_locked(
    environment: &str,
    credential: &str,
    staged: &Staged,
    files: &TomlFiles,
    verified: &mut Verified,
    enc: &credsd_core::encryption::EncryptionService,
) -> Result<TomlFiles, RpcError> {
    let uid = verified.uid();
    let caller_root = credsd_core::config::platform::caller_root(uid);
    let creds_path = caller_root.join("credentials.toml");
    let config_path = caller_root.join("config.toml");

    let checked_creds = std::str::from_utf8(&files.credentials)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    let written_creds = credsd_core::config::credentials::upsert_credential_in(
        &creds_path,
        checked_creds,
        credential,
        &staged.source,
    )
    .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    // Re-seal credentials snapshot from the bytes just written (credentials before config —
    // matches load order), not a fresh read. `from_text` skips validation, same as the
    // `parse_from` it replaces: snapshot seals what was written, not a validated view.
    let sources = credsd_core::config::credentials::from_text(&written_creds)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    let rel_creds = std::path::Path::new("callers")
        .join(uid.to_string())
        .join("credentials.toml");
    let creds_canonical =
        credsd_core::config::snapshot::canonical_credentials(uid, &rel_creds, &sources)
            .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    verified
        .seal_snapshot(
            enc,
            crate::server::revalidate::CREDENTIALS,
            &creds_canonical,
        )
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    verified.pin_sealed(crate::server::revalidate::CREDENTIALS, &creds_canonical);

    let checked_config = std::str::from_utf8(&files.config)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    let mut env_cfg = DaemonConfig::from_text(checked_config)
        .ok()
        .and_then(|c| c.envs.get(environment).cloned())
        .unwrap_or_default();
    if let Some(it) = staged.identity_type {
        env_cfg.identity_type = it;
    }
    append_env_credential(&mut env_cfg, credential);

    let written_config =
        DaemonConfig::save_env_in(&config_path, checked_config, environment, &env_cfg)
            .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    // Re-seal config snapshot from the bytes just written (config last — snapshot after config
    // per write ordering), not a fresh read.
    let config = DaemonConfig::from_text(&written_config)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    let rel_config = std::path::Path::new("callers")
        .join(uid.to_string())
        .join("config.toml");
    let config_canonical =
        credsd_core::config::snapshot::canonical_config(uid, &rel_config, &config)
            .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    verified
        .seal_snapshot(enc, crate::server::revalidate::CONFIG, &config_canonical)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    verified.pin_sealed(crate::server::revalidate::CONFIG, &config_canonical);

    Ok(TomlFiles {
        credentials: written_creds.into_bytes(),
        config: written_config.into_bytes(),
    })
}

/// Send a notification line via the write channel.
async fn send_notif(tx: &mpsc::Sender<Vec<u8>>, params: &ProgressParams) -> Result<(), RpcError> {
    let notif = Notification::new(NOTIFICATION_PROGRESS, params);
    let bytes = codec::encode_notification(&notif)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    tx.send(bytes)
        .await
        .map_err(|_| RpcError::domain(DomainCode::AuthCancelled, "connection closed"))
}

/// Send a progress notification that requires a client selection (account, role, MFA code),
/// install a `oneshot::Sender` in `respond_slot`, and await the client's response.
async fn await_selection(
    notif_tx: &mpsc::Sender<Vec<u8>>,
    respond_slot: &RespondSlot,
    step: &ProgressParams,
) -> Result<String, RpcError> {
    let (tx, rx) = oneshot::channel();
    {
        let mut slot = crate::server::lock(respond_slot);
        if slot.is_some() {
            return Err(RpcError::domain(
                DomainCode::Internal,
                "respond slot already occupied",
            ));
        }
        *slot = Some(tx);
    }
    send_notif(notif_tx, step).await?;
    tokio::time::timeout(INTERACTIVE_STEP_LIMIT, rx)
        .await
        .map_err(|_| {
            RpcError::domain(
                DomainCode::AuthTimeout,
                "timed out waiting for client selection",
            )
        })?
        .map_err(|_| RpcError::domain(DomainCode::AuthCancelled, "client closed connection"))
}

fn parse_identity_type(s: Option<&str>) -> Result<Option<IdentityType>, RpcError> {
    match s {
        None => Ok(None),
        Some("human") => Ok(Some(IdentityType::Human)),
        Some("automation") => Ok(Some(IdentityType::Automation)),
        Some("agent") => Ok(Some(IdentityType::Agent)),
        Some(other) => Err(RpcError::invalid_params(format!(
            "unknown identity_type '{other}'; expected human, automation, or agent"
        ))),
    }
}

fn not_found() -> RpcError {
    RpcError::domain(
        DomainCode::EnvironmentNotFound,
        "profile or credential not found",
    )
}

fn to_value<T: serde::Serialize>(value: T) -> Result<Value, RpcError> {
    serde_json::to_value(value).map_err(|e| RpcError::internal(e.to_string()))
}

#[cfg(test)]
mod auth_failure_tests {
    use super::*;
    use credsd_core::error::DaemonError;
    use credsd_core::rpc::uds::error_to_daemon;

    /// The device-code timeout as the user reads it: one category prefix, and no debug-build
    /// panic from the nested-prefix guard. Relaying the rendered error put `provider error: `
    /// inside the client's `configuration error: auth timed out: ` line.
    #[test]
    fn a_device_code_timeout_reaches_the_client_with_one_prefix() {
        let timeout = DaemonError::provider("SSO authentication timed out after 5 minutes");
        let wire = auth_failure(timeout);
        assert_eq!(wire.domain_code(), Some(DomainCode::AuthTimeout));
        let shown = error_to_daemon(Some("dev"), wire).to_string();
        assert_eq!(
            shown,
            "configuration error: auth timed out: SSO authentication timed out after 5 minutes"
        );
    }

    /// Any other poll failure reaches the client as the daemon's detail, unprefixed.
    #[test]
    fn another_poll_failure_reaches_the_client_verbatim() {
        let wire = auth_failure(DaemonError::provider(
            "access denied by the identity provider",
        ));
        assert_eq!(wire.domain_code(), Some(DomainCode::Internal));
        assert_eq!(
            error_to_daemon(None, wire).to_string(),
            "access denied by the identity provider"
        );
    }
}

#[cfg(test)]
mod provider_kind_tests {
    use super::*;
    use credsd_core::rpc::{
        ProviderParamsAwsWebIdentity, ProviderParamsJwtBearer, ProviderParamsOauth,
        ProviderParamsRa,
    };

    /// `params_digest` binds `endpoint_url` and `region` into what an approval authorizes for
    /// re-send; an approver who cannot see them is signing for a destination never shown.
    #[test]
    fn roles_anywhere_challenge_names_the_exchange_endpoint_and_region() {
        let params = ProviderParams::AwsRolesAnywhere(ProviderParamsRa {
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/ta"
                .to_owned(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:profile/p".to_owned(),
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            cert_der: String::new(),
            key_der: String::new(),
            key_tag: "EC".to_owned(),
            chain_der: Vec::new(),
            region: Some("us-east-1".to_owned()),
            duration_seconds: None,
            role_session_name: None,
            endpoint_url: Some("https://attacker.example".to_owned()),
            identity_type: None,
        });

        let kind = provider_kind(&params);
        assert!(kind.contains("https://attacker.example"), "{kind}");
        assert!(kind.contains("us-east-1"), "{kind}");
        assert!(
            kind.contains("arn:aws:iam::111111111111:role/Dev"),
            "{kind}"
        );
    }

    /// `https_endpoint_opt` validates the URL shape but returns the raw deserialized string, so a
    /// control character in the path (e.g. an ESC byte URL-parsing does not reject) would reach
    /// the terminal verbatim without this escaping.
    #[test]
    fn roles_anywhere_challenge_escapes_control_characters_in_region_and_endpoint() {
        let params = ProviderParams::AwsRolesAnywhere(ProviderParamsRa {
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/ta"
                .to_owned(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:profile/p".to_owned(),
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            cert_der: String::new(),
            key_der: String::new(),
            key_tag: "EC".to_owned(),
            chain_der: Vec::new(),
            region: Some("us-east-1\x1b[2J".to_owned()),
            duration_seconds: None,
            role_session_name: None,
            endpoint_url: Some("https://attacker.example/\x1b[2J".to_owned()),
            identity_type: None,
        });

        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "{kind:?}");
    }

    /// `role_arn` comes from the caller same as `region`/`endpoint_url` and renders before them;
    /// unescaped, it could hide the endpoint from `creds request approve`'s raw terminal output.
    #[test]
    fn roles_anywhere_challenge_escapes_control_characters_in_the_role_arn() {
        let params = ProviderParams::AwsRolesAnywhere(ProviderParamsRa {
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/ta"
                .to_owned(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:profile/p".to_owned(),
            role_arn: "arn:aws:iam::111111111111:role/Dev\x1b[8m".to_owned(),
            cert_der: String::new(),
            key_der: String::new(),
            key_tag: "EC".to_owned(),
            chain_der: Vec::new(),
            region: Some("us-east-1".to_owned()),
            duration_seconds: None,
            role_session_name: None,
            endpoint_url: Some("https://attacker.example".to_owned()),
            identity_type: None,
        });

        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "{kind:?}");
    }

    /// `trust_anchor_arn`/`profile_arn` bound the CreateSession exchange (the profile's session
    /// policy, not `role_arn` alone, caps the minted credential's permissions) and `params_digest`
    /// binds both into the approval; an approver who cannot see them signs for a profile and trust
    /// anchor never shown.
    #[test]
    fn roles_anywhere_challenge_names_the_trust_anchor_and_profile_arns() {
        let params = ProviderParams::AwsRolesAnywhere(ProviderParamsRa {
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/attacker"
                .to_owned(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:profile/attacker".to_owned(),
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            cert_der: String::new(),
            key_der: String::new(),
            key_tag: "EC".to_owned(),
            chain_der: Vec::new(),
            region: Some("us-east-1".to_owned()),
            duration_seconds: None,
            role_session_name: None,
            endpoint_url: None,
            identity_type: None,
        });

        let kind = provider_kind(&params);
        assert!(
            kind.contains("arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/attacker"),
            "{kind}"
        );
        assert!(
            kind.contains("arn:aws:rolesanywhere:us-east-1:111111111111:profile/attacker"),
            "{kind}"
        );
    }

    /// Mirrors the `role_arn` control-character case for `trust_anchor_arn`/`profile_arn`.
    #[test]
    fn roles_anywhere_challenge_escapes_control_characters_in_the_trust_anchor_and_profile_arns() {
        let params = ProviderParams::AwsRolesAnywhere(ProviderParamsRa {
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/ta\x1b[8m"
                .to_owned(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:profile/p\x1b[8m".to_owned(),
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            cert_der: String::new(),
            key_der: String::new(),
            key_tag: "EC".to_owned(),
            chain_der: Vec::new(),
            region: Some("us-east-1".to_owned()),
            duration_seconds: None,
            role_session_name: None,
            endpoint_url: None,
            identity_type: None,
        });

        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "{kind:?}");
    }

    /// `authorization_endpoint` decides where the approver's browser goes to authenticate, and
    /// `client_id`/`region` pick the client the IdP sees and the STS endpoint that receives the
    /// id_token (`assume_role` in credsd-core's oauth provider). An approver who cannot see any
    /// of them is signing for a flow whose destination and client identity stay hidden.
    #[test]
    fn aws_web_identity_challenge_names_the_endpoints_client_and_region() {
        let params = ProviderParams::AwsWebIdentity(ProviderParamsAwsWebIdentity {
            authorization_endpoint: "https://attacker.example/authorize".to_owned(),
            token_endpoint: "https://attacker.example/token".to_owned(),
            client_id: "my-client".to_owned(),
            scopes: vec!["openid".to_owned()],
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            region: "eu-west-1".to_owned(),
            duration_seconds: None,
            role_session_name: None,
            identity_type: None,
            callback_port: None,
        });

        let kind = provider_kind(&params);
        assert!(
            kind.contains("https://attacker.example/authorize"),
            "{kind}"
        );
        assert!(kind.contains("https://attacker.example/token"), "{kind}");
        assert!(kind.contains("my-client"), "{kind}");
        assert!(kind.contains("eu-west-1"), "{kind}");
    }

    /// The approver's challenge names the region the caller set, verbatim. There is no absent
    /// state to disclose: the field is required at parse time.
    #[test]
    fn aws_web_identity_challenge_names_the_region() {
        let params = ProviderParams::AwsWebIdentity(ProviderParamsAwsWebIdentity {
            authorization_endpoint: "https://idp.example.com/authorize".to_owned(),
            token_endpoint: "https://idp.example.com/token".to_owned(),
            client_id: "my-client".to_owned(),
            scopes: vec!["openid".to_owned()],
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            region: "us-west-2".to_owned(),
            duration_seconds: None,
            role_session_name: None,
            identity_type: None,
            callback_port: None,
        });

        let kind = provider_kind(&params);
        assert!(kind.contains("region us-west-2"), "{kind}");
    }

    /// Mirrors the roles-anywhere control-character case for `token_endpoint`.
    #[test]
    fn aws_web_identity_challenge_escapes_control_characters_in_the_token_endpoint() {
        let params = ProviderParams::AwsWebIdentity(ProviderParamsAwsWebIdentity {
            authorization_endpoint: "https://attacker.example/authorize".to_owned(),
            token_endpoint: "https://attacker.example/\x1b[2J".to_owned(),
            client_id: "c".to_owned(),
            scopes: vec!["openid".to_owned()],
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            region: "us-east-1".to_owned(),
            duration_seconds: None,
            role_session_name: None,
            identity_type: None,
            callback_port: None,
        });

        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "{kind:?}");
    }

    /// Mirrors the roles-anywhere `role_arn` control-character case for this arm's `role_arn`.
    #[test]
    fn aws_web_identity_challenge_escapes_control_characters_in_the_role_arn() {
        let params = ProviderParams::AwsWebIdentity(ProviderParamsAwsWebIdentity {
            authorization_endpoint: "https://attacker.example/authorize".to_owned(),
            token_endpoint: "https://attacker.example/token".to_owned(),
            client_id: "c".to_owned(),
            scopes: vec!["openid".to_owned()],
            role_arn: "arn:aws:iam::111111111111:role/Dev\x1b[8m".to_owned(),
            region: "us-east-1".to_owned(),
            duration_seconds: None,
            role_session_name: None,
            identity_type: None,
            callback_port: None,
        });

        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "{kind:?}");
    }

    /// `oauth` and `jwt-bearer` challenges name the exchange endpoint (Requirement 4.1) so an
    /// approver can see where the refresh grant is sent on every unattended renew.
    #[test]
    fn oauth_challenge_names_the_token_endpoint() {
        let params = ProviderParams::Oauth(ProviderParamsOauth {
            token_url: "https://attacker.example/token".to_owned(),
            client_id: "c".to_owned(),
            client_secret: None,
            private_key_pem: None,
            scope: None,
            identity_type: None,
        });
        let kind = provider_kind(&params);
        assert!(kind.contains("https://attacker.example/token"));
    }

    /// `token_url` has no deserialization-time validator at all (unlike `jwt-bearer`'s, which
    /// has `https_endpoint`), so a control character reaches this string unmodified.
    #[test]
    fn oauth_challenge_escapes_control_characters_in_the_token_endpoint() {
        let params = ProviderParams::Oauth(ProviderParamsOauth {
            token_url: "https://attacker.example/\x1b[2J".to_owned(),
            client_id: "c".to_owned(),
            client_secret: None,
            private_key_pem: None,
            scope: None,
            identity_type: None,
        });
        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'));
    }

    #[test]
    fn jwt_bearer_challenge_names_the_token_endpoint() {
        let params = ProviderParams::JwtBearer(ProviderParamsJwtBearer {
            token_url: "https://attacker.example/token".to_owned(),
            assertion: "irrelevant-to-this-test".to_owned(),
            client_id: None,
            scope: None,
            identity_type: None,
        });
        let kind = provider_kind(&params);
        assert!(kind.contains("https://attacker.example/token"));
    }

    /// Mirrors the oauth case for jwt-bearer's own `token_url`.
    #[test]
    fn jwt_bearer_challenge_escapes_control_characters_in_the_token_endpoint() {
        let params = ProviderParams::JwtBearer(ProviderParamsJwtBearer {
            token_url: "https://attacker.example/\x1b[2J".to_owned(),
            assertion: "irrelevant-to-this-test".to_owned(),
            client_id: None,
            scope: None,
            identity_type: None,
        });
        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'));
    }

    /// Mirrors the token-endpoint control-character case for `authorization_endpoint`,
    /// `client_id`, and `region`, the three fields this arm now also renders.
    #[test]
    fn aws_web_identity_challenge_escapes_control_characters_in_the_new_fields() {
        let params = ProviderParams::AwsWebIdentity(ProviderParamsAwsWebIdentity {
            authorization_endpoint: "https://attacker.example/\x1b[2J".to_owned(),
            token_endpoint: "https://attacker.example/token".to_owned(),
            client_id: "c\x1b[8m".to_owned(),
            scopes: vec!["openid".to_owned()],
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            region: "eu-west-1\x1b[2J".to_owned(),
            duration_seconds: None,
            role_session_name: None,
            identity_type: None,
            callback_port: None,
        });

        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "{kind:?}");
        // Pins the escaped form so the assertion above can't pass by dropping the fields
        // instead of escaping them.
        assert!(kind.contains("https://attacker.example/\\x1B[2J"), "{kind}");
        assert!(kind.contains("c\\x1B[8m"), "{kind}");
        assert!(kind.contains("eu-west-1\\x1B[2J"), "{kind}");
    }

    /// `scopes` decides what the minted id_token is authorized for (`assume_role` passes it to the
    /// IdP); a re-bootstrap that keeps every other displayed field identical can still broaden
    /// scopes undisclosed, which is exactly what `params_digest` binds into the approval.
    #[test]
    fn aws_web_identity_challenge_names_the_scopes() {
        let params = ProviderParams::AwsWebIdentity(ProviderParamsAwsWebIdentity {
            authorization_endpoint: "https://attacker.example/authorize".to_owned(),
            token_endpoint: "https://attacker.example/token".to_owned(),
            client_id: "c".to_owned(),
            scopes: vec!["admin:*".to_owned(), "deploy:prod".to_owned()],
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            region: "us-east-1".to_owned(),
            duration_seconds: None,
            role_session_name: None,
            identity_type: None,
            callback_port: None,
        });

        let kind = provider_kind(&params);
        assert!(kind.contains("admin:*"), "{kind}");
        assert!(kind.contains("deploy:prod"), "{kind}");
    }

    fn aws_web_identity_with_scopes(scopes: Vec<String>) -> ProviderParams {
        ProviderParams::AwsWebIdentity(ProviderParamsAwsWebIdentity {
            authorization_endpoint: "https://idp.example/authorize".to_owned(),
            token_endpoint: "https://idp.example/token".to_owned(),
            client_id: "c".to_owned(),
            scopes,
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            region: "us-east-1".to_owned(),
            duration_seconds: None,
            role_session_name: None,
            identity_type: None,
            callback_port: None,
        })
    }

    proptest::proptest! {
        /// `params_digest` tells any two scope lists apart, so the text the approver reads must
        /// too. Adversarial inputs include spaces, quotes, commas, and control characters — the
        /// separators a naive join would let one list impersonate another with.
        #[test]
        fn distinct_scope_lists_render_distinct_challenges(
            a in proptest::collection::vec("[ a-z\"',\\\\\x1b]{0,6}", 0..4),
            b in proptest::collection::vec("[ a-z\"',\\\\\x1b]{0,6}", 0..4),
        ) {
            proptest::prop_assume!(a != b);
            proptest::prop_assert_ne!(
                provider_kind(&aws_web_identity_with_scopes(a)),
                provider_kind(&aws_web_identity_with_scopes(b))
            );
        }
    }

    /// Mirrors the other `aws-web-identity` control-character cases for a scope value.
    #[test]
    fn aws_web_identity_challenge_escapes_control_characters_in_a_scope() {
        let params = ProviderParams::AwsWebIdentity(ProviderParamsAwsWebIdentity {
            authorization_endpoint: "https://attacker.example/authorize".to_owned(),
            token_endpoint: "https://attacker.example/token".to_owned(),
            client_id: "c".to_owned(),
            scopes: vec!["openid\x1b[8m".to_owned()],
            role_arn: "arn:aws:iam::111111111111:role/Dev".to_owned(),
            region: "us-east-1".to_owned(),
            duration_seconds: None,
            role_session_name: None,
            identity_type: None,
            callback_port: None,
        });

        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "{kind:?}");
    }

    /// `client_id`/`scope` decide which OAuth client and authorization breadth the daemon's
    /// client-credentials grant runs under; a same-config re-bootstrap can swap either undisclosed
    /// while `token_url` stays identical.
    #[test]
    fn oauth_challenge_names_the_client_id_and_scope() {
        let params = ProviderParams::Oauth(ProviderParamsOauth {
            token_url: "https://idp.corp/token".to_owned(),
            client_id: "admin-cli".to_owned(),
            client_secret: None,
            private_key_pem: None,
            scope: Some("admin:* deploy:prod".to_owned()),
            identity_type: None,
        });
        let kind = provider_kind(&params);
        assert!(kind.contains("admin-cli"), "{kind}");
        assert!(kind.contains("admin:* deploy:prod"), "{kind}");
    }

    /// Mirrors the token-endpoint control-character case for `client_id`/`scope`.
    #[test]
    fn oauth_challenge_escapes_control_characters_in_the_client_id_and_scope() {
        let params = ProviderParams::Oauth(ProviderParamsOauth {
            token_url: "https://idp.corp/token".to_owned(),
            client_id: "c\x1b[8m".to_owned(),
            client_secret: None,
            private_key_pem: None,
            scope: Some("s\x1b[8m".to_owned()),
            identity_type: None,
        });
        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "{kind:?}");
    }

    /// Mirrors the oauth case for jwt-bearer's own `client_id`/`scope`.
    #[test]
    fn jwt_bearer_challenge_names_the_client_id_and_scope() {
        let params = ProviderParams::JwtBearer(ProviderParamsJwtBearer {
            token_url: "https://idp.corp/token".to_owned(),
            assertion: "irrelevant-to-this-test".to_owned(),
            client_id: Some("admin-cli".to_owned()),
            scope: Some("admin:*".to_owned()),
            identity_type: None,
        });
        let kind = provider_kind(&params);
        assert!(kind.contains("admin-cli"), "{kind}");
        assert!(kind.contains("admin:*"), "{kind}");
    }

    /// Mirrors the oauth control-character case for jwt-bearer's own `client_id`/`scope`.
    #[test]
    fn jwt_bearer_challenge_escapes_control_characters_in_the_client_id_and_scope() {
        let params = ProviderParams::JwtBearer(ProviderParamsJwtBearer {
            token_url: "https://idp.corp/token".to_owned(),
            assertion: "irrelevant-to-this-test".to_owned(),
            client_id: Some("c\x1b[8m".to_owned()),
            scope: Some("s\x1b[8m".to_owned()),
            identity_type: None,
        });
        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "{kind:?}");
    }

    /// IAM user access key ID must be escaped to prevent log-injection attacks.
    /// Control characters in the key ID should not reach logs unescaped.
    #[test]
    fn iam_user_challenge_escapes_control_characters_in_access_key_id() {
        let params = ProviderParams::AwsIamUser(credsd_core::rpc::ProviderParamsIamUser {
            access_key_id: "AKIA\x1b[8mEXAMPLE".to_owned(),
            secret_access_key: "secret".to_owned(),
            region: "us-east-1".to_owned(),
            duration_seconds: None,
            mfa_serial: None,
            identity_type: None,
        });
        let kind = provider_kind(&params);
        assert!(
            !kind.contains('\x1b'),
            "access_key_id escape failed: {kind:?}"
        );
        assert!(kind.contains("iam-user"), "{kind:?}");
    }

    /// AWS SSO start_url, account_id, and role_name must be escaped to prevent log-injection.
    /// Control characters in any of these fields should not reach logs unescaped.
    #[test]
    fn aws_idc_sso_challenge_escapes_control_characters_in_sso_fields() {
        let params = ProviderParams::AwsIdcSso(credsd_core::rpc::ProviderParamsSso {
            start_url: "https://sso.example\x1b[8m".to_owned(),
            account_id: Some("123456\x1b[31m789".to_owned()),
            role_name: Some("Admin\x1b[8m".to_owned()),
            sso_region: "us-east-1".to_owned(),
            identity_type: None,
        });
        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "sso fields escape failed: {kind:?}");
        assert!(kind.contains("aws-idc-sso"), "{kind:?}");
    }
}

/// Two separate `cfg` attributes for the reason the `e2e` module documents: clippy only applies
/// `clippy.toml`'s test allowances to a literal `#[cfg(test)]`.
#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use crate::server::e2e::{EnvVarGuard, DATA_DIR_ENV_LOCK};

    /// A caller root in a temp dir, with `CREDSD_DATA_DIR` pointed at it for as long as this is
    /// held. The env var is process-global, so the harness lock is held too.
    struct Caller {
        uid: u32,
        root: std::path::PathBuf,
        _dir: tempfile::TempDir,
        _env: EnvVarGuard,
        _lock: tokio::sync::MutexGuard<'static, ()>,
    }

    async fn caller() -> Caller {
        let lock = DATA_DIR_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let env = EnvVarGuard::set("CREDSD_DATA_DIR", dir.path());
        credsd_core::config::platform::provision_caller().expect("provision caller root");
        let uid = nix::unistd::getuid().as_raw();
        Caller {
            uid,
            root: caller_root(uid),
            _dir: dir,
            _env: env,
            _lock: lock,
        }
    }

    /// Unreadable records are built as a wrong file type rather than by mode bits, because root
    /// bypasses mode bits and would read the "unreadable" record fine. `EISDIR` and `ENOTDIR`
    /// deny every uid, so the test asserts the same thing whoever runs it.
    #[tokio::test]
    async fn a_sealed_file_that_will_not_read_errors_instead_of_hashing_as_absent() {
        let c = caller().await;
        let absent = records_base(c.uid, &["db"]).expect("absent records hash");

        let sealed_dir = c.root.join("credentials").join("db");
        std::fs::create_dir_all(&sealed_dir).expect("sealed dir");
        std::fs::write(sealed_dir.join("iam_user.enc"), b"sealed").expect("sealed file");
        let present = records_base(c.uid, &["db"]).expect("present records hash");
        assert_ne!(
            present, absent,
            "a credential holding sealed material must not hash as one holding none"
        );

        std::fs::remove_file(sealed_dir.join("iam_user.enc")).expect("remove sealed file");
        std::fs::create_dir(sealed_dir.join("iam_user.enc")).expect("unreadable sealed entry");
        let digest = records_base(c.uid, &["db"]);
        assert!(
            digest.is_err(),
            "a sealed entry that will not read must error, not hash as {:?}",
            digest.map(|d| credsd_core::presence::hex(&d))
        );
    }

    #[tokio::test]
    async fn a_toml_that_will_not_read_errors_instead_of_hashing_as_absent() {
        let c = caller().await;
        let absent = records_base(c.uid, &[]).expect("absent records hash");

        std::fs::create_dir(c.root.join("credentials.toml")).expect("unreadable toml");
        let digest = records_base(c.uid, &[]);
        assert!(
            digest.is_err(),
            "a credentials.toml that will not read must error, not hash as absent ({})",
            credsd_core::presence::hex(&absent)
        );
    }

    /// The gate decision has the same fail-open shape as the digest: an unlistable credential
    /// directory read as "holds nothing" would skip the gate on the material it holds.
    #[tokio::test]
    async fn a_credential_directory_that_will_not_list_errors_instead_of_reading_as_empty() {
        let c = caller().await;
        assert_eq!(
            overwrite_reason(c.uid, "prod", "db").expect("absent credential"),
            None,
            "a credential that does not exist overwrites nothing"
        );

        std::fs::create_dir_all(c.root.join("credentials")).expect("credentials dir");
        std::fs::write(c.root.join("credentials").join("db"), b"not a directory")
            .expect("unlistable credential dir");
        assert!(
            overwrite_reason(c.uid, "prod", "db").is_err(),
            "a credential directory that will not list must error, not read as empty"
        );
    }
}
