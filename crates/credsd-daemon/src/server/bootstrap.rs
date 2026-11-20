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
use credsd_core::config::credentials::{CredentialSource, CredentialSources};
use credsd_core::config::platform::caller_root;
#[cfg(feature = "jwt-bearer")]
use credsd_core::config::JwtBearerConfig;
use credsd_core::config::{
    AwsLoginConfig, AwsWebIdentityConfig, DaemonConfig, IamUserConfig, IdentityType, OauthConfig,
    OauthGrant, RolePair, RolesAnywhereConfig, SsoConfig, StaticSecretConfig,
};
use credsd_core::log::escape_log;
use credsd_core::presence::Challenge;
use credsd_core::providers::aws_login::{
    normalize_name, stored_identity, AwsLoginProvider, Identity, SignedIn,
};
use credsd_core::providers::iam_user::SessionTokenProvider;
use credsd_core::providers::oauth::AwsWebIdentityProvider;
use credsd_core::providers::roles_anywhere::persist_ingested;
use credsd_core::providers::sso::SsoProvider;
use credsd_core::providers::{CredentialProvider, Renewed, Renewer};
use credsd_core::rpc::{
    codec, BootstrapResult, DomainCode, ImportOutcome, ImportParams, ImportStatus, Notification,
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
/// The wait bound is short so a login queued behind another writer answers promptly with a
/// retryable error instead of parking the user. It is not sized to outlast other holders: each
/// bounds its own hold (renewal and logout 60 s), and a holder need not fit inside this wait
/// (`drift-detection` Requirement 5.9).
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
/// Counts the subdirectories of `callers/<uid>/credentials/` this bootstrap would not be reusing:
/// `credential` names the one it would write over, which is already counted and so is excluded.
/// A bootstrap of a credential that exists therefore stores nothing new, and a caller at the cap
/// can still re-authenticate — which `credential/bootstrap` is the routine verb for
/// (`credential-retrieval-api` Req 17 AC 11). `None` is a bootstrap whose name is not settled yet
/// (`name_prefix`), which has no slot to exclude.
///
/// So a caller at the cap re-running a `name_prefix` bootstrap is refused even for a credential it
/// already holds, whose slot would have been excluded had the name been known. That is deliberate:
/// the name is settled only by the sign-in, and refusing before the browser opens is better than
/// after.
///
/// A directory that was created for a credential that later failed leaves an empty slot; those
/// count toward the cap rather than being silently excluded, so the cap is always a reliable upper
/// bound on stored-state size.
fn check_credential_quota(uid: u32, credential: Option<&str>) -> Result<(), RpcError> {
    let creds_dir = caller_root(uid).join("credentials");
    let count = match std::fs::read_dir(&creds_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| credential.is_none_or(|name| e.file_name() != *std::ffi::OsStr::new(name)))
            .count(),
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

/// Refuse an `aws-idc-sso` provider that names one half of the pair, the both-or-neither rule
/// `credential/get` already has (`credential-retrieval-api` Req 17 AC 1, AC 11). Each field is
/// well-formed alone, and a field's own `deserialize_with` cannot see its sibling, so only a check
/// over both catches it: the named half folds in, the other resolves at sign-in, and an approval
/// for "role chosen at sign-in" would then install a pair the approver never saw. Names the
/// fields, never their values.
fn check_sso_pair(provider: &ProviderParams) -> Result<(), RpcError> {
    let ProviderParams::AwsIdcSso(sso) = provider else {
        return Ok(());
    };
    if sso.account_id.is_some() != sso.role_name.is_some() {
        return Err(RpcError::invalid_params(
            "aws_idc_sso needs both account_id and role_name, or neither",
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
    let mut params: ProfileBootstrapParams = request.params_as()?;
    // Before any config or keystore read and before any provider flow, as AC 1 refuses
    // `credential/get`'s half pair: it is decidable from the request alone.
    check_sso_pair(&params.provider)?;
    if let Some(tags) = params.tags.take() {
        let bad = |e: credsd_core::error::DaemonError| match &params.credential {
            Some(name) => RpcError::invalid_params(format!("credential '{name}': {}", e.detail())),
            None => RpcError::invalid_params(e.detail()),
        };
        params.tags = Some(credsd_core::tags::normalize(tags).map_err(bad)?);
    }

    let credential = match (&params.credential, &params.name_prefix, &params.provider) {
        (Some(credential), None, _) => credential.clone(),
        (None, Some(prefix), ProviderParams::AwsLogin(_)) => {
            let prefix = prefix.clone();
            check_credential_quota(uid, None)?;
            return bootstrap_aws_login_by_prefix(
                peer,
                uid,
                daemon,
                params,
                &prefix,
                notif_tx,
                respond_slot,
            )
            .await;
        }
        (None, Some(_), _) => {
            return Err(RpcError::invalid_params(
                "name_prefix is only accepted for an aws_login provider",
            ))
        }
        _ => {
            return Err(RpcError::invalid_params(
                "give exactly one of credential or name_prefix",
            ))
        }
    };
    check_credential_quota(uid, Some(&credential))?;

    // The built-in gate (presence-gated-operations Requirement 1.7). A first bootstrap writes over
    // nothing and runs ungated; one that would replace an existing credential needs presence. Approval grants a one-use
    // authorization for exactly these params against exactly this state, which this re-send
    // spends. The decision is taken twice: here, so an overwrite is refused before any provider
    // flow runs, and again under the write lock at commit, because the records can change while
    // a flow waits on a person for minutes.
    let digest = params_digest("credential/bootstrap", &params)?;
    // Refused before any provider flow runs, so nobody signs in for a write that drift would stop
    // at commit. Not the authoritative check: that is the commit's, under the write lock. Read
    // before the kind is worded, because a kept setting is only nameable from the entry.
    let files =
        TomlFiles::read(uid).map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    precheck_for_write(daemon, uid, &files, BOTH)?;
    let sources = Sources::read(&files, &credential, &params.provider)?;
    let kind = provider_kind(&params.provider, sources.stored.as_ref());
    let subject = Subject {
        credential: &credential,
        kind: &kind,
    };
    let admitted = admit(peer, uid, daemon, &subject, digest, &files, &sources)?;

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
    let mut signed_in: Option<Identity> = None;
    let mut sign_in_stored: Option<oneshot::Sender<()>> = None;
    let tags = params.tags;
    let staged = match params.provider {
        ProviderParams::AwsIdcSso(sso) => bootstrap_sso(
            &data_dir,
            &credential,
            sso,
            stored_sso(sources.stored.as_ref()),
            daemon,
            notif_tx,
            respond_slot,
        )
        .await
        .map(|(staged, stored)| {
            sign_in_stored = Some(stored);
            staged
        }),
        ProviderParams::AwsIamUser(iam) => bootstrap_iam_user(&data_dir, iam, daemon),
        ProviderParams::AwsRolesAnywhere(ra) => bootstrap_ra(&data_dir, ra, daemon),
        ProviderParams::AwsWebIdentity(oauth) => {
            bootstrap_aws_web_identity(&data_dir, &credential, oauth, daemon, notif_tx).await
        }
        ProviderParams::AwsLogin(aws) => {
            bootstrap_aws_login(&data_dir, &credential, aws, daemon, notif_tx, respond_slot)
                .await
                .map(|(staged, identity)| {
                    signed_in = Some(identity);
                    staged
                })
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
        Gate {
            digest,
            admitted,
            signed_in: signed_in.clone(),
            stored_entry: sources.stored.is_some(),
        },
        staging,
        &staged,
        tags.as_ref(),
        daemon,
    )
    .await?;
    // The sign-in is the credential's now, so the record of who signed in may be emitted. A commit
    // that returned above dropped this sender instead, leaving nothing recorded for a sign-in
    // nothing stored.
    if let Some(stored) = sign_in_stored {
        let _ = stored.send(());
    }
    record_mutation(peer, uid, "credential/bootstrap", &credential);
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
        credential = %credential,
        provider = kind.as_str(),
        expires_at = expires_at.as_str(),
        "bootstrap complete"
    );
    match (staged.source, signed_in) {
        (CredentialSource::AwsWebIdentity(config), _) => {
            confirm_aws_web_identity_federates(uid, &credential, config, daemon).await
        }
        (_, Some(identity)) => to_value(BootstrapResult {
            credential: Some(credential),
            identity: Some(identity),
        }),
        _ => to_value(OkResult {}),
    }
}

/// Federate a committed `aws-web-identity` credential once and report the outcome.
async fn confirm_aws_web_identity_federates(
    uid: u32,
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

/// The built-in gate's entry decision for a bootstrap of `subject`, from the `files` the entry's
/// write check verified: `None` when nothing is replaced, or when an `aws-login` sign-in replaces a
/// credential of the same provider source, whose gate depends on who signs in and so is decided at
/// commit (`aws-login-identity` Requirement 2); otherwise the spent approval, or the challenge as
/// the error.
pub(crate) fn admit(
    peer: &PeerInfo,
    uid: u32,
    daemon: &Daemon,
    subject: &Subject<'_>,
    digest: [u8; 32],
    files: &TomlFiles,
    sources: &Sources,
) -> Result<Option<Admitted>, RpcError> {
    let credential = subject.credential;
    let Sources {
        stored, requested, ..
    } = sources;
    let reason = overwrite_reason(uid, credential)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?
        .filter(|_| {
            !requested
                .as_ref()
                .is_some_and(|requested| same_provider_source(stored.as_ref(), requested))
        });
    Ok(match reason {
        None => None,
        Some(reason) => {
            let base = records_base_of(uid, files, &[credential])
                .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
            let Some(approved) = daemon.presence.spend(uid, &digest, &base) else {
                let identity_change = identity_type_change(
                    stored.as_ref(),
                    kept_identity_type(sources.identity_type, stored.as_ref()),
                );
                let challenge = bootstrap_challenge(
                    peer,
                    uid,
                    &Subject {
                        credential,
                        kind: challenge_kind(requested.as_ref(), stored.as_ref(), subject.kind),
                    },
                    &reason,
                    Admission {
                        digest,
                        base,
                        identity_change,
                        sso_change: describe_sso_change(stored.as_ref(), requested.as_ref()),
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
                credential = %credential,
                "presence gate: approved bootstrap authorization spent"
            );
            Some(Admitted {
                pending_operation: approved,
                base,
            })
        }
    })
}

/// The source `files` records for `credential`, or `None` when it records none. Reads the bytes
/// the caller checked, never the file again, so a swap after the check cannot exempt a replace.
/// A file that does not parse, and a credential with sealed material but no entry, both read as
/// no source — neither is ever the same source as a request.
fn stored_source(files: &TomlFiles, credential: &str) -> Option<CredentialSource> {
    std::str::from_utf8(&files.credentials)
        .ok()
        .and_then(|text| credsd_core::config::credentials::from_text(text).ok())
        .and_then(|sources| sources.get(credential).cloned())
}

/// The stored `aws-idc-sso` settings a request's omitted settings are kept from, or `None` when
/// the credential records another source or none.
fn stored_sso(stored: Option<&CredentialSource>) -> Option<&SsoConfig> {
    match stored {
        Some(CredentialSource::AwsIdcSso(config)) => Some(config),
        _ => None,
    }
}

/// What a bootstrap's gate compares, read once from the `credentials.toml` bytes the write check
/// verified: what the credential records, what this request would store over it, and the tier the
/// request named. Read once because the three disagreeing is how a challenge comes to describe a
/// write other than the one performed.
pub(crate) struct Sources {
    stored: Option<CredentialSource>,
    /// `None` for a provider whose replace is never exempt; see [`requested_source`].
    requested: Option<CredentialSource>,
    identity_type: Option<IdentityType>,
}

impl Sources {
    pub(crate) fn read(
        files: &TomlFiles,
        credential: &str,
        provider: &ProviderParams,
    ) -> Result<Self, RpcError> {
        let stored = stored_source(files, credential);
        Ok(Self {
            requested: requested_source(provider, stored.as_ref())?,
            identity_type: provider_identity_type(provider)?,
            stored,
        })
    }
}

/// Whether a bootstrap of `requested` over `stored` replaces only the session rather than the
/// credential. For `aws-login` that is the region and the identity tier: `callback_port` and
/// `remote` are how the sign-in is carried out, not what it signs in to
/// (`aws-login-identity` Decision 4). For `aws-idc-sso` it is every stored setting
/// (`credential-retrieval-api` Req 17 AC 11), which is what `SsoConfig`'s `PartialEq` compares.
/// A tier change is a different source either way, so the gate still discloses it.
fn same_provider_source(stored: Option<&CredentialSource>, requested: &CredentialSource) -> bool {
    match (stored, requested) {
        (Some(CredentialSource::AwsLogin(old)), CredentialSource::AwsLogin(new)) => {
            old.region == new.region && old.identity_type == new.identity_type
        }
        (Some(CredentialSource::AwsIdcSso(old)), CredentialSource::AwsIdcSso(new)) => old == new,
        _ => false,
    }
}

/// Whether the same-source exemption also turns on who signed in. An `aws-login` credential
/// records its Principal, and a sign-in as another one is a replace however equal the settings are
/// (`aws-login-identity` Requirement 2); every other source records nobody, so equal settings are
/// the whole decision. The per-provider half of a decision [`same_provider_source`] takes the other
/// half of, kept beside it and exhaustive without a `_` arm: a source added to the gate must answer
/// this itself rather than inherit whichever side it was written next to.
fn gate_binds_a_principal(source: &CredentialSource) -> bool {
    match source {
        CredentialSource::AwsLogin(_) => true,
        CredentialSource::AwsIdcSso(_)
        | CredentialSource::AwsIamUser(_)
        | CredentialSource::AwsRolesAnywhere(_)
        | CredentialSource::AwsWebIdentity(_)
        | CredentialSource::Jwt(_)
        | CredentialSource::StaticSecret(_)
        | CredentialSource::Oauth(_)
        | CredentialSource::JwtBearer(_)
        | CredentialSource::Unsupported => false,
    }
}

/// The `SsoConfig` a bootstrap of `params` would store over `stored`: each setting the request
/// names, and the stored value of each it omits (`credential-retrieval-api` Req 17 AC 11). An
/// account or role neither side supplies is left empty, which is [`bootstrap_sso`]'s signal to
/// resolve the pair interactively.
///
/// Advisory, not the fold the write installs. The pair it settles is the pair the sign-in runs on,
/// so the sign-in settles it for good; the tier and the allowed list take no part in a sign-in, so
/// [`Staged::written_source`] settles those again at commit, against the entry read under the write
/// lock. The tier is left at the default here and settled by [`kept_identity_type`] alone, in
/// [`requested_source`] and at commit, so no second rule for it can disagree with that one.
fn requested_sso_config(
    params: &credsd_core::rpc::ProviderParamsSso,
    stored: Option<&SsoConfig>,
) -> SsoConfig {
    SsoConfig {
        start_url: params.start_url.clone(),
        sso_region: params.sso_region.clone(),
        account_id: params
            .account_id
            .clone()
            .or_else(|| stored.map(|s| s.account_id.clone()))
            .unwrap_or_default(),
        role_name: params
            .role_name
            .clone()
            .or_else(|| stored.map(|s| s.role_name.clone()))
            .unwrap_or_default(),
        identity_type: IdentityType::default(),
        allowed_roles: kept_allowed_roles(params.allowed_roles.as_deref(), stored),
    }
}

/// The source a bootstrap of `provider` would store over `stored`, for the gate to compare, or
/// `None` for a provider whose replace is never exempt. Only `aws-idc-sso` folds the stored
/// settings in: `aws-login`'s gate compares what the request names and nothing else. The tier is
/// [`kept_identity_type`]'s for either, as it is at commit.
fn requested_source(
    provider: &ProviderParams,
    stored: Option<&CredentialSource>,
) -> Result<Option<CredentialSource>, RpcError> {
    let mut requested = match provider {
        ProviderParams::AwsLogin(p) => CredentialSource::AwsLogin(AwsLoginConfig {
            region: p.region.clone(),
            callback_port: p.callback_port,
            remote: p.remote,
            identity_type: IdentityType::default(),
        }),
        ProviderParams::AwsIdcSso(p) => {
            CredentialSource::AwsIdcSso(requested_sso_config(p, stored_sso(stored)))
        }
        _ => return Ok(None),
    };
    requested.set_identity_type(kept_identity_type(
        provider_identity_type(provider)?,
        stored,
    ));
    Ok(Some(requested))
}

/// Whether `current` is the Principal recorded for the credential in `dir`
/// (`aws-login-identity` Requirement 2.1). A record that is absent or will not open is never a
/// match (Requirement 5.2).
fn signs_in_as_recorded(daemon: &Daemon, dir: &std::path::Path, current: &Identity) -> bool {
    stored_identity(&daemon.encryption, dir).is_some_and(|stored| stored.same_principal(current))
}

/// The params digest an identity-change approval authorizes: the bootstrap's own digest plus the
/// Principal on record (or its absence) and the Principal that signed in. An approval shown one
/// move is therefore never spent on another: not by a re-run that signs in as someone else, nor
/// after the record has changed (`aws-login-identity` Requirement 3.3). The session is left out,
/// because the re-run's sign-in gets a new one.
fn identity_bound_digest(
    params: &[u8; 32],
    previous: Option<&Identity>,
    current: &Identity,
) -> [u8; 32] {
    fn principal(bytes: &mut Vec<u8>, id: &Identity) {
        for part in [&id.partition, &id.account, &id.kind, &id.name] {
            bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
            bytes.extend_from_slice(part.as_bytes());
        }
    }
    let mut bytes = b"aws-login-identity\0".to_vec();
    bytes.extend_from_slice(params);
    match previous {
        None => bytes.push(0),
        Some(previous) => {
            bytes.push(1);
            principal(&mut bytes, previous);
        }
    }
    principal(&mut bytes, current);
    credsd_core::presence::sha256(&bytes)
}

/// The challenge description for an identity change under the same provider source: who the
/// credential signed in as, and who it would sign in as now.
fn describe_identity_change(
    subject: &Subject<'_>,
    previous: Option<&Identity>,
    current: &Identity,
) -> String {
    let who = |i: &Identity| {
        format!(
            "{} {} in account {} ({})",
            escape_log(&i.kind),
            escape_log(&i.name),
            escape_log(&i.account),
            escape_log(&i.partition)
        )
    };
    let was = previous.map_or_else(|| "no recorded sign-in".to_owned(), who);
    format!(
        "replace existing credential '{credential}' with a new {kind} signed in as {now}; it was \
         {was}",
        credential = subject.credential,
        kind = subject.kind,
        now = who(current),
    )
}

/// `credential/login` replaces nothing but the session, so it saves only a sign-in as the
/// Principal on record. Anything else is refused with nothing saved: changing who a credential
/// signs in as is a replace, and a replace goes through the gated bootstrap
/// (`aws-login-identity` Requirement 3.6).
pub(crate) fn login_identity_check(
    credential: &str,
    previous: Option<&Identity>,
    current: &Identity,
) -> Result<(), RpcError> {
    if previous.is_some_and(|p| p.same_principal(current)) {
        return Ok(());
    }
    let was = previous.map_or_else(
        || "it has no recorded sign-in".to_owned(),
        |p| {
            format!(
                "it is recorded for {} {} in account {}",
                escape_log(&p.kind),
                escape_log(&p.name),
                escape_log(&p.account)
            )
        },
    );
    Err(RpcError::domain(
        DomainCode::IdentityMismatch,
        format!(
            "credential '{credential}' signed in as {} {} in account {}, but {was}; nothing was \
             saved. Signing in as another account or role replaces the credential, which needs \
             approval: re-run 'creds bootstrap --credential {credential}' with its aws-login \
             provider",
            escape_log(&current.kind),
            escape_log(&current.name),
            escape_log(&current.account),
        ),
    ))
}

/// `credential/bootstrap` with `name_prefix`: sign in first, then name the credential from the
/// identity (`aws-login-identity` Requirement 4) and gate it under that name.
async fn bootstrap_aws_login_by_prefix(
    peer: &PeerInfo,
    uid: u32,
    daemon: &Daemon,
    params: ProfileBootstrapParams,
    prefix: &str,
    notif_tx: mpsc::Sender<Vec<u8>>,
    respond_slot: RespondSlot,
) -> Result<Value, RpcError> {
    if prefix.len() > MAX_NAME_PREFIX_LEN
        || credsd_core::config::credentials::validate_name(prefix).is_err()
    {
        return Err(RpcError::invalid_params(format!(
            "name_prefix must be a valid credential name of at most {MAX_NAME_PREFIX_LEN} characters"
        )));
    }
    let ProviderParams::AwsLogin(aws) = &params.provider else {
        return Err(RpcError::invalid_params(
            "name_prefix is only accepted for an aws_login provider",
        ));
    };
    let digest = params_digest("credential/bootstrap", &params)?;
    let files =
        TomlFiles::read(uid).map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    precheck_for_write(daemon, uid, &files, BOTH)?;

    let staging = Staging::create(uid)?;
    let (provider, signed, config, identity_type) = sign_in_aws_login(
        staging.path(),
        prefix,
        aws.clone(),
        daemon,
        notif_tx.clone(),
        respond_slot.clone(),
    )
    .await?;
    // The name the identity decides, so the entry this would replace is only knowable here.
    let credential = normalize_name(&signed.identity.name_under(prefix));
    let sources = Sources::read(&files, &credential, &params.provider)?;
    let kind = provider_kind(&params.provider, sources.stored.as_ref());
    let subject = Subject {
        credential: &credential,
        kind: &kind,
    };
    let admitted = admit(peer, uid, daemon, &subject, digest, &files, &sources)?;
    let identity = signed.identity.clone();
    provider
        .commit(signed)
        .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;
    let staged = Staged {
        source: CredentialSource::AwsLogin(config),
        identity_type,
        allowed_roles: None,
    };
    commit_bootstrap(
        uid,
        peer,
        &subject,
        Gate {
            digest,
            admitted,
            signed_in: Some(identity.clone()),
            stored_entry: sources.stored.is_some(),
        },
        staging,
        &staged,
        params.tags.as_ref(),
        daemon,
    )
    .await?;
    record_mutation(peer, uid, "credential/bootstrap", &credential);
    daemon.evict_caller(uid);
    info!(credential = %credential, provider = kind.as_str(), "bootstrap complete");
    to_value(BootstrapResult {
        credential: Some(credential),
        identity: Some(identity),
    })
}

/// Longest `name_prefix` accepted, so the 55-character cut keeps some of the identity.
const MAX_NAME_PREFIX_LEN: usize = 32;

/// What the entry check decided, for the commit to hold the bootstrap to.
pub(crate) struct Gate {
    /// The digest of these params, for a challenge raised at commit.
    pub(crate) digest: [u8; 32],
    /// The approval entry spent, or `None` when the entry check found nothing to overwrite.
    pub(crate) admitted: Option<Admitted>,
    /// Who an `aws-login` sign-in signed in as. A replace under the same provider source is
    /// ungated only when this is the Principal on record (`aws-login-identity` Requirement 2).
    pub(crate) signed_in: Option<Identity>,
    /// Whether the entry check read a source entry for this credential.
    pub(crate) stored_entry: bool,
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
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input to the one commit; bundling them would only rename them"
)]
pub(crate) async fn commit_bootstrap(
    uid: u32,
    peer: &PeerInfo,
    subject: &Subject<'_>,
    gate: Gate,
    staging: Staging,
    staged: &Staged,
    tags: Option<&credsd_core::tags::Tags>,
    daemon: &Daemon,
) -> Result<(), RpcError> {
    let target = caller_root(uid)
        .join("credentials")
        .join(subject.credential);
    let guard = daemon.write_guard(uid).await;
    let read = TomlFiles::read(uid)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))
        .and_then(|files| {
            // The shared write check (drift-detection Requirement 5.8), under the lock the write
            // below holds, against the bytes it writes from.
            let verified = verify_for_write(daemon, &guard.held(), uid, &files, BOTH)?;
            // The settings the sign-in ran on, against the entry as it now stands, under the lock
            // the write holds (`credential-retrieval-api` Req 17 AC 11).
            let stored = stored_source(&files, subject.credential);
            let written = staged.written_source(stored.as_ref());
            let same_source = same_provider_source(stored.as_ref(), &written);
            let gated = match overwrite_reason(uid, subject.credential)
                .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?
            {
                None => None,
                // A source that records no Principal is settled by equal settings alone; one that
                // does has its record read here, under the lock, so nothing can change it between
                // this decision and the install.
                Some(_)
                    if same_source
                        && (!gate_binds_a_principal(&written)
                            || gate.signed_in.as_ref().is_some_and(|current| {
                                signs_in_as_recorded(daemon, &target, current)
                            })) =>
                {
                    None
                }
                Some(reason) => Some((
                    reason,
                    records_base_of(uid, &files, &[subject.credential])
                        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?,
                    same_source,
                )),
            };
            Ok((files, verified, gated, stored, written))
        });
    let (files, mut verified, gated, stored, written) = match (read, &gate.admitted) {
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
    // The entry whose omitted settings the staged source was folded against is gone. Installing
    // now would recreate the credential from a removed entry's settings, ungated because there is
    // nothing left to overwrite, and at the tier a credential with no source on record takes — a
    // combination nobody was shown. Re-gating would ask for an approval the re-run then has no use
    // for, since a create is ungated by design (`presence-gated-operations` Req 1.7), so the
    // sign-in is refused and the re-run starts from the request alone.
    if gate.stored_entry && stored.is_none() {
        if let Some(admitted) = &gate.admitted {
            info!(
                event = "presence.discarded",
                pending_operation = admitted.pending_operation.as_str(),
                credential = %subject.credential,
                outcome = "discarded: the credential it would replace was removed while the \
                           sign-in ran",
                "presence gate"
            );
        }
        return Err(RpcError::domain(
            DomainCode::ProviderUnavailable,
            format!(
                "credential '{credential}' was removed while you were signing in, so that sign-in \
                 was discarded and nothing was saved; re-run the bootstrap to create it again",
                credential = subject.credential
            ),
        ));
    }
    match (gated, gate.signed_in.as_ref()) {
        (None, _) => {}
        // A different Principal, or none on record, under the same provider source: the gate,
        // bound to who signed in (`aws-login-identity` Requirement 3).
        (Some((_, base, true)), Some(current)) => {
            // Read under the lock, so the pair the digest names is the pair the install acts on.
            let previous = stored_identity(&daemon.encryption, &target);
            let digest = identity_bound_digest(&gate.digest, previous.as_ref(), current);
            let Some(approved) = daemon.presence.spend(uid, &digest, &base) else {
                let challenge = daemon.presence.raise(
                    peer,
                    uid,
                    Op::Bootstrap {
                        credential: subject.credential.to_owned(),
                        params: digest,
                        base,
                    },
                    describe_identity_change(subject, previous.as_ref(), current),
                );
                let remediation = format!(
                    "this sign-in is for a different account or role than the credential \
                     records, so nothing was saved. sudo creds request approve {id}, then re-run \
                     the same bootstrap and sign in as the same account and role again",
                    id = challenge.id
                );
                return Err(RpcError::approval_required(&challenge, remediation));
            };
            info!(
                event = "presence.spent",
                pending_operation = approved.as_str(),
                credential = %subject.credential,
                "presence gate: approved identity change spent"
            );
        }
        (Some((reason, base, _)), _) => {
            if gate.admitted.as_ref().map(|a| a.base) != Some(base) {
                let identity_change =
                    identity_type_change(stored.as_ref(), written.identity_type());
                let challenge = bootstrap_challenge(
                    peer,
                    uid,
                    &Subject {
                        credential: subject.credential,
                        kind: challenge_kind(Some(&written), stored.as_ref(), subject.kind),
                    },
                    &reason,
                    Admission {
                        digest: gate.digest,
                        base,
                        identity_change,
                        sso_change: describe_sso_change(stored.as_ref(), Some(&written)),
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
    }
    staging
        .install(&target, &daemon.encryption)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    write_caller_state_locked(
        subject.credential,
        staged,
        stored.as_ref(),
        tags,
        &files,
        &mut verified,
        &daemon.encryption,
    )?;
    daemon.integrity.write(verified)
}

/// What a provider flow produced: sealed material in staging, the source entry that will describe
/// it once committed, and — for each setting no sign-in takes part in — what the request named, so
/// the commit can settle the ones it did not against the entry it reads under the write lock.
/// `None` is a setting the request left to the credential.
pub(crate) struct Staged {
    pub(crate) source: CredentialSource,
    pub(crate) identity_type: Option<IdentityType>,
    pub(crate) allowed_roles: Option<Vec<RolePair>>,
}

impl Staged {
    /// The source this write installs: the settings the sign-in ran on, carrying the tier and the
    /// `aws-idc-sso` allowed list settled against `stored` — the entry read under the write lock
    /// that performs the write (`credential-retrieval-api` Req 17 AC 11). The gate's same-source
    /// decision, the challenge's disclosure, and the write all read it, so none of them can act on
    /// a setting another would not write.
    ///
    /// The pair is not settled again here: the sign-in ran on it, so a credential whose pair moved
    /// meanwhile is a different source and keeps its gate rather than quietly taking the new pair
    /// with a token brokered for the old one.
    fn written_source(&self, stored: Option<&CredentialSource>) -> CredentialSource {
        let mut source = self.source.clone();
        if let CredentialSource::AwsIdcSso(config) = &mut source {
            config.allowed_roles =
                kept_allowed_roles(self.allowed_roles.as_deref(), stored_sso(stored));
        }
        source.set_identity_type(kept_identity_type(self.identity_type, stored));
        source
    }
}

/// The identity tier a write carries: the one the request names, or — when it names none — the
/// stored credential's own, which is what `docs/reference/api.md` documents for every provider.
/// The default is for a credential with no source on record; taking it for one that has a source
/// would promote an `automation` credential to `human` on every repeat bootstrap that omits the
/// field.
fn kept_identity_type(
    requested: Option<IdentityType>,
    stored: Option<&CredentialSource>,
) -> IdentityType {
    requested
        .or_else(|| stored.map(CredentialSource::identity_type))
        .unwrap_or_default()
}

/// The `allowed_roles` a write carries: the list the request names — empty included, which clears
/// the stored one — or, when it names none, the credential's own (`credential-retrieval-api` Req 17
/// AC 11). A credential recording another source, or none, keeps nothing.
fn kept_allowed_roles(requested: Option<&[RolePair]>, stored: Option<&SsoConfig>) -> Vec<RolePair> {
    requested
        .map(<[RolePair]>::to_vec)
        .or_else(|| stored.map(|s| s.allowed_roles.clone()))
        .unwrap_or_default()
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
    /// binding. The error stays typed, so the caller's relay renders its category once.
    fn install(
        mut self,
        target: &std::path::Path,
        enc: &credsd_core::encryption::EncryptionService,
    ) -> credsd_core::error::Result<()> {
        // Re-bind each sealed file to its final path's AAD before the directory rename.
        // Files were sealed with the staging path as AAD; after rename the path changes,
        // so open_from_file at the final location would derive a different AAD and fail.
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            let staging_file = entry.path();
            if staging_file.extension().and_then(|e| e.to_str()) == Some("enc") {
                let final_file = target.join(entry.file_name());
                enc.rebind_file(&staging_file, &final_file)?;
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
                return Err(e.into());
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
    pub(crate) credential: &'a str,
    /// The provider being bootstrapped, as [`provider_kind`] renders it. Each challenge narrows it
    /// with [`challenge_kind`] against the entry that challenge's clauses were worded from, rather
    /// than carrying one decision taken before the sign-in ran.
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
    /// The `aws-idc-sso` settings this write would change, already worded, or empty for every
    /// other source (`credential-retrieval-api` Req 17 AC 11).
    sso_change: String,
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
            credential: subject.credential.to_owned(),
            params: admission.digest,
            base: admission.base,
        },
        describe_overwrite(
            reason,
            subject,
            admission.identity_change,
            &admission.sso_change,
        ),
    )
}

/// What an existing subject would lose to this bootstrap, or `None` for a first bootstrap that
/// writes over nothing.
#[derive(Debug, PartialEq, Eq)]
enum Overwrite {
    /// The credential already has a source entry or sealed material.
    Credential,
}

/// What a bootstrap would overwrite, or `None` for a first bootstrap that writes over nothing.
/// Asked only of records the shared write check has verified: content no snapshot vouches for is
/// refused there as drift, never offered for approval here, because revalidation is the only way
/// to ratify it (drift-detection Requirements 3.9, 4).
fn overwrite_reason(uid: u32, credential: &str) -> std::io::Result<Option<Overwrite>> {
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
        Ok((_, credentials)) => credentials
            .contains_key(credential)
            .then_some(Overwrite::Credential),
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

/// The identity_type an existing credential would lose to this write (Requirement 4.1). `None`
/// when the credential is not on record yet or the value is unchanged: only an actual
/// privilege-tier change is disclosed, matching `config/set`'s wording for the same field.
///
/// `written` is the tier the write would store, not the one the request named, so a challenge
/// cannot drop a rewrite the write would still make — nor name one it would not. `stored` is read
/// from the `credentials.toml` bytes the write check verified; an unparseable one never reaches
/// here, since `verify_records` refuses it as drift first.
fn identity_type_change(
    stored: Option<&CredentialSource>,
    written: IdentityType,
) -> Option<(IdentityType, IdentityType)> {
    stored
        .map(CredentialSource::identity_type)
        .filter(|current| *current != written)
        .map(|current| (current, written))
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
#[cfg(test)]
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

/// What a challenge calls the provider: the source type alone where the change and kept clauses
/// name every setting themselves (`credential-retrieval-api` Req 17 AC 11), since the same values
/// repeated beside those clauses carry no label saying whether each one moves or is kept.
///
/// Only an `aws-idc-sso` sign-in over an `aws-idc-sso` credential gets those clauses. A first
/// bootstrap, or one replacing another source, keeps the full rendering: there is no diff to
/// describe, so the kind is the only thing that can name the pair and the allowed list the
/// approval covers (AC 10).
///
/// Decided from the entry whose clauses will sit beside it — which for the commit's challenge is
/// the entry read under the write lock, not the one the handler started from. An entry that moved
/// to another source while the sign-in ran has no clauses, so the short label there would name
/// neither the pair nor the allowed list.
fn challenge_kind<'a>(
    written: Option<&CredentialSource>,
    stored: Option<&CredentialSource>,
    audit_kind: &'a str,
) -> &'a str {
    match (written, stored) {
        (Some(CredentialSource::AwsIdcSso(_)), Some(CredentialSource::AwsIdcSso(_))) => {
            "aws-idc-sso"
        }
        _ => audit_kind,
    }
}

/// The provider being bootstrapped, as a challenge names it: its kind and the target it binds,
/// never a secret. Also the `provider` field of the `bootstrap complete` audit record.
///
/// `stored` is the source the credential records, so an `aws-idc-sso` request is named by the
/// settings its sign-in will run on rather than by what the request happened to spell out: an
/// omitted account, role, or allowed list is kept from the credential (`credential-retrieval-api`
/// Req 17 AC 11), and naming the raw params would tell the approver a kept pair is chosen at
/// sign-in. Only a pair neither side supplies is.
fn provider_kind(provider: &ProviderParams, stored: Option<&CredentialSource>) -> String {
    match provider {
        ProviderParams::AwsIdcSso(p) => {
            let sso = requested_sso_config(p, stored_sso(stored));
            let chosen_at_sign_in = |value: &str| {
                if value.is_empty() {
                    "chosen at sign-in".to_owned()
                } else {
                    escape_log(value).to_string()
                }
            };
            format!(
                "aws-idc-sso ({} → account {}, role {}{})",
                escape_log(&sso.start_url),
                chosen_at_sign_in(&sso.account_id),
                chosen_at_sign_in(&sso.role_name),
                sso.allowed_roles
                    .iter()
                    .map(|r| format!(
                        "; also allowing account {}, role {}",
                        escape_log(&r.account_id),
                        escape_log(&r.role_name)
                    ))
                    .collect::<String>()
            )
        }
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

/// The identity_type a bootstrap's provider params name — every `ProviderParams` variant carries
/// the same field. Refused here when it does not parse, before the fold and before any provider
/// flow runs, so `None` only ever means a request that named no tier: read as `None`, a malformed
/// tier folded to the stored one, counted as the same source, and cleared the entry check, leaving
/// the provider's own parse to refuse it after the browser had already opened.
fn provider_identity_type(provider: &ProviderParams) -> Result<Option<IdentityType>, RpcError> {
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
    parse_identity_type(raw)
}

/// Requirement 4.1's suffix for an identity_type an approval would also rewrite, appended to both
/// bootstrap's and import's overwrite wording — phrased like `config/set`'s explicit
/// `key = value` text for the same field, so the ride-along is as visible as the explicit path.
/// Names the credential explicitly, since the identity_type is the credential's own.
fn describe_identity_type_change(
    credential: &str,
    change: Option<(IdentityType, IdentityType)>,
) -> String {
    match change {
        Some((old, new)) => {
            format!(
                ", and change credential '{credential}''s identity_type from '{old}' to '{new}'"
            )
        }
        None => String::new(),
    }
}

/// One `allowed_roles` list as the approver reads it, or `none` for an empty one.
fn describe_role_pairs(pairs: &[credsd_core::config::RolePair]) -> String {
    if pairs.is_empty() {
        return "none".to_owned();
    }
    pairs
        .iter()
        .map(|pair| {
            format!(
                "{}/{}",
                escape_log(&pair.account_id),
                escape_log(&pair.role_name)
            )
        })
        .collect::<Vec<_>>()
        .join(" and ")
}

/// Requirement 17 AC 11's clauses for a replace of an `aws-idc-sso` credential: one per changed
/// setting, by its stored key with its old and new value, and — when the instance moves — a
/// trailing parenthetical for the settings that carry over to it, so a reader can tell a value
/// that changes from one that is kept. Empty for every other source, and for a repeat that
/// changes nothing.
///
/// `identity_type` is deliberately absent: [`describe_identity_type_change`] already names it by
/// its stored key with both values, and saying it twice reads as two changes.
fn describe_sso_change(
    stored: Option<&CredentialSource>,
    requested: Option<&CredentialSource>,
) -> String {
    let (Some(CredentialSource::AwsIdcSso(old)), Some(CredentialSource::AwsIdcSso(new))) =
        (stored, requested)
    else {
        return String::new();
    };
    // Exhaustive, with no `..`: a setting added to `SsoConfig` joins the same-source comparison
    // through its `PartialEq`, so it would gate a request with no clause saying what changed
    // unless adding it fails to compile here first.
    let SsoConfig {
        start_url,
        sso_region,
        account_id,
        role_name,
        // Named by `describe_identity_type_change` instead; see below.
        identity_type: _,
        allowed_roles,
    } = new;
    let mut clauses: Vec<String> = Vec::new();
    for (key, was, now) in [
        ("start_url", &old.start_url, start_url),
        ("sso_region", &old.sso_region, sso_region),
        ("account_id", &old.account_id, account_id),
        ("role_name", &old.role_name, role_name),
    ] {
        if was != now {
            clauses.push(format!(
                "change {key} from {} to {}",
                escape_log(was),
                escape_log(now)
            ));
        }
    }
    if old.allowed_roles != *allowed_roles {
        clauses.push(format!(
            "change allowed_roles from {} to {}",
            describe_role_pairs(&old.allowed_roles),
            describe_role_pairs(allowed_roles)
        ));
    }
    if clauses.is_empty() {
        return String::new();
    }
    let mut kept: Vec<String> = Vec::new();
    if old.start_url != *start_url || old.sso_region != *sso_region {
        let same_account = old.account_id == *account_id;
        let same_role = old.role_name == *role_name;
        if same_account && same_role {
            kept.push(format!(
                "account {} role {}",
                escape_log(&old.account_id),
                escape_log(&old.role_name)
            ));
        } else if same_account {
            kept.push(format!("account {}", escape_log(&old.account_id)));
        } else if same_role {
            kept.push(format!("role {}", escape_log(&old.role_name)));
        }
        if old.allowed_roles == *allowed_roles && !old.allowed_roles.is_empty() {
            kept.push(format!(
                "allowed_roles {}",
                describe_role_pairs(&old.allowed_roles)
            ));
        }
    }
    let kept = if kept.is_empty() {
        String::new()
    } else {
        format!(" (kept on the new sign-in: {})", kept.join(", "))
    };
    format!("; {}{kept}", clauses.join("; "))
}

/// The challenge's description (Requirement 4.1): what would be replaced, never the new secret.
fn describe_overwrite(
    reason: &Overwrite,
    subject: &Subject<'_>,
    identity_change: Option<(IdentityType, IdentityType)>,
    sso_change: &str,
) -> String {
    let Subject { credential, kind } = subject;
    let base = match reason {
        Overwrite::Credential => format!(
            "replace existing credential '{credential}' (source and sealed material) with a new \
             {kind}"
        ),
    };
    format!(
        "{base}{sso_change}{}",
        describe_identity_type_change(credential, identity_change)
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

    let (_, credentials) = DaemonConfig::load_from(&caller_root)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    // Login is credential-addressed: one credential, named (credential-retrieval-api Requirement
    // 15 AC 10). A credential the caller does not hold misses as `CREDENTIAL_NOT_FOUND`.
    if !credentials.contains_key(&params.credential) {
        return Err(RpcError::domain(
            DomainCode::CredentialNotFound,
            "credential not found",
        ));
    }
    let cred = params.credential;
    {
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
                )
                .await
            },
        )
        .await
        .map_err(|expired| login_lock_error(&expired, &cred))??;
        if resealed {
            record_mutation(peer, uid, "credential/login", &cred);
        }
    }

    to_value(OkResult {})
}

/// Handle `credential/import`: seal one discovered static-key credential into the caller's
/// per-uid tree. A client importing several profiles makes one call per profile.
///
/// Non-streaming — routed through the normal dispatch path, not the streaming interceptor.
/// Additive: an invalid name or one that already exists is a skip, not an error (Req 2.4). `dry_run` evaluates the same decision against the real tree and writes
/// nothing (Req 2.5). Auto-provisions `callers/<uid>/owner` for a first-time caller, matching
/// bootstrap (Req 2.7).
pub async fn handle_profile_import(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let uid = authorize_for_bootstrap(peer)?;
    let params: ImportParams = request.params_as()?;
    let profiles = std::slice::from_ref(&params.profile);

    // Validate before writing anything: an empty secret or a bad identity_type is a request error.
    let identity_types = validate_import_profiles(profiles)?;

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
    // entry — an existing name is skipped — but its seal can land on sealed material left behind.
    // Import writes no environment (credential-retrieval-api Requirement 16). One challenge covers
    // the whole batch: an import run is one decision, and approving it profile by profile would
    // only train the approver to click.
    if !params.dry_run {
        gate_import(uid, peer, &params, &existing, &files, daemon)?;
    }

    let mut outcomes = Vec::with_capacity(1);
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
    for outcome in outcomes
        .iter()
        .filter(|o| o.status == ImportStatus::Imported)
    {
        record_mutation(peer, uid, "credential/import", &outcome.name);
    }
    result?;
    let outcome = outcomes
        .pop()
        .ok_or_else(|| RpcError::internal("import produced no outcome"))?;
    to_value(outcome)
}

/// One profile `gate_import` would overwrite: what it would replace, and the access key id the
/// challenge must name (Requirement 4.1) — the only fact that distinguishes a benign re-import
/// from a key substitution, and non-secret by AWS's own definition of an access key id.
///
/// No identity_type rewrite to disclose, unlike bootstrap's overwrite: `import::decide` returns
/// `Import` only for a name `existing` does not hold, so a gated profile has no entry and so no
/// stored tier the write could rewrite. What it overwrites is sealed material no entry describes.
struct ImportOverwrite<'a> {
    name: &'a str,
    reason: Overwrite,
    access_key_id: &'a str,
}

/// Refuse an import that would overwrite, unless an approval for exactly this batch against
/// exactly this state is waiting to be spent.
fn gate_import(
    uid: u32,
    peer: &PeerInfo,
    params: &ImportParams,
    existing: &CredentialSources,
    files: &TomlFiles,
    daemon: &Daemon,
) -> Result<(), RpcError> {
    let mut overwrites: Vec<ImportOverwrite<'_>> = Vec::new();
    let profiles = std::slice::from_ref(&params.profile);
    for profile in profiles {
        let fresh = matches!(
            credsd_core::import::decide(&profile.name, &profile.region, existing),
            credsd_core::import::Decision::Import
        );
        if fresh && !overwrites.iter().any(|o| o.name == profile.name) {
            if let Some(reason) = overwrite_reason(uid, &profile.name)
                .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?
            {
                overwrites.push(ImportOverwrite {
                    name: profile.name.as_str(),
                    reason,
                    access_key_id: profile.access_key_id.as_str(),
                });
            }
        }
    }
    if overwrites.is_empty() {
        return Ok(());
    }
    let names: Vec<&str> = overwrites.iter().map(|o| o.name).collect();
    let digest = params_digest("credential/import", params)?;
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
            let (name, key) = (o.name, escape_log(o.access_key_id));
            match &o.reason {
                Overwrite::Credential => format!(
                    "replace sealed data left on disk for credential '{name}' with a new \
                     iam-user (access key {key})"
                ),
            }
        })
        .collect();
    let challenge = daemon.presence.raise(
        peer,
        uid,
        Op::Import {
            credentials: names.iter().map(|n| (*n).to_owned()).collect(),
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
    let dry_run = params.dry_run;
    for (profile, &identity_type) in std::slice::from_ref(&params.profile)
        .iter()
        .zip(identity_types)
    {
        let decision = credsd_core::import::decide(&profile.name, &profile.region, state.existing);
        let (status, reason) = match decision {
            credsd_core::import::Decision::Skip(reason) => {
                let status = if dry_run {
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
                if !dry_run {
                    // Mark the batch as written *before* the seal: persist_iam_user_locked can
                    // fail partway (the key file sealed, or credentials.toml written, before an
                    // error), and the caller must still evict the cache on that abort. Setting the
                    // flag only after full success would skip eviction for a partial write. A false
                    // positive (persist fails before touching disk) only forces a harmless reload.
                    *wrote = true;
                    let staged = Staged {
                        source: CredentialSource::AwsIamUser(config.clone()),
                        identity_type,
                        allowed_roles: None,
                    };
                    // The same seal+write bootstrap uses. `files` carries forward each write's
                    // result, so the next profile in the batch edits from what this one just
                    // wrote, not the snapshot read before the batch started.
                    let mut verified =
                        verify_for_write(daemon, &state.held, uid, state.files, BOTH)?;
                    persist_iam_user_locked(
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
                let status = if dry_run {
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

/// `stored` is the credential's existing `aws-idc-sso` settings, which a request's omitted
/// settings are kept from (`credential-retrieval-api` Req 17 AC 11); `None` for a credential with
/// no entry to read. Advisory here: it decides whether to prompt for a pair, and the commit folds
/// what the sign-in takes no part in again, against the entry it reads under the write lock.
///
/// The returned sender releases the signed-in-user record: the caller sends on it once the commit
/// has stored the sign-in, and drops it otherwise.
async fn bootstrap_sso(
    data_dir: &std::path::Path,
    credential: &str,
    params: credsd_core::rpc::ProviderParamsSso,
    stored: Option<&SsoConfig>,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
    respond_slot: RespondSlot,
) -> Result<(Staged, oneshot::Sender<()>), RpcError> {
    let identity_type = parse_identity_type(params.identity_type.as_deref())?;
    let mut config = requested_sso_config(&params, stored);
    let temp_config = SsoConfig {
        start_url: params.start_url.clone(),
        sso_region: params.sso_region.clone(),
        account_id: String::new(),
        role_name: String::new(),
        identity_type: Default::default(),
        allowed_roles: Vec::new(),
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

    // Account/role resolution: use the request's pair, or the credential's own, and ask the
    // client only when neither supplies one. A re-authentication therefore needs no selection,
    // which a non-interactive sign-in could never answer.
    if config.account_id.is_empty() || config.role_name.is_empty() {
        let (account_id, role_name) = {
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
        };
        config.account_id = account_id;
        config.role_name = role_name;
    }

    // After the pair is final, so the lookup uses the pair the sign-in is stored with — the pair
    // the commit installs, which settles every setting but this one again and leaves this one as
    // the sign-in ran it. Off this path entirely, so the response does not wait on it and the
    // window for the entry to move before commit does not widen.
    let token = Zeroizing::new(cached_token.access_token.clone());
    let (account_id, role_name) = (config.account_id.clone(), config.role_name.clone());
    let (sign_in_stored, stored_by_the_commit) = oneshot::channel();
    audit_signed_in_user(
        credential,
        &config.account_id,
        &config.role_name,
        stored_by_the_commit,
        async move {
            provider
                .signed_in_user(&token, &account_id, &role_name)
                .await
        },
    );

    Ok((
        Staged {
            source: CredentialSource::AwsIdcSso(config),
            identity_type,
            allowed_roles: params.allowed_roles.clone(),
        },
        sign_in_stored,
    ))
}

/// Resolve who signed in on a task of its own, and record it once `stored` says the sign-in was
/// kept; see [`record_signed_in_user`]. The lookup must not endanger the sign-in it describes, and
/// awaiting it here would: it is two SDK calls at 10s connect and 30s
/// read, and `login`'s runs inside the hold bound that cancels the whole login — token seal
/// included — when it expires, the same bound the device-code wait has already been spending. Its
/// only output is a log line, so nothing downstream needs its answer.
///
/// The task owns the copy of the access token it needs, in a `Zeroizing` the caller hands over, so
/// the secret's scope grows by one owner that scrubs it rather than by a return value the operation
/// has to carry. It owns the pair as well, which is the pair the sign-in is stored with.
fn audit_signed_in_user(
    credential: &str,
    account_id: &str,
    role_name: &str,
    stored: oneshot::Receiver<()>,
    lookup: impl std::future::Future<Output = credsd_core::error::Result<Identity>> + Send + 'static,
) {
    tokio::spawn(record_signed_in_user(
        credential.to_owned(),
        account_id.to_owned(),
        role_name.to_owned(),
        stored,
        lookup,
    ));
}

/// The record a sign-in gets, once `stored` says it was kept. A bootstrap's sign-in becomes the
/// credential only at commit, and a commit that refuses — the entry moved, or the write check found
/// drift — stores nothing, so it drops the sender and this emits nothing. The lookup still runs
/// concurrently with the commit; only whether it is recorded waits on the commit's answer.
async fn record_signed_in_user(
    credential: String,
    account_id: String,
    role_name: String,
    stored: oneshot::Receiver<()>,
    lookup: impl std::future::Future<Output = credsd_core::error::Result<Identity>>,
) {
    let resolved = lookup.await;
    if stored.await.is_err() {
        return;
    }
    audit_sso_signed_in_user(&credential, &account_id, &role_name, resolved.as_ref());
}

/// Record who signed in to Identity Center, for local traceability alone: the identity is neither
/// stored nor compared (`credential-retrieval-api` Req 17, "Who signed in"). Its own event, not a
/// field of `bootstrap complete`, because the lookup has an unresolved outcome to express and the
/// reason for it is the useful part of that record.
///
/// The user name comes out of an ARN that Identity Center builds from an IdP's user name, and in a
/// first bootstrap the pair itself comes from `ListAccounts`/`ListAccountRoles`, so every field
/// here is remote data and goes through `escape_log`.
fn audit_sso_signed_in_user(
    credential: &str,
    account_id: &str,
    role_name: &str,
    resolved: Result<&Identity, &credsd_core::error::DaemonError>,
) {
    match resolved {
        Ok(identity) => info!(
            event = "sso.signed_in",
            credential,
            account = %escape_log(account_id),
            role = %escape_log(role_name),
            user = %escape_log(&identity.session),
            "Identity Center sign-in: user recorded"
        ),
        Err(e) => warn!(
            event = "sso.signed_in",
            credential,
            account = %escape_log(account_id),
            role = %escape_log(role_name),
            reason = %escape_log(e),
            "Identity Center sign-in: user unresolved"
        ),
    }
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
        allowed_roles: None,
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
    // `existing` is the one parse of the bytes `files` holds, which the import's own dedupe and
    // gate already decided against; a name it holds is skipped before reaching here.
    let stored = state.existing.get(credential).cloned();
    *state.files = write_caller_state_locked(
        credential,
        staged,
        stored.as_ref(),
        None,
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
        allowed_roles: None,
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
) -> Result<(Staged, Identity), RpcError> {
    let (provider, signed, config, identity_type) = sign_in_aws_login(
        data_dir,
        credential,
        params,
        daemon,
        notif_tx.clone(),
        respond_slot.clone(),
    )
    .await?;
    // Sealed into staging only; whether it may replace anything is the commit's decision.
    let identity = signed.identity.clone();
    provider
        .commit(signed)
        .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;
    Ok((
        Staged {
            source: CredentialSource::AwsLogin(config),
            identity_type,
            allowed_roles: None,
        },
        identity,
    ))
}

/// Validate an `aws-login` bootstrap's params and run its sign-in into `data_dir`, holding the
/// result unsaved.
async fn sign_in_aws_login(
    data_dir: &std::path::Path,
    credential: &str,
    params: credsd_core::rpc::ProviderParamsAwsLogin,
    daemon: &Daemon,
    notif_tx: mpsc::Sender<Vec<u8>>,
    respond_slot: RespondSlot,
) -> Result<
    (
        AwsLoginProvider,
        SignedIn,
        AwsLoginConfig,
        Option<IdentityType>,
    ),
    RpcError,
> {
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
    let (provider, signed) = run_aws_login(
        data_dir,
        credential,
        &config,
        daemon,
        notif_tx,
        respond_slot,
    )
    .await?;
    Ok((provider, signed, config, identity_type))
}

/// The interactive half of `aws-login`, shared by bootstrap and re-login. Nothing is saved: the
/// caller settles the signed-in identity first.
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
) -> Result<(AwsLoginProvider, SignedIn), RpcError> {
    let provider = AwsLoginProvider::new(
        credential.to_string(),
        config.clone(),
        daemon.encryption.clone(),
        data_dir.to_path_buf(),
    )
    .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;

    let signed = if config.remote {
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
        provider
            .finish_remote_login(pending, &paste)
            .await
            .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?
    } else {
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
            .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?
    };
    Ok((provider, signed))
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
        allowed_roles: None,
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
        allowed_roles: None,
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
        allowed_roles: None,
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
        allowed_roles: None,
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
        allowed_roles: None,
    })
}

/// Emit the audit record naming the caller for a bootstrap, import or login that wrote sealed
/// material. Emitted at commit, so a flow that fails leaves none. A gated write also has the gate's
/// own records, at raise and at approval; this one is what an ungated create or a login has.
pub(crate) fn record_mutation(peer: &PeerInfo, uid: u32, operation: &str, credential: &str) {
    info!(
        event = "mutation.applied",
        operation,
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
        // fresh token. The caller named it, so it is told what does work — an `Ok` there reads as
        // "refreshed", which is how an expired token becomes a mystery.
        Some(CredentialSource::Jwt(_)) => Err(RpcError::domain(
            DomainCode::ProviderUnavailable,
            format!(
                "credential '{credential}' is a jwt source: it has no interactive login. Seal a \
                 fresh token with '{}'.",
                credsd_core::providers::jwt::reseal_command(credential)
            ),
        )),
        // Same shape as `jwt`, and for a stronger reason: there is no issuer at all, so the only
        // path to a different secret is a human supplying one, and an `Ok` here would read as
        // "refreshed".
        Some(CredentialSource::StaticSecret(_)) => Err(RpcError::domain(
            DomainCode::ProviderUnavailable,
            format!(
                "credential '{credential}' is a static-secret source: it has no interactive \
                 login. Seal a fresh secret with '{}'.",
                credsd_core::providers::static_secret::reseal_command(credential)
            ),
        )),
        Some(CredentialSource::AwsWebIdentity(oauth)) => {
            let data_dir = caller_root(uid).join("credentials").join(credential);
            run_aws_web_identity(&data_dir, credential, oauth, daemon, notif_tx)
                .await
                .map(|()| true)
        }
        Some(CredentialSource::AwsLogin(aws)) => {
            let data_dir = caller_root(uid).join("credentials").join(credential);
            let (provider, signed) = run_aws_login(
                &data_dir,
                credential,
                aws,
                daemon,
                notif_tx.clone(),
                respond_slot.clone(),
            )
            .await?;
            let stored = stored_identity(&daemon.encryption, &data_dir);
            login_identity_check(credential, stored.as_ref(), &signed.identity)?;
            provider
                .commit(signed)
                .map_err(|e| RpcError::domain(DomainCode::ProviderUnavailable, e.to_string()))?;
            Ok(true)
        }
        None => Err(RpcError::domain(
            DomainCode::CredentialNotFound,
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

    let cached_token = provider
        .complete_auth(auth_start)
        .await
        .map_err(auth_failure)?;

    // Off the login's path, which runs under a bounded hold on the caller's write lock: see
    // [`audit_signed_in_user`].
    let token = Zeroizing::new(cached_token.access_token.clone());
    let (account_id, role_name) = (sso.account_id.clone(), sso.role_name.clone());
    // A login replaces nothing but the session, and `complete_auth` has already sealed it, so this
    // record waits on no later decision.
    let (sealed, stored) = oneshot::channel();
    let _ = sealed.send(());
    audit_signed_in_user(
        credential,
        &sso.account_id,
        &sso.role_name,
        stored,
        async move {
            provider
                .signed_in_user(&token, &account_id, &role_name)
                .await
        },
    );

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
    credential: &str,
    staged: &Staged,
    stored: Option<&CredentialSource>,
    tags: Option<&credsd_core::tags::Tags>,
    files: &TomlFiles,
    verified: &mut Verified,
    enc: &credsd_core::encryption::EncryptionService,
) -> Result<TomlFiles, RpcError> {
    let uid = verified.uid();
    let caller_root = credsd_core::config::platform::caller_root(uid);
    let creds_path = caller_root.join("credentials.toml");
    // The credential owns its identity_type (credential-retrieval-api Requirement 2, amended), so
    // the tier a bootstrap settles on is written onto the source, not onto an environment. The one
    // place every provider's tier is decided: each provider's own params default an omitted tier
    // to `human`, which over an existing credential would be a silent promotion. `stored` is the
    // entry the caller's own gate decided against, passed in rather than parsed out of `files`
    // again, so the write cannot settle a kept setting against a different reading of the same
    // bytes than the decision to allow it did.
    let source = staged.written_source(stored);
    let checked_creds = std::str::from_utf8(&files.credentials)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    let written_creds = credsd_core::config::credentials::upsert_credential_in(
        &creds_path,
        checked_creds,
        credential,
        &source,
        tags,
    )
    .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    // Re-seal credentials snapshot from the bytes just written (credentials before config —
    // matches load order), not a fresh read. `entries_from_text` checks names but leaves tags as
    // written, as every snapshot parse does: the snapshot seals what was written, not a validated
    // view.
    let sources = credsd_core::config::credentials::entries_from_text(&written_creds)
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

    // No environment is written: a credential write touches `credentials.toml` and its snapshot
    // only (credential-retrieval-api Requirement 16 AC 1).
    Ok(TomlFiles {
        credentials: written_creds.into_bytes(),
        config: files.config.clone(),
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
    RpcError::domain(DomainCode::CredentialNotFound, "credential not found")
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
            format!(
                "{}: auth timed out: SSO authentication timed out after 5 minutes",
                credsd_core::error::CONFIG
            )
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
mod deny_by_absence_tests {
    use super::*;

    fn peer(auth: CallerAuth) -> PeerInfo {
        PeerInfo {
            uid: Some(501),
            pid: Some(std::process::id() as i32),
            auth,
            executable: None,
            login_uid: None,
        }
    }

    /// `credential/bootstrap` and `credential/login` are credential-addressed, so a caller they
    /// refuse by absence receives `CREDENTIAL_NOT_FOUND`, never the reserved environment code
    /// (`credential-only-addressing` Requirement 4.5).
    #[test]
    fn bootstrap_and_login_deny_as_credential_not_found() {
        for auth in [
            CallerAuth::Denied(DenyReason::NoPeerCred),
            CallerAuth::Denied(DenyReason::OwnerMismatch),
            CallerAuth::Denied(DenyReason::UnknownUid),
            CallerAuth::Unresolved,
        ] {
            let bootstrap = authorize_for_bootstrap(&peer(auth.clone())).unwrap_err();
            assert_eq!(
                bootstrap.domain_code(),
                Some(DomainCode::CredentialNotFound)
            );
            let login = authorized_uid(&peer(auth)).unwrap_err();
            assert_eq!(login.domain_code(), Some(DomainCode::CredentialNotFound));
        }
    }
}

#[cfg(test)]
mod provider_kind_tests {
    use super::*;
    use credsd_core::rpc::{
        ProviderParamsAwsWebIdentity, ProviderParamsJwtBearer, ProviderParamsOauth,
        ProviderParamsRa,
    };

    /// Every case here is a bootstrap of a credential with nothing on record, which is the only
    /// state in which a request's own values are all there is to name.
    fn provider_kind(params: &ProviderParams) -> String {
        super::provider_kind(params, None)
    }

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
            allowed_roles: None,
        });
        let kind = provider_kind(&params);
        assert!(!kind.contains('\x1b'), "sso fields escape failed: {kind:?}");
        assert!(kind.contains("aws-idc-sso"), "{kind:?}");
    }
}

#[cfg(test)]
mod sso_signed_in_audit_tests {
    use super::*;
    use serde_json::Value;

    const ARN: &str =
        "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_AdminAccess_0a1b2c3d4e5f6a7b/";

    fn identity(session: &str) -> Identity {
        credsd_core::providers::aws_login::parse_caller_arn(&format!("{ARN}{session}"))
            .expect("an Identity Center session ARN")
    }

    /// The `sso.signed_in` records `f` emits, as JSON field maps.
    ///
    /// Each test runs in a child process holding only itself, for the reason
    /// `server::dispatch`'s own capture documents: tracing caches each callsite's interest
    /// process-wide, so a thread that reaches this callsite with no subscriber installed can
    /// store `never` and silence the event for the thread that has one.
    fn records<F: FnOnce()>(f: F) -> Vec<serde_json::Map<String, Value>> {
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .map_err(|_| std::io::Error::other("log buffer poisoned"))?
                    .extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        f();
        drop(guard);
        let bytes = buf.0.lock().expect("log buffer").clone();
        String::from_utf8(bytes)
            .expect("utf-8 log")
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| v["fields"].as_object().cloned())
            .filter(|f| f.get("event").and_then(Value::as_str) == Some("sso.signed_in"))
            .collect()
    }

    /// Runs `name` alone in a child process; see `records`.
    fn alone(name: &str) -> bool {
        const CHILD: &str = "CREDSD_TEST_SSO_AUDIT_CHILD";
        if std::env::var_os(CHILD).is_some() {
            return false;
        }
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", name, "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .expect("run the child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        true
    }

    /// A resolved sign-in records the user, beside the pair the lookup brokered for.
    #[test]
    fn a_resolved_sign_in_records_its_user() {
        if alone(
            "server::bootstrap::sso_signed_in_audit_tests::a_resolved_sign_in_records_its_user",
        ) {
            return;
        }
        let lines = records(|| {
            audit_sso_signed_in_user(
                "work",
                "111122223333",
                "AdminAccess",
                Ok(&identity("test-user")),
            )
        });
        let [record] = lines.as_slice() else {
            panic!("expected one sso.signed_in record, got {lines:?}");
        };
        assert_eq!(record["credential"], Value::from("work"));
        assert_eq!(record["account"], Value::from("111122223333"));
        assert_eq!(record["role"], Value::from("AdminAccess"));
        assert_eq!(record["user"], Value::from("test-user"));
        assert!(!record.contains_key("reason"), "{record:?}");
    }

    /// The lookup is best effort: an unresolved identity records the reason in place of a user
    /// and leaves the sign-in alone (`credential-retrieval-api` Req 17, "Who signed in"). A
    /// pair the signed-in user cannot assume is the ordinary case, since a credential may list
    /// pairs its sign-in no longer holds.
    #[test]
    fn an_unresolved_sign_in_records_the_reason_instead_of_a_user() {
        if alone("server::bootstrap::sso_signed_in_audit_tests::an_unresolved_sign_in_records_the_reason_instead_of_a_user") {
            return;
        }
        let err = credsd_core::error::DaemonError::provider("No access to the role 'AdminAccess'");
        let lines =
            records(|| audit_sso_signed_in_user("work", "111122223333", "AdminAccess", Err(&err)));
        let [record] = lines.as_slice() else {
            panic!("expected one sso.signed_in record, got {lines:?}");
        };
        assert_eq!(record["credential"], Value::from("work"));
        assert!(!record.contains_key("user"), "{record:?}");
        let reason = record["reason"].as_str().expect("a reason");
        assert!(
            reason.contains("No access to the role 'AdminAccess'"),
            "{reason}"
        );
    }

    /// A sign-in the commit refused is recorded as nothing: the lookup runs either way, but the
    /// record is released by the commit that stored the sign-in, and a commit that returns an error
    /// drops the sender instead. Without the gate a credential that stored nothing had a
    /// `user recorded` line saying it did.
    #[test]
    fn a_sign_in_the_commit_refused_records_no_user() {
        if alone("server::bootstrap::sso_signed_in_audit_tests::a_sign_in_the_commit_refused_records_no_user") {
            return;
        }
        let record = |stored: bool| {
            records(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("a runtime for the record's own task");
                let (sender, kept) = oneshot::channel();
                if stored {
                    let _ = sender.send(());
                } else {
                    drop(sender);
                }
                runtime.block_on(record_signed_in_user(
                    "work".to_owned(),
                    "111122223333".to_owned(),
                    "AdminAccess".to_owned(),
                    kept,
                    std::future::ready(Ok(identity("test-user"))),
                ));
            })
        };
        assert!(
            record(false).is_empty(),
            "a refused commit stored nothing, so it records nobody"
        );
        let stored = record(true);
        let [kept] = stored.as_slice() else {
            panic!("a commit that stored the sign-in records its user");
        };
        assert_eq!(kept["user"], Value::from("test-user"));
    }

    /// The user name is remote data: Identity Center builds the session segment from an IdP's
    /// user name, so a control character in it must be escaped rather than written into the log.
    #[test]
    fn a_control_character_in_the_user_is_escaped() {
        if alone("server::bootstrap::sso_signed_in_audit_tests::a_control_character_in_the_user_is_escaped") {
            return;
        }
        let lines = records(|| {
            audit_sso_signed_in_user(
                "work",
                "111122223333",
                "AdminAccess",
                Ok(&identity("test\x1b[8muser")),
            )
        });
        let [record] = lines.as_slice() else {
            panic!("expected one sso.signed_in record, got {lines:?}");
        };
        let user = record["user"].as_str().expect("a user");
        assert!(!user.contains('\x1b'), "{user:?}");
        assert_eq!(user, "test\\x1B[8muser");
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

    fn identity(account: &str, role: &str, session: &str) -> Identity {
        credsd_core::providers::aws_login::parse_caller_arn(&format!(
            "arn:aws:sts::{account}:assumed-role/{role}/{session}"
        ))
        .expect("arn")
    }

    /// An identity-change approval is bound to the move it was shown: a re-run that signs in as
    /// another account, role, user, or partition finds no approval to spend, while a new session
    /// for the approved Principal does.
    #[test]
    fn an_identity_approval_is_bound_to_the_principal_and_not_the_session() {
        let params = [7; 32];
        let was = identity("111111111111", "Was", "s");
        let approved =
            identity_bound_digest(&params, Some(&was), &identity("111111111111", "Admin", "a"));
        assert_eq!(
            approved,
            identity_bound_digest(
                &params,
                Some(&identity("111111111111", "Was", "other-session")),
                &identity("111111111111", "Admin", "b")
            )
        );
        for other in [
            identity("111111111111", "ReadOnly", "a"),
            identity("222222222222", "Admin", "a"),
            credsd_core::providers::aws_login::parse_caller_arn(
                "arn:aws-us-gov:sts::111111111111:assumed-role/Admin/a",
            )
            .unwrap(),
            credsd_core::providers::aws_login::parse_caller_arn(
                "arn:aws:iam::111111111111:user/Admin",
            )
            .unwrap(),
        ] {
            assert_ne!(
                approved,
                identity_bound_digest(&params, Some(&was), &other),
                "{other:?}"
            );
        }
        assert_ne!(
            approved,
            identity_bound_digest(
                &[8; 32],
                Some(&was),
                &identity("111111111111", "Admin", "a")
            ),
            "and to the params"
        );
    }

    /// The approval is also bound to the Principal on record that the challenge showed: once the
    /// record changes, or goes, the approval for the old move cannot be spent.
    #[test]
    fn an_identity_approval_is_bound_to_the_record_it_was_shown() {
        let params = [7; 32];
        let now = identity("111111111111", "Admin", "a");
        let approved =
            identity_bound_digest(&params, Some(&identity("111111111111", "X", "s")), &now);
        for previous in [
            None,
            Some(identity("111111111111", "Y", "s")),
            Some(identity("222222222222", "X", "s")),
        ] {
            assert_ne!(
                approved,
                identity_bound_digest(&params, previous.as_ref(), &now),
                "{previous:?}"
            );
        }
    }

    /// `credential/login` saves only a sign-in as the Principal on record; another one, or a
    /// credential with no record, is refused and names the gated way to change it.
    #[test]
    fn login_saves_only_the_recorded_principal() {
        let alice = identity("111111111111", "Admin", "alice");
        assert!(
            login_identity_check("dev", Some(&alice), &identity("111111111111", "Admin", "x"))
                .is_ok()
        );
        for (previous, current) in [
            (Some(&alice), identity("111111111111", "ReadOnly", "alice")),
            (Some(&alice), identity("222222222222", "Admin", "alice")),
            (None, alice.clone()),
        ] {
            let err = login_identity_check("dev", previous, &current).expect_err("refused");
            assert_eq!(err.domain_code(), Some(DomainCode::IdentityMismatch));
            assert!(err.to_string().contains("creds bootstrap"), "{err}");
        }
    }

    /// The challenge names who the credential signed in as and who it would sign in as now,
    /// with control characters escaped like every other challenge field.
    #[test]
    fn an_identity_change_challenge_names_both_principals() {
        let subject = Subject {
            credential: "dev",
            kind: "aws-login",
        };
        let was = identity("111111111111", "Admin", "alice");
        let now = identity("222222222222", "Evil\u{1b}[2J", "x");
        let text = describe_identity_change(&subject, Some(&was), &now);
        assert!(
            text.contains("111111111111") && text.contains("222222222222"),
            "{text}"
        );
        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(describe_identity_change(&subject, None, &was).contains("no recorded sign-in"));
    }

    fn aws_login(region: &str, identity_type: IdentityType) -> CredentialSource {
        CredentialSource::AwsLogin(AwsLoginConfig {
            region: region.into(),
            callback_port: None,
            remote: false,
            identity_type,
        })
    }

    fn sso(account_id: &str, allowed: &[(&str, &str)]) -> CredentialSource {
        CredentialSource::AwsIdcSso(SsoConfig {
            start_url: "https://example.awsapps.com/start".into(),
            sso_region: "us-east-1".into(),
            account_id: account_id.into(),
            role_name: "Developer".into(),
            identity_type: IdentityType::Human,
            allowed_roles: allowed
                .iter()
                .map(|(account_id, role_name)| credsd_core::config::RolePair {
                    account_id: (*account_id).to_owned(),
                    role_name: (*role_name).to_owned(),
                })
                .collect(),
        })
    }

    /// Same provider source (aws-login in the same region) is what exempts a replace from the
    /// gate; another region or another provider keeps it. How the sign-in is carried out —
    /// `callback_port`, `remote` — is not part of it.
    #[test]
    fn only_the_same_aws_login_region_is_the_same_provider_source() {
        let stored = aws_login("us-east-1", IdentityType::Human);
        let same = |requested: &CredentialSource| same_provider_source(Some(&stored), requested);
        assert!(same(&aws_login("us-east-1", IdentityType::Human)));
        assert!(!same(&aws_login("us-west-2", IdentityType::Human)));
        assert!(!same(&sso("111111111111", &[])));
        assert!(!same_provider_source(
            None,
            &aws_login("us-east-1", IdentityType::Human)
        ));
        // A tier change is a different source, so it keeps the gate that discloses it.
        assert!(!same(&aws_login("us-east-1", IdentityType::Agent)));
        assert!(!same(&aws_login("us-east-1", IdentityType::Automation)));
        assert!(
            same_provider_source(
                Some(&stored),
                &CredentialSource::AwsLogin(AwsLoginConfig {
                    region: "us-east-1".into(),
                    callback_port: Some(8080),
                    remote: true,
                    identity_type: IdentityType::Human,
                })
            ),
            "the callback port and remote flag are how the sign-in runs, not what it signs in to"
        );
    }

    /// An `aws-idc-sso` replace is exempt only when every stored setting is equal
    /// (`credential-retrieval-api` Req 17 AC 11), which is what makes a repeat bootstrap a
    /// re-authentication. A pair the allowed list already names is not exempt.
    #[test]
    fn every_stored_sso_setting_is_part_of_the_same_source_decision() {
        let stored = sso("111111111111", &[("222222222222", "ReadOnly")]);
        let same = |requested: &CredentialSource| same_provider_source(Some(&stored), requested);
        assert!(same(&stored));
        assert!(!same(&sso("222222222222", &[("222222222222", "ReadOnly")])));
        assert!(!same(&sso("111111111111", &[])));
        assert!(!same(&sso(
            "111111111111",
            &[("222222222222", "ReadOnly"), ("333333333333", "Admin")]
        )));
        assert!(!same(&aws_login("us-east-1", IdentityType::Human)));
        let CredentialSource::AwsIdcSso(config) = &stored else {
            panic!("seeded an aws-idc-sso source");
        };
        for other in [
            SsoConfig {
                start_url: "https://other.awsapps.com/start".into(),
                ..config.clone()
            },
            SsoConfig {
                sso_region: "eu-west-1".into(),
                ..config.clone()
            },
            SsoConfig {
                role_name: "Admin".into(),
                ..config.clone()
            },
            SsoConfig {
                identity_type: IdentityType::Automation,
                ..config.clone()
            },
        ] {
            assert!(
                !same(&CredentialSource::AwsIdcSso(other.clone())),
                "{other:?}"
            );
        }
    }

    fn sso_params(
        account_id: Option<&str>,
        role_name: Option<&str>,
        identity_type: Option<&str>,
        allowed_roles: Option<&[(&str, &str)]>,
    ) -> credsd_core::rpc::ProviderParamsSso {
        credsd_core::rpc::ProviderParamsSso {
            start_url: "https://example.awsapps.com/start".to_owned(),
            sso_region: "us-east-1".to_owned(),
            account_id: account_id.map(str::to_owned),
            role_name: role_name.map(str::to_owned),
            identity_type: identity_type.map(str::to_owned),
            allowed_roles: allowed_roles.map(|pairs| {
                pairs
                    .iter()
                    .map(|(account_id, role_name)| credsd_core::config::RolePair {
                        account_id: (*account_id).to_owned(),
                        role_name: (*role_name).to_owned(),
                    })
                    .collect()
            }),
        }
    }

    /// The stored `aws-idc-sso` settings an omitted setting is kept from, at `automation` so a
    /// kept tier is distinguishable from the default.
    fn stored_sso_config() -> SsoConfig {
        SsoConfig {
            start_url: "https://example.awsapps.com/start".into(),
            sso_region: "us-east-1".into(),
            account_id: "111111111111".into(),
            role_name: "Developer".into(),
            identity_type: IdentityType::Automation,
            allowed_roles: vec![credsd_core::config::RolePair {
                account_id: "222222222222".to_owned(),
                role_name: "ReadOnly".to_owned(),
            }],
        }
    }

    /// Requirement 17 AC 11's fold, as the entry check reads it: a setting the request omits keeps
    /// the credential's own, so a re-authentication that names nothing but the instance reproduces
    /// the stored config exactly and is therefore ungated. An omitted `allowed_roles` keeps the
    /// stored list while an empty one clears it, and an omitted `identity_type` keeps the stored
    /// tier rather than silently promoting an `automation` credential to the default `human`.
    #[test]
    fn omitted_sso_settings_are_kept_from_the_credential() {
        let stored = stored_sso_config();
        let source = CredentialSource::AwsIdcSso(stored.clone());
        let fold = |params, over: Option<&CredentialSource>| {
            let folded = requested_source(&ProviderParams::AwsIdcSso(params), over)
                .expect("a tier that parses");
            let Some(CredentialSource::AwsIdcSso(config)) = folded else {
                panic!("an aws-idc-sso request folds to an aws-idc-sso source: {folded:?}");
            };
            config
        };

        assert_eq!(
            fold(sso_params(None, None, None, None), Some(&source)),
            stored,
            "a request that names nothing but the instance is the stored config"
        );
        assert_eq!(
            fold(
                sso_params(None, None, Some("automation"), None),
                Some(&source)
            ),
            stored,
            "naming the stored tier explicitly is still no change"
        );

        let cleared = fold(sso_params(None, None, None, Some(&[])), Some(&source));
        assert!(
            cleared.allowed_roles.is_empty() && cleared != stored,
            "an empty list clears the stored one, which is a change"
        );
        assert_eq!(
            fold(
                sso_params(None, None, None, Some(&[("333333333333", "Admin")])),
                Some(&source)
            )
            .allowed_roles
            .len(),
            1,
            "a named list replaces the stored one"
        );
        assert_eq!(
            fold(sso_params(None, None, Some("human"), None), Some(&source)).identity_type,
            IdentityType::Human,
            "a named tier is the change it looks like"
        );

        // With no entry to read, an omitted pair is left empty for the sign-in to resolve, and
        // an omitted tier takes the default.
        let fresh = fold(sso_params(None, None, None, None), None);
        assert!(fresh.account_id.is_empty() && fresh.role_name.is_empty());
        assert_eq!(fresh.identity_type, IdentityType::default());
        assert!(fresh.allowed_roles.is_empty());
    }

    /// A tier that does not parse is refused at the entry, before the fold, so `None` only ever
    /// means a request that named none. Read as `None`, `--identity-type Automaton` kept the stored
    /// tier, compared as the same source, and cleared the entry check — leaving the provider's own
    /// parse to refuse it once the browser had already opened.
    #[test]
    fn a_malformed_identity_type_is_refused_at_the_entry() {
        let params = ProviderParams::AwsIdcSso(sso_params(None, None, Some("Automaton"), None));
        let stored = CredentialSource::AwsIdcSso(stored_sso_config());
        let Err(entry) = Sources::read(&TomlFiles::default(), "sso", &params) else {
            panic!("the entry check refuses a tier that does not parse");
        };
        for err in [
            requested_source(&params, Some(&stored)).expect_err("and so does the fold it calls"),
            entry,
        ] {
            assert_eq!(err.code, credsd_core::rpc::CODE_INVALID_PARAMS);
            assert!(err.message.contains("identity_type"), "{}", err.message);
        }
        assert!(
            requested_source(
                &ProviderParams::AwsIdcSso(sso_params(None, None, Some("automation"), None)),
                Some(&stored)
            )
            .is_ok(),
            "a tier that parses still folds"
        );
    }

    /// The audit lookup must not endanger the operation it describes. A login seals under a
    /// bounded hold on the caller's write lock, and `write_lock::under` cancels the whole closure
    /// when that bound expires — so a lookup awaited inside it turns a completed sign-in into a
    /// lock-budget failure, and makes every other writer for the uid wait out a call whose only
    /// output is a log line.
    #[tokio::test]
    async fn a_lookup_that_never_answers_cannot_fail_the_sign_in_it_describes() {
        let lock = tokio::sync::Mutex::new(());
        let sealed = crate::server::write_lock::under(&lock, 7, LOGIN_LOCK_BUDGET, async |_| {
            let (stored, kept) = oneshot::channel();
            let _ = stored.send(());
            audit_signed_in_user(
                "work",
                "111122223333",
                "AdminAccess",
                kept,
                std::future::pending(),
            );
            "sealed"
        })
        .await;

        assert_eq!(
            sealed,
            Ok("sealed"),
            "the lookup is not on the login's path"
        );
        assert!(
            lock.try_lock().is_ok(),
            "and the hold ended with the login, not with the lookup"
        );
    }

    /// Req 17 AC 1's both-or-neither, for bootstrap's pair as well as `credential/get`'s. A half
    /// pair passes each field's own validator, so without this it reached the gate as a pair the
    /// challenge called "chosen at sign-in" and left the sign-in free to install another.
    #[test]
    fn naming_one_half_of_the_sso_pair_is_invalid_params() {
        for (account_id, role_name) in [(Some("111122223333"), None), (None, Some("Developer"))] {
            let err = check_sso_pair(&ProviderParams::AwsIdcSso(sso_params(
                account_id, role_name, None, None,
            )))
            .expect_err("naming one half of the pair is invalid params");
            assert_eq!(err.code, credsd_core::rpc::CODE_INVALID_PARAMS);
            assert!(
                err.message.contains("account_id") && err.message.contains("role_name"),
                "the refusal names both fields: {}",
                err.message
            );
            for value in ["111122223333", "Developer"] {
                assert!(
                    !err.message.contains(value),
                    "and echoes neither value: {}",
                    err.message
                );
            }
        }
        for (account_id, role_name) in [(Some("111122223333"), Some("Developer")), (None, None)] {
            check_sso_pair(&ProviderParams::AwsIdcSso(sso_params(
                account_id, role_name, None, None,
            )))
            .expect("both and neither are both still accepted");
        }
    }

    /// What the approver, and the `bootstrap complete` record, are told the sign-in is for: the
    /// pair and the allowed list it will actually use, which for an omitted setting is the
    /// credential's own. Rendering the request alone said "chosen at sign-in" for a pair that is
    /// carried over, and named no allowed pair at all, in exactly the case a re-authentication
    /// sends.
    #[test]
    fn an_sso_kind_names_the_settings_the_sign_in_will_use() {
        let stored = sso("111122223333", &[("222222222222", "ReadOnly")]);
        let repeat = ProviderParams::AwsIdcSso(sso_params(None, None, None, None));
        assert_eq!(
            provider_kind(&repeat, Some(&stored)),
            "aws-idc-sso (https://example.awsapps.com/start → account 111122223333, role \
             Developer; also allowing account 222222222222, role ReadOnly)"
        );
        assert_eq!(
            provider_kind(&repeat, None),
            "aws-idc-sso (https://example.awsapps.com/start → account chosen at sign-in, role \
             chosen at sign-in)",
            "a pair neither side supplies is the one case that is chosen at sign-in"
        );
        assert_eq!(
            provider_kind(&repeat, Some(&aws_login("us-east-1", IdentityType::Human))),
            provider_kind(&repeat, None),
            "a credential recording another source keeps nothing"
        );
        assert_eq!(
            provider_kind(
                &ProviderParams::AwsIdcSso(sso_params(
                    Some("333333333333"),
                    Some("Admin"),
                    None,
                    Some(&[])
                )),
                Some(&stored)
            ),
            "aws-idc-sso (https://example.awsapps.com/start → account 333333333333, role Admin)",
            "a named setting is named, and an empty allowed list clears the stored one"
        );
    }

    /// A challenge names an `aws-idc-sso` provider by its source type and leaves every setting to
    /// the change and kept clauses, which say whether each one moves or carries over. The audit
    /// record keeps the fuller rendering: it has no clauses beside it, so the settings the sign-in
    /// used would otherwise go unrecorded.
    #[test]
    fn a_challenge_names_an_sso_provider_by_its_type_and_leaves_the_settings_to_the_clauses() {
        let stored = sso("111122223333", &[("222222222222", "ReadOnly")]);
        let params = sso_params(None, None, None, Some(&[("333333333333", "Admin")]));
        let written =
            CredentialSource::AwsIdcSso(requested_sso_config(&params, stored_sso(Some(&stored))));
        let moved = ProviderParams::AwsIdcSso(params);
        let audit = provider_kind(&moved, Some(&stored));
        assert_eq!(
            challenge_kind(Some(&written), Some(&stored), &audit),
            "aws-idc-sso"
        );
        let text = describe_overwrite(
            &Overwrite::Credential,
            &Subject {
                credential: "sso.acme",
                kind: challenge_kind(Some(&written), Some(&stored), &audit),
            },
            None,
            &describe_sso_change(Some(&stored), Some(&written)),
        );
        assert_eq!(
            text.matches("333333333333").count(),
            1,
            "a value a clause names is not also named unlabelled beside it: {text}"
        );
        assert!(
            text.contains(
                "change allowed_roles from 222222222222/ReadOnly to \
                           333333333333/Admin"
            ),
            "{text}"
        );

        let iam = ProviderParams::AwsIamUser(credsd_core::rpc::ProviderParamsIamUser {
            access_key_id: "AKIAEXAMPLE".to_owned(),
            secret_access_key: "s".to_owned(),
            region: "us-east-1".to_owned(),
            duration_seconds: None,
            mfa_serial: None,
            identity_type: None,
        });
        let iam_kind = provider_kind(&iam, None);
        assert_eq!(
            challenge_kind(None, Some(&stored), &iam_kind),
            iam_kind,
            "a source with no clauses keeps its whole description"
        );
        assert_eq!(
            challenge_kind(Some(&written), None, &audit),
            audit,
            "a first bootstrap has no diff to describe, so the kind names the settings"
        );
        assert_eq!(
            challenge_kind(
                Some(&written),
                Some(&aws_login("us-east-1", IdentityType::Human)),
                &audit
            ),
            audit,
            "replacing another source has no diff either, and AC 10 wants the pairs named"
        );
    }

    /// The commit's challenge words the kind from the entry it read under the lock. The short
    /// label is safe only beside the clauses that name every setting, and an entry that moved from
    /// `aws-idc-sso` to another source while the sign-in ran has no clauses — so the label decided
    /// at the start of the handler would name neither the pair nor the allowed list the approval
    /// covers (AC 10), in exactly the case the label was meant to be safe for.
    #[test]
    fn a_commit_challenge_words_the_kind_from_the_entry_it_read_under_the_lock() {
        let at_entry = sso("111122223333", &[("222222222222", "ReadOnly")]);
        let params = sso_params(None, None, None, None);
        let written =
            CredentialSource::AwsIdcSso(requested_sso_config(&params, stored_sso(Some(&at_entry))));
        let audit = provider_kind(&ProviderParams::AwsIdcSso(params), Some(&at_entry));
        assert_eq!(
            challenge_kind(Some(&written), Some(&at_entry), &audit),
            "aws-idc-sso",
            "the entry the handler read is sso over sso, so the clauses name every setting"
        );

        // The entry as the commit finds it: another source replaced it while the sign-in ran.
        let at_commit = aws_login("us-east-1", IdentityType::Human);
        let sso_change = describe_sso_change(Some(&at_commit), Some(&written));
        assert!(sso_change.is_empty(), "no clauses once the source moved");
        let subject = |kind| Subject {
            credential: "sso.acme",
            kind,
        };
        let text = describe_overwrite(
            &Overwrite::Credential,
            &subject(challenge_kind(Some(&written), Some(&at_commit), &audit)),
            None,
            &sso_change,
        );
        for named in ["111122223333", "Developer", "222222222222", "ReadOnly"] {
            assert!(
                text.contains(named),
                "with no clauses the kind must name the pair and the allowed list: {text}"
            );
        }
        let stale = describe_overwrite(
            &Overwrite::Credential,
            &subject("aws-idc-sso"),
            None,
            &sso_change,
        );
        assert!(
            !stale.contains("111122223333"),
            "the label decided before the sign-in names nothing here: {stale}"
        );
    }

    /// The challenge wording Requirement 17 AC 11 asks for, pinned as a literal rather than
    /// rebuilt from the same `format!`: one clause per changed setting by its stored key with
    /// both values, and — because the instance moved — what the new sign-in keeps, set apart from
    /// the changes.
    #[test]
    fn an_sso_replace_challenge_names_each_changed_setting_and_what_it_keeps() {
        let stored = sso(
            "111122223333",
            &[("111122223333", "Admin"), ("444455556666", "ReadOnly")],
        );
        let CredentialSource::AwsIdcSso(config) = &stored else {
            panic!("seeded an aws-idc-sso source");
        };
        let moved = CredentialSource::AwsIdcSso(SsoConfig {
            start_url: "https://other.awsapps.com/start".into(),
            sso_region: "eu-west-1".into(),
            role_name: "Admin".into(),
            ..config.clone()
        });
        assert_eq!(
            describe_sso_change(Some(&stored), Some(&moved)),
            "; change start_url from https://example.awsapps.com/start to \
             https://other.awsapps.com/start; change sso_region from us-east-1 to eu-west-1; \
             change role_name from Developer to Admin (kept on the new sign-in: account \
             111122223333, allowed_roles 111122223333/Admin and 444455556666/ReadOnly)"
        );

        // Nothing changed, and every non-SSO pairing, carry no clauses at all.
        assert_eq!(describe_sso_change(Some(&stored), Some(&stored)), "");
        assert_eq!(describe_sso_change(None, Some(&stored)), "");
        assert_eq!(
            describe_sso_change(
                Some(&aws_login("us-east-1", IdentityType::Human)),
                Some(&aws_login("us-west-2", IdentityType::Human))
            ),
            ""
        );

        // A pair that moves without the instance moving is a change with nothing to carry over.
        assert_eq!(
            describe_sso_change(Some(&stored), Some(&sso("999988887777", &[]))),
            "; change account_id from 111122223333 to 999988887777; change allowed_roles from \
             111122223333/Admin and 444455556666/ReadOnly to none"
        );

        // Control characters in a stored or requested value never reach the approver raw.
        let hostile = CredentialSource::AwsIdcSso(SsoConfig {
            start_url: "https://evil\u{1b}[2J".into(),
            ..config.clone()
        });
        let text = describe_sso_change(Some(&stored), Some(&hostile));
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    /// One source of each family, as a provider flow stages it: every provider defaults an
    /// omitted `identity_type` to `human`, so each is built with the default tier.
    fn every_source_family() -> Vec<CredentialSource> {
        vec![
            sso("111111111111", &[]),
            aws_login("us-east-1", IdentityType::default()),
            CredentialSource::AwsIamUser(IamUserConfig {
                region: "us-east-1".into(),
                duration_seconds: None,
                mfa_serial: None,
                identity_type: IdentityType::default(),
            }),
            CredentialSource::AwsRolesAnywhere(RolesAnywhereConfig {
                trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/ta"
                    .into(),
                profile_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:profile/p".into(),
                role_arn: "arn:aws:iam::111111111111:role/Dev".into(),
                region: None,
                duration_seconds: None,
                role_session_name: None,
                endpoint_url: None,
                identity_type: IdentityType::default(),
            }),
            CredentialSource::AwsWebIdentity(AwsWebIdentityConfig {
                authorization_endpoint: Some("https://idp.example/authorize".into()),
                token_endpoint: Some("https://idp.example/token".into()),
                client_id: Some("client".into()),
                scopes: vec!["openid".into()],
                role_arn: "arn:aws:iam::111111111111:role/Dev".into(),
                region: "us-east-1".into(),
                duration_seconds: None,
                role_session_name: None,
                callback_port: None,
                identity_type: IdentityType::default(),
            }),
            CredentialSource::Jwt(credsd_core::config::JwtConfig {
                env_var: None,
                identity_type: IdentityType::default(),
            }),
            CredentialSource::StaticSecret(StaticSecretConfig {
                env_var: None,
                expires_at: None,
                secret_source: None,
                identity_type: IdentityType::default(),
            }),
            CredentialSource::Oauth(OauthConfig {
                token_url: "https://idp.example/token".into(),
                client_id: "client".into(),
                scope: None,
                grant: OauthGrant::ClientCredentials,
                identity_type: IdentityType::default(),
            }),
            CredentialSource::JwtBearer(credsd_core::config::JwtBearerConfig {
                token_url: "https://idp.example/token".into(),
                client_id: None,
                scope: None,
                identity_type: IdentityType::default(),
            }),
        ]
    }

    /// The tier a bootstrap writes, for every source family: the one the request names, or the
    /// credential's own when it names none (`docs/reference/api.md`). Taking each provider's
    /// `human` default over an existing credential would promote an `automation` credential to
    /// the most privileged tier on every repeat bootstrap that omitted the field — and, since the
    /// disclosure is computed from what is written, show the approver no tier clause for it.
    #[test]
    fn an_omitted_identity_type_keeps_the_stored_tier_of_every_source() {
        for staged in every_source_family() {
            let mut stored = staged.clone();
            stored.set_identity_type(IdentityType::Automation);
            let kind = staged.type_name();

            let kept = Staged {
                source: staged.clone(),
                identity_type: None,
                allowed_roles: None,
            };
            assert_eq!(
                kept.written_source(Some(&stored)).identity_type(),
                IdentityType::Automation,
                "{kind}: an omitted tier keeps the stored one"
            );
            assert_eq!(
                identity_type_change(
                    Some(&stored),
                    kept.written_source(Some(&stored)).identity_type()
                ),
                None,
                "{kind}: a kept tier is no change, so the challenge carries no clause"
            );
            assert_eq!(
                kept.written_source(None).identity_type(),
                IdentityType::default(),
                "{kind}: a credential with nothing on record takes the default"
            );

            let named = Staged {
                source: staged,
                identity_type: Some(IdentityType::Human),
                allowed_roles: None,
            };
            assert_eq!(
                named.written_source(Some(&stored)).identity_type(),
                IdentityType::Human,
                "{kind}: a named tier is the change it looks like"
            );
            assert_eq!(
                identity_type_change(
                    Some(&stored),
                    named.written_source(Some(&stored)).identity_type()
                ),
                Some((IdentityType::Automation, IdentityType::Human)),
                "{kind}: and the challenge names both values"
            );
        }
    }

    /// The decision reads the bytes the write check verified, not the file on disk: a
    /// `credentials.toml` swapped after the check cannot turn another source into a same-source
    /// one and skip the gate. A file that does not parse reads as no source, so it is never
    /// a re-authentication however equal the request looks.
    #[tokio::test]
    async fn the_same_source_decision_reads_the_checked_bytes() {
        let c = caller().await;
        let files = TomlFiles::read(c.uid).expect("files");
        let seed = aws_login("us-east-1", IdentityType::Human);
        credsd_core::config::credentials::upsert_credential_at(
            &c.root.join("credentials.toml"),
            "dev",
            &seed,
        )
        .expect("swap after the check");
        assert!(stored_source(&files, "dev").is_none());
        assert!(!same_provider_source(
            stored_source(&files, "dev").as_ref(),
            &seed
        ));
        assert!(
            same_provider_source(
                stored_source(&TomlFiles::read(c.uid).expect("files"), "dev").as_ref(),
                &seed
            ),
            "the same bytes, re-read, do describe the same source"
        );

        let unparseable = TomlFiles {
            credentials: b"not = = toml".to_vec(),
            config: Vec::new(),
        };
        assert!(stored_source(&unparseable, "dev").is_none());
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

    /// At the cap, a bootstrap of a credential that is already one of the counted slots stores
    /// nothing new and proceeds; a name that is not refuses. Without the exemption a caller at the
    /// cap could re-authenticate nothing, since `credential/bootstrap` is what a repeat sign-in
    /// is, and the refusal would tell them to remove unused credentials to refresh one they use.
    #[tokio::test]
    async fn the_credential_cap_counts_only_the_slots_a_bootstrap_would_add() {
        let c = caller().await;
        let creds = c.root.join("credentials");
        std::fs::create_dir_all(&creds).expect("credentials dir");
        for i in 0..MAX_CREDENTIALS_PER_UID {
            std::fs::create_dir(creds.join(format!("cred-{i}"))).expect("seed a credential");
        }

        check_credential_quota(c.uid, Some("cred-0"))
            .expect("an existing credential adds no slot, so it can be re-authenticated");
        for named in [Some("fresh"), None] {
            let err = check_credential_quota(c.uid, named).expect_err("a new name is refused");
            assert_eq!(err.domain_code(), Some(DomainCode::ProviderUnavailable));
            assert!(
                err.to_string().contains("credential limit reached"),
                "{err}"
            );
        }

        std::fs::remove_dir(creds.join("cred-1")).expect("free a slot");
        check_credential_quota(c.uid, Some("fresh")).expect("below the cap, a new name is fine");
    }

    /// The gate decision has the same fail-open shape as the digest: an unlistable credential
    /// directory read as "holds nothing" would skip the gate on the material it holds.
    #[tokio::test]
    async fn a_credential_directory_that_will_not_list_errors_instead_of_reading_as_empty() {
        let c = caller().await;
        assert_eq!(
            overwrite_reason(c.uid, "db").expect("absent credential"),
            None,
            "a credential that does not exist overwrites nothing"
        );

        std::fs::create_dir_all(c.root.join("credentials")).expect("credentials dir");
        std::fs::write(c.root.join("credentials").join("db"), b"not a directory")
            .expect("unlistable credential dir");
        assert!(
            overwrite_reason(c.uid, "db").is_err(),
            "a credential directory that will not list must error, not read as empty"
        );
    }

    /// A sealed file that will not re-bind fails the install, and the caller relays that failure
    /// as the Internal error the client shows. The relay adds no category, so the message holds
    /// exactly one.
    #[tokio::test]
    async fn a_rebind_failure_through_install_names_one_category() {
        let c = caller().await;
        let staging = Staging::create(c.uid).expect("staging");
        std::fs::write(staging.path().join("iam_user.enc"), b"not sealed").expect("staged file");
        let enc = credsd_core::encryption::EncryptionService::new(
            credsd_core::encryption::generate_key().expect("key"),
        )
        .expect("encryption service");
        let target = c.root.join("credentials").join("db");

        let err = staging
            .install(&target, &enc)
            .expect_err("a sealed file that will not re-bind must not install");
        let shown = err.to_string();
        assert_eq!(credsd_core::error::prefixes(&shown), 1, "{shown}");
    }

    /// An install that fails on the filesystem, not on a sealed file, is relayed the same way,
    /// so it too must name exactly one category.
    #[tokio::test]
    async fn an_io_failure_through_install_names_one_category() {
        let c = caller().await;
        let staging = Staging::create(c.uid).expect("staging");
        let enc = credsd_core::encryption::EncryptionService::new(
            credsd_core::encryption::generate_key().expect("key"),
        )
        .expect("encryption service");
        let target = c.root.join("no-such-dir").join("db");

        let err = staging
            .install(&target, &enc)
            .expect_err("a target whose parent is missing must not install");
        let shown = err.to_string();
        assert_eq!(credsd_core::error::prefixes(&shown), 1, "{shown}");
    }
}
