//! JSON-RPC method dispatch for the Unix-domain-socket credential surface.
//!
//! One dispatcher, a carrier parameter, and an exposure table that is *data* rather than
//! control flow scattered through handlers (Requirement 13 AC 1). The exposure check runs
//! before handler lookup and returns `-32601` — never a permission error — for a method a
//! carrier does not expose, because a permission error would confirm the method exists
//! (Requirement 13 AC 5).
//!
//! Every domain failure is re-expressed from the Phase-2 HTTP surface without weakening it:
//! an unauthorized caller (deny-by-absence, `Unresolved`, or peerless) is refused *before*
//! any store lookup and receives `CREDENTIAL_NOT_FOUND` with one message, indistinguishable from
//! a name it does not hold (Requirement 8 AC 3-4, 7). That holds for every credential-addressed
//! method: `credential/get`, `credential/logout`, `credential/remove`, `credential/login`,
//! `credential/bootstrap`, and `credential/import` (Requirement 15 AC 10).
//! `credential/bootstrap/respond` is a notification with no answer. The distinct deny reasons
//! survive only in the audit record, logged when the connection is accepted.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;

use crate::credential_store::{CredentialStore, Lookup};
use crate::server::bootstrap::TomlFiles;
use crate::server::classify::{CallerAssessment, ClaimedIdentity};
use crate::server::integrity::{
    custody_broken, precheck_for_write, unverifiable, verify_for_renewal, verify_for_write,
    CustodyCheck, Integrity, IntegrityCustody, Verified,
};
use crate::server::presence::{Op, Presence, RegistryCustody};
use crate::server::revalidate::{CONFIG, CREDENTIALS};
use crate::server::routes::{CallerAuth, DenyReason, PeerInfo};
use crate::server::write_lock::Held;
use credsd_core::config::credentials::{CredentialSource, CredentialSources};
use credsd_core::config::snapshot::{DriftStatus, Pin};
use credsd_core::config::DaemonConfig;
use credsd_core::config::{self, keys, platform};
use credsd_core::credential_status::credential_session_status_at;
use credsd_core::credentials::CredentialData;
use credsd_core::encryption::EncryptionService;
use credsd_core::presence::{
    self as presence_wire, ApproveParams, ApproveResult, EnrollParams, IdParams,
    METHOD_PRESENCE_ENROLL, METHOD_PRESENCE_REVOKE, METHOD_PRESENCE_STATUS, METHOD_REQUEST_APPROVE,
    METHOD_REQUEST_GET, METHOD_REQUEST_LIST, METHOD_REQUEST_WITHDRAW,
};
use credsd_core::providers::sso::LogoutEnded;
use credsd_core::providers::ReauthInput;
use credsd_core::rpc::{
    Claim, ConfigGetParams, ConfigGetResult, ConfigSetParams, ConfigUnsetParams, CredentialEntry,
    CredentialLogoutParams, CredentialRemoveParams, CredentialResult, CredentialSourceType,
    CredentialSummary, CredentialTagParams, CredentialType, DescribeParams, DomainCode,
    EnvRemoveParams, GetBatchParams, GetBatchResult, GetParams, HealthResult, ListParams,
    ListResult, LogoutResult, Material, OkResult, ProfileManifest, Projection, Provenance,
    ProviderLogout, Request, Response, RpcError, SessionStatus, METHOD_CONFIG_GET,
    METHOD_CONFIG_SET, METHOD_CONFIG_UNSET, METHOD_CREDENTIAL_BOOTSTRAP, METHOD_CREDENTIAL_GET,
    METHOD_CREDENTIAL_IMPORT, METHOD_CREDENTIAL_LIST, METHOD_CREDENTIAL_LOGIN,
    METHOD_CREDENTIAL_LOGOUT, METHOD_CREDENTIAL_REMOVE, METHOD_CREDENTIAL_TAG,
    METHOD_ENVIRONMENT_CREDENTIALS, METHOD_ENV_REMOVE, METHOD_FILE_REVALIDATE,
    METHOD_PROFILE_DESCRIBE, METHOD_SYSTEM_HEALTH,
};
use credsd_core::tags::Tags;

/// The kind every configured source resolves to today. All shipped sources (SSO, IAM user,
/// Roles Anywhere) mint session credentials; no source produces a bare access token as its
/// served credential (design coherence #4), so the manifest and the enumeration report
/// session credentials for every entry.
const SHIPPED_KIND: CredentialType = CredentialType::SessionCredentials;

/// Per-caller state, lazily loaded from `callers/<uid>/` on first request.
pub struct CallerState {
    pub config: Arc<DaemonConfig>,
    pub store: Arc<CredentialStore>,
    pub credentials: Arc<CredentialSources>,
    /// Each credential's tags, by name. A credential with none has no entry.
    pub tags: Arc<HashMap<String, Tags>>,
    /// Modification times of the two files this state was built from, sampled at load. A
    /// later request compares them against the files on disk and reloads on a mismatch, so
    /// an edit made by anything other than the daemon is not served stale for the process
    /// lifetime. `None` means the file was absent at load, which is itself a state worth
    /// detecting a change from — a `credentials.toml` that appears must not be ignored.
    sources: SourceStamps,
    /// The background refresh loop belonging to `store`, aborted when this state drops.
    ///
    /// Without this the loop outlives the state that owns it: `spawn_refresh_task` loops
    /// forever with no cancellation, so every eviction would leak one task per reload,
    /// each still refreshing credentials for a configuration no longer in effect.
    ///
    /// `None` in the test constructor, which injects a store directly and never starts a loop
    /// to cancel, and for a caller whose records are not verified, whose store is never renewed.
    refresh: Option<tokio::task::AbortHandle>,
    /// Drift status of `config.toml`, against its snapshot and the integrity record, sampled at
    /// load. Nothing is served while it is not valid.
    pub config_drift: DriftStatus,
    /// Drift status of `credentials.toml`, sampled the same way. Every served credential's
    /// source is in this file, so nothing is served while it is not valid (Requirement 3.2).
    pub credentials_drift: DriftStatus,
    /// Why the caller's files parsed but did not validate, or `None`. While set, `config` and
    /// `credentials` are empty and every caller read refuses with this reason
    /// (`credential-tags` Requirement 1.5), rather than reading as a caller with nothing.
    pub config_invalid: Option<String>,
}

impl Drop for CallerState {
    fn drop(&mut self) {
        if let Some(refresh) = &self.refresh {
            refresh.abort();
        }
    }
}

/// Modification times of `config.toml` and `credentials.toml` under a caller root.
///
/// Compared as a pair rather than individually: either file changing invalidates the state,
/// because `CredentialStore` is built from both and an env is only meaningful alongside the
/// credential it names.
#[derive(PartialEq, Eq)]
struct SourceStamps {
    config: Option<std::time::SystemTime>,
    credentials: Option<std::time::SystemTime>,
}

impl SourceStamps {
    /// Sample both files. An unreadable or absent file yields `None` rather than an error:
    /// absence is a legitimate state (an unprovisioned caller has neither file), and a
    /// transient stat failure must not take down a request that could be served.
    fn sample(caller_root: &std::path::Path) -> Self {
        let mtime = |name: &str| {
            std::fs::metadata(caller_root.join(name))
                .and_then(|m| m.modified())
                .ok()
        };
        Self {
            config: mtime("config.toml"),
            credentials: mtime("credentials.toml"),
        }
    }
}

/// The state a dispatched request reads. Per-caller config + stores are loaded lazily from
/// `callers/<uid>/` on the first authorized request from each uid.
#[derive(Clone)]
pub struct Daemon {
    pub registry: Arc<std::sync::Mutex<std::collections::HashMap<u32, Arc<CallerState>>>>,
    pub encryption: Arc<EncryptionService>,
    /// One async Mutex per uid, held for the duration of a bootstrap or login write.
    /// Prevents concurrent connections from the same uid racing write_caller_state and
    /// interleaving O_TRUNC + write_all sequences on credentials.toml / config.toml.
    bootstrap_locks:
        Arc<std::sync::Mutex<std::collections::HashMap<u32, Arc<tokio::sync::Mutex<()>>>>>,
    /// UIDs with a bootstrap or login currently in flight, across all connections.
    /// At most one login per uid at a time; a second attempt returns an error rather
    /// than queuing behind a 5-minute device-flow timeout.
    active_logins: Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    /// The `callers/` tree this daemon serves, supplied at construction.
    ///
    /// Supplied rather than resolved here for two reasons. `platform::callers_dir()` reads
    /// `CREDSD_DATA_DIR` on every call, so a daemon that re-derived it would compare a
    /// freshness stamp sampled from one directory against a later sample from another and
    /// reload on every request. And it must be the *same* tree the accept loop authorizes
    /// against: when the two disagree, the daemon stamps and reloads a directory it does not
    /// serve, which is invisible in production (both resolve identically) and wrong anywhere
    /// the two are set independently.
    callers_root: std::path::PathBuf,
    /// Pending gated operations and enrolled presence keys (presence-gate spike).
    pub presence: Arc<Presence>,
    /// Each caller's integrity record (drift-detection Requirement 10).
    pub integrity: Arc<Integrity>,
}

/// RAII guard for the per-uid slot from [`Daemon::claim_login`]. The connection handler moves
/// this into the spawned bootstrap/login task; dropping it — however the task ends — releases
/// the slot. Moving it in, rather than calling `release_login` by hand at the task's exit, means
/// an aborted task (the connection it belongs to dropped) still releases the slot instead of
/// holding it until `CALLBACK_TIMEOUT`.
pub struct LoginClaim {
    daemon: Daemon,
    uid: u32,
}

impl Drop for LoginClaim {
    fn drop(&mut self) {
        crate::server::lock(&self.daemon.active_logins).remove(&self.uid);
    }
}

impl Daemon {
    /// `enrolled_keys` is where the enrolled-key registry is held and `integrity` where the
    /// integrity records are; each `beside` constructor is the file custody beside
    /// `callers_root`.
    ///
    /// Where the records are files, their custody and the registry's is verified here, before
    /// the registry is read (drift-detection Requirement 10.8): a breach leaves the registry
    /// unread and untrusted. The data dir the check walks up to is the records directory's
    /// parent, which is where `beside` puts it.
    pub fn new(
        encryption: Arc<EncryptionService>,
        callers_root: std::path::PathBuf,
        enrolled_keys: RegistryCustody,
        integrity: IntegrityCustody,
    ) -> Self {
        let check = match &integrity {
            IntegrityCustody::File(dir) => {
                let data_dir = dir.parent().unwrap_or(dir).to_path_buf();
                let mut dirs = vec![dir.clone()];
                dirs.extend(enrolled_keys.dir().map(std::path::Path::to_path_buf));
                Some(CustodyCheck::new(data_dir, dirs))
            }
            IntegrityCustody::Slot { .. } => None,
        };
        let integrity = Arc::new(Integrity::new(integrity, check, encryption.clone()));
        let breach = integrity.verify_custody().err();
        let presence = Arc::new(Presence::open(enrolled_keys, encryption.clone(), breach));
        Self {
            registry: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            encryption,
            bootstrap_locks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            active_logins: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            callers_root,
            presence,
            integrity,
        }
    }

    /// Attempt to claim the login slot for `uid`. Returns the guard if the slot was free;
    /// `None` if a login is already in flight for this uid. Dropping the guard — on normal
    /// completion, a panic, or the owning task being aborted — releases the slot, so a
    /// connection that dies mid-login cannot hold the uid locked out for the rest of
    /// `CALLBACK_TIMEOUT`.
    pub fn claim_login(&self, uid: u32) -> Option<LoginClaim> {
        crate::server::lock(&self.active_logins)
            .insert(uid)
            .then(|| LoginClaim {
                daemon: self.clone(),
                uid,
            })
    }

    /// The `callers/` tree this daemon serves. The accept loop authorizes against this same
    /// root, so there is one answer to "which tree" rather than two that can disagree.
    pub fn callers_root(&self) -> &std::path::Path {
        &self.callers_root
    }

    /// This daemon's caller root for `uid`. Stable for the daemon's lifetime.
    fn caller_root(&self, uid: u32) -> std::path::PathBuf {
        self.callers_root.join(uid.to_string())
    }

    /// Acquire an async per-uid write lock that serializes bootstrap/login writes for this uid.
    pub fn bootstrap_lock(&self, uid: u32) -> Arc<tokio::sync::Mutex<()>> {
        crate::server::lock(&self.bootstrap_locks)
            .entry(uid)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Hold `uid`'s write lock until the guard drops, with the proof of the hold the shared drift
    /// check requires.
    pub(crate) async fn write_guard(&self, uid: u32) -> crate::server::write_lock::Guard {
        crate::server::write_lock::acquire(self.bootstrap_lock(uid), uid).await
    }

    /// Retrieve or lazily create the caller's per-uid state. Loads config + credentials from
    /// `callers/<uid>/` on first access; missing config yields an empty DaemonConfig so the
    /// caller can connect but finds no envs until provisioned.
    ///
    /// A cached state is reused only while both source files are unchanged. [`evict_caller`]
    /// covers writes the daemon makes itself; this stat-on-access covers every other way the
    /// files move — a hand-edited `credentials.toml`, a restored backup, a config management
    /// tool. Two `stat` calls per request buys that, which is cheaper than the alternative of
    /// serving a superseded credential source until the process restarts. Under a tightened
    /// boundary policy, serving the previous one would be a permission reduction that
    /// silently failed to take effect.
    ///
    /// [`evict_caller`]: Self::evict_caller
    pub fn caller_state(&self, uid: u32) -> Arc<CallerState> {
        let caller_root = self.caller_root(uid);
        let sources = SourceStamps::sample(&caller_root);
        if let Some(state) = crate::server::lock(&self.registry).get(&uid) {
            if state.sources == sources {
                return state.clone();
            }
            tracing::info!(
                uid,
                "caller config changed on disk, reloading credential store"
            );
        }
        // Drift is checked on the parse that is served, before validation: a file that parses but
        // does not validate is not drift, and reading it as drift would point the owner at a
        // revalidation that finds nothing to reseal.
        let parsed = DaemonConfig::parse_entries_from(&caller_root);
        let (config_drift, credentials_drift) = match (&parsed, self.integrity.read(uid)) {
            (_, Err(_)) => (DriftStatus::Unverifiable, DriftStatus::Unverifiable),
            (Ok((config, credentials)), Ok(record)) => (
                self.assess(uid, CONFIG, record.map(|r| r.config), |rel| {
                    credsd_core::config::snapshot::canonical_config(uid, rel, config)
                }),
                self.assess(uid, CREDENTIALS, record.map(|r| r.credentials), |rel| {
                    credsd_core::config::snapshot::canonical_credentials(uid, rel, credentials)
                }),
            ),
            (Err(_), Ok(_)) => (DriftStatus::Drifted, DriftStatus::Drifted),
        };
        let mut config_invalid = None;
        let (config, credentials, tags) = match parsed {
            Ok((config, mut entries)) => {
                let checked = credsd_core::config::credentials::check_tags(&mut entries)
                    .map_err(|e| vec![e.detail()]);
                let mut credentials = CredentialSources::new();
                let mut tags = HashMap::new();
                for (name, entry) in entries {
                    if !entry.tags.is_empty() {
                        tags.insert(name.clone(), entry.tags);
                    }
                    credentials.insert(name, entry.source);
                }
                match checked.and_then(|()| config.validate(&credentials)) {
                    Ok(()) => (config, credentials, tags),
                    Err(errors) => {
                        let errors = errors.join("; ");
                        tracing::warn!(
                            uid,
                            errors = %errors,
                            "caller config does not validate; serving nothing until it is fixed"
                        );
                        config_invalid = Some(errors);
                        Default::default()
                    }
                }
            }
            Err(_) => Default::default(),
        };
        if config.envs.is_empty() {
            tracing::warn!(
                uid,
                caller_root = %caller_root.display(),
                "no config found for caller — run 'credsd bootstrap' to provision this user"
            );
        }
        let records_check: crate::credential_store::RecordsCheck = {
            let integrity = self.integrity.clone();
            let encryption = self.encryption.clone();
            Arc::new(move |held: &Held<'_>, uid| {
                verify_for_renewal(&integrity, &encryption, held, uid)
                    .map(drop)
                    .map_err(|e| e.message)
            })
        };
        let store = Arc::new(CredentialStore::new(
            uid,
            &credentials,
            self.encryption.clone(),
            self.bootstrap_lock(uid),
            records_check,
        ));
        // A renewal seals material for whatever the records name, so records that did not verify
        // at load get no refresh loop. They stay enumerable from `config`. Records that verified
        // here can drift later without a request to reload them, so every renewal also runs the
        // shared check under the write lock (drift-detection Requirement 5.8).
        let refresh = (config_drift.is_valid() && credentials_drift.is_valid())
            .then(|| store.spawn_refresh_task().abort_handle());

        let state = Arc::new(CallerState {
            config: Arc::new(config),
            store,
            credentials: Arc::new(credentials),
            tags: Arc::new(tags),
            sources,
            refresh,
            config_drift,
            credentials_drift,
            config_invalid,
        });
        // Replaces any entry a concurrent caller inserted. The displaced state's refresh task
        // is aborted by its `Drop` once the last in-flight request holding it finishes, so a
        // request already reading the old state is never cut off mid-flight.
        crate::server::lock(&self.registry).insert(uid, state.clone());
        state
    }

    /// [`snapshot::assess`](credsd_core::config::snapshot::assess) of `uid`'s file `name`
    /// against what the integrity record pins for it, whose canonical form `canonical` builds
    /// from the path relative to the data dir (so it is stable across machines and data-dir
    /// relocations). A file with no canonical form cannot match any snapshot, so it is drift.
    fn assess(
        &self,
        uid: u32,
        name: &str,
        pin: Option<Pin>,
        canonical: impl FnOnce(&std::path::Path) -> credsd_core::error::Result<Vec<u8>>,
    ) -> DriftStatus {
        let rel = std::path::Path::new("callers")
            .join(uid.to_string())
            .join(name);
        match canonical(&rel) {
            Ok(canonical) => credsd_core::config::snapshot::assess(
                &self.encryption,
                &canonical,
                &self.caller_root(uid).join(name),
                pin,
            ),
            Err(_) => DriftStatus::Drifted,
        }
    }

    /// Evict the cached [`CallerState`] for `uid` so the next request triggers a fresh load
    /// from `callers/<uid>/`. Must be called after daemon-side writes to `config.toml` or
    /// `credentials.toml` (e.g. after a successful `profile/bootstrap`) so the next
    /// `credential/get` reloads the updated state rather than serving from a stale store.
    pub fn evict_caller(&self, uid: u32) {
        crate::server::lock(&self.registry).remove(&uid);
    }

    #[cfg(test)]
    pub fn with_caller(
        uid: u32,
        config: DaemonConfig,
        credentials: CredentialSources,
        store: Arc<CredentialStore>,
        encryption: Arc<EncryptionService>,
        callers_root: std::path::PathBuf,
    ) -> Self {
        let enrolled_keys = RegistryCustody::beside(&callers_root);
        // Beside the tree the write paths resolve from `CREDSD_DATA_DIR`, not beside
        // `callers_root`: cases that inject a store pass an unbacked root, and the records the
        // write paths keep must land somewhere writable.
        let integrity = || IntegrityCustody::beside(&platform::callers_dir());
        let mut daemon = Self::new(encryption.clone(), callers_root, enrolled_keys, integrity());
        // The injected state stands in for one that loaded verified, so custody is not checked
        // either: the data dir it would check is whatever install the machine running the suite
        // has, and `serve_refusal` checks custody on every serve.
        daemon.integrity = Arc::new(Integrity::new(integrity(), None, encryption.clone()));
        let state = Arc::new(CallerState {
            config: Arc::new(config),
            store,
            credentials: Arc::new(credentials),
            tags: Default::default(),
            // Stamp from the daemon's own caller root so the injected state reads as fresh.
            // It must be the root this daemon serves: stamping a globally resolved path would
            // pin the daemon to whatever tree a concurrent case had left in `CREDSD_DATA_DIR`,
            // and a write there would make the first `caller_state` call discard this store and
            // reload, throwing away the credentials just injected.
            sources: SourceStamps::sample(&daemon.caller_root(uid)),
            refresh: None,
            config_drift: DriftStatus::Valid { hash: [0u8; 32] },
            credentials_drift: DriftStatus::Valid { hash: [0u8; 32] },
            config_invalid: None,
        });
        crate::server::lock(&daemon.registry).insert(uid, state);
        daemon
    }
}

/// Which transport carried a request. Only [`Carrier::Uds`] is wired this run; the stdio
/// column of the exposure table is encoded anyway so adding the `credsd mcp` carrier later
/// cannot silently expose a material method (Requirement 13 AC 1-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    Uds,
    // `allow` rather than `expect`: tests construct this, so the lint fires for the bin build and
    // not under `--all-targets`, and an `expect` would be unfulfilled in one of the two.
    #[allow(
        dead_code,
        reason = "never constructed by the daemon until the `credsd mcp` carrier lands. Encoded \
                  now because Req 13 AC 1 requires exposure to be explicit rather than \
                  incidental, so the stdio column must exist in the table before a second \
                  carrier can be added without silently exposing Material"
    )]
    Stdio,
}

/// All methods as a typed value so [`exposed`] is an exhaustive match: adding a method
/// without adding an exposure row does not compile.
///
/// `ProfileBootstrap` and `ProfileLogin` are listed here for the exposure table but are
/// NOT reachable via the normal `dispatch()` path — `serve_connection` intercepts them
/// before dispatch and spawns dedicated streaming handlers. They appear in the table so
/// the enum stays exhaustive and any accidental dispatch call returns method-not-found.
///
/// `ProfileBootstrapRespond` is intentionally absent: it is a client-to-daemon notification
/// (no `id`) that `serve_connection` routes into the in-flight respond slot. It must never
/// appear in `Method::parse` so it cannot be dispatched as a normal request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    GetBatch,
    List,
    Describe,
    Health,
    ConfigSet,
    ConfigGet,
    ConfigUnset,
    CredentialRemove,
    CredentialLogout,
    CredentialTag,
    EnvRemove,
    FileRevalidate,
    /// Handled by `serve_connection` via `bootstrap::handle_profile_bootstrap`; this
    /// variant exists only for the exposure table.
    ProfileBootstrap,
    /// Handled by `serve_connection` via `bootstrap::handle_profile_login`.
    ProfileLogin,
    /// Non-streaming batch seal of discovered static-key profiles. Unlike bootstrap/login it is
    /// reached through the normal `dispatch()` path, so `handle` routes it directly.
    ProfileImport,
    RequestApprove,
    RequestGet,
    RequestList,
    RequestWithdraw,
    PresenceEnroll,
    PresenceRevoke,
    PresenceStatus,
}

impl Method {
    fn parse(name: &str) -> Option<Self> {
        match name {
            METHOD_CREDENTIAL_GET => Some(Self::Get),
            METHOD_ENVIRONMENT_CREDENTIALS => Some(Self::GetBatch),
            METHOD_CREDENTIAL_LIST => Some(Self::List),
            METHOD_PROFILE_DESCRIBE => Some(Self::Describe),
            METHOD_SYSTEM_HEALTH => Some(Self::Health),
            METHOD_CONFIG_SET => Some(Self::ConfigSet),
            METHOD_CONFIG_GET => Some(Self::ConfigGet),
            METHOD_CONFIG_UNSET => Some(Self::ConfigUnset),
            METHOD_CREDENTIAL_REMOVE => Some(Self::CredentialRemove),
            METHOD_CREDENTIAL_LOGOUT => Some(Self::CredentialLogout),
            METHOD_CREDENTIAL_TAG => Some(Self::CredentialTag),
            METHOD_ENV_REMOVE => Some(Self::EnvRemove),
            METHOD_FILE_REVALIDATE => Some(Self::FileRevalidate),
            METHOD_CREDENTIAL_BOOTSTRAP => Some(Self::ProfileBootstrap),
            METHOD_CREDENTIAL_LOGIN => Some(Self::ProfileLogin),
            METHOD_CREDENTIAL_IMPORT => Some(Self::ProfileImport),
            METHOD_REQUEST_APPROVE => Some(Self::RequestApprove),
            METHOD_REQUEST_GET => Some(Self::RequestGet),
            METHOD_REQUEST_LIST => Some(Self::RequestList),
            METHOD_REQUEST_WITHDRAW => Some(Self::RequestWithdraw),
            METHOD_PRESENCE_ENROLL => Some(Self::PresenceEnroll),
            METHOD_PRESENCE_REVOKE => Some(Self::PresenceRevoke),
            METHOD_PRESENCE_STATUS => Some(Self::PresenceStatus),
            _ => None,
        }
    }
}

/// The dispatcher's method table as data, for the drift-detection Testing requirement that every
/// write path be enumerated from the dispatcher rather than from a hand-kept list.
#[cfg(test)]
impl Method {
    /// Every method, by walking [`successor`](Self::successor) from the first. That walk is an
    /// exhaustive match, so a variant added to `Method` does not compile until it is placed in it.
    pub(crate) fn all() -> Vec<Self> {
        std::iter::successors(Some(Self::Get), |m| m.successor()).collect()
    }

    fn successor(self) -> Option<Self> {
        Some(match self {
            Self::Get => Self::GetBatch,
            Self::GetBatch => Self::List,
            Self::List => Self::Describe,
            Self::Describe => Self::Health,
            Self::Health => Self::ConfigSet,
            Self::ConfigSet => Self::ConfigGet,
            Self::ConfigGet => Self::ConfigUnset,
            Self::ConfigUnset => Self::CredentialRemove,
            Self::CredentialRemove => Self::CredentialLogout,
            Self::CredentialLogout => Self::CredentialTag,
            Self::CredentialTag => Self::EnvRemove,
            Self::EnvRemove => Self::FileRevalidate,
            Self::FileRevalidate => Self::ProfileBootstrap,
            Self::ProfileBootstrap => Self::ProfileLogin,
            Self::ProfileLogin => Self::ProfileImport,
            Self::ProfileImport => Self::RequestApprove,
            Self::RequestApprove => Self::RequestGet,
            Self::RequestGet => Self::RequestList,
            Self::RequestList => Self::RequestWithdraw,
            Self::RequestWithdraw => Self::PresenceEnroll,
            Self::PresenceEnroll => Self::PresenceRevoke,
            Self::PresenceRevoke => Self::PresenceStatus,
            Self::PresenceStatus => return None,
        })
    }

    /// Whether the method writes a load-bearing file or seals material one names, and so must
    /// pass the shared drift check (drift-detection Requirement 5.8). Exhaustive: a new method
    /// does not compile until it is classified, and a method classified as writing is driven
    /// against drift by `e2e::every_write_path_refuses_while_its_records_are_in_drift`.
    pub(crate) fn writes_load_bearing(self) -> bool {
        match self {
            Self::ConfigSet
            | Self::ConfigUnset
            | Self::CredentialRemove
            | Self::CredentialLogout
            | Self::CredentialTag
            | Self::EnvRemove
            | Self::FileRevalidate
            | Self::ProfileBootstrap
            | Self::ProfileLogin
            | Self::ProfileImport
            | Self::RequestApprove => true,
            // Reads, and presence-key state, which is the registry rather than a caller's records.
            Self::Get
            | Self::GetBatch
            | Self::List
            | Self::Describe
            | Self::Health
            | Self::ConfigGet
            | Self::RequestGet
            | Self::RequestList
            | Self::RequestWithdraw
            | Self::PresenceEnroll
            | Self::PresenceRevoke
            | Self::PresenceStatus => false,
        }
    }
}

/// The exposure matrix of Requirement 13 AC 2, as one exhaustive table.
pub(crate) fn exposed(method: Method, carrier: Carrier) -> bool {
    match (method, carrier) {
        // Material — Unix socket only, never a model-facing carrier.
        (Method::Get, Carrier::Uds) => true,
        (Method::Get, Carrier::Stdio) => false,
        (Method::GetBatch, Carrier::Uds) => false,
        (Method::GetBatch, Carrier::Stdio) => false,
        // Enumeration — no material; the one retrieval-adjacent method a model may reach.
        (Method::List, Carrier::Uds) => true,
        (Method::List, Carrier::Stdio) => true,
        // Manifest — no material, but carries projection inputs a model has no use for.
        (Method::Describe, Carrier::Uds) => false,
        (Method::Describe, Carrier::Stdio) => false,
        // Liveness — no material, no config.
        (Method::Health, Carrier::Uds) => true,
        (Method::Health, Carrier::Stdio) => true,
        // Mutation — UDS only; a model has no need to write config.
        (Method::ConfigSet, Carrier::Uds) => false,
        (Method::ConfigSet, Carrier::Stdio) => false,
        (Method::ConfigGet, Carrier::Uds) => false,
        (Method::ConfigGet, Carrier::Stdio) => false,
        (Method::ConfigUnset, Carrier::Uds) => false,
        (Method::ConfigUnset, Carrier::Stdio) => false,
        (Method::CredentialRemove, Carrier::Uds) => true,
        (Method::CredentialRemove, Carrier::Stdio) => false,
        (Method::CredentialLogout, Carrier::Uds) => true,
        (Method::CredentialLogout, Carrier::Stdio) => false,
        (Method::CredentialTag, Carrier::Uds) => true,
        (Method::CredentialTag, Carrier::Stdio) => false,
        (Method::EnvRemove, Carrier::Uds) => false,
        (Method::EnvRemove, Carrier::Stdio) => false,
        (Method::FileRevalidate, Carrier::Uds) => true,
        (Method::FileRevalidate, Carrier::Stdio) => false,
        // Bootstrap / login — UDS only; intercepted by serve_connection before dispatch.
        // They are in this table purely to keep the match exhaustive; dispatch() returns
        // method-not-found if it is somehow called for these (it should not be).
        (Method::ProfileBootstrap, Carrier::Uds) => true,
        (Method::ProfileBootstrap, Carrier::Stdio) => false,
        (Method::ProfileLogin, Carrier::Uds) => true,
        (Method::ProfileLogin, Carrier::Stdio) => false,
        // Import — UDS only; carries bulk IAM secret material, like bootstrap.
        (Method::ProfileImport, Carrier::Uds) => true,
        (Method::ProfileImport, Carrier::Stdio) => false,
        // Presence gate — UDS only; a model must never see or satisfy a challenge.
        (Method::RequestApprove, Carrier::Uds) => true,
        (Method::RequestApprove, Carrier::Stdio) => false,
        (Method::RequestGet, Carrier::Uds) => true,
        (Method::RequestGet, Carrier::Stdio) => false,
        (Method::RequestList, Carrier::Uds) => true,
        (Method::RequestList, Carrier::Stdio) => false,
        (Method::RequestWithdraw, Carrier::Uds) => true,
        (Method::RequestWithdraw, Carrier::Stdio) => false,
        (Method::PresenceEnroll, Carrier::Uds) => true,
        (Method::PresenceEnroll, Carrier::Stdio) => false,
        (Method::PresenceRevoke, Carrier::Uds) => true,
        (Method::PresenceRevoke, Carrier::Stdio) => false,
        (Method::PresenceStatus, Carrier::Uds) => true,
        (Method::PresenceStatus, Carrier::Stdio) => false,
    }
}

/// Dispatch one request to its handler, mapping the result (or failure) onto a response
/// envelope. Heterogeneous result types are erased to [`Value`] here; the typed
/// `Response<T>` stays the client-side and test-side view.
pub async fn dispatch(
    request: &Request,
    carrier: Carrier,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Response<Value> {
    let id = request.id.clone();
    let Some(method) = Method::parse(&request.method) else {
        return Response::failure(id, RpcError::method_not_found(&request.method));
    };
    if !exposed(method, carrier) {
        return Response::failure(id, RpcError::method_not_found(&request.method));
    }
    if matches!(method, Method::Get | Method::List)
        && request
            .params
            .as_ref()
            .is_some_and(|params| params.contains_key("environment"))
    {
        return Response::failure(
            id,
            RpcError::invalid_params("`environment` is not supported; name a `credential`"),
        );
    }
    match handle(method, request, peer, daemon).await {
        Ok(value) => Response::success(id, value),
        Err(error) => Response::failure(id, error),
    }
}

async fn handle(
    method: Method,
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    match method {
        Method::Health => to_value(HealthResult::default()),
        Method::Get => get(request, peer, daemon).await,
        Method::GetBatch => environment_credentials(request, peer, daemon).await,
        Method::List => list(request, peer, daemon),
        Method::Describe => describe(request, peer, daemon),
        Method::ConfigSet => config_set(request, peer, daemon).await,
        Method::ConfigGet => config_get(request, peer),
        Method::ConfigUnset => config_unset(request, peer, daemon).await,
        Method::CredentialRemove => credential_remove(request, peer, daemon).await,
        Method::CredentialLogout => credential_logout(request, peer, daemon).await,
        Method::CredentialTag => credential_tag(request, peer, daemon).await,
        Method::EnvRemove => env_remove(request, peer, daemon).await,
        Method::FileRevalidate => crate::server::revalidate::handle(request, peer, daemon).await,
        // Non-streaming batch seal, routed here directly (unlike bootstrap/login).
        Method::ProfileImport => {
            crate::server::bootstrap::handle_profile_import(request, peer, daemon).await
        }
        Method::RequestApprove => request_approve(request, peer, daemon).await,
        Method::RequestGet => {
            let params: IdParams = request.params_as()?;
            to_value(daemon.presence.get(approver_or_owner(peer)?, &params.id)?)
        }
        Method::RequestList => to_value(daemon.presence.list(approver_or_owner(peer)?)),
        Method::RequestWithdraw => {
            let params: IdParams = request.params_as()?;
            daemon
                .presence
                .withdraw(authorized_uid(peer)?, &params.id)?;
            to_value(OkResult {})
        }
        Method::PresenceEnroll => presence_enroll(request, peer, daemon),
        Method::PresenceRevoke => {
            let uid = authorized_uid(peer)?;
            daemon
                .integrity
                .verify_custody()
                .map_err(|reason| custody_broken(&reason))?;
            let fingerprint = daemon.presence.revoke(uid)?;
            tracing::info!(
                event = "presence.revoked",
                uid = peer.uid,
                presence_key = fingerprint.as_str(),
                "presence gate"
            );
            to_value(serde_json::json!({ "revoked": fingerprint }))
        }
        Method::PresenceStatus => to_value(daemon.presence.status(authorized_uid(peer)?)),
        // Intercepted by serve_connection before this point; reaching here is a bug.
        Method::ProfileBootstrap | Method::ProfileLogin => {
            Err(RpcError::method_not_found(&request.method))
        }
    }
}

async fn get(request: &Request, peer: &PeerInfo, daemon: &Daemon) -> Result<Value, RpcError> {
    let params: GetParams = request.params_as()?;
    // The form of the request decides the miss code, never what the caller's config holds, so
    // the code discloses nothing the caller did not already know (Requirement 8 AC 7).
    let credential_addressed = params.environment.is_none();
    if params.credential.is_none() {
        return Err(RpcError::invalid_params(
            "credential/get needs a credential",
        ));
    }
    if params.account_id.is_some() != params.role_name.is_some() {
        return Err(RpcError::invalid_params(
            "credential/get needs both account_id and role_name, or neither",
        ));
    }
    let miss = if credential_addressed {
        credential_not_found
    } else {
        not_found
    };
    let uid = if credential_addressed {
        credential_access(peer)?
    } else {
        authorized_uid(peer)?
    };
    let caller = daemon.caller_state(uid);
    let (environment, credential) = (params.environment.as_deref(), params.credential.as_deref());
    // Audit and drift run before anything can miss (Requirement 10 AC 10).
    assess_config(&caller.config, peer, environment, credential, params.claim);
    if let Some(refusal) = serve_refusal(daemon, uid, &caller, environment, credential) {
        return Err(refusal);
    }

    // Credential-addressed: served from the credential alone, whatever environments compose it.
    // Environment-addressed: the environment must compose the credential, and only narrows, since
    // the material comes from the same per-credential lookup (Requirement 10 AC 6-8).
    let credential = match (params.environment.as_deref(), params.credential) {
        (Some(environment), credential) => {
            let members = caller
                .config
                .envs
                .get(environment)
                .ok_or_else(not_found)?
                .credential_list();
            match credential {
                Some(c) if members.contains(&c) => c,
                Some(_) => return Err(not_found()),
                None => members.into_iter().next().ok_or_else(not_found)?,
            }
        }
        (None, Some(c)) if caller.credentials.contains_key(&c) => c,
        (None, _) => return Err(miss()),
    };
    // A pair is read only once the credential resolves, so it never changes a miss, and the
    // stored pair folds into the request without one (Requirement 17 AC 3-4).
    let pair = match (params.account_id.as_deref(), params.role_name.as_deref()) {
        (Some(account_id), Some(role_name)) => match caller.credentials.get(&credential) {
            Some(CredentialSource::AwsIdcSso(sso))
                if sso.account_id == account_id && sso.role_name == role_name =>
            {
                None
            }
            Some(CredentialSource::AwsIdcSso(sso))
                if sso
                    .allowed_roles
                    .iter()
                    .any(|p| p.account_id == account_id && p.role_name == role_name) =>
            {
                Some((account_id, role_name))
            }
            // Any other pair the sign-in may hold still needs the presence-gated approval that
            // adding it to the list takes (`presence-gated-operations` Req 1.7). Audited like a
            // served pair, so a caller probing the list leaves a record.
            Some(CredentialSource::AwsIdcSso(_)) => {
                tracing::warn!(
                    event = "credential.role_selected",
                    uid,
                    credential = %credential,
                    account_id,
                    role_name,
                    outcome = "refused",
                    "credential requested for an account and role it does not allow"
                );
                return Err(RpcError::domain(
                    DomainCode::RoleNotAllowed,
                    format!(
                        "credential '{credential}' does not allow account {account_id}, role \
                         {role_name}; re-bootstrap it with --allow-role to add it"
                    ),
                ));
            }
            Some(_) => {
                return Err(RpcError::domain(
                    DomainCode::RoleSelectionUnsupported,
                    "account_id and role_name apply only to an aws-idc-sso credential",
                ))
            }
            None => return Err(miss()),
        },
        _ => None,
    };
    let lookup = match pair {
        Some((account_id, role_name)) => {
            tracing::info!(
                event = "credential.role_selected",
                uid,
                credential = %credential,
                account_id,
                role_name,
                outcome = "allowed",
                "credential requested for a selected account and role"
            );
            caller
                .store
                .get_role_credential(uid, &credential, account_id, role_name)
                .await
        }
        None => caller.store.get_credential(uid, &credential).await,
    };
    let subject = match params.environment.as_deref() {
        Some(environment) => Subject::Environment(environment),
        None => Subject::Credential,
    };
    to_value(lookup_to_result(credential, lookup, subject)?)
}

/// What a request was addressed to, which decides the wording and code of its failures.
#[derive(Clone, Copy)]
enum Subject<'a> {
    Credential,
    Environment(&'a str),
}

async fn environment_credentials(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let params: GetBatchParams = request.params_as()?;
    let uid = authorized_uid(peer)?;
    let caller = daemon.caller_state(uid);
    assess_config(
        &caller.config,
        peer,
        Some(&params.environment),
        None,
        params.claim,
    );
    if let Some(refusal) = serve_refusal(daemon, uid, &caller, Some(&params.environment), None) {
        return Err(refusal);
    }

    let members = caller
        .config
        .envs
        .get(&params.environment)
        .ok_or_else(not_found)?
        .credential_list();
    // All-or-none: any member failure returns one error and no material. `?` drops every
    // `CredentialResult` collected so far, and each zeroizes its material on drop.
    let mut credentials = Vec::with_capacity(members.len());
    for credential in members {
        let lookup = caller.store.get_credential(uid, &credential).await;
        credentials.push(lookup_to_result(
            credential,
            lookup,
            Subject::Environment(&params.environment),
        )?);
    }
    to_value(GetBatchResult { credentials })
}

fn list(request: &Request, peer: &PeerInfo, daemon: &Daemon) -> Result<Value, RpcError> {
    let params: ListParams = request.params_as()?;
    let bad = |e: credsd_core::error::DaemonError| RpcError::invalid_params(e.detail());
    let filter = credsd_core::tags::fold(params.tags.unwrap_or_default()).map_err(bad)?;
    credsd_core::tags::validate_filter(&filter).map_err(bad)?;
    let Some(uid) = enumerating_uid(peer)? else {
        // A caller with nothing provisioned has an empty list, not an error. Whether
        // `callers/<uid>/` exists is the daemon's business, and a first run should print
        // "no envs configured" rather than a failure the user has to interpret. Such a caller
        // has no environments, so a filter names none and is the same miss as below.
        if params.environment.is_some() {
            return Err(not_found());
        }
        return to_value(ListResult {
            credentials: Vec::new(),
        });
    };
    let caller = daemon.caller_state(uid);
    assess_config(
        &caller.config,
        peer,
        params.environment.as_deref(),
        None,
        None,
    );
    invalid_refusal(&caller)?;

    // Every credential the caller holds, once, whether or not an environment composes it
    // (Requirement 16 AC 4); with a filter, that environment's credentials in its order. A
    // filter naming no environment is the same miss `credential/get` reports for it.
    let (names, environment): (Vec<String>, Option<&String>) = match params.environment.as_ref() {
        Some(filter) => (
            caller
                .config
                .envs
                .get(filter)
                .map(credsd_core::config::EnvConfig::credential_list)
                .ok_or_else(not_found)?,
            Some(filter),
        ),
        None => {
            let mut names: Vec<String> = caller.credentials.keys().cloned().collect();
            names.sort_unstable();
            (names, None)
        }
    };
    let credentials = names
        .into_iter()
        .filter_map(|credential| {
            let tags = caller.tags.get(&credential).cloned().unwrap_or_default();
            if !credsd_core::tags::matches(&tags, &filter) {
                return None;
            }
            let source = caller.credentials.get(&credential);
            Some(CredentialSummary {
                environment: environment.cloned(),
                kind: source
                    .map(CredentialSource::served_kind)
                    .unwrap_or(SHIPPED_KIND),
                source: source
                    .map(CredentialSource::source_type)
                    .unwrap_or(CredentialSourceType::Unsupported),
                status: status_of(uid, &daemon.encryption, &credential, source),
                tags,
                credential,
            })
        })
        .collect();
    to_value(ListResult { credentials })
}

fn describe(request: &Request, peer: &PeerInfo, daemon: &Daemon) -> Result<Value, RpcError> {
    let params: DescribeParams = request.params_as()?;
    let uid = authorized_uid(peer)?;
    let caller = daemon.caller_state(uid);
    assess_config(&caller.config, peer, Some(&params.environment), None, None);
    invalid_refusal(&caller)?;

    let env = caller
        .config
        .envs
        .get(&params.environment)
        .ok_or_else(not_found)?;
    let default = env.default_credential();
    let credentials = env
        .credential_list()
        .into_iter()
        .map(|credential| {
            // A credential an env references but `credentials.toml` does not define reports as
            // `Unsupported` rather than erroring: the manifest still describes the env, and the
            // client's materialization refuses that entry with a message naming it.
            let source = caller.credentials.get(&credential);
            CredentialEntry {
                default: default.as_deref() == Some(credential.as_str()),
                // Kind and env_var come from the full source, not the discriminant: a token
                // source resolves to an access token and names the variable it projects as, and
                // the client materializes from this manifest without reading `credentials.toml`.
                kind: source
                    .map(CredentialSource::served_kind)
                    .unwrap_or(SHIPPED_KIND),
                source: source
                    .map(CredentialSource::source_type)
                    .unwrap_or(CredentialSourceType::Unsupported),
                env_var: source
                    .and_then(CredentialSource::env_var)
                    .map(str::to_owned),
                // The credential level of the projection model has no `credentials.toml` surface
                // yet, so nothing is declared here. The env level travels in
                // `ProfileManifest::projection`, and the invocation level never crosses the wire.
                projection: None,
                status: status_of(
                    uid,
                    &daemon.encryption,
                    &credential,
                    caller.credentials.get(&credential),
                ),
                credential,
            }
        })
        .collect();

    to_value(ProfileManifest {
        environment: params.environment.clone(),
        credentials,
        projection: Projection::from(env),
    })
}

/// Map a store [`Lookup`] onto a wire result or a domain failure.
///
/// The `Unknown` / `Unavailable` / `ReauthRequired` / wrong-type branches are the HTTP
/// surface's `404` / `502` / `428` / `400` re-expressed as domain codes byte-identically to
/// what a caller already branches on.
fn lookup_to_result(
    credential: String,
    lookup: Lookup,
    subject: Subject<'_>,
) -> Result<CredentialResult, RpcError> {
    match lookup {
        Lookup::Ready(creds) => {
            let expires_at = creds.expires_at;
            match &creds.data {
                CredentialData::SessionCredentials {
                    access_key,
                    secret_key,
                    session_token,
                } => Ok(CredentialResult {
                    credential,
                    material: Material::SessionCredentials {
                        access_key_id: access_key.clone(),
                        secret_access_key: secret_key.clone(),
                        session_token: session_token.clone(),
                    },
                    expires_at,
                    // The store serves a shared, per-credential cached session; scoped
                    // minting is not built, so nothing here is minted per request.
                    provenance: Provenance::CachedShared,
                }),
                // Served, not refused: a bearer token is a credential a non-AWS consumer asks for
                // by name. `WrongCredentialType` still fires, but where it belongs — at the
                // *projection*, when a token is asked to fill the AWS ambient credential slot
                // (retrieval spec Req 7 AC 3), which is the ephemeral proxy and
                // `credential_process`, not this method.
                //
                // `Bearer` is not read off the issuer's response: `CredentialData` keeps only the
                // token, since every token credsd obtains today is a Bearer and a DPoP-bound one
                // is never handed to a child (that is out of scope by spec).
                CredentialData::AccessToken { token } => Ok(CredentialResult {
                    credential,
                    material: Material::AccessToken {
                        token: token.clone(),
                        token_type: "Bearer".to_owned(),
                    },
                    expires_at,
                    provenance: Provenance::CachedShared,
                }),
                _ => Err(RpcError::domain(
                    DomainCode::Internal,
                    format!("credential '{credential}' has unrecognised material type"),
                )),
            }
        }
        Lookup::ReauthRequired(input) => {
            let detail = match input {
                ReauthInput::Browser => "complete SSO sign-in in a browser".to_owned(),
                ReauthInput::Code { label } => format!("enter your {label}"),
                _ => "re-authentication required".to_owned(),
            };
            // Login is credential-addressed, so the remediation names the credential whichever
            // way the request was addressed (Requirement 10 AC 12).
            let remediation = format!("creds login --credential {credential}");
            Err(match subject {
                Subject::Credential => RpcError::reauth_required_for_credential(
                    &credential,
                    format!("credential '{credential}' requires re-authentication ({detail})"),
                    remediation,
                ),
                Subject::Environment(environment) => RpcError::reauth_required(
                    environment,
                    format!("env '{environment}' requires re-authentication ({detail})"),
                    remediation,
                ),
            })
        }
        Lookup::Unavailable(cause) => Err(RpcError::domain(
            DomainCode::ProviderUnavailable,
            match subject {
                Subject::Credential => format!("credential '{credential}' unavailable: {cause}"),
                Subject::Environment(environment) => {
                    format!("env '{environment}' credential unavailable: {cause}")
                }
            },
        )),
        Lookup::Unknown => Err(match subject {
            Subject::Credential => credential_not_found(),
            Subject::Environment(_) => not_found(),
        }),
    }
}

/// Emit the caller-assessment audit record, exactly as the HTTP `assess` did — before the
/// authorization gate, so a denied caller and a miss both leave a full audit line.
fn assess_config(
    config: &DaemonConfig,
    peer: &PeerInfo,
    env: Option<&str>,
    credential: Option<&str>,
    claim: Option<Claim>,
) {
    let pid = peer.pid.and_then(|p| u32::try_from(p).ok());
    let claimed = match claim {
        Some(Claim::Agentic) => ClaimedIdentity::Agentic,
        Some(Claim::Unknown) | None => ClaimedIdentity::Unstated,
    };
    CallerAssessment::collect(
        pid,
        peer.uid,
        "uds",
        env,
        credential,
        claimed,
        config.auth.agent_binaries(),
    )
    .log();
}

/// The verified uid, or a not-found failure for any non-`Authorized` decision. Fail-closed:
/// `Denied`, `Unresolved`, and a peerless request all land here, and none is distinguishable
/// from an absent subject on the wire (Requirement 8 AC 3-4).
///
/// `pub` so the bootstrap handler can import it directly without duplicating the logic.
pub fn authorized_uid(peer: &PeerInfo) -> Result<u32, RpcError> {
    match peer.auth {
        CallerAuth::Authorized { uid, .. } => Ok(uid),
        _ => Err(not_found()),
    }
}

/// [`authorized_uid`] for enumeration, where an unprovisioned caller is an empty answer rather
/// than a refusal. `None` means "nothing to enumerate".
///
/// Deny-by-absence exists so a caller cannot learn whether a *named* env exists (Req 8 AC 3-4).
/// Enumerating names nothing, and a kernel-verified uid with no caller root learns nothing from an
/// empty list that it did not already know about itself — so refusing here buys no secrecy and
/// costs every first run a failure. The distinction the daemon would be protecting, "never
/// bootstrapped" versus "bootstrapped with no envs", is not one a caller needs drawn.
///
/// Only [`DenyReason::NoRoot`] is tolerated. An owner mismatch, an unknown uid, or a peer whose
/// credentials could not be read are anomalies rather than empty states, and they keep failing
/// closed — an empty list would tell a caller in one of those states that it had been *seen*.
fn enumerating_uid(peer: &PeerInfo) -> Result<Option<u32>, RpcError> {
    match peer.auth {
        CallerAuth::Authorized { uid, .. } => Ok(Some(uid)),
        CallerAuth::Denied(DenyReason::NoRoot) => Ok(None),
        _ => Err(not_found()),
    }
}

/// `source` supplies the expiry for a source that declares one in config instead of carrying it
/// in its sealed material — `static-secret` is the only such source. Without it a secret the user
/// declared dead would still report `Active` here while a fetch refused it, and `creds list` would
/// disagree with `creds get` about the same credential.
fn status_of(
    uid: u32,
    encryption: &EncryptionService,
    credential: &str,
    source: Option<&CredentialSource>,
) -> SessionStatus {
    // Sealed tokens live at callers/<uid>/credentials/<name>/ in the scoped-user architecture.
    let data_dir = platform::caller_root(uid)
        .join("credentials")
        .join(credential);
    let declared_expiry = match source {
        Some(CredentialSource::StaticSecret(cfg)) => cfg.expires_at,
        _ => None,
    };
    credential_session_status_at(&data_dir, Some(encryption), declared_expiry)
}

fn not_found() -> RpcError {
    credential_not_found()
}

/// The one failure every credential-addressed miss returns, whatever its cause (Requirement 8
/// AC 7): one code and one message, so a miss discloses nothing.
pub(crate) fn credential_not_found() -> RpcError {
    RpcError::domain(DomainCode::CredentialNotFound, "credential not found")
}

/// The one access check every credential-addressed method passes: a caller that fails it misses
/// as a name it does not hold (Requirement 8 AC 7). Claim and tier checks are not part of it.
fn credential_access(peer: &PeerInfo) -> Result<u32, RpcError> {
    authorized_uid(peer).map_err(|_| credential_not_found())
}

/// Why nothing may be served from `caller` (Requirements 3.1, 3.2, 10.6), naming the file that
/// stops it (3.3), or `None` when both files are valid. Every source a served credential has is in
/// `credentials.toml`, so its drift refuses every environment, not only the ones it names. The
/// refusal is audited (8.1).
///
/// Custody is checked here on every serve, not only when `caller` loaded: a cached state is
/// reused while both files are unchanged, and custody can break without either file changing
/// (10.8).
fn serve_refusal(
    daemon: &Daemon,
    uid: u32,
    caller: &CallerState,
    environment: Option<&str>,
    credential: Option<&str>,
) -> Option<RpcError> {
    if let Err(reason) = daemon.integrity.verify_custody() {
        return Some(custody_broken(&reason));
    }
    let Some((name, status)) = [
        (CONFIG, &caller.config_drift),
        (CREDENTIALS, &caller.credentials_drift),
    ]
    .into_iter()
    .find(|(_, status)| !status.is_valid()) else {
        return invalid_refusal(caller).err();
    };
    tracing::info!(
        event = "drift.refused",
        uid,
        environment,
        credential,
        file = name,
        drift = ?status,
        "credential refused: a load-bearing file is not verified"
    );
    let subject = match environment {
        Some(environment) => format!("environment '{environment}'"),
        None => format!("credential '{}'", credential.unwrap_or_default()),
    };
    Some(match status {
        DriftStatus::Unverifiable => unverifiable("see the daemon log"),
        _ if name == CONFIG => RpcError::domain(
            DomainCode::ConfigDrifted,
            format!(
                "{subject} configuration has drifted from its sealed snapshot; \
                 run: creds revalidate"
            ),
        ),
        _ => RpcError::domain(
            DomainCode::ConfigDrifted,
            format!(
                "{subject} credential sources (credentials.toml) have drifted \
                 from their sealed snapshot; run: creds revalidate"
            ),
        ),
    })
}

/// The refusal every caller read returns while `caller`'s files parse but do not validate. It
/// carries the validation errors, which name the credential and key and never a tag value
/// (`credential-tags` Requirement 1.5).
fn invalid_refusal(caller: &CallerState) -> Result<(), RpcError> {
    caller
        .config_invalid
        .as_deref()
        .map_or(Ok(()), |errors| Err(config_invalid(errors)))
}

fn config_invalid(errors: &str) -> RpcError {
    RpcError::domain(
        DomainCode::ConfigInvalid,
        format!(
            "caller configuration does not validate: {errors}; fix it, then run: creds revalidate"
        ),
    )
}

pub(crate) fn to_value<T: Serialize>(value: T) -> Result<Value, RpcError> {
    serde_json::to_value(value).map_err(|e| RpcError::internal(e.to_string()))
}

// ── Mutation handlers ─────────────────────────────────────────────────────────
// Each is scoped daemon-side to the caller's own callers/<uid>/ folder; the
// daemon is the sole writer. No raw secret material is accepted here — bootstrap
// and login remain client-side for this run.

fn caller_config_path(uid: u32) -> std::path::PathBuf {
    platform::caller_root(uid).join("config.toml")
}

/// Name of the directory a replaced credential is moved to before its replacement lands. The
/// credential name leads, so removal can find it again. Names may contain `.`, so the id after
/// the last `.` is the only part that matching trusts (see `is_replaced_aside_of`).
pub(crate) fn replaced_aside_name(credential: &str, id: &str) -> String {
    format!(".replaced-{credential}.{id}")
}

/// True when `entry` is an aside of `credential`. `x.b`'s archive also starts with `.replaced-x.`,
/// so the remainder must be a bare id with no further `.`.
fn is_replaced_aside_of(entry: &str, credential: &str) -> bool {
    entry
        .strip_prefix(&format!(".replaced-{credential}."))
        .is_some_and(|id| !id.contains('.'))
}

fn caller_credentials_path(uid: u32) -> std::path::PathBuf {
    platform::caller_root(uid).join("credentials.toml")
}

async fn config_set(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let uid = authorized_uid(peer)?;
    let _guard = daemon.bootstrap_lock(uid).lock_owned().await;
    let params: ConfigSetParams = request.params_as()?;
    // Refused now, not only at apply, so no challenge is raised for a write that would be
    // refused over drift once approved.
    let files = TomlFiles::read(uid).map_err(|e| internal(e.to_string()))?;
    precheck_for_write(daemon, uid, &files, &[CONFIG])?;
    if let Some(reason) = keys::is_protected(&params.key) {
        return Err(RpcError::invalid_params(format!(
            "cannot set '{}': {}",
            params.key, reason
        )));
    }
    let key_def = keys::find_key(&params.key)
        .ok_or_else(|| RpcError::invalid_params(format!("unknown config key '{}'", params.key)))?;
    key_def
        .value_type
        .validate(&params.value, &params.key)
        .map_err(|e| RpcError::invalid_params(e.to_string()))?;
    // Refuse now what approval could only fail later: a challenge for a write against a missing
    // environment would ask the user to approve something that cannot happen.
    config::get_env_key_at(&caller_config_path(uid), &params.environment, key_def)
        .map_err(|e| RpcError::invalid_params(e.to_string()))?;
    // The built-in gate (presence-gated-operations Requirement 1.7): every `config/set` requires
    // verified presence, so it is always a salvageable deny and always raises a challenge.
    let description = format!(
        "set {} = {} on environment '{}'",
        params.key, params.value, params.environment
    );
    let challenge = daemon.presence.raise(
        peer,
        uid,
        Op::ConfigSet {
            environment: params.environment,
            key: params.key,
            value: params.value,
            base: crate::server::bootstrap::records_base_of(uid, &files, &[])
                .map_err(|e| internal(e.to_string()))?,
        },
        description,
    );
    let remediation = format!("sudo creds request approve {}", challenge.id);
    Err(RpcError::approval_required(&challenge, remediation))
}

/// Perform a `config/set` that has passed the gate. Revalidates the key and value: the pending
/// record holds what was validated, but the key table is the authority at write time.
fn apply_config_set(
    held: &Held<'_>,
    uid: u32,
    environment: &str,
    key: &str,
    value: &str,
    files: &TomlFiles,
    daemon: &Daemon,
) -> Result<(), RpcError> {
    let key_def = keys::find_key(key)
        .ok_or_else(|| RpcError::invalid_params(format!("unknown config key '{key}'")))?;
    let validated = key_def
        .value_type
        .validate(value, key)
        .map_err(|e| RpcError::invalid_params(e.to_string()))?;
    let config_path = caller_config_path(uid);
    let checked = checked_text(&files.config)?;
    records_unchanged(uid, files)?;
    let mut verified = verify_for_write(daemon, held, uid, files, &[CONFIG])?;
    let edited = config::set_env_key_in(checked, environment, key_def, validated)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    // Validate before writing, not after. The key table enforces one key's shape, while
    // `DaemonConfig::validate` enforces the privilege lattice between an env and the credentials
    // it composes — a check `load_from` makes on every normal read, so a gated write must make it
    // too. Writing first would leave a refused operation's edit on disk under the previous seal,
    // which the daemon then reports as drift.
    let config = validated_config(&edited, files)?;
    config::write_config_file(&config_path, &edited).map_err(|e| internal(e.to_string()))?;
    let canonical = seal_config(&verified, &config, daemon)?;
    verified.pin_sealed(CONFIG, &canonical);
    daemon.integrity.write(verified)?;
    daemon.evict_caller(uid);
    Ok(())
}

/// Parse edited config text and check it against the credentials the approval checked. Uses
/// `files.credentials` rather than rereading `credentials.toml`: the validation outcome depends
/// on those bytes, so reading them again would decide against a version no one approved.
fn validated_config(edited: &str, files: &TomlFiles) -> Result<DaemonConfig, RpcError> {
    let config = DaemonConfig::from_text(edited).map_err(|e| internal(e.to_string()))?;
    let credentials =
        credsd_core::config::credentials::from_text(checked_text(&files.credentials)?)
            .map_err(|e| internal(e.to_string()))?;
    if let Err(errors) = config.validate(&credentials) {
        let error = credsd_core::error::DaemonError::config(errors.join("\n"));
        return Err(internal(error.to_string()));
    }
    Ok(config)
}

/// Reseal the snapshot over a config that has just been written, returning the canonical form it
/// seals for the integrity record to pin.
fn seal_config(
    verified: &Verified,
    config: &DaemonConfig,
    daemon: &Daemon,
) -> Result<Vec<u8>, RpcError> {
    let uid = verified.uid();
    let rel = std::path::Path::new("callers")
        .join(uid.to_string())
        .join("config.toml");
    let canonical = credsd_core::config::snapshot::canonical_config(uid, &rel, config)
        .map_err(|e| internal(e.to_string()))?;
    verified
        .seal_snapshot(&daemon.encryption, CONFIG, &canonical)
        .map_err(|e| internal(e.to_string()))?;
    Ok(canonical)
}

/// The uid whose pending operations this connection may see or act on: 0 for an approver, else
/// the authorized caller's own. A uid-0 connection needs no caller root (Requirement 7.6).
fn approver_or_owner(peer: &PeerInfo) -> Result<u32, RpcError> {
    match peer.uid {
        Some(0) => Ok(0),
        _ => authorized_uid(peer),
    }
}

fn presence_enroll(request: &Request, peer: &PeerInfo, daemon: &Daemon) -> Result<Value, RpcError> {
    if peer.uid == Some(0) {
        return Err(RpcError::invalid_params(
            "a presence key is enrolled for the uid that raises the request, and this connection \
             is uid 0 — run 'creds presence enroll' without sudo; approval is a separate, \
             privileged step",
        ));
    }
    let uid = authorized_uid(peer)?;
    let params: EnrollParams = request.params_as()?;
    let public_key = presence_wire::unhex(&params.public_key)
        .ok_or_else(|| RpcError::invalid_params("public_key is not hex"))?;
    to_value(daemon.presence.enroll(peer, uid, public_key)?)
}

async fn request_approve(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let params: ApproveParams = request.params_as()?;
    if peer.uid != Some(0) {
        authorized_uid(peer)?;
    }
    // Before the approval is spent: a presence signature is checked against the registry, and
    // every commit writes what the integrity record governs (drift-detection Requirement 10.8).
    daemon
        .integrity
        .verify_custody()
        .map_err(|reason| custody_broken(&reason))?;
    let (pending, verifier) = daemon.presence.take_approved(peer, &params)?;
    let owner = pending.owner_uid;
    // One flow for every gated operation: the base-state recheck and the discard it can end in
    // are not something an individual operation may skip (presence Requirement 2.6).
    let guard = daemon.write_guard(owner).await;
    // A record that will not read cannot be confirmed to still be in its recorded base state, so
    // it takes the same audited discard as one that changed. `take_approved` above has already
    // spent the approval: returning an internal error here instead would throw away a verified
    // proof with no record that it was ever presented. The kind is logged rather than the error
    // text, which can carry a path.
    let (files, base) = match TomlFiles::read(owner)
        .and_then(|files| current_base(&pending.op, owner, &files).map(|base| (files, base)))
    {
        Ok(confirmed) => confirmed,
        Err(e) => {
            tracing::info!(
                event = "presence.approve",
                pending_operation = pending.id.as_str(),
                proof_verified = true,
                verifier,
                error_kind = ?e.kind(),
                outcome = "discarded: the records it would change could not be read",
                "presence gate"
            );
            return Err(super::bootstrap::records_unreadable(&pending.id));
        }
    };
    if base != pending.op.recorded_base() {
        tracing::info!(
            event = "presence.approve",
            pending_operation = pending.id.as_str(),
            proof_verified = true,
            verifier,
            outcome = "discarded: the records it would change were modified since the request",
            "presence gate"
        );
        return Err(RpcError::approval_refused(
            credsd_core::presence::RefusalReason::BaseStateChanged,
            format!(
                "{}: the records this would change were modified after it was requested, so the \
                 approval no longer describes the state it would apply to; discarded unperformed",
                pending.id
            ),
            "re-run the original command to raise a new request against the current state",
        ));
    }
    let outcome = apply(&guard.held(), &pending, owner, peer, daemon, &files)?;
    tracing::info!(
        event = "presence.approve",
        pending_operation = pending.id.as_str(),
        proof_verified = true,
        verifier,
        presence_key = (verifier == "presence_signature")
            .then(|| daemon.presence.fingerprint_for(owner))
            .flatten()
            .as_deref(),
        approver_uid = peer.uid,
        approver_login_uid = peer.login_uid,
        approver_pid = peer.pid,
        approver_executable = peer.executable.as_deref(),
        outcome = outcome.as_str(),
        "presence gate"
    );
    to_value(ApproveResult {
        outcome,
        verifier: verifier.to_owned(),
    })
}

/// The base state of an operation's subject records as they stand now, computed the same way it
/// was when the operation was raised.
fn current_base(op: &Op, owner: u32, files: &TomlFiles) -> std::io::Result<Option<[u8; 32]>> {
    use crate::server::bootstrap::records_base_of;
    Ok(match op {
        Op::ConfigSet { .. } | Op::ConfigUnset { .. } => Some(records_base_of(owner, files, &[])?),
        Op::Bootstrap { credential, .. } | Op::RemoveCredential { credential, .. } => {
            Some(records_base_of(owner, files, &[credential.as_str()])?)
        }
        Op::Import { credentials, .. } => {
            let names: Vec<&str> = credentials.iter().map(String::as_str).collect();
            Some(records_base_of(owner, files, &names)?)
        }
        Op::RemoveEnvironment { .. } | Op::Revalidate { .. } => {
            Some(records_base_of(owner, files, &[])?)
        }
        Op::Enroll { .. } => None,
    })
}

/// Perform an approved operation, returning the outcome for the audit record. The caller holds
/// the owner's write lock and has confirmed the base state is unchanged.
fn apply(
    held: &Held<'_>,
    pending: &crate::server::presence::Pending,
    owner: u32,
    peer: &PeerInfo,
    daemon: &Daemon,
    files: &TomlFiles,
) -> Result<String, RpcError> {
    Ok(match &pending.op {
        Op::ConfigSet {
            environment,
            key,
            value,
            ..
        } => {
            apply_config_set(held, owner, environment, key, value, files, daemon)?;
            format!("set {key} = {value} on environment '{environment}' for uid {owner}")
        }
        Op::Enroll { public_key } => {
            let fingerprint = daemon.presence.install_key(owner, public_key, peer)?;
            format!("presence key {fingerprint} enrolled for uid {owner}")
        }
        Op::Bootstrap { credential, .. } => {
            daemon.presence.authorize(pending);
            format!(
                "authorized a bootstrap of credential '{credential}' for uid {owner}; re-run the \
                 same bootstrap within 5 minutes to apply it"
            )
        }
        Op::ConfigUnset {
            environment, key, ..
        } => {
            apply_config_unset(held, owner, environment, key, files, daemon)?;
            format!("unset {key} on environment '{environment}' for uid {owner}")
        }
        Op::Import { credentials, .. } => {
            daemon.presence.authorize(pending);
            format!(
                "authorized an import replacing {} for uid {owner}; re-run the same import \
                 within 5 minutes to apply it",
                credentials.join(", ")
            )
        }
        Op::RemoveCredential { credential, .. } => {
            apply_credential_remove(held, owner, credential, files, daemon)?;
            format!("removed credential '{credential}' and its sealed data for uid {owner}")
        }
        Op::RemoveEnvironment { environment, .. } => {
            apply_env_remove(held, owner, environment, files, daemon)?;
            format!("removed environment '{environment}' for uid {owner}")
        }
        Op::Revalidate {
            files: names,
            deleted,
            replaces_record,
            ..
        } => crate::server::revalidate::apply(
            held,
            owner,
            names,
            deleted,
            *replaces_record,
            files,
            daemon,
        )?,
    })
}

fn config_get(request: &Request, peer: &PeerInfo) -> Result<Value, RpcError> {
    let uid = authorized_uid(peer)?;
    let params: ConfigGetParams = request.params_as()?;
    if let Some(reason) = keys::is_protected(&params.key) {
        return Err(RpcError::invalid_params(format!(
            "cannot read '{}': {}",
            params.key, reason
        )));
    }
    let key_def = keys::find_key(&params.key)
        .ok_or_else(|| RpcError::invalid_params(format!("unknown config key '{}'", params.key)))?;
    let value = config::get_env_key_at(&caller_config_path(uid), &params.environment, key_def)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    to_value(ConfigGetResult { value })
}

async fn config_unset(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let uid = authorized_uid(peer)?;
    let _guard = daemon.bootstrap_lock(uid).lock_owned().await;
    let params: ConfigUnsetParams = request.params_as()?;
    let files = TomlFiles::read(uid).map_err(|e| internal(e.to_string()))?;
    precheck_for_write(daemon, uid, &files, &[CONFIG])?;
    if let Some(reason) = keys::is_protected(&params.key) {
        return Err(RpcError::invalid_params(format!(
            "cannot unset '{}': {}",
            params.key, reason
        )));
    }
    let key_def = keys::find_key(&params.key)
        .ok_or_else(|| RpcError::invalid_params(format!("unknown config key '{}'", params.key)))?;
    // Refuse now what approval could only fail later, and leave a key that is not set alone
    // without asking: there is nothing to approve when nothing would change.
    let Some(current) =
        config::get_env_key_at(&caller_config_path(uid), &params.environment, key_def)
            .map_err(|e| RpcError::invalid_params(e.to_string()))?
    else {
        return to_value(OkResult {});
    };
    // Refused here rather than at apply, so no challenge is ever raised for an operation that
    // could only grant privilege. Checked after the no-op return above: a key that is already
    // absent has nothing to escalate, so unsetting it stays a harmless no-op like any other key.
    // The daemon is the boundary: the client runs the same check for a faster error, but a caller
    // that skips the client still cannot get past this one.
    if let Some(reason) = keys::is_unset_protected(&params.key) {
        return Err(RpcError::invalid_params(format!(
            "cannot unset '{}': {}",
            params.key, reason
        )));
    }
    // The built-in gate (presence-gated-operations Requirement 1.7). Unsetting is not harmless — it falls
    // back to a default, and `identity_type`'s default is the least restrictive tier — so every
    // `config/unset` that would change something requires verified presence, like `config/set`.
    let description = format!(
        "unset {} on environment '{}' (currently {current})",
        params.key, params.environment
    );
    let challenge = daemon.presence.raise(
        peer,
        uid,
        Op::ConfigUnset {
            environment: params.environment,
            key: params.key,
            base: crate::server::bootstrap::records_base_of(uid, &files, &[])
                .map_err(|e| internal(e.to_string()))?,
        },
        description,
    );
    let remediation = format!("sudo creds request approve {}", challenge.id);
    Err(RpcError::approval_required(&challenge, remediation))
}

/// The unset `config/unset` describes, performed once approved.
fn apply_config_unset(
    held: &Held<'_>,
    uid: u32,
    environment: &str,
    key: &str,
    files: &TomlFiles,
    daemon: &Daemon,
) -> Result<(), RpcError> {
    // Re-checked here, not just at the RPC that raises this op: a pending op applies through this
    // function alone, so the escalation guard belongs where it cannot be skipped by a second path
    // to the same apply, present or future.
    if let Some(reason) = keys::is_unset_protected(key) {
        return Err(RpcError::domain(
            DomainCode::Internal,
            format!("cannot unset '{key}': {reason}"),
        ));
    }
    // Validated when the request was raised; failing now is the daemon's fault, not the caller's.
    let key_def = keys::find_key(key).ok_or_else(|| {
        RpcError::domain(DomainCode::Internal, format!("unknown config key '{key}'"))
    })?;
    let config_path = caller_config_path(uid);
    let checked = checked_text(&files.config)?;
    records_unchanged(uid, files)?;
    let mut verified = verify_for_write(daemon, held, uid, files, &[CONFIG])?;
    let edited = config::unset_env_key_in(checked, environment, key_def)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    // Not validated, matching the behavior this path has always had: unsetting a key removes a
    // value rather than introducing one, so it cannot create the env-to-credential violation the
    // set arm has to guard. Revisit together with the defaulting of `identity_type`, where the
    // fallback is the most privileged tier.
    let config = DaemonConfig::from_text(&edited)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    config::write_config_file(&config_path, &edited).map_err(|e| internal(e.to_string()))?;
    let canonical = seal_config(&verified, &config, daemon)?;
    verified.pin_sealed(CONFIG, &canonical);
    daemon.integrity.write(verified)?;
    daemon.evict_caller(uid);
    Ok(())
}

async fn credential_remove(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let uid = credential_access(peer)?;
    let _guard = daemon.bootstrap_lock(uid).lock_owned().await;
    let params: CredentialRemoveParams = request.params_as()?;
    let root = platform::caller_root(uid);

    // Refuse now what approval could only fail later, and before any challenge exists, so a
    // challenge never confirms that a name is there (presence Requirement 8.5).
    let (config, credentials) = config::DaemonConfig::load_from(&root)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    let sealed = root.join("credentials").join(&params.credential).exists()
        || !replaced_asides_of(uid, &params.credential)?.is_empty();
    if !sealed && !credentials.contains_key(&params.credential) {
        return Err(credential_not_found());
    }
    // Refuse over drift rather than reseal it: the reseal would trust a same-uid hand edit as a
    // side effect of this removal. A deleted credentials.toml the record names is drift too, not
    // a removal with nothing to check.
    let files = TomlFiles::read(uid).map_err(|e| internal(e.to_string()))?;
    precheck_for_write(daemon, uid, &files, &[CREDENTIALS])?;
    // Refuse while any env still references it: that env would be left pointing at a credential
    // the daemon can no longer resolve. The check has to happen here — a client cannot read this
    // uid's config to make it, which is why the CLI's version of this guard never fired.
    let users = config.envs_using(&params.credential);
    if !users.is_empty() {
        return Err(RpcError::invalid_params(format!(
            "credential '{}' is still referenced by env(s): {}",
            params.credential,
            users.join(", ")
        )));
    }

    // The built-in gate (presence-gated-operations Requirement 1.7): removal destroys sealed material a
    // same-uid process could not restore, so it always needs presence.
    let description = format!(
        "remove credential '{}' and its sealed data{}",
        params.credential,
        if sealed {
            ""
        } else {
            " (no sealed data present)"
        }
    );
    let challenge = daemon.presence.raise(
        peer,
        uid,
        Op::RemoveCredential {
            base: crate::server::bootstrap::records_base_of(
                uid,
                &files,
                &[params.credential.as_str()],
            )
            .map_err(|e| internal(e.to_string()))?,
            credential: params.credential,
        },
        description,
    );
    let remediation = format!("sudo creds request approve {}", challenge.id);
    Err(RpcError::approval_required(&challenge, remediation))
}

/// Sign a credential out (credential-retrieval-api Requirement 15 AC 12-19): delete the sealed
/// session of a credential whose source signs in, keep its entry, and leave the next
/// `credential/login` to restore it. Ungated: login already replaces this material ungated, and a
/// logout only ends the session (presence-gated-operations Requirement 1.7).
async fn credential_logout(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let uid = credential_access(peer)?;
    let params: CredentialLogoutParams = request.params_as()?;
    crate::server::write_lock::under(
        &daemon.bootstrap_lock(uid),
        uid,
        LOGOUT_LOCK_BUDGET,
        async |held| logout_under_lock(held, uid, &params, peer, daemon).await,
    )
    .await
    .map_err(|expired| {
        // Either expiry lands before any deletion: the wait before the body starts, the hold at
        // its one await, the bounded SSO call. Other errors may leave the logout partly done;
        // retrying the same logout is safe and finishes it.
        internal(format!(
            "{} {}s, so '{}' was not signed out; nothing was deleted, retry",
            match expired {
                crate::server::write_lock::Expired::Wait =>
                    "another operation held this user's write lock for longer than",
                crate::server::write_lock::Expired::Hold => "the logout did not finish within",
            },
            expired.limit(LOGOUT_LOCK_BUDGET).as_secs(),
            params.credential
        ))
    })?
}

/// A logout's claim on the caller's write lock. The wait matches login's and renewal's. The hold
/// is a backstop: the SSO refresh and `Logout` calls share the bound [`SSO_LOGOUT_LIMIT`], so an
/// SSO endpoint that never answers fails those calls rather than the logout, and the session is
/// still deleted here (AC 18).
#[cfg(not(test))]
const LOGOUT_LOCK_BUDGET: crate::server::write_lock::Budget = crate::server::write_lock::Budget {
    wait: std::time::Duration::from_secs(10),
    hold: std::time::Duration::from_secs(60),
};
/// Shorter under test so both bounds are reachable quickly. Same code path.
#[cfg(test)]
const LOGOUT_LOCK_BUDGET: crate::server::write_lock::Budget = crate::server::write_lock::Budget {
    wait: std::time::Duration::from_millis(50),
    hold: std::time::Duration::from_secs(1),
};

/// How long a logout waits on the SSO refresh and `Logout` calls together, covering connect, send,
/// and response with any retries counted inside it (AC 18). Half of [`LOGOUT_LOCK_BUDGET`]'s
/// 60-second hold, so the calls plus the local deletion end inside that hold. Writers queued
/// behind the logout are not promised the lock within their own wait (`drift-detection` 5.9).
#[cfg(not(test))]
const SSO_LOGOUT_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);
/// Half the test hold, the same ratio. Same code path.
#[cfg(test)]
const SSO_LOGOUT_LIMIT: std::time::Duration = std::time::Duration::from_millis(500);

async fn logout_under_lock(
    held: Held<'_>,
    uid: u32,
    params: &CredentialLogoutParams,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    // The drift check comes before the entry is read: a hand-edited source type must not widen
    // what a logout deletes, and a drifted caller must not learn which names exist from a miss.
    let files = TomlFiles::read(uid).map_err(|e| internal(e.to_string()))?;
    // Run under the lock; nothing is sealed, so the token it yields is not kept.
    verify_for_write(daemon, &held, uid, &files, &[CONFIG, CREDENTIALS]).map(drop)?;
    let credentials =
        credsd_core::config::credentials::parse_sources(checked_text(&files.credentials)?)
            .map_err(|e| internal(e.to_string()))?;
    let source = match credentials.get(&params.credential) {
        None => return Err(credential_not_found()),
        Some(
            source @ (CredentialSource::AwsLogin(_)
            | CredentialSource::AwsIdcSso(_)
            | CredentialSource::AwsWebIdentity(_)),
        ) => source,
        Some(source) => {
            return Err(RpcError::domain(
                DomainCode::LogoutUnsupportedSource,
                format!(
                    "credential '{}' is a {} source: it has no sign-in to log out of; remove it \
                     with credential/remove (creds remove --credential {})",
                    params.credential,
                    source.type_name(),
                    params.credential
                ),
            ))
        }
    };
    let data_dir = platform::caller_root(uid)
        .join("credentials")
        .join(&params.credential);
    // End the sign-in at SSO while its token is still sealed here. The local deletion below
    // happens either way, so nothing is left behind, and the logout succeeds once it does; a
    // failed call is reported as the provider outcome, since the session stays live at SSO
    // until it expires.
    let mut provider_logout = None;
    if let CredentialSource::AwsIdcSso(sso) = source {
        let provider = credsd_core::providers::sso::SsoProvider::new(
            params.credential.clone(),
            sso.clone(),
            daemon.encryption.clone(),
            data_dir.clone(),
        );
        #[cfg(test)]
        let provider = match tests::SSO_ENDPOINT.with(|url| url.borrow().clone()) {
            Some(url) => provider.with_endpoint(url),
            None => provider,
        };
        provider_logout = match provider.logout(SSO_LOGOUT_LIMIT).await {
            Ok(Some(LogoutEnded::Accepted)) => Some(ProviderLogout::Ended),
            Ok(Some(LogoutEnded::TokenRejected)) => Some(ProviderLogout::TokenRejected),
            Ok(None) => None,
            Err(failed) => {
                tracing::warn!(
                    event = "credential.sso_logout_failed",
                    uid,
                    credential = %params.credential,
                    error = %credsd_core::log::escape_log(&failed.error),
                    "SSO Logout failed; the local session is deleted, the token stays valid at SSO until it expires"
                );
                Some(ProviderLogout::Failed {
                    start_url: sso.start_url.clone(),
                    access_token_expires_at: failed.expires_at,
                })
            }
        };
    }
    delete_session(
        uid,
        &params.credential,
        &data_dir,
        provider_logout,
        peer,
        daemon,
    )
}

/// The logout's local deletion, from the first file removed to the result. Synchronous on
/// purpose: the write lock's hold bound cancels the logout only at an await, so with none here a
/// hold expiry always lands before anything is deleted and the logout can report that nothing
/// was (credential-retrieval-api Requirement 15 AC 18). Keep it a plain `fn`; the compiler then
/// refuses any `.await` added to it.
fn delete_session(
    uid: u32,
    credential: &str,
    data_dir: &std::path::Path,
    provider_logout: Option<ProviderLogout>,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let mut asides = Vec::new();
    for aside in replaced_asides_of(uid, credential)? {
        if holds_only_sign_in_output(&aside)? {
            asides.push(aside);
        }
    }
    let had_session = clear_session(data_dir)?;
    sweep_replaced_asides(&asides)?;
    // Drops the cached session too, so nothing held is served once this returns.
    daemon.evict_caller(uid);
    let signed_out = had_session || !asides.is_empty();
    if signed_out {
        crate::server::bootstrap::record_mutation(peer, uid, METHOD_CREDENTIAL_LOGOUT, credential);
    }
    to_value(LogoutResult::from(provider_logout.unwrap_or(
        if signed_out {
            ProviderLogout::LocalOnly
        } else {
            ProviderLogout::None
        },
    )))
}

// Fails to compile if `delete_session` becomes `async`: its return type would then be a future.
type DeleteSession = fn(
    u32,
    &str,
    &std::path::Path,
    Option<ProviderLogout>,
    &PeerInfo,
    &Daemon,
) -> Result<Value, RpcError>;
const _: DeleteSession = delete_session;

/// The one file a logout keeps: the record of who signed in, which the next sign-in compares
/// against.
const KEPT_ON_LOGOUT: &str = credsd_core::providers::aws_login::IDENTITY_FILE;

/// The files a sign-in writes to a data directory for `aws-login`, `aws-idc-sso`, and
/// `aws-web-identity` (AC 13), plus [`KEPT_ON_LOGOUT`].
const SIGN_IN_OUTPUT: [&str; 5] = [
    "aws_login_token.enc",
    "dpop_key.enc",
    "sso_token.enc",
    "oauth_token.enc",
    KEPT_ON_LOGOUT,
];

/// True when every entry of the archive `aside` is a non-directory named in [`SIGN_IN_OUTPUT`]
/// (a symlink is removed, never followed, by the sweep). Nothing records
/// an archive's source once its entry is replaced, so the files decide (AC 12): an archive holding
/// anything else, such as an IAM key from before a re-bootstrap, is left for the gated remove.
fn holds_only_sign_in_output(aside: &std::path::Path) -> Result<bool, RpcError> {
    for entry in std::fs::read_dir(aside).map_err(|e| internal(e.to_string()))? {
        let entry = entry.map_err(|e| internal(e.to_string()))?;
        let is_dir = entry
            .file_type()
            .map_err(|e| internal(e.to_string()))?
            .is_dir();
        if is_dir || !SIGN_IN_OUTPUT.iter().any(|f| entry.file_name() == *f) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Delete everything in a credential's data directory except [`KEPT_ON_LOGOUT`], and the directory
/// itself once empty. `true` when anything was deleted, the directory included, so a retry after a
/// failed directory removal still reports and audits the sign-out it finishes.
fn clear_session(data_dir: &std::path::Path) -> Result<bool, RpcError> {
    let entries = match std::fs::read_dir(data_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(internal(e.to_string())),
    };
    let mut deleted = false;
    let mut kept = false;
    for entry in entries {
        let entry = entry.map_err(|e| internal(e.to_string()))?;
        if entry.file_name() == KEPT_ON_LOGOUT {
            kept = true;
            continue;
        }
        let path = entry.path();
        let removed = if entry
            .file_type()
            .map_err(|e| internal(e.to_string()))?
            .is_dir()
        {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.map_err(|e| internal(e.to_string()))?;
        deleted = true;
    }
    if !kept {
        std::fs::remove_dir(data_dir).map_err(|e| internal(e.to_string()))?;
    }
    Ok(deleted || !kept)
}
/// `credential/tag`: replace a credential's tags. No presence gate: tags carry no authority
/// (credential-tags Requirement 5.1), but the write goes through the same drift check and seal as
/// every other edit to `credentials.toml`.
async fn credential_tag(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let uid = credential_access(peer)?;
    let mut params: CredentialTagParams = request.params_as()?;
    let name = params.credential.clone();
    let bad = |e: credsd_core::error::DaemonError| {
        RpcError::invalid_params(format!("credential '{name}': {}", e.detail()))
    };
    // Folded and refused before any read, so a bad edit names its key without revealing whether
    // the credential exists, and `Env` in `set` conflicts with `env` in `unset`.
    params.set = credsd_core::tags::fold(std::mem::take(&mut params.set)).map_err(bad)?;
    params.unset = credsd_core::tags::fold_keys(std::mem::take(&mut params.unset)).map_err(bad)?;
    params
        .unset
        .iter()
        .try_for_each(|k| credsd_core::tags::validate_key(k))
        .map_err(bad)?;
    credsd_core::tags::apply(&Tags::new(), &params.set, &params.unset).map_err(bad)?;
    let guard = daemon.write_guard(uid).await;
    let files = TomlFiles::read(uid).map_err(|e| internal(e.to_string()))?;
    let mut verified = verify_for_write(daemon, &guard.held(), uid, &files, &[CREDENTIALS])?;
    let checked = checked_text(&files.credentials)?;
    let mut entries = credsd_core::config::credentials::parse_tagged(checked)
        .map_err(|e| internal(e.detail()))?;
    credsd_core::config::credentials::check_tags(&mut entries)
        .map_err(|e| config_invalid(&e.detail()))?;
    let old = &entries.get(&params.credential).ok_or_else(not_found)?.tags;
    let tags = credsd_core::tags::apply(old, &params.set, &params.unset).map_err(bad)?;
    if &tags == old {
        return to_value(OkResult {});
    }
    let enc = &daemon.encryption;
    let written = credsd_core::config::credentials::set_tags_from(
        &caller_credentials_path(uid),
        checked,
        &params.credential,
        &tags,
        |text| seal_credentials_text(&verified, enc, text),
    );
    daemon.evict_caller(uid);
    let text = written
        .map_err(|e| internal(e.to_string()))?
        .ok_or_else(not_found)?;
    verified.pin_sealed(
        CREDENTIALS,
        &canonical_credentials_text(uid, &text).map_err(|e| internal(e.to_string()))?,
    );
    daemon.integrity.write(verified)?;
    crate::server::bootstrap::record_mutation(peer, uid, METHOD_CREDENTIAL_TAG, &params.credential);
    to_value(OkResult {})
}

/// The removal `credential/remove` describes, performed once approved.
fn apply_credential_remove(
    held: &Held<'_>,
    uid: u32,
    credential: &str,
    files: &TomlFiles,
    daemon: &Daemon,
) -> Result<(), RpcError> {
    let checked = checked_text(&files.credentials)?;
    records_unchanged(uid, files)?;
    let verified = verify_for_write(daemon, held, uid, files, &[CREDENTIALS])?;
    let removed = remove_credential_files(uid, credential, checked, verified, daemon);
    // Evict after any write attempt, success or failure: a step that failed after writing has
    // already changed the files. The refusals above write nothing, so they skip it.
    daemon.evict_caller(uid);
    removed
}

fn remove_credential_files(
    uid: u32,
    credential: &str,
    checked: &str,
    mut verified: Verified,
    daemon: &Daemon,
) -> Result<(), RpcError> {
    let enc = &daemon.encryption;
    // The entry first, then the sealed material. Every refusal (parse, write) happens before
    // anything is deleted, so a refusal leaves the sealed material in place. Deleting the
    // directory is the daemon's job because `callers/<uid>/` is the daemon's tree; the client
    // attempt this replaces hit EACCES on the 0700 parent, read that as "nothing to delete", and
    // left a credential the daemon could still mint sessions from.
    let removed = credsd_core::config::credentials::remove_credential_from(
        &caller_credentials_path(uid),
        checked,
        credential,
        |text| seal_credentials_text(&verified, enc, text),
    )
    .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    // The entry was already gone, so the snapshot can still list it: seal the checked text, which
    // `records_unchanged` has verified against disk.
    if removed.is_none() {
        seal_credentials_text(&verified, enc, checked).map_err(|e| internal(e.to_string()))?;
    }
    // Pinned before any sealed material is deleted, so a failed record update (Requirement 5.7)
    // leaves the material in place for a retry.
    let sealed_text = removed.as_deref().unwrap_or(checked);
    verified.pin_sealed(
        CREDENTIALS,
        &canonical_credentials_text(uid, sealed_text).map_err(|e| internal(e.to_string()))?,
    );
    daemon.integrity.write(verified)?;
    let data_dir = platform::caller_root(uid)
        .join("credentials")
        .join(credential);
    let data_existed = match std::fs::symlink_metadata(&data_dir) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(RpcError::domain(DomainCode::Internal, e.to_string())),
    };
    // A sweep that failed on an earlier attempt leaves archives behind with the entry gone, so
    // they count as sealed data here. Otherwise a retry could find nothing to finish.
    let asides = replaced_asides_of(uid, credential)?;
    // The request handler only let this through because the config entry or the sealed data (or
    // both) existed, and `records_unchanged` just confirmed the config entry's state hasn't
    // moved since. Neither here means the approval no longer matches anything on disk — surface
    // that loudly instead of reporting a removal that did not happen.
    if removed.is_none() && !data_existed && asides.is_empty() {
        return Err(internal(format!(
            "credential '{credential}' was approved for removal but neither its config entry \
             nor its sealed data exist"
        )));
    }
    if data_existed {
        std::fs::remove_dir_all(&data_dir)
            .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    }
    sweep_replaced_asides(&asides)
}

/// The `.replaced-*` archives of `credential` in the caller's tree. Empty when the tree has no
/// `credentials/` directory yet.
fn replaced_asides_of(uid: u32, credential: &str) -> Result<Vec<std::path::PathBuf>, RpcError> {
    let root = platform::caller_root(uid).join("credentials");
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(RpcError::domain(DomainCode::Internal, e.to_string())),
    };
    let mut asides = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
        if is_replaced_aside_of(&entry.file_name().to_string_lossy(), credential) {
            asides.push(entry.path());
        }
    }
    Ok(asides)
}

/// Delete the archives a replacement of `credential` left behind. A removal must not leave
/// the old material where a rename could bring it back. The first failure is returned, so the
/// caller sees it and a retry finds the archives that remain.
fn sweep_replaced_asides(asides: &[std::path::PathBuf]) -> Result<(), RpcError> {
    for aside in asides {
        std::fs::remove_dir_all(aside)
            .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    }
    Ok(())
}

/// Seal the credentials snapshot for `text`, the exact bytes about to be written. Sealing before
/// the write means a failed seal leaves `credentials.toml` as checked. A failed write after it
/// rolls the seal back to `checked`, so a retry of the same removal succeeds normally. If that
/// rollback also fails, the snapshot is left vouching for `text` while the file still holds
/// `checked`: the shared write check then refuses every retry as drift, and revalidation recovers.
fn seal_credentials_text(
    verified: &Verified,
    enc: &EncryptionService,
    text: &str,
) -> credsd_core::error::Result<()> {
    let canonical = canonical_credentials_text(verified.uid(), text)?;
    verified.seal_snapshot(enc, CREDENTIALS, &canonical)
}

/// The canonical form of `text` as the snapshot records it, so a verify and a seal agree.
fn canonical_credentials_text(uid: u32, text: &str) -> credsd_core::error::Result<Vec<u8>> {
    let entries = credsd_core::config::credentials::parse_tagged(text)?;
    let rel = std::path::Path::new("callers")
        .join(uid.to_string())
        .join("credentials.toml");
    credsd_core::config::snapshot::canonical_credentials(uid, &rel, &entries)
}

pub(crate) fn internal(message: String) -> RpcError {
    RpcError::domain(DomainCode::Internal, message)
}

/// The checked toml bytes as text. A file that is not UTF-8 is refused, not rewritten lossily.
pub(crate) fn checked_text(bytes: &[u8]) -> Result<&str, RpcError> {
    std::str::from_utf8(bytes).map_err(|e| internal(e.to_string()))
}

/// Refuse unless both toml files still hold the bytes the approval checked. Run under the owner's
/// lock immediately before an edit, so a hand edit made after the check is discarded, not written
/// over. A write by another process between this check and the edit is not covered.
pub(crate) fn records_unchanged(uid: u32, checked: &TomlFiles) -> Result<(), RpcError> {
    let now = TomlFiles::read(uid).map_err(|e| internal(e.to_string()))?;
    if &now == checked {
        return Ok(());
    }
    Err(RpcError::approval_refused(
        credsd_core::presence::RefusalReason::BaseStateChanged,
        "the records this would change were modified after it was checked, so the approval no \
         longer describes the state it would apply to; discarded unperformed"
            .to_owned(),
        "re-run the original command to raise a new request against the current state",
    ))
}

async fn env_remove(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let uid = authorized_uid(peer)?;
    let _guard = daemon.bootstrap_lock(uid).lock_owned().await;
    let params: EnvRemoveParams = request.params_as()?;
    let (config, _) = config::DaemonConfig::load_from(&platform::caller_root(uid))
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    let Some(env) = config.envs.get(&params.environment) else {
        return Err(not_found());
    };
    let files = TomlFiles::read(uid).map_err(|e| internal(e.to_string()))?;
    precheck_for_write(daemon, uid, &files, &[CONFIG])?;

    let description = format!(
        "remove environment '{}' (credentials kept: {})",
        params.environment,
        env.credential_list().join(", ")
    );
    let challenge = daemon.presence.raise(
        peer,
        uid,
        Op::RemoveEnvironment {
            environment: params.environment,
            base: crate::server::bootstrap::records_base_of(uid, &files, &[])
                .map_err(|e| internal(e.to_string()))?,
        },
        description,
    );
    let remediation = format!("sudo creds request approve {}", challenge.id);
    Err(RpcError::approval_required(&challenge, remediation))
}

/// The removal `environment/remove` describes, performed once approved. Its credentials are left
/// intact: they are reusable atoms, removed by `credential/remove`.
fn apply_env_remove(
    held: &Held<'_>,
    uid: u32,
    environment: &str,
    files: &TomlFiles,
    daemon: &Daemon,
) -> Result<(), RpcError> {
    let config_path = caller_config_path(uid);
    let checked = checked_text(&files.config)?;
    records_unchanged(uid, files)?;
    let mut verified = verify_for_write(daemon, held, uid, files, &[CONFIG])?;
    // `records_unchanged` confirmed the config text hasn't moved since the request handler
    // found this environment, but `remove_env_from` can still return `None` — e.g. a
    // hand-edited `environments` written as an inline table rather than a bracketed section
    // parses as present to `config.envs.get` but isn't a shape the removal mutator rewrites.
    // Surface that loudly instead of resealing the unchanged config and reporting a removal
    // that did not happen.
    let written = config::remove_env_from(&config_path, checked, environment)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?
        .ok_or_else(|| {
            internal(format!(
                "environment '{environment}' could not be removed from the checked config"
            ))
        })?;
    let config = DaemonConfig::from_text(&written).map_err(|e| {
        RpcError::domain(
            DomainCode::Internal,
            format!(
                "config.toml parse error at {}",
                credsd_core::config::located(e.span(), &written)
            ),
        )
    })?;
    let rel = std::path::Path::new("callers")
        .join(uid.to_string())
        .join("config.toml");
    let canonical = credsd_core::config::snapshot::canonical_config(uid, &rel, &config)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    verified
        .seal_snapshot(&daemon.encryption, CONFIG, &canonical)
        .map_err(|e| RpcError::domain(DomainCode::Internal, e.to_string()))?;
    verified.pin_sealed(CONFIG, &canonical);
    daemon.integrity.write(verified)?;
    daemon.evict_caller(uid);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::routes::DenyReason;
    use credsd_core::config::credentials::CredentialSource;
    use credsd_core::config::{EnvConfig, SsoConfig};
    use credsd_core::credentials::{CredentialType as DataKind, Credentials};
    use credsd_core::rpc::{Id, Outcome, Version};

    const TEST_UID: u32 = 501;

    /// Caller root for cases that inject a store directly. Deliberately a path that does not
    /// exist: no tree backs these stores, and sampling an absent directory is stable, so the
    /// injected state cannot be invalidated by another case writing somewhere real.
    fn unbacked_root() -> std::path::PathBuf {
        std::path::PathBuf::from("/nonexistent/credsd-unit-test-callers")
    }

    fn authorized() -> CallerAuth {
        CallerAuth::Authorized {
            uid: TEST_UID,
            root: std::path::PathBuf::from("/authorized/caller/root"),
        }
    }

    fn peer(auth: CallerAuth) -> PeerInfo {
        PeerInfo {
            uid: Some(TEST_UID),
            pid: Some(std::process::id() as i32),
            auth,
            executable: None,
            login_uid: None,
        }
    }

    fn session_creds() -> Credentials {
        Credentials::session(
            "AKIAIOSFODNN7EXAMPLE".into(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            "FwoGZXIvYXdzEBY...".into(),
            credsd_core::credentials::expires_in_seconds(3600),
        )
    }

    /// A daemon seeded with `dev` and `default` as session credentials, `token-only` as an
    /// access token (wrong-type branch), and `needs-reauth` backed by a real SSO source with
    /// no token on disk (so its renewer returns `ReauthRequired`).
    fn test_daemon() -> Daemon {
        let key = credsd_core::encryption::generate_key().unwrap();
        let encryption = Arc::new(credsd_core::encryption::EncryptionService::new(key).unwrap());

        let mut config = DaemonConfig::default();
        for name in ["dev", "default", "token-only", "needs-reauth"] {
            config.envs.insert(
                name.to_string(),
                EnvConfig {
                    credentials: vec![name.to_string()],
                    ..EnvConfig::default()
                },
            );
        }

        let mut sources = CredentialSources::default();
        for name in ["dev", "default", "needs-reauth"] {
            sources.insert(
                name.to_string(),
                CredentialSource::AwsIdcSso(SsoConfig {
                    start_url: "https://example.awsapps.com/start".into(),
                    sso_region: "us-east-1".into(),
                    account_id: "111111111111".into(),
                    role_name: "Developer".into(),
                    identity_type: Default::default(),
                    allowed_roles: Vec::new(),
                }),
            );
        }
        sources.insert(
            "token-only".to_owned(),
            CredentialSource::Jwt(credsd_core::config::JwtConfig {
                env_var: None,
                identity_type: Default::default(),
            }),
        );

        let store = Arc::new(CredentialStore::new(
            TEST_UID,
            &sources,
            encryption.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            crate::credential_store::records_verified(),
        ));
        store.inject_for_test(TEST_UID, "dev", session_creds());
        store.inject_for_test(TEST_UID, "default", session_creds());
        store.inject_for_test(
            TEST_UID,
            "token-only",
            Credentials {
                credential_type: DataKind::AccessToken,
                data: CredentialData::AccessToken {
                    token: "aoeu-not-a-real-token".into(),
                },
                expires_at: Some(credsd_core::credentials::expires_in_seconds(3600)),
            },
        );

        Daemon::with_caller(
            TEST_UID,
            config,
            sources,
            store,
            encryption,
            unbacked_root(),
        )
    }

    fn get_request(profile: &str, credential: Option<&str>) -> Request {
        Request::with_params(
            Id::from(1),
            METHOD_CREDENTIAL_GET,
            &GetParams {
                environment: None,
                credential: Some(credential.unwrap_or(profile).to_owned()),
                account_id: None,
                role_name: None,
                scope: None,
                claim: None,
                request_id: None,
            },
        )
        .expect("object params")
    }

    async fn dispatch_uds(request: &Request, peer: &PeerInfo) -> Response<Value> {
        dispatch(request, Carrier::Uds, peer, &test_daemon()).await
    }

    fn domain_code(response: &Response<Value>) -> Option<DomainCode> {
        match &response.outcome {
            Outcome::Error(e) => e.domain_code(),
            Outcome::Result(_) => None,
        }
    }

    #[tokio::test]
    async fn get_ready_returns_material_with_ecs_field_names() {
        let response = dispatch_uds(&get_request("dev", None), &peer(authorized())).await;
        let Outcome::Result(value) = response.outcome else {
            panic!("expected a result");
        };
        assert_eq!(value["credential"], "dev");
        assert_eq!(value["material"]["type"], "session_credentials");
        assert_eq!(value["material"]["access_key_id"], "AKIAIOSFODNN7EXAMPLE");
        assert!(value["material"]["secret_access_key"].is_string());
        assert!(value["material"]["session_token"].is_string());
        assert_eq!(value["provenance"], "cached_shared");
        assert!(value["expires_at"].is_string());
    }

    #[tokio::test]
    async fn get_unknown_profile_is_profile_not_found() {
        let response = dispatch_uds(&get_request("nonexistent", None), &peer(authorized())).await;
        assert_eq!(domain_code(&response), Some(DomainCode::CredentialNotFound));
    }

    /// A bearer-token credential is material this method serves, tagged with its own kind — the
    /// answer a non-AWS consumer asked for. `WrongCredentialType` now belongs only to the
    /// projections that hold exactly one AWS identity (the ephemeral proxy, `credential_process`),
    /// so it must NOT appear here.
    #[tokio::test]
    async fn get_serves_an_access_token_tagged_as_one() {
        let response = dispatch_uds(&get_request("token-only", None), &peer(authorized())).await;
        assert_ne!(
            domain_code(&response),
            Some(DomainCode::WrongCredentialType)
        );
        let Outcome::Result(value) = response.outcome else {
            panic!("expected a result");
        };
        assert_eq!(value["credential"], "token-only");
        assert_eq!(value["material"]["type"], "access_token");
        assert_eq!(value["material"]["token"], "aoeu-not-a-real-token");
        assert_eq!(value["material"]["token_type"], "Bearer");
        assert!(value["expires_at"].is_string());
    }

    #[tokio::test]
    async fn get_reauth_required_env_is_reauth_required() {
        let response = dispatch_uds(&get_request("needs-reauth", None), &peer(authorized())).await;
        assert_eq!(domain_code(&response), Some(DomainCode::ReauthRequired));
        // The remediation context Requirement 8 requires.
        let Outcome::Error(e) = response.outcome else {
            panic!("expected an error");
        };
        let data = e.data.expect("reauth data");
        assert_eq!(data["credential"], "needs-reauth");
        // Login is credential-addressed, so the remediation names the credential the
        // environment served, with the client command that exists.
        assert_eq!(data["remediation"], "creds login --credential needs-reauth");
    }

    #[tokio::test]
    async fn a_credential_the_profile_does_not_reach_is_indistinguishable_from_absent() {
        // Open Decision 1 guard: naming a credential the profile does not reach fails exactly
        // as an unknown one does, so it cannot be an existence oracle.
        let response = dispatch_uds(
            &get_request("dev", Some("some-other-cred")),
            &peer(authorized()),
        )
        .await;
        assert_eq!(domain_code(&response), Some(DomainCode::CredentialNotFound));
    }

    #[tokio::test]
    async fn every_non_authorized_decision_is_profile_not_found_before_any_lookup() {
        for auth in [
            CallerAuth::Denied(DenyReason::NoRoot),
            CallerAuth::Denied(DenyReason::NoPeerCred),
            CallerAuth::Denied(DenyReason::OwnerMismatch),
            CallerAuth::Denied(DenyReason::UnknownUid),
            CallerAuth::Unresolved,
        ] {
            let response = dispatch_uds(&get_request("dev", None), &peer(auth)).await;
            assert_eq!(
                domain_code(&response),
                Some(DomainCode::CredentialNotFound),
                "an unauthorized caller must not distinguish a real env from an absent one"
            );
        }
    }

    /// `credential/remove` is credential-addressed: an unauthorized caller is refused as
    /// `CREDENTIAL_NOT_FOUND` before any file is read (`credential-only-addressing` Req 4.5).
    #[tokio::test]
    async fn credential_remove_denies_by_absence_as_credential_not_found() {
        let request = Request::with_params(
            Id::from(1),
            METHOD_CREDENTIAL_REMOVE,
            &serde_json::json!({ "credential": "dev" }),
        )
        .unwrap();
        for auth in [
            CallerAuth::Denied(DenyReason::NoRoot),
            CallerAuth::Denied(DenyReason::NoPeerCred),
            CallerAuth::Denied(DenyReason::OwnerMismatch),
            CallerAuth::Denied(DenyReason::UnknownUid),
            CallerAuth::Unresolved,
        ] {
            let response = dispatch_uds(&request, &peer(auth)).await;
            assert_eq!(domain_code(&response), Some(DomainCode::CredentialNotFound));
        }
    }

    fn name_only_request(credential: &str) -> Request {
        Request::with_params(
            Id::from(1),
            METHOD_CREDENTIAL_GET,
            &serde_json::json!({ "credential": credential }),
        )
        .expect("object params")
    }

    /// A daemon holding `credentials` as SSO sources, composed by `envs`. Those in `ready` have
    /// session material cached; the rest need re-authentication.
    fn daemon_with_credentials(
        envs: &[(&str, &[&str])],
        credentials: &[&str],
        ready: &[&str],
    ) -> Daemon {
        let key = credsd_core::encryption::generate_key().unwrap();
        let encryption = Arc::new(credsd_core::encryption::EncryptionService::new(key).unwrap());
        let mut config = DaemonConfig::default();
        for (env, members) in envs {
            config.envs.insert(
                env.to_string(),
                EnvConfig {
                    credentials: members.iter().map(|c| c.to_string()).collect(),
                    ..EnvConfig::default()
                },
            );
        }
        let mut sources = CredentialSources::default();
        for credential in credentials {
            sources.insert(
                credential.to_string(),
                CredentialSource::AwsIdcSso(SsoConfig {
                    start_url: "https://example.awsapps.com/start".into(),
                    sso_region: "us-east-1".into(),
                    account_id: "111111111111".into(),
                    role_name: "Developer".into(),
                    identity_type: Default::default(),
                    allowed_roles: Vec::new(),
                }),
            );
        }
        let store = Arc::new(CredentialStore::new(
            TEST_UID,
            &sources,
            encryption.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            crate::credential_store::records_verified(),
        ));
        for credential in ready {
            store.inject_for_test(TEST_UID, credential, session_creds());
        }
        Daemon::with_caller(
            TEST_UID,
            config,
            sources,
            store,
            encryption,
            unbacked_root(),
        )
    }

    /// Swap the caller's state for one whose `credentials.toml` has drifted from its snapshot.
    fn drift_credentials(daemon: &Daemon) {
        drift(daemon, CREDENTIALS);
    }

    /// Mark `file` (`CONFIG` or `CREDENTIALS`) drifted in the cached caller state.
    fn drift(daemon: &Daemon, file: &str) {
        let mut registry = crate::server::lock(&daemon.registry);
        let state = registry.get(&TEST_UID).expect("caller state").clone();
        let status = |name: &str, current: &DriftStatus| {
            if name == file {
                DriftStatus::Drifted
            } else {
                current.clone()
            }
        };
        let drifted = CallerState {
            config: state.config.clone(),
            store: state.store.clone(),
            credentials: state.credentials.clone(),
            tags: state.tags.clone(),
            sources: SourceStamps::sample(&daemon.caller_root(TEST_UID)),
            refresh: None,
            config_drift: status(CONFIG, &state.config_drift),
            credentials_drift: status(CREDENTIALS, &state.credentials_drift),
            config_invalid: None,
        };
        registry.insert(TEST_UID, Arc::new(drifted));
    }

    fn credential_addressed(response: &Response<Value>) -> Value {
        serde_json::to_value(&response.outcome).unwrap()
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

        /// A config that fails validation reaches the client as the Internal error it shows
        /// as is, so the relayed message must carry exactly one category, however many
        /// problems the config has and whatever its environment names are.
        #[test]
        fn a_relayed_config_validation_error_names_one_category(
            envs in proptest::collection::btree_map(
                "[a-zA-Z0-9 ._-]{0,12}",
                proptest::collection::vec("[a-z][a-z0-9-]{0,8}", 1..3),
                1..4,
            ),
        ) {
            let text: String = envs
                .iter()
                .map(|(name, credentials)| {
                    format!("[environments.\"{name}\"]\ncredentials = {credentials:?}\n")
                })
                .collect();
            let Err(e) = validated_config(&text, &TomlFiles::default()) else {
                panic!("an env composing an undefined credential must not validate: {text}");
            };
            proptest::prop_assert_eq!(
                credsd_core::error::prefixes(&e.message), 1, "{}", e.message
            );
        }

        /// A credential is reachable by name however many environments compose it, none
        /// included, and every environment that composes it serves exactly what the
        /// credential-addressed request serves (Requirement 10 AC 6-8).
        #[test]
        fn a_credential_is_served_by_name_however_many_environments_compose_it(
            credential in "[a-z][a-z0-9._-]{0,15}",
            composing in 0usize..4,
            ready in proptest::bool::ANY,
        ) {
            let envs: Vec<String> = (0..composing).map(|i| format!("env-{i}")).collect();
            let member = [credential.as_str()];
            let members: Vec<(&str, &[&str])> =
                envs.iter().map(|e| (e.as_str(), &member[..])).collect();
            let ready_list: &[&str] = if ready { &[credential.as_str()] } else { &[] };
            let daemon = daemon_with_credentials(&members, &[credential.as_str()], ready_list);
            let rt = tokio::runtime::Runtime::new().unwrap();
            let by_name = rt.block_on(dispatch(
                &name_only_request(&credential),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            ));
            match &by_name.outcome {
                Outcome::Result(value) => proptest::prop_assert_eq!(&value["credential"], &credential),
                Outcome::Error(e) => {
                    proptest::prop_assert!(!ready, "a ready credential must be served by name: {e:?}");
                    proptest::prop_assert_eq!(e.domain_code(), Some(DomainCode::ReauthRequired));
                }
            }
            for env in &envs {
                let by_env = rt.block_on(dispatch(
                    &get_request(env, Some(&credential)),
                    Carrier::Uds,
                    &peer(authorized()),
                    &daemon,
                ));
                if ready {
                    proptest::prop_assert_eq!(
                        credential_addressed(&by_env),
                        credential_addressed(&by_name)
                    );
                } else {
                    proptest::prop_assert_eq!(domain_code(&by_env), Some(DomainCode::ReauthRequired));
                }
            }
        }

        /// An environment parameter is refused, while the same named credential is served.
        #[test]
        fn an_environment_never_serves_more_than_the_credential_addressed_request(
            credential in "[a-z][a-z0-9._-]{0,15}",
            other in "[a-z][a-z0-9._-]{0,15}",
        ) {
            proptest::prop_assume!(credential != other);
            let daemon = daemon_with_credentials(
                &[("narrow", &[other.as_str()])],
                &[credential.as_str(), other.as_str()],
                &[credential.as_str(), other.as_str()],
            );
            let rt = tokio::runtime::Runtime::new().unwrap();
            let by_env = rt.block_on(dispatch(
                &Request::with_params(
                    Id::from(1),
                    METHOD_CREDENTIAL_GET,
                    &serde_json::json!({"environment": "narrow", "credential": credential}),
                ).expect("object params"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            ));
            let Outcome::Error(error) = by_env.outcome else {
                return Err(proptest::test_runner::TestCaseError::fail("environment was served"));
            };
            proptest::prop_assert_eq!(error.code, credsd_core::rpc::CODE_INVALID_PARAMS);
            let by_name = rt.block_on(dispatch(
                &name_only_request(&credential),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            ));
            proptest::prop_assert!(matches!(by_name.outcome, Outcome::Result(_)));
        }

        /// Every credential-addressed miss is one code and one message, whatever the cause:
        /// an unknown name and an unauthorized caller are indistinguishable (Requirement 8 AC 7).
        #[test]
        fn every_credential_addressed_miss_is_one_code_and_one_message(
            missing in "[a-z][a-z0-9._-]{0,15}",
        ) {
            proptest::prop_assume!(missing != "held");
            let daemon = daemon_with_credentials(&[], &["held"], &["held"]);
            let rt = tokio::runtime::Runtime::new().unwrap();
            let unknown = rt.block_on(dispatch(
                &name_only_request(&missing),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            ));
            let unauthorized = rt.block_on(dispatch(
                &name_only_request("held"),
                Carrier::Uds,
                &peer(CallerAuth::Unresolved),
                &daemon,
            ));
            proptest::prop_assert_eq!(domain_code(&unknown), Some(DomainCode::CredentialNotFound));
            proptest::prop_assert_eq!(credential_addressed(&unknown), credential_addressed(&unauthorized));
        }
    }

    fn role_request(
        addressing: (&str, &str),
        account_id: Option<&str>,
        role_name: Option<&str>,
    ) -> Request {
        let mut params = serde_json::json!({ addressing.0: addressing.1 });
        if let Some(account_id) = account_id {
            params["account_id"] = account_id.into();
        }
        if let Some(role_name) = role_name {
            params["role_name"] = role_name.into();
        }
        Request::with_params(Id::from(1), METHOD_CREDENTIAL_GET, &params).expect("object params")
    }

    /// The `sso.acme` daemon of the role tests, its credential allowing `allowed` besides its
    /// stored pair `111111111111`/`Developer`.
    fn sso_daemon_allowing(allowed: &[credsd_core::config::RolePair]) -> Daemon {
        let daemon =
            daemon_with_credentials(&[("sso", &["sso.acme"])], &["sso.acme"], &["sso.acme"]);
        let state = daemon.caller_state(TEST_UID);
        let mut sources = state.credentials.as_ref().clone();
        let Some(CredentialSource::AwsIdcSso(sso)) = sources.get_mut("sso.acme") else {
            panic!("daemon_with_credentials holds SSO sources")
        };
        sso.allowed_roles = allowed.to_vec();
        Daemon::with_caller(
            TEST_UID,
            state.config.as_ref().clone(),
            sources,
            state.store.clone(),
            daemon.encryption.clone(),
            unbacked_root(),
        )
    }

    fn role_pair(account_id: &str, role_name: &str) -> credsd_core::config::RolePair {
        credsd_core::config::RolePair {
            account_id: account_id.into(),
            role_name: role_name.into(),
        }
    }

    /// Records each event as one `field=value` line, so a test reads what an operator's log would
    /// carry. Spans are ignored.
    #[derive(Clone, Default)]
    struct EventCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl tracing::Subscriber for EventCapture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut line = String::new();
            event.record(
                &mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
                    line.push_str(&format!("{field}={value:?} "));
                },
            );
            self.0.lock().expect("capture lock").push(line);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

        /// One half of a pair is malformed whoever asks and however the request is addressed,
        /// since that is decidable from the request alone (Requirement 17 AC 1).
        #[test]
        fn half_a_role_pair_is_invalid_params_before_anything_is_read(
            account_half in proptest::bool::ANY,
            by_environment in proptest::bool::ANY,
            authorized_caller in proptest::bool::ANY,
            name in "[a-z][a-z0-9._-]{0,15}",
        ) {
            let daemon = daemon_with_credentials(&[("sso", &["sso.acme"])], &["sso.acme"], &["sso.acme"]);
            drift_credentials(&daemon);
            let addressing = if by_environment { ("environment", name.as_str()) } else { ("credential", name.as_str()) };
            let request = if account_half {
                role_request(addressing, Some("222222222222"), None)
            } else {
                role_request(addressing, None, Some("ReadOnly"))
            };
            let auth = if authorized_caller { authorized() } else { CallerAuth::Unresolved };
            let rt = tokio::runtime::Runtime::new().unwrap();
            let response = rt.block_on(dispatch(&request, Carrier::Uds, &peer(auth), &daemon));
            let Outcome::Error(e) = response.outcome else {
                return Err(proptest::test_runner::TestCaseError::fail("half a pair was served"));
            };
            proptest::prop_assert_eq!(e.code, credsd_core::rpc::CODE_INVALID_PARAMS);
        }

        /// A pair selects that account and role of the sign-in, never the stored pair's cached
        /// material; the stored pair is the same request as none; and a selected pair with no
        /// sign-in asks for the credential's own login (Requirement 17 AC 4-6).
        #[test]
        fn a_selected_role_is_served_from_the_sign_in_not_the_stored_role(
            account_id in proptest::prop_oneof!["111111111111", "[0-9]{12}"],
            role_name in proptest::prop_oneof!["Developer", "[A-Za-z0-9+=,.@_-]{1,64}"],
        ) {
            let daemon = sso_daemon_allowing(&[role_pair(&account_id, &role_name)]);
            let addressing = ("credential", "sso.acme");
            let request = role_request(addressing, Some(&account_id), Some(&role_name));
            let rt = tokio::runtime::Runtime::new().unwrap();
            let response = rt.block_on(dispatch(&request, Carrier::Uds, &peer(authorized()), &daemon));
            if account_id == "111111111111" && role_name == "Developer" {
                let Outcome::Result(value) = response.outcome else {
                    return Err(proptest::test_runner::TestCaseError::fail("the stored pair was not served"));
                };
                proptest::prop_assert_eq!(&value["material"]["access_key_id"], "AKIAIOSFODNN7EXAMPLE");
            } else {
                let Outcome::Error(e) = response.outcome else {
                    return Err(proptest::test_runner::TestCaseError::fail("a selected pair was served the stored pair's material"));
                };
                proptest::prop_assert_eq!(e.domain_code(), Some(DomainCode::ReauthRequired));
                let data = e.data.expect("reauth data");
                proptest::prop_assert_eq!(&data["remediation"], "creds login --credential sso.acme");
                proptest::prop_assert_eq!(&data["credential"], "sso.acme");
            }
        }

        /// A pair is served only when it is the stored pair or one the credential allows; any
        /// other is a domain refusal naming the credential, never a sign-in, and an empty list
        /// allows only the stored pair (Requirement 17 AC 8; `presence-gated-operations` Req 1.7).
        #[test]
        fn only_the_stored_pair_or_an_allowed_one_is_served(
            allowed in proptest::collection::vec(("[0-9]{12}", "[A-Za-z0-9+=,.@_-]{1,64}"), 0..6),
            pick in 0usize..5,
            index in proptest::prelude::any::<proptest::sample::Index>(),
            other in ("[0-9]{12}", "[A-Za-z0-9+=,.@_-]{1,64}"),
        ) {
            let allowed: Vec<_> = allowed.iter().map(|(a, r)| role_pair(a, r)).collect();
            let stored = role_pair("111111111111", "Developer");
            let asked = match pick {
                0 => stored.clone(),
                1 if !allowed.is_empty() => allowed[index.index(allowed.len())].clone(),
                // Half of an allowed pair is not an allowed pair.
                2 if !allowed.is_empty() => role_pair(&allowed[index.index(allowed.len())].account_id, &other.1),
                3 if !allowed.is_empty() => role_pair(&other.0, &allowed[index.index(allowed.len())].role_name),
                _ => role_pair(&other.0, &other.1),
            };
            let permitted = asked == stored || allowed.contains(&asked);
            let daemon = sso_daemon_allowing(&allowed);
            let addressing = ("credential", "sso.acme");
            let request = role_request(addressing, Some(&asked.account_id), Some(&asked.role_name));
            let rt = tokio::runtime::Runtime::new().unwrap();
            let capture = EventCapture::default();
            let response = rt.block_on(tracing::instrument::WithSubscriber::with_subscriber(
                dispatch(&request, Carrier::Uds, &peer(authorized()), &daemon),
                capture.clone(),
            ));
            // The allowed list is a boundary a caller can probe, so every pair but the stored one
            // leaves one audit line naming it and its outcome, refused or not (AC 8).
            let audited: Vec<String> = capture.0.lock().expect("capture lock").iter()
                .filter(|line| line.contains("\"credential.role_selected\"")).cloned().collect();
            if asked == stored {
                proptest::prop_assert!(audited.is_empty(), "{audited:?}");
            } else {
                proptest::prop_assert_eq!(audited.len(), 1, "{:?}", audited);
                let outcome = if permitted { "\"allowed\"" } else { "\"refused\"" };
                for wanted in [
                    format!("account_id={:?}", asked.account_id),
                    format!("role_name={:?}", asked.role_name),
                    format!("outcome={outcome}"),
                ] {
                    proptest::prop_assert!(audited[0].contains(&wanted), "{wanted} in {}", audited[0]);
                }
            }
            match (&response.outcome, permitted) {
                (Outcome::Result(_), true) => proptest::prop_assert_eq!(&asked, &stored),
                // An allowed pair with no cached material goes to the sign-in, not a refusal.
                (Outcome::Error(e), true) => proptest::prop_assert_eq!(e.domain_code(), Some(DomainCode::ReauthRequired)),
                (Outcome::Error(e), false) => {
                    proptest::prop_assert_eq!(e.domain_code(), Some(DomainCode::RoleNotAllowed));
                    proptest::prop_assert!(e.message.contains("'sso.acme'"), "names the credential: {}", e.message);
                }
                (Outcome::Result(_), false) => {
                    return Err(proptest::test_runner::TestCaseError::fail("a pair outside the list was served"));
                }
            }
        }
    }

    /// A pair is accepted only for `aws-idc-sso`, and only once the credential resolves, so a
    /// miss, an unauthorized caller, and a drifted caller answer exactly as they do without one
    /// (Requirement 17 AC 3, 7).
    #[tokio::test]
    async fn a_role_pair_is_refused_for_any_other_source_and_never_changes_a_miss() {
        let mut daemon = daemon_with_credentials(&[], &["sso.acme"], &["sso.acme"]);
        let mut sources = daemon.caller_state(TEST_UID).credentials.as_ref().clone();
        sources.insert(
            "keys".into(),
            CredentialSource::AwsIamUser(credsd_core::config::IamUserConfig {
                region: "us-east-1".into(),
                duration_seconds: None,
                mfa_serial: None,
                identity_type: Default::default(),
            }),
        );
        let store = daemon.caller_state(TEST_UID).store.clone();
        daemon = Daemon::with_caller(
            TEST_UID,
            daemon.caller_state(TEST_UID).config.as_ref().clone(),
            sources,
            store,
            daemon.encryption.clone(),
            unbacked_root(),
        );
        let pair = |credential| {
            role_request(
                ("credential", credential),
                Some("222222222222"),
                Some("ReadOnly"),
            )
        };

        let other = dispatch(&pair("keys"), Carrier::Uds, &peer(authorized()), &daemon).await;
        let Outcome::Error(e) = other.outcome else {
            panic!("a pair on a non-SSO source was served");
        };
        // Decided from resolved config, so a domain refusal, never an envelope code (Req 8 AC 1),
        // and its own code: `WRONG_CREDENTIAL_TYPE` already means unusable material (AC 5).
        assert_eq!(e.domain_code(), Some(DomainCode::RoleSelectionUnsupported));

        for (credential, auth) in [
            ("missing", authorized()),
            ("keys", CallerAuth::Unresolved),
            ("sso.acme", CallerAuth::Unresolved),
        ] {
            let with = dispatch(
                &pair(credential),
                Carrier::Uds,
                &peer(auth.clone()),
                &daemon,
            )
            .await;
            let without = dispatch(
                &name_only_request(credential),
                Carrier::Uds,
                &peer(auth),
                &daemon,
            )
            .await;
            assert_eq!(
                domain_code(&with),
                Some(DomainCode::CredentialNotFound),
                "{credential}"
            );
            assert_eq!(
                credential_addressed(&with),
                credential_addressed(&without),
                "{credential}"
            );
        }

        drift_credentials(&daemon);
        let drifted = dispatch(
            &pair("sso.acme"),
            Carrier::Uds,
            &peer(authorized()),
            &daemon,
        )
        .await;
        assert_eq!(domain_code(&drifted), Some(DomainCode::ConfigDrifted));
    }

    /// A drifted caller gets the drift refusal, never a miss, on the credential-addressed path:
    /// a miss reported over drifted records would be an existence oracle (Requirement 10 AC 10).
    #[tokio::test]
    async fn a_drifted_caller_is_refused_before_a_credential_addressed_miss() {
        let daemon = daemon_with_credentials(&[], &["held"], &["held"]);
        drift_credentials(&daemon);
        for credential in ["held", "missing"] {
            let response = dispatch(
                &name_only_request(credential),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            assert_eq!(
                domain_code(&response),
                Some(DomainCode::ConfigDrifted),
                "{credential}"
            );
        }
    }

    /// A credential-addressed re-authentication names the credential, not an environment, and
    /// remediates with the real client command (Requirement 10 AC 12).
    #[tokio::test]
    async fn a_credential_addressed_reauth_names_the_credential_and_the_login_command() {
        let daemon = daemon_with_credentials(&[], &["solo"], &[]);
        let response = dispatch(
            &name_only_request("solo"),
            Carrier::Uds,
            &peer(authorized()),
            &daemon,
        )
        .await;
        let Outcome::Error(e) = response.outcome else {
            panic!("expected re-authentication");
        };
        let data = e.data.expect("reauth data");
        assert_eq!(data["credential"], "solo");
        assert!(data.get("environment").is_none(), "{data:?}");
        assert_eq!(data["remediation"], "creds login --credential solo");
    }

    #[tokio::test]
    async fn get_with_neither_environment_nor_credential_is_invalid_params() {
        for params in [
            serde_json::json!({}),
            serde_json::json!({ "credential": "" }),
        ] {
            let request = Request::with_params(Id::from(1), METHOD_CREDENTIAL_GET, &params)
                .expect("object params");
            let response = dispatch_uds(&request, &peer(authorized())).await;
            let Outcome::Error(e) = response.outcome else {
                panic!("{params}: expected an error");
            };
            assert_eq!(e.code, credsd_core::rpc::CODE_INVALID_PARAMS, "{params}");
        }
    }

    #[tokio::test]
    async fn get_batch_is_unavailable() {
        let request = Request::with_params(
            Id::from(1),
            METHOD_ENVIRONMENT_CREDENTIALS,
            &GetBatchParams {
                environment: "dev".into(),
                scope: None,
                claim: None,
                request_id: None,
            },
        )
        .expect("object params");
        let response = dispatch_uds(&request, &peer(authorized())).await;
        let Outcome::Error(error) = response.outcome else {
            panic!("expected method-not-found");
        };
        assert_eq!(error.code, credsd_core::rpc::CODE_METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn list_enumerates_credentials_without_material() {
        let request = Request::new(Id::from(1), METHOD_CREDENTIAL_LIST);
        let response = dispatch_uds(&request, &peer(authorized())).await;
        let Outcome::Result(value) = response.outcome else {
            panic!("expected a result");
        };
        let names: Vec<&str> = value["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["credential"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"dev"));
        // No entry carries material, and an unfiltered list names no environment.
        for entry in value["credentials"].as_array().unwrap() {
            assert!(entry.get("material").is_none());
            assert!(entry.get("environment").is_none(), "{entry}");
            assert!(
                entry.get("default").is_none(),
                "list is capped at name/kind/status"
            );
        }
    }

    /// Requirement 13 AC 4 caps an enumeration row at name, kind, source type, status, and tags,
    /// because agent tools may show the list to a model. Any other key on an unfiltered row
    /// breaks the cap.
    #[tokio::test]
    async fn list_rows_carry_only_name_kind_source_status_and_tags() {
        let request = Request::new(Id::from(1), METHOD_CREDENTIAL_LIST);
        let response = dispatch_uds(&request, &peer(authorized())).await;
        let Outcome::Result(value) = response.outcome else {
            panic!("expected a result");
        };
        let rows = value["credentials"].as_array().unwrap();
        assert!(!rows.is_empty());
        for row in rows {
            let mut keys: Vec<&str> = row
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                ["credential", "kind", "source", "status", "tags"],
                "{row}"
            );
            assert_eq!(row["tags"], serde_json::json!({}), "{row}");
        }
    }

    /// A tag filter value that breaks the tag grammar is a bad request, and the refusal does not
    /// echo the value back.
    #[tokio::test]
    async fn a_bad_list_tag_filter_is_invalid_params_without_its_value() {
        let request = Request::with_params(
            Id::from(1),
            METHOD_CREDENTIAL_LIST,
            &serde_json::json!({ "tags": { "team": "sk-planted\u{7}" } }),
        )
        .expect("object params");
        let response = dispatch_uds(&request, &peer(authorized())).await;
        let Outcome::Error(e) = response.outcome else {
            panic!("a bad filter value was accepted");
        };
        assert_eq!(e.code, credsd_core::rpc::CODE_INVALID_PARAMS);
        assert!(
            !e.message.contains("unknown field"),
            "refused as an unknown field, not a bad tag: {}",
            e.message
        );
        assert!(!e.message.contains("sk-planted"), "{}", e.message);
    }

    fn tag_request(params: Value) -> Request {
        Request::with_params(Id::from(1), "credential/tag", &params).expect("object params")
    }

    /// Requirement 15 AC 2 for `credential/tag`: served on the local socket, method-not-found on
    /// stdio, like every other mutation method.
    #[tokio::test]
    async fn credential_tag_is_local_socket_only() {
        let request = tag_request(serde_json::json!({ "credential": "dev", "unset": ["team"] }));
        let uds = dispatch_uds(&request, &peer(authorized())).await;
        if let Outcome::Error(e) = &uds.outcome {
            assert_ne!(
                e.code,
                credsd_core::rpc::CODE_METHOD_NOT_FOUND,
                "credential/tag is not served on the socket"
            );
        }
        let stdio = dispatch(
            &request,
            Carrier::Stdio,
            &peer(authorized()),
            &test_daemon(),
        )
        .await;
        let Outcome::Error(e) = stdio.outcome else {
            panic!("credential/tag must not be exposed over stdio");
        };
        assert_eq!(e.code, credsd_core::rpc::CODE_METHOD_NOT_FOUND);
        assert_eq!(e.domain_code(), None);
    }

    /// A key in both `set` and `unset` is a bad request, refused before anything is read.
    #[tokio::test]
    async fn a_tag_edit_naming_a_key_twice_is_invalid_params() {
        let request = tag_request(serde_json::json!({
            "credential": "dev",
            "set": { "team": "payments" },
            "unset": ["team"],
        }));
        let response = dispatch_uds(&request, &peer(authorized())).await;
        let Outcome::Error(e) = response.outcome else {
            panic!("an overlapping edit was accepted");
        };
        assert_eq!(
            e.code,
            credsd_core::rpc::CODE_INVALID_PARAMS,
            "{}",
            e.message
        );
        assert!(e.message.contains("\"team\""), "{}", e.message);
    }

    /// Item: `config.toml` stays load-bearing for a credential-addressed get. It decides whether
    /// `credentials.toml` validates at all, and it supplies the audit's agent allowlist, so its
    /// drift refuses the credential path exactly as `credentials.toml` drift does.
    #[tokio::test]
    async fn a_credential_addressed_get_is_refused_over_drift_in_either_file() {
        for file in [CONFIG, CREDENTIALS] {
            let daemon = daemon_with_credentials(&[], &["held"], &["held"]);
            drift(&daemon, file);
            let response = dispatch(
                &name_only_request("held"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            assert_eq!(
                domain_code(&response),
                Some(DomainCode::ConfigDrifted),
                "{file}"
            );
            let Outcome::Error(e) = response.outcome else {
                panic!("expected a drift refusal");
            };
            assert!(
                e.message.contains("credential 'held'") && !e.message.contains("environment"),
                "a credential-addressed refusal names the credential: {}",
                e.message
            );
        }
    }

    fn list_request(environment: &str) -> Request {
        Request::with_params(
            Id::from(1),
            METHOD_CREDENTIAL_LIST,
            &serde_json::json!({ "environment": environment }),
        )
        .expect("object params")
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

        /// A filter naming no environment is ENVIRONMENT_NOT_FOUND, the code credential/get
        /// returns for the same miss; a filter naming an environment that composes nothing is
        /// an empty list.
        #[test]
        #[ignore = "environment API is unavailable"]
        fn list_filtered_to_an_unknown_environment_is_environment_not_found(
            name in "[a-z][a-z0-9-]{0,15}",
        ) {
            proptest::prop_assume!(name != "dev" && name != "empty");
            let daemon = daemon_with_credentials(
                &[("dev", &["held"]), ("empty", &[])],
                &["held"],
                &["held"],
            );
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let call = |env: &str| rt.block_on(dispatch(&list_request(env), Carrier::Uds, &peer(authorized()), &daemon));

            let unknown = call(&name);
            proptest::prop_assert_eq!(domain_code(&unknown), Some(DomainCode::EnvironmentNotFound));
            let get = rt.block_on(dispatch(
                &Request::with_params(
                    Id::from(1),
                    METHOD_CREDENTIAL_GET,
                    &serde_json::json!({ "environment": name }),
                ).unwrap(),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            ));
            proptest::prop_assert_eq!(domain_code(&unknown), domain_code(&get));
            // A caller with nothing provisioned has no environments, so the same filter is the
            // same miss for it, not the empty list an unfiltered call returns.
            let unprovisioned = rt.block_on(dispatch(
                &list_request(&name),
                Carrier::Uds,
                &peer(CallerAuth::Denied(DenyReason::NoRoot)),
                &daemon,
            ));
            proptest::prop_assert_eq!(domain_code(&unprovisioned), domain_code(&unknown));

            let Outcome::Result(empty) = call("empty").outcome else {
                return Err(proptest::test_runner::TestCaseError::fail("an empty environment lists"));
            };
            proptest::prop_assert_eq!(&empty["credentials"], &serde_json::json!([]));
            let Outcome::Result(dev) = call("dev").outcome else {
                return Err(proptest::test_runner::TestCaseError::fail("a known environment lists"));
            };
            proptest::prop_assert_eq!(dev["credentials"].as_array().map(Vec::len), Some(1));
        }
    }

    /// The `caller assessment` audit lines `f` emits, as JSON field maps.
    async fn audit_lines<F: std::future::Future>(f: F) -> Vec<serde_json::Map<String, Value>> {
        #[derive(Clone, Default)]
        struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);
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
        f.await;
        drop(guard);
        let bytes = buf.0.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| v["fields"].as_object().cloned())
            .filter(|f| {
                f.get("message")
                    .and_then(Value::as_str)
                    .is_some_and(|m| m.starts_with("caller assessment"))
            })
            .collect()
    }

    /// The audit names a credential-addressed request's credential in its own field and leaves
    /// `env` absent (`credential-only-addressing` Requirement 4.4).
    ///
    /// Runs in a child process holding only this test. tracing caches each callsite's
    /// interest process-wide: a test thread that first registers the audit callsite with no
    /// subscriber can store `never` after this thread's subscriber was installed, and the
    /// event is then skipped. Alone in its process, nothing else can register it.
    #[test]
    fn the_audit_records_the_credential_apart_from_the_environment() {
        const CHILD: &str = "CREDSD_TEST_AUDIT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let name = "server::dispatch::tests::the_audit_records_the_credential_apart_from_the_environment";
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--test-threads=1"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && stdout.contains("1 passed"),
                "{stdout}{}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(audit_records_the_credential_apart_from_the_environment());
    }

    async fn audit_records_the_credential_apart_from_the_environment() {
        let daemon = daemon_with_credentials(&[("dev", &["held"])], &["held"], &["held"]);
        let request = |params: Value| {
            Request::with_params(Id::from(1), METHOD_CREDENTIAL_GET, &params).unwrap()
        };
        for (params, env, credential) in [(
            serde_json::json!({ "credential": "held" }),
            None,
            Some("held"),
        )] {
            let lines = audit_lines(dispatch(
                &request(params.clone()),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            ))
            .await;
            assert_eq!(lines.len(), 1, "{params}");
            let line = &lines[0];
            assert_eq!(line.get("env").and_then(Value::as_str), env, "{params}");
            assert_eq!(
                line.get("credential").and_then(Value::as_str),
                credential,
                "{params}"
            );
            let evidence: Value = serde_json::from_str(line["evidence"].as_str().unwrap()).unwrap();
            assert_eq!(evidence.get("env").and_then(Value::as_str), env, "{params}");
            assert_eq!(
                evidence.get("credential").and_then(Value::as_str),
                credential,
                "{params}"
            );
        }
    }

    #[tokio::test]
    async fn describe_is_unavailable() {
        let mut config = DaemonConfig::default();
        config.envs.insert(
            "dev".to_string(),
            EnvConfig {
                credentials: vec!["dev".into()],
                region: Some("eu-central-1".into()),
                ..Default::default()
            },
        );
        let mut sources = CredentialSources::default();
        sources.insert(
            "dev".to_string(),
            CredentialSource::AwsIdcSso(SsoConfig {
                start_url: "https://example.awsapps.com/start".into(),
                sso_region: "us-east-1".into(),
                account_id: "111111111111".into(),
                role_name: "Developer".into(),
                identity_type: Default::default(),
                allowed_roles: Vec::new(),
            }),
        );
        let key = credsd_core::encryption::generate_key().unwrap();
        let encryption = Arc::new(credsd_core::encryption::EncryptionService::new(key).unwrap());
        let store = Arc::new(CredentialStore::new(
            TEST_UID,
            &sources,
            encryption.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            crate::credential_store::records_verified(),
        ));
        let daemon = Daemon::with_caller(
            TEST_UID,
            config,
            sources,
            store,
            encryption,
            unbacked_root(),
        );

        let request = Request::with_params(
            Id::from(1),
            METHOD_PROFILE_DESCRIBE,
            &DescribeParams {
                environment: "dev".into(),
                request_id: None,
            },
        )
        .expect("object params");
        let response = dispatch(&request, Carrier::Uds, &peer(authorized()), &daemon).await;
        let Outcome::Error(error) = response.outcome else {
            panic!("expected method-not-found");
        };
        assert_eq!(error.code, credsd_core::rpc::CODE_METHOD_NOT_FOUND);
    }

    /// A first run has nothing provisioned, and `creds list` must still work: an empty list is
    /// the truthful answer, and the CLI already knows to print "no envs configured" for it.
    /// Failing here sent a fresh install to a daemon error instead.
    #[tokio::test]
    async fn list_is_empty_rather_than_an_error_for_an_unprovisioned_caller() {
        let request = Request::new(Id::from(1), METHOD_CREDENTIAL_LIST);
        let response = dispatch_uds(&request, &peer(CallerAuth::Denied(DenyReason::NoRoot))).await;
        let Outcome::Result(value) = response.outcome else {
            panic!("an unprovisioned caller must get an empty list, not an error");
        };
        assert_eq!(value["credentials"].as_array().map(Vec::len), Some(0));
    }

    /// Only a missing caller root is an empty state. An owner mismatch, an unknown uid, or a peer
    /// whose credentials could not be read are anomalies, and an empty list would tell a caller in
    /// one of those states that it had been seen.
    #[tokio::test]
    async fn list_still_refuses_every_deny_reason_that_is_not_an_absent_root() {
        for auth in [
            CallerAuth::Denied(DenyReason::NoPeerCred),
            CallerAuth::Denied(DenyReason::OwnerMismatch),
            CallerAuth::Denied(DenyReason::UnknownUid),
            CallerAuth::Unresolved,
        ] {
            let request = Request::new(Id::from(1), METHOD_CREDENTIAL_LIST);
            let response = dispatch_uds(&request, &peer(auth.clone())).await;
            assert_eq!(
                domain_code(&response),
                Some(DomainCode::CredentialNotFound),
                "{auth:?} is an anomaly, not an empty state"
            );
        }
    }

    #[tokio::test]
    async fn health_is_served_without_a_resolved_caller() {
        let request = Request::new(Id::from(1), METHOD_SYSTEM_HEALTH);
        let response = dispatch_uds(&request, &peer(CallerAuth::Denied(DenyReason::NoRoot))).await;
        let Outcome::Result(value) = response.outcome else {
            panic!("health must not require authorization");
        };
        assert_eq!(value["protocol"], 1);
    }

    #[tokio::test]
    async fn atomic_retrieval_is_method_not_found_over_stdio_never_a_permission_error() {
        // Requirement 13 AC 5: a method a carrier does not expose is method-not-found, not a
        // permission error, because a permission error confirms the method exists.
        let response = dispatch(
            &get_request("dev", None),
            Carrier::Stdio,
            &peer(authorized()),
            &test_daemon(),
        )
        .await;
        let Outcome::Error(e) = response.outcome else {
            panic!("credential/get must not be exposed over stdio");
        };
        assert_eq!(e.code, credsd_core::rpc::CODE_METHOD_NOT_FOUND);
        assert_eq!(e.domain_code(), None);
    }

    #[tokio::test]
    async fn an_unknown_method_is_method_not_found() {
        let request = Request::new(Id::from(1), "credential/delete");
        let response = dispatch_uds(&request, &peer(authorized())).await;
        let Outcome::Error(e) = response.outcome else {
            panic!("expected an error");
        };
        assert_eq!(e.code, credsd_core::rpc::CODE_METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn withdrawn_methods_are_unavailable_on_every_carrier() {
        let daemon = test_daemon();
        for method in [
            "environment/credentials",
            "environment/describe",
            "environment/remove",
            "config/set",
            "config/get",
            "config/unset",
        ] {
            for carrier in [Carrier::Uds, Carrier::Stdio] {
                let response = dispatch(
                    &Request::new(Id::from(1), method),
                    carrier,
                    &peer(authorized()),
                    &daemon,
                )
                .await;
                let Outcome::Error(error) = response.outcome else {
                    panic!("{method} was exposed on {carrier:?}");
                };
                assert_eq!(error.code, credsd_core::rpc::CODE_METHOD_NOT_FOUND);
            }
        }
    }

    #[tokio::test]
    async fn credential_methods_reject_any_environment_member_before_caller_loading() {
        let daemon = test_daemon();
        for method in [METHOD_CREDENTIAL_GET, METHOD_CREDENTIAL_LIST] {
            for value in [serde_json::Value::Null, serde_json::json!("secret-name")] {
                let request = Request::with_params(
                    Id::from(1),
                    method,
                    &serde_json::json!({"environment": value, "credential": "dev"}),
                )
                .unwrap();
                let response = dispatch(
                    &request,
                    Carrier::Uds,
                    &peer(CallerAuth::Unresolved),
                    &daemon,
                )
                .await;
                let Outcome::Error(error) = response.outcome else {
                    panic!("{method} accepted environment");
                };
                assert_eq!(error.code, credsd_core::rpc::CODE_INVALID_PARAMS);
                assert!(error.message.contains("environment"));
                assert!(!error.message.contains("secret-name"));
            }
        }
    }

    #[tokio::test]
    async fn the_response_echoes_the_request_id_and_protocol_version() {
        let request = Request::new(Id::from("corr-9"), METHOD_SYSTEM_HEALTH);
        let response = dispatch_uds(&request, &peer(authorized())).await;
        assert_eq!(response.id, Id::from("corr-9"));
        assert_eq!(response.jsonrpc, Version::V2);
    }

    /// Two unchanged samples of the same caller root compare equal, and a write to either
    /// source file makes them differ. This is the comparison `caller_state` reuses a cached
    /// store on, so if it stopped discriminating, every freshness check would silently pass
    /// and the staleness bug would return with its test still green.
    #[test]
    fn source_stamps_differ_after_either_file_is_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        // Absent files are a legitimate state (an unprovisioned caller), and two samples of
        // that state must still agree — otherwise every request would reload.
        let absent = SourceStamps::sample(root);
        assert!(absent.config.is_none() && absent.credentials.is_none());
        assert!(
            absent == SourceStamps::sample(root),
            "sampling an unprovisioned caller twice must compare equal"
        );

        for name in ["config.toml", "credentials.toml"] {
            let before = SourceStamps::sample(root);
            std::fs::write(root.join(name), "# written\n").expect("write");
            let after = SourceStamps::sample(root);
            assert!(
                before != after,
                "writing {name} must invalidate the stamp pair"
            );
            // A file appearing is a change even though the *other* file did not move.
            assert!(
                after == SourceStamps::sample(root),
                "re-sampling without a write must compare equal for {name}"
            );
        }
    }

    /// A daemon serves the `callers/` tree it was handed, and never consults
    /// `CREDSD_DATA_DIR` — not at construction, and not on a later request.
    ///
    /// Two properties in one case because they fail together. `platform::callers_dir()` reads
    /// that variable on every call, and the test binary runs cases as threads over one process
    /// environment, so a daemon that consulted it could stamp a freshness sample from one
    /// directory and compare it against a later sample from another — or worse, pin itself to a
    /// tree a concurrent case is actively writing. Either way it reads its own config as changed,
    /// reloads, discards an injected store, and answers `ENVIRONMENT_NOT_FOUND` for an env it
    /// holds. That is a nondeterministic failure of unrelated cases, so it is pinned here.
    #[tokio::test]
    async fn the_daemon_serves_the_root_it_was_given_not_the_environment() {
        let _lock = crate::server::e2e::DATA_DIR_ENV_LOCK.lock().await;
        let prev = std::env::var_os("CREDSD_DATA_DIR");
        let restore = || match &prev {
            Some(v) => std::env::set_var("CREDSD_DATA_DIR", v),
            None => std::env::remove_var("CREDSD_DATA_DIR"),
        };

        let given = tempfile::tempdir().expect("tempdir");
        let decoy = tempfile::tempdir().expect("tempdir");

        // The environment points somewhere else from the outset, as it would while a concurrent
        // case holds it. A daemon that resolved the root itself would land on the decoy.
        std::env::set_var("CREDSD_DATA_DIR", decoy.path());

        let key = credsd_core::encryption::generate_key().unwrap();
        let encryption = Arc::new(credsd_core::encryption::EncryptionService::new(key).unwrap());
        let daemon = Daemon::new(
            encryption,
            given.path().to_path_buf(),
            RegistryCustody::beside(given.path()),
            IntegrityCustody::File(given.path().join("integrity")),
        );
        assert_eq!(
            daemon.callers_root(),
            given.path(),
            "the daemon must serve the tree it was handed, not the one in the environment"
        );

        let cached = daemon.caller_state(TEST_UID);

        // Writing into the decoy is what a concurrent case's bootstrap looks like. It must not
        // invalidate state belonging to a tree this daemon does not serve.
        std::fs::create_dir_all(decoy.path().join(TEST_UID.to_string())).expect("mkdir");
        std::fs::write(
            decoy.path().join(TEST_UID.to_string()).join("config.toml"),
            "# a concurrent case's write\n",
        )
        .expect("write");

        assert!(
            Arc::ptr_eq(&daemon.caller_state(TEST_UID), &cached),
            "cached state must survive writes to a tree this daemon does not serve"
        );

        restore();
    }

    /// Dropping a `CallerState` aborts the refresh loop it owns.
    ///
    /// `spawn_refresh_task` loops forever with no cancellation, so before this the handle was
    /// discarded and every eviction leaked a task that kept refreshing credentials for a
    /// configuration no longer in effect. The freshness check multiplies evictions, which is
    /// what makes this load-bearing rather than tidy.
    #[tokio::test]
    async fn dropping_caller_state_aborts_its_refresh_task() {
        let key = credsd_core::encryption::generate_key().unwrap();
        let encryption = Arc::new(credsd_core::encryption::EncryptionService::new(key).unwrap());
        let root = unbacked_root();
        let daemon = Daemon::new(
            encryption,
            root.clone(),
            RegistryCustody::beside(&root),
            IntegrityCustody::beside(&root),
        );

        let state = daemon.caller_state(TEST_UID);
        let handle = state
            .refresh
            .clone()
            .expect("a lazily loaded state owns a refresh task");
        assert!(!handle.is_finished(), "refresh task should be running");

        // Remove the registry's reference, then our own: `Drop` runs when the last one goes,
        // which is what keeps an in-flight request from being cut off mid-read.
        daemon.evict_caller(TEST_UID);
        assert!(
            !handle.is_finished(),
            "eviction alone must not abort while a caller still holds the state"
        );
        drop(state);

        tokio::task::yield_now().await;
        assert!(
            handle.is_finished(),
            "refresh task must be aborted once the last reference to its state drops"
        );
    }

    /// Points `CREDSD_DATA_DIR` at an empty tempdir for the duration of `f`, then restores
    /// whatever was there before — including when `f` panics, via `e2e::EnvVarGuard`'s `Drop`.
    /// Nothing writes a `callers/<uid>/` tree into the tempdir unless `f` does, so a case that
    /// doesn't seed one reads every path under it back as "not found".
    ///
    /// Shares `e2e::DATA_DIR_ENV_LOCK` rather than a lock of its own: that is the one guard every
    /// case touching this process-global variable already coordinates through, and a second,
    /// uncoordinated lock would still race against it.
    async fn with_empty_data_dir<T>(f: impl FnOnce() -> T) -> T {
        let _lock = crate::server::e2e::DATA_DIR_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = crate::server::e2e::EnvVarGuard::set("CREDSD_DATA_DIR", dir.path());
        f()
    }

    /// Neither the credential's config entry nor its sealed data exist on disk, despite the
    /// request handler and `records_unchanged` both having let the approval through. This is
    /// the invariant violation `apply_credential_remove` must now refuse loudly instead of
    /// reporting a removal that did not happen.
    #[tokio::test]
    async fn apply_credential_remove_errors_when_entry_and_sealed_data_are_both_already_gone() {
        with_empty_data_dir(|| {
            let daemon = test_daemon();
            let files = TomlFiles::read(TEST_UID).expect("read empty caller root");
            let result = apply_credential_remove(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "ghost-cred",
                &files,
                &daemon,
            );
            assert_eq!(
                result.err().and_then(|e| e.domain_code()),
                Some(DomainCode::Internal)
            );
        })
        .await;
    }

    /// The config entry is already absent, but the credential's sealed data directory still
    /// exists. Unlike the case above, this is a legitimate, reachable state (sealed data left
    /// behind by prior cleanup) and must still succeed by deleting the orphaned directory.
    #[tokio::test]
    async fn apply_credential_remove_cleans_up_an_orphaned_sealed_directory() {
        with_empty_data_dir(|| {
            let daemon = test_daemon();
            let data_dir = platform::caller_root(TEST_UID)
                .join("credentials")
                .join("orphan-cred");
            std::fs::create_dir_all(&data_dir).expect("create orphaned sealed dir");
            // The entry is gone but the file it was removed from is present and empty, as the
            // removal that left this directory behind would have resealed it.
            std::fs::write(caller_credentials_path(TEST_UID), "").expect("write empty file");
            pin_on_disk(&daemon);
            let files = TomlFiles::read(TEST_UID).expect("read empty caller root");
            apply_credential_remove(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "orphan-cred",
                &files,
                &daemon,
            )
            .expect("orphaned sealed data alone must still be removable");
            assert!(!data_dir.exists(), "orphaned sealed directory must be gone");
        })
        .await;
    }

    /// Removing `x` must also delete the `.replaced-x.<id>` archive that a replaced `x` left
    /// behind, or the old credential can be restored by renaming it back. Another
    /// credential's archive, including `x.b`, whose name starts with `x.`, must survive.
    #[tokio::test]
    async fn apply_credential_remove_sweeps_the_replaced_archives_of_that_credential_only() {
        with_empty_data_dir(|| {
            let daemon = test_daemon();
            let root = platform::caller_root(TEST_UID).join("credentials");
            let own = root.join(".replaced-x.0123456789abcdef");
            let other = root.join(".replaced-y.0123456789abcdef");
            let dotted = root.join(".replaced-x.b.0123456789abcdef");
            for dir in [&own, &other, &dotted] {
                std::fs::create_dir_all(dir).expect("create archive");
            }
            std::fs::create_dir_all(root.join("x")).expect("create sealed dir");
            std::fs::write(caller_credentials_path(TEST_UID), "").expect("write empty file");
            pin_on_disk(&daemon);
            let files = TomlFiles::read(TEST_UID).expect("read empty caller root");
            apply_credential_remove(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "x",
                &files,
                &daemon,
            )
            .expect("remove x");
            assert!(!own.exists(), "x's archive must be swept");
            assert!(other.exists(), "y's archive must survive");
            assert!(dotted.exists(), "x.b's archive must survive");
        })
        .await;
    }

    /// A sweep that fails must surface its error, and a retry must finish the removal. By the
    /// time the sweep runs the entry is already gone, so the retry has to find the leftover
    /// archive itself. The blocker is a plain file where an archive directory belongs:
    /// `remove_dir_all` cannot delete it, whatever user runs the test. Replacing it with an
    /// empty directory clears the fault for the retry.
    #[tokio::test]
    async fn a_failed_archive_sweep_is_reported_and_a_retry_finishes_the_removal() {
        with_empty_data_dir(|| {
            let daemon = test_daemon();
            credsd_core::config::credentials::upsert_credential_at(
                &caller_credentials_path(TEST_UID),
                "retry-cred",
                &CredentialSource::AwsIdcSso(SsoConfig {
                    start_url: "https://example.awsapps.com/start".into(),
                    sso_region: "us-east-1".into(),
                    account_id: "111111111111".into(),
                    role_name: "Developer".into(),
                    identity_type: credsd_core::config::IdentityType::Human,
                    allowed_roles: Vec::new(),
                }),
            )
            .expect("seed credential entry");
            let root = platform::caller_root(TEST_UID).join("credentials");
            let archive = root.join(".replaced-retry-cred.0123456789abcdef");
            std::fs::create_dir_all(&root).expect("create credentials dir");
            std::fs::write(&archive, "blocks the sweep").expect("write blocking archive");
            pin_on_disk(&daemon);

            let files = TomlFiles::read(TEST_UID).expect("read seeded caller root");
            let first = apply_credential_remove(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "retry-cred",
                &files,
                &daemon,
            );
            assert_eq!(
                first.err().and_then(|e| e.domain_code()),
                Some(DomainCode::Internal),
                "a failed sweep must be reported to the caller"
            );

            std::fs::remove_file(&archive).expect("clear blocker");
            std::fs::create_dir_all(&archive).expect("replace blocker with a deletable archive");
            let files = TomlFiles::read(TEST_UID).expect("read caller root after failure");
            apply_credential_remove(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "retry-cred",
                &files,
                &daemon,
            )
            .expect("a retry must finish the removal");
            let leftover = std::fs::read_dir(&root)
                .expect("read credentials dir")
                .any(|entry| {
                    entry
                        .expect("read entry")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".replaced-")
                });
            assert!(!leftover, "no .replaced-* archive may survive the retry");
        })
        .await;
    }

    proptest::proptest! {
        /// The install side names an archive with `replaced_aside_name`; removal must match it
        /// for that credential and never for a dotted extension of it. Dots are in the
        /// generator because they are the only character that makes the two names collide.
        #[test]
        fn replaced_aside_matches_its_credential_only(
            credential in "[a-z0-9._-]{1,24}",
            suffix in "[a-z0-9._-]{1,8}",
            id in "[0-9a-f]{12}",
        ) {
            let own = replaced_aside_name(&credential, &id);
            proptest::prop_assert!(is_replaced_aside_of(&own, &credential));
            let dotted = format!("{credential}.{suffix}");
            proptest::prop_assert!(!is_replaced_aside_of(
                &replaced_aside_name(&dotted, &id),
                &credential
            ));
        }
    }

    /// The ordinary case the two cases above are measured against: a credential whose config
    /// entry and sealed data both exist. Guards against a regression that returns `Ok` (or an
    /// `Internal` error) without actually removing the entry — the earlier two cases alone would
    /// stay green against such a regression, since neither exercises `removed = Some(_)`.
    #[tokio::test]
    async fn apply_credential_remove_removes_an_entry_that_still_exists() {
        with_empty_data_dir(|| {
            let daemon = test_daemon();
            let credentials_path = caller_credentials_path(TEST_UID);
            credsd_core::config::credentials::upsert_credential_at(
                &credentials_path,
                "happy-cred",
                &CredentialSource::AwsIdcSso(SsoConfig {
                    start_url: "https://example.awsapps.com/start".into(),
                    sso_region: "us-east-1".into(),
                    account_id: "111111111111".into(),
                    role_name: "Developer".into(),
                    identity_type: Default::default(),
                    allowed_roles: Vec::new(),
                }),
            )
            .expect("seed credential entry");
            let data_dir = platform::caller_root(TEST_UID)
                .join("credentials")
                .join("happy-cred");
            std::fs::create_dir_all(&data_dir).expect("create sealed dir");
            pin_on_disk(&daemon);

            let files = TomlFiles::read(TEST_UID).expect("read seeded caller root");
            apply_credential_remove(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "happy-cred",
                &files,
                &daemon,
            )
            .expect("an existing credential must be removable");

            assert!(!data_dir.exists(), "sealed directory must be gone");
            let remaining =
                std::fs::read_to_string(&credentials_path).expect("read credentials.toml");
            assert!(
                !remaining.contains("happy-cred"),
                "config entry must be gone: {remaining}"
            );
        })
        .await;
    }

    /// The environment is already absent from the checked config text, despite the request
    /// handler having confirmed it was present and `records_unchanged` confirming the config
    /// hasn't moved since. `apply_env_remove` must refuse loudly rather than reseal the
    /// unchanged config and report a removal that did not happen.
    #[tokio::test]
    async fn apply_env_remove_errors_when_environment_is_no_longer_in_the_checked_config() {
        with_empty_data_dir(|| {
            let daemon = test_daemon();
            let files = TomlFiles::read(TEST_UID).expect("read empty caller root");
            let result = apply_env_remove(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "ghost-env",
                &files,
                &daemon,
            );
            assert_eq!(
                result.err().and_then(|e| e.domain_code()),
                Some(DomainCode::Internal)
            );
        })
        .await;
    }

    /// The ordinary case the case above is measured against: an environment that still exists
    /// in the config. Guards against a regression that returns `Ok` (or an `Internal` error)
    /// without actually removing the entry — the case above alone would stay green against such
    /// a regression, since it never exercises a `Some(_)` result from `remove_env_from`.
    #[tokio::test]
    #[ignore = "environment files are invalid until environment operations return"]
    async fn apply_env_remove_removes_an_environment_that_still_exists() {
        with_empty_data_dir(|| {
            let daemon = test_daemon();
            let config_path = caller_config_path(TEST_UID);
            std::fs::create_dir_all(config_path.parent().expect("config path has a parent"))
                .expect("create caller root");
            std::fs::write(&config_path, "[environments.happy-env]\n")
                .expect("seed config.toml with the environment");
            pin_on_disk(&daemon);

            let files = TomlFiles::read(TEST_UID).expect("read seeded caller root");
            apply_env_remove(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "happy-env",
                &files,
                &daemon,
            )
            .expect("an existing environment must be removable");

            let config = DaemonConfig::load_from(&platform::caller_root(TEST_UID))
                .expect("read back the sealed config")
                .0;
            assert!(
                !config.envs.contains_key("happy-env"),
                "environment must be gone from the sealed config"
            );
        })
        .await;
    }

    /// `config.toml` changed after the approval's `files` snapshot was taken (a hand edit, or a
    /// write by another request) but before apply ran. Both arms must refuse against the stale
    /// snapshot rather than editing from bytes that no longer match the file, and must not touch
    /// the file that is actually there.
    #[tokio::test]
    async fn config_set_and_unset_refuse_a_base_that_does_not_match_the_file() {
        with_empty_data_dir(|| {
            let daemon = test_daemon();
            let config_path = caller_config_path(TEST_UID);
            std::fs::create_dir_all(config_path.parent().expect("config path has a parent"))
                .expect("create caller root");
            std::fs::write(&config_path, "[environments.dev]\n")
                .expect("seed config.toml before the snapshot");
            let stale = TomlFiles::read(TEST_UID).expect("snapshot before the drift");

            std::fs::write(
                &config_path,
                "[environments.dev]\ndescription = 'hand edit'\n",
            )
            .expect("drift config.toml after the snapshot");

            let set_result = apply_config_set(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "dev",
                "description",
                "new",
                &stale,
                &daemon,
            );
            assert_eq!(
                set_result.err().and_then(|e| e.refusal_reason()),
                Some(credsd_core::presence::RefusalReason::BaseStateChanged)
            );

            let unset_result = apply_config_unset(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "dev",
                "description",
                &stale,
                &daemon,
            );
            assert_eq!(
                unset_result.err().and_then(|e| e.refusal_reason()),
                Some(credsd_core::presence::RefusalReason::BaseStateChanged)
            );

            let on_disk = std::fs::read_to_string(&config_path).expect("read config.toml");
            assert!(
                on_disk.contains("hand edit"),
                "the file on disk must be untouched by either refused arm: {on_disk}"
            );
        })
        .await;
    }

    /// `credentials.toml` drifted after the snapshot, while `config.toml` did not. The subject
    /// records of a config operation are both files, so this must refuse too — the set arm
    /// validates against the credentials, so stale credentials would decide the write.
    #[tokio::test]
    async fn config_set_refuses_when_only_credentials_drifted() {
        with_empty_data_dir(|| {
            let daemon = test_daemon();
            let config_path = caller_config_path(TEST_UID);
            std::fs::create_dir_all(config_path.parent().expect("config path has a parent"))
                .expect("create caller root");
            std::fs::write(&config_path, "[environments.dev]\n").expect("seed config.toml");
            let stale = TomlFiles::read(TEST_UID).expect("snapshot before the drift");

            seed_human_credential("drifted-in");

            let result = apply_config_set(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "dev",
                "description",
                "new",
                &stale,
                &daemon,
            );
            assert_eq!(
                result.err().and_then(|e| e.refusal_reason()),
                Some(credsd_core::presence::RefusalReason::BaseStateChanged)
            );
        })
        .await;
    }

    /// The reason the set arm validates before it writes: `identity_type = automation` on an env
    /// composing a Human credential violates the privilege lattice. The operation must be refused
    /// with `config.toml` left as it was, not written and then reported as drift.
    #[tokio::test]
    #[ignore = "environment files are invalid until environment operations return"]
    async fn config_set_refuses_a_privilege_lattice_violation_without_writing() {
        with_empty_data_dir(|| {
            let daemon = test_daemon();
            let config_path = caller_config_path(TEST_UID);
            std::fs::create_dir_all(config_path.parent().expect("config path has a parent"))
                .expect("create caller root");
            seed_human_credential("human-cred");
            let before = "[environments.dev]\ncredential = \"human-cred\"\n";
            std::fs::write(&config_path, before).expect("seed config.toml");
            pin_on_disk(&daemon);

            let files = TomlFiles::read(TEST_UID).expect("snapshot the seeded tree");
            let result = apply_config_set(
                &crate::server::write_lock::try_acquire(daemon.bootstrap_lock(TEST_UID), TEST_UID)
                    .expect("uncontended")
                    .held(),
                TEST_UID,
                "dev",
                "identity_type",
                "automation",
                &files,
                &daemon,
            );

            assert_eq!(
                result.err().and_then(|e| e.domain_code()),
                Some(DomainCode::Internal),
                "an env that may not compose its credential must be refused"
            );
            assert_eq!(
                std::fs::read_to_string(&config_path).expect("read config.toml"),
                before,
                "a refused set must not leave its edit on disk"
            );
        })
        .await;
    }

    /// The walk `Method::all` takes visits each method once, so the drift test that enumerates it
    /// drives every method the dispatcher has.
    #[test]
    fn the_method_walk_visits_each_method_once() {
        let all = Method::all();
        for (i, m) in all.iter().enumerate() {
            assert!(!all[..i].contains(m), "{m:?} visited twice");
        }
        assert!(all.iter().any(|m| m.writes_load_bearing()));
    }

    /// Seal both load-bearing files as they stand and pin them in the integrity record, as a
    /// daemon write would have, so a seeded tree reads as the daemon's own rather than as drift.
    fn pin_on_disk(daemon: &Daemon) {
        let files = TomlFiles::read(TEST_UID).expect("read seeded caller root");
        let mut record = crate::server::integrity::Record::UNPROVISIONED;
        for (name, bytes) in [(CONFIG, &files.config), (CREDENTIALS, &files.credentials)] {
            let path = platform::caller_root(TEST_UID).join(name);
            if !path.exists() {
                continue;
            }
            let text = std::str::from_utf8(bytes).expect("utf-8");
            let canonical =
                crate::server::integrity::canonical_of(TEST_UID, name, text).expect("canonical");
            record.pin_sealed(name, &canonical);
            crate::server::integrity::Verified::for_test(TEST_UID, record)
                .seal_snapshot(&daemon.encryption, name, &canonical)
                .expect("seal");
        }
        daemon
            .integrity
            .write(crate::server::integrity::Verified::for_test(
                TEST_UID, record,
            ))
            .expect("pin");
    }

    fn logout_request(credential: &str) -> Request {
        Request::with_params(
            Id::from(1),
            METHOD_CREDENTIAL_LOGOUT,
            &CredentialLogoutParams {
                credential: credential.into(),
            },
        )
        .expect("object params")
    }

    /// Not `sso_token.enc`: a logout opens that to end the sign-in at SSO, and these cases test the
    /// local deletion alone.
    const STAND_IN_SESSION: &str = "session.enc";

    /// Seal a stand-in session file in `name`'s data directory, as a sign-in would have.
    fn seed_session(daemon: &Daemon, name: &str) -> std::path::PathBuf {
        let dir = platform::caller_root(TEST_UID)
            .join("credentials")
            .join(name);
        daemon
            .encryption
            .seal_to_file(&dir.join(STAND_IN_SESSION), b"not a real session")
            .expect("seal session");
        dir
    }

    /// Captures every `tracing` event emitted on this thread while it is held.
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("capture lock")).into_owned()
        }
    }

    /// Run `f` with a fresh data dir and a log capture, for async cases that need both.
    async fn with_logout_fixture<F, Fut>(f: F)
    where
        F: FnOnce(Daemon, Captured) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let _lock = crate::server::e2e::DATA_DIR_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = crate::server::e2e::EnvVarGuard::set("CREDSD_DATA_DIR", dir.path());
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _log = tracing::subscriber::set_default(subscriber);
        // Backed by the temp data dir, unlike `test_daemon`, so a get after the logout reloads
        // what is on disk.
        let callers = platform::callers_dir();
        let daemon = Daemon::new(
            Arc::new(
                credsd_core::encryption::EncryptionService::new(
                    credsd_core::encryption::generate_key().expect("key"),
                )
                .expect("encryption"),
            ),
            callers.clone(),
            RegistryCustody::beside(&callers),
            IntegrityCustody::beside(&callers),
        );
        f(daemon, captured).await;
    }

    /// Requirement 15 AC 12 and 16: a logout deletes the session and its archives, keeps the
    /// entry, leaves the records valid, audits the deletion, and the next get must sign in again.
    #[tokio::test]
    async fn logout_signs_a_credential_out_and_keeps_its_entry() {
        with_logout_fixture(|daemon, log| async move {
            seed_human_credential("work");
            let session = seed_session(&daemon, "work");
            let archive = platform::caller_root(TEST_UID)
                .join("credentials")
                .join(".replaced-work.0123456789abcdef");
            std::fs::create_dir_all(&archive).expect("seed archive");
            pin_on_disk(&daemon);
            let before = TomlFiles::read(TEST_UID).expect("read before");

            let logged_out = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            // No sealed SSO token, so nothing was sent to SSO: only the local session ended.
            logged_out_with(&logged_out, "local_only");

            assert!(!session.exists(), "the sealed session must be gone");
            assert!(
                !archive.exists(),
                "a replaced archive must not survive a logout"
            );
            assert!(
                TomlFiles::read(TEST_UID).expect("read after") == before,
                "a logout must not change either load-bearing file"
            );
            assert!(
                log.text().contains("operation=\"credential/logout\"")
                    && log.text().contains("credential=\"work\""),
                "a logout that deleted material must be audited: {}",
                log.text()
            );
            let after = dispatch(
                &Request::with_params(
                    Id::from(2),
                    METHOD_CREDENTIAL_GET,
                    &GetParams {
                        environment: None,
                        credential: Some("work".into()),
                        account_id: None,
                        role_name: None,
                        scope: None,
                        claim: None,
                        request_id: None,
                    },
                )
                .expect("object params"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            assert_eq!(
                domain_code(&after),
                Some(DomainCode::ReauthRequired),
                "{after:?}"
            );
        })
        .await;
    }

    /// What a sign-in writes to a data directory (design: the data-directory table), plus the
    /// identity record, then files only other sources write.
    const SIGN_IN_FILES: [&str; 5] = [
        "aws_login_token.enc",
        "dpop_key.enc",
        "sso_token.enc",
        "oauth_token.enc",
        "identity.enc",
    ];
    const OTHER_FILES: [&str; 5] = [
        "iam_user.enc",
        "iam_session.enc",
        "static_secret.enc",
        "ra_key.enc",
        "jwt.enc",
    ];

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

        /// AC 12: a logout deletes exactly the archives holding nothing but sign-in output, and
        /// leaves any other, such as one with an IAM key from before a re-bootstrap, intact for
        /// the gated remove. Deleting no archive and no session is `none`.
        #[test]
        fn logout_sweeps_only_archives_of_sign_in_output(
            archives in proptest::collection::vec(
                proptest::collection::vec(
                    proptest::sample::select([SIGN_IN_FILES, OTHER_FILES].concat()),
                    0..4,
                ),
                0..4,
            ),
        ) {
            block_on(with_logout_fixture(|daemon, _log| async move {
                seed_human_credential("work");
                pin_on_disk(&daemon);
                let credentials = platform::caller_root(TEST_UID).join("credentials");
                let seeded: Vec<_> = archives
                    .iter()
                    .enumerate()
                    .map(|(i, files)| {
                        let dir = credentials.join(replaced_aside_name("work", &format!("{i:016x}")));
                        std::fs::create_dir_all(&dir).expect("seed archive");
                        for file in files {
                            std::fs::write(dir.join(file), b"sealed").expect("seed file");
                        }
                        let sign_in_only = files.iter().all(|f| SIGN_IN_FILES.contains(f));
                        (dir, sign_in_only)
                    })
                    .collect();

                let logged_out = dispatch(
                    &logout_request("work"),
                    Carrier::Uds,
                    &peer(authorized()),
                    &daemon,
                )
                .await;

                let swept = seeded.iter().any(|(_, sign_in_only)| *sign_in_only);
                logged_out_with(&logged_out, if swept { "local_only" } else { "none" });
                for ((dir, sign_in_only), files) in seeded.iter().zip(&archives) {
                    assert_eq!(dir.exists(), !sign_in_only, "{files:?}");
                    if !sign_in_only {
                        assert!(files.iter().all(|f| dir.join(f).exists()), "{files:?}");
                    }
                }
            }));
        }
    }

    /// AC 15: an unknown name is CREDENTIAL_NOT_FOUND, and a second logout of the same credential
    /// succeeds, deletes nothing, and writes no second audit record.
    #[tokio::test]
    async fn logout_of_an_unknown_name_is_not_found_and_a_repeat_is_harmless() {
        with_logout_fixture(|daemon, log| async move {
            seed_human_credential("work");
            seed_session(&daemon, "work");
            pin_on_disk(&daemon);

            let unknown = dispatch(
                &logout_request("nope"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            assert_eq!(domain_code(&unknown), Some(DomainCode::CredentialNotFound));

            // Only the first logout signs out; the repeat finds no session.
            for expected in ["local_only", "none"] {
                let again = dispatch(
                    &logout_request("work"),
                    Carrier::Uds,
                    &peer(authorized()),
                    &daemon,
                )
                .await;
                logged_out_with(&again, expected);
            }
            assert_eq!(
                log.text()
                    .matches("operation=\"credential/logout\"")
                    .count(),
                1,
                "only the logout that deleted something is audited"
            );
        })
        .await;
    }

    /// A logout keeps the record of who signed in, so the next sign-in can compare against it.
    #[tokio::test]
    async fn logout_keeps_the_signed_in_identity_record() {
        with_logout_fixture(|daemon, _log| async move {
            seed_human_credential("work");
            let dir = seed_session(&daemon, "work");
            let identity = dir.join(KEPT_ON_LOGOUT);
            std::fs::write(&identity, b"sealed identity").expect("seed identity record");
            pin_on_disk(&daemon);

            let logged_out = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            assert!(
                matches!(logged_out.outcome, Outcome::Result(_)),
                "{logged_out:?}"
            );
            assert!(
                !dir.join(STAND_IN_SESSION).exists(),
                "the session must be gone"
            );
            assert!(
                identity.exists(),
                "the identity record must survive a logout"
            );
        })
        .await;
    }

    /// A logout touches only the credential it names.
    #[tokio::test]
    async fn logout_leaves_other_credentials_alone() {
        with_logout_fixture(|daemon, _log| async move {
            seed_human_credential("work");
            seed_human_credential("home");
            seed_session(&daemon, "work");
            let other = seed_session(&daemon, "home");
            pin_on_disk(&daemon);

            let logged_out = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            assert!(
                matches!(logged_out.outcome, Outcome::Result(_)),
                "{logged_out:?}"
            );
            assert!(other.exists(), "another credential's session must survive");
        })
        .await;
    }

    /// AC 13: a source whose material no sign-in restores is refused, and nothing is deleted.
    #[tokio::test]
    async fn logout_refuses_a_credential_that_does_not_sign_in() {
        with_logout_fixture(|daemon, _log| async move {
            credsd_core::config::credentials::upsert_credential_at(
                &caller_credentials_path(TEST_UID),
                "keys",
                &CredentialSource::AwsIamUser(credsd_core::config::IamUserConfig {
                    region: "us-east-1".into(),
                    duration_seconds: None,
                    mfa_serial: None,
                    identity_type: credsd_core::config::IdentityType::Human,
                }),
            )
            .expect("seed iam user");
            let key = seed_session(&daemon, "keys");
            pin_on_disk(&daemon);

            let refused = dispatch(
                &logout_request("keys"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            let Outcome::Error(e) = refused.outcome else {
                panic!("a logout of an IAM key must be refused");
            };
            assert_eq!(e.code, -32000);
            assert_eq!(
                e.data.as_ref().and_then(|data| data.get("code")),
                Some(&Value::from("LOGOUT_UNSUPPORTED_SOURCE")),
                "{e:?}"
            );
            assert!(e.message.contains("credential/remove"), "{}", e.message);
            assert!(key.exists(), "a refused logout must delete nothing");
        })
        .await;
    }

    /// AC 14: over a drifted credentials.toml a logout is refused before the entry is read, so a
    /// hand-edited source type cannot make it delete material a sign-in does not restore.
    #[tokio::test]
    async fn logout_refuses_over_drift_and_deletes_nothing() {
        with_logout_fixture(|daemon, _log| async move {
            seed_human_credential("work");
            let session = seed_session(&daemon, "work");
            pin_on_disk(&daemon);
            let path = caller_credentials_path(TEST_UID);
            let text = std::fs::read_to_string(&path).expect("read credentials");
            std::fs::write(&path, text.replace("us-east-1", "us-west-2"))
                .expect("drift credentials.toml");

            let refused = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            assert_eq!(domain_code(&refused), Some(DomainCode::ConfigDrifted));
            assert!(session.exists(), "a refused logout must delete nothing");
        })
        .await;
    }

    /// A Human-tier credential in the caller's `credentials.toml`, for cases that need an env to
    /// reference something real.
    fn seed_human_credential(name: &str) {
        credsd_core::config::credentials::upsert_credential_at(
            &caller_credentials_path(TEST_UID),
            name,
            &CredentialSource::AwsIdcSso(SsoConfig {
                start_url: "https://example.awsapps.com/start".into(),
                sso_region: "us-east-1".into(),
                account_id: "111111111111".into(),
                role_name: "Developer".into(),
                identity_type: credsd_core::config::IdentityType::Human,
                allowed_roles: Vec::new(),
            }),
        )
        .expect("seed credential entry");
    }

    thread_local! {
        /// The SSO portal a logout on this thread calls; `None` keeps the regional endpoint.
        pub(super) static SSO_ENDPOINT: std::cell::RefCell<Option<String>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Log out of an aws-idc-sso sign-in sealing `token`, against a mock portal that answers its
    /// one `Logout` (which must bear `token`) with `status`, carrying `code` as the AWS error type
    /// when there is one. Returns the response and whether the sealed session survived.
    async fn logout_at_portal(
        daemon: &Daemon,
        token: &str,
        status: usize,
        code: Option<&str>,
    ) -> (Response<Value>, bool) {
        let mut server = mockito::Server::new_async().await;
        let mut mock = server
            .mock("POST", "/logout")
            .match_header("x-amz-sso_bearer_token", token)
            .with_status(status);
        if let Some(code) = code {
            mock = mock.with_header("x-amzn-errortype", code);
        }
        let logout = mock.expect(1).create_async().await;
        SSO_ENDPOINT.with(|url| *url.borrow_mut() = Some(server.url()));
        let session = seal_sso_session(daemon, &sso_session(token));

        let logged_out = dispatch(
            &logout_request("work"),
            Carrier::Uds,
            &peer(authorized()),
            daemon,
        )
        .await;
        SSO_ENDPOINT.with(|url| *url.borrow_mut() = None);
        logout.assert_async().await;
        (logged_out, session.exists())
    }

    fn block_on(future: impl std::future::Future<Output = ()>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(future);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(8))]

        /// Requirement 15: a `credential/logout` of an aws-idc-sso sign-in ends it at SSO, with
        /// exactly one `Logout` bearing the sealed access token, and still deletes it here.
        #[test]
        fn logout_ends_an_sso_sign_in_at_sso(token in "[A-Za-z0-9+/=._-]{1,256}") {
            block_on(with_logout_fixture(|daemon, _log| async move {
                let (logged_out, session_left) = logout_at_portal(&daemon, &token, 200, None).await;
                logged_out_with(&logged_out, "ended");
                assert!(!session_left, "the sealed session must be gone");
            }));
        }

        /// AC 18: SSO refusing the access token as invalid or expired is `token_rejected`, not
        /// `ended`, since the portal session may still be live; the session is still deleted here.
        #[test]
        fn a_logout_sso_refuses_as_unauthorized_reports_token_rejected(
            token in "[A-Za-z0-9+/=._-]{1,256}",
        ) {
            block_on(with_logout_fixture(|daemon, _log| async move {
                let (logged_out, session_left) =
                    logout_at_portal(&daemon, &token, 401, Some("UnauthorizedException")).await;
                logged_out_with(&logged_out, "token_rejected");
                assert!(!session_left, "the sealed session must be gone");
            }));
        }

        /// A `Logout` SSO refuses other than as an invalid token never reads as ended (these carry
        /// no error code): the logout succeeds, since the session is
        /// deleted here, and reports `failed` with where to end it at SSO and when the access token expires.
        #[test]
        fn a_refused_sso_logout_reports_failed_and_still_deletes_the_session(
            token in "[A-Za-z0-9+/=._-]{1,256}",
            status in proptest::sample::select(vec![400usize, 401, 403, 404]),
        ) {
            block_on(with_logout_fixture(|daemon, log| async move {
                let (logged_out, session_left) = logout_at_portal(&daemon, &token, status, None).await;
                assert_failed_at_sso(&logged_out, Some(ACCESS_TOKEN_EXPIRES_AT));
                assert!(!session_left, "the sealed session must be gone");
                assert!(
                    log.text().contains("operation=\"credential/logout\""),
                    "a refused Logout must still audit the deletion: {}",
                    log.text()
                );
                assert_repeat_does_not_retry_logout(&daemon).await;
            }));
        }
    }

    /// AC 18: after a logout whose `Logout` failed, a repeat finds no sealed session, succeeds
    /// with provider `none`, and sends SSO nothing.
    async fn assert_repeat_does_not_retry_logout(daemon: &Daemon) {
        let mut server = mockito::Server::new_async().await;
        let logout = server
            .mock("POST", "/logout")
            .expect(0)
            .create_async()
            .await;
        SSO_ENDPOINT.with(|url| *url.borrow_mut() = Some(server.url()));
        let again = dispatch(
            &logout_request("work"),
            Carrier::Uds,
            &peer(authorized()),
            daemon,
        )
        .await;
        SSO_ENDPOINT.with(|url| *url.borrow_mut() = None);
        logout.assert_async().await;
        logged_out_with(&again, "none");
    }

    /// The `provider` outcome of a logout that must have succeeded. Only `none` is not signed out,
    /// and only `failed` says where to end the session at SSO and when the access token expires.
    fn logged_out_with<'a>(response: &'a Response<Value>, provider: &str) -> &'a Value {
        let Outcome::Result(value) = &response.outcome else {
            panic!("a logout that deleted something, or found nothing, must succeed: {response:?}");
        };
        assert_eq!(value["provider"], provider, "{value}");
        assert_eq!(value["signed_out"], provider != "none", "{value}");
        if provider != "failed" {
            assert!(value.get("start_url").is_none(), "{value}");
            assert!(value.get("access_token_expires_at").is_none(), "{value}");
        }
        value
    }

    /// A logout whose SSO `Logout` failed: signed out here, with the start URL to end the session
    /// at SSO and, when the sealed token was readable, when that access token expires.
    fn assert_failed_at_sso(response: &Response<Value>, expires: Option<&str>) {
        let value = logged_out_with(response, "failed");
        assert_eq!(
            value["start_url"], "https://example.awsapps.com/start",
            "{value}"
        );
        assert_eq!(
            value.get("access_token_expires_at").and_then(Value::as_str),
            expires,
            "{value}"
        );
    }

    const ACCESS_TOKEN_EXPIRES_AT: &str = "2999-01-01T00:00:00Z";

    /// AC 17: an aws-login or aws-web-identity sign-in has no session at an identity provider to
    /// end, so its logout deletes it here, sends nothing, and reports `local_only`.
    #[tokio::test]
    async fn a_sign_in_with_nothing_to_end_upstream_reports_local_only() {
        for source in [
            serde_json::json!({"type": "aws-login", "region": "us-east-1"}),
            serde_json::json!({
                "type": "aws-web-identity",
                "role_arn": "arn:aws:iam::111111111111:role/Developer",
                "region": "us-east-1",
            }),
        ] {
            with_logout_fixture(|daemon, _log| async move {
                credsd_core::config::credentials::upsert_credential_at(
                    &caller_credentials_path(TEST_UID),
                    "work",
                    &serde_json::from_value(source).expect("source"),
                )
                .expect("seed credential entry");
                let session = seed_session(&daemon, "work");
                pin_on_disk(&daemon);
                let logged_out = dispatch(
                    &logout_request("work"),
                    Carrier::Uds,
                    &peer(authorized()),
                    &daemon,
                )
                .await;
                logged_out_with(&logged_out, "local_only");
                assert!(!session.exists(), "the session must be gone");
                assert_repeat_does_not_retry_logout(&daemon).await;
            })
            .await;
        }
    }

    /// AC 18: an SSO endpoint that cannot be reached never keeps the user signed in here.
    #[tokio::test]
    async fn an_unreachable_sso_endpoint_still_signs_out_here() {
        with_logout_fixture(|daemon, _log| async move {
            // Bind and drop a listener, so the port is known to refuse connections.
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("bind")
                .local_addr()
                .expect("addr")
                .port();
            SSO_ENDPOINT.with(|url| *url.borrow_mut() = Some(format!("http://127.0.0.1:{port}")));
            let session = seal_sso_session(&daemon, &sso_session("token"));

            let logged_out = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            SSO_ENDPOINT.with(|url| *url.borrow_mut() = None);
            assert_failed_at_sso(&logged_out, Some(ACCESS_TOKEN_EXPIRES_AT));
            assert!(!session.exists(), "the sealed session must be gone");
        })
        .await;
    }

    /// A `Logout` SSO never answers is cut off at its limit and reads as `failed`; the session
    /// is still deleted here, the cached state evicted, and the deletion audited.
    #[tokio::test]
    async fn a_stalled_sso_logout_times_out_and_still_signs_out_here() {
        with_logout_fixture(|daemon, log| async move {
            // Bound but never accepted: the kernel completes the handshake, nothing answers.
            let stalled = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let url = format!("http://{}", stalled.local_addr().expect("addr"));
            SSO_ENDPOINT.with(|endpoint| *endpoint.borrow_mut() = Some(url));
            let session = seal_sso_session(&daemon, &sso_session("token"));
            let cached = daemon.caller_state(TEST_UID);

            let logged_out = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            SSO_ENDPOINT.with(|endpoint| *endpoint.borrow_mut() = None);
            assert_failed_at_sso(&logged_out, Some(ACCESS_TOKEN_EXPIRES_AT));
            assert!(!session.exists(), "the sealed session must be gone");
            assert!(
                !Arc::ptr_eq(&daemon.caller_state(TEST_UID), &cached),
                "the cached state must be evicted"
            );
            assert!(
                log.text().contains("operation=\"credential/logout\""),
                "a stalled Logout must still audit the deletion: {}",
                log.text()
            );
        })
        .await;
    }

    /// Seal `bytes` as `work`'s SSO session, as a sign-in would have, and return its path.
    fn seal_sso_session(daemon: &Daemon, bytes: &[u8]) -> std::path::PathBuf {
        seed_human_credential("work");
        let session = platform::caller_root(TEST_UID)
            .join("credentials")
            .join("work")
            .join("sso_token.enc");
        daemon.encryption.seal_to_file(&session, bytes).unwrap();
        pin_on_disk(daemon);
        session
    }

    fn sso_session(token: &str) -> Vec<u8> {
        serde_json::to_vec(&credsd_core::providers::sso::CachedSsoToken {
            access_token: token.into(),
            expires_at: ACCESS_TOKEN_EXPIRES_AT.into(),
            refresh_token: None,
            client_id: "client".into(),
            client_secret: "secret".into(),
            start_url: "https://example.awsapps.com/start".into(),
            region: "us-east-1".into(),
        })
        .unwrap()
    }

    /// A logout queued behind another writer gives up on its wait budget instead of parking, and
    /// deletes nothing, since it never ran.
    #[tokio::test]
    async fn a_logout_behind_a_held_write_lock_gives_up_and_deletes_nothing() {
        with_logout_fixture(|daemon, _log| async move {
            let session = seal_sso_session(&daemon, &sso_session("token"));
            let lock = daemon.bootstrap_lock(TEST_UID);
            let held = lock.lock().await;
            let logged_out = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                dispatch(
                    &logout_request("work"),
                    Carrier::Uds,
                    &peer(authorized()),
                    &daemon,
                ),
            )
            .await
            .expect("a logout behind a held lock must give up, not park");
            drop(held);
            // An error, since nothing was deleted; a logout that deleted something succeeds.
            assert_eq!(
                domain_code(&logged_out),
                Some(DomainCode::Internal),
                "{logged_out:?}"
            );
            let Outcome::Error(error) = &logged_out.outcome else {
                panic!("{logged_out:?}");
            };
            assert!(
                error.message.contains("nothing was deleted"),
                "{}",
                error.message
            );
            assert!(session.exists(), "a logout that never ran deletes nothing");
        })
        .await;
    }

    /// A logout that fails after its deletion started errs, and a retry of the same logout
    /// finishes it: the sealed token is gone, the cached state evicted, and the deletion audited,
    /// with SSO called only once.
    #[tokio::test]
    async fn a_logout_that_fails_partway_is_finished_by_a_retry() {
        with_logout_fixture(|daemon, log| async move {
            let mut server = mockito::Server::new_async().await;
            let sso = server
                .mock("POST", "/logout")
                .with_status(200)
                .expect(1)
                .create_async()
                .await;
            SSO_ENDPOINT.with(|url| *url.borrow_mut() = Some(server.url()));
            let session = seal_sso_session(&daemon, &sso_session("token"));
            let cached = daemon.caller_state(TEST_UID);
            // The data directory behind a symlink: every file in it is deleted through the link,
            // then removing the link as a directory fails, whatever user runs the test. A real
            // empty directory in its place clears the fault for the retry.
            let credentials = platform::caller_root(TEST_UID).join("credentials");
            let data_dir = credentials.join("work");
            let linked = platform::caller_root(TEST_UID).join("linked-work");
            std::fs::rename(&data_dir, &linked).expect("move data dir");
            std::os::unix::fs::symlink(&linked, &data_dir).expect("link data dir");
            let failed = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            std::fs::remove_file(&data_dir).expect("drop link");
            std::fs::create_dir(&data_dir).expect("empty data dir");
            assert!(
                matches!(failed.outcome, Outcome::Error(_)),
                "a logout that could not finish must err: {failed:?}"
            );
            assert!(!session.exists(), "the deletion had started");

            let retried = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            SSO_ENDPOINT.with(|url| *url.borrow_mut() = None);
            sso.assert_async().await;
            logged_out_with(&retried, "local_only");
            assert!(!session.exists(), "the sealed token must be gone");
            assert!(
                !credentials.join("work").exists(),
                "the data directory must be gone"
            );
            assert!(
                !Arc::ptr_eq(&daemon.caller_state(TEST_UID), &cached),
                "the cached state must be evicted"
            );
            assert!(
                log.text().contains("operation=\"credential/logout\""),
                "the retry must audit the deletion: {}",
                log.text()
            );
        })
        .await;
    }

    /// AC 18: a logout that fails after SSO accepted `Logout` but before it deleted the sealed
    /// token leaves that token behind. The retry sends it again, SSO refuses it as invalid, and
    /// the retry reports `token_rejected`, not `ended`, since nothing on disk records that the
    /// first call succeeded.
    #[tokio::test]
    async fn a_retry_after_a_partial_logout_that_sso_refuses_reports_token_rejected() {
        with_logout_fixture(|daemon, _log| async move {
            let mut server = mockito::Server::new_async().await;
            let accepted = server
                .mock("POST", "/logout")
                .with_status(200)
                .expect(1)
                .create_async()
                .await;
            SSO_ENDPOINT.with(|url| *url.borrow_mut() = Some(server.url()));
            let session = seal_sso_session(&daemon, &sso_session("token"));
            // An archive name that is a file, not a directory: reading it fails after `Logout`
            // and before any deletion. Removing it clears the fault for the retry.
            let archive = platform::caller_root(TEST_UID)
                .join("credentials")
                .join(replaced_aside_name("work", "0123456789abcdef"));
            std::fs::write(&archive, b"not a directory").expect("seed archive file");
            let failed = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            assert!(
                matches!(failed.outcome, Outcome::Error(_)),
                "a logout that could not finish must err: {failed:?}"
            );
            assert!(
                session.exists(),
                "the sealed token must survive the failure"
            );
            accepted.assert_async().await;
            accepted.remove_async().await;
            std::fs::remove_file(&archive).expect("clear fault");

            let refused = server
                .mock("POST", "/logout")
                .with_status(401)
                .with_header("x-amzn-errortype", "UnauthorizedException")
                .with_body(r#"{"message":"Session token not found or invalid"}"#)
                .expect(1)
                .create_async()
                .await;
            let retried = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            SSO_ENDPOINT.with(|url| *url.borrow_mut() = None);
            refused.assert_async().await;
            logged_out_with(&retried, "token_rejected");
            assert!(!session.exists(), "the retry must delete the sealed token");
        })
        .await;
    }

    /// A logout whose hold runs out reports that nothing was deleted, so that must be true: the
    /// hold cancels the body only at an await, and the body's only awaits, the bounded SSO
    /// refresh and `Logout`, come before the first deletion. Here SSO never answers, so that
    /// await lasts its whole bound; any await added inside the deletion that outlasts the rest of
    /// the hold would let the hold cancel a logout that had already deleted the session.
    #[tokio::test(start_paused = true)]
    async fn a_logout_hold_expiry_never_lands_after_deletion_started() {
        with_logout_fixture(|daemon, _log| async move {
            // Bound but never accepted: the kernel completes the handshake, nothing answers.
            let stalled = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let url = format!("http://{}", stalled.local_addr().expect("addr"));
            SSO_ENDPOINT.with(|endpoint| *endpoint.borrow_mut() = Some(url));
            let session = seal_sso_session(&daemon, &sso_session("token"));
            let logged_out = dispatch(
                &logout_request("work"),
                Carrier::Uds,
                &peer(authorized()),
                &daemon,
            )
            .await;
            SSO_ENDPOINT.with(|endpoint| *endpoint.borrow_mut() = None);
            match &logged_out.outcome {
                Outcome::Error(error) => {
                    assert!(
                        error.message.contains("nothing was deleted"),
                        "{}",
                        error.message
                    );
                    assert!(
                        session.exists(),
                        "an error that says nothing was deleted: {}",
                        error.message
                    );
                }
                Outcome::Result(_) => {
                    assert!(
                        !session.exists(),
                        "a logout that succeeds deletes the session"
                    );
                }
            }
        })
        .await;
    }

    /// A login queued behind a logout whose SSO endpoint never answers is not promised the lock
    /// within its wait (`drift-detection` 5.9): the logout's `Logout` is bounded by its own hold,
    /// not by other operations' waits. The login's wait runs out before it starts, so it writes
    /// nothing and may be retried, and the logout still signs out here.
    #[tokio::test(start_paused = true)]
    async fn a_login_queued_behind_a_stalled_sso_logout_fails_its_wait_before_starting() {
        with_logout_fixture(|daemon, _log| async move {
            // Bound but never accepted: the kernel completes the handshake, nothing answers.
            let stalled = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let url = format!("http://{}", stalled.local_addr().expect("addr"));
            SSO_ENDPOINT.with(|endpoint| *endpoint.borrow_mut() = Some(url));
            seal_sso_session(&daemon, &sso_session("token"));
            let request = logout_request("work");
            let caller = peer(authorized());
            let lock = daemon.bootstrap_lock(TEST_UID);
            let login = async {
                assert!(
                    lock.try_lock().is_err(),
                    "the logout must hold the lock first"
                );
                crate::server::write_lock::under(
                    &lock,
                    TEST_UID,
                    crate::server::bootstrap::LOGIN_LOCK_BUDGET,
                    async |_| (),
                )
                .await
            };
            let (logged_out, login) =
                tokio::join!(dispatch(&request, Carrier::Uds, &caller, &daemon), login);
            SSO_ENDPOINT.with(|endpoint| *endpoint.borrow_mut() = None);
            assert_eq!(
                login,
                Err(crate::server::write_lock::Expired::Wait),
                "the login's wait must run out before the logout's SSO bound does"
            );
            assert_failed_at_sso(&logged_out, Some(ACCESS_TOKEN_EXPIRES_AT));
        })
        .await;
    }

    /// An SSO endpoint that accepts and never answers cannot hold the caller's write lock past
    /// the logout's budget, and the logout still signs out here (AC 18).
    #[tokio::test]
    async fn a_silent_sso_endpoint_cannot_hold_the_write_lock() {
        with_logout_fixture(|daemon, _log| async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let port = listener.local_addr().expect("addr").port();
            // Accept every connection and never answer it.
            let silent = tokio::spawn(async move {
                let mut open = Vec::new();
                while let Ok((stream, _)) = listener.accept().await {
                    open.push(stream);
                }
            });
            SSO_ENDPOINT.with(|url| *url.borrow_mut() = Some(format!("http://127.0.0.1:{port}")));
            let session = seal_sso_session(&daemon, &sso_session("token"));

            let logged_out = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                dispatch(
                    &logout_request("work"),
                    Carrier::Uds,
                    &peer(authorized()),
                    &daemon,
                ),
            )
            .await;
            SSO_ENDPOINT.with(|url| *url.borrow_mut() = None);
            silent.abort();
            let logged_out = logged_out.expect("a silent SSO endpoint must not stall the logout");
            assert_failed_at_sso(&logged_out, Some(ACCESS_TOKEN_EXPIRES_AT));
            assert!(!session.exists(), "the sealed session must be gone");
            assert!(
                daemon.bootstrap_lock(TEST_UID).try_lock().is_ok(),
                "the write lock must be free once the logout returns"
            );
        })
        .await;
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(16))]

        /// A sealed session that cannot be read (corrupt, or sealed under a key since rotated) is
        /// not "no session": SSO cannot be told to end it, so the logout reports `failed` as a
        /// refused `Logout` does, with no expiry since none can be read, and still deletes it.
        #[test]
        fn an_unreadable_sso_session_reports_failed_and_is_still_deleted(
            garbage in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
        ) {
            block_on(with_logout_fixture(|daemon, log| async move {
                let mut server = mockito::Server::new_async().await;
                let logout = server.mock("POST", "/logout").expect(0).create_async().await;
                SSO_ENDPOINT.with(|url| *url.borrow_mut() = Some(server.url()));
                let session = seal_sso_session(&daemon, b"placeholder");
                // Overwrite the seal with bytes that open under no key.
                std::fs::write(&session, &garbage).unwrap();

                let logged_out = dispatch(
                    &logout_request("work"),
                    Carrier::Uds,
                    &peer(authorized()),
                    &daemon,
                )
                .await;
                SSO_ENDPOINT.with(|url| *url.borrow_mut() = None);
                logout.assert_async().await;
                assert_failed_at_sso(&logged_out, None);
                assert!(!session.exists(), "the unreadable session must still be deleted");
                assert!(log.text().contains("operation=\"credential/logout\""), "{}", log.text());
            }));
        }
    }

    /// An unauthorized caller of the credential-addressed `credential/logout` gets the
    /// credential-addressed miss, the same as a name it does not hold (Requirement 8 AC 7).
    #[tokio::test]
    async fn an_unauthorized_logout_misses_as_credential_not_found() {
        for auth in [
            CallerAuth::Denied(DenyReason::NoRoot),
            CallerAuth::Denied(DenyReason::NoPeerCred),
            CallerAuth::Denied(DenyReason::OwnerMismatch),
            CallerAuth::Denied(DenyReason::UnknownUid),
        ] {
            let response = dispatch_uds(&logout_request("work"), &peer(auth)).await;
            assert_eq!(
                domain_code(&response),
                Some(DomainCode::CredentialNotFound),
                "{response:?}"
            );
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(16))]

        /// `credential/remove` is credential-addressed: a name the caller does not hold and a
        /// caller that fails the access check get the same answer, `CREDENTIAL_NOT_FOUND`, so a
        /// removal cannot probe whether a credential exists, and nothing is removed (Requirement
        /// 8 AC 7-8, Requirement 15 AC 4).
        #[test]
        fn every_credential_remove_miss_is_one_code_and_one_message(
            missing in "[a-z][a-z0-9._-]{0,15}",
        ) {
            proptest::prop_assume!(missing != "work");
            tokio::runtime::Runtime::new().unwrap().block_on(with_logout_fixture(
                |daemon, _log| async move {
                    seed_human_credential("work");
                    let remove = |name: &str| {
                        Request::with_params(
                            Id::from(1),
                            METHOD_CREDENTIAL_REMOVE,
                            &CredentialRemoveParams { credential: name.into() },
                        )
                        .expect("object params")
                    };
                    let unknown =
                        dispatch(&remove(&missing), Carrier::Uds, &peer(authorized()), &daemon)
                            .await;
                    assert_eq!(domain_code(&unknown), Some(DomainCode::CredentialNotFound));
                    for auth in [
                        CallerAuth::Denied(DenyReason::NoRoot),
                        CallerAuth::Denied(DenyReason::NoPeerCred),
                        CallerAuth::Denied(DenyReason::OwnerMismatch),
                        CallerAuth::Denied(DenyReason::UnknownUid),
                        CallerAuth::Unresolved,
                    ] {
                        let denied =
                            dispatch(&remove("work"), Carrier::Uds, &peer(auth), &daemon).await;
                        assert_eq!(credential_addressed(&denied), credential_addressed(&unknown));
                    }
                    let (_, credentials) =
                        config::DaemonConfig::load_from(&platform::caller_root(TEST_UID))
                            .expect("load");
                    assert!(credentials.contains_key("work"), "a miss removed nothing");
                },
            ));
        }
    }

    /// Why a credential-addressed call misses: a caller that fails the access check, or a
    /// name the caller does not hold.
    #[derive(Clone, Debug)]
    enum Miss {
        Denied(DenyReason),
        Unresolved,
        Peerless,
        UnknownName,
    }

    /// Call a credential-addressed method the way `serve_connection` routes it: bootstrap and
    /// login through their streaming handlers, every other method through `dispatch`.
    async fn call_credential_addressed(
        method: &str,
        credential: &str,
        peer: &PeerInfo,
        daemon: &Daemon,
    ) -> Response<Value> {
        let request = Request::with_params(
            Id::from(1),
            method,
            &serde_json::json!({ "credential": credential }),
        )
        .expect("object params");
        let (notif_tx, _notif_rx) = tokio::sync::mpsc::channel(8);
        let respond_slot = crate::server::bootstrap::RespondSlot::default();
        let outcome = match method {
            METHOD_CREDENTIAL_BOOTSTRAP => {
                crate::server::bootstrap::handle_profile_bootstrap(
                    &request,
                    peer,
                    daemon,
                    notif_tx,
                    respond_slot,
                )
                .await
            }
            METHOD_CREDENTIAL_LOGIN => {
                crate::server::bootstrap::handle_profile_login(
                    &request,
                    peer,
                    daemon,
                    notif_tx,
                    respond_slot,
                )
                .await
            }
            _ => return dispatch(&request, Carrier::Uds, peer, daemon).await,
        };
        match outcome {
            Ok(value) => Response::success(Id::from(1), value),
            Err(error) => Response::failure(Id::from(1), error),
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(8))]

        /// Every credential-addressed method answers every miss with the one response a name the
        /// caller does not hold gets: `CREDENTIAL_NOT_FOUND`, one message, so no method
        /// distinguishes an unauthorized caller from an absent credential (Requirement 8 AC 3-4,
        /// 7; Requirement 15 AC 10). Bootstrap and import create the credential they name, so an
        /// unknown name is not a miss for them, and a first-time caller (`NoRoot`) with a uid is
        /// provisioned rather than refused (Requirement 2.7).
        #[test]
        fn every_credential_addressed_method_misses_with_one_response(
            missing in "[a-z][a-z0-9._-]{0,15}",
        ) {
            proptest::prop_assume!(missing != "work");
            tokio::runtime::Runtime::new().unwrap().block_on(with_logout_fixture(
                |daemon, _log| async move {
                    seed_human_credential("work");
                    pin_on_disk(&daemon);
                    let reference = credential_addressed(
                        &dispatch(
                            &name_only_request(&missing),
                            Carrier::Uds,
                            &peer(authorized()),
                            &daemon,
                        )
                        .await,
                    );
                    let methods = [
                        (METHOD_CREDENTIAL_GET, false),
                        (METHOD_CREDENTIAL_LOGOUT, false),
                        (METHOD_CREDENTIAL_REMOVE, false),
                        (METHOD_CREDENTIAL_LOGIN, false),
                        (METHOD_CREDENTIAL_BOOTSTRAP, true),
                        (METHOD_CREDENTIAL_IMPORT, true),
                    ];
                    let misses = [
                        Miss::Denied(DenyReason::NoRoot),
                        Miss::Denied(DenyReason::NoPeerCred),
                        Miss::Denied(DenyReason::OwnerMismatch),
                        Miss::Denied(DenyReason::UnknownUid),
                        Miss::Unresolved,
                        Miss::Peerless,
                        Miss::UnknownName,
                    ];
                    for (method, creates) in methods {
                        for miss in misses.clone() {
                            let (caller, name) = match miss {
                                Miss::Denied(DenyReason::NoRoot) | Miss::UnknownName if creates => {
                                    continue
                                }
                                Miss::Denied(ref reason) => (peer(CallerAuth::Denied(reason.clone())), "work"),
                                Miss::Unresolved => (peer(CallerAuth::Unresolved), "work"),
                                Miss::Peerless => (
                                    PeerInfo {
                                        uid: None,
                                        pid: None,
                                        auth: CallerAuth::Denied(DenyReason::NoPeerCred),
                                        executable: None,
                                        login_uid: None,
                                    },
                                    "work",
                                ),
                                Miss::UnknownName => (peer(authorized()), missing.as_str()),
                            };
                            let response =
                                call_credential_addressed(method, name, &caller, &daemon).await;
                            assert_eq!(
                                credential_addressed(&response),
                                reference,
                                "{method} {miss:?}"
                            );
                        }
                    }
                },
            ));
        }
    }
}
