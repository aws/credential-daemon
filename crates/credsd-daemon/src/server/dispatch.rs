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
//! any store lookup and receives `ENVIRONMENT_NOT_FOUND`, indistinguishable from an absent
//! subject (Requirement 8 AC 3-4). The distinct deny reasons survive only in the audit
//! record, exactly as they did over HTTP.

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
use credsd_core::providers::ReauthInput;
use credsd_core::rpc::{
    Claim, ConfigGetParams, ConfigGetResult, ConfigSetParams, ConfigUnsetParams, CredentialEntry,
    CredentialRemoveParams, CredentialResult, CredentialSourceType, CredentialSummary,
    CredentialType, DescribeParams, DomainCode, EnvRemoveParams, GetBatchParams, GetBatchResult,
    GetParams, HealthResult, ListParams, ListResult, Material, OkResult, ProfileManifest,
    Projection, Provenance, Request, Response, RpcError, SessionStatus, METHOD_CONFIG_GET,
    METHOD_CONFIG_SET, METHOD_CONFIG_UNSET, METHOD_CREDENTIAL_GET, METHOD_CREDENTIAL_GET_BATCH,
    METHOD_CREDENTIAL_LIST, METHOD_CREDENTIAL_REMOVE, METHOD_ENV_REMOVE, METHOD_FILE_REVALIDATE,
    METHOD_PROFILE_BOOTSTRAP, METHOD_PROFILE_DESCRIBE, METHOD_PROFILE_IMPORT, METHOD_PROFILE_LOGIN,
    METHOD_SYSTEM_HEALTH,
};

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
        let parsed = DaemonConfig::parse_from(&caller_root);
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
        let (config, credentials) = match parsed {
            Ok((config, credentials)) => match config.validate(&credentials) {
                Ok(()) => (config, credentials),
                Err(errors) => {
                    tracing::warn!(
                        uid,
                        errors = %errors.join("; "),
                        "caller config does not validate; serving nothing until it is fixed"
                    );
                    Default::default()
                }
            },
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
            &config,
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
            sources,
            refresh,
            config_drift,
            credentials_drift,
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
            // Stamp from the daemon's own caller root so the injected state reads as fresh.
            // It must be the root this daemon serves: stamping a globally resolved path would
            // pin the daemon to whatever tree a concurrent case had left in `CREDSD_DATA_DIR`,
            // and a write there would make the first `caller_state` call discard this store and
            // reload, throwing away the credentials just injected.
            sources: SourceStamps::sample(&daemon.caller_root(uid)),
            refresh: None,
            config_drift: DriftStatus::Valid { hash: [0u8; 32] },
            credentials_drift: DriftStatus::Valid { hash: [0u8; 32] },
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
            METHOD_CREDENTIAL_GET_BATCH => Some(Self::GetBatch),
            METHOD_CREDENTIAL_LIST => Some(Self::List),
            METHOD_PROFILE_DESCRIBE => Some(Self::Describe),
            METHOD_SYSTEM_HEALTH => Some(Self::Health),
            METHOD_CONFIG_SET => Some(Self::ConfigSet),
            METHOD_CONFIG_GET => Some(Self::ConfigGet),
            METHOD_CONFIG_UNSET => Some(Self::ConfigUnset),
            METHOD_CREDENTIAL_REMOVE => Some(Self::CredentialRemove),
            METHOD_ENV_REMOVE => Some(Self::EnvRemove),
            METHOD_FILE_REVALIDATE => Some(Self::FileRevalidate),
            METHOD_PROFILE_BOOTSTRAP => Some(Self::ProfileBootstrap),
            METHOD_PROFILE_LOGIN => Some(Self::ProfileLogin),
            METHOD_PROFILE_IMPORT => Some(Self::ProfileImport),
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
            Self::CredentialRemove => Self::EnvRemove,
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
fn exposed(method: Method, carrier: Carrier) -> bool {
    match (method, carrier) {
        // Material — Unix socket only, never a model-facing carrier.
        (Method::Get, Carrier::Uds) => true,
        (Method::Get, Carrier::Stdio) => false,
        (Method::GetBatch, Carrier::Uds) => true,
        (Method::GetBatch, Carrier::Stdio) => false,
        // Enumeration — no material; the one retrieval-adjacent method a model may reach.
        (Method::List, Carrier::Uds) => true,
        (Method::List, Carrier::Stdio) => true,
        // Manifest — no material, but carries projection inputs a model has no use for.
        (Method::Describe, Carrier::Uds) => true,
        (Method::Describe, Carrier::Stdio) => false,
        // Liveness — no material, no config.
        (Method::Health, Carrier::Uds) => true,
        (Method::Health, Carrier::Stdio) => true,
        // Mutation — UDS only; a model has no need to write config.
        (Method::ConfigSet, Carrier::Uds) => true,
        (Method::ConfigSet, Carrier::Stdio) => false,
        (Method::ConfigGet, Carrier::Uds) => true,
        (Method::ConfigGet, Carrier::Stdio) => false,
        (Method::ConfigUnset, Carrier::Uds) => true,
        (Method::ConfigUnset, Carrier::Stdio) => false,
        (Method::CredentialRemove, Carrier::Uds) => true,
        (Method::CredentialRemove, Carrier::Stdio) => false,
        (Method::EnvRemove, Carrier::Uds) => true,
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
        Method::GetBatch => get_batch(request, peer, daemon).await,
        Method::List => list(request, peer, daemon),
        Method::Describe => describe(request, peer, daemon),
        Method::ConfigSet => config_set(request, peer, daemon).await,
        Method::ConfigGet => config_get(request, peer),
        Method::ConfigUnset => config_unset(request, peer, daemon).await,
        Method::CredentialRemove => credential_remove(request, peer, daemon).await,
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
    let uid = authorized_uid(peer)?;
    let caller = daemon.caller_state(uid);
    assess_config(&caller.config, peer, &params.environment, params.claim);
    if let Some(refusal) = serve_refusal(daemon, uid, &caller, &params.environment) {
        return Err(refusal);
    }

    let env = caller
        .config
        .envs
        .get(&params.environment)
        .ok_or_else(not_found)?;
    // Absent `credential` is the profile's default; the store resolves that via `get`. A named
    // `credential` is honored only when the profile actually reaches it — anything else fails as
    // not-found, indistinguishable from absent (Requirement 8 AC 4). This is the Open Decision 1
    // guard: while boundary application is deferred, the daemon must not honor an arbitrary
    // credential unrestricted.
    let (credential, lookup) = match params.credential.as_deref() {
        None => {
            let name = env.default_credential(&params.environment);
            (name, caller.store.get(uid, &params.environment).await)
        }
        Some(c)
            if env
                .credential_list(&params.environment)
                .iter()
                .any(|m| m == c) =>
        {
            (c.to_owned(), caller.store.get_credential(uid, c).await)
        }
        Some(_) => return Err(not_found()),
    };
    to_value(lookup_to_result(credential, lookup, &params.environment)?)
}

async fn get_batch(request: &Request, peer: &PeerInfo, daemon: &Daemon) -> Result<Value, RpcError> {
    let params: GetBatchParams = request.params_as()?;
    let uid = authorized_uid(peer)?;
    let caller = daemon.caller_state(uid);
    assess_config(&caller.config, peer, &params.environment, params.claim);
    if let Some(refusal) = serve_refusal(daemon, uid, &caller, &params.environment) {
        return Err(refusal);
    }

    let env = caller
        .config
        .envs
        .get(&params.environment)
        .ok_or_else(not_found)?;
    let members = env.credential_list(&params.environment);
    // All-or-none: any member failure returns one error and no material. `?` drops every
    // `CredentialResult` collected so far, and each zeroizes its material on drop.
    let mut credentials = Vec::with_capacity(members.len());
    for credential in members {
        let lookup = caller.store.get_credential(uid, &credential).await;
        credentials.push(lookup_to_result(credential, lookup, &params.environment)?);
    }
    to_value(GetBatchResult { credentials })
}

fn list(request: &Request, peer: &PeerInfo, daemon: &Daemon) -> Result<Value, RpcError> {
    let params: ListParams = request.params_as()?;
    let Some(uid) = enumerating_uid(peer)? else {
        // A caller with nothing provisioned has an empty list, not an error. Whether
        // `callers/<uid>/` exists is the daemon's business, and a first run should print
        // "no envs configured" rather than a failure the user has to interpret.
        return to_value(ListResult {
            credentials: Vec::new(),
        });
    };
    let caller = daemon.caller_state(uid);
    assess_config(
        &caller.config,
        peer,
        params.environment.as_deref().unwrap_or("*"),
        None,
    );

    let mut credentials = Vec::new();
    for (profile, env) in &caller.config.envs {
        if params
            .environment
            .as_deref()
            .is_some_and(|filter| filter != profile)
        {
            continue;
        }
        for credential in env.credential_list(profile) {
            credentials.push(CredentialSummary {
                environment: profile.clone(),
                kind: SHIPPED_KIND,
                status: status_of(
                    uid,
                    &daemon.encryption,
                    &credential,
                    caller.credentials.get(&credential),
                ),
                credential,
            });
        }
    }
    to_value(ListResult { credentials })
}

fn describe(request: &Request, peer: &PeerInfo, daemon: &Daemon) -> Result<Value, RpcError> {
    let params: DescribeParams = request.params_as()?;
    let uid = authorized_uid(peer)?;
    let caller = daemon.caller_state(uid);
    assess_config(&caller.config, peer, &params.environment, None);

    let env = caller
        .config
        .envs
        .get(&params.environment)
        .ok_or_else(not_found)?;
    let default = env.default_credential(&params.environment);
    let credentials = env
        .credential_list(&params.environment)
        .into_iter()
        .map(|credential| {
            // A credential an env references but `credentials.toml` does not define reports as
            // `Unsupported` rather than erroring: the manifest still describes the env, and the
            // client's materialization refuses that entry with a message naming it.
            let source = caller.credentials.get(&credential);
            CredentialEntry {
                default: credential == default,
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
    environment: &str,
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
            Err(RpcError::reauth_required(
                environment,
                format!("env '{environment}' requires re-authentication ({detail})"),
                format!("credsd login --environment {environment}"),
            ))
        }
        Lookup::Unavailable(cause) => Err(RpcError::domain(
            DomainCode::ProviderUnavailable,
            format!("env '{environment}' credential unavailable: {cause}"),
        )),
        Lookup::Unknown => Err(not_found()),
    }
}

/// Emit the caller-assessment audit record, exactly as the HTTP `assess` did — before the
/// authorization gate, so a denied caller and a miss both leave a full audit line.
fn assess_config(config: &DaemonConfig, peer: &PeerInfo, env: &str, claim: Option<Claim>) {
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
    RpcError::domain(
        DomainCode::EnvironmentNotFound,
        "profile or credential not found",
    )
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
    environment: &str,
) -> Option<RpcError> {
    if let Err(reason) = daemon.integrity.verify_custody() {
        return Some(custody_broken(&reason));
    }
    let (name, status) = [
        (CONFIG, &caller.config_drift),
        (CREDENTIALS, &caller.credentials_drift),
    ]
    .into_iter()
    .find(|(_, status)| !status.is_valid())?;
    tracing::info!(
        event = "drift.refused",
        uid,
        environment,
        file = name,
        drift = ?status,
        "credential refused: a load-bearing file is not verified"
    );
    Some(match status {
        DriftStatus::Unverifiable => unverifiable("see the daemon log"),
        _ if name == CONFIG => RpcError::domain(
            DomainCode::ConfigDrifted,
            format!(
                "environment '{environment}' configuration has drifted from its sealed snapshot; \
                 run: creds revalidate"
            ),
        ),
        _ => RpcError::domain(
            DomainCode::ConfigDrifted,
            format!(
                "environment '{environment}' credential sources (credentials.toml) have drifted \
                 from their sealed snapshot; run: creds revalidate"
            ),
        ),
    })
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
        return Err(internal(errors.join("\n")));
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
        Op::Import { environments, .. } => {
            let names: Vec<&str> = environments.iter().map(String::as_str).collect();
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
        Op::Bootstrap {
            environment,
            credential,
            ..
        } => {
            daemon.presence.authorize(pending);
            format!(
                "authorized a bootstrap of credential '{credential}' (environment \
                 '{environment}') for uid {owner}; re-run the same bootstrap within 5 minutes \
                 to apply it"
            )
        }
        Op::ConfigUnset {
            environment, key, ..
        } => {
            apply_config_unset(held, owner, environment, key, files, daemon)?;
            format!("unset {key} on environment '{environment}' for uid {owner}")
        }
        Op::Import { environments, .. } => {
            daemon.presence.authorize(pending);
            format!(
                "authorized an import binding {} for uid {owner}; re-run the same import within \
                 5 minutes to apply it",
                environments.join(", ")
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
    let uid = authorized_uid(peer)?;
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
        return Err(not_found());
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
    let sources = credsd_core::config::credentials::parse_sources(text)?;
    let rel = std::path::Path::new("callers")
        .join(uid.to_string())
        .join("credentials.toml");
    credsd_core::config::snapshot::canonical_credentials(uid, &rel, &sources)
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
        env.credential_list(&params.environment).join(", ")
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
            config.envs.insert(name.to_string(), EnvConfig::default());
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
                }),
            );
        }

        let store = Arc::new(CredentialStore::new(
            TEST_UID,
            &config,
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
                environment: profile.into(),
                credential: credential.map(String::from),
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
        assert_eq!(
            domain_code(&response),
            Some(DomainCode::EnvironmentNotFound)
        );
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
        assert_eq!(data["environment"], "needs-reauth");
        assert!(data["remediation"]
            .as_str()
            .unwrap()
            .contains("credsd login"));
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
        assert_eq!(
            domain_code(&response),
            Some(DomainCode::EnvironmentNotFound)
        );
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
                Some(DomainCode::EnvironmentNotFound),
                "an unauthorized caller must not distinguish a real env from an absent one"
            );
        }
    }

    #[tokio::test]
    async fn get_batch_returns_every_credential_the_profile_names() {
        let request = Request::with_params(
            Id::from(1),
            METHOD_CREDENTIAL_GET_BATCH,
            &GetBatchParams {
                environment: "dev".into(),
                scope: None,
                claim: None,
                request_id: None,
            },
        )
        .expect("object params");
        let response = dispatch_uds(&request, &peer(authorized())).await;
        let Outcome::Result(value) = response.outcome else {
            panic!("expected a result");
        };
        assert_eq!(value["credentials"][0]["credential"], "dev");
        assert_eq!(
            value["credentials"][0]["material"]["access_key_id"],
            "AKIAIOSFODNN7EXAMPLE"
        );
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
        // No entry carries material.
        for entry in value["credentials"].as_array().unwrap() {
            assert!(entry.get("material").is_none());
            assert!(
                entry.get("source").is_none(),
                "list is capped at name/kind/status"
            );
        }
    }

    #[tokio::test]
    async fn describe_returns_a_manifest_with_projection_and_no_material() {
        let mut config = DaemonConfig::default();
        config.envs.insert(
            "dev".to_string(),
            EnvConfig {
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
            }),
        );
        let key = credsd_core::encryption::generate_key().unwrap();
        let encryption = Arc::new(credsd_core::encryption::EncryptionService::new(key).unwrap());
        let store = Arc::new(CredentialStore::new(
            TEST_UID,
            &config,
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
        let Outcome::Result(value) = response.outcome else {
            panic!("expected a result");
        };
        assert_eq!(value["environment"], "dev");
        assert_eq!(value["projection"]["region"], "eu-central-1");
        let entry = &value["credentials"][0];
        assert_eq!(entry["credential"], "dev");
        assert_eq!(entry["source"], "aws_idc_sso");
        assert_eq!(entry["default"], true);
        assert!(entry.get("material").is_none());
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
                Some(DomainCode::EnvironmentNotFound),
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
            }),
        )
        .expect("seed credential entry");
    }
}
