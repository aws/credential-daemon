//! In-memory credential cache with background provider refresh.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use credsd_core::log::escape_log;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::credentials::{CredentialSource, CredentialSources};
use crate::config::platform::caller_root;
use crate::config::DaemonConfig;
use crate::credentials::Credentials;
use crate::encryption::EncryptionService;
use crate::providers::aws_login::AwsLoginProvider;
use crate::providers::client_credentials::ClientCredentialsProvider;
use crate::providers::iam_user::SessionTokenProvider;
#[cfg(feature = "jwt-bearer")]
use crate::providers::jwt_bearer::JwtBearerProvider;
use crate::providers::oauth::AwsWebIdentityProvider;
use crate::providers::roles_anywhere::RolesAnywhereProvider;
use crate::providers::sso::SsoProvider;
use crate::providers::{CredentialProvider, ReauthInput, Renewed, Renewer};

/// Outcome of a credential lookup, so the HTTP layer can tell three cases apart instead of
/// collapsing them to one 404: creds to serve, a re-auth the user must run, or an env the
/// daemon knows nothing about (also the terminal state of a transient renewal failure with no
/// valid cache to fall back on).
///
/// `ReauthRequired` carries the provider-declared [`ReauthInput`] — what the user must supply
/// to re-authenticate — so a consumer can prompt without knowing the provider.
pub enum Lookup {
    Ready(Credentials),
    ReauthRequired(ReauthInput),
    /// Renewal failed with a real error and no valid cache remains — the credential is
    /// configured but temporarily unavailable (expired/rejected Roles Anywhere cert, SSO/STS
    /// AccessDenied, throttling, network). The `String` is the provider's cause, surfaced to
    /// the caller so a failure reads as its actual reason, not as a missing env. Every
    /// provider reaches this the same way: a `renew()` that returns `Err`.
    Unavailable(String),
    Unknown,
}

#[cfg(test)]
impl Lookup {
    fn is_ready(&self) -> bool {
        matches!(self, Lookup::Ready(_))
    }
    fn is_reauth(&self) -> bool {
        matches!(self, Lookup::ReauthRequired(_))
    }
    fn is_unknown(&self) -> bool {
        matches!(self, Lookup::Unknown)
    }
}

/// In-memory credential cache with background refresh from configured providers.
///
/// Providers and cache entries are keyed by *credential* (the `credentials.toml` entry), not
/// by env, so envs sharing a credential share one provider, one cache entry, and one refresh
/// timer. A credential is the addressable atom: a provider is built for **every** defined
/// credential, so an ad-hoc request (`credsd get --credential X`, or an inline `exec
/// --credential X`) resolves any credential, not only those a configured env references.
///
/// Two lookup keys: by env name (`get`, which resolves the env's default/first credential —
/// what the container endpoint carries) and by credential name (`get_credential`, what
/// `credential_process` invocations and ad-hoc composition carry).
pub struct CredentialStore {
    /// Keyed by `(caller uid, credential name)`, not by name alone: the cache is partitioned
    /// per caller so a serve-time lookup is impossible without a kernel-verified caller
    /// dimension. In single-user runs there is exactly one uid, so this collapses to the
    /// previous one-entry-per-credential behavior.
    cache: Arc<RwLock<HashMap<(u32, String), Credentials>>>,
    /// One turn lock per `(uid, credential)`, so concurrent renewals of a credential queue
    /// rather than racing on its rotating refresh token. See `renew_single_flight`.
    renew_turns: std::sync::Mutex<RenewTurns>,
    providers: Arc<HashMap<String, Box<dyn CredentialProvider>>>,
    env_to_credentials: Arc<HashMap<String, Vec<String>>>,
    /// Credentials any configured env references — the set warmed by the background loop.
    /// Ad-hoc-only credentials (built as providers but referenced by no env) are refreshed
    /// only once fetched on demand, so an unused credential costs no refresh traffic.
    warm_set: Arc<std::collections::HashSet<String>>,
    /// This caller's bootstrap/login write lock — the same one `commit_bootstrap` and
    /// `profile/import` take. A background or on-demand renewal writes sealed material into the
    /// same per-credential directory a staged bootstrap installs into; without sharing this lock
    /// the two can interleave and leave a newer config pointing at an older renewal's bytes, or
    /// vice versa.
    bootstrap_lock: Arc<tokio::sync::Mutex<()>>,
    /// Run under `bootstrap_lock` before every renewal, since a renewal seals material the
    /// caller's records name (drift-detection Requirement 5.8).
    records_check: RecordsCheck,
}

/// The shared drift check for a caller uid, as a renewal runs it; `Err` says why the records are
/// not verified.
/// Takes the proof of the write lock, so it can only run inside the hold the renewal seals under.
pub type RecordsCheck =
    Arc<dyn Fn(&crate::server::write_lock::Held<'_>, u32) -> Result<(), String> + Send + Sync>;

/// A check that always passes, for stores whose records the test does not provision.
#[cfg(test)]
pub(crate) fn records_verified() -> RecordsCheck {
    Arc::new(|_, _| Ok(()))
}

type RenewTurns = HashMap<(u32, String), Arc<tokio::sync::Mutex<()>>>;

/// A renewal's claim on the caller's write lock.
///
/// The wait is the bound `credsd_core::rpc::uds::call_blocking` uses for "the daemon accepted the
/// connection but is taking too long": `get_by_credential` is on the serving path, and a login can
/// hold this lock for its whole interactive step, so a renewal queued behind one gives up on that
/// budget and falls through to its cache/reauth/failure precedence rather than parking the caller.
///
/// The hold allows two HTTP round trips at the 30-second per-request ceiling the provider clients
/// set, which is the shape of every unattended renewal (refresh grant, then credential exchange).
/// Past that the request is not going to answer, and the writers queued behind it should not keep
/// waiting on it.
#[cfg(not(test))]
const RENEWAL_LOCK_BUDGET: crate::server::write_lock::Budget = crate::server::write_lock::Budget {
    wait: std::time::Duration::from_secs(10),
    hold: std::time::Duration::from_secs(60),
};
/// Shorter under test so both bounds are reachable without a minute-long test. Same code path.
#[cfg(test)]
const RENEWAL_LOCK_BUDGET: crate::server::write_lock::Budget = crate::server::write_lock::Budget {
    wait: std::time::Duration::from_millis(50),
    hold: std::time::Duration::from_millis(250),
};

/// A cached credential may be served only with a minute of margin, so it does not expire in the
/// caller's hands. No stated expiry means it cannot go stale.
fn servable(creds: &Credentials) -> bool {
    creds
        .expires_at
        .is_none_or(|at| at.signed_duration_since(Utc::now()).num_seconds() > 60)
}

impl CredentialStore {
    pub fn new(
        uid: u32,
        config: &DaemonConfig,
        credentials: &CredentialSources,
        encryption: Arc<EncryptionService>,
        bootstrap_lock: Arc<tokio::sync::Mutex<()>>,
        records_check: RecordsCheck,
    ) -> Self {
        let mut providers: HashMap<String, Box<dyn CredentialProvider>> = HashMap::new();
        let mut env_to_credentials: HashMap<String, Vec<String>> = HashMap::new();
        let mut warm_set: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (env_name, env) in &config.envs {
            let creds = env.credential_list(env_name);
            for c in &creds {
                warm_set.insert(c.clone());
            }
            env_to_credentials.insert(env_name.clone(), creds);
        }

        // Build a provider for every DEFINED credential (not just env-referenced ones), so
        // ad-hoc composition can address any credential. Unused ones cost a struct, not
        // traffic — the background loop only warms `warm_set`.
        for (credential_name, source) in credentials {
            let credential_name = credential_name.clone();
            match source {
                CredentialSource::AwsIdcSso(sso_cfg) => {
                    let provider = SsoProvider::new(
                        credential_name.clone(),
                        sso_cfg.clone(),
                        encryption.clone(),
                        caller_root(uid).join("credentials").join(&credential_name),
                    );
                    providers.insert(credential_name, Box::new(provider));
                }
                CredentialSource::StaticSecret(cfg) => {
                    let provider = credsd_core::providers::static_secret::StaticSecretProvider::new(
                        credential_name.clone(),
                        cfg.clone(),
                        encryption.clone(),
                        caller_root(uid).join("credentials").join(&credential_name),
                    );
                    providers.insert(credential_name, Box::new(provider));
                }
                CredentialSource::AwsIamUser(cfg) => {
                    let provider = SessionTokenProvider::new(
                        credential_name.clone(),
                        cfg.clone(),
                        encryption.clone(),
                        caller_root(uid).join("credentials").join(&credential_name),
                    );
                    providers.insert(credential_name, Box::new(provider));
                }
                CredentialSource::AwsRolesAnywhere(cfg) => {
                    let provider = RolesAnywhereProvider::new(
                        credential_name.clone(),
                        cfg.clone(),
                        encryption.clone(),
                        caller_root(uid).join("credentials").join(&credential_name),
                    );
                    providers.insert(credential_name, Box::new(provider));
                }
                CredentialSource::AwsWebIdentity(cfg) => {
                    match AwsWebIdentityProvider::new(
                        credential_name.clone(),
                        cfg.clone(),
                        encryption.clone(),
                        caller_root(uid).join("credentials").join(&credential_name),
                    ) {
                        Ok(provider) => {
                            providers.insert(credential_name, Box::new(provider));
                        }
                        Err(e) => {
                            tracing::error!(
                                credential = %credential_name,
                                error = %e,
                                "failed to build HTTP client; credential will be unavailable"
                            );
                        }
                    }
                }
                CredentialSource::AwsLogin(cfg) => {
                    match AwsLoginProvider::new(
                        credential_name.clone(),
                        cfg.clone(),
                        encryption.clone(),
                        caller_root(uid).join("credentials").join(&credential_name),
                    ) {
                        Ok(provider) => {
                            providers.insert(credential_name, Box::new(provider));
                        }
                        Err(e) => {
                            tracing::error!(
                                credential = %credential_name,
                                error = %e,
                                "failed to build HTTP client; credential will be unavailable"
                            );
                        }
                    }
                }
                CredentialSource::Jwt(cfg) => {
                    let provider = credsd_core::providers::jwt::JwtProvider::new(
                        credential_name.clone(),
                        cfg.clone(),
                        encryption.clone(),
                        caller_root(uid).join("credentials").join(&credential_name),
                    );
                    providers.insert(credential_name, Box::new(provider));
                }
                CredentialSource::Oauth(cfg) => {
                    let data_dir = caller_root(uid).join("credentials").join(&credential_name);
                    match ClientCredentialsProvider::new(
                        credential_name.clone(),
                        cfg.clone(),
                        data_dir,
                        encryption.clone(),
                    ) {
                        Ok(provider) => {
                            providers.insert(credential_name, Box::new(provider));
                        }
                        Err(e) => {
                            warn!(credential = %credential_name, error = %escape_log(&e), "cannot build OAuth client, skipping")
                        }
                    }
                }
                #[cfg(feature = "jwt-bearer")]
                CredentialSource::JwtBearer(cfg) => {
                    let data_dir = caller_root(uid).join("credentials").join(&credential_name);
                    match JwtBearerProvider::new(cfg.clone(), encryption.clone(), data_dir) {
                        Ok(provider) => {
                            warn!(credential = %credential_name, "jwt-bearer is experimental and subject to change");
                            providers.insert(credential_name, Box::new(provider));
                        }
                        Err(e) => {
                            warn!(credential = %credential_name, error = %escape_log(&e), "cannot build JWT bearer client, skipping")
                        }
                    }
                }
                #[cfg(not(feature = "jwt-bearer"))]
                CredentialSource::JwtBearer(_) => {
                    warn!(credential = %credential_name, "JWT bearer is not in this build, skipping");
                }
                CredentialSource::Unsupported => {
                    info!(credential = %credential_name, "credential source not yet implemented, skipping");
                }
            }
        }

        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            renew_turns: std::sync::Mutex::new(HashMap::new()),
            providers: Arc::new(providers),
            env_to_credentials: Arc::new(env_to_credentials),
            warm_set: Arc::new(warm_set),
            bootstrap_lock,
            records_check,
        }
    }

    /// Resolve an env to its **default** (first) credential — the ambient identity the
    /// container endpoint serves. Named credentials within the env are fetched individually
    /// via [`CredentialStore::get_credential`].
    pub async fn get(&self, uid: u32, env: &str) -> Lookup {
        match self.env_to_credentials.get(env).and_then(|c| c.first()) {
            Some(credential) => self.get_by_credential(uid, credential).await,
            None => Lookup::Unknown,
        }
    }

    /// Resolve a single credential by name, independent of any env. This is what
    /// `credential_process` (`credsd get --credential X`) and ad-hoc composition carry.
    pub async fn get_credential(&self, uid: u32, credential: &str) -> Lookup {
        self.get_by_credential(uid, credential).await
    }

    /// Renew `key` if `due` says the cached entry (or its absence) needs it. Callers queue on a
    /// per-credential lock and `due` is checked again once each holds it, so a caller queued
    /// behind a renewal reuses that entry instead of spending the rotating refresh token again.
    /// `None` means the entry was already fresh enough by the time the lock was taken.
    async fn renew_single_flight(
        &self,
        key: &(u32, String),
        renewer: &dyn Renewer,
        due: impl Fn(Option<&Credentials>) -> bool,
    ) -> crate::error::Result<Option<Renewed>> {
        let turn = {
            let mut turns = self.renew_turns.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(turns.entry(key.clone()).or_default())
        };
        let _turn = turn.lock().await;

        if !due(self.cache.read().await.get(key)) {
            return Ok(None);
        }
        // Renewal writes into the same per-credential directory a staged bootstrap installs
        // into, so it runs under the same per-uid lock `commit_bootstrap` takes — otherwise a
        // renewal can land mid-install and leave config pointing at one provider's material
        // while an older or newer provider's bytes are sealed under it. Bounded on both sides by
        // `RENEWAL_LOCK_BUDGET`; the error is the provider cause `get_by_credential` already
        // routes to its cache/reauth/`Unavailable` precedence. The drift check runs inside the
        // hold, so a hand-edit landing after this state loaded is refused before anything seals.
        let renewed = crate::server::write_lock::under(
            &self.bootstrap_lock,
            key.0,
            RENEWAL_LOCK_BUDGET,
            async |held| {
                (self.records_check)(&held, key.0).map_err(|reason| {
                    crate::error::DaemonError::provider(format!(
                        "renewal refused: the credential records are not verified: {reason}"
                    ))
                })?;
                renewer.renew().await
            },
        )
        .await
        .map_err(|expired| {
            crate::error::DaemonError::provider(format!(
                "renewal deferred: {} ({}s)",
                match expired {
                    crate::server::write_lock::Expired::Wait =>
                        "a bootstrap, import, or login for this user is in progress",
                    crate::server::write_lock::Expired::Hold => "the provider did not answer",
                },
                expired.limit(RENEWAL_LOCK_BUDGET).as_secs(),
            ))
        })??;
        if let Renewed::Ready(creds) = &renewed {
            self.cache.write().await.insert(key.clone(), creds.clone());
        }
        Ok(Some(renewed))
    }

    async fn get_by_credential(&self, uid: u32, credential: &str) -> Lookup {
        let key = (uid, credential.to_string());
        {
            let cache = self.cache.read().await;
            if let Some(creds) = cache.get(&key).filter(|c| servable(c)) {
                return Lookup::Ready(creds.clone());
            }
        }

        // A re-auth-only source (`renewer() == None`) has no unattended renewal, so the
        // daemon can only serve what an earlier interactive setup left in cache. A renewal
        // that returns `ReauthRequired` is remembered so it can surface to the caller if no
        // still-valid cache entry exists; a transient `Err` is logged and left to retry.
        // Either way we never serve an expired entry — that would keep the daemon handing out
        // dead credentials until the next successful renewal.
        let mut reauth: Option<ReauthInput> = None;
        let mut failure: Option<String> = None;
        if let Some(renewer) = self.providers.get(credential).and_then(|p| p.renewer()) {
            match self
                .renew_single_flight(&key, renewer, |c| !c.is_some_and(servable))
                .await
            {
                Ok(Some(Renewed::Ready(creds))) => return Lookup::Ready(creds),
                Ok(Some(Renewed::ReauthRequired(input))) => {
                    warn!(credential = %credential, input = input.kind(), "credential requires re-authentication");
                    reauth = Some(input);
                }
                // Another caller renewed while we queued; the cache check below serves it.
                Ok(None) => {}
                Err(e) => {
                    error!(credential = %credential, error = %escape_log(&e), "credential renewal failed");
                    failure = Some(e.detail());
                }
            }
        }

        {
            let cache = self.cache.read().await;
            if let Some(creds) = cache.get(&key).filter(|c| !c.is_expired()) {
                return Lookup::Ready(creds.clone());
            }
        }

        // Precedence: an actionable re-auth beats a transient failure, which beats "unknown".
        // A hard `renew()` error with no valid cache is `Unavailable(cause)`, not `Unknown`, so
        // the caller sees the real reason instead of a spurious "env not found".
        match (reauth, failure) {
            (Some(input), _) => Lookup::ReauthRequired(input),
            (None, Some(cause)) => Lookup::Unavailable(cause),
            (None, None) => Lookup::Unknown,
        }
    }

    /// Refresh every credential nearing expiry, per provisioned caller. One pass per
    /// `(uid, credential)`, so envs sharing a credential do not each trigger their own
    /// refresh. The cache is partitioned by caller uid, so the warm loop must warm each
    /// provisioned caller's entries: it iterates the union of the uids with a provisioned
    /// caller root and any uid already present in the cache (an on-demand fetch can only
    /// have inserted under an authorized — hence provisioned — uid). In single-user runs
    /// this is exactly one uid, preserving the previous one-entry-per-credential behavior.
    pub async fn refresh_all(&self) {
        let uids = self.refresh_uids().await;
        for uid in uids {
            for (name, provider) in self.providers.as_ref() {
                // Re-auth-only sources have no unattended renewal; the loop leaves them alone.
                let Some(renewer) = provider.renewer() else {
                    continue;
                };
                let key = (uid, name.clone());

                let due = |cached: Option<&Credentials>| match cached {
                    // Already warm: refresh as it nears expiry. Only a stated expiry can be near
                    // one, so a credential without one is never refreshed here.
                    Some(creds) => creds
                        .expires_at
                        .is_some_and(|at| at.signed_duration_since(Utc::now()).num_minutes() <= 15),
                    // Cold: pre-warm only credentials a configured env references. An ad-hoc-only
                    // credential is left cold until first fetched on demand.
                    None => self.warm_set.contains(name),
                };
                match self.renew_single_flight(&key, renewer, due).await {
                    Ok(Some(Renewed::Ready(_))) => {
                        info!(credential = %name, uid = uid, "credentials refreshed");
                    }
                    // Can't renew unattended; leave any still-valid cache entry in place
                    // and wait for an interactive login to re-seed it.
                    Ok(Some(Renewed::ReauthRequired(input))) => {
                        warn!(credential = %name, input = input.kind(), "awaiting re-authentication, skipping");
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!(credential = %name, error = %escape_log(&e), "background refresh failed");
                    }
                }
            }
        }
    }

    /// The uids the warm loop should cover: those with a provisioned caller root, plus any
    /// already present in the cache (warmed by an earlier on-demand fetch).
    async fn refresh_uids(&self) -> std::collections::HashSet<u32> {
        let mut uids: std::collections::HashSet<u32> =
            crate::config::platform::provisioned_caller_uids()
                .into_iter()
                .collect();
        let cache = self.cache.read().await;
        for (uid, _) in cache.keys() {
            uids.insert(*uid);
        }
        uids
    }

    pub fn spawn_refresh_task(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let store = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                store.refresh_all().await;
            }
        })
    }

    /// Seed the cache for a credential. The name is a `credentials.toml` entry, so an env
    /// must resolve to it for `get` to find what this inserts.
    #[cfg(test)]
    pub async fn inject_for_test_async(&self, uid: u32, credential: &str, creds: Credentials) {
        self.cache
            .write()
            .await
            .insert((uid, credential.to_string()), creds);
    }

    #[cfg(test)]
    pub fn inject_for_test(&self, uid: u32, credential: &str, creds: Credentials) {
        // Use try_write for non-async test contexts; fallback to a new runtime.
        // This is only for tests — production code uses the async path.
        if let Ok(mut cache) = self.cache.try_write() {
            cache.insert((uid, credential.to_string()), creds);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credentials::CredentialSource;
    use crate::config::{EnvConfig, SsoConfig};

    /// A fixed caller uid for the store tests. The cache is partitioned by uid, so every
    /// seed/read must agree on one; production supplies the kernel-verified peer uid.
    const TEST_UID: u32 = 501;

    fn store_for(envs: &[(&str, Option<&str>)], credential_names: &[&str]) -> CredentialStore {
        let mut config = DaemonConfig::default();
        for (name, credential) in envs {
            config.envs.insert(
                name.to_string(),
                EnvConfig {
                    credential: credential.map(String::from),
                    ..Default::default()
                },
            );
        }

        let credentials: CredentialSources = credential_names
            .iter()
            .map(|name| {
                (
                    name.to_string(),
                    CredentialSource::AwsIdcSso(SsoConfig {
                        start_url: "https://example.awsapps.com/start".into(),
                        sso_region: "us-east-1".into(),
                        account_id: "111111111111".into(),
                        role_name: "Developer".into(),
                        identity_type: Default::default(),
                    }),
                )
            })
            .collect();

        let key = crate::encryption::generate_key().unwrap();
        let encryption = Arc::new(crate::encryption::EncryptionService::new(key).unwrap());
        CredentialStore::new(
            TEST_UID,
            &config,
            &credentials,
            encryption,
            Arc::new(tokio::sync::Mutex::new(())),
            records_verified(),
        )
    }

    fn session_creds() -> Credentials {
        Credentials::session(
            "AKIAIOSFODNN7EXAMPLE".into(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            "FwoGZXIvYXdzEBY...".into(),
            credsd_core::credentials::expires_in_seconds(3600),
        )
    }

    /// A renewer that counts its calls and yields, so a second caller can queue behind the first.
    struct Counting(Arc<std::sync::atomic::AtomicUsize>);
    #[async_trait::async_trait]
    impl crate::providers::Renewer for Counting {
        async fn renew(&self) -> crate::error::Result<Renewed> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(Renewed::Ready(session_creds()))
        }
    }
    struct CountingProvider(Counting);
    impl CredentialProvider for CountingProvider {
        fn renewer(&self) -> Option<&dyn crate::providers::Renewer> {
            Some(&self.0)
        }
        fn mode_name(&self) -> &'static str {
            "counting"
        }
    }

    /// Concurrent lookups for one credential spend one renewal: the second queues behind the
    /// first and is served the entry it cached. Without the turn lock both would renew, and the
    /// second would rotate away the refresh token the first just used.
    #[tokio::test]
    async fn concurrent_lookups_renew_once() {
        let renewals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = CountingProvider(Counting(Arc::clone(&renewals)));
        let store = store_with_provider("ra", Box::new(provider));
        let (a, b) = tokio::join!(
            store.get_credential(TEST_UID, "ra"),
            store.get_credential(TEST_UID, "ra")
        );
        assert!(a.is_ready() && b.is_ready());
        assert_eq!(renewals.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A renewal shares its uid's bootstrap lock with `commit_bootstrap`/`profile/import`, so a
    /// renewal cannot write while one of those holds it. Without the shared lock a renewal and a
    /// staged install interleave, leaving config pointing at one provider's bytes while a
    /// different provider's material is sealed on disk.
    ///
    /// It gives up on `RENEWAL_LOCK_TIMEOUT` rather than waiting indefinitely: `get_credential`
    /// is on the serving path and a login can hold this lock for its whole interactive step, so
    /// the renewal falls through to the existing cache/reauth/failure precedence — here, with no
    /// cache to fall back on, `Unavailable`. The alternative is a caller stalled for as long as
    /// someone else's device-code entry takes.
    #[tokio::test]
    async fn renewal_defers_rather_than_writing_behind_the_bootstrap_lock() {
        let renewals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = CountingProvider(Counting(Arc::clone(&renewals)));
        let store = store_with_provider("ra", Box::new(provider));
        let held = store.bootstrap_lock.clone().lock_owned().await;

        match store.get_credential(TEST_UID, "ra").await {
            Lookup::Unavailable(cause) => assert!(cause.contains("in progress"), "{cause}"),
            Lookup::Ready(_) => panic!("renewed while the bootstrap lock was held elsewhere"),
            Lookup::ReauthRequired(_) => panic!("a deferred renewal is not a re-auth"),
            Lookup::Unknown => panic!("a deferred renewal must report its cause, not Unknown"),
        }
        assert_eq!(renewals.load(std::sync::atomic::Ordering::SeqCst), 0);

        drop(held);
        let result = store.get_credential(TEST_UID, "ra").await;
        assert!(result.is_ready());
        assert_eq!(renewals.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A renewal whose records no longer verify seals nothing, even though the state it belongs to
    /// loaded verified (drift-detection Requirement 5.8): the check runs per renewal, under the
    /// write lock, not once at load.
    #[tokio::test]
    async fn renewal_is_refused_when_the_records_no_longer_verify() {
        let renewals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = CountingProvider(Counting(Arc::clone(&renewals)));
        let mut store = store_with_provider("ra", Box::new(provider));
        let drifted = Arc::new(std::sync::atomic::AtomicBool::new(true));
        store.records_check = {
            let drifted = Arc::clone(&drifted);
            Arc::new(move |_, _| {
                if drifted.load(std::sync::atomic::Ordering::SeqCst) {
                    Err("config.toml has drifted".to_owned())
                } else {
                    Ok(())
                }
            })
        };

        match store.get_credential(TEST_UID, "ra").await {
            Lookup::Unavailable(cause) => assert!(cause.contains("not verified"), "{cause}"),
            _ => panic!("a renewal over unverified records must report why it did not run"),
        }
        store.refresh_all().await;
        assert_eq!(renewals.load(std::sync::atomic::Ordering::SeqCst), 0);

        drifted.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(store.get_credential(TEST_UID, "ra").await.is_ready());
        assert_eq!(renewals.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A re-auth-only source: no unattended renewal, so `refresher()` yields `None`. Stands in
    /// for a provider whose only path to a new credential is its (interactive) auth process.
    struct ReauthOnly;
    impl CredentialProvider for ReauthOnly {
        fn renewer(&self) -> Option<&dyn crate::providers::Renewer> {
            None
        }
        fn mode_name(&self) -> &'static str {
            "reauth-only"
        }
    }

    /// Build a store around one hand-supplied provider. `store_for` only knows how to build
    /// SSO providers from config; this reaches the private fields directly (same module) to
    /// install an arbitrary provider — the only way to exercise the re-auth-only routing.
    fn store_with_provider(
        credential: &str,
        provider: Box<dyn CredentialProvider>,
    ) -> CredentialStore {
        let mut providers: HashMap<String, Box<dyn CredentialProvider>> = HashMap::new();
        providers.insert(credential.to_string(), provider);
        let mut env_to_credentials = HashMap::new();
        env_to_credentials.insert(credential.to_string(), vec![credential.to_string()]);
        let mut warm_set = std::collections::HashSet::new();
        warm_set.insert(credential.to_string());
        CredentialStore {
            cache: Arc::new(RwLock::new(HashMap::new())),
            renew_turns: std::sync::Mutex::new(HashMap::new()),
            providers: Arc::new(providers),
            env_to_credentials: Arc::new(env_to_credentials),
            warm_set: Arc::new(warm_set),
            bootstrap_lock: Arc::new(tokio::sync::Mutex::new(())),
            records_check: records_verified(),
        }
    }

    /// A renewer whose unattended path is *exhausted* — has the capability but returns a
    /// re-auth challenge each call. Models SSO once its refresh token has died.
    struct Exhausted;
    #[async_trait::async_trait]
    impl crate::providers::Renewer for Exhausted {
        async fn renew(&self) -> crate::error::Result<Renewed> {
            Ok(Renewed::ReauthRequired(
                crate::providers::ReauthInput::Browser,
            ))
        }
    }
    struct ExhaustedProvider;
    impl CredentialProvider for ExhaustedProvider {
        fn renewer(&self) -> Option<&dyn crate::providers::Renewer> {
            Some(&Exhausted)
        }
        fn mode_name(&self) -> &'static str {
            "exhausted"
        }
    }

    /// A renewer that fails with a real error (expired/rejected cert, AccessDenied, throttle).
    /// Every provider reaches the store this way — a `renew()` returning `Err`.
    struct Failing;
    #[async_trait::async_trait]
    impl crate::providers::Renewer for Failing {
        async fn renew(&self) -> crate::error::Result<Renewed> {
            Err(crate::error::DaemonError::provider(
                "roles-anywhere 'x': API error (status 403): certificate expired",
            ))
        }
    }
    struct FailingProvider;
    impl CredentialProvider for FailingProvider {
        fn renewer(&self) -> Option<&dyn crate::providers::Renewer> {
            Some(&Failing)
        }
        fn mode_name(&self) -> &'static str {
            "failing"
        }
    }

    /// A hard renewal error with no valid cache surfaces as `Unavailable(cause)` — the real
    /// reason, not a spurious `Unknown`/"env not found". This is the standardized failure
    /// channel every provider funnels through.
    #[tokio::test]
    async fn renewal_error_without_cache_is_unavailable_with_cause() {
        let store = store_with_provider("ra", Box::new(FailingProvider));
        match store.get(TEST_UID, "ra").await {
            Lookup::Unavailable(cause) => {
                assert!(cause.contains("status 403"), "cause: {cause}");
                // The client adds its own prefix; the cause must not carry one too.
                assert!(!cause.contains("provider error"), "cause: {cause}");
            }
            _ => panic!("expected Unavailable"),
        }
    }

    /// The background loop renews a credential nearing expiry, and only that. Under the turn lock
    /// the near-expiry test must still hold; a 60-second margin here would skip the renewal.
    #[tokio::test]
    async fn refresh_all_renews_only_a_credential_near_expiry() {
        // `refresh_all` also pre-warms every provisioned caller under the data dir; an empty
        // dir keeps the host's own callers out of the renewal count.
        let _lock = crate::server::e2e::DATA_DIR_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let _env = crate::server::e2e::EnvVarGuard::set("CREDSD_DATA_DIR", dir.path());
        let renewals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let store = store_with_provider(
            "ra",
            Box::new(CountingProvider(Counting(Arc::clone(&renewals)))),
        );

        let fresh = Credentials::session(
            "AK".into(),
            "SK".into(),
            "TOK".into(),
            credsd_core::credentials::expires_in_seconds(3600),
        );
        store.inject_for_test_async(TEST_UID, "ra", fresh).await;
        store.refresh_all().await;
        assert_eq!(renewals.load(std::sync::atomic::Ordering::SeqCst), 0);

        let near = Credentials::session(
            "AK".into(),
            "SK".into(),
            "TOK".into(),
            credsd_core::credentials::expires_in_seconds(600),
        );
        store.inject_for_test_async(TEST_UID, "ra", near).await;
        store.refresh_all().await;
        assert_eq!(renewals.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A renewal error does NOT override a still-valid cache — the cached credential is served,
    /// same as the re-auth case. `Unavailable` is only for when nothing valid remains.
    #[tokio::test]
    async fn renewal_error_serves_valid_cache() {
        let store = store_with_provider("ra", Box::new(FailingProvider));
        store
            .inject_for_test_async(TEST_UID, "ra", session_creds())
            .await;
        assert!(store.get(TEST_UID, "ra").await.is_ready());
    }

    /// A `ReauthRequired` renewal serves a still-valid cached credential (it is not an error)
    /// but never an expired one — same rule as a failed renewal.
    #[tokio::test]
    async fn reauth_required_serves_valid_cache_but_not_expired() {
        let store = store_with_provider("sso", Box::new(ExhaustedProvider));
        store
            .inject_for_test_async(TEST_UID, "sso", session_creds())
            .await;
        assert!(store.get(TEST_UID, "sso").await.is_ready());

        let expired = Credentials::session(
            "AK".into(),
            "SK".into(),
            "TOK".into(),
            Utc::now() - chrono::Duration::hours(1),
        );
        store.inject_for_test_async(TEST_UID, "sso", expired).await;
        // Exhausted renewer + no valid cache now surfaces as a re-auth challenge, not a bare miss.
        assert!(store.get(TEST_UID, "sso").await.is_reauth());
    }

    /// The background loop treats `ReauthRequired` as "leave it alone" — it does not clobber a
    /// still-valid cache entry with an attempt that has no fresh credential to offer.
    #[tokio::test]
    async fn reauth_required_leaves_cache_untouched_in_background() {
        let store = store_with_provider("sso", Box::new(ExhaustedProvider));
        let creds = session_creds();
        let expires_at = creds.expires_at;
        store.inject_for_test_async(TEST_UID, "sso", creds).await;
        store.refresh_all().await;
        assert_eq!(
            store
                .cache
                .read()
                .await
                .get(&(TEST_UID, "sso".to_string()))
                .unwrap()
                .expires_at,
            expires_at
        );
    }

    /// A re-auth-only source with nothing cached cannot mint on demand — there is no
    /// unattended path, so a miss returns `None` rather than launching an interactive flow.
    #[tokio::test]
    async fn reauth_only_miss_returns_none() {
        let store = store_with_provider("manual", Box::new(ReauthOnly));
        assert!(store.get(TEST_UID, "manual").await.is_unknown());
    }

    /// While a valid credential still sits in cache (seeded by an earlier interactive setup),
    /// a re-auth-only source serves it — the missing refresher never blocks a cache hit.
    #[tokio::test]
    async fn reauth_only_serves_valid_cached() {
        let store = store_with_provider("manual", Box::new(ReauthOnly));
        store
            .inject_for_test_async(TEST_UID, "manual", session_creds())
            .await;
        assert!(store.get(TEST_UID, "manual").await.is_ready());
    }

    /// The background loop skips a re-auth-only source structurally: it never renews, so an
    /// empty cache stays empty rather than the loop attempting (and failing) to refresh.
    #[tokio::test]
    async fn reauth_only_is_skipped_by_background_refresh() {
        let store = store_with_provider("manual", Box::new(ReauthOnly));
        store.refresh_all().await;
        assert!(store.cache.read().await.is_empty());
    }

    /// The observable payoff of the env/credential split: one login serves every
    /// env naming it, so seeding the credential once satisfies both envs.
    #[tokio::test]
    async fn envs_sharing_a_credential_share_one_cache_entry() {
        let store = store_for(
            &[("dev", Some("shared")), ("dev-tokyo", Some("shared"))],
            &["shared"],
        );
        store
            .inject_for_test_async(TEST_UID, "shared", session_creds())
            .await;

        assert!(store.get(TEST_UID, "dev").await.is_ready());
        assert!(store.get(TEST_UID, "dev-tokyo").await.is_ready());
        assert_eq!(store.cache.read().await.len(), 1);
        assert_eq!(store.providers.len(), 1);
    }

    #[tokio::test]
    async fn a_env_without_an_explicit_credential_uses_its_own_name() {
        let store = store_for(&[("dev", None)], &["dev"]);
        store
            .inject_for_test_async(TEST_UID, "dev", session_creds())
            .await;
        assert!(store.get(TEST_UID, "dev").await.is_ready());
    }

    /// Entering by credential name rather than env name must not work — the HTTP API
    /// and `credential_process` both carry env names, and the mapping is the
    /// authorization boundary.
    #[tokio::test]
    async fn a_credential_name_is_not_a_env_name() {
        let store = store_for(&[("dev", Some("shared"))], &["shared"]);
        store
            .inject_for_test_async(TEST_UID, "shared", session_creds())
            .await;
        assert!(store.get(TEST_UID, "shared").await.is_unknown());
    }

    /// A renewal that can't produce fresh creds must not serve an expired cache entry. The SSO
    /// provider has no token on disk here, so it returns `ReauthRequired`; without the expiry
    /// filter the daemon would serve the dead session instead of signalling re-auth.
    #[tokio::test]
    async fn expired_cached_creds_are_not_served_when_fetch_fails() {
        let store = store_for(&[("dev", None)], &["dev"]);
        let expired = Credentials::session(
            "AK".into(),
            "SK".into(),
            "TOK".into(),
            Utc::now() - chrono::Duration::hours(1),
        );
        store.inject_for_test_async(TEST_UID, "dev", expired).await;
        assert!(store.get(TEST_UID, "dev").await.is_reauth());
    }

    /// The same failing-fetch path still serves a cache entry that is stale-but-valid, so a
    /// transient provider error does not needlessly drop still-good credentials.
    #[tokio::test]
    async fn valid_cached_creds_are_served_when_fetch_fails() {
        let store = store_for(&[("dev", None)], &["dev"]);
        let near = Credentials::session(
            "AK".into(),
            "SK".into(),
            "TOK".into(),
            Utc::now() + chrono::Duration::seconds(30),
        );
        store.inject_for_test_async(TEST_UID, "dev", near).await;
        assert!(store.get(TEST_UID, "dev").await.is_ready());
    }

    /// Every defined credential gets a provider — so ad-hoc composition (`--credential X`) can
    /// address any credential, not only env-referenced ones. An unreferenced credential is
    /// built but kept OUT of the warm set, so it costs a struct, not refresh traffic, until
    /// first fetched on demand.
    #[tokio::test]
    async fn every_defined_credential_gets_a_provider_but_only_referenced_ones_are_warm() {
        let store = store_for(&[("dev", None)], &["dev", "unused"]);
        assert_eq!(store.providers.len(), 2);
        assert!(store.providers.contains_key("dev"));
        assert!(store.providers.contains_key("unused"));
        assert!(store.warm_set.contains("dev"));
        assert!(!store.warm_set.contains("unused"));
    }

    /// `get_credential` resolves any defined credential by name, env-independent — the
    /// per-credential serving path `credential_process` and ad-hoc composition use. An env
    /// still resolves its default credential via `get`.
    #[tokio::test]
    async fn get_credential_resolves_any_defined_credential() {
        let store = store_for(&[("dev", None)], &["dev", "adhoc"]);
        store
            .inject_for_test_async(TEST_UID, "adhoc", session_creds())
            .await;
        assert!(store.get_credential(TEST_UID, "adhoc").await.is_ready());

        store
            .inject_for_test_async(TEST_UID, "dev", session_creds())
            .await;
        assert!(store.get(TEST_UID, "dev").await.is_ready());

        // An undefined credential is Unknown, not a panic.
        assert!(store.get_credential(TEST_UID, "nope").await.is_unknown());
    }
}
