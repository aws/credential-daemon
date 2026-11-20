//! End-to-end tests over a real Unix socket.
//!
//! The rest of the suite calls `dispatch` directly with a synthesized `PeerInfo`, which skips
//! everything between: `prepare_socket`'s permissions, `peer_cred` sampling, `resolve_caller`'s
//! owner check, the line codec, the bootstrap task split, and the client's own
//! `credential_resolve` mapping. Those layers are where a wire contract actually breaks, and
//! `private/TODO.md` asks for this harness twice (the 428 round-trip and the MFA login items).
//!
//! What this cannot cover is the uid boundary: the daemon and the client are the same process,
//! so the peer uid is this test's uid. Denial paths stay unit-tested against a synthesized
//! peer. What it does cover is every layer above that, against material sealed on disk.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use credsd_core::config::platform;
use credsd_core::credentials::CredentialData;
use credsd_core::encryption::{generate_key, EncryptionService};
use credsd_core::rpc::{
    uds as rpc_uds, CredentialResult, CredentialSourceType, CredentialType, DescribeParams,
    GetParams, ImportOutcome, ImportParams, ImportProfile, ImportStatus, Material, OkResult,
    ProfileBootstrapParams, ProfileLoginParams, ProfileManifest, Provenance, ProviderParams,
    ProviderParamsIamUser, ProviderParamsJwt, ProviderParamsStaticSecret, SessionStatus,
    METHOD_CREDENTIAL_BOOTSTRAP, METHOD_CREDENTIAL_GET, METHOD_CREDENTIAL_IMPORT,
    METHOD_CREDENTIAL_LOGIN, METHOD_PROFILE_DESCRIBE,
};

use crate::server::dispatch::Daemon;

/// `CREDSD_DATA_DIR` is process-global while the test binary runs cases on parallel threads, so
/// a case that points it at its own tree would otherwise decide where another case's daemon
/// reads. Every case here holds this for its lifetime and restores the prior value on `Drop`,
/// so a failed assertion unwinds without leaking the override.
pub(crate) static DATA_DIR_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Sets an env var for the guard's lifetime and restores the prior value (or removes it) on drop,
/// so a scoped override cannot leak past the test — including on an early return or a panic. Used
/// where a single case needs to override a var the `Harness` already manages (e.g. pointing
/// `CREDSD_SOCKET` at a dead socket); the guard restores the `Harness`'s value, and the `Harness`
/// then restores the pre-test value.
pub(crate) struct EnvVarGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    pub(crate) fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

/// The outcomes of a sequence of `credential/import` calls, in order.
struct ImportResult {
    outcomes: Vec<ImportOutcome>,
}

struct Harness {
    socket: PathBuf,
    /// The served daemon's state, for acting as a peer the socket cannot produce: uid 0.
    daemon: Daemon,
    _dir: tempfile::TempDir,
    _prev: Option<std::ffi::OsString>,
    _prev_socket: Option<std::ffi::OsString>,
    _lock: tokio::sync::MutexGuard<'static, ()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        match self._prev.take() {
            Some(v) => std::env::set_var("CREDSD_DATA_DIR", v),
            None => std::env::remove_var("CREDSD_DATA_DIR"),
        }
        match self._prev_socket.take() {
            Some(v) => std::env::set_var("CREDSD_SOCKET", v),
            None => std::env::remove_var("CREDSD_SOCKET"),
        }
    }
}

impl Harness {
    /// A daemon serving on a real socket inside a temp tree, with a freshly generated
    /// encryption key rather than the platform keystore — a test must not touch the operator's
    /// keychain, and the key's provenance is irrelevant to every layer under test.
    async fn start() -> Self {
        let lock = DATA_DIR_ENV_LOCK.lock().await;
        let prev = std::env::var_os("CREDSD_DATA_DIR");
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("CREDSD_DATA_DIR", dir.path());

        // The daemon authorizes by peer uid against `callers/<uid>/owner`. Same process here,
        // so provisioning our own uid is what the installed daemon does on first bootstrap.
        platform::provision_caller().expect("provision caller root");

        let socket = dir.path().join("credsd.sock");
        // Point client_socket_path() at this daemon so client-side code that resolves the socket
        // from the environment (e.g. the MCP list_envs status path) reaches this harness.
        let prev_socket = std::env::var_os("CREDSD_SOCKET");
        std::env::set_var("CREDSD_SOCKET", &socket);
        let listener = crate::server::uds::prepare_socket(&socket).expect("bind socket");
        let encryption =
            Arc::new(EncryptionService::new(generate_key().expect("key")).expect("encryption"));
        let callers = platform::callers_dir();
        let daemon = Daemon::new(
            encryption,
            callers.clone(),
            crate::server::presence::RegistryCustody::beside(&callers),
            crate::server::integrity::IntegrityCustody::beside(&callers),
        );

        let served = daemon.clone();
        tokio::spawn(async move {
            let _ = crate::server::uds::serve(listener, served).await;
        });

        Self {
            socket,
            daemon,
            _dir: dir,
            _prev: prev,
            _prev_socket: prev_socket,
            _lock: lock,
        }
    }

    async fn bootstrap_jwt(&self, env: &str, jwt: &str, env_var: Option<&str>) -> OkResult {
        let params = ProfileBootstrapParams {
            tags: None,
            credential: Some(env.to_owned()),
            name_prefix: None,
            request_id: None,
            provider: ProviderParams::Jwt(ProviderParamsJwt {
                jwt: jwt.to_owned(),
                env_var: env_var.map(str::to_owned),
                identity_type: Some("automation".to_owned()),
            }),
        };
        self.call(METHOD_CREDENTIAL_BOOTSTRAP, &params, env)
            .await
            .expect("bootstrap")
    }

    /// An MFA-bearing iam-user credential. Bootstrap seals the long-term key pair locally with no
    /// network call; `login` on it blocks in `await_selection` waiting for an MFA code, which is
    /// the only way to hold a login open from a test without standing up an IdP.
    async fn bootstrap_iam_user_with_mfa(&self, env: &str) -> OkResult {
        let params = ProfileBootstrapParams {
            tags: None,
            credential: Some(env.to_owned()),
            name_prefix: None,
            request_id: None,
            provider: ProviderParams::AwsIamUser(ProviderParamsIamUser {
                access_key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
                secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
                region: "us-east-1".to_owned(),
                duration_seconds: None,
                mfa_serial: Some("arn:aws:iam::111111111111:mfa/example".to_owned()),
                identity_type: Some("human".to_owned()),
            }),
        };
        self.call(METHOD_CREDENTIAL_BOOTSTRAP, &params, env)
            .await
            .expect("bootstrap")
    }

    async fn bootstrap_static_secret(
        &self,
        env: &str,
        secret: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> OkResult {
        let params = ProfileBootstrapParams {
            tags: None,
            credential: Some(env.to_owned()),
            name_prefix: None,
            request_id: None,
            provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
                secret: secret.to_owned(),
                env_var: None,
                expires_at,
                secret_source: Some("stdin".to_owned()),
                identity_type: Some("automation".to_owned()),
            }),
        };
        self.call(METHOD_CREDENTIAL_BOOTSTRAP, &params, env)
            .await
            .expect("bootstrap")
    }

    /// A static-secret bootstrap that returns the daemon's answer instead of asserting success,
    /// for cases that expect the presence gate to refuse it.
    async fn try_bootstrap_static_secret(
        &self,
        env: &str,
        credential: Option<&str>,
        secret: &str,
    ) -> credsd_core::error::Result<OkResult> {
        let params = ProfileBootstrapParams {
            tags: None,
            credential: Some(credential.unwrap_or(env).to_owned()),
            name_prefix: None,
            request_id: None,
            provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
                secret: secret.to_owned(),
                env_var: None,
                expires_at: None,
                secret_source: Some("stdin".to_owned()),
                identity_type: Some("automation".to_owned()),
            }),
        };
        self.call(METHOD_CREDENTIAL_BOOTSTRAP, &params, env).await
    }

    async fn remove_env(&self, env: &str) -> credsd_core::error::Result<OkResult> {
        let params = credsd_core::rpc::EnvRemoveParams {
            environment: env.to_owned(),
        };
        self.call(credsd_core::rpc::METHOD_ENV_REMOVE, &params, env)
            .await
    }

    async fn remove_credential(&self, credential: &str) -> credsd_core::error::Result<OkResult> {
        let params = credsd_core::rpc::CredentialRemoveParams {
            credential: credential.to_owned(),
        };
        self.call(
            credsd_core::rpc::METHOD_CREDENTIAL_REMOVE,
            &params,
            credential,
        )
        .await
    }

    /// Approve `id` as `sudo creds request approve` does: a connection whose kernel-reported uid is 0.
    /// The socket cannot carry that peer in-process, so this dispatches with it directly.
    async fn approve_as_root(&self, id: &str) -> credsd_core::error::Result<serde_json::Value> {
        use crate::server::dispatch::{dispatch, Carrier};
        use crate::server::routes::{CallerAuth, PeerInfo};
        use credsd_core::presence::{ApproveParams, METHOD_REQUEST_APPROVE};
        use credsd_core::rpc::{Id, Outcome, Request};
        let request = Request::with_params(
            Id::from(1),
            METHOD_REQUEST_APPROVE,
            &ApproveParams {
                id: id.to_owned(),
                signature: None,
            },
        )
        .expect("encode approve");
        let root = PeerInfo {
            uid: Some(0),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: None,
            login_uid: None,
        };
        match dispatch(&request, Carrier::Uds, &root, &self.daemon)
            .await
            .outcome
        {
            Outcome::Result(value) => Ok(value),
            Outcome::Error(e) => Err(rpc_uds::error_to_daemon(None, e)),
        }
    }

    async fn call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &P,
        subject: &str,
    ) -> credsd_core::error::Result<R> {
        rpc_uds::call(&self.socket, method, params, Some(subject)).await
    }

    async fn get(&self, credential: &str) -> credsd_core::error::Result<CredentialResult> {
        let params = GetParams {
            environment: None,
            credential: Some(credential.to_owned()),
            account_id: None,
            role_name: None,
            scope: None,
            claim: None,
            request_id: None,
        };
        self.call(METHOD_CREDENTIAL_GET, &params, credential).await
    }

    /// `credential/get` addressed to the environment `env`, for its first credential.
    async fn get_in_env(&self, env: &str) -> credsd_core::error::Result<CredentialResult> {
        let params = GetParams {
            environment: Some(env.to_owned()),
            credential: None,
            account_id: None,
            role_name: None,
            scope: None,
            claim: None,
            request_id: None,
        };
        self.call(METHOD_CREDENTIAL_GET, &params, env).await
    }

    /// Import `profiles` the way `creds import` does: one `credential/import` call each.
    async fn import(&self, profiles: Vec<ImportProfile>, dry_run: bool) -> ImportResult {
        let mut outcomes = Vec::with_capacity(profiles.len());
        for profile in profiles {
            let params = ImportParams { profile, dry_run };
            outcomes.push(
                self.call(METHOD_CREDENTIAL_IMPORT, &params, "import")
                    .await
                    .expect("import"),
            );
        }
        ImportResult { outcomes }
    }

    /// Compose `env` from `credentials`. No method creates an environment (credential-retrieval-api
    /// Requirement 16 AC 2), so this edits `config.toml` and ratifies the edit the sanctioned way:
    /// an approved revalidation.
    async fn compose_env(&self, env: &str, credentials: &[&str]) {
        self.compose_env_with(env, credentials, "").await;
    }

    /// [`Harness::compose_env`] with `extra` TOML lines under the environment's table.
    async fn compose_env_with(&self, env: &str, credentials: &[&str], extra: &str) {
        let path = platform::caller_root(nix::unistd::getuid().as_raw()).join("config.toml");
        let before = std::fs::read_to_string(&path).unwrap_or_default();
        let list: Vec<String> = credentials.iter().map(|c| format!("\"{c}\"")).collect();
        std::fs::write(
            &path,
            format!(
                "{before}\n[environments.{env}]\ncredentials = [{}]\n{extra}",
                list.join(", ")
            ),
        )
        .expect("compose env in config.toml");
        let challenge = match revalidate(self).await {
            Err(credsd_core::error::DaemonError::ApprovalRequired(c)) => *c,
            other => panic!("composing an env must raise a revalidation challenge: {other:?}"),
        };
        self.approve_as_root(&challenge.id).await.expect("approve");
    }

    /// Give `config.toml` the content `body` and ratify it the sanctioned way: an approved
    /// revalidation. `body` carries no environment table, which a caller config may not hold.
    async fn seed_config(&self, body: &str) {
        let path = platform::caller_root(nix::unistd::getuid().as_raw()).join("config.toml");
        std::fs::write(&path, body).expect("write config.toml");
        let challenge = match revalidate(self).await {
            Err(credsd_core::error::DaemonError::ApprovalRequired(c)) => *c,
            other => panic!("seeding config.toml must raise a revalidation challenge: {other:?}"),
        };
        self.approve_as_root(&challenge.id).await.expect("approve");
    }

    /// The source type `credentials.toml` records for `credential`, read through the daemon's own
    /// loader rather than a manifest, which is not dispatched.
    fn source_of(&self, credential: &str) -> CredentialSourceType {
        let root = platform::caller_root(nix::unistd::getuid().as_raw());
        let (_, credentials) =
            credsd_core::config::DaemonConfig::load_from(&root).expect("load caller config");
        credentials
            .get(credential)
            .unwrap_or_else(|| panic!("{credential} is not in credentials.toml"))
            .source_type()
    }

    async fn describe(&self, env: &str) -> ProfileManifest {
        let params = DescribeParams {
            environment: env.to_owned(),
            request_id: None,
        };
        self.call(METHOD_PROFILE_DESCRIBE, &params, env)
            .await
            .expect("describe")
    }
}

/// A JWT expiring `secs` from now. Header and signature are throwaway — nothing in credsd
/// verifies the signature, because credsd is not the audience.
fn jwt_expiring_in(secs: i64) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let exp = chrono::Utc::now().timestamp().saturating_add(secs);
    let b64 = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
    format!(
        "{}.{}.{}",
        b64(br#"{"alg":"RS256","typ":"JWT"}"#),
        b64(format!(r#"{{"sub":"cam","exp":{exp}}}"#).as_bytes()),
        b64(b"signature")
    )
}

fn token_of(result: &CredentialResult) -> &str {
    match &result.material {
        Material::AccessToken { token, .. } => token,
        other => panic!("expected an access token, got {other:?}"),
    }
}

/// The whole path a token credential takes, over the socket: bootstrap seals it, `credential/get`
/// serves it as `access_token` material with the issuer's own expiry, and the client's
/// `credential_resolve` maps that back onto a `CredentialData::AccessToken`. Each of those is a
/// separate encode/decode of the new wire variant, which is what makes doing them in one case
/// worth more than three direct `dispatch` calls.
#[tokio::test]
async fn a_jwt_credential_round_trips_over_the_socket() {
    let h = Harness::start().await;
    let jwt = jwt_expiring_in(3600);
    h.bootstrap_jwt("gh", &jwt, Some("GITHUB_TOKEN")).await;

    let result = h.get("gh").await.expect("get");
    assert_eq!(result.credential, "gh");
    assert_eq!(token_of(&result), jwt);
    assert_eq!(
        result.expires_at.expect("jwt stamps an exp").timestamp(),
        crate::providers::jwt::exp_of(&jwt)
            .expect("exp")
            .timestamp(),
        "the served expiry must be the JWT's own exp, not a locally invented one"
    );

    // The client-side mapping, over the same socket: this is the half `credential/get`'s unit
    // tests cannot reach, and where an unknown-variant decode would surface.
    let creds = credsd_core::credential_resolve::fetch_credential(
        &h.socket,
        "gh",
        credsd_core::wire::ClaimedIdentity::Unstated,
    )
    .await
    .expect("client fetch");
    match &creds.data {
        CredentialData::AccessToken { token } => assert_eq!(token, &jwt),
        other => panic!("client mapped the token to {other:?}"),
    }
}

/// The variable a shell-format `creds get` exports a token under is the name derived from the
/// credential, with or without a recorded `env_var`: the recorded one is not read.
#[tokio::test]
async fn a_token_is_exported_under_its_derived_name_whatever_env_var_records() {
    let h = Harness::start().await;
    h.bootstrap_jwt("declared", &jwt_expiring_in(3600), Some("OPENAI_API_KEY"))
        .await;
    h.bootstrap_jwt("my-token", &jwt_expiring_in(3600), None)
        .await;
    for (credential, expected) in [("declared", "DECLARED"), ("my-token", "MY_TOKEN")] {
        let creds = credsd_core::credential_resolve::fetch_credential(
            &h.socket,
            credential,
            credsd_core::wire::ClaimedIdentity::Unstated,
        )
        .await
        .expect("client fetch");
        let name = credsd_core::get::token_export_name(credential);
        assert_eq!(name, expected);
        let line = credsd_core::get::format_credentials(
            &creds,
            credsd_core::get::OutputFormat::Shell,
            &name,
        )
        .expect("format");
        assert!(line.starts_with(&format!("export {expected}=")), "{line}");
        assert!(!line.contains("OPENAI_API_KEY"), "{line}");
    }
}

/// A secret with no declared expiry, over the socket, end to end. This is the case the whole
/// nullable-expiry change exists for: bootstrap seals an opaque string, `credential/get` serves it
/// with `expires_at: null`, and the client maps that back to a credential that is not expired.
///
/// It is also the integration proof that the provider offers a renewer. The store reaches sealed
/// material only through one, so a provider returning `None` would make this `get` report the
/// credential as unknown — every unit test in the provider would still pass, because none of them
/// goes through the store.
#[tokio::test]
async fn a_static_secret_with_no_expiry_round_trips_over_the_socket() {
    let h = Harness::start().await;
    let secret = "sk-opaque-no-expiry-value";
    h.bootstrap_static_secret("openai", secret, None).await;

    let result = h.get("openai").await.expect("get");
    assert_eq!(result.credential, "openai");
    assert_eq!(token_of(&result), secret);
    assert!(
        result.expires_at.is_none(),
        "a secret with no declared expiry must serve as null, got {:?}",
        result.expires_at
    );
    assert_eq!(
        result.provenance,
        Provenance::CachedShared,
        "the secret is served from the shared sealed file, not minted per request"
    );
    match &result.material {
        Material::AccessToken { token_type, .. } => assert_eq!(
            token_type, "Bearer",
            "token_type is fixed, not derived from the opaque secret"
        ),
        other => panic!("expected access-token material, got {other:?}"),
    }

    // The client half, over the same socket: `null` has to decode into "never expires" rather
    // than into an error or a fabricated instant.
    let creds = credsd_core::credential_resolve::fetch_credential(
        &h.socket,
        "openai",
        credsd_core::wire::ClaimedIdentity::Unstated,
    )
    .await
    .expect("client fetch");
    assert!(creds.expires_at.is_none());
    assert!(
        !creds.is_expired(),
        "no declared expiry must never read expired"
    );
    match &creds.data {
        CredentialData::AccessToken { token } => assert_eq!(token, secret),
        other => panic!("client mapped the secret to {other:?}"),
    }
}

/// A declared expiry survives the round trip, so the shared status logic has a real instant to
/// grade against rather than the null case above.
#[tokio::test]
async fn a_declared_expiry_survives_the_socket() {
    let h = Harness::start().await;
    let declared = chrono::Utc::now() + chrono::TimeDelta::hours(6);
    h.bootstrap_static_secret("gh", "sk-with-declared-expiry", Some(declared))
        .await;

    let result = h.get("gh").await.expect("get");
    assert_eq!(
        result.expires_at.expect("declared").timestamp(),
        declared.timestamp()
    );
}

/// The challenge a gated call carried, or a failure naming what came back instead.
fn challenge_of(result: credsd_core::error::Result<OkResult>) -> credsd_core::presence::Challenge {
    match result {
        Err(credsd_core::error::DaemonError::ApprovalRequired(c)) => *c,
        Err(other) => panic!("expected APPROVAL_REQUIRED, got {other}"),
        Ok(_) => panic!("expected APPROVAL_REQUIRED, but the overwrite was performed"),
    }
}

/// Re-bootstrap is still the rotation path, but over an existing credential it is gated: it
/// changes nothing until approved, an approval admits exactly one identical re-send, and the
/// rotated-in value is then the one served — never the old, and never a merge of the two.
#[tokio::test]
async fn re_bootstrapping_rotates_only_after_approval_and_only_once() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("rotate", "sk-first-value", None)
        .await;

    let challenge = challenge_of(
        h.try_bootstrap_static_secret("rotate", None, "sk-second-value")
            .await,
    );
    assert!(
        challenge
            .description
            .contains("replace existing credential 'rotate'"),
        "the description names what is replaced: {}",
        challenge.description
    );
    assert!(
        !challenge.description.contains("sk-second-value"),
        "the description never carries the new secret"
    );
    assert_eq!(
        token_of(&h.get("rotate").await.expect("get")),
        "sk-first-value",
        "an unapproved overwrite must leave the served secret untouched"
    );

    h.approve_as_root(&challenge.id).await.expect("approve");
    h.try_bootstrap_static_secret("rotate", None, "sk-second-value")
        .await
        .expect("the approved re-send is performed");
    assert_eq!(
        token_of(&h.get("rotate").await.expect("get")),
        "sk-second-value",
        "the rotated-in secret must be the one served"
    );

    challenge_of(
        h.try_bootstrap_static_secret("rotate", None, "sk-second-value")
            .await,
    );
}

/// An approval authorizes the params it was raised for. A re-send carrying a different secret
/// is a different request and is gated afresh, however soon after the approval it arrives.
#[tokio::test]
async fn an_approval_does_not_admit_a_different_secret() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("bound", "sk-original", None)
        .await;

    let approved = challenge_of(
        h.try_bootstrap_static_secret("bound", None, "sk-approved")
            .await,
    );
    h.approve_as_root(&approved.id).await.expect("approve");

    challenge_of(
        h.try_bootstrap_static_secret("bound", None, "sk-substituted")
            .await,
    );
    assert_eq!(token_of(&h.get("bound").await.expect("get")), "sk-original");
}

/// The pairs an SSO credential allows change only through the presence-gated re-bootstrap that
/// changes its stored pair (`presence-gated-operations` Req 1.7): the challenge shows the approver
/// every pair it would allow, and an approval for one list never admits another.
#[tokio::test]
async fn changing_the_allowed_roles_needs_presence_for_exactly_that_list() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("acme", "sk-original", None).await;
    let sso = |allowed: &[(&str, &str)]| ProfileBootstrapParams {
        tags: None,
        credential: Some("acme".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::AwsIdcSso(credsd_core::rpc::ProviderParamsSso {
            start_url: "https://example.awsapps.com/start".to_owned(),
            sso_region: "us-east-1".to_owned(),
            account_id: Some("111111111111".to_owned()),
            role_name: Some("Developer".to_owned()),
            identity_type: Some("automation".to_owned()),
            allowed_roles: Some(
                allowed
                    .iter()
                    .map(|(account_id, role_name)| credsd_core::config::RolePair {
                        account_id: (*account_id).to_owned(),
                        role_name: (*role_name).to_owned(),
                    })
                    .collect(),
            ),
        }),
    };
    let wanted = [("222222222222", "ReadOnly"), ("333333333333", "Admin")];

    let challenge = challenge_of(
        h.call(METHOD_CREDENTIAL_BOOTSTRAP, &sso(&wanted), "acme")
            .await,
    );
    for (account_id, role_name) in wanted {
        assert!(
            challenge
                .description
                .contains(&format!("account {account_id}, role {role_name}")),
            "the approver is shown every pair it would allow: {}",
            challenge.description
        );
    }

    // Approval for this list is spent only by this list: a wider one is gated afresh, before any
    // sign-in runs.
    h.approve_as_root(&challenge.id).await.expect("approve");
    challenge_of(
        h.call(
            METHOD_CREDENTIAL_BOOTSTRAP,
            &sso(&[wanted[0], wanted[1], ("444444444444", "Owner")]),
            "acme",
        )
        .await,
    );
    assert_eq!(token_of(&h.get("acme").await.expect("get")), "sk-original");
}

/// An approval is given against the state it was shown. Once the records it would replace move,
/// the authorization no longer matches and the re-send is gated again.
#[tokio::test]
async fn an_approval_lapses_when_the_records_it_described_change() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("drift", "sk-original", None)
        .await;

    let approved = challenge_of(
        h.try_bootstrap_static_secret("drift", None, "sk-next")
            .await,
    );
    h.approve_as_root(&approved.id).await.expect("approve");

    // A first bootstrap elsewhere is ungated, and it rewrites both config files.
    h.bootstrap_static_secret("elsewhere", "sk-other", None)
        .await;

    challenge_of(
        h.try_bootstrap_static_secret("drift", None, "sk-next")
            .await,
    );
    assert_eq!(token_of(&h.get("drift").await.expect("get")), "sk-original");
}

/// Creating a credential creates only the credential (credential-retrieval-api Requirement 16):
/// no `config.toml` is written, the credential is listed and served by name, and an
/// environment-addressed request for the same name is refused (credential-only-addressing 4.2).
#[tokio::test]
async fn a_bootstrap_creates_the_credential_and_no_environment() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("solo", "sk-solo", None).await;
    let uid = nix::unistd::getuid().as_raw();
    assert!(
        !platform::caller_root(uid).join("config.toml").exists(),
        "a bootstrap writes no environment"
    );
    assert_eq!(
        token_of(&h.get("solo").await.expect("get by name")),
        "sk-solo"
    );
    let refused = h
        .get_in_env("solo")
        .await
        .expect_err("an environment-addressed request is refused");
    assert!(refused.to_string().contains("environment"), "{refused}");
    let listed: credsd_core::rpc::ListResult = h
        .call(
            credsd_core::rpc::METHOD_CREDENTIAL_LIST,
            &credsd_core::rpc::ListParams::default(),
            "list",
        )
        .await
        .expect("list");
    let entry = listed
        .credentials
        .iter()
        .find(|c| c.credential == "solo")
        .expect("a credential no environment composes is still listed");
    assert_eq!(entry.environment, None);
    assert_eq!(
        entry.kind,
        credsd_core::credentials::CredentialType::AccessToken
    );
    assert_eq!(h.source_of("solo"), CredentialSourceType::StaticSecret);
}

/// Rows of `credential/list` under `params`, as `(name, tags)`, sorted by name.
async fn tagged_rows(
    h: &Harness,
    params: serde_json::Value,
) -> credsd_core::error::Result<Vec<(String, serde_json::Value)>> {
    let listed: serde_json::Value = h
        .call(credsd_core::rpc::METHOD_CREDENTIAL_LIST, &params, "list")
        .await?;
    let mut rows: Vec<(String, serde_json::Value)> = listed["credentials"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| {
            (
                row["credential"].as_str().expect("name").to_owned(),
                row["tags"].clone(),
            )
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(rows)
}

/// A static-secret bootstrap of `credential` carrying `tags` on the wire.
async fn bootstrap_tagged(h: &Harness, credential: &str, tags: serde_json::Value) {
    let mut params = serde_json::to_value(ProfileBootstrapParams {
        tags: None,
        credential: Some(credential.to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
            secret: format!("sk-{credential}"),
            env_var: None,
            expires_at: None,
            secret_source: Some("stdin".to_owned()),
            identity_type: Some("automation".to_owned()),
        }),
    })
    .expect("params");
    params["tags"] = tags;
    let _: OkResult = h
        .call(METHOD_CREDENTIAL_BOOTSTRAP, &params, credential)
        .await
        .expect("bootstrap");
}

async fn tag(
    h: &Harness,
    params: serde_json::Value,
) -> credsd_core::error::Result<serde_json::Value> {
    let subject = params["credential"].as_str().unwrap_or("tag").to_owned();
    h.call("credential/tag", &params, &subject).await
}

/// Requirements 3 and 4 end to end: bootstrap sets tags, `credential/tag` edits them in one
/// write, rows always carry them, and the filter ANDs value and presence conditions.
#[tokio::test]
async fn tags_set_at_bootstrap_and_by_tag_filter_the_list() {
    let h = Harness::start().await;
    bootstrap_tagged(
        &h,
        "pay",
        serde_json::json!({ "team": "payments", "stage": "prod" }),
    )
    .await;
    h.bootstrap_static_secret("plain", "sk-plain", None).await;

    let all = tagged_rows(&h, serde_json::json!({})).await.expect("list");
    assert_eq!(
        all,
        [
            (
                "pay".to_owned(),
                serde_json::json!({ "stage": "prod", "team": "payments" })
            ),
            ("plain".to_owned(), serde_json::json!({})),
        ]
    );

    let ok = tag(
        &h,
        serde_json::json!({ "credential": "plain", "set": { "team": "payments" }, "unset": ["absent"] }),
    )
    .await
    .expect("tag set");
    assert_eq!(ok, serde_json::json!({}));
    tag(
        &h,
        serde_json::json!({ "credential": "pay", "unset": ["stage"] }),
    )
    .await
    .expect("tag unset");

    let names = |rows: Vec<(String, serde_json::Value)>| -> Vec<String> {
        rows.into_iter().map(|(n, _)| n).collect()
    };
    assert_eq!(
        names(
            tagged_rows(&h, serde_json::json!({ "tags": { "team": "payments" } }))
                .await
                .expect("list")
        ),
        ["pay", "plain"]
    );
    assert!(
        tagged_rows(
            &h,
            serde_json::json!({ "tags": { "team": "payments", "stage": null } })
        )
        .await
        .expect("list")
        .is_empty(),
        "stage was unset"
    );
    assert!(
        tagged_rows(&h, serde_json::json!({ "tags": { "team": "other" } }))
            .await
            .expect("list")
            .is_empty()
    );
}

/// Requirement 3.5: an overlapping edit and an edit whose result breaks the grammar both refuse
/// and write nothing. Requirement 3.4: an unknown credential is CREDENTIAL_NOT_FOUND.
#[tokio::test]
async fn a_refused_tag_edit_writes_nothing() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("plain", "sk-plain", None).await;
    let uid = nix::unistd::getuid().as_raw();
    let file = platform::caller_root(uid).join("credentials.toml");
    let before = std::fs::read(&file).expect("credentials.toml");

    for bad in [
        serde_json::json!({ "credential": "plain", "set": { "team": "x" }, "unset": ["team"] }),
        serde_json::json!({ "credential": "plain", "set": { "Team": "x", "team": "y" } }),
        serde_json::json!({ "credential": "plain", "set": { "Team": "x" }, "unset": ["team"] }),
        serde_json::json!({ "credential": "plain", "unset": ["Team", "team"] }),
        serde_json::json!({ "credential": "plain", "set": { "team": "sk-planted\u{7}" } }),
    ] {
        let err = tag(&h, bad.clone()).await.expect_err("refused").to_string();
        assert!(!err.contains("unknown method"), "{bad}: {err}");
        assert!(!err.contains("sk-planted"), "{bad}: {err}");
        assert_eq!(
            std::fs::read(&file).expect("credentials.toml"),
            before,
            "{bad}"
        );
    }
    assert!(matches!(
        tag(
            &h,
            serde_json::json!({ "credential": "ghost", "set": { "team": "x" } })
        )
        .await,
        Err(credsd_core::error::DaemonError::EnvNotFound(_))
    ));
}

/// Requirement 1.4: every input folds keys to lowercase and keeps values byte for byte, so a key
/// written in any case at bootstrap, by `credential/tag`, or in a filter is the same key.
/// Requirement 1.6: two spellings of one key in one request are refused naming both.
#[tokio::test]
async fn tag_keys_fold_at_every_input() {
    let h = Harness::start().await;
    bootstrap_tagged(&h, "pay", serde_json::json!({ "Team": "Pay Ments" })).await;
    tag(
        &h,
        serde_json::json!({ "credential": "pay", "set": { "STAGE": "Prod" }, "unset": ["OWNER"] }),
    )
    .await
    .expect("tag set");
    let want = [(
        "pay".to_owned(),
        serde_json::json!({ "stage": "Prod", "team": "Pay Ments" }),
    )];
    assert_eq!(
        tagged_rows(
            &h,
            serde_json::json!({ "tags": { "TEAM": "Pay Ments", "Stage": null } })
        )
        .await
        .expect("list"),
        want
    );
    tag(
        &h,
        serde_json::json!({ "credential": "pay", "unset": ["Stage"] }),
    )
    .await
    .expect("tag unset");
    assert_eq!(
        tagged_rows(&h, serde_json::json!({})).await.expect("list")[0].1,
        serde_json::json!({ "team": "Pay Ments" })
    );

    let err = tagged_rows(
        &h,
        serde_json::json!({ "tags": { "Env": "a", "env": null } }),
    )
    .await
    .expect_err("filter collision")
    .to_string();
    assert!(err.contains("\"Env\"") && err.contains("\"env\""), "{err}");
    let err = tag(
        &h,
        serde_json::json!({ "credential": "pay", "set": { "Env": "sk-planted", "env": "sk-planted" } }),
    )
    .await
    .expect_err("set collision")
    .to_string();
    assert!(err.contains("\"Env\"") && err.contains("\"env\""), "{err}");
    assert!(err.contains("'pay'"), "{err}");
    assert!(!err.contains("sk-planted"), "{err}");
}

/// Requirement 3.3 against 3.2: `credential/tag` merges into the existing set, so a second edit
/// keeps the first edit's other keys, while a bootstrap given `tags` replaces the whole set.
#[tokio::test]
async fn tag_edits_merge_and_bootstrap_tags_replace() {
    let h = Harness::start().await;
    bootstrap_tagged(&h, "pay", serde_json::json!({})).await;
    for set in [
        serde_json::json!({ "foo": "a", "bar": "a" }),
        serde_json::json!({ "bar": "b", "baz": "b" }),
    ] {
        tag(&h, serde_json::json!({ "credential": "pay", "set": set }))
            .await
            .expect("tag set");
    }
    let tags_of = |rows: Vec<(String, serde_json::Value)>| rows[0].1.clone();
    assert_eq!(
        tags_of(tagged_rows(&h, serde_json::json!({})).await.expect("list")),
        serde_json::json!({ "foo": "a", "bar": "b", "baz": "b" })
    );

    let mut params = serde_json::to_value(ProfileBootstrapParams {
        tags: None,
        credential: Some("pay".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
            secret: "sk-again".to_owned(),
            env_var: None,
            expires_at: None,
            secret_source: Some("stdin".to_owned()),
            identity_type: Some("automation".to_owned()),
        }),
    })
    .expect("params");
    params["tags"] = serde_json::json!({ "only": "x" });
    let challenge = challenge_of(h.call(METHOD_CREDENTIAL_BOOTSTRAP, &params, "pay").await);
    h.approve_as_root(&challenge.id).await.expect("approve");
    let _: OkResult = h
        .call(METHOD_CREDENTIAL_BOOTSTRAP, &params, "pay")
        .await
        .expect("approved re-send");
    assert_eq!(
        tags_of(tagged_rows(&h, serde_json::json!({})).await.expect("list")),
        serde_json::json!({ "only": "x" })
    );
}

/// drift-detection: tags are part of the sealed form, so a hand edit to a credential's `tags`
/// table is drift like any other hand edit, while the daemon's own tag write is not.
#[tokio::test]
async fn a_hand_edit_to_tags_is_drift() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("plain", "sk-plain", None).await;
    tag(
        &h,
        serde_json::json!({ "credential": "plain", "set": { "team": "payments" } }),
    )
    .await
    .expect("tag set");
    h.get("plain")
        .await
        .expect("a daemon tag write is not drift");

    let uid = nix::unistd::getuid().as_raw();
    let file = platform::caller_root(uid).join("credentials.toml");
    let text = std::fs::read_to_string(&file).expect("credentials.toml");
    std::fs::write(&file, text.replace("payments", "billing")).expect("hand edit");
    h.daemon.evict_caller(uid);
    let err = h.get("plain").await.expect_err("drift served");
    assert!(err.to_string().contains("config drifted"), "{err}");
}

/// Upgrade: an entry sealed before tags existed, whose file already held a `tags` table that
/// was ignored then, reads as drifted once tags are part of the sealed form. Nobody edited
/// anything, so the owner's revalidation is the remedy, and afterwards the tags are served.
#[tokio::test]
async fn a_tags_table_sealed_before_tags_existed_is_drift_until_revalidated() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("plain", "sk-plain", None).await;

    // The seal covers the untagged entry, as an older daemon's would; the table beside it is
    // what that daemon ignored.
    let uid = nix::unistd::getuid().as_raw();
    let file = platform::caller_root(uid).join("credentials.toml");
    let text = std::fs::read_to_string(&file).expect("credentials.toml");
    assert!(!text.contains("tags"), "{text}");
    std::fs::write(&file, format!("{text}tags = {{ team = \"payments\" }}\n")).expect("table");
    h.daemon.evict_caller(uid);
    let err = h.get("plain").await.expect_err("drift served");
    assert!(err.to_string().contains("config drifted"), "{err}");

    let challenge = challenge_of(revalidate(&h).await);
    h.approve_as_root(&challenge.id).await.expect("approve");
    h.get("plain").await.expect("revalidated");
    assert_eq!(
        tagged_rows(&h, serde_json::json!({})).await.expect("list"),
        [(
            "plain".to_owned(),
            serde_json::json!({ "team": "payments" })
        )]
    );
}

/// A tag that breaks the grammar is an invalid config, not a file that fails to parse: the
/// owner's revalidation ratifies it, and the caller then reads as invalid rather than drifted, so
/// the remedy is editing the tag, not a revalidation that can never succeed. Every caller read
/// refuses with the error of Requirement 1.5 (credential and key, no value), and so does a
/// `credential/tag` of another credential in the same file.
#[tokio::test]
async fn a_bad_tag_is_invalid_config_not_drift() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("plain", "sk-plain", None).await;
    h.bootstrap_static_secret("other", "sk-other", None).await;
    tag(
        &h,
        serde_json::json!({ "credential": "plain", "set": { "team": "payments" } }),
    )
    .await
    .expect("tag set");

    let uid = nix::unistd::getuid().as_raw();
    let file = platform::caller_root(uid).join("credentials.toml");
    let text = std::fs::read_to_string(&file).expect("credentials.toml");
    assert!(text.contains("team = "), "{text}");
    std::fs::write(&file, text.replace("team = ", "\"bad key\" = ")).expect("hand edit");
    h.daemon.evict_caller(uid);

    let challenge = challenge_of(revalidate(&h).await);
    h.approve_as_root(&challenge.id)
        .await
        .expect("a file that parses is ratified, whatever its tags");
    h.daemon.evict_caller(uid);
    let err = h
        .get("plain")
        .await
        .expect_err("an invalid config serves nothing");
    let listed = tagged_rows(&h, serde_json::json!({}))
        .await
        .expect_err("an invalid config lists nothing");
    let retag = tag(
        &h,
        serde_json::json!({ "credential": "other", "set": { "stage": "dev" } }),
    )
    .await
    .expect_err("a tag edit over an invalid file is refused");
    for err in [err.to_string(), listed.to_string(), retag.to_string()] {
        assert!(err.contains("config invalid"), "{err}");
        assert!(
            err.contains("'plain'") && err.contains("\"bad key\""),
            "{err}"
        );
        assert!(!err.contains("payments"), "echoes a tag value: {err}");
    }
}

/// A ratified `config.toml` that fails validation serves nothing, as a bad tag does.
#[tokio::test]
async fn a_ratified_config_that_does_not_validate_serves_nothing() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("plain", "sk-plain", None).await;

    let uid = nix::unistd::getuid().as_raw();
    let file = platform::caller_root(uid).join("config.toml");
    let text = std::fs::read_to_string(&file).unwrap_or_default();
    std::fs::write(&file, format!("socket_path = \"relative.sock\"\n{text}")).expect("hand edit");
    h.daemon.evict_caller(uid);

    let challenge = challenge_of(revalidate(&h).await);
    h.approve_as_root(&challenge.id)
        .await
        .expect("a file that parses is ratified");
    h.daemon.evict_caller(uid);
    let err = h
        .get("plain")
        .await
        .expect_err("an invalid config serves nothing");
    assert!(err.to_string().contains("config invalid"), "{err}");
    assert!(err.to_string().contains("socket_path"), "{err}");
}

/// Requirement 2.4: removing a credential removes its tags, so a credential of the same name
/// bootstrapped later starts with none.
#[tokio::test]
async fn removing_a_credential_removes_its_tags() {
    let h = Harness::start().await;
    bootstrap_tagged(&h, "pay", serde_json::json!({ "team": "payments" })).await;
    let challenge = challenge_of(h.remove_credential("pay").await);
    h.approve_as_root(&challenge.id)
        .await
        .expect("approve removal");
    h.bootstrap_static_secret("pay", "sk-again", None).await;
    assert_eq!(
        tagged_rows(&h, serde_json::json!({})).await.expect("list"),
        [("pay".to_owned(), serde_json::json!({}))]
    );
}

/// Re-bootstrapping a credential can carry an identity_type that rewrites the credential's own
/// privilege tier. The challenge must name the rewrite, not just the replacement — the same bar
/// `config/set` already holds for this field.
#[tokio::test]
async fn bootstrap_disclosure_names_an_identity_type_rewrite_to_the_credential() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("shared", "sk-original", None)
        .await; // identity_type: automation

    let params = ProfileBootstrapParams {
        tags: None,
        credential: Some("shared".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
            secret: "sk-replacement".to_owned(),
            env_var: None,
            expires_at: None,
            secret_source: Some("stdin".to_owned()),
            identity_type: Some("human".to_owned()),
        }),
    };
    let challenge = challenge_of(h.call(METHOD_CREDENTIAL_BOOTSTRAP, &params, "shared").await);
    assert!(
        challenge
            .description
            .contains("change credential 'shared''s identity_type from 'automation' to 'human'"),
        "{}",
        challenge.description
    );
}

/// A caller at the per-uid credential cap can still re-authenticate a credential it holds: the
/// cap bounds stored state, and a bootstrap of an existing credential adds none. A new name is
/// still refused, which is the only case the refusal's wording describes.
#[tokio::test]
async fn at_the_credential_cap_an_existing_credential_can_still_be_bootstrapped() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("held", "sk-original", None).await;
    // The cap counts the credential directories; fill the rest with the empty slots a failed
    // bootstrap would have left.
    let creds = platform::caller_root(nix::unistd::getuid().as_raw()).join("credentials");
    for i in 0..49 {
        std::fs::create_dir(creds.join(format!("filler-{i}"))).expect("fill a slot");
    }

    let err = h
        .try_bootstrap_static_secret("new", None, "sk-new")
        .await
        .expect_err("a new name at the cap is refused");
    assert!(
        err.to_string().contains("credential limit reached"),
        "{err}"
    );

    // Reached the gate rather than the cap, which is what the cap must not pre-empt.
    let challenge = challenge_of(
        h.try_bootstrap_static_secret("held", None, "sk-rotated")
            .await,
    );
    h.approve_as_root(&challenge.id).await.expect("approve");
    h.try_bootstrap_static_secret("held", None, "sk-rotated")
        .await
        .expect("a credential that exists adds no slot");
    assert_eq!(token_of(&h.get("held").await.expect("get")), "sk-rotated");
}

/// The same bar from the other side: a re-bootstrap that names no identity_type rewrites nothing,
/// so the challenge carries no tier clause and the credential keeps the tier it had. Over the real
/// write path, because the staged source carries each provider's `human` default and only the
/// write settles what is stored.
#[tokio::test]
async fn a_repeat_bootstrap_naming_no_identity_type_keeps_the_credential_s_tier() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-original", None).await; // identity_type: automation

    let params = ProfileBootstrapParams {
        tags: None,
        credential: Some("tier".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
            secret: "sk-replacement".to_owned(),
            env_var: None,
            expires_at: None,
            secret_source: Some("stdin".to_owned()),
            identity_type: None,
        }),
    };
    let challenge = challenge_of(h.call(METHOD_CREDENTIAL_BOOTSTRAP, &params, "tier").await);
    assert!(
        !challenge.description.contains("identity_type"),
        "a write that rewrites no tier names none: {}",
        challenge.description
    );

    h.approve_as_root(&challenge.id).await.expect("approve");
    h.call::<_, OkResult>(METHOD_CREDENTIAL_BOOTSTRAP, &params, "tier")
        .await
        .expect("the approved re-send is performed");
    let entry = std::fs::read_to_string(
        platform::caller_root(nix::unistd::getuid().as_raw()).join("credentials.toml"),
    )
    .expect("read credentials.toml");
    assert!(
        entry.contains("identity_type = \"automation\""),
        "the stored tier survives a bootstrap that named none: {entry}"
    );
}

/// A config that will not load still gates the overwrite, but its identity_type cannot be
/// compared, so no challenge may be raised at all: one without the rewrite would ask the
/// approver to sign for a privilege-tier change they were never shown.
#[tokio::test]
async fn bootstrap_over_an_unloadable_config_raises_no_challenge_that_omits_a_rewrite() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("shared", "sk-original", None)
        .await; // identity_type: automation
    let config_path = platform::caller_root(nix::unistd::getuid().as_raw()).join("config.toml");
    std::fs::write(&config_path, "[environments.shared\n").expect("corrupt config");

    let params = ProfileBootstrapParams {
        tags: None,
        credential: Some("intruder".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
            secret: "sk-intruder".to_owned(),
            env_var: None,
            expires_at: None,
            secret_source: Some("stdin".to_owned()),
            identity_type: Some("human".to_owned()),
        }),
    };
    match h
        .call::<_, OkResult>(METHOD_CREDENTIAL_BOOTSTRAP, &params, "shared")
        .await
    {
        Err(credsd_core::error::DaemonError::ApprovalRequired(c)) => {
            panic!(
                "raised a challenge that cannot name the rewrite: {}",
                c.description
            )
        }
        Err(e) => assert!(e.to_string().contains("config.toml"), "{e}"),
        Ok(_) => panic!("the overwrite was performed over an unloadable config"),
    }
}

/// `list` and `get` must agree about a secret the user declared dead. Before the declared expiry
/// reached the status probe, the manifest read `Active` while a fetch refused the same credential —
/// the operator saw a healthy credential and an unexplained failure at the API.
#[tokio::test]
async fn a_secret_past_its_declared_expiry_is_refused_at_bootstrap_and_saves_nothing() {
    let h = Harness::start().await;
    let past = chrono::Utc::now() - chrono::TimeDelta::minutes(1);
    let params = ProfileBootstrapParams {
        tags: None,
        credential: Some("stale".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
            secret: "sk-already-rotated".to_owned(),
            env_var: None,
            expires_at: Some(past),
            secret_source: Some("stdin".to_owned()),
            identity_type: Some("automation".to_owned()),
        }),
    };
    let err = h
        .call::<_, OkResult>(METHOD_CREDENTIAL_BOOTSTRAP, &params, "stale")
        .await
        .expect_err("an already-expired secret must not bootstrap");
    let text = err.to_string();
    assert!(text.contains("expire"), "{text}");
    assert!(
        text.contains("static-secret"),
        "the error must name the command that replaces it: {text}"
    );

    h.get("stale")
        .await
        .expect_err("a refused bootstrap must leave nothing to serve");
}

/// The manifest reports the source faithfully, so a client materializing from it projects the
/// secret as an environment variable and never into an AWS profile slot it cannot fill.
#[ignore = "environment API is unavailable"]
#[tokio::test]
async fn the_manifest_reports_a_static_secret_as_an_env_var_source() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("openai", "sk-manifest-check", None)
        .await;
    h.compose_env("openai", &["openai"]).await;

    let manifest = h.describe("openai").await;
    let entry = manifest
        .credentials
        .iter()
        .find(|c| c.credential == "openai")
        .expect("the manifest names the credential");
    assert_eq!(entry.kind, CredentialType::AccessToken);
    assert_eq!(entry.source, CredentialSourceType::StaticSecret);
    assert_eq!(
        entry.status,
        SessionStatus::Active,
        "a sealed secret with no declared expiry is active"
    );
}

/// An approved re-bootstrap with a new JWT replaces what `get` serves — a cached provider or a
/// stale `CallerState` would keep serving the old one.
#[tokio::test]
async fn bootstrapping_a_new_jwt_replaces_what_get_serves() {
    let h = Harness::start().await;
    let first = jwt_expiring_in(3600);
    h.bootstrap_jwt("gh", &first, None).await;
    assert_eq!(token_of(&h.get("gh").await.expect("get")), first);

    let second = jwt_expiring_in(7200);
    assert_ne!(first, second);
    // Replacing an existing credential is gated; approve it and re-send, as `creds` does.
    let params = ProfileBootstrapParams {
        tags: None,
        credential: Some("gh".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::Jwt(ProviderParamsJwt {
            jwt: second.clone(),
            env_var: None,
            identity_type: Some("automation".to_owned()),
        }),
    };
    let challenge = challenge_of(h.call(METHOD_CREDENTIAL_BOOTSTRAP, &params, "gh").await);
    h.approve_as_root(&challenge.id).await.expect("approve");
    let _: OkResult = h
        .call(METHOD_CREDENTIAL_BOOTSTRAP, &params, "gh")
        .await
        .expect("approved re-send");

    assert_eq!(
        token_of(&h.get("gh").await.expect("get")),
        second,
        "the re-bootstrapped token must be the one served"
    );
}

/// An expired token is an error naming the re-seal, not a re-auth prompt (there is no
/// interactive flow) and not a served credential. Asserted over the socket because the message
/// is the entire remediation — a caller sees this string and nothing else.
#[tokio::test]
async fn an_expired_jwt_fails_with_the_reseal_instruction() {
    let h = Harness::start().await;
    // Sealed while still valid, then expired by the time it is served. `-1` would be refused at
    // seal time (persist_token validates), which is a different property — asserted in the
    // provider's own tests.
    h.bootstrap_jwt("gh", &jwt_expiring_in(1), None).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let err = h
        .get("gh")
        .await
        .expect_err("an expired token must not serve");
    let text = err.to_string();
    assert!(text.contains("expired"), "{text}");
    // The remediation must be the command that actually re-seals. `creds login` has nothing to run
    // for this source, so naming it would send the caller to a no-op.
    assert!(text.contains("creds bootstrap"), "{text}");
    // Not a re-auth: that would tell a client to run an interactive flow this source lacks.
    assert!(
        !matches!(err, credsd_core::error::DaemonError::ReauthRequired(_)),
        "{text}"
    );
}

/// A jwt source has no interactive login, so `login` on it is refused with the command that does
/// work: an `Ok` there would read as "refreshed".
#[tokio::test]
async fn login_refuses_a_jwt_source_with_the_reseal_command() {
    let h = Harness::start().await;
    h.bootstrap_jwt("gh", &jwt_expiring_in(3600), None).await;

    let named = ProfileLoginParams {
        credential: "gh".to_owned(),
        request_id: None,
    };
    let err = h
        .call::<_, OkResult>(METHOD_CREDENTIAL_LOGIN, &named, "gh")
        .await
        .expect_err("a jwt credential has no login to run");
    let text = err.to_string();
    assert!(text.contains("no interactive login"), "{text}");
    assert!(text.contains("creds bootstrap --credential gh"), "{text}");
}

/// A login runs under the same per-uid lock `commit_bootstrap` and `profile/import` take, so a
/// login queued behind one of those waits rather than racing it into the same credential
/// directory — and gives up on its wait budget rather than parking, reporting that it sealed
/// nothing. The jwt source never reaches the network: `login_one` reports it unattended before
/// touching any provider, so this exercises the lock and nothing else.
#[tokio::test]
async fn a_login_behind_a_held_lock_gives_up_without_writing() {
    let h = Harness::start().await;
    h.bootstrap_jwt("gh", &jwt_expiring_in(3600), None).await;

    let uid = nix::unistd::getuid().as_raw();
    let held = h.daemon.bootstrap_lock(uid).lock_owned().await;

    let sweep = ProfileLoginParams {
        credential: "gh".to_owned(),
        request_id: None,
    };
    let err = h
        .call::<_, OkResult>(METHOD_CREDENTIAL_LOGIN, &sweep, "gh")
        .await
        .expect_err("a login cannot proceed while the write lock is held elsewhere");
    let text = err.to_string();
    assert!(text.contains("write lock"), "{text}");
    assert!(text.contains("nothing was written"), "{text}");

    // Once the lock is free the login runs: a jwt source has no flow, so it is refused for that
    // reason, not for the lock.
    drop(held);
    let err = h
        .call::<_, OkResult>(METHOD_CREDENTIAL_LOGIN, &sweep, "gh")
        .await
        .expect_err("a jwt source has no login");
    assert!(err.to_string().contains("no interactive login"), "{err}");
}

/// The other half of the bound: a login that stalls mid-flow is cut off and its lock released,
/// so one parked login cannot keep every other write for that uid waiting indefinitely. The MFA
/// prompt is the stall — the respond slot is never filled — and the hold budget, not the much
/// longer interactive-step budget, is what ends it. Asserted by taking the lock afterward: a
/// login cut off while keeping its guard would leave this failing.
///
/// Calls the handler rather than the socket, because the socket path would deliver the MFA
/// progress notification to a client that has no handler for one. The lock is the same either
/// way: both reach it through the served daemon's per-uid registry.
#[tokio::test]
async fn a_login_that_stalls_is_cut_off_and_releases_the_lock() {
    let h = Harness::start().await;
    h.bootstrap_iam_user_with_mfa("mfa").await;

    let uid = nix::unistd::getuid().as_raw();
    let request = credsd_core::rpc::Request::with_params(
        credsd_core::rpc::Id::Number(1.into()),
        METHOD_CREDENTIAL_LOGIN,
        &ProfileLoginParams {
            credential: "mfa".to_owned(),
            request_id: None,
        },
    )
    .expect("login params serialize to an object");
    let peer = crate::server::routes::PeerInfo {
        uid: Some(uid),
        pid: Some(std::process::id() as i32),
        auth: crate::server::routes::CallerAuth::Authorized {
            uid,
            root: platform::caller_root(uid),
        },
        executable: None,
        login_uid: None,
    };
    // Capacity for the MFA prompt the login emits before it blocks, so it stalls waiting for an
    // answer rather than on a full channel.
    let (notif_tx, _notif_rx) = tokio::sync::mpsc::channel(8);

    let err = crate::server::bootstrap::handle_profile_login(
        &request,
        &peer,
        &h.daemon,
        notif_tx,
        Arc::new(std::sync::Mutex::new(None)),
    )
    .await
    .expect_err("a login awaiting an MFA code that never arrives must not hang forever");
    assert!(err.message.contains("did not finish"), "{}", err.message);

    assert!(
        h.daemon.bootstrap_lock(uid).try_lock().is_ok(),
        "the cut-off login kept the write lock"
    );
}

/// A client that disconnects while the daemon is blocked waiting for an answer — a Ctrl-C, or
/// any other way the process ends mid-bootstrap — must not leave the uid's one-login-at-a-time
/// slot claimed until `CALLBACK_TIMEOUT` (five minutes). `serve_connection` aborts the orphaned
/// task once it notices the socket closed; the task's `LoginClaim` releases the slot as it
/// unwinds.
///
/// Uses `bootstrap`, not `login`: a login holds `bootstrap_lock` across its own flow with a
/// hold budget that is itself shortened under `cfg(test)` (`LOGIN_LOCK_BUDGET`), which would
/// end the task on its own and pass this test whether or not the fix under test exists. A
/// bootstrap holds no such lock across the interactive wait, so the only thing that can end the
/// task here is the abort this test is checking for. `aws-login --remote` blocks in
/// `await_selection` on a plain oneshot with no real network call, so nothing needs mocking.
///
/// Goes over the real socket, unlike the lock test above it, because this is exactly the layer
/// the fix lives in: `serve_connection`'s per-connection read loop and the task handle it now
/// tracks. A direct `handle_profile_bootstrap` call would skip the thing under test.
#[tokio::test]
async fn disconnecting_mid_bootstrap_releases_the_uid_login_claim() {
    use credsd_core::rpc::{codec, Id, ProviderParamsAwsLogin, Request};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let h = Harness::start().await;
    let uid = nix::unistd::getuid().as_raw();

    let mut stream = UnixStream::connect(&h.socket).await.expect("connect");
    let request = Request::with_params(
        Id::Number(1.into()),
        METHOD_CREDENTIAL_BOOTSTRAP,
        &ProfileBootstrapParams {
            tags: None,
            credential: Some("aws-login-stall".to_owned()),
            name_prefix: None,
            request_id: None,
            provider: ProviderParams::AwsLogin(ProviderParamsAwsLogin {
                region: "us-east-1".to_owned(),
                callback_port: None,
                remote: true,
                identity_type: None,
            }),
        },
    )
    .expect("bootstrap params serialize to an object");
    stream
        .write_all(&codec::encode_request(&request).expect("encode request"))
        .await
        .expect("send bootstrap request");

    // Read notification lines until the authorize-code prompt arrives — the daemon is now
    // blocked in `await_selection`, holding the uid's `LoginClaim`.
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader
            .read_until(b'\n', &mut line)
            .await
            .expect("read notification line");
        assert!(
            n > 0,
            "daemon closed the connection before prompting for the authorization code"
        );
        let raw: serde_json::Value =
            serde_json::from_slice(&line).expect("notification line is JSON");
        if raw
            .get("params")
            .and_then(|p| p.get("type"))
            .and_then(|t| t.as_str())
            == Some("authorize_code")
        {
            break;
        }
    }

    // Drop the connection without answering — what a Ctrl-C leaves behind.
    drop(reader);
    drop(write_half);

    // Without the fix this stays claimed until `CALLBACK_TIMEOUT` (five minutes, not
    // test-shortened — see `INTERACTIVE_STEP_LIMIT`); with it, the aborted task's `LoginClaim`
    // releases the slot within a connection-loop iteration of the disconnect.
    let mut released = false;
    for _ in 0..40 {
        if h.daemon.claim_login(uid).is_some() {
            released = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        released,
        "uid login claim was not released within 2s of the client disconnecting"
    );
}

/// A JWT whose lifetime cannot be read must be refused at the boundary, before anything is
/// written — otherwise the credential exists on disk with an unknowable expiry.
#[tokio::test]
async fn a_jwt_with_no_readable_expiry_is_refused_at_bootstrap() {
    let h = Harness::start().await;
    let params = ProfileBootstrapParams {
        tags: None,
        credential: Some("bad".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::Jwt(ProviderParamsJwt {
            jwt: "not-a-jwt".to_owned(),
            env_var: None,
            identity_type: None,
        }),
    };
    let err: credsd_core::error::DaemonError = h
        .call::<_, OkResult>(METHOD_CREDENTIAL_BOOTSTRAP, &params, "bad")
        .await
        .expect_err("a malformed JWT must not bootstrap");
    assert!(err.to_string().contains("JWT"), "{err}");

    // Nothing written: no credential to serve, and no config entry pointing at absent material.
    assert!(h.get("bad").await.is_err());
    assert!(!sealed_token_path(
        &platform::caller_root(nix::unistd::getuid().as_raw()),
        "bad"
    )
    .exists());
}

fn sealed_token_path(caller_root: &Path, credential: &str) -> PathBuf {
    caller_root
        .join("credentials")
        .join(credential)
        .join("jwt.enc")
}

fn sealed_key_path(caller_root: &Path, credential: &str) -> PathBuf {
    caller_root
        .join("credentials")
        .join(credential)
        .join("iam_user.enc")
}

fn import_profile(name: &str) -> ImportProfile {
    import_profile_keyed(name, "AKIAIOSFODNN7EXAMPLE")
}

fn import_profile_keyed(name: &str, access_key_id: &str) -> ImportProfile {
    ImportProfile {
        name: name.to_owned(),
        access_key_id: access_key_id.to_owned(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
        region: "us-west-2".to_owned(),
        identity_type: None,
    }
}

/// `profile/import` over the socket seals a batch into the per-uid tree the daemon serves.
/// Covers the properties the client-side loop this replaces could not: the batch lands where
/// `credential/get` serves from, an invalid name and an already-present name are per-profile skips that do
/// not abort the batch, and re-import is additive rather than a clobber. (First-time
/// auto-provisioning is covered separately by `import_auto_provisions_a_first_time_caller`.)
#[tokio::test]
async fn import_seals_a_batch_into_the_served_tree_and_skips_bad_and_existing_names() {
    let h = Harness::start().await;
    let caller_root = platform::caller_root(nix::unistd::getuid().as_raw());

    // A batch with two valid profiles and one invalid name. The invalid one is a skip, not a
    // batch abort (Req 2.4).
    let result = h
        .import(
            vec![
                import_profile("work"),
                import_profile("prod"),
                import_profile("../evil"),
            ],
            false,
        )
        .await;
    let status = |name: &str| {
        result
            .outcomes
            .iter()
            .find(|o| o.name == name)
            .unwrap_or_else(|| panic!("no outcome for {name}"))
            .status
    };
    assert_eq!(status("work"), ImportStatus::Imported);
    assert_eq!(status("prod"), ImportStatus::Imported);
    assert_eq!(status("../evil"), ImportStatus::Skipped);
    assert!(sealed_key_path(&caller_root, "work").exists());
    assert!(sealed_key_path(&caller_root, "prod").exists());

    // Landed in the served per-uid tree as iam-user credentials, with no environment written
    // (credential-retrieval-api Requirement 16 AC 1).
    assert!(!caller_root.join("config.toml").exists());
    let listed: credsd_core::rpc::ListResult = h
        .call(
            credsd_core::rpc::METHOD_CREDENTIAL_LIST,
            &credsd_core::rpc::ListParams::default(),
            "list",
        )
        .await
        .expect("list");
    let entry = listed
        .credentials
        .iter()
        .find(|e| e.credential == "work")
        .expect("work listed");
    assert_eq!(
        entry.kind,
        credsd_core::credentials::CredentialType::SessionCredentials
    );

    // Additive: an existing name skips, a new one in the same batch still imports.
    let again = h
        .import(vec![import_profile("work"), import_profile("new")], false)
        .await;
    let again_status = |name: &str| {
        again
            .outcomes
            .iter()
            .find(|o| o.name == name)
            .unwrap_or_else(|| panic!("no outcome for {name}"))
            .status
    };
    assert_eq!(again_status("work"), ImportStatus::Skipped);
    assert_eq!(again_status("new"), ImportStatus::Imported);

    assert_eq!(h.source_of("work"), CredentialSourceType::AwsIamUser);
}

/// `dry_run` evaluates the decision against the real per-uid tree and writes nothing: a new name
/// reports `would_import` and no sealed material lands (Req 2.5).
#[tokio::test]
async fn import_dry_run_reports_without_writing() {
    let h = Harness::start().await;
    let caller_root = platform::caller_root(nix::unistd::getuid().as_raw());

    let result = h.import(vec![import_profile("stage")], true).await;
    assert_eq!(result.outcomes[0].status, ImportStatus::WouldImport);
    assert!(
        !sealed_key_path(&caller_root, "stage").exists(),
        "dry_run must not seal material"
    );
}

/// Profiles reach the daemon through the client's discovery. A profile whose credentials-file
/// `region` is set imports, and one that names no region anywhere is skipped with a message that
/// names `--region`. A dry run reports the same skip, and nothing is sealed for the skipped one.
#[tokio::test]
async fn import_takes_the_credentials_file_region_and_skips_a_profile_with_none() {
    let h = Harness::start().await;
    let caller_root = platform::caller_root(nix::unistd::getuid().as_raw());
    let dir = tempfile::tempdir().expect("tempdir");
    let creds = dir.path().join("credentials");
    std::fs::write(
        &creds,
        "[named]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = eu-central-1\n\n[unnamed]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    )
    .expect("write credentials");
    // Explicit inputs: no flag, no environment, no config file, so the host's ~/.aws is never read.
    let discover = || {
        credsd_core::import::discover_import_profiles(
            &credsd_core::import::ImportSource::AwsProfiles {
                path: Some(creds.clone()),
                region: credsd_core::import::RegionInputs::default(),
            },
        )
        .expect("discover")
    };
    let status = |r: &ImportResult, name: &str| {
        r.outcomes
            .iter()
            .find(|o| o.name == name)
            .unwrap_or_else(|| panic!("no outcome for {name}"))
            .status
    };

    let dry = h.import(discover(), true).await;
    assert_eq!(status(&dry, "named"), ImportStatus::WouldImport);
    assert_eq!(status(&dry, "unnamed"), ImportStatus::WouldSkip);
    assert!(!sealed_key_path(&caller_root, "named").exists());

    let result = h.import(discover(), false).await;
    assert_eq!(status(&result, "named"), ImportStatus::Imported);
    assert_eq!(status(&result, "unnamed"), ImportStatus::Skipped);
    let reason = result
        .outcomes
        .iter()
        .find(|o| o.name == "unnamed")
        .and_then(|o| o.reason.as_deref())
        .unwrap_or_default();
    assert!(reason.contains("--region"), "{reason}");
    assert!(sealed_key_path(&caller_root, "named").exists());
    assert!(
        !sealed_key_path(&caller_root, "unnamed").exists(),
        "a region-less profile must not be sealed"
    );
}

/// A first-time caller (no `callers/<uid>/`) is auto-provisioned by import, matching bootstrap
/// (Req 2.7). The harness provisions on start, so this removes the caller root first to reach the
/// `Denied(NoRoot)` branch in `authorize_for_bootstrap`, then asserts `owner` is recreated and the
/// import lands.
#[tokio::test]
async fn import_auto_provisions_a_first_time_caller() {
    let h = Harness::start().await;
    let caller_root = platform::caller_root(nix::unistd::getuid().as_raw());

    // Undo the harness's provisioning so this uid looks first-time to the daemon.
    std::fs::remove_dir_all(&caller_root).expect("remove caller root");
    assert!(
        !caller_root.join("owner").exists(),
        "precondition: no owner"
    );

    let result = h.import(vec![import_profile("work")], false).await;
    assert_eq!(result.outcomes[0].status, ImportStatus::Imported);
    assert!(
        caller_root.join("owner").exists(),
        "import must auto-provision callers/<uid>/owner"
    );
    assert!(sealed_key_path(&caller_root, "work").exists());
}

/// A hand edit to `config.toml` is seen without a restart. `evict_caller` covers only the
/// daemon's own writes, so before the stat-on-access check a hand-edited config was invisible for
/// the process lifetime. The edit adds an environment table, which a caller config may not hold
/// (`credential-only-addressing` Requirement 5), so a daemon that notices refuses to serve.
///
/// Ordering matters: the first `get` forces the cached `CallerState` into existence. Without it
/// the later lookup would be a cold load and would refuse whether or not freshness is checked.
#[tokio::test]
async fn an_external_config_edit_is_picked_up_without_a_restart() {
    let h = Harness::start().await;
    let caller_root = platform::caller_root(nix::unistd::getuid().as_raw());

    h.bootstrap_jwt("alpha", &jwt_expiring_in(3600), None).await;
    h.seed_config(SEED_CONFIG).await;
    h.get("alpha")
        .await
        .expect("served, and the caller state is cached");

    let config_path = caller_root.join("config.toml");
    let before = std::fs::read_to_string(&config_path).expect("read config");
    let mtime_before = std::fs::metadata(&config_path)
        .and_then(|m| m.modified())
        .expect("stat config");
    std::fs::write(
        &config_path,
        format!("{before}\n[environments.beta]\ncredentials = [\"alpha\"]\n"),
    )
    .expect("write config");

    // Detection is mtime-based, and a write in the same mtime tick as the bootstrap's own write
    // leaves the stamp unchanged, which made this test flaky. Move the stamp explicitly instead.
    let mtime_after = mtime_before
        .checked_add(std::time::Duration::from_secs(2))
        .expect("mtime overflow");
    std::fs::File::options()
        .write(true)
        .open(&config_path)
        .and_then(|f| f.set_modified(mtime_after))
        .expect("set config mtime");

    let err = h
        .get("alpha")
        .await
        .expect_err("the edited config is seen, and refused");
    // The edit changes the sealed canonical form, so drift is what refuses first; revalidation
    // then refuses to seal the table (Requirement 5.2).
    assert!(err.to_string().contains("creds revalidate"), "{err}");
    let refused = revalidate(&h)
        .await
        .expect_err("an environment table is never sealed");
    assert!(refused.to_string().contains("not supported"), "{refused}");
}

/// Records in drift are not sealed over by a first bootstrap of another name, and no approval
/// admits one: a bootstrap seals both toml files whole, so it would ratify whatever is there, and
/// revalidation is the only way to ratify a file (drift-detection Requirements 3.9, 4, 5.2).
#[tokio::test]
async fn a_first_bootstrap_over_records_in_drift_is_refused_until_revalidated() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("kept", "sk-kept", None).await;
    let root = platform::caller_root(nix::unistd::getuid().as_raw());
    std::fs::remove_file(root.join("credentials_snapshot.enc")).expect("remove snapshot");

    let err = h
        .try_bootstrap_static_secret("fresh", None, "sk-fresh")
        .await
        .expect_err("a bootstrap over drift is refused");
    assert!(
        !matches!(err, credsd_core::error::DaemonError::ApprovalRequired(_)),
        "drift is not salvageable by an approval: {err}"
    );
    assert!(err.to_string().contains("creds revalidate"), "{err}");

    let challenge = challenge_of(revalidate(&h).await);
    h.approve_as_root(&challenge.id).await.expect("approve");
    h.try_bootstrap_static_secret("fresh", None, "sk-fresh")
        .await
        .expect("a bootstrap over revalidated records is a first write again");
    assert_eq!(token_of(&h.get("fresh").await.expect("get")), "sk-fresh");
    assert_eq!(token_of(&h.get("kept").await.expect("get")), "sk-kept");
}

/// Login seals fresh material for whatever the records name, so it refuses records in drift.
/// Static secrets have no interactive flow, so without the refusal this would succeed as a no-op;
/// the refusal is what the test pins.
#[tokio::test]
async fn login_refuses_records_in_drift() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("login", "sk-login", None).await;
    let root = platform::caller_root(nix::unistd::getuid().as_raw());
    std::fs::write(root.join("config.toml"), "# edited by hand\n").expect("hand edit");

    let params = credsd_core::rpc::ProfileLoginParams {
        credential: "login".to_owned(),
        request_id: None,
    };
    let err = h
        .call::<_, OkResult>(credsd_core::rpc::METHOD_CREDENTIAL_LOGIN, &params, "login")
        .await
        .expect_err("login over records in drift is refused");
    assert!(err.to_string().contains("creds revalidate"), "{err}");
}

/// Records that do not parse are refused outright, not offered as a challenge: an approval could
/// never complete a write over them.
#[tokio::test]
async fn bootstrap_refuses_records_that_do_not_parse() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("kept", "sk-kept", None).await;
    let root = platform::caller_root(nix::unistd::getuid().as_raw());
    std::fs::write(root.join("config.toml"), "[envs\nnot = toml = \n").expect("hand edit");

    let err = h
        .try_bootstrap_static_secret("fresh", None, "sk-fresh")
        .await
        .expect_err("a bootstrap over unparseable records is refused");
    assert!(
        !matches!(err, credsd_core::error::DaemonError::ApprovalRequired(_)),
        "{err}"
    );
    assert!(err.to_string().contains("does not parse"), "{err}");
    assert!(
        err.to_string()
            .contains("Correct or restore it, then run: creds revalidate"),
        "{err}"
    );
}

/// Sealed data with no credentials.toml is drift — the record names the file, so its deletion is
/// not absence (Requirement 10.3): the removal is refused and the sealed data stays.
#[tokio::test]
async fn removing_a_credential_refuses_sealed_data_with_no_credentials_file() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("gone", "sk-gone", None).await;
    let root = platform::caller_root(nix::unistd::getuid().as_raw());
    std::fs::remove_file(root.join("credentials.toml")).expect("remove credentials.toml");

    let err = h
        .remove_credential("gone")
        .await
        .expect_err("removal over drift is refused");
    assert!(err.to_string().contains("has been deleted"), "{err}");
    assert!(
        sealed_dir("gone").exists(),
        "sealed data must survive a refused removal"
    );
}

/// Sealed material on disk for `credential` with no source entry naming it: what a removal whose
/// sweep failed leaves behind.
fn leave_sealed_data(credential: &str) {
    let dir = sealed_dir(credential);
    std::fs::create_dir_all(&dir).expect("create sealed dir");
    std::fs::write(dir.join("left-behind.enc"), b"x").expect("leave sealed data");
}

fn sealed_dir(credential: &str) -> PathBuf {
    platform::caller_root(nix::unistd::getuid().as_raw())
        .join("credentials")
        .join(credential)
}

/// Removing an environment is gated: it survives an unapproved request, approval performs the
/// removal with nothing to re-send, and its credential is left in place either way.
#[ignore = "environment API is unavailable"]
#[tokio::test]
async fn removing_an_environment_waits_for_approval_and_keeps_its_credential() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("svc", "sk-value", None).await;
    h.compose_env("svc", &["svc"]).await;

    let challenge = challenge_of(h.remove_env("svc").await);
    assert!(
        challenge.description.contains("remove environment 'svc'"),
        "{}",
        challenge.description
    );
    assert_eq!(
        token_of(&h.get("svc").await.expect("still served before approval")),
        "sk-value"
    );

    h.approve_as_root(&challenge.id).await.expect("approve");
    assert!(
        matches!(
            h.get_in_env("svc").await,
            Err(credsd_core::error::DaemonError::EnvNotFound(_))
        ),
        "the environment is gone once approved"
    );
    assert_eq!(
        token_of(&h.get("svc").await.expect("still served by name")),
        "sk-value"
    );
    assert!(
        sealed_dir("svc").exists(),
        "environment removal keeps the credential's sealed data"
    );
}

/// Removing a credential destroys material a same-uid process could not restore, so it waits for
/// approval, and approval deletes both the source entry and the sealed directory.
#[tokio::test]
async fn removing_a_credential_waits_for_approval_then_deletes_its_sealed_data() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("gone", "sk-value", None).await;

    let challenge = challenge_of(h.remove_credential("gone").await);
    assert!(
        challenge
            .description
            .contains("remove credential 'gone' and its sealed data"),
        "{}",
        challenge.description
    );
    assert!(
        sealed_dir("gone").exists(),
        "nothing deleted before approval"
    );

    h.approve_as_root(&challenge.id).await.expect("approve");
    assert!(
        !sealed_dir("gone").exists(),
        "sealed data deleted on approval"
    );
    assert!(
        matches!(
            h.remove_credential("gone").await,
            Err(credsd_core::error::DaemonError::EnvNotFound(
                credsd_core::error::NotFound {
                    kind: credsd_core::error::Addressed::Credential,
                    ..
                }
            ))
        ),
        "a second removal finds nothing"
    );
}

/// The snapshot changes between the challenge and its approval: the approval is refused against
/// the disk, before anything is written, and the sealed data stays. Once the snapshot matches
/// the file again (here the test restores the bytes it saved), a new request completes.
#[tokio::test]
async fn a_snapshot_changed_after_the_challenge_refuses_the_approval() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("keep", "sk-keep", None).await;
    h.bootstrap_static_secret("gone", "sk-gone", None).await;
    let challenge = challenge_of(h.remove_credential("gone").await);

    let root = platform::caller_root(nix::unistd::getuid().as_raw());
    let snapshot = root.join("credentials_snapshot.enc");
    let sealed_before = std::fs::read(&snapshot).expect("the snapshot");
    std::fs::remove_file(&snapshot).expect("replace the snapshot");
    std::fs::create_dir(&snapshot).expect("block the snapshot");
    let refused = h
        .approve_as_root(&challenge.id)
        .await
        .expect_err("a snapshot that no longer matches must refuse the approval");
    assert!(
        refused.to_string().contains("sealed snapshot"),
        "refused for drift, got {refused}"
    );
    assert!(sealed_dir("gone").exists(), "sealed data kept on refusal");
    assert!(
        std::fs::read_to_string(root.join("credentials.toml"))
            .expect("credentials.toml")
            .contains("[gone]"),
        "the toml is untouched on refusal"
    );

    std::fs::remove_dir(&snapshot).expect("unblock the snapshot");
    std::fs::write(&snapshot, sealed_before).expect("restore the snapshot");
    let retry = challenge_of(h.remove_credential("gone").await);
    h.approve_as_root(&retry.id)
        .await
        .expect("the retry completes the removal");
    assert!(!sealed_dir("gone").exists(), "sealed data deleted on retry");
    assert!(
        !std::fs::read_to_string(root.join("credentials.toml"))
            .expect("credentials.toml")
            .contains("[gone]"),
        "the toml no longer lists the credential"
    );
}

/// The snapshot is removed after the caller's state was cached: the request still refuses,
/// because drift is measured from the disk rather than from a cache that does not track it.
#[tokio::test]
async fn a_snapshot_removed_after_the_cache_filled_refuses_a_removal() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("keep", "sk-keep", None).await;
    h.bootstrap_static_secret("gone", "sk-gone", None).await;
    h.get("keep").await.expect("get fills the caller cache");

    let root = platform::caller_root(nix::unistd::getuid().as_raw());
    std::fs::remove_file(root.join("credentials_snapshot.enc")).expect("remove the snapshot");
    let refused = h
        .remove_credential("gone")
        .await
        .expect_err("a removal with no snapshot must be refused");
    assert!(
        refused.to_string().contains("sealed snapshot"),
        "refused for drift, got {refused}"
    );
}

/// A hand edit that drops an entry, then a removal of that entry: the removal is refused rather
/// than resealed, so the edit is not trusted as a side effect and the sealed data stays.
#[tokio::test]
async fn a_removal_over_a_hand_edit_is_refused_and_keeps_the_sealed_data() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("keep", "sk-keep", None).await;
    h.bootstrap_static_secret("gone", "sk-gone", None).await;

    let root = platform::caller_root(nix::unistd::getuid().as_raw());
    let path = root.join("credentials.toml");
    let before = std::fs::read_to_string(&path).expect("credentials.toml");
    let edited = before.split("[gone]").next().expect("split").to_owned();
    std::fs::write(&path, &edited).expect("hand edit drops the entry");

    let refused = h
        .remove_credential("gone")
        .await
        .expect_err("a removal over drift must be refused before any challenge");
    assert!(
        refused.to_string().contains("sealed snapshot"),
        "refused for drift, got {refused}"
    );
    assert!(sealed_dir("gone").exists(), "sealed data kept on refusal");
    assert_eq!(
        std::fs::read_to_string(&path).expect("credentials.toml"),
        edited,
        "the hand edit is kept, not resealed"
    );
}

/// What approval could only fail is refused before a challenge exists: an unknown name is not
/// found, and raises nothing to approve, so a challenge never confirms that a name exists.
#[tokio::test]
async fn removals_that_cannot_succeed_are_refused_without_a_challenge() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("held", "sk-value", None).await;

    assert!(matches!(
        h.remove_credential("never-existed").await,
        Err(credsd_core::error::DaemonError::EnvNotFound(
            credsd_core::error::NotFound {
                kind: credsd_core::error::Addressed::Credential,
                ..
            }
        ))
    ));
}

/// An approved removal is performed against the state it was shown. When the records change in
/// between, the approval is discarded unperformed.
#[tokio::test]
async fn an_approved_removal_is_discarded_when_the_records_changed() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("kept", "sk-value", None).await;

    let challenge = challenge_of(h.remove_credential("kept").await);
    // A first bootstrap elsewhere is ungated, and it rewrites both config files.
    h.bootstrap_static_secret("other", "sk-other", None).await;

    let err = h
        .approve_as_root(&challenge.id)
        .await
        .expect_err("a stale approval must not be performed");
    assert!(
        matches!(
            err,
            credsd_core::error::DaemonError::ApprovalRefused {
                reason: credsd_core::presence::RefusalReason::BaseStateChanged,
                ..
            }
        ),
        "{err}"
    );
    assert!(
        matches!(
            h.approve_as_root(&challenge.id).await,
            Err(credsd_core::error::DaemonError::RequestNotFound)
        ),
        "a changed base state discards the request (Requirement 8.3)"
    );
    assert_eq!(
        token_of(&h.get("kept").await.expect("still served")),
        "sk-value"
    );
}

/// A record that will not read is not confirmed to be in its recorded base state, so the approval
/// is discarded the same way a changed one is — not returned as an internal error, which would
/// spend a verified proof with nothing in the audit record to show it.
///
/// The record is made unreadable by putting a directory where the file belongs, because root
/// bypasses mode bits and a chmod would leave this asserting nothing when run as root.
#[tokio::test]
async fn an_approved_removal_is_discarded_when_the_records_cannot_be_read() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("kept", "sk-value", None).await;

    let challenge = challenge_of(h.remove_credential("kept").await);
    let credentials_toml =
        platform::caller_root(nix::unistd::getuid().as_raw()).join("credentials.toml");
    std::fs::remove_file(&credentials_toml).expect("remove credentials.toml");
    std::fs::create_dir(&credentials_toml).expect("unreadable credentials.toml");

    let err = h
        .approve_as_root(&challenge.id)
        .await
        .expect_err("an unconfirmable approval must not be performed");
    assert!(
        matches!(
            err,
            credsd_core::error::DaemonError::ApprovalRefused {
                reason: credsd_core::presence::RefusalReason::BaseStateChanged,
                ..
            }
        ),
        "{err}"
    );
    assert!(
        matches!(
            h.approve_as_root(&challenge.id).await,
            Err(credsd_core::error::DaemonError::RequestNotFound)
        ),
        "a base state that cannot be confirmed discards the request, like one that changed"
    );
}

/// Read one config key over the socket.
async fn config_get(h: &Harness, env: &str, key: &str) -> Option<String> {
    let params = credsd_core::rpc::ConfigGetParams {
        environment: env.to_owned(),
        key: key.to_owned(),
    };
    let result: credsd_core::rpc::ConfigGetResult = h
        .call(credsd_core::rpc::METHOD_CONFIG_GET, &params, env)
        .await
        .expect("config/get");
    result.value
}

async fn config_unset(h: &Harness, env: &str, key: &str) -> credsd_core::error::Result<OkResult> {
    let params = credsd_core::rpc::ConfigUnsetParams {
        environment: env.to_owned(),
        key: key.to_owned(),
    };
    h.call(credsd_core::rpc::METHOD_CONFIG_UNSET, &params, env)
        .await
}

/// Unsetting falls back to a default, so an unset waits for approval like a set does — and
/// approval performs it. Driven with `region`: `identity_type` would be the shorter case, since
/// bootstrap sets it, but its unset is refused outright rather than gated (see
/// `unsetting_identity_type_is_refused_rather_than_gated`).
#[ignore = "environment API is unavailable"]
#[tokio::test]
async fn unsetting_a_key_waits_for_approval() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    h.compose_env("tier", &["tier"]).await;
    let set = challenge_of(
        h.call(
            credsd_core::rpc::METHOD_CONFIG_SET,
            &credsd_core::rpc::ConfigSetParams {
                environment: "tier".to_owned(),
                key: "region".to_owned(),
                value: "eu-west-1".to_owned(),
            },
            "tier",
        )
        .await,
    );
    h.approve_as_root(&set.id).await.expect("approve the set");
    assert_eq!(
        config_get(&h, "tier", "region").await.as_deref(),
        Some("eu-west-1")
    );

    let challenge = challenge_of(config_unset(&h, "tier", "region").await);
    assert!(
        challenge
            .description
            .contains("unset region on environment 'tier' (currently eu-west-1)"),
        "{}",
        challenge.description
    );
    assert_eq!(
        config_get(&h, "tier", "region").await.as_deref(),
        Some("eu-west-1"),
        "nothing changes before approval"
    );

    h.approve_as_root(&challenge.id).await.expect("approve");
    assert_eq!(config_get(&h, "tier", "region").await, None);
}

/// `config/set` validates against `credentials.toml` as well as `config.toml` (an env-to-
/// credential privilege lattice check), so its approval base must cover both files. A drift in
/// credentials.toml alone, with config.toml untouched, must still discard the approval.
#[ignore = "environment API is unavailable"]
#[tokio::test]
async fn a_config_set_approval_is_discarded_when_only_credentials_drift() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    h.compose_env("tier", &["tier"]).await;

    let challenge = challenge_of(
        h.call(
            credsd_core::rpc::METHOD_CONFIG_SET,
            &credsd_core::rpc::ConfigSetParams {
                environment: "tier".to_owned(),
                key: "region".to_owned(),
                value: "eu-west-1".to_owned(),
            },
            "tier",
        )
        .await,
    );

    let caller_root = platform::caller_root(nix::unistd::getuid().as_raw());
    let credentials_path = caller_root.join("credentials.toml");
    let before = std::fs::read_to_string(&credentials_path).expect("read credentials.toml");
    std::fs::write(&credentials_path, format!("{before}\n# hand edit\n"))
        .expect("drift credentials.toml, leaving config.toml untouched");

    let err = h
        .approve_as_root(&challenge.id)
        .await
        .expect_err("a base that moved under credentials.toml alone must still be refused");
    assert!(
        matches!(
            err,
            credsd_core::error::DaemonError::ApprovalRefused {
                reason: credsd_core::presence::RefusalReason::BaseStateChanged,
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(
        config_get(&h, "tier", "region").await,
        None,
        "the set must not have applied"
    );
}

/// A key that is not set has nothing to approve: unsetting it succeeds without a challenge.
#[ignore = "environment API is unavailable"]
#[tokio::test]
async fn unsetting_a_key_that_is_not_set_asks_for_nothing() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("plain", "sk-value", None).await;
    h.compose_env("plain", &["plain"]).await;
    config_unset(&h, "plain", "sdk.endpoint_url")
        .await
        .expect("a no-op unset is not gated");
}

/// Import never replaces a credential, but its seal can land on sealed material a removed
/// credential left behind. That batch waits for one approval; a batch of fresh names, and any dry
/// run, is not gated at all.
#[tokio::test]
async fn an_import_over_sealed_data_left_behind_is_gated() {
    let h = Harness::start().await;
    let fresh = h.import(vec![import_profile("brand-new")], false).await;
    assert_eq!(fresh.outcomes[0].status, ImportStatus::Imported);

    leave_sealed_data("prod");
    let dry = h.import(vec![import_profile("prod")], true).await;
    assert_eq!(dry.outcomes[0].status, ImportStatus::WouldImport);

    let params = ImportParams {
        profile: import_profile("prod"),
        dry_run: false,
    };
    let gated: credsd_core::error::Result<ImportOutcome> =
        h.call(METHOD_CREDENTIAL_IMPORT, &params, "import").await;
    let challenge = match gated {
        Err(credsd_core::error::DaemonError::ApprovalRequired(c)) => *c,
        Err(other) => panic!("expected APPROVAL_REQUIRED, got {other}"),
        Ok(_) => panic!("expected APPROVAL_REQUIRED, but the import was performed"),
    };
    assert!(
        challenge.description.contains(
            "replace sealed data left on disk for credential 'prod' with a new iam-user \
             (access key AKIAIOSFODNN7EXAMPLE)"
        ),
        "{}",
        challenge.description
    );
    h.approve_as_root(&challenge.id).await.expect("approve");
    let applied: ImportOutcome = h
        .call(METHOD_CREDENTIAL_IMPORT, &params, "import")
        .await
        .expect("the approved re-send imports");
    assert_eq!(applied.status, ImportStatus::Imported);
}

/// The approver's only way to tell a benign re-import from a key substitution is the access key
/// id the batch carries, so the challenge must name the incoming key rather than a fixed example.
#[tokio::test]
async fn an_import_challenge_names_the_incoming_access_key() {
    let h = Harness::start().await;
    leave_sealed_data("prod");

    let params = ImportParams {
        profile: import_profile_keyed("prod", "AKIAI44QH8DHBEXAMPLE"),
        dry_run: false,
    };
    let gated: credsd_core::error::Result<ImportOutcome> =
        h.call(METHOD_CREDENTIAL_IMPORT, &params, "import").await;
    let challenge = match gated {
        Err(credsd_core::error::DaemonError::ApprovalRequired(c)) => *c,
        Err(other) => panic!("expected APPROVAL_REQUIRED, got {other}"),
        Ok(_) => panic!("expected APPROVAL_REQUIRED, but the import was performed"),
    };
    assert!(
        challenge.description.contains("AKIAI44QH8DHBEXAMPLE"),
        "{}",
        challenge.description
    );
}

/// Nothing validates `access_key_id`'s shape before it reaches the challenge, so an ESC byte in
/// it must not reach the approver's terminal, or the displayed key could be made to look
/// different from the key actually imported.
#[tokio::test]
async fn an_import_challenge_escapes_control_characters_in_the_access_key() {
    let h = Harness::start().await;
    leave_sealed_data("prod");

    let params = ImportParams {
        profile: import_profile_keyed("prod", "AKIA\x1b[2JEXAMPLE"),
        dry_run: false,
    };
    let gated: credsd_core::error::Result<ImportOutcome> =
        h.call(METHOD_CREDENTIAL_IMPORT, &params, "import").await;
    let challenge = match gated {
        Err(credsd_core::error::DaemonError::ApprovalRequired(c)) => *c,
        Err(other) => panic!("expected APPROVAL_REQUIRED, got {other}"),
        Ok(_) => panic!("expected APPROVAL_REQUIRED, but the import was performed"),
    };
    assert!(
        !challenge.description.contains('\x1b'),
        "{:?}",
        challenge.description
    );
}

/// `config/set` returns its challenge as an `APPROVAL_REQUIRED` error like every other gated
/// verb, never as a success, so a client unaware of the gate observes a failure (Requirement
/// 8.1). Approval performs the write.
#[ignore = "environment API is unavailable"]
#[tokio::test]
async fn config_set_is_an_approval_required_error_until_approved() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("cfg", "sk-value", None).await;
    h.compose_env("cfg", &["cfg"]).await;
    let params = credsd_core::rpc::ConfigSetParams {
        environment: "cfg".to_owned(),
        key: "region".to_owned(),
        value: "eu-west-1".to_owned(),
    };
    let challenge = challenge_of(
        h.call(credsd_core::rpc::METHOD_CONFIG_SET, &params, "cfg")
            .await,
    );
    assert_eq!(config_get(&h, "cfg", "region").await, None);

    h.approve_as_root(&challenge.id).await.expect("approve");
    assert_eq!(
        config_get(&h, "cfg", "region").await.as_deref(),
        Some("eu-west-1")
    );
}

/// An absent `identity_type` reads as `human`, the most privileged tier, so unsetting it would
/// raise privilege. The daemon refuses outright rather than raising a challenge: an approval
/// prompt for an operation that can only grant privilege is a prompt that should not exist.
#[ignore = "environment API is unavailable"]
#[tokio::test]
async fn unsetting_identity_type_is_refused_rather_than_gated() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("cfg", "sk-value", None).await;
    h.compose_env_with("cfg", &["cfg"], "identity_type = \"automation\"\n")
        .await;
    let params = credsd_core::rpc::ConfigUnsetParams {
        environment: "cfg".to_owned(),
        key: "identity_type".to_owned(),
    };

    let result: credsd_core::error::Result<OkResult> = h
        .call(credsd_core::rpc::METHOD_CONFIG_UNSET, &params, "cfg")
        .await;

    match result {
        Err(credsd_core::error::DaemonError::ApprovalRequired(_)) => {
            panic!("a privilege-granting unset must not raise a challenge")
        }
        Err(other) => assert!(
            other.to_string().contains("human"),
            "the refusal names the tier it would grant: {other}"
        ),
        Ok(_) => panic!("expected a refusal, but the unset was performed"),
    }

    // Still settable: the key is refused for removal only, not frozen.
    let challenge = challenge_of(
        h.call(
            credsd_core::rpc::METHOD_CONFIG_SET,
            &credsd_core::rpc::ConfigSetParams {
                environment: "cfg".to_owned(),
                key: "identity_type".to_owned(),
                value: "automation".to_owned(),
            },
            "cfg",
        )
        .await,
    );
    h.approve_as_root(&challenge.id).await.expect("approve");
    assert_eq!(
        config_get(&h, "cfg", "identity_type").await.as_deref(),
        Some("automation")
    );
}

/// An identifier that names nothing is `REQUEST_NOT_FOUND`, a code of its own rather than invalid
/// params (Requirement 8.4). The refusal codes for a pending request are unit-tested in the gate:
/// this harness's peer is whoever runs the suite, and a suite run as root is a privileged
/// approver, so an "unprivileged owner" case cannot be expressed over this socket.
#[tokio::test]
async fn approving_an_unknown_request_is_not_found() {
    use credsd_core::presence::{ApproveParams, ApproveResult, METHOD_REQUEST_APPROVE};
    let h = Harness::start().await;
    h.bootstrap_static_secret("any", "sk-value", None).await;
    let missing = ApproveParams {
        id: "req-000000000000".to_owned(),
        signature: None,
    };
    let unknown: credsd_core::error::Result<ApproveResult> =
        h.call(METHOD_REQUEST_APPROVE, &missing, "any").await;
    assert!(
        matches!(
            unknown,
            Err(credsd_core::error::DaemonError::RequestNotFound)
        ),
        "{unknown:?}"
    );
}

/// `aws-login-identity` Requirements 2 and 3, over the commit the gate actually runs in: a
/// re-sign-in as the Principal on record replaces the credential ungated; a sign-in as any other
/// one raises a challenge and saves nothing; once approved, a re-run as the approved Principal
/// installs and a re-run as a third one is challenged again. A credential with no record — every
/// credential that predates identity recording — is gated on bootstrap and refused by
/// `credential/login` (2.4, 3.6). The sign-in itself is not driven here — the
/// Sign-In endpoint is not stubbable from this harness — so the signed-in identity is handed to
/// `commit_bootstrap` the way the provider flow hands it over.
#[tokio::test]
async fn an_aws_login_resign_in_is_gated_only_when_the_identity_changes() {
    use crate::server::bootstrap::{
        commit_bootstrap, login_identity_check, Gate, Staged, Staging, Subject,
    };
    use crate::server::routes::{CallerAuth, PeerInfo};
    use credsd_core::config::{AwsLoginConfig, IdentityType};
    use credsd_core::providers::aws_login::{
        parse_caller_arn, stored_identity, Identity, IDENTITY_FILE,
    };
    use credsd_core::rpc::DomainCode;
    let h = Harness::start().await;
    let uid = nix::unistd::getuid().as_raw();
    let root = platform::caller_root(uid);
    let target = root.join("credentials").join("dev");

    let source = |tier| {
        credsd_core::config::credentials::CredentialSource::AwsLogin(AwsLoginConfig {
            region: "us-east-1".to_owned(),
            callback_port: None,
            remote: false,
            identity_type: tier,
        })
    };
    let who = |arn: &str| parse_caller_arn(arn).expect("arn");
    let recorded = who("arn:aws:sts::111111111111:assumed-role/Admin/alice");

    let peer = PeerInfo {
        uid: Some(uid),
        pid: None,
        auth: CallerAuth::Unresolved,
        executable: None,
        login_uid: None,
    };
    let subject = Subject {
        credential: "dev",
        kind: "aws-login",
    };
    let staged = Staged {
        source: source(IdentityType::Human),
        identity_type: Some(IdentityType::Human),
        allowed_roles: None,
    };
    // A sign-in stages its own sealed record, as the provider's commit does.
    let stage_as = |id: &Identity| {
        let staging = Staging::create(uid).expect("staging");
        h.daemon
            .encryption
            .seal_to_file(
                &staging.path().join(IDENTITY_FILE),
                &serde_json::to_vec(id).expect("identity json"),
            )
            .expect("seal the staged identity record");
        staging
    };
    // `stored_entry` is what the entry check would have read: nothing for the first bootstrap, an
    // entry for every commit after it.
    let commit = |signed_in: Identity, staging, stored_entry: bool| {
        commit_bootstrap(
            uid,
            &peer,
            &subject,
            Gate {
                digest: [7; 32],
                admitted: None,
                signed_in: Some(signed_in),
                stored_entry,
            },
            staging,
            &staged,
            None,
            &h.daemon,
        )
    };
    let stored_account = || {
        let bytes = h
            .daemon
            .encryption
            .open_from_file(&target.join(IDENTITY_FILE))
            .expect("the record is readable");
        serde_json::from_slice::<Identity>(&bytes).expect("identity")
    };

    // The first bootstrap: a new credential, written through the daemon's own path so its
    // snapshot and integrity record are the daemon's, not a hand-edit.
    commit(recorded.clone(), stage_as(&recorded), false)
        .await
        .expect("a first bootstrap writes over nothing");
    assert_eq!(stored_account().account, "111111111111");

    // Signing in as somebody else: challenged, and nothing is written.
    let intruder = who("arn:aws:sts::222222222222:assumed-role/Admin/eve");
    let err = commit(intruder.clone(), stage_as(&intruder), true)
        .await
        .expect_err("a different identity must not be saved on the caller's word");
    assert_eq!(
        err.domain_code(),
        Some(credsd_core::rpc::DomainCode::ApprovalRequired),
        "{err:?}"
    );
    assert_eq!(
        stored_account().account,
        "111111111111",
        "the stored identity must be untouched"
    );

    // Signing in again as the Principal on record: ungated, and the new session is recorded.
    let again = who("arn:aws:sts::111111111111:assumed-role/Admin/alice-2");
    commit(again.clone(), stage_as(&again), true)
        .await
        .expect("the same account and role needs no approval");
    assert_eq!(stored_account().session, "alice-2");

    // Approve the change to the intruder's account, then re-run. A re-run that signs in as a
    // third Principal finds no approval to spend (3.3); one as the approved Principal spends it.
    let challenge = commit(intruder.clone(), stage_as(&intruder), true)
        .await
        .expect_err("still a change")
        .challenge()
        .expect("an identity change carries a challenge");
    h.approve_as_root(&challenge.id).await.expect("approve");
    let third = who("arn:aws:sts::333333333333:assumed-role/Admin/mallory");
    let err = commit(third.clone(), stage_as(&third), true)
        .await
        .expect_err("an approval shown one Principal is not spent by another");
    assert_eq!(
        err.domain_code(),
        Some(DomainCode::ApprovalRequired),
        "{err:?}"
    );
    assert_eq!(stored_account().account, "111111111111");
    let intruder_again = who("arn:aws:sts::222222222222:assumed-role/Admin/eve-2");
    commit(intruder_again.clone(), stage_as(&intruder_again), true)
        .await
        .expect("the approved Principal spends the approval and installs");
    let installed = stored_account();
    assert_eq!(
        (installed.account.as_str(), installed.session.as_str()),
        ("222222222222", "eve-2")
    );
    let err = commit(intruder.clone(), stage_as(&intruder), true)
        .await
        .err()
        .map(|e| e.domain_code());
    assert_eq!(
        err, None,
        "now the record, so the same Principal is ungated"
    );

    // A credential with no record, as every one created before identities were recorded: the
    // same Principal that is about to sign in is still gated on bootstrap (2.4), and
    // `credential/login` refuses it with nothing saved (3.6).
    std::fs::remove_file(target.join(IDENTITY_FILE)).expect("remove the record");
    assert_eq!(stored_identity(&h.daemon.encryption, &target), None);
    let err = commit(intruder.clone(), stage_as(&intruder), true)
        .await
        .expect_err("no record is never a match");
    assert_eq!(
        err.domain_code(),
        Some(DomainCode::ApprovalRequired),
        "{err:?}"
    );
    assert!(
        !target.join(IDENTITY_FILE).exists(),
        "a refused bootstrap writes no record"
    );
    let err = login_identity_check(
        "dev",
        stored_identity(&h.daemon.encryption, &target).as_ref(),
        &intruder,
    )
    .expect_err("login over a credential with no record");
    assert_eq!(err.domain_code(), Some(DomainCode::IdentityMismatch));
}

/// A bootstrap whose name was free when it started, and taken by the time its flow finished,
/// must not commit over what appeared. This is the window an interactive provider opens while it
/// waits on a person: the entry check saw nothing to overwrite, so only the commit's re-check,
/// under the write lock, stands between the stalled flow and the owner's new credential.
#[tokio::test]
async fn a_bootstrap_cannot_commit_over_a_credential_created_while_its_flow_ran() {
    use crate::server::bootstrap::{
        bootstrap_static_secret, commit_bootstrap, Gate, Staging, Subject,
    };
    use crate::server::routes::{CallerAuth, PeerInfo};
    let h = Harness::start().await;
    let uid = nix::unistd::getuid().as_raw();

    // The stalled flow: entry found "late" absent, so it was admitted ungated and sealed into
    // staging.
    let staging = Staging::create(uid).expect("staging");
    let staged = bootstrap_static_secret(
        staging.path(),
        ProviderParamsStaticSecret {
            secret: "sk-attacker".to_owned(),
            env_var: None,
            expires_at: None,
            secret_source: Some("stdin".to_owned()),
            identity_type: Some("automation".to_owned()),
        },
        &h.daemon,
    )
    .expect("stage");

    // Meanwhile the owner creates the credential, ungated because it is new.
    h.bootstrap_static_secret("late", "sk-owner", None).await;

    let peer = PeerInfo {
        uid: Some(uid),
        pid: None,
        auth: CallerAuth::Unresolved,
        executable: None,
        login_uid: None,
    };
    let subject = Subject {
        credential: "late",
        kind: "static-secret",
    };
    let err = commit_bootstrap(
        uid,
        &peer,
        &subject,
        Gate {
            digest: [7; 32],
            admitted: None,
            signed_in: None,
            stored_entry: false,
        },
        staging,
        &staged,
        None,
        &h.daemon,
    )
    .await
    .expect_err("the commit must refuse what it was not admitted to overwrite");
    assert_eq!(
        err.domain_code(),
        Some(credsd_core::rpc::DomainCode::ApprovalRequired),
        "{err:?}"
    );

    assert_eq!(
        token_of(&h.get("late").await.expect("get")),
        "sk-owner",
        "the owner's credential survives"
    );
    let leftovers: Vec<_> = std::fs::read_dir(platform::caller_root(uid).join("credentials"))
        .expect("list")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "staging is removed: {leftovers:?}");
}

/// Commit a staged `aws-idc-sso` sign-in the way `bootstrap_sso` hands it over: a sealed token in
/// staging and the `SsoConfig` the sign-in ran on. Identity Center is not stubbable from this
/// harness, so the device flow itself is not driven; the gate's decision is, which is what AC 11
/// is about.
///
/// A request that named every setting, over a credential the entry check found nothing on record
/// for. [`commit_sso_as`] drives a repeat.
async fn commit_sso(
    uid: u32,
    peer: &crate::server::routes::PeerInfo,
    credential: &str,
    config: credsd_core::config::SsoConfig,
    daemon: &Daemon,
) -> std::result::Result<(), credsd_core::rpc::RpcError> {
    let named = Some(config.allowed_roles.clone());
    let gate = crate::server::bootstrap::Gate {
        digest: [7; 32],
        admitted: None,
        signed_in: None,
        stored_entry: false,
    };
    commit_sso_as(uid, peer, credential, config, named, gate, daemon).await
}

/// [`commit_sso`] for a repeat: `named_allowed_roles` is the list the request named, `None` for one
/// that omitted the flag and left the list to the credential, and `gate` is what the entry check
/// decided before the sign-in ran.
async fn commit_sso_as(
    uid: u32,
    peer: &crate::server::routes::PeerInfo,
    credential: &str,
    config: credsd_core::config::SsoConfig,
    named_allowed_roles: Option<Vec<credsd_core::config::RolePair>>,
    gate: crate::server::bootstrap::Gate,
    daemon: &Daemon,
) -> std::result::Result<(), credsd_core::rpc::RpcError> {
    use crate::server::bootstrap::{commit_bootstrap, Staged, Staging, Subject};
    let staging = Staging::create(uid).expect("staging");
    daemon
        .encryption
        .seal_to_file(&staging.path().join("sso_token.enc"), b"token")
        .expect("seal the staged token");
    let identity_type = config.identity_type;
    commit_bootstrap(
        uid,
        peer,
        &Subject {
            credential,
            kind: "aws-idc-sso",
        },
        gate,
        staging,
        &Staged {
            source: credsd_core::config::credentials::CredentialSource::AwsIdcSso(config),
            identity_type: Some(identity_type),
            allowed_roles: named_allowed_roles,
        },
        None,
        daemon,
    )
    .await
}

fn test_peer(uid: u32) -> crate::server::routes::PeerInfo {
    use crate::server::routes::{CallerAuth, PeerInfo};
    PeerInfo {
        uid: Some(uid),
        pid: None,
        auth: CallerAuth::Unresolved,
        executable: None,
        login_uid: None,
    }
}

/// `credential-retrieval-api` Requirement 17 AC 11, over the commit the gate runs in: a repeat
/// `aws-idc-sso` bootstrap that leaves every stored setting as it found it replaces only the
/// sign-in and needs no approval, while any named difference stays a presence-gated replace whose
/// challenge names the changed setting.
#[tokio::test]
async fn a_repeat_sso_bootstrap_is_gated_only_when_a_stored_setting_changes() {
    use credsd_core::config::{IdentityType, RolePair, SsoConfig};
    use credsd_core::rpc::DomainCode;
    let h = Harness::start().await;
    let uid = nix::unistd::getuid().as_raw();
    let peer = test_peer(uid);

    let stored = || SsoConfig {
        start_url: "https://example.awsapps.com/start".to_owned(),
        sso_region: "us-east-1".to_owned(),
        account_id: "111111111111".to_owned(),
        role_name: "Developer".to_owned(),
        identity_type: IdentityType::Automation,
        allowed_roles: vec![RolePair {
            account_id: "222222222222".to_owned(),
            role_name: "ReadOnly".to_owned(),
        }],
    };

    commit_sso(uid, &peer, "sso", stored(), &h.daemon)
        .await
        .expect("a first bootstrap writes over nothing");
    commit_sso(uid, &peer, "sso", stored(), &h.daemon)
        .await
        .expect("the same settings replace only the sign-in, so no approval is needed");

    // Every stored setting is inside the gate, including a pair the allowed list already names.
    for (setting, config) in [
        (
            "start_url",
            SsoConfig {
                start_url: "https://other.awsapps.com/start".to_owned(),
                ..stored()
            },
        ),
        (
            "sso_region",
            SsoConfig {
                sso_region: "eu-west-1".to_owned(),
                ..stored()
            },
        ),
        (
            "account_id",
            SsoConfig {
                account_id: "222222222222".to_owned(),
                ..stored()
            },
        ),
        (
            "role_name",
            SsoConfig {
                role_name: "ReadOnly".to_owned(),
                ..stored()
            },
        ),
        (
            "allowed_roles",
            SsoConfig {
                allowed_roles: Vec::new(),
                ..stored()
            },
        ),
        (
            "identity_type",
            SsoConfig {
                identity_type: IdentityType::Human,
                ..stored()
            },
        ),
    ] {
        let err = commit_sso(uid, &peer, "sso", config, &h.daemon)
            .await
            .unwrap_err();
        assert_eq!(
            err.domain_code(),
            Some(DomainCode::ApprovalRequired),
            "a changed {setting} is a replace: {err:?}"
        );
        let challenge = err.challenge().expect("a replace carries a challenge");
        assert!(
            challenge.description.contains(setting),
            "the approval names the changed setting: {}",
            challenge.description
        );
        // The entry check admitted this ungated and the sign-in has already run, so the commit is
        // the only thing between a changed setting and the install. The sign-in is discarded.
        let remediation = err.remediation().expect("a refusal carries a remediation");
        assert!(
            remediation.contains("changed while you were signing in"),
            "a discarded sign-in says so: {remediation}"
        );
    }

    let entry = std::fs::read_to_string(platform::caller_root(uid).join("credentials.toml"))
        .expect("read credentials.toml");
    assert!(
        entry.contains("Developer") && !entry.contains("eu-west-1"),
        "no refused replace reached the entry: {entry}"
    );
}

/// Req 17 AC 11's fold, against the entry the write lock holds rather than the one the handler
/// read: a repeat that omits `allowed_roles` keeps the list as the commit finds it. While the
/// sign-in ran, an approved edit added a pair; folding at entry alone made the commit compare the
/// list as it was against the list as it is, and raise a challenge to drop the new pair — which
/// reads as a confirmation of the re-authentication the caller asked for.
#[tokio::test]
async fn a_repeat_sso_bootstrap_keeps_an_allowed_list_that_grew_while_it_signed_in() {
    use crate::server::bootstrap::{records_base, Admitted, Gate};
    use credsd_core::config::{IdentityType, RolePair, SsoConfig};
    let h = Harness::start().await;
    let uid = nix::unistd::getuid().as_raw();
    let peer = test_peer(uid);
    let pair = |account_id: &str, role_name: &str| RolePair {
        account_id: account_id.to_owned(),
        role_name: role_name.to_owned(),
    };
    let with = |allowed_roles: Vec<RolePair>| SsoConfig {
        start_url: "https://example.awsapps.com/start".to_owned(),
        sso_region: "us-east-1".to_owned(),
        account_id: "111122223333".to_owned(),
        role_name: "Developer".to_owned(),
        identity_type: IdentityType::Automation,
        allowed_roles,
    };
    let a = || vec![pair("444455556666", "ReadOnly")];
    let grown = || {
        vec![
            pair("444455556666", "ReadOnly"),
            pair("777788889999", "Admin"),
        ]
    };

    commit_sso(uid, &peer, "sso", with(a()), &h.daemon)
        .await
        .expect("a first bootstrap writes over nothing");

    // The owner's approved edit, committed the way the approve path commits a re-sent bootstrap.
    let approved = Gate {
        digest: [7; 32],
        admitted: Some(Admitted {
            pending_operation: "req-approved".to_owned(),
            base: records_base(uid, &["sso"]).expect("the base the approval covered"),
        }),
        signed_in: None,
        stored_entry: true,
    };
    commit_sso_as(
        uid,
        &peer,
        "sso",
        with(grown()),
        Some(grown()),
        approved,
        &h.daemon,
    )
    .await
    .expect("the approved edit adds the pair");

    // The repeat, staged before that edit: it named no list, so its staged source still carries the
    // list as the entry check read it.
    let repeat = Gate {
        digest: [7; 32],
        admitted: None,
        signed_in: None,
        stored_entry: true,
    };
    commit_sso_as(uid, &peer, "sso", with(a()), None, repeat, &h.daemon)
        .await
        .expect("a repeat that named no list is a re-authentication, whatever the list now holds");

    let entry = std::fs::read_to_string(platform::caller_root(uid).join("credentials.toml"))
        .expect("read credentials.toml");
    assert!(
        entry.contains("777788889999") && entry.contains("444455556666"),
        "the re-authentication kept the list it found, not the one it was folded against: {entry}"
    );
}

/// A credential removed while its repeat bootstrap signed in must not come back. The staged
/// settings were folded from the entry that is now gone, and with nothing left to overwrite the
/// commit's gate has nothing to compare them against — so the credential returned ungated, with
/// the removed entry's pair and allowed list, at the tier a credential with no source on record
/// takes. The sign-in is refused instead, and the re-run starts from the request alone.
#[tokio::test]
async fn a_repeat_sso_bootstrap_whose_credential_was_removed_mid_flow_is_refused() {
    use crate::server::bootstrap::Gate;
    use credsd_core::config::{IdentityType, RolePair, SsoConfig};
    let h = Harness::start().await;
    let uid = nix::unistd::getuid().as_raw();
    let peer = test_peer(uid);
    let stored = || SsoConfig {
        start_url: "https://example.awsapps.com/start".to_owned(),
        sso_region: "us-east-1".to_owned(),
        account_id: "111122223333".to_owned(),
        role_name: "Developer".to_owned(),
        identity_type: IdentityType::Automation,
        allowed_roles: vec![RolePair {
            account_id: "444455556666".to_owned(),
            role_name: "ReadOnly".to_owned(),
        }],
    };

    commit_sso(uid, &peer, "sso", stored(), &h.daemon)
        .await
        .expect("a first bootstrap writes over nothing");

    // The owner removes it, through the daemon, while the browser is open.
    let challenge = challenge_of(h.remove_credential("sso").await);
    h.approve_as_root(&challenge.id).await.expect("approve");

    let repeat = Gate {
        digest: [7; 32],
        admitted: None,
        signed_in: None,
        stored_entry: true,
    };
    let err = commit_sso_as(uid, &peer, "sso", stored(), None, repeat, &h.daemon)
        .await
        .expect_err("a removed credential must not be recreated from the entry it had");
    assert!(
        err.to_string()
            .contains("was removed while you were signing in"),
        "the refusal says what happened: {err}"
    );

    assert!(
        !sealed_dir("sso").exists(),
        "and nothing was installed under the removed name"
    );
    let entry = std::fs::read_to_string(platform::caller_root(uid).join("credentials.toml"))
        .expect("read credentials.toml");
    assert!(
        !entry.contains("111122223333") && !entry.contains("444455556666"),
        "nor did the removed entry's settings return: {entry}"
    );
}

/// The same decision at the entry check, which is where a replace is refused before a browser
/// opens. Both of `admit`'s callers are production, so nothing else drives it: inverting its
/// exemption — every replace admitted, or every re-authentication gated — left the whole suite
/// green, including the commit-side case above.
#[tokio::test]
async fn the_entry_check_exempts_a_re_authentication_and_gates_a_replace() {
    use crate::server::bootstrap::{admit, Sources, Subject, TomlFiles};
    use credsd_core::config::{IdentityType, RolePair, SsoConfig};
    use credsd_core::rpc::{DomainCode, ProviderParamsSso};
    let h = Harness::start().await;
    let uid = nix::unistd::getuid().as_raw();
    let peer = test_peer(uid);

    commit_sso(
        uid,
        &peer,
        "sso",
        SsoConfig {
            start_url: "https://example.awsapps.com/start".to_owned(),
            sso_region: "us-east-1".to_owned(),
            account_id: "111111111111".to_owned(),
            role_name: "Developer".to_owned(),
            identity_type: IdentityType::Automation,
            allowed_roles: vec![RolePair {
                account_id: "222222222222".to_owned(),
                role_name: "ReadOnly".to_owned(),
            }],
        },
        &h.daemon,
    )
    .await
    .expect("a first bootstrap writes over nothing");

    let entry = |account_id: Option<&str>, role_name: Option<&str>| {
        let provider = ProviderParams::AwsIdcSso(ProviderParamsSso {
            start_url: "https://example.awsapps.com/start".to_owned(),
            sso_region: "us-east-1".to_owned(),
            account_id: account_id.map(str::to_owned),
            role_name: role_name.map(str::to_owned),
            identity_type: None,
            allowed_roles: None,
        });
        let files = TomlFiles::read(uid).expect("read the toml files");
        let sources = Sources::read(&files, "sso", &provider).expect("a tier that parses");
        admit(
            &peer,
            uid,
            &h.daemon,
            &Subject {
                credential: "sso",
                kind: "aws-idc-sso",
            },
            [7; 32],
            &files,
            &sources,
        )
    };

    assert!(
        entry(None, None)
            .expect("a repeat that leaves every stored setting alone needs no approval")
            .is_none(),
        "and spends no approval, because none was needed"
    );
    assert!(entry(Some("111111111111"), Some("Developer"))
        .expect("naming the stored pair is the same request")
        .is_none());

    let Err(err) = entry(Some("111111111111"), Some("Admin")) else {
        panic!("a changed role is a replace, which needs approval");
    };
    assert_eq!(err.domain_code(), Some(DomainCode::ApprovalRequired));
    let challenge = err.challenge().expect("a replace carries a challenge");
    assert!(
        challenge
            .description
            .contains("change role_name from Developer to Admin"),
        "{}",
        challenge.description
    );
    let remediation = err.remediation().expect("a refusal carries a remediation");
    assert!(
        remediation.contains("re-run the same bootstrap"),
        "the entry check refuses before any sign-in, so nothing was discarded: {remediation}"
    );
}

/// AC 10 and AC 11 over the handler's own wording, rather than over a `Subject` a test built: a
/// replace of an `aws-idc-sso` credential is named by its source type alone, because the change
/// clauses beside it name every setting themselves. Each value therefore appears once, labelled
/// with whether it moves — which is only true while the narrowing runs where the clauses are
/// worded, from the entry those clauses were read from.
#[tokio::test]
async fn an_sso_replace_is_named_by_its_source_type_beside_its_clauses() {
    use credsd_core::config::{IdentityType, RolePair, SsoConfig};
    let h = Harness::start().await;
    let uid = nix::unistd::getuid().as_raw();
    commit_sso(
        uid,
        &test_peer(uid),
        "sso",
        SsoConfig {
            start_url: "https://example.awsapps.com/start".to_owned(),
            sso_region: "us-east-1".to_owned(),
            account_id: "111122223333".to_owned(),
            role_name: "Developer".to_owned(),
            identity_type: IdentityType::Automation,
            allowed_roles: vec![RolePair {
                account_id: "222222222222".to_owned(),
                role_name: "ReadOnly".to_owned(),
            }],
        },
        &h.daemon,
    )
    .await
    .expect("a first bootstrap writes over nothing");

    let params = ProfileBootstrapParams {
        tags: None,
        credential: Some("sso".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::AwsIdcSso(credsd_core::rpc::ProviderParamsSso {
            start_url: "https://example.awsapps.com/start".to_owned(),
            sso_region: "us-east-1".to_owned(),
            account_id: Some("111122223333".to_owned()),
            role_name: Some("Admin".to_owned()),
            identity_type: None,
            allowed_roles: None,
        }),
    };
    let description = challenge_of(h.call(METHOD_CREDENTIAL_BOOTSTRAP, &params, "sso").await)
        .description
        .clone();

    assert!(
        description.contains("with a new aws-idc-sso;"),
        "the source type alone, then the clauses: {description}"
    );
    assert!(
        description.contains("change role_name from Developer to Admin"),
        "{description}"
    );
    assert_eq!(
        description.matches("Admin").count(),
        1,
        "the clause names the new role, and nothing beside it repeats it: {description}"
    );
}

/// Req 17 AC 1's both-or-neither over the wire. An account with no role is refused from the
/// request alone, so the sign-in it would otherwise have resolved the role at — a real device
/// flow against the Identity Center instance — never starts and nothing is staged.
#[tokio::test]
async fn an_sso_account_without_a_role_never_reaches_a_device_flow() {
    let h = Harness::start().await;
    let params = ProfileBootstrapParams {
        tags: None,
        credential: Some("half".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::AwsIdcSso(credsd_core::rpc::ProviderParamsSso {
            start_url: "https://example.awsapps.com/start".to_owned(),
            sso_region: "us-east-1".to_owned(),
            account_id: Some("111122223333".to_owned()),
            role_name: None,
            identity_type: None,
            allowed_roles: None,
        }),
    };
    let refusal = h
        .call::<_, OkResult>(METHOD_CREDENTIAL_BOOTSTRAP, &params, "half")
        .await
        .expect_err("a half pair is refused")
        .to_string();
    assert!(
        refusal.contains("account_id") && refusal.contains("role_name"),
        "refused from the request, not by the flow it never started: {refusal}"
    );
    assert!(
        !platform::caller_root(nix::unistd::getuid().as_raw())
            .join("credentials")
            .join("half")
            .exists(),
        "and nothing was staged or installed"
    );
}

/// AC 11's two negative cases, which must never read as a re-authentication however equal the
/// settings look: a credential holding sealed material but no `credentials.toml` entry, which the
/// gate refuses, and a `credentials.toml` that does not parse, which the write check refuses
/// before the gate is reached.
#[tokio::test]
async fn a_repeat_sso_bootstrap_over_an_unreadable_entry_is_refused() {
    use credsd_core::config::{IdentityType, SsoConfig};
    use credsd_core::rpc::DomainCode;
    let h = Harness::start().await;
    let uid = nix::unistd::getuid().as_raw();
    let root = platform::caller_root(uid);

    let config = || SsoConfig {
        start_url: "https://example.awsapps.com/start".to_owned(),
        sso_region: "us-east-1".to_owned(),
        account_id: "111111111111".to_owned(),
        role_name: "Developer".to_owned(),
        identity_type: IdentityType::Human,
        allowed_roles: Vec::new(),
    };
    let peer = test_peer(uid);

    // Sealed material under a name no entry describes.
    let orphan = root.join("credentials").join("orphan");
    std::fs::create_dir_all(&orphan).expect("orphan dir");
    h.daemon
        .encryption
        .seal_to_file(&orphan.join("sso_token.enc"), b"token")
        .expect("seal");
    let err = commit_sso(uid, &peer, "orphan", config(), &h.daemon)
        .await
        .unwrap_err();
    assert_eq!(
        err.domain_code(),
        Some(DomainCode::ApprovalRequired),
        "sealed material with no entry is never a re-authentication: {err:?}"
    );

    // A `credentials.toml` that does not parse never reaches the gate at all: the shared write
    // check cannot canonicalize it against its sealed snapshot, so it refuses first. That is the
    // code this path produces, and asserting the gate's own refusal here would pass whatever the
    // gate did with an unparseable entry. What the gate does with one is
    // `the_same_source_decision_reads_the_checked_bytes`: it reads as no source.
    commit_sso(uid, &peer, "sso", config(), &h.daemon)
        .await
        .expect("a first bootstrap writes over nothing");
    let path = root.join("credentials.toml");
    let before = std::fs::read_to_string(&path).expect("read credentials.toml");
    std::fs::write(&path, format!("{before}\nnot = = toml\n")).expect("break the toml");
    let err = commit_sso(uid, &peer, "sso", config(), &h.daemon)
        .await
        .unwrap_err();
    assert_eq!(
        err.domain_code(),
        Some(DomainCode::ConfigDrifted),
        "a credentials.toml that does not parse is never a re-authentication: {err:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("read credentials.toml"),
        format!("{before}\nnot = = toml\n"),
        "and nothing was written over it"
    );
}

async fn revalidate(h: &Harness) -> credsd_core::error::Result<OkResult> {
    rpc_uds::call(
        &h.socket,
        credsd_core::rpc::METHOD_FILE_REVALIDATE,
        &credsd_core::rpc::RevalidateParams::default(),
        None,
    )
    .await
}

/// A hand edit that changes what `config.toml` means, not only its text: a comment-only edit
/// leaves the canonical form, and so the snapshot, valid. The C1 control `U+009B` is legal raw in a
/// TOML string and opens an escape sequence on a terminal, so it must not reach the approver as-is.
/// `config.toml` content a caller may hold: no environment table.
const SEED_CONFIG: &str = "[auth]\nagent_binaries = [\"claude\"]\n";

/// Hand-edit `credentials.toml`, adding a field to its last entry with a C1 control in the value
/// so the challenge's sanitization is observable. `credentials.toml` is the file to drift:
/// `config.toml` holds no load-bearing field once environment tables are invalid.
fn drift_credentials() -> PathBuf {
    let path = platform::caller_root(nix::unistd::getuid().as_raw()).join("credentials.toml");
    let before = std::fs::read_to_string(&path).expect("read credentials.toml");
    std::fs::write(&path, format!("{before}env_var = \"US_WEST_2\u{9b}2J\"\n"))
        .expect("hand-edit credentials.toml");
    path
}

#[tokio::test]
async fn revalidating_a_root_with_nothing_drifted_raises_no_challenge() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    revalidate(&h)
        .await
        .expect("nothing drifted, so nothing to approve");
}

/// The challenge shows the drifted file in full, escaped, names the other file as unchanged, and
/// approval reseals only the drifted one.
#[tokio::test]
async fn revalidation_shows_the_drifted_file_and_reseals_only_it_on_approval() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    h.seed_config(SEED_CONFIG).await;
    let uid = nix::unistd::getuid().as_raw();
    let config_snapshot = platform::caller_root(uid).join("config_snapshot.enc");
    let sealed_before = std::fs::read(&config_snapshot).expect("config snapshot");
    drift_credentials();
    assert!(!h.daemon.caller_state(uid).credentials_drift.is_valid());

    let challenge = challenge_of(revalidate(&h).await);
    let d = &challenge.description;
    assert!(
        d.starts_with("revalidate drifted config files: credentials.toml\n"),
        "{d}"
    );
    assert!(
        d.contains("credentials.toml has drifted. Current contents:"),
        "{d}"
    );
    assert!(d.contains("env_var"), "{d}");
    assert!(
        d.contains("config.toml is unchanged and will not be resealed."),
        "{d}"
    );
    assert!(
        !d.contains('\u{9b}'),
        "a C1 control reached the approver: {d:?}"
    );
    assert!(d.contains("US_WEST_2\u{FFFD}2J"), "{d:?}");

    h.approve_as_root(&challenge.id).await.expect("approve");
    assert!(h.daemon.caller_state(uid).credentials_drift.is_valid());
    assert_eq!(
        std::fs::read(&config_snapshot).expect("config snapshot"),
        sealed_before,
        "a file shown as unchanged is not resealed"
    );
    revalidate(&h)
        .await
        .expect("the resealed root has nothing left to revalidate");
}

#[tokio::test]
async fn a_revalidation_is_discarded_when_either_file_changes_before_approval() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    h.seed_config(SEED_CONFIG).await;
    drift_credentials();
    let challenge = challenge_of(revalidate(&h).await);

    let config_path = platform::caller_root(nix::unistd::getuid().as_raw()).join("config.toml");
    let before = std::fs::read_to_string(&config_path).expect("read config.toml");
    std::fs::write(&config_path, format!("{before}\n# hand edit\n"))
        .expect("edit the file that is not being resealed");

    let err = h
        .approve_as_root(&challenge.id)
        .await
        .expect_err("an edit to either file discards the request");
    assert!(
        matches!(
            err,
            credsd_core::error::DaemonError::ApprovalRefused {
                reason: credsd_core::presence::RefusalReason::BaseStateChanged,
                ..
            }
        ),
        "{err}"
    );
    challenge_of(revalidate(&h).await);
}

#[tokio::test]
async fn revalidation_refuses_a_selector() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    let err = rpc_uds::call::<_, OkResult>(
        &h.socket,
        credsd_core::rpc::METHOD_FILE_REVALIDATE,
        &serde_json::json!({ "env": "tier" }),
        None,
    )
    .await
    .expect_err("a snapshot covers its whole file, so no narrower selector is accepted");
    assert!(err.to_string().contains("unknown field"), "{err}");
}

#[tokio::test]
async fn revalidation_refuses_a_file_that_does_not_parse() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    let path = platform::caller_root(nix::unistd::getuid().as_raw()).join("config.toml");
    std::fs::write(&path, "[environments.tier\n").expect("break config.toml");
    let err = revalidate(&h)
        .await
        .expect_err("a file with no canonical form has nothing to seal");
    assert!(err.to_string().contains("does not parse"), "{err}");
}

/// A deleted load-bearing file the integrity record names is drift, not absence (Requirement
/// 10.3), on the load path and in revalidation alike: nothing is served, the refusal names
/// revalidation, and revalidation names the file as deleted and records it as absent (4.1, 4.4).
#[tokio::test]
async fn a_deleted_file_is_drift_until_revalidation_records_it_absent() {
    for name in ["config.toml", "credentials.toml"] {
        let h = Harness::start().await;
        h.bootstrap_static_secret("tier", "sk-value", None).await;
        h.seed_config(SEED_CONFIG).await;
        let uid = nix::unistd::getuid().as_raw();
        std::fs::remove_file(platform::caller_root(uid).join(name)).expect("delete");

        let caller = h.daemon.caller_state(uid);
        let drift = if name == "config.toml" {
            &caller.config_drift
        } else {
            &caller.credentials_drift
        };
        assert_eq!(
            *drift,
            credsd_core::config::snapshot::DriftStatus::Deleted,
            "{name}"
        );
        let err = h.get("tier").await.expect_err("nothing is served");
        assert!(
            err.to_string().contains("creds revalidate"),
            "{name}: {err}"
        );

        let challenge = challenge_of(revalidate(&h).await);
        assert!(
            challenge.description.contains(&format!(
                "{name} has been deleted. Approving records it as absent"
            )),
            "{name}: {}",
            challenge.description
        );
        h.approve_as_root(&challenge.id).await.expect("approve");
        let caller = h.daemon.caller_state(uid);
        assert!(caller.config_drift.is_valid(), "{name}");
        assert!(caller.credentials_drift.is_valid(), "{name}");
        assert!(
            !platform::caller_root(uid).join(name).exists(),
            "revalidation records a deletion; it does not recreate the file"
        );
        revalidate(&h)
            .await
            .unwrap_or_else(|e| panic!("{name}: a recorded deletion has nothing left: {e}"));
    }
}

/// Design Decision 11: a same-uid process deletes a credential's entry, sealed files, and the
/// snapshot, then bootstraps the same name as if it were new. Read as absence, that first write
/// would run ungated and the environment would serve a credential its owner never approved.
#[tokio::test]
async fn deleting_a_credential_cannot_turn_its_replacement_into_a_first_bootstrap() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-owner", None).await;
    let root = platform::caller_root(nix::unistd::getuid().as_raw());
    for file in ["credentials.toml", "credentials_snapshot.enc"] {
        std::fs::remove_file(root.join(file)).expect("delete");
    }
    std::fs::remove_dir_all(root.join("credentials").join("tier")).expect("delete sealed data");

    let err = h
        .try_bootstrap_static_secret("tier", None, "sk-attacker")
        .await
        .expect_err("the replacement is refused");
    assert!(
        !matches!(err, credsd_core::error::DaemonError::ApprovalRequired(_)),
        "{err}"
    );
    assert!(err.to_string().contains("has been deleted"), "{err}");
    assert!(!root.join("credentials.toml").exists(), "nothing written");
}

/// Requirement 10.4: a legitimately sealed `(file, snapshot)` pair saved earlier and restored
/// together verifies on its own, and only the record tells it from the current one.
#[tokio::test]
async fn a_restored_earlier_pair_is_drift() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    let root = platform::caller_root(nix::unistd::getuid().as_raw());
    let saved: Vec<(PathBuf, Vec<u8>)> = ["credentials.toml", "credentials_snapshot.enc"]
        .iter()
        .map(|f| (root.join(f), std::fs::read(root.join(f)).expect("save")))
        .collect();

    h.bootstrap_static_secret("other", "sk-other", None).await;
    h.get("tier").await.expect("the current state is served");

    for (path, bytes) in &saved {
        std::fs::write(path, bytes).expect("restore the earlier pair");
    }
    let err = h.get("tier").await.expect_err("a restored pair is drift");
    assert!(err.to_string().contains("creds revalidate"), "{err}");
}

/// Requirement 10.5 and 9.6: a root written before the record existed — snapshots that verify,
/// and no record — is in drift, once, and revalidation is how it is recorded. Nothing records it
/// automatically.
#[tokio::test]
async fn a_root_with_snapshots_and_no_record_is_drift_until_revalidated() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    h.seed_config(SEED_CONFIG).await;
    let uid = nix::unistd::getuid().as_raw();
    std::fs::remove_file(
        platform::data_dir()
            .join("integrity")
            .join(format!("{uid}.enc")),
    )
    .expect("remove the record");

    let err = h
        .get("tier")
        .await
        .expect_err("an unrecorded root is drift");
    assert!(err.to_string().contains("creds revalidate"), "{err}");
    h.get("tier")
        .await
        .expect_err("a refusal does not record the root as a side effect");

    let challenge = challenge_of(revalidate(&h).await);
    assert!(
        challenge
            .description
            .starts_with("revalidate drifted config files: config.toml, credentials.toml\n"),
        "{}",
        challenge.description
    );
    h.approve_as_root(&challenge.id).await.expect("approve");
    assert_eq!(token_of(&h.get("tier").await.expect("get")), "sk-value");
}

/// Requirement 10.6: a record that will not open serves nothing and refuses writes, and is never
/// rebuilt silently. Revalidation replaces it, under an approval that shows both files and says
/// there is no record to compare them against; until approved, the record is left as found.
#[tokio::test]
async fn an_unreadable_record_serves_nothing_until_an_approved_revalidation_replaces_it() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    h.seed_config(SEED_CONFIG).await;
    let uid = nix::unistd::getuid().as_raw();
    let record = platform::data_dir()
        .join("integrity")
        .join(format!("{uid}.enc"));
    std::fs::write(&record, b"{\"not\":\"sealed\"}").expect("corrupt the record");
    h.daemon.evict_caller(uid);

    let err = h.get("tier").await.expect_err("nothing is served");
    assert!(
        err.to_string().starts_with(&format!(
            "{}: config unverifiable:",
            credsd_core::error::CONFIG
        )),
        "not reported as drift (Requirement 11.2): {err}"
    );
    assert!(err.to_string().contains("creds revalidate"), "{err}");
    let err = h
        .try_bootstrap_static_secret("fresh", None, "sk-fresh")
        .await
        .expect_err("a write does not replace the record");
    assert!(err.to_string().contains("config unverifiable"), "{err}");

    let challenge = challenge_of(revalidate(&h).await);
    assert!(
        challenge
            .description
            .contains("There is no record to compare these files against"),
        "{}",
        challenge.description
    );
    assert!(
        challenge.description.contains("config.toml has drifted"),
        "{}",
        challenge.description
    );
    assert_eq!(
        std::fs::read(&record).expect("record"),
        b"{\"not\":\"sealed\"}",
        "the record is left in place until approval"
    );
    h.approve_as_root(&challenge.id).await.expect("approve");
    assert_eq!(token_of(&h.get("tier").await.expect("get")), "sk-value");
}

/// A record that read as unverifiable and then recovers leaves a stale refusal cached, since
/// neither load-bearing file changed. The remedy the refusal names clears it even when it finds
/// nothing to reseal.
#[tokio::test]
async fn revalidation_clears_a_stale_unverifiable_state_when_the_record_recovers() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    let uid = nix::unistd::getuid().as_raw();
    let record = platform::data_dir()
        .join("integrity")
        .join(format!("{uid}.enc"));
    let sealed = std::fs::read(&record).expect("record");
    std::fs::write(&record, b"{\"not\":\"sealed\"}").expect("corrupt the record");
    h.daemon.evict_caller(uid);
    h.get("tier").await.expect_err("nothing is served");

    std::fs::write(&record, &sealed).expect("restore the record");
    h.get("tier")
        .await
        .expect_err("the refusal is cached while neither file changes");
    revalidate(&h)
        .await
        .expect("nothing to reseal once the record opens");
    assert_eq!(token_of(&h.get("tier").await.expect("get")), "sk-value");
}

/// Requirement 10.8 end to end: once the records directory is writable by group, nothing the
/// record or the enrolled-key registry governs is served or approved, and the mode is left as
/// found. The unit cases in `integrity.rs` cover each path and each kind of breach.
#[tokio::test]
async fn a_broken_custody_refuses_serving_and_approval_and_is_not_repaired() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    h.bootstrap_static_secret("other", "sk-other", None).await;
    assert_eq!(token_of(&h.get("tier").await.expect("get")), "sk-value");
    let set = challenge_of(h.remove_credential("other").await);
    let dir = platform::data_dir().join("integrity");
    // No eviction: the caller's state is already cached, and a breach must stop it serving
    // without either load-bearing file changing.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).expect("chmod");

    let err = h.get("tier").await.expect_err("nothing is served");
    assert!(
        err.to_string().contains("integrity custody broken"),
        "{err}"
    );
    assert!(!err.to_string().contains("creds revalidate"), "{err}");
    let err = h
        .approve_as_root(&set.id)
        .await
        .expect_err("nothing is approved");
    assert!(err.to_string().contains("writable by group"), "{err}");
    assert_eq!(
        std::fs::metadata(&dir).expect("stat").permissions().mode() & 0o777,
        0o770,
        "custody is not repaired"
    );
    // Requirement 10.10: restoring the mode does not lift the breach; only a restart does.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let err = h
        .approve_as_root(&set.id)
        .await
        .expect_err("the breach latches until restart");
    assert!(
        err.to_string().contains("integrity custody broken"),
        "{err}"
    );
    h.get("tier").await.expect_err("nor is anything served");
    let err = revalidate(&h)
        .await
        .expect_err("revalidation is no remedy for a breach");
    assert!(
        err.to_string().contains("integrity custody broken"),
        "{err}"
    );
}

/// The Testing section of drift-detection design.md: every method the dispatcher classifies as
/// writing a load-bearing file, or sealing material one names, refuses while the records are in
/// drift, and leaves the files, snapshots, and record as it found them (Requirement 5.8). The list
/// comes from `Method::all`, so a writing method added later is driven here too — and
/// `writes_load_bearing` will not compile until the new method is classified.
///
/// The drift is two deleted snapshots: it leaves both files' bytes, and so every pending
/// approval's base state, unchanged, which is what lets the commit of an approved request reach
/// its own drift check rather than stopping at the base check. Revalidation is the one writer
/// that proceeds: its base check is its form of the shared check, and drift is what it ratifies.
#[tokio::test]
async fn every_write_path_refuses_while_its_records_are_in_drift() {
    use crate::server::dispatch::{exposed, Carrier, Method};
    use credsd_core::error::DaemonError;
    // A withdrawn method answers method-not-found before any drift check, so only the writers a
    // caller can reach are driven (`credential-only-addressing` Requirement 4.1).
    let writers: Vec<Method> = Method::all()
        .into_iter()
        .filter(|m| m.writes_load_bearing() && exposed(*m, Carrier::Uds))
        .collect();
    assert!(writers.len() >= 6, "{writers:?}");
    for method in writers {
        let h = Harness::start().await;
        h.bootstrap_static_secret("tier", "sk-value", None).await;
        h.bootstrap_static_secret("other", "sk-other", None).await;
        h.seed_config(SEED_CONFIG).await;
        let uid = nix::unistd::getuid().as_raw();
        let root = platform::caller_root(uid);
        let pending = challenge_of(h.remove_credential("other").await);
        for snapshot in ["config_snapshot.enc", "credentials_snapshot.enc"] {
            std::fs::remove_file(root.join(snapshot)).expect("remove snapshot");
        }
        let record = platform::data_dir()
            .join("integrity")
            .join(format!("{uid}.enc"));
        let tree = |root: &Path| -> Vec<Option<Vec<u8>>> {
            [
                root.join("config.toml"),
                root.join("credentials.toml"),
                root.join("config_snapshot.enc"),
                root.join("credentials_snapshot.enc"),
                record.clone(),
            ]
            .iter()
            .map(|p| std::fs::read(p).ok())
            .collect()
        };
        let before = tree(&root);

        let outcome: credsd_core::error::Result<serde_json::Value> = match method {
            Method::CredentialRemove => h
                .remove_credential("tier")
                .await
                .map(|_| Default::default()),
            Method::CredentialLogout => {
                h.call(
                    credsd_core::rpc::METHOD_CREDENTIAL_LOGOUT,
                    &credsd_core::rpc::CredentialLogoutParams {
                        credential: "tier".to_owned(),
                    },
                    "tier",
                )
                .await
            }
            Method::CredentialTag => {
                tag(
                    &h,
                    serde_json::json!({ "credential": "tier", "set": { "team": "payments" } }),
                )
                .await
            }
            Method::FileRevalidate => revalidate(&h).await.map(|_| Default::default()),
            Method::ProfileBootstrap => h
                .try_bootstrap_static_secret("fresh", None, "sk-fresh")
                .await
                .map(|_| Default::default()),
            Method::ProfileLogin => {
                h.call(
                    METHOD_CREDENTIAL_LOGIN,
                    &ProfileLoginParams {
                        credential: "tier".to_owned(),
                        request_id: None,
                    },
                    "tier",
                )
                .await
            }
            Method::ProfileImport => {
                h.call(
                    METHOD_CREDENTIAL_IMPORT,
                    &ImportParams {
                        profile: import_profile("fresh"),
                        dry_run: false,
                    },
                    "import",
                )
                .await
            }
            Method::RequestApprove => h.approve_as_root(&pending.id).await,
            other => panic!("{other:?} is classified as writing but not driven here"),
        };

        match (method, outcome) {
            (Method::FileRevalidate, Err(DaemonError::ApprovalRequired(_))) => {}
            (Method::FileRevalidate, other) => {
                panic!("revalidation is the remedy and raises a challenge: {other:?}")
            }
            (_, Err(e)) => assert!(
                e.to_string().contains("config drifted"),
                "{method:?} refused for something other than drift: {e}"
            ),
            (_, Ok(v)) => panic!("{method:?} wrote over drift: {v}"),
        }
        assert_eq!(tree(&root), before, "{method:?} changed what it refused");
    }
}

/// Requirements 2.4 and 2.11: a damaged snapshot under a record that opens is drift, not a lost
/// key, so it is refused as drift and revalidation reseals it.
#[tokio::test]
async fn a_damaged_snapshot_is_drift_and_revalidation_reseals_it() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
    h.seed_config(SEED_CONFIG).await;
    let uid = nix::unistd::getuid().as_raw();
    let snapshot = platform::caller_root(uid).join("config_snapshot.enc");
    std::fs::write(&snapshot, b"{}").expect("corrupt the snapshot");
    h.daemon.evict_caller(uid);

    let err = h.get("tier").await.expect_err("nothing is served");
    assert!(err.to_string().contains("config drifted"), "{err}");
    let challenge = challenge_of(revalidate(&h).await);
    assert!(
        challenge
            .description
            .starts_with("revalidate drifted config files: config.toml\n"),
        "{}",
        challenge.description
    );
    h.approve_as_root(&challenge.id).await.expect("approve");
    assert_eq!(token_of(&h.get("tier").await.expect("get")), "sk-value");
}

/// A bootstrap re-send spends its approval at entry, so a record that will not read by commit is
/// the approve path's case again: the approval is refused as `base_state_changed` and discarded,
/// not lost behind an internal error (Requirement 2.6). The record is made unreadable by putting a
/// directory where the file belongs, which holds when the suite runs as root.
#[tokio::test]
async fn a_spent_bootstrap_approval_is_discarded_when_the_records_cannot_be_read_at_commit() {
    use crate::server::bootstrap::{
        bootstrap_static_secret, commit_bootstrap, Admitted, Gate, Staging, Subject,
    };
    use crate::server::routes::{CallerAuth, PeerInfo};
    let h = Harness::start().await;
    let uid = nix::unistd::getuid().as_raw();
    h.bootstrap_static_secret("kept", "sk-owner", None).await;

    let staging = Staging::create(uid).expect("staging");
    let staged = bootstrap_static_secret(
        staging.path(),
        ProviderParamsStaticSecret {
            secret: "sk-replacement".to_owned(),
            env_var: None,
            expires_at: None,
            secret_source: Some("stdin".to_owned()),
            identity_type: None,
        },
        &h.daemon,
    )
    .expect("stage");

    let credentials_toml = platform::caller_root(uid).join("credentials.toml");
    std::fs::remove_file(&credentials_toml).expect("remove credentials.toml");
    std::fs::create_dir(&credentials_toml).expect("unreadable credentials.toml");

    let peer = PeerInfo {
        uid: Some(uid),
        pid: None,
        auth: CallerAuth::Unresolved,
        executable: None,
        login_uid: None,
    };
    let subject = Subject {
        credential: "kept",
        kind: "static-secret",
    };
    let err = commit_bootstrap(
        uid,
        &peer,
        &subject,
        Gate {
            digest: [7; 32],
            admitted: Some(Admitted {
                pending_operation: "req-spent".to_owned(),
                base: [9; 32],
            }),
            signed_in: None,
            stored_entry: true,
        },
        staging,
        &staged,
        None,
        &h.daemon,
    )
    .await
    .expect_err("an unconfirmable commit must not be performed");
    assert_eq!(
        err.domain_code(),
        Some(credsd_core::rpc::DomainCode::ApprovalRefused),
        "{err:?}"
    );
    assert!(err.to_string().contains("req-spent"), "{err}");
    assert!(
        std::fs::read_dir(platform::caller_root(uid).join("credentials"))
            .expect("list")
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with('.')),
        "staging is removed"
    );
}

/// An empty secret is refused at bootstrap and nothing is saved, for both secret-bearing providers.
#[tokio::test]
async fn an_empty_secret_is_refused_at_bootstrap_and_saves_nothing() {
    let h = Harness::start().await;

    let static_secret = ProfileBootstrapParams {
        tags: None,
        credential: Some("empty-static".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
            secret: String::new(),
            env_var: None,
            expires_at: None,
            secret_source: Some("stdin".to_owned()),
            identity_type: Some("automation".to_owned()),
        }),
    };
    let err = h
        .call::<_, OkResult>(METHOD_CREDENTIAL_BOOTSTRAP, &static_secret, "empty-static")
        .await
        .expect_err("an empty static secret must not bootstrap");
    assert!(err.to_string().contains("must not be empty"), "{err}");
    h.get("empty-static")
        .await
        .expect_err("a refused bootstrap leaves nothing to serve");

    let oauth = ProfileBootstrapParams {
        tags: None,
        credential: Some("empty-oauth".to_owned()),
        name_prefix: None,
        request_id: None,
        provider: ProviderParams::Oauth(credsd_core::rpc::ProviderParamsOauth {
            token_url: "https://idp.example.com/token".to_owned(),
            client_id: "client".to_owned(),
            client_secret: Some(String::new()),
            private_key_pem: None,
            scope: None,
            identity_type: Some("automation".to_owned()),
        }),
    };
    let err = h
        .call::<_, OkResult>(METHOD_CREDENTIAL_BOOTSTRAP, &oauth, "empty-oauth")
        .await
        .expect_err("an empty client secret must not bootstrap");
    assert!(err.to_string().contains("must not be empty"), "{err}");
    h.get("empty-oauth")
        .await
        .expect_err("a refused bootstrap leaves nothing to serve");
}
