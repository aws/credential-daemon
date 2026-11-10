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
    GetParams, ImportParams, ImportProfile, ImportResult, ImportStatus, Material, OkResult,
    ProfileBootstrapParams, ProfileLoginParams, ProfileManifest, Provenance, ProviderParams,
    ProviderParamsIamUser, ProviderParamsJwt, ProviderParamsStaticSecret, SessionStatus,
    METHOD_CREDENTIAL_GET, METHOD_PROFILE_BOOTSTRAP, METHOD_PROFILE_DESCRIBE,
    METHOD_PROFILE_IMPORT, METHOD_PROFILE_LOGIN,
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
            environment: env.to_owned(),
            credential: None,
            request_id: None,
            provider: ProviderParams::Jwt(ProviderParamsJwt {
                jwt: jwt.to_owned(),
                env_var: env_var.map(str::to_owned),
                identity_type: Some("automation".to_owned()),
            }),
        };
        self.call(METHOD_PROFILE_BOOTSTRAP, &params, env)
            .await
            .expect("bootstrap")
    }

    /// An MFA-bearing iam-user credential. Bootstrap seals the long-term key pair locally with no
    /// network call; `login` on it blocks in `await_selection` waiting for an MFA code, which is
    /// the only way to hold a login open from a test without standing up an IdP.
    async fn bootstrap_iam_user_with_mfa(&self, env: &str) -> OkResult {
        let params = ProfileBootstrapParams {
            environment: env.to_owned(),
            credential: None,
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
        self.call(METHOD_PROFILE_BOOTSTRAP, &params, env)
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
            environment: env.to_owned(),
            credential: None,
            request_id: None,
            provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
                secret: secret.to_owned(),
                env_var: None,
                expires_at,
                secret_source: Some("stdin".to_owned()),
                identity_type: Some("automation".to_owned()),
            }),
        };
        self.call(METHOD_PROFILE_BOOTSTRAP, &params, env)
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
            environment: env.to_owned(),
            credential: credential.map(str::to_owned),
            request_id: None,
            provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
                secret: secret.to_owned(),
                env_var: None,
                expires_at: None,
                secret_source: Some("stdin".to_owned()),
                identity_type: Some("automation".to_owned()),
            }),
        };
        self.call(METHOD_PROFILE_BOOTSTRAP, &params, env).await
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
            environment: credential.to_owned(),
            credential: None,
            scope: None,
            claim: None,
            request_id: None,
        };
        self.call(METHOD_CREDENTIAL_GET, &params, credential).await
    }

    async fn import(&self, profiles: Vec<ImportProfile>, dry_run: bool) -> ImportResult {
        let params = ImportParams { profiles, dry_run };
        self.call(METHOD_PROFILE_IMPORT, &params, "import")
            .await
            .expect("import")
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
    let creds = credsd_core::credential_resolve::fetch_from_daemon_uds(
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
    let creds = credsd_core::credential_resolve::fetch_from_daemon_uds(
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

/// Binding a new identity into an environment already in use changes what it serves, so it is
/// gated even though the credential itself is new.
#[tokio::test]
async fn binding_a_new_credential_into_an_existing_environment_is_gated() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("shared", "sk-original", None)
        .await;

    let challenge = challenge_of(
        h.try_bootstrap_static_secret("shared", Some("intruder"), "sk-intruder")
            .await,
    );
    assert!(
        challenge.description.contains(
            "bind new credential 'intruder' (static-secret) into existing environment 'shared'"
        ),
        "{}",
        challenge.description
    );
    // Both bootstraps name identity_type "automation" (Harness::try_bootstrap_static_secret):
    // an unchanged value must not raise a false rewrite disclosure.
    assert!(
        !challenge.description.contains("identity_type"),
        "{}",
        challenge.description
    );
}

/// Binding a new credential into an existing environment can also carry an identity_type that
/// rewrites that environment's privilege tier. The challenge must name the rewrite, not just
/// the binding — the same bar `config/set` already holds for this field.
#[tokio::test]
async fn bootstrap_disclosure_names_an_identity_type_rewrite_to_an_existing_environment() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("shared", "sk-original", None)
        .await; // identity_type: automation

    let params = ProfileBootstrapParams {
        environment: "shared".to_owned(),
        credential: Some("intruder".to_owned()),
        request_id: None,
        provider: ProviderParams::StaticSecret(ProviderParamsStaticSecret {
            secret: "sk-intruder".to_owned(),
            env_var: None,
            expires_at: None,
            secret_source: Some("stdin".to_owned()),
            identity_type: Some("human".to_owned()),
        }),
    };
    let challenge = challenge_of(h.call(METHOD_PROFILE_BOOTSTRAP, &params, "shared").await);
    assert!(
        challenge
            .description
            .contains("change environment 'shared''s identity_type from 'automation' to 'human'"),
        "{}",
        challenge.description
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
        environment: "shared".to_owned(),
        credential: Some("intruder".to_owned()),
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
        .call::<_, OkResult>(METHOD_PROFILE_BOOTSTRAP, &params, "shared")
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
        environment: "stale".to_owned(),
        credential: None,
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
        .call::<_, OkResult>(METHOD_PROFILE_BOOTSTRAP, &params, "stale")
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
#[tokio::test]
async fn the_manifest_reports_a_static_secret_as_an_env_var_source() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("openai", "sk-manifest-check", None)
        .await;

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
        environment: "gh".to_owned(),
        credential: None,
        request_id: None,
        provider: ProviderParams::Jwt(ProviderParamsJwt {
            jwt: second.clone(),
            env_var: None,
            identity_type: Some("automation".to_owned()),
        }),
    };
    let challenge = challenge_of(h.call(METHOD_PROFILE_BOOTSTRAP, &params, "gh").await);
    h.approve_as_root(&challenge.id).await.expect("approve");
    let _: OkResult = h
        .call(METHOD_PROFILE_BOOTSTRAP, &params, "gh")
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

/// `login` reaches a jwt source two ways, and they must answer differently. An env sweep skips it
/// like any other unattended source, or logging in to an env would fail over a credential that
/// needed nothing. A caller that named the credential is asking for the one thing this source
/// cannot do, so it gets the command that can — an `Ok` there reads as "refreshed".
#[tokio::test]
async fn login_skips_a_jwt_source_in_a_sweep_and_refuses_it_by_name() {
    let h = Harness::start().await;
    h.bootstrap_jwt("gh", &jwt_expiring_in(3600), None).await;

    let sweep = ProfileLoginParams {
        environment: "gh".to_owned(),
        credential: None,
        request_id: None,
    };
    let _: OkResult = h
        .call(METHOD_PROFILE_LOGIN, &sweep, "gh")
        .await
        .expect("an env sweep must not fail over an unattended source");

    let named = ProfileLoginParams {
        environment: "gh".to_owned(),
        credential: Some("gh".to_owned()),
        request_id: None,
    };
    let err = h
        .call::<_, OkResult>(METHOD_PROFILE_LOGIN, &named, "gh")
        .await
        .expect_err("a named jwt credential has no login to run");
    let text = err.to_string();
    assert!(text.contains("no interactive login"), "{text}");
    assert!(text.contains("creds bootstrap"), "{text}");
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
        environment: "gh".to_owned(),
        credential: None,
        request_id: None,
    };
    let err = h
        .call::<_, OkResult>(METHOD_PROFILE_LOGIN, &sweep, "gh")
        .await
        .expect_err("a login cannot proceed while the write lock is held elsewhere");
    let text = err.to_string();
    assert!(text.contains("write lock"), "{text}");
    assert!(text.contains("nothing was written"), "{text}");

    drop(held);
    let _: OkResult = h
        .call(METHOD_PROFILE_LOGIN, &sweep, "gh")
        .await
        .expect("login completes once the lock is free");
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
        METHOD_PROFILE_LOGIN,
        &ProfileLoginParams {
            environment: "mfa".to_owned(),
            credential: None,
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
        METHOD_PROFILE_BOOTSTRAP,
        &ProfileBootstrapParams {
            environment: "aws-login-stall".to_owned(),
            credential: None,
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
        environment: "bad".to_owned(),
        credential: None,
        request_id: None,
        provider: ProviderParams::Jwt(ProviderParamsJwt {
            jwt: "not-a-jwt".to_owned(),
            env_var: None,
            identity_type: None,
        }),
    };
    let err: credsd_core::error::DaemonError = h
        .call::<_, OkResult>(METHOD_PROFILE_BOOTSTRAP, &params, "bad")
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
/// `describe` reads, an invalid name and an already-present name are per-profile skips that do
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

    // Landed in the served per-uid tree: `describe` reads them as iam-user, wrapped in same-named
    // 1:1 envs — the divergence the client-side path left invisible to the daemon.
    let manifest = h.describe("work").await;
    let entry = manifest
        .credentials
        .iter()
        .find(|e| e.credential == "work")
        .expect("work in manifest");
    assert_eq!(
        entry.source,
        credsd_core::rpc::CredentialSourceType::AwsIamUser
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

/// An edit made to `callers/<uid>/config.toml` by anything other than the daemon is served,
/// without a restart and without an eviction.
///
/// `evict_caller` covers only the daemon's own writes, so before the stat-on-access check a
/// hand-edited config was invisible for the process lifetime.
/// The env added here (`beta`) is never written through an RPC — the test
/// writes the file directly, exactly as an operator or a config-management tool would.
///
/// Ordering matters: `describe("alpha")` runs first to force the cached `CallerState` into
/// existence. Without that the later lookup would be a cold load and would pass whether or
/// not freshness is checked at all.
#[tokio::test]
async fn an_external_config_edit_is_picked_up_without_a_restart() {
    let h = Harness::start().await;
    let caller_root = platform::caller_root(nix::unistd::getuid().as_raw());

    h.bootstrap_jwt("alpha", &jwt_expiring_in(3600), None).await;
    assert_eq!(h.describe("alpha").await.environment, "alpha");

    // A cold load would pass this test vacuously, so prove the state really is cached: the
    // env we are about to add must not resolve yet.
    let config_path = caller_root.join("config.toml");
    let before = std::fs::read_to_string(&config_path).expect("read config");
    assert!(
        !before.contains("[environments.beta]"),
        "beta must not exist yet: {before}"
    );
    let mtime_before = std::fs::metadata(&config_path)
        .and_then(|m| m.modified())
        .expect("stat config");

    // The external edit. `beta` composes the credential `alpha` already sealed above, so the
    // only thing missing for it to resolve is the daemon noticing the file moved.
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

    let manifest = h.describe("beta").await;
    assert_eq!(manifest.environment, "beta");
    assert_eq!(
        manifest.credentials.len(),
        1,
        "beta composes exactly the credential the edit named"
    );
    assert_eq!(manifest.credentials[0].credential, "alpha");
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
        environment: "login".to_owned(),
        credential: None,
        request_id: None,
    };
    let err = h
        .call::<_, OkResult>(credsd_core::rpc::METHOD_PROFILE_LOGIN, &params, "login")
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
    // No env may reference the credential, or config validation refuses before the drift check.
    let root = platform::caller_root(nix::unistd::getuid().as_raw());
    std::fs::write(root.join("config.toml"), "").expect("clear config.toml");
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

fn sealed_dir(credential: &str) -> PathBuf {
    platform::caller_root(nix::unistd::getuid().as_raw())
        .join("credentials")
        .join(credential)
}

/// Removing an environment is gated: it survives an unapproved request, approval performs the
/// removal with nothing to re-send, and its credential is left in place either way.
#[tokio::test]
async fn removing_an_environment_waits_for_approval_and_keeps_its_credential() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("svc", "sk-value", None).await;

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
            h.get("svc").await,
            Err(credsd_core::error::DaemonError::EnvNotFound(_))
        ),
        "the environment is gone once approved"
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
    let env = challenge_of(h.remove_env("gone").await);
    h.approve_as_root(&env.id)
        .await
        .expect("approve env removal");

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
            Err(credsd_core::error::DaemonError::EnvNotFound(_))
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
    let env = challenge_of(h.remove_env("gone").await);
    h.approve_as_root(&env.id)
        .await
        .expect("approve env removal");
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
    let env = challenge_of(h.remove_env("gone").await);
    h.approve_as_root(&env.id)
        .await
        .expect("approve env removal");
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
    let env = challenge_of(h.remove_env("gone").await);
    h.approve_as_root(&env.id)
        .await
        .expect("approve env removal");
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
/// found, and a credential still in use is refused. Neither raises anything to approve, so a
/// challenge never confirms that a name exists.
#[tokio::test]
async fn removals_that_cannot_succeed_are_refused_without_a_challenge() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("inuse", "sk-value", None).await;

    assert!(matches!(
        h.remove_env("never-existed").await,
        Err(credsd_core::error::DaemonError::EnvNotFound(_))
    ));
    assert!(matches!(
        h.remove_credential("never-existed").await,
        Err(credsd_core::error::DaemonError::EnvNotFound(_))
    ));
    match h.remove_credential("inuse").await {
        Err(credsd_core::error::DaemonError::ApprovalRequired(_)) => {
            panic!("a credential still referenced must be refused, not offered for approval")
        }
        Err(e) => assert!(e.to_string().contains("still referenced"), "{e}"),
        Ok(_) => panic!("a referenced credential was removed"),
    }
}

/// An approved removal is performed against the state it was shown. When the records change in
/// between, the approval is discarded unperformed.
#[tokio::test]
async fn an_approved_removal_is_discarded_when_the_records_changed() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("kept", "sk-value", None).await;

    let challenge = challenge_of(h.remove_env("kept").await);
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

    let challenge = challenge_of(h.remove_env("kept").await);
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
#[tokio::test]
async fn unsetting_a_key_waits_for_approval() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;
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
#[tokio::test]
async fn a_config_set_approval_is_discarded_when_only_credentials_drift() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("tier", "sk-value", None).await;

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
#[tokio::test]
async fn unsetting_a_key_that_is_not_set_asks_for_nothing() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("plain", "sk-value", None).await;
    config_unset(&h, "plain", "sdk.endpoint_url")
        .await
        .expect("a no-op unset is not gated");
}

/// Import never replaces a credential, but its same-named environment can bind a new identity
/// into one already in use. That batch waits for one approval, which admits one identical
/// re-send; a batch of fresh names, and any dry run, is not gated at all.
#[tokio::test]
async fn an_import_that_binds_into_an_existing_environment_is_gated() {
    let h = Harness::start().await;
    h.try_bootstrap_static_secret("prod", Some("prod-original"), "sk-value")
        .await
        .expect("first bootstrap");

    let fresh = h.import(vec![import_profile("brand-new")], false).await;
    assert_eq!(fresh.outcomes[0].status, ImportStatus::Imported);

    let dry = h.import(vec![import_profile("prod")], true).await;
    assert_eq!(dry.outcomes[0].status, ImportStatus::WouldImport);

    let params = ImportParams {
        profiles: vec![import_profile("prod")],
        dry_run: false,
    };
    let gated: credsd_core::error::Result<ImportResult> =
        h.call(METHOD_PROFILE_IMPORT, &params, "import").await;
    let challenge = match gated {
        Err(credsd_core::error::DaemonError::ApprovalRequired(c)) => *c,
        Err(other) => panic!("expected APPROVAL_REQUIRED, got {other}"),
        Ok(_) => panic!("expected APPROVAL_REQUIRED, but the import was performed"),
    };
    assert!(
        challenge.description.contains(
            "bind new credential 'prod' (iam-user, access key AKIAIOSFODNN7EXAMPLE) into \
             existing environment 'prod'"
        ),
        "{}",
        challenge.description
    );
    // import_profile carries no identity_type: an absent value must not raise a false rewrite
    // disclosure.
    assert!(
        !challenge.description.contains("identity_type"),
        "{}",
        challenge.description
    );

    h.approve_as_root(&challenge.id).await.expect("approve");
    let applied = h.import(vec![import_profile("prod")], false).await;
    assert_eq!(applied.outcomes[0].status, ImportStatus::Imported);
}

/// Import's environment-binding wording had the same identity_type omission as bootstrap's: the
/// per-profile identity_type param can rewrite an existing environment's tier without the batch
/// challenge ever naming it.
#[tokio::test]
async fn import_disclosure_names_an_identity_type_rewrite_to_an_existing_environment() {
    let h = Harness::start().await;
    h.try_bootstrap_static_secret("prod", Some("prod-original"), "sk-value")
        .await
        .expect("first bootstrap"); // identity_type: automation

    let mut profile = import_profile("prod");
    profile.identity_type = Some("human".to_owned());
    let params = ImportParams {
        profiles: vec![profile],
        dry_run: false,
    };
    let gated: credsd_core::error::Result<ImportResult> =
        h.call(METHOD_PROFILE_IMPORT, &params, "import").await;
    let challenge = match gated {
        Err(credsd_core::error::DaemonError::ApprovalRequired(c)) => *c,
        Err(other) => panic!("expected APPROVAL_REQUIRED, got {other}"),
        Ok(_) => panic!("expected APPROVAL_REQUIRED, but the import was performed"),
    };
    assert!(
        challenge
            .description
            .contains("change environment 'prod''s identity_type from 'automation' to 'human'"),
        "{}",
        challenge.description
    );
}

/// The approver's only way to tell a benign re-import from a key substitution is the access key
/// id the batch carries, so the challenge must name the incoming key rather than a fixed example.
#[tokio::test]
async fn an_import_challenge_names_the_incoming_access_key() {
    let h = Harness::start().await;
    h.try_bootstrap_static_secret("prod", Some("prod-original"), "sk-value")
        .await
        .expect("first bootstrap");

    let params = ImportParams {
        profiles: vec![import_profile_keyed("prod", "AKIAI44QH8DHBEXAMPLE")],
        dry_run: false,
    };
    let gated: credsd_core::error::Result<ImportResult> =
        h.call(METHOD_PROFILE_IMPORT, &params, "import").await;
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
    h.try_bootstrap_static_secret("prod", Some("prod-original"), "sk-value")
        .await
        .expect("first bootstrap");

    let params = ImportParams {
        profiles: vec![import_profile_keyed("prod", "AKIA\x1b[2JEXAMPLE")],
        dry_run: false,
    };
    let gated: credsd_core::error::Result<ImportResult> =
        h.call(METHOD_PROFILE_IMPORT, &params, "import").await;
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
#[tokio::test]
async fn config_set_is_an_approval_required_error_until_approved() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("cfg", "sk-value", None).await;
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
#[tokio::test]
async fn unsetting_identity_type_is_refused_rather_than_gated() {
    let h = Harness::start().await;
    h.bootstrap_static_secret("cfg", "sk-value", None).await;
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
        environment: "late",
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
        },
        staging,
        &staged,
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
fn drift_config() -> PathBuf {
    let path = platform::caller_root(nix::unistd::getuid().as_raw()).join("config.toml");
    let before = std::fs::read_to_string(&path).expect("read config.toml");
    std::fs::write(
        &path,
        format!(
            "{before}\n[environments.beta]\ncredentials = [\"tier\"]\nidentity_type = \"automation\"\nregion = \"us-west-2\u{9b}2J\"\n"
        ),
    )
    .expect("hand-edit config.toml");
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
    let uid = nix::unistd::getuid().as_raw();
    let credentials_snapshot = platform::caller_root(uid).join("credentials_snapshot.enc");
    let sealed_before = std::fs::read(&credentials_snapshot).expect("credentials snapshot");
    drift_config();
    assert!(!h.daemon.caller_state(uid).config_drift.is_valid());

    let challenge = challenge_of(revalidate(&h).await);
    let d = &challenge.description;
    assert!(
        d.starts_with("revalidate drifted config files: config.toml\n"),
        "{d}"
    );
    assert!(
        d.contains("config.toml has drifted. Current contents:"),
        "{d}"
    );
    assert!(d.contains("[environments.beta]"), "{d}");
    assert!(
        d.contains("credentials.toml is unchanged and will not be resealed."),
        "{d}"
    );
    assert!(
        !d.contains('\u{9b}'),
        "a C1 control reached the approver: {d:?}"
    );
    assert!(d.contains("us-west-2\u{FFFD}2J"), "{d:?}");

    h.approve_as_root(&challenge.id).await.expect("approve");
    assert!(h.daemon.caller_state(uid).config_drift.is_valid());
    assert_eq!(
        std::fs::read(&credentials_snapshot).expect("credentials snapshot"),
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
    drift_config();
    let challenge = challenge_of(revalidate(&h).await);

    let credentials_path =
        platform::caller_root(nix::unistd::getuid().as_raw()).join("credentials.toml");
    let before = std::fs::read_to_string(&credentials_path).expect("read credentials.toml");
    std::fs::write(&credentials_path, format!("{before}\n# hand edit\n"))
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
    let saved: Vec<(PathBuf, Vec<u8>)> = ["config.toml", "config_snapshot.enc"]
        .iter()
        .map(|f| (root.join(f), std::fs::read(root.join(f)).expect("save")))
        .collect();

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
    h.approve_as_root(&set.id).await.expect("approve");
    h.get("tier").await.expect("the approved state is served");

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
    let uid = nix::unistd::getuid().as_raw();
    let record = platform::data_dir()
        .join("integrity")
        .join(format!("{uid}.enc"));
    std::fs::write(&record, b"{\"not\":\"sealed\"}").expect("corrupt the record");
    h.daemon.evict_caller(uid);

    let err = h.get("tier").await.expect_err("nothing is served");
    assert!(
        err.to_string()
            .starts_with("configuration error: config unverifiable:"),
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
    assert_eq!(token_of(&h.get("tier").await.expect("get")), "sk-value");
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
    use crate::server::dispatch::Method;
    use credsd_core::error::DaemonError;
    let writers: Vec<Method> = Method::all()
        .into_iter()
        .filter(|m| m.writes_load_bearing())
        .collect();
    assert!(writers.len() >= 9, "{writers:?}");
    for method in writers {
        let h = Harness::start().await;
        h.bootstrap_static_secret("tier", "sk-value", None).await;
        let uid = nix::unistd::getuid().as_raw();
        let root = platform::caller_root(uid);
        let pending = challenge_of(
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
            Method::ConfigSet => {
                h.call(
                    credsd_core::rpc::METHOD_CONFIG_SET,
                    &credsd_core::rpc::ConfigSetParams {
                        environment: "tier".to_owned(),
                        key: "region".to_owned(),
                        value: "us-west-2".to_owned(),
                    },
                    "tier",
                )
                .await
            }
            Method::ConfigUnset => {
                h.call(
                    credsd_core::rpc::METHOD_CONFIG_UNSET,
                    &credsd_core::rpc::ConfigUnsetParams {
                        environment: "tier".to_owned(),
                        key: "region".to_owned(),
                    },
                    "tier",
                )
                .await
            }
            Method::CredentialRemove => h
                .remove_credential("tier")
                .await
                .map(|_| Default::default()),
            Method::EnvRemove => h.remove_env("tier").await.map(|_| Default::default()),
            Method::FileRevalidate => revalidate(&h).await.map(|_| Default::default()),
            Method::ProfileBootstrap => h
                .try_bootstrap_static_secret("fresh", None, "sk-fresh")
                .await
                .map(|_| Default::default()),
            Method::ProfileLogin => {
                h.call(
                    METHOD_PROFILE_LOGIN,
                    &ProfileLoginParams {
                        environment: "tier".to_owned(),
                        credential: None,
                        request_id: None,
                    },
                    "tier",
                )
                .await
            }
            Method::ProfileImport => {
                h.call(
                    METHOD_PROFILE_IMPORT,
                    &ImportParams {
                        profiles: vec![import_profile("fresh")],
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
        environment: "kept",
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
        },
        staging,
        &staged,
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
        environment: "empty-static".to_owned(),
        credential: None,
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
        .call::<_, OkResult>(METHOD_PROFILE_BOOTSTRAP, &static_secret, "empty-static")
        .await
        .expect_err("an empty static secret must not bootstrap");
    assert!(err.to_string().contains("must not be empty"), "{err}");
    h.get("empty-static")
        .await
        .expect_err("a refused bootstrap leaves nothing to serve");

    let oauth = ProfileBootstrapParams {
        environment: "empty-oauth".to_owned(),
        credential: None,
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
        .call::<_, OkResult>(METHOD_PROFILE_BOOTSTRAP, &oauth, "empty-oauth")
        .await
        .expect_err("an empty client secret must not bootstrap");
    assert!(err.to_string().contains("must not be empty"), "{err}");
    h.get("empty-oauth")
        .await
        .expect_err("a refused bootstrap leaves nothing to serve");
}
