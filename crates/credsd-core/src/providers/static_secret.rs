//! A pre-issued secret the user already holds, served verbatim as the credential.
//!
//! The source for an API that authenticates with something credsd cannot obtain for itself: a
//! personal access token, a service API key, a pre-provisioned bearer token. Nothing is
//! exchanged and nothing is federated — the credential *is* the secret, so this provider is
//! the seal, the optional expiry, and the serving, and no more.
//!
//! The secret lives sealed in `static_secret.enc` under the credential's data dir, the
//! convention every other provider's secret follows (`jwt.enc`, `iam_user.enc`,
//! `sso_token.enc`). It differs from `jwt` in exactly one way, and it is the reason this is a
//! separate source: a JWT states its own lifetime in `exp`, while an opaque secret states
//! nothing. The expiry is therefore whatever the user declared in `credentials.toml`, and
//! absent means never — credsd does not invent a lifetime for a string it cannot read.
//!
//! The secret's bytes are never interpreted. Any non-empty byte sequence is a valid secret,
//! including one that happens to be a JWT; reading an `exp` out of it is the `jwt` source's
//! job, and doing it here would silently give two sources different behaviour for the same
//! input.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use zeroize::Zeroizing;

use crate::config::StaticSecretConfig;
use crate::credentials::Credentials;
use crate::encryption::EncryptionService;
use crate::error::{DaemonError, Result};
use crate::providers::{CredentialProvider, Renewed, Renewer};

/// The sealed artifact, beside the credential's other state.
pub const SECRET_FILE: &str = "static_secret.enc";

/// Seal a secret as the credential's material.
///
/// Bootstrap is the only writer. Re-running it is how a rotated secret replaces the old one,
/// since nothing in this provider can obtain a new one — there is no issuer to ask.
///
/// An empty secret is refused here rather than at first use: sealing it would produce a
/// credential that exists, reports healthy, and authenticates nothing, and the failure would
/// surface at the API instead of at the command that caused it. The caller still has the input
/// in hand at this point and can say which file was empty.
pub fn persist_secret(
    encryption: &EncryptionService,
    data_dir: &Path,
    secret: &Zeroizing<String>,
) -> Result<()> {
    if secret.is_empty() {
        return Err(DaemonError::provider(
            "the secret must not be empty; a static-secret credential must carry a value",
        ));
    }
    encryption.seal_to_file(&data_dir.join(SECRET_FILE), secret.as_bytes())
}

/// The command that seals a fresh secret for `credential`, named by every message reporting
/// there is none to serve.
///
/// `<env>` and `<path>` are placeholders rather than real values on purpose. The recorded
/// `secret_source` is caller-supplied text, and interpolating it here would put it into daemon
/// log lines and error strings — the same reason `jwt::reseal_command` takes no path.
pub fn reseal_command(credential: &str) -> String {
    format!(
        "creds bootstrap --env <env> --credential {credential} static-secret --secret-file <path>"
    )
}

pub struct StaticSecretProvider {
    credential_name: String,
    config: StaticSecretConfig,
    encryption: Arc<EncryptionService>,
    data_dir: PathBuf,
}

impl StaticSecretProvider {
    pub fn new(
        credential_name: String,
        config: StaticSecretConfig,
        encryption: Arc<EncryptionService>,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            credential_name,
            config,
            encryption,
            data_dir,
        }
    }
}

impl CredentialProvider for StaticSecretProvider {
    /// Renewable in the trait's sense only: serving the sealed secret needs no human, so the
    /// store can load it on a cache miss. What "renewal" cannot do is produce a *different*
    /// secret — there is no issuer to ask — so an expired one is an error naming the re-seal
    /// rather than a `ReauthRequired`, which would advertise an interactive flow that does not
    /// exist. Identical posture to `jwt`.
    ///
    /// The background refresh loop still leaves this source alone, because a credential with no
    /// declared expiry never nears one and there is nothing to refresh toward.
    fn renewer(&self) -> Option<&dyn Renewer> {
        Some(self)
    }

    fn mode_name(&self) -> &'static str {
        "static-secret"
    }
}

#[async_trait]
impl Renewer for StaticSecretProvider {
    async fn renew(&self) -> Result<Renewed> {
        let plaintext = self
            .encryption
            .open_from_file(&self.data_dir.join(SECRET_FILE))
            .map_err(|e| {
                DaemonError::provider(format!(
                    "no usable secret for credential '{}': {}. Seal one with '{}'.",
                    self.credential_name,
                    e,
                    reseal_command(&self.credential_name)
                ))
            })?;
        let secret = Zeroizing::new(String::from_utf8(plaintext.to_vec()).map_err(|_| {
            DaemonError::provider(format!(
                "sealed secret for credential '{}' is not valid UTF-8",
                self.credential_name
            ))
        })?);

        // The declared expiry, if the user recorded one. Checked here rather than left to the
        // store so an expired secret is an error naming the fix, not a cached credential the
        // store re-asks for on every miss and never explains.
        if let Some(expires_at) = self.config.expires_at {
            if Utc::now() >= expires_at {
                return Err(DaemonError::provider(format!(
                    "the secret sealed for credential '{}' was declared to expire at {}; seal a \
                     fresh one with '{}'",
                    self.credential_name,
                    expires_at.to_rfc3339(),
                    reseal_command(&self.credential_name)
                )));
            }
        }

        // `None` passes straight through as "never expires": an opaque secret states no
        // lifetime, and inventing one here would either cut a live credential short or claim a
        // dead one is valid.
        Ok(Renewed::Ready(Credentials::access_token(
            secret.to_string(),
            self.config.expires_at,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_key;
    use proptest::prelude::*;
    use tempfile::tempdir;

    fn encryption() -> EncryptionService {
        EncryptionService::new(generate_key().expect("key")).expect("encryption service")
    }

    #[test]
    fn a_sealed_secret_round_trips() {
        let dir = tempdir().expect("tempdir");
        let enc = encryption();
        let secret = Zeroizing::new("sk-not-a-real-key".to_owned());

        persist_secret(&enc, dir.path(), &secret).expect("seal");
        let opened = enc
            .open_from_file(&dir.path().join(SECRET_FILE))
            .expect("open");
        assert_eq!(opened.as_slice(), secret.as_bytes());
    }

    /// The sealed file must not contain the secret in the clear. Asserted directly rather than
    /// inferred from the round trip, because a `seal_to_file` that wrote plaintext would pass a
    /// round-trip test perfectly.
    #[test]
    fn the_sealed_file_does_not_contain_the_secret() {
        let dir = tempdir().expect("tempdir");
        let secret = Zeroizing::new("sk-plaintext-must-not-appear".to_owned());

        persist_secret(&encryption(), dir.path(), &secret).expect("seal");

        let on_disk = std::fs::read(dir.path().join(SECRET_FILE)).expect("read");
        assert!(
            !on_disk
                .windows(secret.len())
                .any(|w| w == secret.as_bytes()),
            "plaintext secret found in {SECRET_FILE}"
        );
    }

    /// An empty secret is refused at seal time. Sealing it would produce a credential that
    /// exists and reports healthy while authenticating nothing.
    #[test]
    fn an_empty_secret_is_refused_before_sealing() {
        let dir = tempdir().expect("tempdir");
        let err = persist_secret(&encryption(), dir.path(), &Zeroizing::new(String::new()))
            .expect_err("an empty secret must not seal");

        assert!(err.to_string().contains("empty"), "{err}");
        assert!(
            !dir.path().join(SECRET_FILE).exists(),
            "a refused secret must leave no file behind"
        );
    }

    /// Re-sealing replaces the secret rather than appending or leaving the old one readable:
    /// this is the rotation path (Req 2.4), so the previous value must not survive.
    #[test]
    fn re_sealing_replaces_the_previous_secret() {
        let dir = tempdir().expect("tempdir");
        let enc = encryption();
        let old = Zeroizing::new("sk-rotated-away".to_owned());
        let new = Zeroizing::new("sk-current-value".to_owned());

        persist_secret(&enc, dir.path(), &old).expect("seal old");
        persist_secret(&enc, dir.path(), &new).expect("seal new");

        let opened = enc
            .open_from_file(&dir.path().join(SECRET_FILE))
            .expect("open");
        assert_eq!(opened.as_slice(), new.as_bytes());

        let on_disk = std::fs::read(dir.path().join(SECRET_FILE)).expect("read");
        assert!(
            !on_disk.windows(old.len()).any(|w| w == old.as_bytes()),
            "the rotated-away secret is still present in {SECRET_FILE}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_sealed_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        persist_secret(
            &encryption(),
            dir.path(),
            &Zeroizing::new("sk-check-modes".to_owned()),
        )
        .expect("seal");

        let mode = std::fs::metadata(dir.path().join(SECRET_FILE))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{SECRET_FILE} is {mode:o}");
    }

    /// The command names the credential and the subcommand that seals one, and never carries a
    /// caller-supplied path — `<path>` stays a placeholder so nothing from config reaches a log.
    #[test]
    fn the_reseal_command_names_the_credential_and_no_path() {
        let cmd = reseal_command("openai");
        assert!(cmd.contains("static-secret"), "{cmd}");
        assert!(cmd.contains("openai"), "{cmd}");
        assert!(cmd.contains("<path>"), "{cmd}");
    }

    fn provider(
        config: StaticSecretConfig,
    ) -> (
        StaticSecretProvider,
        Arc<EncryptionService>,
        tempfile::TempDir,
    ) {
        let dir = tempdir().expect("tempdir");
        let enc = Arc::new(encryption());
        let provider = StaticSecretProvider::new(
            "openai".to_owned(),
            config,
            enc.clone(),
            dir.path().to_path_buf(),
        );
        (provider, enc, dir)
    }

    fn config(expires_at: Option<chrono::DateTime<Utc>>) -> StaticSecretConfig {
        StaticSecretConfig {
            env_var: None,
            expires_at,
            secret_source: None,
            identity_type: Default::default(),
        }
    }

    /// Seals a value for cases whose assertion is about expiry rather than about the secret.
    fn seal_any(enc: &EncryptionService, dir: &Path) {
        persist_secret(enc, dir, &Zeroizing::new("sk-any-value".to_owned())).expect("seal");
    }

    fn token_of(renewed: &Renewed) -> &str {
        match renewed {
            Renewed::Ready(creds) => match &creds.data {
                crate::credentials::CredentialData::AccessToken { token } => token,
                other => panic!("expected an access token, got {other:?}"),
            },
            Renewed::ReauthRequired(_) => panic!("expected ready credentials"),
        }
    }

    /// The whole point of the source: what was sealed is what is served, unchanged.
    #[tokio::test]
    async fn a_sealed_secret_is_served_verbatim() {
        let (p, enc, dir) = provider(config(None));
        let secret = Zeroizing::new("sk-served-verbatim".to_owned());
        persist_secret(&enc, dir.path(), &secret).expect("seal");

        let renewed = p.renew().await.expect("renew");
        assert_eq!(token_of(&renewed), secret.as_str());
    }

    /// No declared expiry serves as "never expires": `expires_at` is `None` on the wire and the
    /// credential is not expired. Serving it with a fabricated expiry would either cut a live
    /// credential short or claim a dead one is valid.
    #[tokio::test]
    async fn an_undeclared_expiry_serves_as_never() {
        let (p, enc, dir) = provider(config(None));
        persist_secret(&enc, dir.path(), &Zeroizing::new("sk-eternal".to_owned())).expect("seal");

        let Renewed::Ready(creds) = p.renew().await.expect("renew") else {
            panic!("expected ready credentials");
        };
        assert!(creds.expires_at.is_none(), "{:?}", creds.expires_at);
        assert!(!creds.is_expired());
    }

    /// A declared expiry is carried through so the shared status logic can report
    /// Active/Expiring/Expired against it.
    #[tokio::test]
    async fn a_declared_expiry_is_carried_through() {
        let declared = Utc::now() + chrono::TimeDelta::hours(1);
        let (p, enc, dir) = provider(config(Some(declared)));
        seal_any(&enc, dir.path());

        let Renewed::Ready(creds) = p.renew().await.expect("renew") else {
            panic!("expected ready credentials");
        };
        assert_eq!(creds.expires_at, Some(declared));
        assert!(!creds.is_expired());
    }

    /// Past its declared expiry the secret is refused with the command that replaces it, not
    /// returned. Returning it would have the store cache a dead credential and re-ask on every
    /// miss without ever saying why.
    #[tokio::test]
    async fn a_secret_past_its_declared_expiry_is_refused() {
        let (p, enc, dir) = provider(config(Some(Utc::now() - chrono::TimeDelta::minutes(1))));
        seal_any(&enc, dir.path());

        let err = p
            .renew()
            .await
            .expect_err("an expired secret must not serve");
        let text = err.to_string();
        assert!(text.contains("expire"), "{text}");
        assert!(text.contains("static-secret"), "{text}");
        assert!(text.contains("openai"), "{text}");
    }

    /// An absent secret names the command that seals one. Never a decrypt error, and never
    /// empty credentials — a caller that gets "" authenticates as nobody and learns nothing.
    #[tokio::test]
    async fn an_absent_secret_names_the_bootstrap_command() {
        let (p, _enc, _dir) = provider(config(None));

        let err = p.renew().await.expect_err("no secret sealed");
        let text = err.to_string();
        assert!(text.contains("no usable secret"), "{text}");
        assert!(text.contains("creds bootstrap"), "{text}");
        assert!(text.contains("static-secret"), "{text}");
    }

    /// Renewal reloads and never mints, which is what lets a cache miss be served while leaving
    /// the source re-auth-only. A `None` here would make the credential unservable: the store
    /// reaches sealed material only through the renewer.
    #[test]
    fn the_provider_offers_a_renewer_and_names_its_mode() {
        let (p, _enc, _dir) = provider(config(None));
        assert!(p.renewer().is_some());
        assert_eq!(p.mode_name(), "static-secret");
    }

    proptest! {
        /// A secret is opaque: any non-empty byte string survives sealing byte-for-byte. The
        /// provider must not trim, re-encode, or interpret it — a token altered in transit
        /// fails at the API, where the cause is invisible.
        #[test]
        fn any_non_empty_secret_survives_sealing(secret in "\\PC{1,512}") {
            let dir = tempdir().expect("tempdir");
            let enc = encryption();
            let secret = Zeroizing::new(secret);

            persist_secret(&enc, dir.path(), &secret).expect("seal");
            let opened = enc
                .open_from_file(&dir.path().join(SECRET_FILE))
                .expect("open");
            prop_assert_eq!(opened.as_slice(), secret.as_bytes());
        }
    }
}
