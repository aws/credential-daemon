//! Long-term IAM key brokered into short-lived credentials via `sts:GetSessionToken`.
//!
//! The daemon holds the long-term `AKIA` key encrypted on disk — one `iam_user.enc` file per
//! credential under the data dir, the same convention the SSO provider uses for `sso_token.enc` —
//! and hands children only the ephemeral session credentials GetSessionToken returns. The forever
//! key never reaches a child, and never lands in `credentials.toml`. This is blast-radius
//! reduction, not permission scoping — the brokered credentials carry the same permissions as the
//! key.
//!
//! Without MFA the daemon mints unattended: the stored key brokers a session with no human, so
//! the source renews like any other. With `mfa_serial` set, GetSessionToken requires a fresh
//! code the daemon can't supply, so the only unattended path is the session `credsd login`
//! persists (`iam_session.enc`): [`renew`](SessionTokenProvider::renew) serves it until it
//! expires, then reports [`ReauthInput::Code`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_sts::config::{BehaviorVersion, Credentials as StsCredentials, Region};
use aws_sdk_sts::error::ProvideErrorMetadata as _;
use aws_sdk_sts::Client;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::IamUserConfig;
use crate::credentials::Credentials;
use crate::encryption::{EncryptionService, SecretString};
use crate::error::{DaemonError, Result};
use crate::providers::{CredentialProvider, ReauthInput, Renewed, Renewer};

/// The key-pair blob lives beside the SSO provider's `sso_token.enc` under the credential's data
/// dir, so both credential kinds store their secret material the same way: an encrypted file, never
/// `credentials.toml`.
const KEY_FILE: &str = "iam_user.enc";

/// Where `credsd login` persists an MFA-minted session, so the daemon can serve it unattended
/// until expiry. Encrypted like every other artifact under the credential's data dir.
const SESSION_FILE: &str = "iam_session.enc";

// `secret_access_key` is a `SecretString`, so deriving `Debug` is safe — its own `Debug` redacts,
// and the whole struct zeroizes on drop. Read-only: `SecretString` is not `Serialize`, so this is
// the deserialize (load) shape; the write shape is `KeyPairDisk` in `persist_key_pair`.
#[derive(Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
struct KeyPair {
    #[zeroize(skip)]
    access_key_id: String,
    secret_access_key: SecretString,
}

/// Encrypt a key pair and write it to `<data_dir>/iam_user.enc` (0600). Bootstrap writes it; the
/// provider reads it back. Mirrors the SSO provider's token persistence — the secret material lives
/// in its own encrypted file, keyed by credential name, not inline in `credentials.toml`.
pub fn persist_key_pair(
    encryption: &EncryptionService,
    data_dir: &Path,
    access_key_id: &str,
    secret_access_key: &str,
) -> Result<()> {
    // The on-disk (write) shape: plain `&str` fields, so `SecretString`'s absent `Serialize` can't
    // be worked around. Field names mirror `KeyPair` for the read round-trip. The serialized buffer
    // is cleartext until `seal_to_file` encrypts it, so zeroize it on drop.
    #[derive(Serialize)]
    struct KeyPairDisk<'a> {
        access_key_id: &'a str,
        secret_access_key: &'a str,
    }
    let json = Zeroizing::new(serde_json::to_vec(&KeyPairDisk {
        access_key_id,
        secret_access_key,
    })?);
    encryption.seal_to_file(&data_dir.join(KEY_FILE), &json)
}

pub struct SessionTokenProvider {
    credential_name: String,
    config: IamUserConfig,
    encryption: Arc<EncryptionService>,
    data_dir: PathBuf,
}

impl SessionTokenProvider {
    pub fn new(
        credential_name: String,
        config: IamUserConfig,
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

    fn key_pair(&self) -> Result<KeyPair> {
        // `open_from_file` hands back a self-zeroizing buffer, so the decrypted JSON is scrubbed on
        // drop; the parsed `KeyPair` is `ZeroizeOnDrop` in turn.
        let plaintext = self
            .encryption
            .open_from_file(&self.data_dir.join(KEY_FILE))
            .map_err(|e| {
                let e = e.detail();
                DaemonError::provider(format!(
                    "no usable key for credential '{}': {}. If the keystore key changed, \
                     re-run 'credsd bootstrap --env {}'.",
                    self.credential_name, e, self.credential_name
                ))
            })?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Broker the stored long-term key into a session via `sts:GetSessionToken`, optionally
    /// presenting an `(mfa_serial, token_code)` pair. The only GetSessionToken call site.
    async fn session_token(&self, mfa: Option<(&str, &str)>) -> Result<Credentials> {
        let pair = self.key_pair()?;
        let signer = StsCredentials::new(
            pair.access_key_id.clone(),
            pair.secret_access_key.expose_secret().to_owned(),
            None,
            None,
            "credsd",
        );
        let conf = aws_sdk_sts::Config::builder()
            .region(Region::new(self.config.region.clone()))
            .credentials_provider(signer)
            .behavior_version(BehaviorVersion::latest())
            .build();
        let mut req = Client::from_conf(conf)
            .get_session_token()
            .set_duration_seconds(self.config.duration_seconds);
        if let Some((serial, code)) = mfa {
            req = req.serial_number(serial).token_code(code);
        }
        let out = req.send().await.map_err(|e| {
            let msg = e
                .as_service_error()
                .and_then(|se| se.message())
                .unwrap_or("AWS authentication failed");
            DaemonError::provider(msg)
        })?;

        let creds = out
            .credentials()
            .ok_or_else(|| DaemonError::provider("no credentials in GetSessionToken response"))?;
        let expires_at = DateTime::from_timestamp(creds.expiration().secs(), 0)
            .unwrap_or_else(|| crate::credentials::expires_in_seconds(3600));

        Ok(Credentials::session(
            creds.access_key_id().to_string(),
            creds.secret_access_key().to_string(),
            creds.session_token().to_string(),
            expires_at,
        ))
    }

    /// Unattended mint — no MFA. Used by `renew` for non-MFA keys and by bootstrap's verify.
    pub async fn mint(&self) -> Result<Credentials> {
        self.session_token(None).await
    }

    /// Interactive mint — presents an MFA code. Driven by `credsd login`, never the daemon.
    pub async fn mint_with_mfa(&self, code: &str) -> Result<Credentials> {
        let serial = self.config.mfa_serial.as_deref().ok_or_else(|| {
            DaemonError::config("mint_with_mfa called but credential has no mfa_serial")
        })?;
        self.session_token(Some((serial, code))).await
    }

    /// Persist a minted session so the daemon can serve it unattended until it expires. Only
    /// meaningful for MFA keys, whose session cannot be re-minted without a fresh code.
    pub fn persist_session(&self, creds: &Credentials) -> Result<()> {
        let json = Zeroizing::new(serde_json::to_vec(creds)?);
        self.encryption
            .seal_to_file(&self.data_dir.join(SESSION_FILE), &json)
    }

    fn load_session(&self) -> Result<Option<Credentials>> {
        let path = self.data_dir.join(SESSION_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let plaintext = self.encryption.open_from_file(&path)?;
        // A session that decrypts but won't parse is reported as absent, so `renew` answers with a
        // re-auth challenge — the actionable outcome, since `credsd login` rewrites this file.
        // Propagating instead surfaces the credential as unknown (the error is only logged upstream)
        // and re-fails the same parse every refresh. Decrypt and I/O failures still propagate above:
        // logging in again would not fix those.
        match serde_json::from_slice(&plaintext) {
            Ok(creds) => Ok(Some(creds)),
            Err(e) => {
                warn!(
                    credential = %self.credential_name,
                    error = %e,
                    "persisted session is unreadable, treating as absent"
                );
                Ok(None)
            }
        }
    }
}

impl CredentialProvider for SessionTokenProvider {
    // The stored long-term key re-mints a session unattended, so this source is always
    // renewable — there is no interactive step to fall back to.
    fn renewer(&self) -> Option<&dyn Renewer> {
        Some(self)
    }

    fn mode_name(&self) -> &'static str {
        "aws-iam-user"
    }
}

#[async_trait]
impl Renewer for SessionTokenProvider {
    async fn renew(&self) -> Result<Renewed> {
        // An MFA-gated key cannot be minted unattended — GetSessionToken demands a fresh code.
        // The only unattended path is the session `credsd login` persisted: serve it until it
        // expires, then a re-auth challenge. Without MFA, the key re-mints on demand.
        if let Some(serial) = self.config.mfa_serial.as_deref() {
            return Ok(match self.load_session()? {
                Some(creds) if !creds.is_expired() => Renewed::Ready(creds),
                _ => Renewed::ReauthRequired(ReauthInput::Code {
                    label: format!("MFA code for {}", serial),
                }),
            });
        }
        self.mint().await.map(Renewed::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_key;
    use tempfile::tempdir;

    fn service() -> Arc<EncryptionService> {
        Arc::new(EncryptionService::new(generate_key().unwrap()).unwrap())
    }
    fn provider(encryption: Arc<EncryptionService>, data_dir: PathBuf) -> SessionTokenProvider {
        SessionTokenProvider::new(
            "work".into(),
            IamUserConfig {
                region: "us-east-1".into(),
                duration_seconds: None,
                mfa_serial: None,
                identity_type: Default::default(),
            },
            encryption,
            data_dir,
        )
    }
    fn mfa_provider(encryption: Arc<EncryptionService>, data_dir: PathBuf) -> SessionTokenProvider {
        SessionTokenProvider::new(
            "work".into(),
            IamUserConfig {
                region: "us-east-1".into(),
                duration_seconds: None,
                mfa_serial: Some("arn:aws:iam::111111111111:mfa/user".into()),
                identity_type: Default::default(),
            },
            encryption,
            data_dir,
        )
    }
    fn session(expires_at: chrono::DateTime<chrono::Utc>) -> Credentials {
        Credentials::session("AK".into(), "SK".into(), "TOK".into(), expires_at)
    }

    /// An MFA key cannot mint unattended, so with no persisted session `renew` asks for a code
    /// (the provider-declared input) rather than erroring or blocking.
    #[tokio::test]
    async fn mfa_renew_without_a_session_asks_for_a_code() {
        let dir = tempdir().unwrap();
        match mfa_provider(service(), dir.path().to_path_buf())
            .renew()
            .await
            .unwrap()
        {
            Renewed::ReauthRequired(ReauthInput::Code { label }) => {
                assert!(label.contains("mfa/user"), "label was: {}", label)
            }
            other => panic!("expected Code reauth, got {:?}", other),
        }
    }

    /// A session `credsd login` persisted is served unattended until it expires.
    #[tokio::test]
    async fn mfa_renew_serves_a_valid_persisted_session() {
        let dir = tempdir().unwrap();
        let provider = mfa_provider(service(), dir.path().to_path_buf());
        provider
            .persist_session(&session(chrono::Utc::now() + chrono::Duration::hours(1)))
            .unwrap();
        assert!(matches!(provider.renew().await.unwrap(), Renewed::Ready(_)));
    }

    /// Once that session expires, the daemon must not serve it — `renew` falls back to a code.
    #[tokio::test]
    async fn mfa_renew_asks_for_a_code_once_the_session_expires() {
        let dir = tempdir().unwrap();
        let provider = mfa_provider(service(), dir.path().to_path_buf());
        provider
            .persist_session(&session(chrono::Utc::now() - chrono::Duration::minutes(1)))
            .unwrap();
        assert!(matches!(
            provider.renew().await.unwrap(),
            Renewed::ReauthRequired(ReauthInput::Code { .. })
        ));
    }

    /// A session that decrypts but no longer parses — here the pre-`type`-tag payload shape — is
    /// treated as absent, so `renew` asks for a code. `credsd login` rewrites the file, which is
    /// the fix; reporting an error would instead surface the credential as unknown.
    #[tokio::test]
    async fn mfa_renew_asks_for_a_code_when_the_session_is_unparseable() {
        let dir = tempdir().unwrap();
        let encryption = service();
        encryption
            .seal_to_file(
                &dir.path().join(SESSION_FILE),
                br#"{"credential_type":"session_credentials",
                     "data":{"access_key":"AK","secret_key":"SK","session_token":"TOK"},
                     "expires_at":"2099-01-01T00:00:00Z"}"#,
            )
            .unwrap();
        let provider = mfa_provider(Arc::clone(&encryption), dir.path().to_path_buf());
        assert!(matches!(
            provider.renew().await.unwrap(),
            Renewed::ReauthRequired(ReauthInput::Code { .. })
        ));
    }

    #[test]
    fn key_pair_round_trips_through_the_enc_file() {
        let encryption = service();
        let dir = tempdir().unwrap();
        persist_key_pair(&encryption, dir.path(), "AKIAEXAMPLE", "secretkey").unwrap();
        let pair = provider(encryption, dir.path().to_path_buf())
            .key_pair()
            .unwrap();
        assert_eq!(pair.access_key_id, "AKIAEXAMPLE");
        assert_eq!(pair.secret_access_key.expose_secret(), "secretkey");
    }
    #[test]
    fn wrong_key_cannot_open() {
        let dir = tempdir().unwrap();
        persist_key_pair(&service(), dir.path(), "AKIAEXAMPLE", "secretkey").unwrap();
        assert!(provider(service(), dir.path().to_path_buf())
            .key_pair()
            .is_err());
    }
    #[test]
    fn missing_key_file_names_the_bootstrap_fix() {
        let dir = tempdir().unwrap();
        let err = provider(service(), dir.path().to_path_buf())
            .key_pair()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("credsd bootstrap"),
            "unexpected error: {}",
            err
        );
    }
}
