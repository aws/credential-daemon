//! OAuth 2.0 JWT Bearer grant (RFC 7523) provider.
//!
//! The caller supplies the assertion JWT at bootstrap; credsd seals it. To rotate, the
//! caller re-bootstraps with a fresh assertion — bootstrap is idempotent (upsert). The
//! daemon never reads caller-supplied file paths: the client reads the assertion file and
//! passes its contents, ensuring access is bounded by the caller's own permissions.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::config::JwtBearerConfig;
use crate::credentials::{expires_in_seconds, Credentials};
use crate::encryption::EncryptionService;
use crate::error::{DaemonError, Result};
use crate::providers::oauth::{http_client, token};
use crate::providers::{CredentialProvider, Renewed, Renewer};

const ASSERTION_FILE: &str = "jwt_assertion.enc";

/// Seal a JWT assertion to `<data_dir>/jwt_assertion.enc`. Bootstrap is the only writer;
/// re-bootstrap with a fresh assertion is how rotation works.
pub fn persist_assertion(
    encryption: &EncryptionService,
    data_dir: &Path,
    assertion: &Zeroizing<String>,
) -> Result<()> {
    // RFC 7523 assertions carry `exp`; one already past it can never be exchanged, so refuse it
    // here rather than at the first `get`.
    let exp = crate::providers::jwt::exp_of(assertion)?;
    crate::providers::jwt::check_not_expired(exp, chrono::Utc::now(), "assertion")?;
    encryption.seal_to_file(&data_dir.join(ASSERTION_FILE), assertion.as_bytes())
}

pub struct JwtBearerProvider {
    config: JwtBearerConfig,
    encryption: Arc<EncryptionService>,
    data_dir: PathBuf,
    http: reqwest::Client,
}

impl JwtBearerProvider {
    pub fn new(
        config: JwtBearerConfig,
        encryption: Arc<EncryptionService>,
        data_dir: PathBuf,
    ) -> Result<Self> {
        Ok(Self {
            config,
            encryption,
            data_dir,
            http: http_client()?,
        })
    }
}

impl CredentialProvider for JwtBearerProvider {
    fn renewer(&self) -> Option<&dyn Renewer> {
        Some(self)
    }

    fn mode_name(&self) -> &'static str {
        "jwt-bearer"
    }
}

#[async_trait]
impl Renewer for JwtBearerProvider {
    async fn renew(&self) -> Result<Renewed> {
        let plaintext = self
            .encryption
            .open_from_file(&self.data_dir.join(ASSERTION_FILE))
            .map_err(|e| {
                DaemonError::provider(format!(
                    "no usable assertion for credential: {}. Re-bootstrap with a fresh JWT.",
                    e
                ))
            })?;
        let jwt = String::from_utf8(plaintext.to_vec())
            .map_err(|_| DaemonError::provider("sealed assertion is not valid UTF-8"))?;

        match token::jwt_bearer(
            &self.config.token_url,
            &jwt,
            self.config.client_id.as_deref(),
            self.config.scope.as_deref(),
            &self.http,
        )
        .await
        {
            Ok(t) => Ok(Renewed::Ready(Credentials::access_token(
                t.access_token,
                Some(expires_in_seconds(
                    t.expires_in.min(crate::credentials::MAX_EXPIRES_IN_SECS),
                )),
            ))),
            // No interactive flow exists for jwt-bearer. A rejected assertion means it
            // is expired or invalid; the caller must re-bootstrap with a fresh one.
            Err(DaemonError::ReauthRequired(_)) => Err(DaemonError::provider(
                "assertion rejected by token endpoint; re-bootstrap with a fresh JWT assertion",
            )),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_key;
    use base64::Engine;
    use proptest::prelude::*;
    use tempfile::tempdir;

    /// An unsigned JWT with the given payload. `exp_of` reads only the payload, so the signature
    /// segment can be a placeholder.
    fn jwt_with_payload(payload: &str) -> Zeroizing<String> {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        Zeroizing::new(format!(
            "{}.{}.sig",
            b64.encode(br#"{"alg":"none"}"#),
            b64.encode(payload)
        ))
    }

    proptest! {
        /// Refused exactly when `exp` is not after `now`, across the whole positive i64 range the
        /// JWT `exp` claim can carry in practice, including the equal-instant boundary.
        #[test]
        fn refuses_exactly_when_exp_is_not_after_now(
            exp in 0i64..=4_102_444_800,
            now in 0i64..=4_102_444_800,
        ) {
            let exp_t = chrono::DateTime::from_timestamp(exp, 0).expect("in range");
            let now_t = chrono::DateTime::from_timestamp(now, 0).expect("in range");
            prop_assert_eq!(crate::providers::jwt::check_not_expired(exp_t, now_t, "assertion").is_ok(), exp > now);
        }
    }

    #[test]
    fn an_expired_assertion_is_refused_and_nothing_is_sealed() {
        let dir = tempdir().expect("tempdir");
        let enc = EncryptionService::new(generate_key().expect("key")).expect("encryption");
        let past = chrono::Utc::now().timestamp() - 60;
        let err = persist_assertion(
            &enc,
            dir.path(),
            &jwt_with_payload(&format!(r#"{{"exp":{past}}}"#)),
        )
        .expect_err("an expired assertion must not seal");
        assert!(err.to_string().contains("expired"), "{err}");
        assert!(!dir.path().join(ASSERTION_FILE).exists(), "nothing written");
    }

    #[test]
    fn an_assertion_without_exp_is_refused() {
        let dir = tempdir().expect("tempdir");
        let enc = EncryptionService::new(generate_key().expect("key")).expect("encryption");
        let err = persist_assertion(&enc, dir.path(), &jwt_with_payload(r#"{"sub":"svc"}"#))
            .expect_err("RFC 7523 assertions carry exp");
        assert!(err.to_string().contains("exp"), "{err}");
        assert!(!dir.path().join(ASSERTION_FILE).exists(), "nothing written");
    }

    #[test]
    fn a_live_assertion_seals() {
        let dir = tempdir().expect("tempdir");
        let enc = EncryptionService::new(generate_key().expect("key")).expect("encryption");
        let future = chrono::Utc::now().timestamp() + 600;
        persist_assertion(
            &enc,
            dir.path(),
            &jwt_with_payload(&format!(r#"{{"exp":{future}}}"#)),
        )
        .expect("a live assertion seals");
        assert!(dir.path().join(ASSERTION_FILE).exists());
    }

    fn provider() -> (JwtBearerProvider, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let enc = Arc::new(
            EncryptionService::new(generate_key().expect("key")).expect("encryption service"),
        );
        let p = JwtBearerProvider::new(
            JwtBearerConfig {
                token_url: "https://idp.example.com/token".into(),
                client_id: None,
                scope: None,
                identity_type: Default::default(),
            },
            enc,
            dir.path().to_path_buf(),
        )
        .expect("provider");
        (p, dir)
    }

    #[tokio::test]
    async fn no_sealed_assertion_errors() {
        let (p, _d) = provider();
        let err = p.renew().await.unwrap_err();
        assert!(err.to_string().contains("Re-bootstrap"));
    }

    // Exchange tests live in providers::oauth::token.
}
