//! OAuth 2.0 client-credentials (2LO) provider.
//!
//! Entirely unattended: every renewal is a `POST` to the token endpoint with the
//! client's own credentials, no user interaction required.
//!
//! Authentication method is inferred at runtime from which sealed file exists:
//!   - `oauth_client_secret.enc` present → `client_secret_basic`
//!   - absent → `private_key_jwt` (ES256 key in `oauth_client_key.enc`)
//!
//! Neither secret is stored in `credentials.toml`. `bootstrap` seals the chosen
//! material via [`persist_secret`] or [`persist_key`], and the provider unseals at
//! renew time.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::config::{OauthConfig, OauthGrant};
use crate::credentials::{expires_in_seconds, Credentials};
use crate::encryption::EncryptionService;
use crate::error::{DaemonError, Result};
use crate::providers::oauth::{http_client, token};
use crate::providers::{CredentialProvider, Renewed, Renewer};

pub const SECRET_FILE: &str = "oauth_client_secret.enc";
pub const KEY_FILE: &str = "oauth_client_key.enc";

/// Seal `client_secret` into `data_dir/oauth_client_secret.enc`. Called by bootstrap.
pub fn persist_secret(
    data_dir: &std::path::Path,
    client_secret: &str,
    enc: &EncryptionService,
) -> Result<()> {
    enc.seal_to_file(&data_dir.join(SECRET_FILE), client_secret.as_bytes())
}

/// Seal a PKCS#8 private key into `data_dir/oauth_client_key.enc`. Called by bootstrap.
pub fn persist_key(
    data_dir: &std::path::Path,
    pkcs8: &[u8],
    enc: &EncryptionService,
) -> Result<()> {
    enc.seal_to_file(&data_dir.join(KEY_FILE), pkcs8)
}

pub struct ClientCredentialsProvider {
    credential_name: String,
    config: OauthConfig,
    data_dir: PathBuf,
    encryption: Arc<EncryptionService>,
    http: reqwest::Client,
}

impl ClientCredentialsProvider {
    pub fn new(
        credential_name: String,
        config: OauthConfig,
        data_dir: PathBuf,
        encryption: Arc<EncryptionService>,
    ) -> Result<Self> {
        Ok(Self {
            credential_name,
            config,
            data_dir,
            encryption,
            http: http_client()?,
        })
    }
}

impl CredentialProvider for ClientCredentialsProvider {
    fn renewer(&self) -> Option<&dyn Renewer> {
        Some(self)
    }

    fn mode_name(&self) -> &'static str {
        "oauth"
    }
}

#[async_trait]
impl Renewer for ClientCredentialsProvider {
    async fn renew(&self) -> Result<Renewed> {
        if !matches!(self.config.grant, OauthGrant::ClientCredentials) {
            return Err(DaemonError::provider(format!(
                "oauth credential '{}': unsupported grant type",
                self.credential_name
            )));
        }

        // Infer auth method from which sealed file exists. `secret_str` must outlive `auth`
        // because ClientCredentialsAuth::Secret borrows from it.
        let secret_path = self.data_dir.join(SECRET_FILE);
        let secret_str: Zeroizing<String>;
        let pkcs8: zeroize::Zeroizing<Vec<u8>>;
        let auth = if secret_path.exists() {
            let bytes = self.encryption.open_from_file(&secret_path).map_err(|_| {
                DaemonError::provider(format!(
                    "oauth credential '{}': failed to unseal client secret",
                    self.credential_name
                ))
            })?;
            secret_str = Zeroizing::new(String::from_utf8(bytes.to_vec()).map_err(|_| {
                DaemonError::provider(format!(
                    "oauth credential '{}': sealed client secret is not valid UTF-8",
                    self.credential_name
                ))
            })?);
            token::ClientCredentialsAuth::Secret(&secret_str)
        } else {
            // Load sealed key on every renewal so a rotated key is picked up immediately.
            pkcs8 = self
                .encryption
                .open_from_file(&self.data_dir.join(KEY_FILE))
                .map_err(|e| {
                    DaemonError::provider(format!(
                        "oauth credential '{}': no client secret or key — run bootstrap: {}",
                        self.credential_name, e
                    ))
                })?;
            token::ClientCredentialsAuth::PrivateKeyJwt { pkcs8 }
        };

        match token::client_credentials(
            &self.config.token_url,
            &self.config.client_id,
            auth,
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
            Err(DaemonError::ReauthRequired(_)) => Err(DaemonError::provider(format!(
                "oauth credential '{}': token endpoint rejected the client credentials; check client_id and the client secret, then run bootstrap again",
                self.credential_name
            ))),
            Err(e) => Err(e),
        }
    }
}
