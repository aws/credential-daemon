//! AWS SSO (IAM Identity Center) credential provider.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_sso::error::ProvideErrorMetadata as _;
use aws_sdk_sso::Client as SsoClient;
use aws_sdk_ssooidc::operation::create_token::CreateTokenError;
use aws_sdk_ssooidc::Client as OidcClient;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::log::escape_log;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::SsoConfig;
use crate::credentials::Credentials;
use crate::encryption::EncryptionService;
use crate::error::{DaemonError, Result};
use crate::providers::{CredentialProvider, ReauthInput, Renewed, Renewer};

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CachedSsoToken {
    pub access_token: String,
    #[zeroize(skip)]
    pub expires_at: String,
    pub refresh_token: Option<String>,
    #[zeroize(skip)]
    pub client_id: String,
    pub client_secret: String,
    #[zeroize(skip)]
    pub start_url: String,
    #[zeroize(skip)]
    pub region: String,
}

/// Result of an unattended SSO token refresh, splitting the terminal "grant is spent"
/// case (→ re-auth) from transient failures (which stay `Err` on the enclosing `Result`).
enum RefreshOutcome {
    Refreshed(CachedSsoToken),
    Reauth,
}

/// Result of [`SsoProvider::start_auth`]: the device-code details needed to either show
/// the user where to sign in or to pass directly to the daemon's notification mechanism.
///
/// Contains `client_secret` and `device_code` — sensitive OIDC material. Debug redacts both.
pub struct AuthStart {
    pub client_id: String,
    pub client_secret: String,
    pub device_code: String,
    /// The complete verification URI (with embedded user code when available).
    pub verification_uri: String,
    /// The short user code to enter at the verification page.
    pub user_code: String,
    /// Recommended polling interval in seconds.
    pub interval: u64,
}

impl fmt::Debug for AuthStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthStart")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("device_code", &"<redacted>")
            .field("verification_uri", &self.verification_uri)
            .field("user_code", &self.user_code)
            .field("interval", &self.interval)
            .finish()
    }
}

pub struct SsoProvider {
    pub credential_name: String,
    pub config: SsoConfig,
    encryption: std::sync::Arc<EncryptionService>,
    data_dir: std::path::PathBuf,
}

impl SsoProvider {
    pub fn new(
        credential_name: String,
        config: SsoConfig,
        encryption: std::sync::Arc<EncryptionService>,
        data_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            credential_name,
            config,
            encryption,
            data_dir,
        }
    }

    fn create_oidc_client(&self) -> OidcClient {
        let config = aws_sdk_ssooidc::Config::builder()
            .region(aws_sdk_ssooidc::config::Region::new(
                self.config.sso_region.clone(),
            ))
            .behavior_version(aws_sdk_ssooidc::config::BehaviorVersion::latest())
            .timeout_config(
                aws_sdk_ssooidc::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(10))
                    .read_timeout(Duration::from_secs(30))
                    .build(),
            )
            .build();
        OidcClient::from_conf(config)
    }

    fn create_sso_client(&self) -> SsoClient {
        let config = aws_sdk_sso::Config::builder()
            .region(aws_sdk_sso::config::Region::new(
                self.config.sso_region.clone(),
            ))
            .behavior_version(aws_sdk_sso::config::BehaviorVersion::latest())
            .timeout_config(
                aws_sdk_sso::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(10))
                    .read_timeout(Duration::from_secs(30))
                    .build(),
            )
            .build();
        SsoClient::from_conf(config)
    }

    async fn try_new_style_flow(
        &self,
        oidc: &OidcClient,
    ) -> Result<(
        String,
        String,
        aws_sdk_ssooidc::operation::start_device_authorization::StartDeviceAuthorizationOutput,
    )> {
        let reg = oidc
            .register_client()
            .client_name("credsd")
            .client_type("public")
            .scopes("sso:account:access")
            .grant_types("urn:ietf:params:oauth:grant-type:device_code")
            .grant_types("refresh_token")
            .issuer_url(&self.config.start_url)
            .send()
            .await
            .map_err(|e| {
                DaemonError::provider(
                    e.as_service_error()
                        .and_then(|se| se.message())
                        .unwrap_or("register_client failed"),
                )
            })?;

        let client_id = reg.client_id().unwrap_or_default().to_string();
        let client_secret = reg.client_secret().unwrap_or_default().to_string();

        let auth = oidc
            .start_device_authorization()
            .client_id(&client_id)
            .client_secret(&client_secret)
            .start_url(&self.config.start_url)
            .send()
            .await
            .map_err(|e| {
                DaemonError::provider(
                    e.as_service_error()
                        .and_then(|se| se.message())
                        .unwrap_or("start_device_authorization failed"),
                )
            })?;

        Ok((client_id, client_secret, auth))
    }

    async fn try_legacy_flow(
        &self,
        oidc: &OidcClient,
    ) -> Result<(
        String,
        String,
        aws_sdk_ssooidc::operation::start_device_authorization::StartDeviceAuthorizationOutput,
    )> {
        let reg = oidc
            .register_client()
            .client_name("credsd")
            .client_type("public")
            .send()
            .await
            .map_err(|e| {
                DaemonError::provider(
                    e.as_service_error()
                        .and_then(|se| se.message())
                        .unwrap_or("register_client failed"),
                )
            })?;

        let client_id = reg.client_id().unwrap_or_default().to_string();
        let client_secret = reg.client_secret().unwrap_or_default().to_string();

        let auth = oidc
            .start_device_authorization()
            .client_id(&client_id)
            .client_secret(&client_secret)
            .start_url(&self.config.start_url)
            .send()
            .await
            .map_err(|e| {
                DaemonError::provider(
                    e.as_service_error()
                        .and_then(|se| se.message())
                        .unwrap_or("start_device_authorization failed"),
                )
            })?;

        Ok((client_id, client_secret, auth))
    }

    /// Start the SSO device-authorization flow, returning the device code details without
    /// performing any UI (no `eprintln!`, no browser open). The caller is responsible for
    /// showing the URI/code and then calling [`complete_auth`](Self::complete_auth) to poll.
    ///
    /// Split from [`authenticate`](Self::authenticate) so the daemon-side bootstrap handler
    /// can send a `notifications/progress` instead of writing to stderr.
    pub async fn start_auth(&self) -> Result<AuthStart> {
        let oidc = self.create_oidc_client();
        info!("registering OIDC client");
        let (client_id, client_secret, auth) = match self.try_new_style_flow(&oidc).await {
            Ok(result) => result,
            Err(e) => {
                info!(error = %escape_log(&e), "new-style flow failed, trying legacy registration");
                self.try_legacy_flow(&oidc).await?
            }
        };
        info!(client_id = %escape_log(&client_id), "device authorization started");
        Ok(AuthStart {
            client_id,
            client_secret,
            device_code: auth.device_code().unwrap_or_default().to_string(),
            verification_uri: browser_uri(
                auth.verification_uri(),
                auth.verification_uri_complete(),
            ),
            user_code: auth.user_code().unwrap_or_default().to_string(),
            interval: poll_interval_secs(auth.interval()),
        })
    }

    /// Poll for the OIDC token and persist it. Call after the user has completed the
    /// device-authorization step (opened the URI and entered the code).
    pub async fn complete_auth(&self, start: AuthStart) -> Result<CachedSsoToken> {
        let oidc = self.create_oidc_client();
        let token = self
            .poll_for_token(
                &oidc,
                &start.client_id,
                &start.client_secret,
                &start.device_code,
                start.interval,
            )
            .await?;
        let cached = CachedSsoToken {
            access_token: token.0,
            expires_at: crate::credentials::expires_in_seconds(
                (token.1 as i64).min(crate::credentials::MAX_EXPIRES_IN_SECS),
            )
            .to_rfc3339(),
            refresh_token: token.2,
            client_id: start.client_id,
            client_secret: start.client_secret,
            start_url: self.config.start_url.clone(),
            region: self.config.sso_region.clone(),
        };
        self.persist_token(&cached)?;
        info!(credential = %self.credential_name, "SSO authentication successful");
        Ok(cached)
    }

    /// Full interactive authenticate: start the device flow, print the URI/code, open the
    /// browser, then poll until the user completes sign-in. Client-side only — the daemon uses
    /// [`start_auth`](Self::start_auth) + [`complete_auth`](Self::complete_auth) instead.
    pub async fn authenticate(&self) -> Result<CachedSsoToken> {
        let start = self.start_auth().await?;
        eprintln!("\nOpening browser for SSO authentication...");
        eprintln!(
            "If the browser doesn't open, visit: {}",
            crate::log::escape_log(&start.verification_uri)
        );
        eprintln!(
            "Enter this code when prompted: {}\n",
            crate::log::escape_log(&start.user_code)
        );
        if reqwest::Url::parse(&start.verification_uri).is_ok_and(|u| u.scheme() == "https") {
            let _ = open::that(&start.verification_uri);
        } else {
            eprintln!(
                "creds: verification URI is not HTTPS, open manually: {}",
                crate::log::escape_log(&start.verification_uri)
            );
        }
        self.complete_auth(start).await
    }

    async fn poll_for_token(
        &self,
        oidc: &OidcClient,
        client_id: &str,
        client_secret: &str,
        device_code: &str,
        interval: u64,
    ) -> Result<(String, i32, Option<String>)> {
        // `Instant + Duration` panics on overflow. Five minutes past now cannot overflow a
        // monotonic clock in practice, so the fallback is only there to say what happens if it
        // somehow could: poll once and give up, rather than crash mid-authentication.
        let now = tokio::time::Instant::now();
        let timeout = now.checked_add(Duration::from_secs(300)).unwrap_or(now);
        let poll_interval = Duration::from_secs(interval.max(1));

        loop {
            if tokio::time::Instant::now() >= timeout {
                return Err(DaemonError::provider(
                    "SSO authentication timed out after 5 minutes",
                ));
            }

            tokio::time::sleep(poll_interval).await;

            let result = oidc
                .create_token()
                .client_id(client_id)
                .client_secret(client_secret)
                .grant_type("urn:ietf:params:oauth:grant-type:device_code")
                .device_code(device_code)
                .send()
                .await;

            match result {
                Ok(resp) => {
                    let access_token = resp.access_token().unwrap_or_default().to_string();
                    let expires_in = resp.expires_in();
                    let refresh_token = resp.refresh_token().map(|s| s.to_string());
                    return Ok((access_token, expires_in, refresh_token));
                }
                Err(e) => match e.as_service_error() {
                    Some(
                        CreateTokenError::AuthorizationPendingException(_)
                        | CreateTokenError::SlowDownException(_),
                    ) => continue,
                    _ => {
                        let msg = e
                            .as_service_error()
                            .and_then(|se| se.message())
                            .unwrap_or("token creation failed");
                        return Err(DaemonError::provider(msg));
                    }
                },
            }
        }
    }

    pub async fn list_accounts(&self, access_token: &str) -> Result<Vec<(String, String, String)>> {
        let sso = self.create_sso_client();
        let mut accounts = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = sso.list_accounts().access_token(access_token);
            if let Some(ref token) = next_token {
                req = req.next_token(token);
            }
            let resp = req.send().await.map_err(|e| {
                DaemonError::provider(
                    e.as_service_error()
                        .and_then(|se| se.message())
                        .unwrap_or("list_accounts failed"),
                )
            })?;

            for acct in resp.account_list() {
                accounts.push((
                    acct.account_id().unwrap_or_default().to_string(),
                    acct.account_name().unwrap_or_default().to_string(),
                    acct.email_address().unwrap_or_default().to_string(),
                ));
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(accounts)
    }

    pub async fn list_roles(&self, access_token: &str, account_id: &str) -> Result<Vec<String>> {
        let sso = self.create_sso_client();
        let mut roles = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = sso
                .list_account_roles()
                .access_token(access_token)
                .account_id(account_id);
            if let Some(ref token) = next_token {
                req = req.next_token(token);
            }
            let resp = req.send().await.map_err(|e| {
                DaemonError::provider(
                    e.as_service_error()
                        .and_then(|se| se.message())
                        .unwrap_or("list_account_roles failed"),
                )
            })?;

            for role in resp.role_list() {
                roles.push(role.role_name().unwrap_or_default().to_string());
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(roles)
    }

    async fn get_role_credentials(&self, access_token: &str) -> Result<Credentials> {
        let sso = self.create_sso_client();
        let resp = sso
            .get_role_credentials()
            .access_token(access_token)
            .account_id(&self.config.account_id)
            .role_name(&self.config.role_name)
            .send()
            .await
            .map_err(|e| {
                DaemonError::provider(
                    e.as_service_error()
                        .and_then(|se| se.message())
                        .unwrap_or("get_role_credentials failed"),
                )
            })?;

        let creds = resp
            .role_credentials()
            .ok_or_else(|| DaemonError::provider("no role credentials in response"))?;

        let expires_at = DateTime::from_timestamp_millis(creds.expiration())
            .unwrap_or_else(|| crate::credentials::expires_in_seconds(3600));

        Ok(Credentials::session(
            creds.access_key_id().unwrap_or_default().to_string(),
            creds.secret_access_key().unwrap_or_default().to_string(),
            creds.session_token().unwrap_or_default().to_string(),
            expires_at,
        ))
    }

    async fn refresh_token(&self) -> Result<RefreshOutcome> {
        let mut cached = self.load_token()?;
        // No refresh token was ever issued — the only way forward is a fresh device flow.
        let Some(refresh_token) = cached.refresh_token.as_ref().cloned() else {
            return Ok(RefreshOutcome::Reauth);
        };

        let oidc = self.create_oidc_client();
        let resp = match oidc
            .create_token()
            .client_id(&cached.client_id)
            .client_secret(&cached.client_secret)
            .grant_type("refresh_token")
            .refresh_token(&refresh_token)
            .send()
            .await
        {
            Ok(resp) => resp,
            // A rejected/expired grant is terminal — the refresh token is spent, so signal
            // re-auth. Everything else (network, throttling, 5xx) is transient: surface it as
            // `Err` so the caller retries rather than nagging the user to log in.
            Err(e) => {
                return match e.as_service_error() {
                    Some(
                        CreateTokenError::InvalidGrantException(_)
                        | CreateTokenError::ExpiredTokenException(_),
                    ) => Ok(RefreshOutcome::Reauth),
                    _ => Err(DaemonError::provider(
                        e.as_service_error()
                            .and_then(|se| se.message())
                            .unwrap_or("token refresh failed"),
                    )),
                };
            }
        };

        cached.access_token.zeroize();
        if let Some(ref mut rt) = cached.refresh_token {
            rt.zeroize();
        }

        cached.access_token = resp.access_token().unwrap_or_default().to_string();
        cached.expires_at = crate::credentials::expires_in_seconds(
            (resp.expires_in() as i64).min(crate::credentials::MAX_EXPIRES_IN_SECS),
        )
        .to_rfc3339();
        cached.refresh_token = resp.refresh_token().map(|s| s.to_string());

        self.persist_token(&cached)?;
        info!(credential = %self.credential_name, "SSO token refreshed");
        Ok(RefreshOutcome::Refreshed(cached))
    }

    fn persist_token(&self, token: &CachedSsoToken) -> Result<()> {
        let path = self.data_dir.join("sso_token.enc");
        // Cleartext until seal_to_file encrypts it — scrub the transient on drop.
        let json = Zeroizing::new(serde_json::to_vec(token)?);
        self.encryption.seal_to_file(&path, &json)
    }

    fn load_token(&self) -> Result<CachedSsoToken> {
        let path = self.data_dir.join("sso_token.enc");
        let plaintext = self.encryption.open_from_file(&path).map_err(|e| {
            DaemonError::provider(format!(
                "no usable SSO token for credential '{}': {}. If the keystore key changed, \
                 run 'credsd login --env {}'.",
                self.credential_name, e, self.credential_name
            ))
        })?;
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

impl CredentialProvider for SsoProvider {
    // SSO renews unattended: a valid access token brokers role credentials directly, and a
    // near-expiry one refreshes via the stored refresh-token grant. The interactive device
    // flow (`authenticate`) is only ever driven by `bootstrap`, never by the store.
    fn renewer(&self) -> Option<&dyn Renewer> {
        Some(self)
    }

    fn mode_name(&self) -> &'static str {
        "aws-idc-sso"
    }
}

#[async_trait]
impl Renewer for SsoProvider {
    async fn renew(&self) -> Result<Renewed> {
        // No token on disk (never authed) or an unreadable one (keystore key rotated) is not
        // a transient failure — only an interactive login recovers it. Surface it as a
        // re-auth challenge, not `Err` (which the store would retry forever).
        let Ok(cached) = self.load_token() else {
            return Ok(Renewed::ReauthRequired(ReauthInput::Browser));
        };

        let expires_at = DateTime::parse_from_rfc3339(&cached.expires_at)
            .map_err(|e| DaemonError::provider(format!("invalid expires_at: {}", e)))?;
        let remaining = expires_at.signed_duration_since(Utc::now());

        let mut access_token = if remaining.num_seconds() <= 300 {
            info!(credential = %self.credential_name, "SSO token expiring, refreshing");
            // `?` lets a transient refresh failure propagate as `Err` (retryable); only a
            // terminal `Reauth` becomes a re-auth challenge.
            match self.refresh_token().await? {
                RefreshOutcome::Refreshed(refreshed) => refreshed.access_token.clone(),
                RefreshOutcome::Reauth => {
                    warn!(credential = %self.credential_name, "SSO refresh token spent, re-auth required");
                    return Ok(Renewed::ReauthRequired(ReauthInput::Browser));
                }
            }
        } else {
            cached.access_token.clone()
        };

        let result = self.get_role_credentials(&access_token).await;

        // `cached` is ZeroizeOnDrop and scrubs its own secrets when it drops here;
        // `access_token` is a bare String extracted above, so scrub it explicitly.
        access_token.zeroize();

        result.map(Renewed::Ready)
    }
}

/// Clamp an IdP-supplied poll interval to a safe `u64` seconds value.
///
/// `as u64` sign-extension turns `-1i32` into a ~584-year sleep; non-positive values
/// fall back to RFC 8628's 5 s default instead. Positive values are capped at 60 s so
/// a misbehaving IdP cannot stall the flow indefinitely.
fn poll_interval_secs(advertised: i32) -> u64 {
    match advertised {
        i @ 1.. => u64::from(i.min(60).unsigned_abs()),
        _ => 5,
    }
}

/// Pick the URI handed to the browser launcher.
///
/// The launcher receives the URI in argv, which any local user can read from `/proc`. The
/// complete URI embeds the user code, so prefer the bare one and let the user type the code
/// shown in the terminal.
///
/// AWS IAM Identity Center always returns both, so for `aws-idc-sso` the fallback never fires. It
/// exists so a missing bare URI degrades to a working login rather than none. A provider derived
/// from this one for an IdP that may return only the complete URI reopens the leak through this
/// fallback; it must not open the complete URI and should print it for the user to copy instead.
fn browser_uri(bare: Option<&str>, complete: Option<&str>) -> String {
    bare.filter(|u| !u.is_empty())
        .or(complete)
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_key;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn poll_interval_clamps_correctly() {
        assert_eq!(poll_interval_secs(-1), 5);
        assert_eq!(poll_interval_secs(0), 5);
        assert_eq!(poll_interval_secs(3600), 60);
        assert_eq!(poll_interval_secs(5), 5);
    }

    #[test]
    fn browser_uri_omits_the_user_code() {
        let bare = "https://device.sso.us-east-1.amazonaws.com/";
        let complete = "https://device.sso.us-east-1.amazonaws.com/?user_code=ABCD-EFGH";
        assert_eq!(browser_uri(Some(bare), Some(complete)), bare);
        assert_eq!(browser_uri(Some(""), Some(complete)), complete);
        assert_eq!(browser_uri(None, Some(complete)), complete);
        assert_eq!(browser_uri(None, None), "");
    }

    /// With no token on disk, an unattended renew cannot proceed and must not report a
    /// transient `Err` (which the store would retry forever) — it yields a re-auth challenge
    /// so the caller can steer the user into the interactive device flow.
    #[tokio::test]
    async fn renew_without_a_token_asks_for_reauth() {
        let dir = tempdir().unwrap();
        let encryption = Arc::new(EncryptionService::new(generate_key().unwrap()).unwrap());
        let provider = SsoProvider::new(
            "work".into(),
            SsoConfig {
                start_url: "https://example.awsapps.com/start".into(),
                sso_region: "us-east-1".into(),
                account_id: "111111111111".into(),
                role_name: "Developer".into(),
                identity_type: Default::default(),
            },
            encryption,
            dir.path().to_path_buf(),
        );
        match provider.renew().await {
            Ok(Renewed::ReauthRequired(_)) => {}
            other => panic!("expected ReauthRequired, got {:?}", other),
        }
    }

    #[test]
    fn zeroize_scrubs_secrets_preserves_metadata() {
        let mut token = CachedSsoToken {
            access_token: "at-secret".into(),
            expires_at: "2026-07-17T00:00:00Z".into(),
            refresh_token: Some("rt-secret".into()),
            client_id: "client-123".into(),
            client_secret: "cs-secret".into(),
            start_url: "https://example.awsapps.com/start".into(),
            region: "us-east-1".into(),
        };
        token.zeroize();

        assert!(token.access_token.is_empty());
        assert!(token.client_secret.is_empty());
        // Zeroize on Option<String> scrubs the inner secret and resets to None.
        assert_eq!(token.refresh_token, None);

        // Non-secret metadata is skipped so callers can still inspect it.
        assert_eq!(token.expires_at, "2026-07-17T00:00:00Z");
        assert_eq!(token.client_id, "client-123");
        assert_eq!(token.start_url, "https://example.awsapps.com/start");
        assert_eq!(token.region, "us-east-1");
    }
}
