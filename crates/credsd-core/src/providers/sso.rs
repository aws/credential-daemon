//! AWS SSO (IAM Identity Center) credential provider.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_sso::error::ProvideErrorMetadata;
use aws_sdk_sso::Client as SsoClient;
use aws_sdk_ssooidc::operation::create_token::CreateTokenError;
use aws_sdk_ssooidc::Client as OidcClient;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::log::escape_log;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::SsoConfig;
use crate::credentials::{CredentialData, Credentials};
use crate::encryption::EncryptionService;
use crate::error::{DaemonError, Result};
use crate::providers::aws_login::{caller_arn, parse_caller_arn, Identity};
use crate::providers::{sdk_failure, CredentialProvider, ReauthInput, Renewed, Renewer};

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

/// How [`SsoProvider::logout`] left a sign-in unable to act at SSO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutEnded {
    /// SSO accepted `Logout`.
    Accepted,
    /// SSO refused the refresh token, or the access token `Logout` carried, as invalid or
    /// expired, so nothing sealed can act there.
    TokenRejected,
}

/// Why [`SsoProvider::logout`] could not end a sign-in at SSO.
#[derive(Debug)]
pub struct LogoutFailed {
    pub error: DaemonError,
    /// When the sign-in expires at SSO; `None` when the sealed token could not be read.
    pub expires_at: Option<String>,
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
    /// Endpoint override for the Identity Center portal, OIDC, and STS, for tests only. `None`
    /// lets each SDK resolve its region's endpoint.
    endpoint: Option<String>,
}

/// The identity an `sts:GetCallerIdentity` ARN names, for credentials brokered from an Identity
/// Center sign-in. Identity Center issues them under a reserved role, so the ARN is
/// `assumed-role/AWSReservedSSO_<permission-set>_<hash>/<user>` and the session segment is the
/// Identity Center user name. An ARN with no session segment names no user, so it does not
/// resolve rather than resolving to an empty one.
fn sso_caller_identity(arn: &str) -> Result<Identity> {
    let identity = parse_caller_arn(arn)?;
    if identity.session.is_empty() {
        return Err(DaemonError::provider(
            "the brokered credentials are not an Identity Center role session",
        ));
    }
    Ok(identity)
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
            endpoint: None,
        }
    }

    /// Point the portal, OIDC, and STS at `url` instead of the regional endpoints, so a test can
    /// mock them.
    #[cfg(any(test, feature = "test-seam"))]
    #[doc(hidden)]
    pub fn with_endpoint(mut self, url: String) -> Self {
        self.endpoint = Some(url);
        self
    }

    fn create_oidc_client(&self) -> OidcClient {
        let mut config = aws_sdk_ssooidc::Config::builder()
            .region(aws_sdk_ssooidc::config::Region::new(
                self.config.sso_region.clone(),
            ))
            .behavior_version(aws_sdk_ssooidc::config::BehaviorVersion::latest())
            .timeout_config(
                aws_sdk_ssooidc::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(10))
                    .read_timeout(Duration::from_secs(30))
                    .build(),
            );
        config.set_endpoint_url(self.endpoint.clone());
        OidcClient::from_conf(config.build())
    }

    fn create_sso_client(&self) -> SsoClient {
        let mut config = aws_sdk_sso::Config::builder()
            .region(aws_sdk_sso::config::Region::new(
                self.config.sso_region.clone(),
            ))
            .behavior_version(aws_sdk_sso::config::BehaviorVersion::latest())
            .timeout_config(
                aws_sdk_sso::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(10))
                    .read_timeout(Duration::from_secs(30))
                    .build(),
            );
        config.set_endpoint_url(self.endpoint.clone());
        SsoClient::from_conf(config.build())
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

    async fn get_role_credentials(
        &self,
        access_token: &str,
        account_id: &str,
        role_name: &str,
    ) -> Result<Credentials> {
        let sso = self.create_sso_client();
        let resp = sso
            .get_role_credentials()
            .access_token(access_token)
            .account_id(account_id)
            .role_name(role_name)
            .send()
            .await
            .map_err(|e| sdk_failure("get_role_credentials", e))?;

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

    /// Who the sign-in behind `access_token` acts as, for the audit record only: role credentials
    /// are brokered for `account_id`/`role_name` and `sts:GetCallerIdentity` is asked whose
    /// session they are. The sign-in asks for `sso:account:access` alone, so no identity token
    /// comes back with the access token and this is the only way to name the user.
    ///
    /// Every failure is the caller's to absorb (`credential-retrieval-api` Req 17, "Who signed
    /// in"): the identity is not stored and not compared, so a pair this user cannot assume must
    /// not fail a sign-in that is otherwise complete.
    pub async fn signed_in_user(
        &self,
        access_token: &str,
        account_id: &str,
        role_name: &str,
    ) -> Result<Identity> {
        let brokered = self
            .get_role_credentials(access_token, account_id, role_name)
            .await?;
        let CredentialData::SessionCredentials {
            access_key,
            secret_key,
            session_token,
        } = &brokered.data
        else {
            return Err(DaemonError::provider(
                "Identity Center returned no session credentials to identify",
            ));
        };
        let creds = aws_sdk_sts::config::Credentials::new(
            access_key.clone(),
            secret_key.clone(),
            Some(session_token.clone()),
            brokered.expires_at.map(Into::into),
            "credsd-idc-sso",
        );
        let arn = caller_arn(creds, &self.config.sso_region, self.endpoint.as_deref()).await?;
        sso_caller_identity(&arn)
    }

    async fn refresh_token(&self) -> Result<RefreshOutcome> {
        let outcome = self.refreshed(&self.load_token()?, false).await?;
        if let RefreshOutcome::Refreshed(ref token) = outcome {
            self.persist_token(token)?;
            info!(credential = %self.credential_name, "SSO token refreshed");
        }
        Ok(outcome)
    }

    /// `cached` with its access token refreshed, not persisted. `once` sends a single attempt
    /// with no timeouts of its own, for a caller that bounds the call itself.
    async fn refreshed(&self, cached: &CachedSsoToken, once: bool) -> Result<RefreshOutcome> {
        // No refresh token was ever issued — the only way forward is a fresh device flow.
        let Some(refresh_token) = cached.refresh_token.as_deref() else {
            return Ok(RefreshOutcome::Reauth);
        };

        let request = self
            .create_oidc_client()
            .create_token()
            .client_id(&cached.client_id)
            .client_secret(&cached.client_secret)
            .grant_type("refresh_token")
            .refresh_token(refresh_token);
        let sent = if once {
            request
                .customize()
                .config_override(
                    aws_sdk_ssooidc::Config::builder()
                        .retry_config(aws_sdk_ssooidc::config::retry::RetryConfig::disabled())
                        .timeout_config(
                            aws_sdk_ssooidc::config::timeout::TimeoutConfig::disabled(),
                        ),
                )
                .send()
                .await
        } else {
            request.send().await
        };
        let resp = match sent {
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

        let mut next = cached.clone();
        next.access_token.zeroize();
        next.refresh_token.zeroize();
        next.access_token = resp.access_token().unwrap_or_default().to_string();
        next.expires_at = crate::credentials::expires_in_seconds(
            (resp.expires_in() as i64).min(crate::credentials::MAX_EXPIRES_IN_SECS),
        )
        .to_rfc3339();
        next.refresh_token = resp.refresh_token().map(|s| s.to_string());
        Ok(RefreshOutcome::Refreshed(next))
    }

    /// End the sign-in server-side with SSO `Logout`, so the access token stops working
    /// everywhere, not only here (credential-retrieval-api Requirement 15 AC 18). An expired
    /// access token is refreshed first when a refresh token is sealed with it, since the refresh
    /// token can keep the portal session live; the refreshed token is used only for this call.
    /// The refresh and `Logout` share `limit`, each sent once with no client timeouts.
    ///
    /// `Ok(Some(_))`: SSO ended it, or refused the refresh or the token as invalid or expired.
    /// `Ok(None)`: no sealed token, so nothing to end and nothing sent. An unreadable token (corrupt, or sealed under a key since rotated), any other
    /// refusal, or no answer within `limit` is an error: the sign-in may still be live at SSO.
    pub async fn logout(
        &self,
        limit: Duration,
    ) -> std::result::Result<Option<LogoutEnded>, LogoutFailed> {
        if let Ok(false) = self.data_dir.join("sso_token.enc").try_exists() {
            return Ok(None);
        }
        let cached = self.load_token().map_err(|error| LogoutFailed {
            error,
            expires_at: None,
        })?;
        // The expiry of the token `Logout` carries, reported if SSO does not end it.
        let mut expires_at = cached.expires_at.clone();
        let attempt = async {
            let live =
                DateTime::parse_from_rfc3339(&cached.expires_at).is_ok_and(|at| at > Utc::now());
            let refreshed;
            let token = if live || cached.refresh_token.is_none() {
                &cached
            } else {
                match self.refreshed(&cached, true).await? {
                    RefreshOutcome::Refreshed(next) => refreshed = next,
                    // The refresh token is spent, so nothing sealed can act at SSO.
                    RefreshOutcome::Reauth => return Ok(LogoutEnded::TokenRejected),
                }
                expires_at.clone_from(&refreshed.expires_at);
                &refreshed
            };
            match self
                .create_sso_client()
                .logout()
                .access_token(&token.access_token)
                .customize()
                .config_override(
                    aws_sdk_sso::Config::builder()
                        .retry_config(aws_sdk_sso::config::retry::RetryConfig::disabled())
                        .timeout_config(aws_sdk_sso::config::timeout::TimeoutConfig::disabled()),
                )
                .send()
                .await
            {
                Ok(_) => Ok(LogoutEnded::Accepted),
                // The token is invalid or expired: a retry after SSO already ended the sign-in
                // draws this, and either way the token can no longer act at SSO.
                Err(e)
                    if e.as_service_error()
                        .is_some_and(|se| se.is_unauthorized_exception()) =>
                {
                    Ok(LogoutEnded::TokenRejected)
                }
                Err(e) => Err(DaemonError::provider(
                    e.as_service_error()
                        .and_then(|se| se.message())
                        .unwrap_or("no reason given"),
                )),
            }
        };
        let outcome = tokio::time::timeout(limit, attempt).await;
        let error = match outcome {
            Ok(Ok(ended)) => return Ok(Some(ended)),
            Ok(Err(error)) => error,
            Err(_) => DaemonError::provider(format!("no answer within {limit:?}")),
        };
        Err(LogoutFailed {
            error,
            expires_at: Some(expires_at),
        })
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
                 run 'creds login --credential {}'.",
                self.credential_name,
                e.detail(),
                self.credential_name
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

    // One sign-in brokers every account and role the user holds, so a selected pair shares the
    // token and its refresh, and differs only in what it asks `GetRoleCredentials` for.
    fn role_renewer<'a>(
        &'a self,
        account_id: &'a str,
        role_name: &'a str,
    ) -> Option<Box<dyn Renewer + 'a>> {
        Some(Box::new(RoleRenewer {
            provider: self,
            account_id,
            role_name,
        }))
    }

    fn mode_name(&self) -> &'static str {
        "aws-idc-sso"
    }
}

struct RoleRenewer<'a> {
    provider: &'a SsoProvider,
    account_id: &'a str,
    role_name: &'a str,
}

#[async_trait]
impl Renewer for RoleRenewer<'_> {
    async fn renew(&self) -> Result<Renewed> {
        self.provider
            .renew_role(self.account_id, self.role_name)
            .await
    }
}

#[async_trait]
impl Renewer for SsoProvider {
    async fn renew(&self) -> Result<Renewed> {
        self.renew_role(&self.config.account_id, &self.config.role_name)
            .await
    }
}

impl SsoProvider {
    async fn renew_role(&self, account_id: &str, role_name: &str) -> Result<Renewed> {
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

        let result = self
            .get_role_credentials(&access_token, account_id, role_name)
            .await;

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

    /// The ARN `sts:GetCallerIdentity` returns for credentials brokered from an Identity Center
    /// sign-in, and the user it names. The reserved role carries the permission set and a hash,
    /// so only the session segment identifies the person.
    #[test]
    fn an_identity_center_session_arn_names_its_user() {
        let identity = sso_caller_identity(
            "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_AdminAccess_0a1b2c3d4e5f6a7b/test-user",
        )
        .expect("an Identity Center session ARN resolves");
        assert_eq!(identity.session, "test-user");
        assert_eq!(identity.account, "111122223333");
        assert_eq!(identity.kind, "role");
        assert_eq!(identity.name, "AWSReservedSSO_AdminAccess_0a1b2c3d4e5f6a7b");
    }

    /// An ARN with no session segment names no user, so it must not resolve to an empty one: the
    /// audit record would then claim an identity it does not have.
    #[test]
    fn an_arn_without_a_session_resolves_to_no_user() {
        for arn in [
            "arn:aws:iam::111122223333:user/test-user",
            "arn:aws:iam::111122223333:root",
            "not-an-arn",
        ] {
            assert!(sso_caller_identity(arn).is_err(), "{arn}");
        }
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
                allowed_roles: Vec::new(),
            },
            encryption,
            dir.path().to_path_buf(),
        );
        match provider.renew().await {
            Ok(Renewed::ReauthRequired(_)) => {}
            other => panic!("expected ReauthRequired, got {:?}", other),
        }
    }

    /// Any account and role renews from the credential's one sign-in: with no token on disk a
    /// selected pair asks for the same re-auth the stored pair does, rather than starting a
    /// sign-in of its own (credential-retrieval-api Requirement 17 AC 5).
    #[tokio::test]
    async fn a_selected_role_renews_from_the_one_sign_in() {
        let dir = tempdir().unwrap();
        let encryption = Arc::new(EncryptionService::new(generate_key().unwrap()).unwrap());
        let provider = SsoProvider::new(
            "sso.acme".into(),
            SsoConfig {
                start_url: "https://example.awsapps.com/start".into(),
                sso_region: "us-east-1".into(),
                account_id: "111111111111".into(),
                role_name: "Admin".into(),
                identity_type: Default::default(),
                allowed_roles: Vec::new(),
            },
            encryption,
            dir.path().to_path_buf(),
        );
        let renewer = provider
            .role_renewer("222222222222", "ReadOnly")
            .expect("an aws-idc-sso credential selects roles");
        match renewer.renew().await {
            Ok(Renewed::ReauthRequired(ReauthInput::Browser)) => {}
            other => panic!("expected ReauthRequired, got {:?}", other),
        }
    }

    /// A provider whose portal and STS calls both go to `endpoint`, so the audit lookup can be
    /// driven over the wire. One server serves both: the portal's brokering is a `GET` and
    /// `GetCallerIdentity` a `POST`.
    fn stubbed(dir: &std::path::Path, endpoint: String) -> SsoProvider {
        let mut provider = SsoProvider::new(
            "work".into(),
            SsoConfig {
                start_url: "https://example.awsapps.com/start".into(),
                sso_region: "us-east-1".into(),
                account_id: "111122223333".into(),
                role_name: "AdminAccess".into(),
                identity_type: Default::default(),
                allowed_roles: Vec::new(),
            },
            Arc::new(EncryptionService::new(generate_key().unwrap()).unwrap()),
            dir.to_path_buf(),
        );
        provider.endpoint = Some(endpoint);
        provider
    }

    const BROKERED_CREDENTIALS: &str = r#"{"roleCredentials":{"accessKeyId":"AKIAIOSFODNN7EXAMPLE","secretAccessKey":"brokered","sessionToken":"session","expiration":4102444800000}}"#;

    /// The audit lookup end to end: the portal brokers role credentials for the pair, STS is asked
    /// whose session they are, and the Identity Center user comes out of the reserved-role ARN.
    #[tokio::test]
    async fn the_signed_in_user_comes_from_sts_with_the_brokered_credentials() {
        let mut server = mockito::Server::new_async().await;
        let portal = server
            .mock("GET", mockito::Matcher::Any)
            .with_header("content-type", "application/json")
            .with_body(BROKERED_CREDENTIALS)
            .create_async()
            .await;
        let sts = server
            .mock("POST", "/")
            .with_header("content-type", "text/xml")
            .with_body(
                r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_AdminAccess_0a1b2c3d4e5f6a7b/test-user</Arn><UserId>AROAEXAMPLE:test-user</UserId><Account>111122223333</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>"#,
            )
            .create_async()
            .await;
        let dir = tempdir().unwrap();
        let identity = stubbed(dir.path(), server.url())
            .signed_in_user("access-token", "111122223333", "AdminAccess")
            .await
            .expect("the signed-in user resolves");
        portal.assert_async().await;
        sts.assert_async().await;
        assert_eq!(identity.session, "test-user");
        assert_eq!(identity.account, "111122223333");
    }

    /// And its failure path: an STS that refuses leaves the lookup unresolved, carrying the
    /// service's own reason, which is what the `sso.signed_in` record names in place of a user
    /// (Req 17, "Who signed in"). The sign-in itself is unaffected — nothing here is persisted.
    #[tokio::test]
    async fn a_refused_lookup_carries_the_reason_it_was_refused_with() {
        let mut server = mockito::Server::new_async().await;
        let _portal = server
            .mock("GET", mockito::Matcher::Any)
            .with_header("content-type", "application/json")
            .with_body(BROKERED_CREDENTIALS)
            .create_async()
            .await;
        let _sts = server
            .mock("POST", "/")
            .with_status(403)
            .with_header("content-type", "text/xml")
            .with_body(
                r#"<ErrorResponse><Error><Code>AccessDenied</Code><Message>no assignment for that role</Message></Error></ErrorResponse>"#,
            )
            .create_async()
            .await;
        let dir = tempdir().unwrap();
        let err = stubbed(dir.path(), server.url())
            .signed_in_user("access-token", "111122223333", "AdminAccess")
            .await
            .expect_err("a refused lookup does not resolve");
        assert!(
            err.to_string().contains("no assignment for that role"),
            "the reason reaches the record: {err}"
        );
        assert!(
            std::fs::read_dir(dir.path())
                .expect("list the data dir")
                .next()
                .is_none(),
            "and the lookup persists nothing either way"
        );
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

    /// A provider whose SSO portal is `endpoint`, with `access_token` sealed as its sign-in.
    fn signed_in_at(
        dir: &std::path::Path,
        endpoint: String,
        access_token: Option<&str>,
    ) -> SsoProvider {
        let encryption = Arc::new(EncryptionService::new(generate_key().unwrap()).unwrap());
        let provider = SsoProvider::new(
            "work".into(),
            SsoConfig {
                start_url: "https://example.awsapps.com/start".into(),
                sso_region: "us-east-1".into(),
                account_id: "111111111111".into(),
                role_name: "Developer".into(),
                identity_type: Default::default(),
                allowed_roles: Vec::new(),
            },
            encryption,
            dir.to_path_buf(),
        )
        .with_endpoint(endpoint);
        if let Some(access_token) = access_token {
            provider
                .persist_token(&CachedSsoToken {
                    access_token: access_token.into(),
                    expires_at: "2999-01-01T00:00:00Z".into(),
                    refresh_token: Some("rt".into()),
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    start_url: "https://example.awsapps.com/start".into(),
                    region: "us-east-1".into(),
                })
                .unwrap();
        }
        provider
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(16))]

        /// A logout ends the sign-in at SSO: exactly one `Logout` call, bearing the sealed
        /// access token and no other, for any token shape SSO issues.
        #[test]
        fn logout_ends_the_sealed_sign_in_at_sso(token in "[A-Za-z0-9+/=._-]{1,256}") {
            let dir = tempdir().unwrap();
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async {
                let mut server = mockito::Server::new_async().await;
                let logout = server
                    .mock("POST", "/logout")
                    .match_header("x-amz-sso_bearer_token", token.as_str())
                    .with_status(200)
                    .expect(1)
                    .create_async()
                    .await;
                let provider = signed_in_at(dir.path(), server.url(), Some(&token));
                assert_eq!(provider.logout(LIMIT).await.unwrap(), Some(LogoutEnded::Accepted));
                logout.assert_async().await;
            });
        }

        /// A refusal of the token as invalid or expired (`UnauthorizedException`) is what a
        /// retry draws after SSO already ended the sign-in, and it is `TokenRejected` (AC 18).
        /// Every other refusal, including one with no error code, stays an error.
        #[test]
        fn logout_refused_as_unauthorized_is_token_rejected_and_any_other_refusal_fails(
            token in "[A-Za-z0-9+/=._-]{1,256}",
            (code, status) in proptest::sample::select(vec![
                (Some("UnauthorizedException"), 401usize),
                (Some("InvalidRequestException"), 400),
                (Some("TooManyRequestsException"), 429),
                (Some("ResourceNotFoundException"), 404),
                (None, 401),
                (None, 403),
            ]),
        ) {
            let dir = tempdir().unwrap();
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async {
                let mut server = mockito::Server::new_async().await;
                let mut mock = server
                    .mock("POST", "/logout")
                    .with_status(status)
                    .with_body(r#"{"message":"Session token not found or invalid"}"#);
                if let Some(code) = code {
                    mock = mock.with_header("x-amzn-errortype", code);
                }
                let logout = mock.expect(1).create_async().await;
                let provider = signed_in_at(dir.path(), server.url(), Some(&token));
                match provider.logout(LIMIT).await {
                    Ok(ended) => assert!(
                        ended == Some(LogoutEnded::TokenRejected)
                            && code == Some("UnauthorizedException"),
                        "{code:?} {status} ended: {ended:?}"
                    ),
                    Err(failed) => {
                        assert_ne!(code, Some("UnauthorizedException"), "{}", failed.error);
                        assert_eq!(failed.expires_at.as_deref(), Some("2999-01-01T00:00:00Z"));
                    }
                }
                logout.assert_async().await;
            });
        }
    }

    /// A provider whose sealed access token `old-at` expired an hour ago, with `refresh_token`
    /// sealed beside it.
    fn expired_sign_in_at(
        dir: &std::path::Path,
        endpoint: String,
        refresh_token: Option<&str>,
    ) -> SsoProvider {
        let provider = signed_in_at(dir, endpoint, None);
        provider
            .persist_token(&CachedSsoToken {
                access_token: "old-at".into(),
                expires_at: crate::credentials::expires_in_seconds(-3600).to_rfc3339(),
                refresh_token: refresh_token.map(Into::into),
                client_id: "client".into(),
                client_secret: "secret".into(),
                start_url: "https://example.awsapps.com/start".into(),
                region: "us-east-1".into(),
            })
            .unwrap();
        provider
    }

    /// Answer `mock` with `status`, carrying `code` as the AWS error type when there is one.
    fn answering(mock: mockito::Mock, status: usize, code: Option<&str>) -> mockito::Mock {
        let mock = mock
            .with_status(status)
            .with_body(r#"{"message":"refused"}"#);
        match code {
            Some(code) => mock.with_header("x-amzn-errortype", code),
            None => mock,
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

        /// AC 18: an expired sealed access token with a refresh token is refreshed first, and
        /// `Logout` carries the refreshed token. A refresh refused as invalid or expired ends the
        /// sign-in with no `Logout`; any other refresh refusal fails it with no `Logout`. After a
        /// refresh, `Logout` accepted or refused as unauthorized ends it and any other refusal
        /// fails it. The refreshed token is never written back.
        #[test]
        fn an_expired_token_is_refreshed_before_logout(
            new_token in "[A-Za-z0-9._-]{1,64}",
            refresh_token in "[A-Za-z0-9._-]{1,64}",
            (refresh_status, refresh_code) in proptest::sample::select(vec![
                (200usize, None),
                (400, Some("InvalidGrantException")),
                (400, Some("ExpiredTokenException")),
                (401, Some("InvalidClientException")),
                (400, Some("AccessDeniedException")),
                (500, Some("InternalServerException")),
                (500, None),
            ]),
            (logout_status, logout_code) in proptest::sample::select(vec![
                (200usize, None),
                (401, Some("UnauthorizedException")),
                (400, Some("InvalidRequestException")),
                (500, None),
            ]),
        ) {
            let dir = tempdir().unwrap();
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async {
                let mut server = mockito::Server::new_async().await;
                let refreshed = refresh_status == 200;
                let token_mock = server
                    .mock("POST", "/token")
                    .match_body(mockito::Matcher::Regex(regex_escape(&refresh_token)));
                let token_mock = if refreshed {
                    token_mock.with_status(200).with_body(format!(
                        r#"{{"accessToken":"{new_token}","expiresIn":3600,"refreshToken":"rt-new","tokenType":"Bearer"}}"#
                    ))
                } else {
                    answering(token_mock, refresh_status, refresh_code)
                };
                let token = token_mock.expect(1).create_async().await;
                let logout = answering(
                    server
                        .mock("POST", "/logout")
                        .match_header("x-amz-sso_bearer_token", new_token.as_str()),
                    logout_status,
                    logout_code,
                )
                .expect(usize::from(refreshed))
                .create_async()
                .await;
                let provider =
                    expired_sign_in_at(dir.path(), server.url(), Some(&refresh_token));
                let sealed = provider.load_token().unwrap().expires_at.clone();

                // `None`: the logout fails.
                let expected = match (refreshed, logout_status, logout_code, refresh_code) {
                    (true, 200, ..) => Some(LogoutEnded::Accepted),
                    (true, _, Some("UnauthorizedException"), _)
                    | (false, .., Some("InvalidGrantException" | "ExpiredTokenException")) => {
                        Some(LogoutEnded::TokenRejected)
                    }
                    _ => None,
                };
                match provider.logout(LIMIT).await {
                    Ok(ended) => assert!(
                        ended.is_some() && ended == expected,
                        "ended {ended:?}, expected {expected:?}"
                    ),
                    Err(failed) => {
                        assert_eq!(expected, None, "failed: {}", failed.error);
                        let expires_at = failed.expires_at.expect("the token was readable");
                        if refreshed {
                            assert_ne!(expires_at, sealed, "the expiry of the token Logout carried");
                        } else {
                            assert_eq!(expires_at, sealed);
                        }
                    }
                }
                token.assert_async().await;
                logout.assert_async().await;
                let kept = provider.load_token().unwrap();
                assert_eq!(kept.access_token, "old-at", "the refresh is never written back");
                assert_eq!(kept.refresh_token.as_deref(), Some(refresh_token.as_str()));
            });
        }
    }

    fn regex_escape(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_string()
                } else {
                    format!("\\{c}")
                }
            })
            .collect()
    }

    /// An expired token with no refresh token is sent as it is: SSO refuses it as unauthorized,
    /// and nothing sealed can act any longer, so the sign-in is ended (AC 18).
    #[tokio::test]
    async fn an_expired_token_with_no_refresh_token_is_sent_as_sealed() {
        let dir = tempdir().unwrap();
        let mut server = mockito::Server::new_async().await;
        let token = server.mock("POST", "/token").expect(0).create_async().await;
        let logout = answering(
            server
                .mock("POST", "/logout")
                .match_header("x-amz-sso_bearer_token", "old-at"),
            401,
            Some("UnauthorizedException"),
        )
        .expect(1)
        .create_async()
        .await;
        let provider = expired_sign_in_at(dir.path(), server.url(), None);
        assert_eq!(
            provider.logout(LIMIT).await.unwrap(),
            Some(LogoutEnded::TokenRejected)
        );
        token.assert_async().await;
        logout.assert_async().await;
    }

    /// An unexpired token goes straight to `Logout`, with no refresh.
    #[tokio::test]
    async fn an_unexpired_token_is_not_refreshed() {
        let dir = tempdir().unwrap();
        let mut server = mockito::Server::new_async().await;
        let token = server.mock("POST", "/token").expect(0).create_async().await;
        let logout = server
            .mock("POST", "/logout")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        let provider = signed_in_at(dir.path(), server.url(), Some("live"));
        assert_eq!(
            provider.logout(LIMIT).await.unwrap(),
            Some(LogoutEnded::Accepted)
        );
        token.assert_async().await;
        logout.assert_async().await;
    }

    /// The refresh and `Logout` share one bound: each answering inside it alone is not enough
    /// when together they do not (AC 18).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_refresh_and_logout_share_one_bound() {
        let dir = tempdir().unwrap();
        let mut server = mockito::Server::new_async().await;
        let slow = std::time::Duration::from_millis(300);
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_body_from_request(move |_| {
                std::thread::sleep(slow);
                br#"{"accessToken":"new","expiresIn":3600,"tokenType":"Bearer"}"#.to_vec()
            })
            .create_async()
            .await;
        server
            .mock("POST", "/logout")
            .with_status(200)
            .with_body_from_request(move |_| {
                std::thread::sleep(slow);
                b"{}".to_vec()
            })
            .create_async()
            .await;
        let provider = expired_sign_in_at(dir.path(), server.url(), Some("rt"));
        let limit = std::time::Duration::from_millis(450);
        let failed = provider.logout(limit).await.unwrap_err();
        assert!(
            failed.error.to_string().contains("no answer within"),
            "{}",
            failed.error
        );
    }

    /// The logout's bound is its own: the SSO client's 30-second read timeout does not cut a
    /// `Logout` short when the logout allows longer (AC 18).
    #[tokio::test(start_paused = true)]
    async fn the_logout_bound_is_not_the_shared_client_timeout() {
        let dir = tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let provider = signed_in_at(dir.path(), format!("http://127.0.0.1:{port}"), Some("t"));
        let limit = std::time::Duration::from_secs(120);
        let failed = provider.logout(limit).await.unwrap_err();
        assert!(
            failed.error.to_string().contains("no answer within 120s"),
            "{}",
            failed.error
        );
    }

    const LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

    /// With no sealed sign-in there is nothing to end, so a logout calls nothing and says so.
    #[tokio::test]
    async fn logout_without_a_sign_in_calls_nothing() {
        let dir = tempdir().unwrap();
        let mut server = mockito::Server::new_async().await;
        let logout = server
            .mock("POST", "/logout")
            .expect(0)
            .create_async()
            .await;
        let provider = signed_in_at(dir.path(), server.url(), None);
        assert_eq!(
            provider.logout(LIMIT).await.unwrap(),
            None,
            "nothing was ended"
        );
        logout.assert_async().await;
    }

    /// A `Logout` SSO refuses is an error carrying the session's expiry, so the caller can say
    /// until when the server-side session may still be live.
    #[tokio::test]
    async fn a_refused_logout_is_an_error() {
        let dir = tempdir().unwrap();
        let mut server = mockito::Server::new_async().await;
        let logout = server
            .mock("POST", "/logout")
            .with_status(401)
            .with_body(r#"{"message":"Session token not found or invalid"}"#)
            .expect(1)
            .create_async()
            .await;
        let provider = signed_in_at(dir.path(), server.url(), Some("stale"));
        let failed = provider.logout(LIMIT).await.unwrap_err();
        assert_eq!(failed.expires_at.as_deref(), Some("2999-01-01T00:00:00Z"));
        logout.assert_async().await;
    }

    /// A `Logout` SSO fails is sent once, never retried: the logout holds the credential's
    /// write lock, so its one attempt must fit the limit, and a repeat logout finds nothing to end.
    #[tokio::test]
    async fn a_failed_logout_is_not_retried() {
        let dir = tempdir().unwrap();
        let mut server = mockito::Server::new_async().await;
        let logout = server
            .mock("POST", "/logout")
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let provider = signed_in_at(dir.path(), server.url(), Some("token"));
        provider.logout(LIMIT).await.unwrap_err();
        logout.assert_async().await;
    }

    /// A sign-in sealed under a key since rotated cannot be ended at SSO, so a logout must say
    /// so rather than report that there was nothing to end.
    #[tokio::test]
    async fn logout_of_a_session_sealed_under_another_key_is_an_error() {
        let dir = tempdir().unwrap();
        let mut server = mockito::Server::new_async().await;
        let logout = server
            .mock("POST", "/logout")
            .expect(0)
            .create_async()
            .await;
        // Seal under one key, then log out with a provider holding another.
        signed_in_at(dir.path(), server.url(), Some("token"));
        let rotated = signed_in_at(dir.path(), server.url(), None);
        let failed = rotated.logout(LIMIT).await.unwrap_err();
        assert_eq!(
            failed.expires_at, None,
            "an unreadable token has no known expiry"
        );
        logout.assert_async().await;
    }
}
