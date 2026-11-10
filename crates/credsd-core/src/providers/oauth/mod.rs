//! OAuth2 credential providers.
//!
//! `AwsWebIdentityProvider` runs an OAuth2 authorization-code + PKCE login, caches the resulting tokens sealed on disk, and federates the OIDC JWT
//! to `sts:AssumeRoleWithWebIdentity`, so the child gets ordinary AWS credentials
//! (served via the existing `credential_process` path). The child never sees the
//! OAuth token; it lives entirely credsd↔IdP.

pub mod callback;
pub mod dpop;
pub mod pkce;
pub mod token;

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_sts::error::ProvideErrorMetadata as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::log::escape_log;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use self::callback::{CallbackServer, CALLBACK_TIMEOUT};
use self::dpop::DpopSigner;
use crate::config::AwsWebIdentityConfig;
use crate::credentials::Credentials;
use crate::encryption::EncryptionService;
use crate::error::{DaemonError, Result};
use crate::providers::{CredentialProvider, ReauthInput, Renewed, Renewer};

const TOKEN_FILE: &str = "oauth_token.enc";

/// Cached OAuth tokens, sealed at rest. Secrets zeroize on drop; `expires_at`
/// (RFC 3339) and `token_type` are non-secret metadata.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct CachedOAuthToken {
    access_token: String,
    id_token: Option<String>,
    refresh_token: Option<String>,
    #[zeroize(skip)]
    expires_at: String,
    #[zeroize(skip)]
    token_type: String,
}

impl CachedOAuthToken {
    /// The JWT presented to STS: the OIDC **id_token** when present (it carries the
    /// `aud`/`sub` STS validates), else the access token.
    fn web_identity_token(&self) -> &str {
        self.id_token.as_deref().unwrap_or(&self.access_token)
    }

    /// Build a cache entry from a token-endpoint response, carrying `prior`'s tokens
    /// forward when the server omits them. Both the code exchange (`prior = None`) and
    /// the refresh grant (`prior = Some(current)`) go through here, so the two paths
    /// cannot drift: OIDC lets a refresh response omit `id_token` *and* `refresh_token`,
    /// and dropping the id_token would silently fall `web_identity_token` back to the
    /// access token (wrong `aud`) and break STS after the first refresh. Expiry derives
    /// from the id_token's own `exp` — the JWT STS validates, which can outlive or
    /// under-live the access token's `expires_in` — falling back to `expires_in` only
    /// when there is no id_token or its `exp` is unreadable.
    fn from_response(resp: token::TokenResponse, prior: Option<&CachedOAuthToken>) -> Self {
        let id_token = resp
            .id_token
            .or_else(|| prior.and_then(|p| p.id_token.clone()));
        // Expiry tracks the token that will actually be presented to STS — the carried id_token
        // when the refresh returned none. Deriving it from `expires_in` instead would let the
        // cache look fresh while STS is handed a JWT that already expired. When the presented JWT
        // is *already* past, `renew` turns that into a re-auth rather than an endless refresh; see
        // the staleness check there.
        let expires_at = id_token
            .as_deref()
            .and_then(|jwt| parse_jwt_exp(jwt).ok())
            .unwrap_or_else(|| crate::credentials::expires_in_seconds(resp.expires_in))
            .to_rfc3339();
        Self {
            access_token: resp.access_token,
            id_token,
            refresh_token: resp
                .refresh_token
                .or_else(|| prior.and_then(|p| p.refresh_token.clone())),
            expires_at,
            token_type: resp.token_type,
        }
    }
}

/// HTTP client for every IdP call, with the timeouts `Client::new()` does not set.
///
/// Unbounded is not an option here: a token endpoint that accepts a connection and never answers
/// parks the caller forever, and `refresh_all` awaits credentials serially — so one such endpoint
/// stalls the background pre-warm pass for every uid, not just its own.
pub(crate) fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        // A validated https endpoint that answers 307/308 `Location: http://...` would otherwise
        // get the form body re-POSTed in cleartext — the code and PKCE verifier on exchange, the
        // refresh token on renew (reqwest replays the body on 307/308). `https_only` refuses the
        // downgrade rather than following it.
        .https_only(cfg!(not(debug_assertions)) || std::env::var("CREDSD_ALLOW_HTTP").is_err())
        // Token endpoints never legitimately redirect; following a redirect would replay
        // credentials (code, PKCE verifier, refresh token) to an attacker-controlled URL.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| DaemonError::provider(format!("cannot build HTTP client: {e}")))
}

/// A loopback listener bound and an authorization URL built, waiting on the browser.
///
/// Holds the PKCE verifier and the DPoP key (aws-login only), so it must not be logged, serialized, or sent over
/// the wire — only [`authorize_url`](Self::authorize_url) is safe to disclose.
pub struct PendingLogin {
    pub(crate) server: CallbackServer,
    pub(crate) pkce: pkce::Pkce,
    /// `Zeroizing` because the CSRF gate lives across a 5-minute await; a copy in dropped memory
    /// is exactly the window worth scrubbing. Matches `pkce::Pkce`.
    pub(crate) state: Zeroizing<String>,
    pub(crate) dpop: Option<DpopSigner>,
    pub(crate) redirect_uri: String,
    pub(crate) authorize_url: String,
}

impl PendingLogin {
    /// The URL the user must visit. Public by design: it carries the PKCE *challenge*, never the
    /// verifier, so disclosing it does not let a third party redeem the code.
    pub fn authorize_url(&self) -> &str {
        &self.authorize_url
    }
}

pub struct AwsWebIdentityProvider {
    credential_name: String,
    config: AwsWebIdentityConfig,
    encryption: Arc<EncryptionService>,
    data_dir: PathBuf,
    /// Built once at construction so the connection pool survives across refreshes. Rebuilding
    /// per call — the previous shape — threw the pool away every renew and made "one shared
    /// client" only true within a single flow.
    http: reqwest::Client,
}

impl AwsWebIdentityProvider {
    pub fn new(
        credential_name: String,
        config: AwsWebIdentityConfig,
        encryption: Arc<EncryptionService>,
        data_dir: PathBuf,
    ) -> Result<Self> {
        let http = http_client()?;
        Ok(Self {
            credential_name,
            config,
            encryption,
            data_dir,
            http,
        })
    }

    fn persist_token(&self, token: &CachedOAuthToken) -> Result<()> {
        // Cleartext until seal_to_file encrypts it — scrub the transient on drop.
        let json = Zeroizing::new(serde_json::to_vec(token)?);
        self.encryption
            .seal_to_file(&self.data_dir.join(TOKEN_FILE), &json)
    }

    fn load_token(&self) -> Result<CachedOAuthToken> {
        let plaintext = self
            .encryption
            .open_from_file(&self.data_dir.join(TOKEN_FILE))
            .map_err(|e| {
                DaemonError::provider(format!(
                    "no usable OAuth token for credential '{}': {}. \
                     Run 'credsd login --environment {}'.",
                    self.credential_name, e, self.credential_name
                ))
            })?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Begin an interactive login: bind the loopback listener and build the authorization URL.
    ///
    /// Split from [`finish_interactive_login`](Self::finish_interactive_login) so the URL can be
    /// *reported* rather than opened. The daemon runs as the scoped `credsd` user with no display
    /// session, so it cannot open a browser; it sends the URL to the client as a
    /// `ProgressParams::AuthorizeUrl` notification and the client opens it. The listener is bound
    /// here, before the URL exists, because the URL embeds the port it is listening on.
    ///
    /// Nothing secret crosses the socket: the PKCE challenge in the URL is public by design and
    /// the verifier stays in the returned [`PendingLogin`], which never leaves this process.
    pub fn begin_interactive_login(&self) -> Result<PendingLogin> {
        // The interactive flow needs the OAuth endpoints. They are `Option` because a
        // token-seeded credential would carry none, which no command creates yet (see
        // `seed_id_token`) — so today this branch means a hand-edited `credentials.toml`.
        // `token_endpoint` is validated here but read in `finish`, so the presence check covers both.
        let (authorization_endpoint, client_id, _token_endpoint) = match (
            self.config.authorization_endpoint.as_deref(),
            self.config.client_id.as_deref(),
            self.config.token_endpoint.as_deref(),
        ) {
            (Some(a), Some(c), Some(t)) => (a, c, t),
            _ => {
                return Err(DaemonError::provider(
                    "interactive login requires authorization_endpoint, token_endpoint, and \
                     client_id; this credential has none configured, so there is no browser \
                     flow to run",
                ))
            }
        };

        let pkce = pkce::Pkce::generate()?;
        let state = Zeroizing::new(pkce::random_token(32)?);
        let server = match self.config.callback_port {
            Some(port) => CallbackServer::bind_port(port)?,
            None => CallbackServer::bind()?,
        };
        let redirect_uri = server.redirect_uri("/callback");

        // RFC 6749 §3.1 permits the authorization endpoint to carry its own query, so the first
        // separator is `&` when one is already present. A second `?` makes the AS drop every
        // parameter after it, and the redirect simply never arrives.
        let separator = if authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let mut auth_url = format!(
            "{}{separator}response_type=code&client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256",
            authorization_endpoint,
            urlencode(client_id),
            urlencode(&redirect_uri),
            urlencode(state.as_str()),
            pkce.challenge,
        );
        if !self.config.scopes.is_empty() {
            auth_url.push_str(&format!(
                "&scope={}",
                urlencode(&self.config.scopes.join(" "))
            ));
        }

        Ok(PendingLogin {
            server,
            pkce,
            state,
            dpop: None,
            redirect_uri,
            authorize_url: auth_url,
        })
    }

    /// Wait for the browser redirect, exchange the code, and seal the tokens.
    ///
    /// Consumes the [`PendingLogin`] so a listener cannot be waited on twice, and so the PKCE
    /// verifier is dropped with it.
    pub async fn finish_interactive_login(&self, pending: PendingLogin) -> Result<()> {
        let PendingLogin {
            server,
            pkce,
            state,
            dpop: _,
            redirect_uri,
            authorize_url: _,
        } = pending;

        // Re-read the endpoints rather than carrying borrows through the await: `begin` already
        // proved they are present, and this keeps `PendingLogin` free of config copies.
        let (client_id, token_endpoint) = match (
            self.config.client_id.as_deref(),
            self.config.token_endpoint.as_deref(),
        ) {
            (Some(c), Some(t)) => (c, t),
            _ => {
                return Err(DaemonError::provider(
                    "interactive login requires token_endpoint and client_id",
                ))
            }
        };

        // The callback server blocks on a raw socket — keep it off the async runtime.
        let code =
            tokio::task::spawn_blocking(move || server.wait(state.as_str(), CALLBACK_TIMEOUT))
                .await
                .map_err(|e| DaemonError::provider(format!("callback task failed: {}", e)))??;

        let tokens = token::exchange_code(
            &self.http,
            token_endpoint,
            client_id,
            &code,
            &pkce.verifier,
            &redirect_uri,
        )
        .await
        .map_err(|e| DaemonError::provider(format!("token exchange failed: {}", e)))?;

        let cached = CachedOAuthToken::from_response(tokens, None);
        self.persist_token(&cached)?;
        info!(credential = %self.credential_name, "OAuth login successful");
        Ok(())
    }

    /// Seed a pre-obtained OIDC JWT as the cached token, skipping the browser flow — the
    /// non-interactive path for CI. **No command reaches this yet** — it needs a
    /// `credential/seal_oauth` RPC alongside the existing seal methods, since a client cannot
    /// write the caller tree itself. Kept as that seam rather than deleted and rewritten. The
    /// JWT's `exp` sets the
    /// cache expiry; there is no refresh token, so once it expires the credential needs a
    /// fresh token fed in. `jwt` is secret (zeroized by the caller and by `CachedOAuthToken`).
    pub fn seed_id_token(&self, jwt: &Zeroizing<String>) -> Result<()> {
        let expires_at = parse_jwt_exp(jwt)?;
        let token = CachedOAuthToken {
            access_token: jwt.to_string(),
            id_token: Some(jwt.to_string()),
            refresh_token: None,
            expires_at: expires_at.to_rfc3339(),
            token_type: "Bearer".to_string(),
        };
        self.persist_token(&token)
    }

    /// Federate the OIDC JWT to short-lived AWS credentials.
    async fn assume_role(&self, web_identity_token: &str) -> Result<Credentials> {
        let conf = aws_sdk_sts::Config::builder()
            .region(aws_sdk_sts::config::Region::new(self.config.region.clone()))
            .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest())
            // Matches the token-endpoint client: the serial pre-warm loop would
            // park here indefinitely on a reachable-but-silent STS endpoint without it.
            .timeout_config(
                aws_sdk_sts::config::timeout::TimeoutConfig::builder()
                    .operation_timeout(std::time::Duration::from_secs(30))
                    .build(),
            )
            .build();
        let sts = aws_sdk_sts::Client::from_conf(conf);

        let session_name = self
            .config
            .role_session_name
            .clone()
            .unwrap_or_else(|| self.credential_name.clone());

        let resp = sts
            .assume_role_with_web_identity()
            .role_arn(&self.config.role_arn)
            .role_session_name(session_name)
            .web_identity_token(web_identity_token)
            .set_duration_seconds(self.config.duration_seconds)
            .send()
            .await
            .map_err(|e| {
                // The service message, not a Debug dump of the SdkError — CONTRIBUTING.md forbids
                // the latter, and the most common failure here (the role's trust policy rejecting
                // this issuer → AccessDenied) is precisely the case where the message is the
                // whole answer.
                DaemonError::provider(format!(
                    "AssumeRoleWithWebIdentity failed: {}",
                    e.as_service_error()
                        .and_then(|se| se.message())
                        .unwrap_or("see daemon log for the SDK error")
                ))
            })?;

        let creds = resp
            .credentials()
            .ok_or_else(|| DaemonError::provider("no credentials in STS response"))?;
        let expires_at = DateTime::from_timestamp(creds.expiration().secs(), 0)
            .unwrap_or_else(|| crate::credentials::expires_in_seconds(3600));

        Ok(Credentials::session(
            creds.access_key_id().to_string(),
            creds.secret_access_key().to_string(),
            creds.session_token().to_string(),
            expires_at,
        ))
    }
}

impl CredentialProvider for AwsWebIdentityProvider {
    // The stored refresh token re-mints the JWT unattended, which STS federates to AWS
    // creds — so this source renews unattended until the refresh token is spent, then
    // reports a browser re-auth. The interactive login lives in `authenticate`.
    fn renewer(&self) -> Option<&dyn Renewer> {
        Some(self)
    }

    fn mode_name(&self) -> &'static str {
        "aws-web-identity"
    }
}

#[async_trait]
impl Renewer for AwsWebIdentityProvider {
    async fn renew(&self) -> Result<Renewed> {
        // No token on disk (never logged in) or unreadable (keystore rotated) → re-auth,
        // not a transient error the store would retry forever.
        let Ok(cached) = self.load_token() else {
            return Ok(Renewed::ReauthRequired(ReauthInput::Browser));
        };

        let expires_at = DateTime::parse_from_rfc3339(&cached.expires_at)
            .map_err(|e| DaemonError::provider(format!("invalid token expires_at: {}", e)))?;
        let fresh = expires_at.signed_duration_since(Utc::now()).num_seconds() > 60;

        // Hold the refreshed token alive for the STS call; it zeroizes on drop.
        let mut refreshed: Option<CachedOAuthToken> = None;
        let web_identity_token: &str = if fresh {
            cached.web_identity_token()
        } else {
            let Some(refresh_token) = cached.refresh_token.as_deref() else {
                // No refresh token. An interactive credential (endpoints set) can re-auth in a
                // browser; one with no endpoints has no unattended path at all.
                if self.config.token_endpoint.is_some() {
                    warn!(credential = %self.credential_name, "OAuth token expired, no refresh token — re-auth required");
                    return Ok(Renewed::ReauthRequired(ReauthInput::Browser));
                }
                return Err(DaemonError::provider(format!(
                    "seeded OIDC token for '{}' expired and the credential has no OAuth \
                     endpoints, so it cannot be renewed; re-create it with a fresh token",
                    self.credential_name
                )));
            };
            info!(credential = %self.credential_name, "OAuth token expiring, refreshing");
            // A refresh token is only ever written by the interactive flow, so the endpoints are
            // present; guard anyway rather than unwrap.
            let (Some(token_endpoint), Some(client_id)) = (
                self.config.token_endpoint.as_deref(),
                self.config.client_id.as_deref(),
            ) else {
                return Ok(Renewed::ReauthRequired(ReauthInput::Browser));
            };
            match token::refresh(&self.http, token_endpoint, client_id, refresh_token).await {
                Ok(tokens) => {
                    // Carry the prior id_token/refresh_token forward when the server omits
                    // them (see CachedOAuthToken::from_response).
                    let new = CachedOAuthToken::from_response(tokens, Some(&cached));

                    // A refresh that succeeds but leaves the presented JWT expired means the AS
                    // renewed the access token without issuing a new id_token — the one STS
                    // validates. Retrying redeems the refresh token again and again and each STS
                    // call fails, which surfaces as `Unavailable` and never offers a re-login.
                    // Only a browser login mints a fresh id_token, so say so.
                    if DateTime::parse_from_rfc3339(&new.expires_at)
                        .map(|e| e.with_timezone(&Utc) <= Utc::now())
                        .unwrap_or(false)
                    {
                        warn!(
                            credential = %self.credential_name,
                            "refresh returned no new id_token and the stored one has expired — re-auth required"
                        );
                        return Ok(Renewed::ReauthRequired(ReauthInput::Browser));
                    }
                    self.persist_token(&new)?;
                    // `Option::insert` hands back a reference with the Option's lifetime, so the
                    // borrow outlives this arm without storing-then-unwrapping the value back out.
                    refreshed.insert(new).web_identity_token()
                }
                Err(token::TokenError::Terminal(m)) => {
                    warn!(credential = %self.credential_name, reason = %escape_log(&m), "OAuth refresh token spent — re-auth required");
                    return Ok(Renewed::ReauthRequired(ReauthInput::Browser));
                }
                Err(token::TokenError::Transient(m)) => {
                    return Err(DaemonError::provider(format!(
                        "OAuth refresh failed: {}",
                        m
                    )));
                }
            }
        };

        let creds = self.assume_role(web_identity_token).await?;
        drop(refreshed);
        Ok(Renewed::Ready(creds))
    }
}

/// Extract the `exp` (Unix seconds) from a JWT's payload to set the local cache expiry.
/// The signature is NOT verified — STS validates the token; this only decodes the middle
/// base64url segment to learn when to stop serving it.
fn parse_jwt_exp(jwt: &str) -> Result<DateTime<Utc>> {
    use base64::Engine as _;
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(DaemonError::provider(
            "malformed JWT: expected header.payload.signature",
        ));
    }
    let payload_b64 = parts
        .get(1)
        .ok_or_else(|| DaemonError::provider("malformed JWT: missing payload"))?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| DaemonError::provider(format!("malformed JWT payload: {}", e)))?;
    #[derive(Deserialize)]
    struct Claims {
        exp: Option<i64>,
    }
    let claims: Claims = serde_json::from_slice(&payload)
        .map_err(|e| DaemonError::provider(format!("malformed JWT claims: {}", e)))?;
    let exp = claims
        .exp
        .ok_or_else(|| DaemonError::provider("JWT has no exp claim"))?;
    DateTime::from_timestamp(exp, 0).ok_or_else(|| DaemonError::provider("JWT exp out of range"))
}

/// Percent-encode a query-parameter value (RFC 3986 unreserved set passes through).
pub(crate) fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_key;
    use tempfile::tempdir;

    fn cfg() -> AwsWebIdentityConfig {
        AwsWebIdentityConfig {
            authorization_endpoint: Some("https://idp/authorize".into()),
            token_endpoint: Some("https://idp/token".into()),
            client_id: Some("client-123".into()),
            scopes: vec!["openid".into()],
            role_arn: "arn:aws:iam::111111111111:role/App".into(),
            region: "us-east-1".into(),
            duration_seconds: None,
            role_session_name: None,
            callback_port: None,
            identity_type: Default::default(),
        }
    }

    fn provider(config: AwsWebIdentityConfig) -> (AwsWebIdentityProvider, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let enc = Arc::new(EncryptionService::new(generate_key().unwrap()).unwrap());
        (
            AwsWebIdentityProvider::new("work".into(), config, enc, dir.path().to_path_buf())
                .unwrap(),
            dir,
        )
    }

    #[test]
    fn urlencode_encodes_reserved_only() {
        assert_eq!(urlencode("abcXYZ-._~"), "abcXYZ-._~");
        assert_eq!(urlencode("a b/c"), "a%20b%2Fc");
        assert_eq!(urlencode("https://x/y"), "https%3A%2F%2Fx%2Fy");
    }

    #[test]
    fn web_identity_token_prefers_id_token() {
        let with_id = CachedOAuthToken {
            access_token: "at".into(),
            id_token: Some("idt".into()),
            refresh_token: None,
            expires_at: "x".into(),
            token_type: "Bearer".into(),
        };
        assert_eq!(with_id.web_identity_token(), "idt");
        let no_id = CachedOAuthToken {
            access_token: "at".into(),
            id_token: None,
            refresh_token: None,
            expires_at: "x".into(),
            token_type: "Bearer".into(),
        };
        assert_eq!(no_id.web_identity_token(), "at");
    }

    /// No token on disk → unattended renew asks for re-auth (not a retryable `Err`).
    #[tokio::test]
    async fn renew_without_a_token_asks_for_reauth() {
        let (p, _d) = provider(cfg());
        match p.renew().await {
            Ok(Renewed::ReauthRequired(ReauthInput::Browser)) => {}
            other => panic!("expected browser re-auth, got {:?}", other),
        }
    }

    /// The URL the daemon hands the client must carry the PKCE *challenge* and never the
    /// verifier: it crosses the socket, reaches the client, and is opened in a browser. A
    /// verifier there would let anyone who saw the URL redeem the code.
    #[test]
    fn authorize_url_discloses_no_verifier() {
        let (p, _d) = provider(cfg());
        let pending = p.begin_interactive_login().expect("begin");
        let url = pending.authorize_url().to_string();

        assert!(
            !url.contains(&pending.pkce.verifier),
            "URL leaks the PKCE verifier"
        );
        assert!(
            url.contains("code_challenge_method=S256"),
            "PKCE must be S256: {url}"
        );
        assert!(
            url.contains(&pending.pkce.challenge),
            "URL must carry the challenge"
        );
        assert!(url.contains("state="), "URL must carry state: {url}");
        // The redirect the browser is sent to is the daemon's own loopback listener.
        assert!(
            url.contains("127.0.0.1") || url.contains("127.0.0.1%3A"),
            "redirect_uri must be loopback: {url}"
        );
    }

    /// An authorization endpoint may already carry a query (RFC 6749 §3.1). A second `?` makes
    /// the AS drop everything after it, and the only symptom is a redirect that never arrives —
    /// indistinguishable, from the user's side, from a 5-minute timeout.
    #[test]
    fn authorize_url_appends_to_an_existing_query() {
        let mut config = cfg();
        config.authorization_endpoint = Some("https://idp/authorize?tenant=acme".into());
        let (p, _d) = provider(config);

        let url = p
            .begin_interactive_login()
            .expect("begin")
            .authorize_url()
            .to_string();
        assert!(
            url.starts_with("https://idp/authorize?tenant=acme&response_type=code"),
            "{url}"
        );
        assert_eq!(
            url.matches('?').count(),
            1,
            "exactly one query separator: {url}"
        );
    }

    /// Expiry must track the JWT that will be presented, so a refresh returning no id_token
    /// inherits the carried token's `exp` rather than `now + expires_in` — otherwise the cache
    /// looks fresh while STS is handed an expired JWT. When that carried `exp` is already past,
    /// `renew` is what turns it into a re-auth; this pins the `from_response` half.
    #[test]
    fn refresh_without_id_token_tracks_the_presented_token() {
        let prior = CachedOAuthToken {
            access_token: "old-access".into(),
            id_token: Some(jwt_with_exp(Some(Utc::now().timestamp() - 3600))),
            refresh_token: Some("r".into()),
            expires_at: (Utc::now() - chrono::TimeDelta::hours(1)).to_rfc3339(),
            token_type: "Bearer".into(),
        };
        let resp = token::TokenResponse {
            access_token: "new-access".into(),
            id_token: None,
            refresh_token: None,
            expires_in: 3600,
            token_type: "Bearer".into(),
            scope: None,
        };
        let next = CachedOAuthToken::from_response(resp, Some(&prior));
        let expires_at = DateTime::parse_from_rfc3339(&next.expires_at).expect("rfc3339");
        assert!(
            expires_at.with_timezone(&Utc) <= Utc::now(),
            "expiry {} must follow the carried (expired) id_token, not expires_in",
            next.expires_at
        );
        // The id_token itself is carried forward — it is what STS validates.
        assert_eq!(next.id_token, prior.id_token);
    }

    /// `state` must be unguessable per flow, since it is the only thing standing between a local
    /// process and injecting its own authorization code into someone else's login.
    #[test]
    fn each_login_gets_a_fresh_state_and_verifier() {
        let (p, _d) = provider(cfg());
        let a = p.begin_interactive_login().expect("begin");
        let b = p.begin_interactive_login().expect("begin");
        assert_ne!(a.state, b.state);
        assert_ne!(a.pkce.verifier, b.pkce.verifier);
        // 32 random bytes, base64url-nopad.
        assert_eq!(a.state.len(), 43, "state should be 256 bits of entropy");
    }

    #[test]
    fn token_seal_round_trips() {
        let (p, _d) = provider(cfg());
        let tok = CachedOAuthToken {
            access_token: "at".into(),
            id_token: Some("idt".into()),
            refresh_token: Some("rt".into()),
            expires_at: "2026-01-01T00:00:00+00:00".into(),
            token_type: "Bearer".into(),
        };
        p.persist_token(&tok).unwrap();
        let back = p.load_token().unwrap();
        assert_eq!(back.access_token, "at");
        assert_eq!(back.id_token.as_deref(), Some("idt"));
        assert_eq!(back.refresh_token.as_deref(), Some("rt"));
    }

    /// An `aws-web-identity` credentials.toml entry parses.
    #[test]
    fn parses_aws_login_credential_source() {
        use crate::config::credentials::CredentialSource;
        let toml = r#"
type = "aws-web-identity"
authorization_endpoint = "https://idp/authorize"
token_endpoint = "https://idp/token"
client_id = "c"
role_arn = "arn:aws:iam::111111111111:role/App"
region = "us-east-1"
scopes = ["openid"]
"#;
        match toml::from_str::<CredentialSource>(toml).unwrap() {
            CredentialSource::AwsWebIdentity(c) => {
                assert_eq!(c.client_id.as_deref(), Some("c"));
            }
            other => panic!("expected AwsWebIdentity, got {:?}", other),
        }
    }

    /// `dpop` was removed from `aws-web-identity` (AssumeRoleWithWebIdentity is bearer, so the
    /// flag bound only the credsd-to-IdP leg). An entry that still sets it must fail to parse,
    /// whatever the value, so an upgraded operator sees an error rather than a silent downgrade.
    #[test]
    fn web_identity_entry_rejects_the_removed_dpop_key() {
        use crate::config::credentials::CredentialSource;
        for value in ["true", "false", "\"yes\"", "1", "[]", "{}"] {
            let toml = format!(
                "type = \"aws-web-identity\"\n\
                 authorization_endpoint = \"https://idp/authorize\"\n\
                 token_endpoint = \"https://idp/token\"\n\
                 client_id = \"c\"\n\
                 role_arn = \"arn:aws:iam::111111111111:role/App\"\n\
                 region = \"us-east-1\"\n\
                 dpop = {value}\n"
            );
            let err = toml::from_str::<CredentialSource>(&toml)
                .expect_err("dpop must be rejected for every value");
            assert!(
                err.to_string().contains("unknown field `dpop`"),
                "dpop = {value}: wrong error: {err}"
            );
        }
    }

    /// The `credentials.toml` path an operator actually hits: an entry with no `region` is refused
    /// at parse, the same as the typed config. It must not federate against a guessed endpoint.
    #[test]
    fn aws_web_identity_credential_source_without_region_fails_to_parse() {
        use crate::config::credentials::CredentialSource;
        let toml = r#"
type = "aws-web-identity"
authorization_endpoint = "https://idp/authorize"
token_endpoint = "https://idp/token"
client_id = "c"
role_arn = "arn:aws:iam::111111111111:role/App"
scopes = ["openid"]
"#;
        let err = toml::from_str::<CredentialSource>(toml).expect_err("no region must not parse");
        assert!(err.to_string().contains("missing field `region`"), "{err}");
    }

    // A JWT with the given exp (or none); header/signature are throwaway (never verified).
    fn jwt_with_exp(exp: Option<i64>) -> String {
        use base64::Engine as _;
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let claims = match exp {
            Some(e) => format!("{{\"sub\":\"u\",\"exp\":{}}}", e),
            None => "{\"sub\":\"u\"}".to_string(),
        };
        format!(
            "{}.{}.{}",
            b64(b"{\"alg\":\"none\"}"),
            b64(claims.as_bytes()),
            b64(b"sig")
        )
    }

    #[test]
    fn parse_jwt_exp_reads_exp() {
        let dt = parse_jwt_exp(&jwt_with_exp(Some(1_800_000_000))).unwrap();
        assert_eq!(dt.timestamp(), 1_800_000_000);
    }

    #[test]
    fn parse_jwt_exp_rejects_missing_and_malformed() {
        assert!(parse_jwt_exp(&jwt_with_exp(None)).is_err()); // no exp claim
        assert!(parse_jwt_exp("not-a-jwt").is_err()); // not 3 segments
        assert!(parse_jwt_exp("a.b").is_err()); // 2 segments
        assert!(parse_jwt_exp("a.!!!.c").is_err()); // bad base64 payload
    }

    /// A refresh response that OMITS both id_token and refresh_token (OIDC permits this)
    /// must carry the prior ones forward — else web_identity_token falls back to the access
    /// token and STS rejects it after the first refresh — and expiry derives from the
    /// carried id_token's own `exp`, not `now + expires_in`.
    #[test]
    fn from_response_carries_tokens_forward_and_uses_id_token_exp() {
        let prior = CachedOAuthToken {
            access_token: "old-at".into(),
            id_token: Some(jwt_with_exp(Some(1_800_000_000))),
            refresh_token: Some("old-rt".into()),
            expires_at: "x".into(),
            token_type: "Bearer".into(),
        };
        let resp = token::TokenResponse {
            access_token: "new-at".into(),
            id_token: None,
            refresh_token: None,
            expires_in: 3600,
            token_type: "Bearer".into(),
            scope: None,
        };
        let merged = CachedOAuthToken::from_response(resp, Some(&prior));
        assert_eq!(merged.access_token, "new-at");
        assert_eq!(merged.id_token.as_deref(), prior.id_token.as_deref()); // carried forward
        assert_eq!(merged.refresh_token.as_deref(), Some("old-rt")); // carried forward
        assert_eq!(
            DateTime::parse_from_rfc3339(&merged.expires_at)
                .unwrap()
                .timestamp(),
            1_800_000_000 // from the id_token exp, not now + 3600
        );
    }

    /// A seeded token (no endpoints, no refresh) round-trips and, while fresh, drives the
    /// STS federation — i.e. renew() gets past token loading to the assume-role call.
    #[test]
    fn seed_id_token_round_trips() {
        let mut config = cfg();
        config.authorization_endpoint = None;
        config.token_endpoint = None;
        config.client_id = None;
        let (p, _d) = provider(config);
        let jwt = Zeroizing::new(jwt_with_exp(Some(4_100_000_000))); // far future
        p.seed_id_token(&jwt).unwrap();
        let back = p.load_token().unwrap();
        assert_eq!(back.web_identity_token(), jwt.as_str());
        assert!(back.refresh_token.is_none());
    }

    /// An EXPIRED seeded token (no refresh, no endpoints) can't re-auth in a browser — renew
    /// surfaces a clear error telling the user to feed a fresh token, not a bogus reauth.
    #[tokio::test]
    async fn expired_seeded_token_without_endpoints_errors_clearly() {
        let mut config = cfg();
        config.authorization_endpoint = None;
        config.token_endpoint = None;
        config.client_id = None;
        let (p, _d) = provider(config);
        p.seed_id_token(&Zeroizing::new(jwt_with_exp(Some(1)))) // 1970 → expired
            .unwrap();
        match p.renew().await {
            Err(e) => assert!(
                e.to_string().contains("cannot be renewed"),
                "the message must say why it is stuck, not name a flag that does not exist: {}",
                e
            ),
            other => panic!("expected a fresh-token error, got {:?}", other),
        }
    }
}
