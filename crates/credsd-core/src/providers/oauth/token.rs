//! OAuth2 token-endpoint client: authorization-code exchange and refresh.
//!
//! Both grants POST `application/x-www-form-urlencoded` to the token endpoint. Failures are split into
//! **terminal** (grant spent → the provider surfaces re-auth) and **transient**
//! (network/5xx → retried) so a dead refresh token doesn't masquerade as an outage.

use serde::Deserialize;

use crate::error::{DaemonError, Result};

/// Lifetime assumed when the AS omits `expires_in`, which RFC 6749 §5.1 permits (it is
/// RECOMMENDED, not REQUIRED). Short on purpose: the real lifetime is unknown, so the only safe
/// assumption is one that expires soon enough to re-check and not so soon that it reads as
/// already dead. Defaulting to 0 made "unknown" indistinguishable from "expired", which the
/// stale-cache guard in `renew` then turned into a demand for a browser login — for a refresh
/// that had just returned a usable token.
const DEFAULT_EXPIRES_IN_SECS: i64 = 300;

/// Cap on token-response body bytes. A real response fits in a few KiB; ten of them is generous
/// while still refusing a peer that streams forever. The 30s request-level timeout bounds
/// *duration*, not size, so both are needed.
const MAX_TOKEN_BODY_BYTES: usize = 64 * 1024;

/// Whether an OAuth `error` code is terminal: no retry can change the answer.
///
/// The single place this classification lives, so a test can assert it without restating the
/// table — a duplicated table in a test passes while production drifts away from it.
async fn read_bounded_body(mut resp: reqwest::Response) -> std::result::Result<String, TokenError> {
    // `Content-Length` lets us refuse an oversized response before reading any of it. A chunked
    // response advertises nothing, so the cap is also enforced per chunk: buffering the whole
    // body first and checking afterwards lets a peer stream gigabytes inside the request timeout.
    if let Some(len) = resp.content_length() {
        if len > MAX_TOKEN_BODY_BYTES as u64 {
            return Err(TokenError::Transient(format!(
                "token response advertised {len} bytes; cap is {MAX_TOKEN_BODY_BYTES}"
            )));
        }
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| TokenError::Transient(format!("reading token response: {e}")))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_TOKEN_BODY_BYTES {
            return Err(TokenError::Transient(format!(
                "token response exceeded {MAX_TOKEN_BODY_BYTES} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes)
        .map_err(|e| TokenError::Transient(format!("token response is not utf-8: {e}")))
}

pub(super) fn is_terminal_oauth_error(code: &str) -> bool {
    matches!(code, "invalid_grant" | "invalid_token" | "expired_token")
}

/// Tokens returned by the endpoint. `expires_in` falls back to
/// [`DEFAULT_EXPIRES_IN_SECS`] when the server omits it.
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    pub token_type: String,
    /// Scope granted by the server (RFC 6749 §5.1). May differ from the requested
    /// scope when the server narrows it; callers SHOULD verify this field rather than
    /// trusting the request reflected their intent.
    pub scope: Option<String>,
}

/// A token request failure, split by whether re-authentication is the only fix.
pub enum TokenError {
    /// Grant is spent (`invalid_grant` / `invalid_token` / expired) — needs re-auth.
    Terminal(String),
    /// Transport, throttling, 5xx, or a malformed response — safe to retry.
    Transient(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Terminal(m) => write!(f, "{}", m),
            TokenError::Transient(m) => write!(f, "{}", m),
        }
    }
}

#[derive(Deserialize)]
struct RawToken {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Exchange an authorization code (PKCE) for tokens.
pub async fn exchange_code(
    client: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> std::result::Result<TokenResponse, TokenError> {
    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("code_verifier", verifier),
        ("redirect_uri", redirect_uri),
    ];
    post_token(client, token_endpoint, &params).await
}

/// Obtain tokens using the client_credentials grant (machine-to-machine).
///
/// Credentials are sent as HTTP Basic (`client_secret_basic`) rather than
/// body params because several IdP implementations echo request bodies in
/// audit logs, which would expose the secret (RFC 6749 §2.3.1 prefers the
/// header form for exactly this reason).
/// Rejects any URL whose scheme is not `https`. Extracted so the check is unconditional and
/// directly testable — a `cfg(not(test))` gate would mean the tests never exercise it.
pub(crate) fn require_https(token_url: &str) -> Result<()> {
    let url = reqwest::Url::parse(token_url)
        .map_err(|e| DaemonError::Config(format!("invalid token_url: {e}")))?;
    if url.scheme() == "https" {
        return Ok(());
    }
    #[cfg(debug_assertions)]
    if std::env::var("CREDSD_ALLOW_HTTP").is_ok() {
        return Ok(());
    }
    Err(DaemonError::Config(
        "token_url must use HTTPS to prevent credential exposure".into(),
    ))
}

/// Client authentication options for the token endpoint.
#[non_exhaustive]
pub enum ClientCredentialsAuth<'a> {
    /// `client_secret_basic`: HTTP Basic with client_id + client_secret.
    Secret(&'a str),
    /// `private_key_jwt`: ES256 signed client assertion (RFC 7523 §2.2).
    /// `pkcs8` is the PKCS#8 DER of the private key (owned; zeroized on drop).
    PrivateKeyJwt { pkcs8: zeroize::Zeroizing<Vec<u8>> },
}

pub async fn client_credentials(
    token_url: &str,
    client_id: &str,
    auth: ClientCredentialsAuth<'_>,
    scope: Option<&str>,
    http: &reqwest::Client,
) -> Result<TokenResponse> {
    require_https(token_url)?;
    exchange_client_credentials(token_url, client_id, auth, scope, http).await
}

/// Inner request logic. Private so the only production entry is `client_credentials`, which
/// runs `require_https` first. Tests call this directly to drive mock HTTP endpoints without
/// duplicating the request behaviour.
pub(crate) async fn exchange_client_credentials(
    token_url: &str,
    client_id: &str,
    auth: ClientCredentialsAuth<'_>,
    scope: Option<&str>,
    http: &reqwest::Client,
) -> Result<TokenResponse> {
    require_https(token_url)?;
    let base = [("grant_type", "client_credentials")];
    let scope_entry = scope.map(|s| ("scope", s));

    // Build request: Secret uses HTTP Basic; PrivateKeyJwt adds client_assertion form params.
    const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    match auth {
        ClientCredentialsAuth::Secret(secret) => {
            let params: Vec<(&str, &str)> = base.into_iter().chain(scope_entry).collect();
            send_and_parse(
                http.post(token_url)
                    .basic_auth(client_id, Some(secret))
                    .form(&params),
            )
            .await
        }
        ClientCredentialsAuth::PrivateKeyJwt { pkcs8 } => {
            let assertion_buf = sign_client_assertion(client_id, token_url, &pkcs8)?;
            let params: Vec<(&str, &str)> = base
                .into_iter()
                .chain(scope_entry)
                .chain([
                    ("client_id", client_id),
                    ("client_assertion_type", ASSERTION_TYPE),
                    ("client_assertion", assertion_buf.as_str()),
                ])
                .collect();
            send_and_parse(http.post(token_url).form(&params)).await
        }
    }
}

/// Sign an RFC 7523 §2.2 client assertion JWT with an ES256 private key.
fn sign_client_assertion(
    client_id: &str,
    token_url: &str,
    pkcs8: &zeroize::Zeroizing<Vec<u8>>,
) -> Result<String> {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chrono::Utc;

    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
        .map_err(|_| DaemonError::provider("private_key_jwt: malformed key"))?;
    let pub_point = kp.public_key().as_ref();
    let (x, y) = match pub_point {
        [0x04, rest @ ..] if rest.len() == 64 => {
            let (x, y) = rest.split_at(32);
            (URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y))
        }
        _ => {
            return Err(DaemonError::provider(
                "private_key_jwt: unexpected public key encoding",
            ))
        }
    };

    let now = Utc::now().timestamp();
    let header =
        serde_json::json!({"alg":"ES256","typ":"JWT","jwk":{"crv":"P-256","kty":"EC","x":x,"y":y}});
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": token_url,
        "iat": now,
        "exp": now.saturating_add(300),
        "jti": super::pkce::random_token(16)?,
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?),
    );
    let sig = kp
        .sign(&SystemRandom::new(), signing_input.as_bytes())
        .map_err(|_| DaemonError::provider("private_key_jwt: signing failed"))?;
    Ok(format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(sig.as_ref())
    ))
}

/// Send a prepared request and parse the token response.
async fn send_and_parse(req: reqwest::RequestBuilder) -> Result<TokenResponse> {
    let resp = req
        .send()
        .await
        .map_err(|e| DaemonError::Provider(format!("token request failed: {}", e)))?;

    // A 3xx from a token endpoint signals misconfiguration, not a valid
    // protocol step; following it would silently strip the Authorization header.
    if resp.status().is_redirection() {
        return Err(DaemonError::Provider(format!(
            "unexpected redirect {} from token endpoint",
            resp.status()
        )));
    }

    let status = resp.status();
    let body = zeroize::Zeroizing::new(
        read_bounded_body(resp)
            .await
            .map_err(|e| DaemonError::Provider(e.to_string()))?,
    );

    if status.is_success() {
        let raw: RawToken = serde_json::from_str(&body)
            .map_err(|e| DaemonError::Provider(format!("malformed token response: {}", e)))?;
        return Ok(TokenResponse {
            access_token: raw.access_token,
            id_token: raw.id_token,
            refresh_token: raw.refresh_token,
            expires_in: raw.expires_in.unwrap_or(DEFAULT_EXPIRES_IN_SECS),
            token_type: raw.token_type.unwrap_or_else(|| "Bearer".to_string()),
            scope: raw.scope,
        });
    }

    let parsed_err: Option<OAuthError> = serde_json::from_str(&body).ok();
    let code = parsed_err.as_ref().map(|e| e.error.as_str()).unwrap_or("");
    let detail = parsed_err
        .as_ref()
        .and_then(|e| e.error_description.as_deref())
        .unwrap_or("");

    // invalid_client means the credentials are wrong or revoked; no retry will
    // succeed, so surface a terminal error rather than spinning the retry loop.
    match code {
        "invalid_client" => Err(DaemonError::ReauthRequired(format!(
            "invalid_client: {}",
            detail
        ))),
        _ => Err(DaemonError::Provider(format!(
            "token endpoint returned {}: {}",
            status, detail
        ))),
    }
}

/// Obtain tokens using the JWT Bearer grant (RFC 7523).
///
/// The assertion JWT is the sole credential; no client_secret is involved.
/// Attaching Basic auth with empty credentials is incorrect for this grant and
/// rejected by strict IdPs, so no Authorization header is added.
#[cfg(feature = "jwt-bearer")]
pub async fn jwt_bearer(
    token_url: &str,
    assertion: &str,
    client_id: Option<&str>,
    scope: Option<&str>,
    http: &reqwest::Client,
) -> Result<TokenResponse> {
    require_https(token_url)?;
    exchange_jwt_bearer(token_url, assertion, client_id, scope, http).await
}

/// Inner request logic. Private so the only production entry is `jwt_bearer`, which
/// runs `require_https` first. Tests call this directly against mock HTTP endpoints.
#[cfg(feature = "jwt-bearer")]
pub(crate) async fn exchange_jwt_bearer(
    token_url: &str,
    assertion: &str,
    client_id: Option<&str>,
    scope: Option<&str>,
    http: &reqwest::Client,
) -> Result<TokenResponse> {
    require_https(token_url)?;
    let base = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", assertion),
    ];
    let client_id_entry = client_id.map(|id| ("client_id", id));
    let scope_entry = scope.map(|s| ("scope", s));
    let params: Vec<(&str, &str)> = base
        .into_iter()
        .chain(client_id_entry)
        .chain(scope_entry)
        .collect();

    let resp = http
        .post(token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| DaemonError::Provider(format!("token request failed: {}", e)))?;

    if resp.status().is_redirection() {
        return Err(DaemonError::Provider(format!(
            "unexpected redirect {} from token endpoint",
            resp.status()
        )));
    }

    let status = resp.status();
    let body = zeroize::Zeroizing::new(
        read_bounded_body(resp)
            .await
            .map_err(|e| DaemonError::Provider(e.to_string()))?,
    );

    if status.is_success() {
        let raw: RawToken = serde_json::from_str(&body)
            .map_err(|e| DaemonError::Provider(format!("malformed token response: {}", e)))?;
        return Ok(TokenResponse {
            access_token: raw.access_token,
            id_token: raw.id_token,
            refresh_token: raw.refresh_token,
            expires_in: raw.expires_in.unwrap_or(DEFAULT_EXPIRES_IN_SECS),
            token_type: raw.token_type.unwrap_or_else(|| "Bearer".to_string()),
            scope: raw.scope,
        });
    }

    let parsed_err: Option<OAuthError> = serde_json::from_str(&body).ok();
    let code = parsed_err.as_ref().map(|e| e.error.as_str()).unwrap_or("");
    let detail = parsed_err
        .as_ref()
        .and_then(|e| e.error_description.as_deref())
        .unwrap_or("");

    match code {
        "invalid_client" => Err(DaemonError::ReauthRequired(format!(
            "invalid_client: {}",
            detail
        ))),
        _ => Err(DaemonError::Provider(format!(
            "token endpoint returned {}: {}",
            status, detail
        ))),
    }
}

/// Redeem a refresh token for a fresh access token.
pub async fn refresh(
    client: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
) -> std::result::Result<TokenResponse, TokenError> {
    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ];
    post_token(client, token_endpoint, &params).await
}

async fn post_token(
    client: &reqwest::Client,
    token_endpoint: &str,
    params: &[(&str, &str)],
) -> std::result::Result<TokenResponse, TokenError> {
    let resp = client
        .post(token_endpoint)
        .form(params)
        .send()
        .await
        .map_err(|e| TokenError::Transient(format!("token request failed: {}", e)))?;

    let status = resp.status();
    // Stream up to the cap, then reject: `.text()` would accept whatever the peer chose to
    // send, so a slow or hostile endpoint could pin memory even inside the request timeout.
    // Wrapped in `Zeroizing`: the body carries the refresh_token on success and echoes it in
    // the AS error path when the server rejects the redemption.
    let body = zeroize::Zeroizing::new(read_bounded_body(resp).await?);

    if status.is_success() {
        let raw: RawToken = serde_json::from_str(&body)
            .map_err(|e| TokenError::Transient(format!("malformed token response: {}", e)))?;
        return Ok(TokenResponse {
            access_token: raw.access_token,
            id_token: raw.id_token,
            refresh_token: raw.refresh_token,
            // RFC 6749 §5.1 makes `expires_in` RECOMMENDED, not REQUIRED. Defaulting it to 0
            // made "lifetime unknown" indistinguishable from "already expired", which the
            // stale-cache guard in `renew` then reads as "demand a browser login" — for a
            // refresh that had just returned a perfectly usable token. A short conservative
            // lifetime instead: the credential works, and the next renew re-checks soon.
            expires_in: raw.expires_in.unwrap_or(DEFAULT_EXPIRES_IN_SECS),
            token_type: raw.token_type.unwrap_or_else(|| "Bearer".to_string()),
            scope: raw.scope,
        });
    }

    // Parse the OAuth error to classify.
    let parsed: Option<OAuthError> = serde_json::from_str(&body).ok();
    let code = parsed.as_ref().map(|e| e.error.as_str()).unwrap_or("");
    let detail = parsed
        .as_ref()
        .and_then(|e| e.error_description.as_deref())
        .unwrap_or("");
    if is_terminal_oauth_error(code) {
        Err(TokenError::Terminal(format!("{}: {}", code, detail)))
    } else {
        Err(TokenError::Transient(format!(
            "token endpoint returned {}: {}",
            status, detail
        )))
    }
}

#[cfg(test)]
#[allow(
    clippy::panic_in_result_fn,
    reason = "assert_eq! in async test fns returning Result is idiomatic"
)]
mod tests {
    use super::*;
    use crate::error::DaemonError;
    use mockito::Matcher;

    // Allow HTTP for mock servers. Set once; only makes things more permissive (never less),
    // so concurrent tests that don't check HTTP enforcement are unaffected.
    fn allow_http() {
        static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            std::env::set_var("CREDSD_ALLOW_HTTP", "1");
        });
    }

    /// A DPoP proof the AS rejects means the key on disk is not the key the token was bound to.
    /// No retry fixes that, so it must be terminal — `Transient` surfaced as `Unavailable` and
    /// never offered the re-login that repairs the binding.
    /// The 6/12 interaction: a refresh returning no `expires_in` and no `id_token` used to seal
    /// `expires_at = now`, which the stale-cache guard then read as "already expired" and turned
    /// into a forced browser re-login — for a token that had just been refreshed. Assert on the
    /// parser output rather than a full round trip, since that is where the constant applies.
    #[test]
    fn a_missing_expires_in_defaults_to_a_short_lifetime_not_zero() {
        let raw = r#"{"access_token":"a","token_type":"Bearer"}"#;
        let body: RawToken = serde_json::from_str(raw).expect("parse");
        assert_eq!(
            body.expires_in.unwrap_or(DEFAULT_EXPIRES_IN_SECS),
            DEFAULT_EXPIRES_IN_SECS,
            "unwrap_or(0) would surface as a forced re-auth every renew"
        );
    }

    #[test]
    fn oauth_error_codes_split_terminal_from_transient() {
        for (code, terminal) in [
            ("invalid_grant", true),
            ("invalid_token", true),
            ("expired_token", true),
            ("temporarily_unavailable", false),
        ] {
            assert_eq!(
                is_terminal_oauth_error(code),
                terminal,
                "{code} classified wrongly"
            );
        }
    }

    #[test]
    fn parses_a_token_response() {
        let raw: RawToken = serde_json::from_str(
            r#"{"access_token":"jwt","refresh_token":"r","expires_in":3600,"token_type":"Bearer"}"#,
        )
        .unwrap();
        assert_eq!(raw.access_token, "jwt");
        assert_eq!(raw.refresh_token.as_deref(), Some("r"));
        assert_eq!(raw.expires_in, Some(3600));
    }

    #[test]
    fn missing_optional_fields_default() {
        let raw: RawToken = serde_json::from_str(r#"{"access_token":"jwt"}"#).unwrap();
        assert_eq!(raw.refresh_token, None);
        assert_eq!(raw.expires_in, None);
        assert_eq!(raw.token_type, None);
    }

    #[test]
    fn parses_an_oauth_error() {
        let e: OAuthError =
            serde_json::from_str(r#"{"error":"invalid_grant","error_description":"expired"}"#)
                .unwrap();
        assert_eq!(e.error, "invalid_grant");
        assert_eq!(e.error_description.as_deref(), Some("expired"));
    }

    /// Build a reqwest client that surfaces redirect responses rather than following them.
    /// Token endpoints never legitimately redirect; passing this client to tests that check
    /// 3xx handling: the redirect check inside client_credentials fires, not
    /// reqwest's built-in redirect logic.
    fn no_redirect_client() -> Result<reqwest::Client> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| DaemonError::Provider(format!("test client build: {}", e)))
    }

    #[test]
    fn require_https_accepts_https() {
        assert!(require_https("https://auth.example.com/token").is_ok());
    }

    #[test]
    fn require_https_rejects_http() {
        // This test must not run concurrently with allow_http() callers. Run it before any
        // async test sets CREDSD_ALLOW_HTTP, or run the suite with --test-threads=1.
        // In CI the var is absent at process start, so this runs correctly.
        if std::env::var("CREDSD_ALLOW_HTTP").is_ok() {
            // Another test set the var; skip rather than racing.
            return;
        }
        assert!(require_https("http://auth.example.com/token").is_err());
    }

    #[test]
    fn require_https_rejects_malformed_url() {
        assert!(require_https("not-a-url").is_err());
    }

    #[tokio::test]
    async fn redirect_disabled() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _m = server
            .mock("POST", "/token")
            .with_status(302)
            .with_header("location", &format!("{}/nowhere", base))
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let result = exchange_client_credentials(
            &format!("{}/token", base),
            "id",
            ClientCredentialsAuth::Secret("secret"),
            None,
            &client,
        )
        .await;
        assert!(matches!(result, Err(DaemonError::Provider(_))));
        _m.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn invalid_client_is_terminal() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _m = server
            .mock("POST", "/token")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"invalid_client","error_description":"unknown client"}"#)
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let result = exchange_client_credentials(
            &format!("{}/token", base),
            "bad-id",
            ClientCredentialsAuth::Secret("bad-secret"),
            None,
            &client,
        )
        .await;
        assert!(matches!(result, Err(DaemonError::ReauthRequired(_))));
        _m.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn successful_exchange() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _m = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"test_at","token_type":"Bearer","expires_in":3600}"#)
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let token = exchange_client_credentials(
            &format!("{}/token", base),
            "id",
            ClientCredentialsAuth::Secret("secret"),
            None,
            &client,
        )
        .await?;
        assert_eq!(token.access_token, "test_at");
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, 3600);
        _m.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn scope_included_when_some() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        // Mock only matches when scope= appears in the form body; if the parameter
        // were omitted the mock would not fire and mockito would return 501.
        let _m = server
            .mock("POST", "/token")
            .match_body(Matcher::Regex("scope=openid".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"scoped_at","token_type":"Bearer","expires_in":900}"#)
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let token = exchange_client_credentials(
            &format!("{}/token", base),
            "id",
            ClientCredentialsAuth::Secret("secret"),
            Some("openid"),
            &client,
        )
        .await?;
        assert_eq!(token.access_token, "scoped_at");
        _m.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn scope_omitted_when_none() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        // Exact body match: the form must contain only grant_type. If scope were
        // appended the match would fail and mockito would respond 501, causing an Err.
        let _m = server
            .mock("POST", "/token")
            .match_body(Matcher::Exact("grant_type=client_credentials".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"no_scope_at","token_type":"Bearer","expires_in":900}"#)
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let token = exchange_client_credentials(
            &format!("{}/token", base),
            "id",
            ClientCredentialsAuth::Secret("secret"),
            None,
            &client,
        )
        .await?;
        assert_eq!(token.access_token, "no_scope_at");
        _m.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn oversized_client_credentials_body_is_refused() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _m = server
            .mock("POST", "/token")
            .with_status(200)
            .with_body("x".repeat(MAX_TOKEN_BODY_BYTES.saturating_add(1)))
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let result = exchange_client_credentials(
            &format!("{}/token", base),
            "id",
            ClientCredentialsAuth::Secret("secret"),
            None,
            &client,
        )
        .await;
        assert!(
            matches!(&result, Err(DaemonError::Provider(m)) if m.contains("cap is")),
            "expected the body cap to refuse the response"
        );
        Ok(())
    }

    /// A chunked body advertises no length, so only the per-chunk cap can refuse it. The peer
    /// streams until the client hangs up: a buffer-then-check read never returns here, which the
    /// timeout turns into a failure rather than a hung test.
    #[cfg(feature = "jwt-bearer")]
    #[tokio::test]
    async fn endless_chunked_jwt_bearer_body_is_refused() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _m = server
            .mock("POST", "/token")
            .with_status(200)
            .with_chunked_body(|w| {
                let chunk = [b'x'; 1024];
                loop {
                    w.write_all(&chunk)?;
                }
            })
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            exchange_jwt_bearer(&format!("{}/token", base), "h.p.s", None, None, &client),
        )
        .await
        .map_err(|_| DaemonError::Provider("read did not stop at the cap".into()))?;
        assert!(
            matches!(&result, Err(DaemonError::Provider(m)) if m.contains("exceeded")),
            "expected the per-chunk cap to refuse the response"
        );
        Ok(())
    }

    // jwt_bearer HTTPS enforcement is covered by require_https_rejects_http (tests require_https directly).

    #[cfg(feature = "jwt-bearer")]
    #[tokio::test]
    async fn jwt_bearer_successful_exchange() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _m = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"jwt_at","token_type":"Bearer","expires_in":3600}"#)
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let token =
            exchange_jwt_bearer(&format!("{}/token", base), "h.p.s", None, None, &client).await?;
        assert_eq!(token.access_token, "jwt_at");
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, 3600);
        _m.assert_async().await;
        Ok(())
    }

    #[cfg(feature = "jwt-bearer")]
    #[tokio::test]
    async fn jwt_bearer_invalid_client_terminal() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _m = server
            .mock("POST", "/token")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"invalid_client","error_description":"bad assertion"}"#)
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let result =
            exchange_jwt_bearer(&format!("{}/token", base), "bad.jwt", None, None, &client).await;
        assert!(matches!(result, Err(DaemonError::ReauthRequired(_))));
        _m.assert_async().await;
        Ok(())
    }

    #[cfg(feature = "jwt-bearer")]
    #[tokio::test]
    async fn jwt_bearer_scope_forwarded() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _m = server
            .mock("POST", "/token")
            .match_body(Matcher::Regex("scope=openid".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"scoped_jwt_at","token_type":"Bearer","expires_in":900}"#)
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let token = exchange_jwt_bearer(
            &format!("{}/token", base),
            "h.p.s",
            None,
            Some("openid"),
            &client,
        )
        .await?;
        assert_eq!(token.access_token, "scoped_jwt_at");
        _m.assert_async().await;
        Ok(())
    }

    /// JWT-bearer sends the assertion in the body; no Authorization header is needed or correct.
    /// Strict IdPs reject Basic auth on this grant, so the absence is load-bearing, not cosmetic.
    /// The mock only fires when Authorization is absent; if the header were sent, mockito returns
    /// 501 and the test fails — the absence check is structural, not a post-hoc assertion.
    #[cfg(feature = "jwt-bearer")]
    #[tokio::test]
    async fn jwt_bearer_no_basic_auth() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _m = server
            .mock("POST", "/token")
            .match_header("Authorization", Matcher::Missing)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"no_auth_at","token_type":"Bearer","expires_in":3600}"#)
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let token =
            exchange_jwt_bearer(&format!("{}/token", base), "h.p.s", None, None, &client).await?;
        assert_eq!(token.access_token, "no_auth_at");
        _m.assert_async().await;
        Ok(())
    }

    /// Rotating the assertion (different jwt_v1 → jwt_v2) is picked up on the next call.
    /// If the assertion were cached, the jwt_v2 mock would never fire and the test fails.
    #[cfg(feature = "jwt-bearer")]
    #[tokio::test]
    async fn jwt_bearer_rotation_picked_up() -> Result<()> {
        allow_http();
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _m1 = server
            .mock("POST", "/token")
            .match_body(Matcher::Regex("assertion=jwt_v1".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"token_v1","token_type":"Bearer","expires_in":3600}"#)
            .create_async()
            .await;
        let _m2 = server
            .mock("POST", "/token")
            .match_body(Matcher::Regex("assertion=jwt_v2".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"token_v2","token_type":"Bearer","expires_in":3600}"#)
            .create_async()
            .await;
        let client = no_redirect_client()?;
        let r1 =
            exchange_jwt_bearer(&format!("{}/token", base), "jwt_v1", None, None, &client).await?;
        assert_eq!(r1.access_token, "token_v1");
        let r2 =
            exchange_jwt_bearer(&format!("{}/token", base), "jwt_v2", None, None, &client).await?;
        assert_eq!(r2.access_token, "token_v2");
        _m1.assert_async().await;
        _m2.assert_async().await;
        Ok(())
    }
}
