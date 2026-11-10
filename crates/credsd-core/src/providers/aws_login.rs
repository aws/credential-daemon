//! AWS Sign-In login (`aws login`): the same-device OAuth2 authorization-code + PKCE flow with
//! DPoP that the AWS CLI runs. The token endpoint returns raw AWS credentials, so there is no STS
//! call. Client id and User-Agent are the AWS CLI's; Sign-In may refuse them from another client.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::AwsLoginConfig;
use crate::credentials::Credentials;
use crate::encryption::EncryptionService;
use crate::error::{DaemonError, Result};
use crate::log::escape_log;
use crate::providers::oauth::callback::{self, CallbackServer, CALLBACK_TIMEOUT};
use crate::providers::oauth::dpop::DpopSigner;
use crate::providers::oauth::{http_client, pkce, urlencode, PendingLogin};
use crate::providers::{CredentialProvider, ReauthInput, Renewed, Renewer};

pub(crate) const TOKEN_FILE: &str = "aws_login_token.enc";
/// Sign-In's two registered devtools clients — the service accepts no other value. Which one is
/// sent decides which redirect URI Sign-In will honour, so the pair is never mixed.
const CLIENT_ID_SAME_DEVICE: &str = "arn:aws:signin:::devtools/same-device";
const CLIENT_ID_CROSS_DEVICE: &str = "arn:aws:signin:::devtools/cross-device";
const USER_AGENT: &str = "aws-cli/2.15.0";
const REDIRECT_PATH: &str = "/oauth/callback";
/// Sign-In's own page for the cross-device flow. It shows the authorization result instead of
/// redirecting to a port on a machine the browser cannot reach.
const CONFIRMATION_PATH: &str = "/v1/sessions/confirmation";
const TOKEN_BODY_LIMIT: usize = 64 * 1024;
/// Refresh once this little life is left. Matches the AWS CLI's lazy-refresh window.
const REFRESH_THRESHOLD: Duration = Duration::minutes(5);

/// Cached session credentials and the refresh token, sealed at rest. Secrets zeroize on drop.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct CachedAwsLogin {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    refresh_token: String,
    #[zeroize(skip)]
    expires_at: String,
}

impl CachedAwsLogin {
    fn from_output(out: TokenOutput) -> Self {
        Self {
            access_key_id: out.access_token.access_key_id,
            secret_access_key: out.access_token.secret_access_key,
            session_token: out.access_token.session_token,
            refresh_token: out.refresh_token,
            expires_at: crate::credentials::expires_in_seconds(
                out.expires_in.min(crate::credentials::MAX_EXPIRES_IN_SECS),
            )
            .to_rfc3339(),
        }
    }

    fn expires_at(&self) -> Result<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.expires_at)
            .map(|e| e.with_timezone(&Utc))
            .map_err(|e| DaemonError::provider(format!("invalid token expires_at: {e}")))
    }

    fn credentials(&self) -> Result<Credentials> {
        Ok(Credentials::session(
            self.access_key_id.clone(),
            self.secret_access_key.clone(),
            self.session_token.clone(),
            self.expires_at()?,
        ))
    }
}

/// The token endpoint's success body (`tokenOutput`).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenOutput {
    access_token: SessionCredentials,
    refresh_token: String,
    expires_in: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: Option<String>,
}

/// `Reauth` means only a browser login can help; `Failed` is transient or unexpected.
enum TokenError {
    Reauth(String),
    Failed(String),
}

fn classify_error(code: String) -> TokenError {
    match code.as_str() {
        "AUTHCODE_EXPIRED" | "TOKEN_EXPIRED" | "USER_CREDENTIALS_CHANGED" => {
            TokenError::Reauth(code)
        }
        _ => TokenError::Failed(format!("token endpoint returned {code}")),
    }
}

/// The region becomes the host of every token request, so only DNS-label characters may pass.
/// Anything else (`#`, `/`, `@`, `:`) could redirect the authorization code and refresh token.
fn valid_region(region: &str) -> bool {
    !region.is_empty()
        && region.len() <= 32
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn authorize_url(
    base: &str,
    client_id: &str,
    state: &str,
    redirect_uri: &str,
    challenge: &str,
) -> String {
    format!(
        "{base}/v1/authorize?response_type=code&client_id={}&state={}&code_challenge_method=SHA-256&scope=openid&redirect_uri={}&code_challenge={challenge}",
        urlencode(client_id),
        urlencode(state),
        urlencode(redirect_uri),
    )
}

/// Read the authorization code out of what the cross-device confirmation page shows the user:
/// base64 of the same `code=…&state=…` query string a loopback redirect would have carried.
///
/// The `state` check is what makes a hand-carried result as trustworthy as a redirect — it is the
/// only evidence the paste answers *this* login and not one a third party started — so it is
/// compared constant-time and a mismatch fails closed, exactly as in [`CallbackServer::wait`].
fn code_from_paste(paste: &str, expected_state: &str) -> Result<Zeroizing<String>> {
    // Whitespace stripped throughout, not just trimmed: the value is carried between two machines
    // by hand, so a terminal may have line-wrapped it, and that is not something the user can see
    // to correct.
    let stripped = Zeroizing::new(
        paste
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    );
    let decoded = Zeroizing::new(base64_decode(&stripped).ok_or_else(|| {
        DaemonError::provider(
            "that is not the value Sign-In displayed; copy the whole code from the browser",
        )
    })?);
    let query = Zeroizing::new(String::from_utf8(decoded.to_vec()).map_err(|_| {
        DaemonError::provider("the pasted Sign-In code did not decode to readable text")
    })?);
    let callback = callback::parse_query(&query);

    // State before anything else the paste claims. Until it matches, the value is just a string
    // the user was handed by something, so neither its code nor its error text has standing.
    if !callback
        .state
        .as_deref()
        .is_some_and(|state| callback::state_matches(state, expected_state))
    {
        return Err(DaemonError::provider(
            "the pasted Sign-In code belongs to a different login; start over",
        ));
    }
    if let Some(error) = callback.error {
        return Err(DaemonError::provider(match callback.error_description {
            Some(description) => format!(
                "the identity provider rejected the login: {}: {}",
                crate::log::escape_log(&error),
                crate::log::escape_log(&description)
            ),
            None => format!(
                "the identity provider rejected the login: {}",
                crate::log::escape_log(&error)
            ),
        }));
    }
    callback
        .code
        .filter(|code| !code.is_empty())
        .map(Zeroizing::new)
        .ok_or_else(|| {
            DaemonError::provider("the pasted Sign-In code carried no authorization code")
        })
}

/// base64-decode accepting either alphabet and either padding. Sign-In's confirmation page is the
/// only producer, but which of the four forms it emits is not something this code can pin down,
/// and a decode that rejects three of them reads to the user as "the code you copied is wrong".
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, NO_PAD};
    const ANY_PAD: GeneralPurposeConfig =
        NO_PAD.with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);
    const STANDARD: GeneralPurpose = GeneralPurpose::new(&base64::alphabet::STANDARD, ANY_PAD);
    const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&base64::alphabet::URL_SAFE, ANY_PAD);
    STANDARD.decode(s).or_else(|_| URL_SAFE.decode(s)).ok()
}

/// A login whose authorization URL is built but whose result the user must carry back by hand.
///
/// Holds the PKCE verifier and the DPoP key, so it must not be logged, serialized, or sent over
/// the wire — only [`authorize_url`](Self::authorize_url) is safe to disclose.
pub struct PendingRemoteLogin {
    pkce: pkce::Pkce,
    /// `Zeroizing` because the CSRF gate lives across the wait for the paste; a copy in dropped
    /// memory is exactly the window worth scrubbing. Matches `pkce::Pkce`.
    state: Zeroizing<String>,
    dpop: DpopSigner,
    redirect_uri: String,
    authorize_url: String,
}

impl PendingRemoteLogin {
    /// The URL the user must visit, on whichever machine has a browser. Public by design: it
    /// carries the PKCE *challenge*, never the verifier, so disclosing it does not let a third
    /// party redeem the code.
    pub fn authorize_url(&self) -> &str {
        &self.authorize_url
    }
}

/// A token that is already expired would be served as a live credential, so a zero or negative
/// lifetime is a broken response, not a session.
fn lifetime_checked(out: TokenOutput) -> std::result::Result<TokenOutput, TokenError> {
    if out.expires_in > 0 {
        Ok(out)
    } else {
        Err(TokenError::Failed(
            "token response lifetime is not positive".into(),
        ))
    }
}

async fn post_token(
    http: &reqwest::Client,
    token_url: &str,
    dpop: &DpopSigner,
    body: serde_json::Value,
) -> std::result::Result<TokenOutput, TokenError> {
    let proof = dpop
        .sign("POST", token_url, None, None)
        .map_err(|e| TokenError::Failed(e.to_string()))?;
    let resp = http
        .post(token_url)
        .header("DPoP", proof)
        .header("User-Agent", USER_AGENT)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&body).map_err(|e| TokenError::Failed(e.to_string()))?)
        .send()
        .await
        .map_err(|e| TokenError::Failed(format!("token request failed: {e}")))?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| TokenError::Failed(format!("token response unreadable: {e}")))?;
    if bytes.len() > TOKEN_BODY_LIMIT {
        return Err(TokenError::Failed(
            "token response exceeds size limit".into(),
        ));
    }
    if status.is_success() {
        return serde_json::from_slice(&bytes)
            .map_err(|e| TokenError::Failed(format!("unreadable token response: {e}")))
            .and_then(lifetime_checked);
    }
    let code = serde_json::from_slice::<ErrorBody>(&bytes)
        .ok()
        .and_then(|b| b.error)
        .unwrap_or_else(|| status.to_string());
    Err(classify_error(code))
}

pub struct AwsLoginProvider {
    credential_name: String,
    config: AwsLoginConfig,
    encryption: Arc<EncryptionService>,
    data_dir: PathBuf,
    http: reqwest::Client,
    /// `https://{region}.signin.aws.amazon.com`. A field, not derived per call, so tests can point
    /// the token endpoint at a local mock.
    base_url: String,
}

impl AwsLoginProvider {
    pub fn new(
        credential_name: String,
        config: AwsLoginConfig,
        encryption: Arc<EncryptionService>,
        data_dir: PathBuf,
    ) -> Result<Self> {
        let region = config.region.as_str();
        if !valid_region(region) {
            return Err(DaemonError::provider("invalid aws-login region"));
        }
        // Checked here rather than at bootstrap so a hand-edited `credentials.toml` cannot reach
        // a login either: a remote flow binds no listener, so a port alongside it names a
        // redirect URI nothing will ever use, and silently dropping it would hide the mistake.
        if config.remote && config.callback_port.is_some() {
            return Err(DaemonError::provider(
                "aws-login cannot set both callback_port and remote: a remote login binds no \
                 loopback listener",
            ));
        }
        let base_url = format!("https://{region}.signin.aws.amazon.com");
        Ok(Self {
            credential_name,
            config,
            encryption,
            data_dir,
            http: http_client()?,
            base_url,
        })
    }

    fn persist_token(&self, token: &CachedAwsLogin) -> Result<()> {
        let json = Zeroizing::new(serde_json::to_vec(token)?);
        self.encryption
            .seal_to_file(&self.data_dir.join(TOKEN_FILE), &json)
    }

    fn load_token(&self) -> Result<CachedAwsLogin> {
        let plaintext = self
            .encryption
            .open_from_file(&self.data_dir.join(TOKEN_FILE))
            .map_err(|e| {
                DaemonError::provider(format!(
                    "no usable login for credential '{}': {e}",
                    self.credential_name
                ))
            })?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Which devtools client this credential logs in as. Fixes the redirect URI too: Sign-In
    /// honours a loopback redirect only for `same-device` and its confirmation page only for
    /// `cross-device`.
    fn client_id(&self) -> &'static str {
        if self.config.remote {
            CLIENT_ID_CROSS_DEVICE
        } else {
            CLIENT_ID_SAME_DEVICE
        }
    }

    /// Bind the loopback listener and build the authorization URL. The DPoP key is generated
    /// here and sealed only once the token it binds is written, as in `aws-web-identity`.
    pub fn begin_interactive_login(&self) -> Result<PendingLogin> {
        let pkce = pkce::Pkce::generate()?;
        let state = Zeroizing::new(pkce::random_token(32)?);
        let server = match self.config.callback_port {
            Some(port) => CallbackServer::bind_port(port)?,
            None => CallbackServer::bind()?,
        };
        let redirect_uri = server.redirect_uri(REDIRECT_PATH);
        let authorize_url = authorize_url(
            &self.base_url,
            self.client_id(),
            &state,
            &redirect_uri,
            &pkce.challenge,
        );
        Ok(PendingLogin {
            server,
            pkce,
            state,
            dpop: Some(DpopSigner::generate_unsealed()?),
            redirect_uri,
            authorize_url,
        })
    }

    /// Build the authorization URL for a cross-device login. No listener is bound: the browser is
    /// on another machine and could not reach one, so Sign-In redirects to its own confirmation
    /// page and the user carries the result back to
    /// [`finish_remote_login`](Self::finish_remote_login).
    pub fn begin_remote_login(&self) -> Result<PendingRemoteLogin> {
        let pkce = pkce::Pkce::generate()?;
        let state = Zeroizing::new(pkce::random_token(32)?);
        let redirect_uri = format!("{}{CONFIRMATION_PATH}", self.base_url);
        let authorize_url = authorize_url(
            &self.base_url,
            self.client_id(),
            &state,
            &redirect_uri,
            &pkce.challenge,
        );
        Ok(PendingRemoteLogin {
            pkce,
            state,
            dpop: DpopSigner::generate_unsealed()?,
            redirect_uri,
            authorize_url,
        })
    }

    /// Exchange the result the user carried back from the browser. `paste` is the value Sign-In's
    /// confirmation page displayed, verbatim.
    pub async fn finish_remote_login(
        &self,
        pending: PendingRemoteLogin,
        paste: &str,
    ) -> Result<()> {
        let PendingRemoteLogin {
            pkce,
            state,
            dpop,
            redirect_uri,
            authorize_url: _,
        } = pending;
        let code = code_from_paste(paste, &state)?;
        self.exchange_code(&dpop, code.as_str(), &pkce, &redirect_uri)
            .await
    }

    pub async fn finish_interactive_login(&self, pending: PendingLogin) -> Result<()> {
        let PendingLogin {
            server,
            pkce,
            state,
            dpop,
            redirect_uri,
            authorize_url: _,
        } = pending;
        let dpop = dpop.ok_or_else(|| DaemonError::provider("aws-login requires a DPoP key"))?;

        let code =
            tokio::task::spawn_blocking(move || server.wait(state.as_str(), CALLBACK_TIMEOUT))
                .await
                .map_err(|e| DaemonError::provider(format!("callback task failed: {e}")))??;

        self.exchange_code(&dpop, code.as_str(), &pkce, &redirect_uri)
            .await
    }

    /// Redeem an authorization code and persist what it buys. `redirect_uri` must be the one the
    /// authorization request carried, whichever flow produced the code.
    async fn exchange_code(
        &self,
        dpop: &DpopSigner,
        code: &str,
        pkce: &pkce::Pkce,
        redirect_uri: &str,
    ) -> Result<()> {
        let token_url = format!("{}/v1/token", self.base_url);
        let out = post_token(
            &self.http,
            &token_url,
            dpop,
            serde_json::json!({
                "client_id": self.client_id(),
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": pkce.verifier,
                "redirect_uri": redirect_uri,
            }),
        )
        .await
        .map_err(|e| match e {
            TokenError::Reauth(m) | TokenError::Failed(m) => {
                DaemonError::provider(format!("token exchange failed: {m}"))
            }
        })?;

        // Token before key, as in `aws-web-identity`: a newer token with a stale key fails its next
        // refresh and offers re-login; the reverse leaves nothing to refresh with.
        self.persist_token(&CachedAwsLogin::from_output(out))?;
        dpop.seal(&self.encryption, &self.data_dir)?;
        info!(credential = %self.credential_name, "aws login successful");
        Ok(())
    }
}

impl CredentialProvider for AwsLoginProvider {
    fn renewer(&self) -> Option<&dyn Renewer> {
        Some(self)
    }

    fn mode_name(&self) -> &'static str {
        "aws-login"
    }
}

#[async_trait]
impl Renewer for AwsLoginProvider {
    async fn renew(&self) -> Result<Renewed> {
        let Ok(cached) = self.load_token() else {
            return Ok(Renewed::ReauthRequired(ReauthInput::Browser));
        };
        if cached.expires_at()?.signed_duration_since(Utc::now()) > REFRESH_THRESHOLD {
            return Ok(Renewed::Ready(cached.credentials()?));
        }
        // An emptied refresh token is the recorded rejection. There is nothing to redeem.
        if cached.refresh_token.is_empty() {
            return Ok(Renewed::ReauthRequired(ReauthInput::Browser));
        }

        // An unreadable key is the same class as an unreadable token: only a fresh login repairs it.
        let Ok(dpop) = DpopSigner::from_encrypted(&self.encryption, &self.data_dir) else {
            warn!(credential = %self.credential_name, "DPoP key unusable, re-login required");
            return Ok(Renewed::ReauthRequired(ReauthInput::Browser));
        };

        let token_url = format!("{}/v1/token", self.base_url);
        match post_token(
            &self.http,
            &token_url,
            &dpop,
            serde_json::json!({
                "client_id": self.client_id(),
                "grant_type": "refresh_token",
                "refresh_token": cached.refresh_token,
            }),
        )
        .await
        {
            Ok(out) => {
                let fresh = CachedAwsLogin::from_output(out);
                // The server has already retired the old refresh token. Failing here would drop
                // the rotated one, so keep serving from memory and let the warning say what to fix.
                if let Err(e) = self.persist_token(&fresh) {
                    warn!(credential = %self.credential_name, error = %escape_log(&e), "rotated aws login token not saved");
                }
                info!(credential = %self.credential_name, "aws login token refreshed");
                Ok(Renewed::Ready(fresh.credentials()?))
            }
            Err(TokenError::Reauth(m)) => {
                // Record the rejection where status reads it: the sealed token keeps its session
                // and loses the refresh token, which status grades as sign-in required.
                let mut rejected = cached;
                rejected.refresh_token.zeroize();
                if let Err(e) = self.persist_token(&rejected) {
                    warn!(credential = %self.credential_name, error = %escape_log(&e), "aws login rejection not saved");
                }
                warn!(credential = %self.credential_name, reason = %escape_log(&m), "aws login refresh rejected, re-login required");
                Ok(Renewed::ReauthRequired(ReauthInput::Browser))
            }
            Err(TokenError::Failed(m)) => Err(DaemonError::provider(format!(
                "aws login refresh failed: {m}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_url_carries_challenge_and_no_verifier() {
        let url = authorize_url(
            "https://us-east-1.signin.aws.amazon.com",
            CLIENT_ID_SAME_DEVICE,
            "st",
            "http://127.0.0.1:5000/oauth/callback",
            "CHALLENGE",
        );
        assert!(url.starts_with("https://us-east-1.signin.aws.amazon.com/v1/authorize?"));
        assert!(url.contains("code_challenge_method=SHA-256"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Foauth%2Fcallback"));
        assert!(url.ends_with("&code_challenge=CHALLENGE"));
        assert!(!url.contains("code_verifier"));
    }

    fn provider(config: &str) -> AwsLoginProvider {
        AwsLoginProvider::new(
            "test".into(),
            serde_json::from_str(config).unwrap(),
            Arc::new(EncryptionService::new(crate::encryption::generate_key().unwrap()).unwrap()),
            std::path::PathBuf::from("/nonexistent"),
        )
        .unwrap()
    }

    /// The client id picks which redirect URI Sign-In will honour, so the two must move together:
    /// a cross-device client sent with a loopback redirect, or the reverse, is rejected by the
    /// service and reads to the user as a broken login.
    #[test]
    fn remote_login_advertises_the_cross_device_client_and_confirmation_page() {
        let remote = provider(r#"{"region":"us-east-1","remote":true}"#)
            .begin_remote_login()
            .unwrap();
        assert!(remote
            .authorize_url()
            .contains("client_id=arn%3Aaws%3Asignin%3A%3A%3Adevtools%2Fcross-device"));
        assert_eq!(
            remote.redirect_uri,
            "https://us-east-1.signin.aws.amazon.com/v1/sessions/confirmation"
        );

        let same = provider(r#"{"region":"us-east-1"}"#)
            .begin_interactive_login()
            .unwrap();
        assert!(same
            .authorize_url()
            .contains("client_id=arn%3Aaws%3Asignin%3A%3A%3Adevtools%2Fsame-device"));
    }

    /// Only the `state` Sign-In echoed proves the paste answers this login. Everything else a
    /// user could paste — another login's result, a truncated copy, an outright forgery — must
    /// fail closed rather than redeem a code against our PKCE verifier.
    #[test]
    fn a_paste_is_accepted_only_for_its_own_state() {
        let encode = |q: &str| base64::engine::general_purpose::STANDARD.encode(q);

        let good = encode("code=abc123&state=st");
        assert_eq!(code_from_paste(&good, "st").unwrap().as_str(), "abc123");
        // Browsers and shells readily add surrounding whitespace to a copied value.
        assert!(code_from_paste(&format!("  {good}\n"), "st").is_ok());

        assert!(code_from_paste(&good, "other").is_err());
        assert!(code_from_paste(&encode("code=abc123"), "st").is_err());
        assert!(code_from_paste(&encode("state=st"), "st").is_err());
        assert!(code_from_paste(&encode("state=&code=c"), "st").is_err());
        assert!(code_from_paste(&encode("code=&state=st"), "st").is_err());
        assert!(code_from_paste("not base64 at all", "st").is_err());
        assert!(code_from_paste("", "st").is_err());
    }

    /// A rejection arrives in the paste the same way it would in a redirect (RFC 6749 §4.1.2.1).
    /// Reporting it beats telling the user their code was invalid.
    #[test]
    fn a_rejection_in_the_paste_reports_its_cause() {
        let paste = base64::engine::general_purpose::STANDARD
            .encode("error=access_denied&error_description=user+said+no&state=st");
        let err = code_from_paste(&paste, "st").unwrap_err().to_string();
        assert!(err.contains("access_denied"), "{err}");
        assert!(err.contains("user said no"), "{err}");
    }

    proptest::proptest! {
        /// No arbitrary string may yield a code: without a matching `state` there is no evidence
        /// the value came from the login we started.
        #[test]
        fn arbitrary_pastes_never_yield_a_code(paste in ".*") {
            proptest::prop_assert!(code_from_paste(&paste, "the-expected-state").is_err());
        }

        /// The accept path, over every code and state the service could pick and all four base64
        /// forms the value could arrive in. Pairs with the negative property above: on its own,
        /// a decoder that rejected everything would satisfy that one.
        #[test]
        fn a_well_formed_paste_in_any_base64_form_yields_its_code(
            code in "[A-Za-z0-9._~-]{1,64}",
            state in "[A-Za-z0-9]{1,64}",
            url_safe: bool,
            padded: bool,
        ) {
            use base64::alphabet;
            use base64::engine::general_purpose::{GeneralPurpose, NO_PAD, PAD};
            let alphabet = if url_safe { &alphabet::URL_SAFE } else { &alphabet::STANDARD };
            let engine = GeneralPurpose::new(alphabet, if padded { PAD } else { NO_PAD });
            let paste = engine.encode(format!("code={code}&state={state}"));
            proptest::prop_assert_eq!(
                code_from_paste(&paste, &state).map(|c| c.to_string()).ok(),
                Some(code)
            );
        }
    }

    /// The guard lives in the constructor, so it fires on a hand-edited `credentials.toml` at
    /// load time and not only on the bootstrap RPC that clap already blocks.
    #[test]
    fn a_remote_credential_may_not_also_fix_a_callback_port() {
        let build = |config: &str| {
            AwsLoginProvider::new(
                "test".into(),
                serde_json::from_str(config).unwrap(),
                Arc::new(
                    EncryptionService::new(crate::encryption::generate_key().unwrap()).unwrap(),
                ),
                std::path::PathBuf::from("/nonexistent"),
            )
        };
        assert!(build(r#"{"region":"us-east-1","remote":true,"callback_port":5000}"#).is_err());
        assert!(build(r#"{"region":"us-east-1","remote":true}"#).is_ok());
        assert!(build(r#"{"region":"us-east-1","callback_port":5000}"#).is_ok());
    }

    #[test]
    fn token_response_parses_raw_credentials_and_sets_expiry() {
        let body = r#"{"accessToken":{"accessKeyId":"AKIA","secretAccessKey":"s","sessionToken":"t"},
            "refreshToken":"r2","expiresIn":900,"tokenType":"Bearer"}"#;
        let out: TokenOutput = serde_json::from_str(body).unwrap();
        let cached = CachedAwsLogin::from_output(out);
        assert_eq!(cached.access_key_id, "AKIA");
        assert_eq!(cached.refresh_token, "r2");
        let life = cached
            .expires_at()
            .unwrap()
            .signed_duration_since(Utc::now());
        assert!(life > Duration::seconds(890) && life <= Duration::seconds(900));
    }

    #[test]
    fn non_positive_lifetime_is_rejected() {
        for expires_in in [0, -1, i64::MIN] {
            let out = TokenOutput {
                access_token: SessionCredentials {
                    access_key_id: "A".into(),
                    secret_access_key: "s".into(),
                    session_token: "t".into(),
                },
                refresh_token: "r".into(),
                expires_in,
            };
            assert!(matches!(lifetime_checked(out), Err(TokenError::Failed(_))));
        }
    }

    /// A region that could alter the token host must never reach `new`. The property covers any
    /// string an RPC or a hand-edited file could carry; the table names the characters that matter.
    #[test]
    fn region_cannot_change_the_token_host() {
        for hostile in [
            "evil.example#",
            "x/?",
            "a@evil.example",
            "us-east-1:443",
            "a.b",
            "US-EAST-1",
            "",
        ] {
            assert!(!valid_region(hostile), "{hostile:?}");
        }
        assert!(valid_region("us-gov-west-1"));
    }

    proptest::proptest! {
        #[test]
        fn accepted_region_is_a_bare_label(region in ".*") {
            if valid_region(&region) {
                proptest::prop_assert!(region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
            }
        }
    }

    /// The server names the lifetime, so a hostile or broken value must not pin a token in the
    /// cache past the ceiling SSO uses.
    #[test]
    fn server_expiry_is_clamped_to_the_ceiling() {
        let body = r#"{"accessToken":{"accessKeyId":"A","secretAccessKey":"s","sessionToken":"t"},
            "refreshToken":"r","expiresIn":9223372036854775807}"#;
        let cached = CachedAwsLogin::from_output(serde_json::from_str(body).unwrap());
        let life = cached
            .expires_at()
            .unwrap()
            .signed_duration_since(Utc::now());
        assert!(life <= Duration::seconds(crate::credentials::MAX_EXPIRES_IN_SECS));
    }

    #[test]
    fn only_spent_session_codes_force_reauth() {
        for code in [
            "AUTHCODE_EXPIRED",
            "TOKEN_EXPIRED",
            "USER_CREDENTIALS_CHANGED",
        ] {
            assert!(matches!(classify_error(code.into()), TokenError::Reauth(_)));
        }
        for code in ["INSUFFICIENT_PERMISSIONS", "ServiceUnavailable"] {
            assert!(matches!(classify_error(code.into()), TokenError::Failed(_)));
        }
    }

    /// Renew against a local `/v1/token` mock. The request must be the snake_case refresh grant
    /// with a DPoP proof bound to that exact token URL, and the rotated refresh token must be the
    /// one persisted, or the next refresh would spend a token the server already retired.
    #[tokio::test]
    async fn renew_posts_refresh_grant_with_bound_dpop_and_persists_rotated_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let dir = tempfile::tempdir().unwrap();
        let encryption =
            Arc::new(EncryptionService::new(crate::encryption::generate_key().unwrap()).unwrap());
        DpopSigner::generate_unsealed()
            .unwrap()
            .seal(&encryption, dir.path())
            .unwrap();

        let mut server = mockito::Server::new_async().await;
        let captured = Arc::new(std::sync::Mutex::new(None));
        let sink = Arc::clone(&captured);
        let mock = server
            .mock("POST", "/v1/token")
            .with_body_from_request(move |req| {
                let proof = req.header("DPoP").first().map(|v| v.to_str().unwrap().to_owned());
                *sink.lock().unwrap() = Some((proof, req.body().unwrap().clone()));
                br#"{"accessToken":{"accessKeyId":"AKIA2","secretAccessKey":"s2","sessionToken":"t2"},
                    "refreshToken":"r2","expiresIn":900,"tokenType":"Bearer"}"#
                    .to_vec()
            })
            .create_async()
            .await;

        let config = serde_json::from_str(r#"{"region":"us-east-1"}"#).unwrap();
        let mut provider = AwsLoginProvider::new(
            "test".into(),
            config,
            Arc::clone(&encryption),
            dir.path().into(),
        )
        .unwrap();
        provider.base_url = server.url();
        provider.http = reqwest::Client::new();
        provider
            .persist_token(&CachedAwsLogin {
                access_key_id: "AKIA1".into(),
                secret_access_key: "s1".into(),
                session_token: "t1".into(),
                refresh_token: "r1".into(),
                expires_at: (Utc::now() + Duration::minutes(1)).to_rfc3339(),
            })
            .unwrap();

        let renewed = provider.renew().await.unwrap();
        assert!(matches!(renewed, Renewed::Ready(_)), "{renewed:?}");
        mock.assert_async().await;

        let (proof, body) = captured.lock().unwrap().take().unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "client_id": CLIENT_ID_SAME_DEVICE,
                "grant_type": "refresh_token",
                "refresh_token": "r1",
            })
        );

        let proof = proof.expect("DPoP header present");
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], format!("{}/v1/token", server.url()));

        assert_eq!(provider.load_token().unwrap().refresh_token, "r2");
    }

    /// A refresh the IdP rejects must read as sign-in required, and credsd must not spend a dead
    /// token again: the second renew returns without a request, which `expect(1)` enforces.
    #[tokio::test]
    async fn rejected_refresh_reads_sign_in_required_and_is_not_retried() {
        let dir = tempfile::tempdir().unwrap();
        let encryption =
            Arc::new(EncryptionService::new(crate::encryption::generate_key().unwrap()).unwrap());
        DpopSigner::generate_unsealed()
            .unwrap()
            .seal(&encryption, dir.path())
            .unwrap();

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v1/token")
            .with_status(400)
            .with_body(r#"{"error":"TOKEN_EXPIRED"}"#)
            .expect(1)
            .create_async()
            .await;

        let config = serde_json::from_str(r#"{"region":"us-east-1"}"#).unwrap();
        let mut provider = AwsLoginProvider::new(
            "test".into(),
            config,
            Arc::clone(&encryption),
            dir.path().into(),
        )
        .unwrap();
        provider.base_url = server.url();
        provider.http = reqwest::Client::new();
        provider
            .persist_token(&CachedAwsLogin {
                access_key_id: "AKIA1".into(),
                secret_access_key: "s1".into(),
                session_token: "t1".into(),
                refresh_token: "r1".into(),
                expires_at: (Utc::now() + Duration::minutes(1)).to_rfc3339(),
            })
            .unwrap();

        assert!(matches!(
            provider.renew().await.unwrap(),
            Renewed::ReauthRequired(_)
        ));
        assert_eq!(
            crate::credential_status::credential_session_status_at(
                dir.path(),
                Some(&encryption),
                None
            ),
            crate::rpc::SessionStatus::SignInRequired
        );
        assert!(matches!(
            provider.renew().await.unwrap(),
            Renewed::ReauthRequired(_)
        ));
        mock.assert_async().await;
    }
}
