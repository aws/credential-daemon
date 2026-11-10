//! A bearer JWT held on credsd's behalf and served as the credential itself.
//!
//! The source for an API that authenticates with a JWT and has no OAuth flow to run: a CI-issued
//! OIDC token, a Kubernetes projected service-account token, an IdP token minted out of band.
//! Nothing is exchanged and nothing is federated — the credential *is* the token, so this provider
//! is the seal, the expiry, and the serving, and no more.
//!
//! The JWT lives sealed in `jwt.enc` under the credential's data dir, the convention every other
//! provider's secret follows (`sso_token.enc`, `iam_user.enc`, `oauth_token.enc`). Its expiry is
//! the token's own `exp` claim: the issuer already stated the lifetime, and a second lifetime
//! invented here could only disagree with it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::config::JwtConfig;
use crate::credentials::Credentials;
use crate::encryption::EncryptionService;
use crate::error::{DaemonError, Result};
use crate::providers::{CredentialProvider, Renewed, Renewer};

const TOKEN_FILE: &str = "jwt.enc";

/// Seal a JWT as the credential's material. Bootstrap is the only writer — re-running it is how a
/// credential whose token expired gets a fresh one, since nothing in this provider can mint one.
pub fn persist_token(
    encryption: &EncryptionService,
    data_dir: &Path,
    jwt: &Zeroizing<String>,
) -> Result<()> {
    // Reject before sealing, not at first use: a JWT with no readable `exp` would seal fine and
    // then serve as a credential with an unknowable lifetime. The caller still has the input in
    // hand here and can say which file was wrong.
    let exp = exp_of(jwt)?;
    check_not_expired(exp, chrono::Utc::now(), "JWT")?;
    encryption.seal_to_file(&data_dir.join(TOKEN_FILE), jwt.as_bytes())
}

/// Refuse a credential whose `exp` is not after `now`. Shared by every JWT-shaped bootstrap, and
/// pure so the boundary is testable at any instant; the caller supplies the clock.
pub(crate) fn check_not_expired(
    exp: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    what: &str,
) -> Result<()> {
    if exp <= now {
        return Err(DaemonError::provider(format!(
            "{what} expired at {exp}; mint a new one and bootstrap again"
        )));
    }
    Ok(())
}

/// The command that seals a fresh token for `credential`, named by every message that reports
/// there is none to serve — the daemon's login handler included, since re-bootstrap is the only
/// writer.
///
pub fn reseal_command(credential: &str) -> String {
    format!("creds bootstrap --env <env> --credential {credential} jwt --token-file <path>")
}

/// The `exp` (Unix seconds) claim of a JWT, as the local expiry.
///
/// The signature is NOT verified: credsd is not the audience — whoever receives the token
/// validates it — and this only decodes the middle segment to learn when to stop serving.
pub fn exp_of(jwt: &str) -> Result<DateTime<Utc>> {
    let mut parts = jwt.split('.');
    let (Some(_header), Some(payload_b64), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(DaemonError::provider(
            "malformed JWT: expected header.payload.signature",
        ));
    };
    let payload = URL_SAFE_NO_PAD
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

pub struct JwtProvider {
    credential_name: String,
    #[expect(
        dead_code,
        reason = "env_var is materialised by the client; the provider needs only the sealed token, \
                  and holding the config keeps this constructor identical to every other provider's"
    )]
    config: JwtConfig,
    encryption: Arc<EncryptionService>,
    data_dir: PathBuf,
}

impl JwtProvider {
    pub fn new(
        credential_name: String,
        config: JwtConfig,
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

impl CredentialProvider for JwtProvider {
    // Renewable, in the trait's sense: serving the sealed token needs no human. What renewal
    // cannot do is produce a *new* token — so an expired one is an error naming the re-seal, not a
    // `ReauthRequired`, which would advertise an interactive flow this source does not have.
    fn renewer(&self) -> Option<&dyn Renewer> {
        Some(self)
    }

    fn mode_name(&self) -> &'static str {
        "jwt"
    }
}

#[async_trait]
impl Renewer for JwtProvider {
    async fn renew(&self) -> Result<Renewed> {
        let plaintext = self
            .encryption
            .open_from_file(&self.data_dir.join(TOKEN_FILE))
            .map_err(|e| {
                DaemonError::provider(format!(
                    "no usable JWT for credential '{}': {}. Seal one with '{}'.",
                    self.credential_name,
                    e,
                    reseal_command(&self.credential_name)
                ))
            })?;
        let jwt = Zeroizing::new(String::from_utf8(plaintext.to_vec()).map_err(|_| {
            DaemonError::provider(format!(
                "sealed JWT for credential '{}' is not valid UTF-8",
                self.credential_name
            ))
        })?);

        let expires_at = exp_of(&jwt)?;
        if Utc::now() >= expires_at {
            // Deliberately an error rather than `Renewed::Ready` with a past expiry: the store
            // would cache it, re-ask on every miss, and never say why. The message names the one
            // action that fixes it.
            return Err(DaemonError::provider(format!(
                "the JWT sealed for credential '{}' expired at {}; seal a fresh one with '{}'",
                self.credential_name,
                expires_at,
                reseal_command(&self.credential_name)
            )));
        }
        Ok(Renewed::Ready(Credentials::access_token(
            jwt.to_string(),
            Some(expires_at),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialData;
    use crate::encryption::generate_key;
    use proptest::prelude::*;
    use tempfile::tempdir;

    fn provider(config: JwtConfig) -> (JwtProvider, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let enc = Arc::new(
            EncryptionService::new(generate_key().expect("key")).expect("encryption service"),
        );
        (
            JwtProvider::new("gh".into(), config, enc, dir.path().to_path_buf()),
            dir,
        )
    }

    fn config() -> JwtConfig {
        JwtConfig {
            env_var: Some("GITHUB_TOKEN".into()),
            identity_type: Default::default(),
        }
    }

    /// A JWT with the given `exp`; header and signature are throwaway (never verified).
    fn jwt_with_exp(exp: Option<i64>) -> String {
        let b64 = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
        let claims = match exp {
            Some(e) => format!("{{\"sub\":\"u\",\"exp\":{}}}", e),
            None => "{\"sub\":\"u\"}".to_string(),
        };
        format!(
            "{}.{}.{}",
            b64(b"{\"alg\":\"RS256\"}"),
            b64(claims.as_bytes()),
            b64(b"sig")
        )
    }

    #[tokio::test]
    async fn a_sealed_token_is_served_with_its_own_expiry() {
        let (p, _d) = provider(config());
        let jwt = Zeroizing::new(jwt_with_exp(Some(4_100_000_000)));
        persist_token(&p.encryption, &p.data_dir, &jwt).expect("seal");

        match p.renew().await.expect("renew") {
            Renewed::Ready(creds) => {
                assert_eq!(
                    creds.expires_at.expect("jwt stamps an exp").timestamp(),
                    4_100_000_000
                );
                match &creds.data {
                    CredentialData::AccessToken { token } => assert_eq!(token, jwt.as_str()),
                    other => panic!("expected an access token, got {:?}", other),
                }
            }
            other => panic!("expected ready credentials, got {:?}", other),
        }
    }

    /// The two ways this source has no credential to serve, and why neither is `ReauthRequired`:
    /// there is no interactive flow to offer. Both must name the re-bootstrap instead, or the
    /// operator is told only that something is unavailable — and naming `creds login` would be
    /// worse than saying nothing, since that command has nothing to run for this source.
    #[tokio::test]
    async fn nothing_sealed_and_expired_both_name_the_reseal() {
        let (p, _d) = provider(config());
        let never_sealed = p.renew().await.expect_err("no token on disk");
        assert!(
            never_sealed.to_string().contains("creds bootstrap"),
            "{never_sealed}"
        );

        // Sealed directly: persist refuses an expired token, and this models one that expired
        // after bootstrap sealed it, which is the case serving must still refuse.
        p.encryption
            .seal_to_file(
                &p.data_dir.join(TOKEN_FILE),
                jwt_with_exp(Some(1)).as_bytes(), // 1970
            )
            .expect("seal");
        let expired = p.renew().await.expect_err("expired token");
        assert!(expired.to_string().contains("expired"), "{expired}");
        assert!(expired.to_string().contains("creds bootstrap"), "{expired}");
    }

    /// Sealing validates first: a token whose lifetime cannot be read must be refused while the
    /// caller still knows which input it came from, not at the next `creds get`.
    #[test]
    fn an_unreadable_expiry_is_refused_at_seal_time() {
        let (p, _d) = provider(config());
        for bad in [jwt_with_exp(None), "not-a-jwt".into(), "a.b".into()] {
            assert!(
                persist_token(&p.encryption, &p.data_dir, &Zeroizing::new(bad.clone())).is_err(),
                "sealed a JWT with no usable exp: {bad}"
            );
        }
    }

    /// The edges themselves, which uniform sampling over an i64 range essentially never lands on:
    /// chrono's last representable second is accepted, and the next one is refused.
    #[test]
    fn exp_of_boundary_is_chronos_own() {
        let max = DateTime::<Utc>::MAX_UTC.timestamp();
        let min = DateTime::<Utc>::MIN_UTC.timestamp();
        assert!(exp_of(&jwt_with_exp(Some(max))).is_ok());
        assert!(exp_of(&jwt_with_exp(Some(min))).is_ok());
        assert!(exp_of(&jwt_with_exp(Some(max.saturating_add(1)))).is_err());
        assert!(exp_of(&jwt_with_exp(Some(min.saturating_sub(1)))).is_err());
        // The value that exposed the old, calendar-guessed bound: year ~11476 is representable.
        assert!(exp_of(&jwt_with_exp(Some(300_000_000_000))).is_ok());
    }

    proptest! {
        /// `exp_of` parses attacker-controlled bytes — the token comes from a file credsd was
        /// pointed at — so no input may panic, and no unreadable input may yield an expiry. The
        /// never-crash lint denies the panicking constructs; this covers the arithmetic and
        /// slicing the lint cannot see into.
        #[test]
        fn exp_of_never_panics(jwt in ".{0,300}") {
            let _ = exp_of(&jwt);
        }

        /// A well-formed JWT's `exp` is read back exactly, for every representable instant —
        /// including the negative (pre-1970) and far-future values a hostile issuer can state.
        /// The bounds are chrono's own, not a calendar guess: it represents years far past 9999.
        #[test]
        fn exp_of_round_trips_representable_instants(
            exp in DateTime::<Utc>::MIN_UTC.timestamp()..=DateTime::<Utc>::MAX_UTC.timestamp()
        ) {
            let parsed = exp_of(&jwt_with_exp(Some(exp))).expect("well-formed JWT");
            prop_assert_eq!(parsed.timestamp(), exp);
        }

        /// Out-of-range `exp` values are refused rather than saturating: a clamped far-future
        /// expiry would make an unusable token look valid forever.
        #[test]
        fn exp_of_refuses_unrepresentable_instants(
            exp in prop_oneof![
                i64::MIN..DateTime::<Utc>::MIN_UTC.timestamp(),
                DateTime::<Utc>::MAX_UTC.timestamp().saturating_add(1)..=i64::MAX,
            ]
        ) {
            prop_assert!(exp_of(&jwt_with_exp(Some(exp))).is_err());
        }

        /// A payload that is valid base64url but not JSON claims is a parse error, never an
        /// expiry — the case that separates "decoded" from "understood".
        #[test]
        fn a_non_claims_payload_is_an_error(payload in "[a-z]{1,40}") {
            let jwt = format!(
                "{}.{}.{}",
                URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\"}"),
                URL_SAFE_NO_PAD.encode(payload.as_bytes()),
                URL_SAFE_NO_PAD.encode(b"sig")
            );
            prop_assert!(exp_of(&jwt).is_err());
        }
    }
}
