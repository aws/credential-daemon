//! Shared credential status check used by the JSON-RPC `credential/list` / `profile/describe`
//! handlers. Status is computed daemon-side against the per-uid tree; the client obtains it over
//! the RPC rather than opening storage locally.

use crate::encryption::EncryptionService;
use crate::rpc::SessionStatus;

/// Inspect the on-disk token under an explicit data directory and classify its session. The
/// single source of truth for a credential's status, so the [`SessionStatus`] variants can never
/// disagree about what "expiring" or "corrupt" means. Used by the daemon dispatch layer, which
/// stores tokens at `callers/<uid>/credentials/<name>/`.
/// `declared_expiry` is the expiry a source records in `credentials.toml` rather than inside its
/// sealed material. Only `static-secret` has one: an opaque secret states no lifetime, so the
/// user's declaration is the only expiry there is, and it is not in the file this function reads.
/// Every other source carries its expiry in the material and passes `None`.
pub fn credential_session_status_at(
    data_dir: &std::path::Path,
    enc: Option<&EncryptionService>,
    declared_expiry: Option<chrono::DateTime<chrono::Utc>>,
) -> SessionStatus {
    // A `jwt` source's material is the token, sealed as a bare JWT rather than as a JSON record
    // with an `expires_at` — so its status is read from the JWT's own `exp`, not by the SSO path
    // below. Probed first only because the two files never coexist; either answers alone.
    let jwt_path = data_dir.join("jwt.enc");
    if jwt_path.exists() {
        return jwt_session_status(&jwt_path, enc);
    }
    // A `static-secret` source seals an opaque secret with no lifetime inside it, so status
    // cannot be read from the file the way `jwt.enc` is. Presence means bootstrapped, and the
    // expiry — if the user declared one — arrives as `declared_expiry` because it lives in
    // `credentials.toml`. Graded through the same `classify` every other source uses, so
    // "expiring" means one thing across the surface; no declaration means never expires.
    let static_secret_path = data_dir.join(crate::providers::static_secret::SECRET_FILE);
    if static_secret_path.exists() {
        if enc.is_none() {
            return SessionStatus::Unknown;
        }
        return match declared_expiry {
            Some(at) => classify(at.signed_duration_since(chrono::Utc::now())),
            None => SessionStatus::Active,
        };
    }
    // OAuth provider writes `oauth_token.enc`; its JSON also carries `expires_at` so the same
    // decoder applies.
    let oauth_path = data_dir.join("oauth_token.enc");
    if oauth_path.exists() {
        return credential_session_status_impl(&oauth_path, enc);
    }
    // IAM-user provider persists an MFA-minted session as `iam_session.enc`; its JSON is a
    // serialised `Credentials` that carries `expires_at` at the top level, so the same decoder
    // applies.  Probed before the permanent key-pair file so an expired session still shows
    // `Expired` rather than the key-pair's static `Active`.
    let iam_session_path = data_dir.join("iam_session.enc");
    if iam_session_path.exists() {
        return credential_session_status_impl(&iam_session_path, enc);
    }
    // The long-term key pair (`iam_user.enc`) carries no expiry — it is a permanent AKIA key.
    // Its presence means the credential was bootstrapped; non-MFA keys self-renew on demand.
    let iam_user_path = data_dir.join("iam_user.enc");
    if iam_user_path.exists() {
        return match enc {
            Some(_) => SessionStatus::Active,
            None => SessionStatus::Unknown,
        };
    }
    // Probed before the `sso_token.enc` fallback, which would otherwise answer "no session" for a
    // live aws-login.
    let aws_login_path = data_dir.join(crate::providers::aws_login::TOKEN_FILE);
    if aws_login_path.exists() {
        return aws_login_session_status(&aws_login_path, enc);
    }
    let token_path = data_dir.join("sso_token.enc");
    credential_session_status_impl(&token_path, enc)
}

/// Classify a sealed bare JWT by its `exp` claim, using the same thresholds as every other
/// source so "expiring" means one thing across the whole surface.
fn jwt_session_status(
    jwt_path: &std::path::Path,
    enc: Option<&EncryptionService>,
) -> SessionStatus {
    let Some(enc) = enc else {
        return SessionStatus::Unknown;
    };
    let Ok(jwt) = enc.open_from_file(jwt_path) else {
        return SessionStatus::DecryptFailed;
    };
    let Ok(jwt) = std::str::from_utf8(&jwt) else {
        return SessionStatus::Corrupt;
    };
    let Ok(expires_at) = crate::providers::jwt::exp_of(jwt) else {
        return SessionStatus::Corrupt;
    };
    classify(expires_at.signed_duration_since(chrono::Utc::now()))
}

fn credential_session_status_impl(
    token_path: &std::path::Path,
    enc: Option<&EncryptionService>,
) -> SessionStatus {
    if !token_path.exists() {
        return SessionStatus::NoSession;
    }

    #[derive(serde::Deserialize)]
    struct TokenExpiry {
        expires_at: String,
    }
    let token = match open_json::<TokenExpiry>(token_path, enc) {
        Ok(token) => token,
        Err(status) => return status,
    };

    let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(&token.expires_at) else {
        return SessionStatus::Corrupt;
    };

    classify(expires_at.signed_duration_since(chrono::Utc::now()))
}

/// aws-login is graded on its refresh token, not its session. credsd renews the 15-minute session
/// on use, so the session clock says nothing about whether the user must act. The refresh token
/// does: the provider empties it when the IdP rejects a refresh, and only then is sign-in needed.
fn aws_login_session_status(
    token_path: &std::path::Path,
    enc: Option<&EncryptionService>,
) -> SessionStatus {
    #[derive(serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    struct RefreshToken {
        refresh_token: String,
    }
    match open_json::<RefreshToken>(token_path, enc) {
        Ok(token) if token.refresh_token.is_empty() => SessionStatus::SignInRequired,
        Ok(_) => SessionStatus::Active,
        Err(status) => status,
    }
}

/// Open a sealed JSON record, mapping each way that can fail to the status it means.
fn open_json<T: serde::de::DeserializeOwned>(
    path: &std::path::Path,
    enc: Option<&EncryptionService>,
) -> Result<T, SessionStatus> {
    let Some(enc) = enc else {
        return Err(SessionStatus::Unknown);
    };
    let decrypted = match enc.open_from_file(path) {
        Ok(d) => d,
        Err(crate::error::DaemonError::Io(_)) => return Err(SessionStatus::Unreadable),
        Err(_) => return Err(SessionStatus::DecryptFailed),
    };
    serde_json::from_slice(&decrypted).map_err(|_| SessionStatus::Corrupt)
}

/// The one place the refresh window is defined: at 15 minutes remaining a credential is still
/// `Expiring`, and only past that is it `Active`. Shared by every source so the word means the
/// same thing whatever the material is.
fn classify(remaining: chrono::TimeDelta) -> SessionStatus {
    if remaining <= chrono::TimeDelta::zero() {
        SessionStatus::Expired
    } else if remaining <= chrono::TimeDelta::minutes(15) {
        SessionStatus::Expiring
    } else {
        SessionStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_key;
    use tempfile::tempdir;

    fn make_enc() -> EncryptionService {
        EncryptionService::new(generate_key().unwrap()).unwrap()
    }

    fn write_token(
        dir: &std::path::Path,
        filename: &str,
        expires_at: &str,
        enc: &EncryptionService,
    ) {
        let json = format!(
            r#"{{"expires_at":"{}","access_token":"tok","token_type":"Bearer"}}"#,
            expires_at
        );
        enc.seal_to_file(&dir.join(filename), json.as_bytes())
            .unwrap();
    }

    fn seal_static_secret(dir: &std::path::Path, enc: &EncryptionService) {
        crate::providers::static_secret::persist_secret(
            enc,
            dir,
            &zeroize::Zeroizing::new("sk-status-check".to_owned()),
        )
        .expect("seal");
    }

    /// A secret with no declared expiry never expires, so presence alone is `Active`. Reporting
    /// anything else would make a perfectly good credential look broken.
    #[test]
    fn a_static_secret_without_a_declared_expiry_is_active() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        seal_static_secret(dir.path(), &enc);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Active
        );
    }

    /// A declared expiry is graded through the same thresholds every other source uses, so
    /// `creds list` agrees with what a fetch will do. Without this a secret the user declared
    /// dead reads `Active` while `get` refuses it.
    #[test]
    fn a_static_secret_is_graded_against_its_declared_expiry() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        seal_static_secret(dir.path(), &enc);

        let past = chrono::Utc::now() - chrono::TimeDelta::minutes(1);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), Some(past)),
            SessionStatus::Expired
        );

        let soon = chrono::Utc::now() + chrono::TimeDelta::minutes(5);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), Some(soon)),
            SessionStatus::Expiring
        );

        let later = chrono::Utc::now() + chrono::TimeDelta::hours(6);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), Some(later)),
            SessionStatus::Active
        );
    }

    #[test]
    fn oauth_token_expires_in_future_is_active() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        write_token(dir.path(), "oauth_token.enc", "9999-12-30T00:00:00Z", &enc);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Active
        );
    }
    #[test]
    fn oauth_token_expired() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        write_token(dir.path(), "oauth_token.enc", "2002-02-10T00:00:00Z", &enc);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Expired
        );
    }

    #[test]
    fn oauth_no_token_file_present() {
        let dir = tempdir().unwrap();
        assert_eq!(
            credential_session_status_at(dir.path(), None, None),
            SessionStatus::NoSession
        );
    }

    fn write_aws_login(
        dir: &std::path::Path,
        expires_at: &str,
        refresh_token: &str,
        enc: &EncryptionService,
    ) {
        let json = format!(
            r#"{{"access_key_id":"AK","secret_access_key":"SK","session_token":"ST","refresh_token":"{refresh_token}","expires_at":"{expires_at}"}}"#
        );
        enc.seal_to_file(
            &dir.join(crate::providers::aws_login::TOKEN_FILE),
            json.as_bytes(),
        )
        .unwrap();
    }

    /// aws-login writes `aws_login_token.enc`, not `oauth_token.enc`. A live login must read as
    /// active, not as "no session".
    #[test]
    fn aws_login_live_token_is_active() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        write_aws_login(dir.path(), "9999-12-30T00:00:00Z", "r", &enc);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Active
        );
    }

    /// The 15-minute session is renewed by credsd on use, so its clock is not a status. A session
    /// due in 900 seconds is a healthy login, not an expiring one.
    #[test]
    fn aws_login_session_due_in_900s_is_active() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        let due = chrono::Utc::now() + chrono::TimeDelta::seconds(900);
        write_aws_login(dir.path(), &due.to_rfc3339(), "r", &enc);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Active
        );
    }

    proptest::proptest! {
        /// Whatever the session clock says, a live refresh token keeps the login Active. A lapsed
        /// session between uses is not the user's problem to fix.
        #[test]
        fn aws_login_status_ignores_the_session_clock(
            offset_secs in -10_000_000i64..10_000_000,
        ) {
            let dir = tempdir().unwrap();
            let enc = make_enc();
            let at = chrono::Utc::now()
                .checked_add_signed(chrono::TimeDelta::seconds(offset_secs))
                .unwrap();
            write_aws_login(dir.path(), &at.to_rfc3339(), "r", &enc);
            proptest::prop_assert_eq!(
                credential_session_status_at(dir.path(), Some(&enc), None),
                SessionStatus::Active
            );
        }
    }

    /// An emptied refresh token is what a rejected refresh leaves behind. The login needs a browser
    /// sign-in whatever the session clock says, so a live session does not hide it.
    #[test]
    fn aws_login_with_rejected_refresh_reads_sign_in_required() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        write_aws_login(dir.path(), "9999-12-30T00:00:00Z", "", &enc);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::SignInRequired
        );
    }

    #[test]
    fn aws_login_undecodable_payload_reads_corrupt() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        enc.seal_to_file(&dir.path().join("aws_login_token.enc"), b"not json")
            .unwrap();
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Corrupt
        );
    }

    /// The boundaries are exact: at 15 minutes remaining the credential is still `Expiring`, one
    /// millisecond later it is `Active`, and zero or below is `Expired`. Truncating to whole
    /// minutes read 15m59s as `Expiring`.
    #[test]
    fn classify_boundaries_are_exact() {
        use chrono::TimeDelta;
        assert_eq!(
            classify(TimeDelta::milliseconds(-1)),
            SessionStatus::Expired
        );
        assert_eq!(classify(TimeDelta::zero()), SessionStatus::Expired);
        assert_eq!(
            classify(TimeDelta::milliseconds(1)),
            SessionStatus::Expiring
        );
        assert_eq!(classify(TimeDelta::minutes(15)), SessionStatus::Expiring);
        assert_eq!(
            classify(TimeDelta::minutes(15) + TimeDelta::milliseconds(1)),
            SessionStatus::Active
        );
    }

    #[test]
    fn oauth_token_file_empty_is_decrypt_failed() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        std::fs::write(dir.path().join("oauth_token.enc"), "").unwrap();
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::DecryptFailed
        );
    }

    #[test]
    fn has_both_sso_and_oauth_enc_files_oauth_wins() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        write_token(dir.path(), "oauth_token.enc", "9999-12-30T00:00:00Z", &enc);
        write_token(dir.path(), "sso_token.enc", "2002-02-10T00:00:00Z", &enc); // expired
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Active
        )
    }

    fn write_iam_session(dir: &std::path::Path, expires_at: &str, enc: &EncryptionService) {
        // `iam_session.enc` is a serialised `Credentials` struct; only `expires_at` matters for
        // status classification.
        let json = format!(
            r#"{{"credential_type":"session_credentials","data":{{"type":"session_credentials","access_key":"AK","secret_key":"SK","session_token":"TOK"}},"expires_at":"{}"}}"#,
            expires_at
        );
        enc.seal_to_file(&dir.join("iam_session.enc"), json.as_bytes())
            .unwrap();
    }

    fn write_iam_user_key(dir: &std::path::Path, enc: &EncryptionService) {
        let json = br#"{"access_key_id":"AKIAEXAMPLE","secret_access_key":"secret"}"#;
        enc.seal_to_file(&dir.join("iam_user.enc"), json).unwrap();
    }

    #[test]
    fn iam_user_key_file_present_is_active() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        write_iam_user_key(dir.path(), &enc);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Active
        );
    }

    #[test]
    fn iam_user_key_file_present_without_enc_is_unknown() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        write_iam_user_key(dir.path(), &enc);
        assert_eq!(
            credential_session_status_at(dir.path(), None, None),
            SessionStatus::Unknown
        );
    }

    #[test]
    fn iam_session_active() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        write_iam_session(dir.path(), "9999-12-30T00:00:00Z", &enc);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Active
        );
    }

    #[test]
    fn iam_session_expired() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        write_iam_session(dir.path(), "2002-02-10T00:00:00Z", &enc);
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Expired
        );
    }

    #[test]
    fn iam_session_wins_over_iam_user_key() {
        let dir = tempdir().unwrap();
        let enc = make_enc();
        write_iam_session(dir.path(), "2002-02-10T00:00:00Z", &enc); // expired session
        write_iam_user_key(dir.path(), &enc); // permanent key present
        assert_eq!(
            credential_session_status_at(dir.path(), Some(&enc), None),
            SessionStatus::Expired // session expiry takes priority over key presence
        );
    }
}
