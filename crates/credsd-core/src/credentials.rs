//! Credential data model and type discriminators.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Server-supplied `expires_in` values are clamped to this ceiling (12 hours).
///
/// The floor is intentionally absent from the reported expiry: a 30-second token clamped to
/// 60 seconds would be served for 30 seconds after it expires, causing 401s. If a minimum
/// refresh interval is needed, apply it in the scheduler, not here.
pub const MAX_EXPIRES_IN_SECS: i64 = 43_200;

/// An expiry `seconds` from now, without arithmetic that can panic.
///
/// chrono's `Add` panics on overflow in every build profile, so an expiry cannot be written as
/// `Utc::now() + Duration::seconds(n)` in code that must not crash — and `n` here comes from a
/// provider's `expires_in`, which is a value this process does not control.
///
/// An unrepresentable lifetime collapses to *now*, i.e. already expired, rather than saturating
/// at the far future. Both are wrong for a nonsense input, but only one is wrong safely: an
/// already-expired credential forces a refresh, while an eternal one would have every consumer
/// treat unusable material as valid forever.
pub fn expires_in_seconds(seconds: i64) -> DateTime<Utc> {
    let now = Utc::now();
    chrono::TimeDelta::try_seconds(seconds)
        .and_then(|delta| now.checked_add_signed(delta))
        .unwrap_or(now)
}

/// Discriminator for the kind of credential stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    AccessToken,
    SessionCredentials,
    /// A credential kind not recognised by this version.
    #[serde(other)]
    Unknown,
}

/// Payload variants holding the actual secret material.
///
/// Internally tagged on `type`, not `#[serde(untagged)]`: untagged picks a
/// variant by field shape, so a subset/superset payload can parse as the wrong
/// kind and an unknown variant yields an opaque error. For a secret-bearing type
/// that is fail-open. The `type` tag fails closed on any value it does not know
/// and matches the discriminator [`CredentialType`] already carries.
///
/// `ZeroizeOnDrop` scrubs the secret strings from memory when the last owner is
/// dropped, per the project invariant that secret-bearing types zeroize. The
/// non-secret `access_key` (an AWS key ID) is skipped so a partial derive isn't
/// required; only the true secrets need scrubbing, but zeroizing the whole
/// variant is simpler and harmless.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CredentialData {
    AccessToken {
        token: String,
    },
    SessionCredentials {
        access_key: String,
        secret_key: String,
        session_token: String,
    },
}

/// Hand-written, not derived: a derived `Debug` printed `secret_key`, `session_token`,
/// and `token` in the clear, so one `{:?}` on a `Credentials`, a provider error, or a
/// panic payload put live material in a log. The variant name is kept because the *kind*
/// of credential is not secret and is what makes a Debug line useful at all. Same
/// guarantee as [`SecretString`](crate::encryption::SecretString), reached differently
/// because this type must stay `Serialize` to be sealed to disk.
impl std::fmt::Debug for CredentialData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match self {
            Self::AccessToken { .. } => "AccessToken",
            Self::SessionCredentials { .. } => "SessionCredentials",
        };
        write!(f, "{variant}(<redacted>)")
    }
}

/// A resolved credential with expiration metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub credential_type: CredentialType,
    pub data: CredentialData,
    /// Absolute expiry, or `None` for a credential with no issuer-stated lifetime.
    ///
    /// `None` means *never expires*, not *unknown*: it is reachable only for a secret the
    /// user supplied with no expiry to declare, and it makes the credential servable
    /// indefinitely. Every source that federates or exchanges stamps `Some`, because its
    /// issuer states a lifetime. Treat a `None` here as a deliberate, auditable claim.
    pub expires_at: Option<DateTime<Utc>>,
}

impl Credentials {
    /// Session credentials always carry an absolute expiry: the issuer states one, so this
    /// takes a `DateTime` rather than an `Option` and the never-expires state is
    /// unrepresentable here.
    pub fn session(
        access_key: String,
        secret_key: String,
        session_token: String,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            credential_type: CredentialType::SessionCredentials,
            data: CredentialData::SessionCredentials {
                access_key,
                secret_key,
                session_token,
            },
            expires_at: Some(expires_at),
        }
    }

    /// `expires_at` is `None` only for a secret with no stated lifetime; see the field.
    pub fn access_token(token: String, expires_at: Option<DateTime<Utc>>) -> Self {
        Self {
            credential_type: CredentialType::AccessToken,
            data: CredentialData::AccessToken { token },
            expires_at,
        }
    }

    /// Whether the credential is past its stated expiry. A credential with no stated
    /// expiry is never expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|at| Utc::now() >= at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn expires_in_seconds_advances_the_clock() {
        let before = Utc::now();
        let expiry = expires_in_seconds(3600);
        assert!(expiry > before, "{expiry} must be after {before}");
        assert!(
            expiry.signed_duration_since(before) >= chrono::TimeDelta::seconds(3600),
            "{expiry}"
        );
    }

    /// The safety-relevant direction. A lifetime that cannot be represented must land on
    /// *already expired*, never on the far future: an eternal expiry would have every consumer
    /// treat unusable material as valid forever, while an expired one forces a refresh.
    #[test]
    fn an_unrepresentable_lifetime_expires_immediately() {
        // Literal shifts rather than a division: one of the two guards rejects each of these,
        // whether `TimeDelta::try_seconds` (its range is milliseconds in an i64) or
        // `checked_add_signed` (chrono's calendar ends in year 262143).
        for absurd in [i64::MAX, 1 << 62, 1 << 55] {
            let expiry = expires_in_seconds(absurd);
            assert!(
                expiry.signed_duration_since(Utc::now()) <= chrono::TimeDelta::seconds(1),
                "{absurd} produced {expiry}, which is not expired"
            );
        }
    }

    /// A negative lifetime is a credential that already expired; it must stay in the past rather
    /// than being clamped forward to now.
    #[test]
    fn a_negative_lifetime_stays_in_the_past() {
        assert!(expires_in_seconds(-60) < Utc::now());
    }

    /// `None` means *never expires*, so `is_expired` must read it as valid rather than as a
    /// missing value to be treated conservatively. Getting this backwards would make a
    /// no-expiry credential permanently unservable; getting `Some(past)` wrong would serve a
    /// dead one, so both directions are pinned here.
    #[test]
    fn an_absent_expiry_never_expires() {
        let never = Credentials::access_token("aoOiZmFrZS10b2tlbg".into(), None);
        assert!(!never.is_expired());

        let past =
            Credentials::access_token("aoOiZmFrZS10b2tlbg".into(), Some(expires_in_seconds(-60)));
        assert!(past.is_expired());

        let future =
            Credentials::access_token("aoOiZmFrZS10b2tlbg".into(), Some(expires_in_seconds(3600)));
        assert!(!future.is_expired());
    }

    /// Session credentials cannot be constructed without an expiry: the constructor takes a
    /// `DateTime`, so the never-expires state is unrepresentable for AWS material rather than
    /// merely discouraged.
    #[test]
    fn session_credentials_always_carry_an_expiry() {
        let creds = Credentials::session(
            "AKIAIOSFODNN7EXAMPLE".into(),
            "secret".into(),
            "token".into(),
            expires_in_seconds(900),
        );
        assert!(creds.expires_at.is_some());
    }

    #[test]
    fn zeroize_clears_session_secrets() {
        let mut data = CredentialData::SessionCredentials {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: "FwoGZXIvYXdzEBY".into(),
        };
        data.zeroize();
        match &data {
            CredentialData::SessionCredentials {
                access_key,
                secret_key,
                session_token,
            } => {
                assert!(secret_key.is_empty());
                assert!(session_token.is_empty());
                assert!(access_key.is_empty());
            }
            _ => panic!("variant changed under zeroize"),
        }
    }

    #[test]
    fn debug_does_not_leak_secret_material() {
        const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        const SESSION_TOKEN: &str = "FwoGZXIvYXdzEBYaDHNlY3JldA";
        const TOKEN: &str = "aoOiZmFrZS1zc28tdG9rZW4";

        let session = Credentials::session(
            "AKIAIOSFODNN7EXAMPLE".into(),
            SECRET_KEY.into(),
            SESSION_TOKEN.into(),
            Utc::now(),
        );
        let access_token = Credentials {
            credential_type: CredentialType::AccessToken,
            data: CredentialData::AccessToken {
                token: TOKEN.into(),
            },
            expires_at: Some(Utc::now()),
        };

        for rendered in [
            format!("{session:?}"),
            format!("{:?}", session.data),
            format!("{session:#?}"),
            format!("{access_token:?}"),
            format!("{access_token:#?}"),
        ] {
            for secret in [SECRET_KEY, SESSION_TOKEN, TOKEN] {
                assert!(!rendered.contains(secret), "{rendered}");
            }
            assert!(rendered.contains("<redacted>"), "{rendered}");
        }

        // The kind survives redaction: it is not secret, and it is the whole
        // reason a Debug line on this type is worth printing.
        assert!(format!("{session:?}").contains("SessionCredentials"));
        assert!(format!("{access_token:?}").contains("AccessToken"));
    }

    #[test]
    fn zeroize_clears_access_token() {
        let mut data = CredentialData::AccessToken {
            token: "super-secret-token".into(),
        };
        data.zeroize();
        match &data {
            CredentialData::AccessToken { token } => assert!(token.is_empty()),
            _ => panic!("variant changed under zeroize"),
        }
    }
}
