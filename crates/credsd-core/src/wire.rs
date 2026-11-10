//! Wire/protocol types shared across the daemon, the client, and the ephemeral proxy.
//!
//! These types are the contract between the credential server and every consumer of it —
//! the ECS-shaped credential body the AWS SDKs parse, the `credential_process` output, and
//! the `--agentic` self-report carried on the socket. They live here, in `credsd-core`,
//! rather than in the daemon so the client-side fetch path and the run-command proxy can
//! reference the *same* type the daemon serializes, without importing daemon (`server/`)
//! code. Reading a request header into a [`ClaimedIdentity`] is deliberately *not* here:
//! that step depends on axum and stays in the daemon.

use serde::{Deserialize, Serialize};

/// What the caller said about itself. Unverifiable, and therefore only ever used to
/// increase restriction — never to clear an observed positive.
///
/// Carried as the optional `claim` field of a JSON-RPC request rather than a header: its
/// presence is the assertion and its absence means unstated, so a caller cannot say "I am
/// not an agent". This type is transport-agnostic so both bins can name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimedIdentity {
    /// Caller passed `--agentic`.
    Agentic,
    Unstated,
    /// A claim not recognised by this version — treated as `Unstated`.
    Unknown,
}

/// ECS ContainerCredentialsProvider format — the primary SDK integration path.
///
/// One type, referenced everywhere it is constructed (the daemon routes, the run-command
/// proxy) and parsed (the client fetch path), so the ECS field-name contract with the AWS
/// SDKs cannot drift between a daemon copy and a client copy.
#[derive(Serialize, Deserialize)]
pub struct ContainerCredentialResponse {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "Expiration")]
    pub expiration: String,
}

/// Hand-written, not derived: a derived `Debug` printed `secret_access_key` and `token` in
/// the clear, so one `{:?}` on a response — in a log, a provider error, or a panic payload —
/// would put live credential material on disk. Mirrors the redaction on
/// [`CredentialData`](crate::credentials::CredentialData): the non-secret `access_key_id` is
/// kept because it is not a secret and is what makes a Debug line useful; everything else is
/// elided.
impl std::fmt::Debug for ContainerCredentialResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainerCredentialResponse")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("token", &"<redacted>")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// AWS credential_process output format (Version 1).
#[derive(Debug, Serialize)]
pub struct CredentialProcessOutput {
    #[serde(rename = "Version")]
    pub version: i32,
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "SessionToken")]
    pub session_token: String,
    #[serde(rename = "Expiration")]
    pub expiration: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The redaction contract: a `{:?}` on a response must never carry the secret key or
    /// the session token, while the non-secret access-key id and expiration survive so the
    /// line stays useful.
    #[test]
    fn debug_does_not_leak_secret_material() {
        const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        const TOKEN: &str = "FwoGZXIvYXdzEBYaDHNlY3JldA";
        let resp = ContainerCredentialResponse {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: SECRET_KEY.into(),
            token: TOKEN.into(),
            expiration: "2026-01-01T00:00:00Z".into(),
        };
        for rendered in [format!("{resp:?}"), format!("{resp:#?}")] {
            assert!(!rendered.contains(SECRET_KEY), "{rendered}");
            assert!(!rendered.contains(TOKEN), "{rendered}");
            assert!(rendered.contains("<redacted>"), "{rendered}");
            assert!(rendered.contains("AKIAIOSFODNN7EXAMPLE"), "{rendered}");
        }
    }
}
