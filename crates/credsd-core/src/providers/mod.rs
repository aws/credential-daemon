//! Credential provider trait and implementations.

pub mod aws_login;
pub mod client_credentials;
pub mod iam_user;
pub mod jwt;
#[cfg(feature = "jwt-bearer")]
pub mod jwt_bearer;
pub mod oauth;
pub mod roles_anywhere;
pub mod sso;
pub mod static_secret;

use crate::credentials::Credentials;
use crate::error::Result;
use async_trait::async_trait;

/// A credential source and its renewal capability.
///
/// The daemon renews credentials from two positions the trait must keep apart: the
/// background refresh loop and an on-demand cache miss, both *unattended*, and the
/// foreground setup command, which may run an *interactive* auth process (device-code,
/// MFA, a pasted key). Sources differ in whether the unattended positions can renew at
/// all:
///
/// - **Renewable** — a fresh credential is obtainable without a human. The provider
///   returns a [`Renewer`] from [`renewer`](CredentialProvider::renewer); the store renews
///   it in the background and on a miss. SSO (refresh-token grant) and a brokered IAM key
///   (re-mint) are both renewable.
/// - **Re-auth-only** — the only path to a new credential is the provider's full auth
///   process, so every renewal must go through it. The provider returns `None`; the store
///   never renews it unattended, and a miss surfaces a re-auth error instead of silently
///   launching an interactive flow.
///
/// The interactive process itself is deliberately absent from this trait: its inputs and
/// outputs are provider-specific (SSO selects an account/role; a key source reads a
/// secret), so it lives in `bootstrap`, not behind a shared signature.
pub trait CredentialProvider: Send + Sync {
    /// The unattended renewal capability, or `None` for a re-auth-only source.
    fn renewer(&self) -> Option<&dyn Renewer>;

    fn mode_name(&self) -> &'static str;
}

/// Unattended credential renewal: an "unattended renewer". A provider implements this only
/// when it can produce a fresh credential with **no user interaction** — that is what makes
/// it safe for the background loop and on-demand misses to call. Providers whose only path
/// to a new credential is an interactive auth flow do not implement it.
#[async_trait]
pub trait Renewer: Send + Sync {
    async fn renew(&self) -> Result<Renewed>;
}

/// Outcome of an unattended renewal.
///
/// Three-valued on purpose: a `Renewer` can succeed, *or* discover that its unattended path
/// is exhausted and only an interactive re-auth can proceed. That second case is not an
/// error — nothing failed — so it is a distinct `Ok` variant, not `Err`. `Err` stays
/// reserved for transient failures the caller should retry (network, throttling).
///
#[derive(Debug)]
pub enum Renewed {
    /// Fresh credentials, ready to serve and cache.
    Ready(Credentials),
    /// The unattended path is spent (SSO refresh token expired, MFA session lapsed); a human
    /// must re-authenticate. The provider says *what input that takes* via [`ReauthInput`], so
    /// a consumer can prompt correctly without knowing which provider it is talking to.
    ReauthRequired(ReauthInput),
}

/// What the provider needs from the user to re-authenticate. The producing provider chooses
/// the variant — this is the "type needed from the user", defined at the source rather than
/// inferred by the caller. It enumerates *interaction shapes* (not provider kinds), so a new
/// provider usually reuses one; a genuinely new interaction is the only reason to extend it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ReauthInput {
    /// The provider drives an out-of-band flow (e.g. SSO device authorization in a browser);
    /// nothing is typed at the terminal.
    Browser,
    /// The user must enter a code read off a device (MFA TOTP). `label` names what to prompt.
    Code { label: String },
}

impl ReauthInput {
    /// Stable tag for structured logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Code { .. } => "code",
        }
    }
}
