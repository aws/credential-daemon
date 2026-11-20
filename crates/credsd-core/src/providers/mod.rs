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
use crate::error::{DaemonError, Result};
use async_trait::async_trait;

/// An SDK failure as a record must name it: the service's own message where there is one, and
/// otherwise the error's source chain, which is the only place a failure with no service error —
/// an unreachable endpoint, a timeout, a response that would not parse — says what it was. A fixed
/// fallback string made all of those read as the operation name, so an unreachable STS and a
/// missing assignment audited identically, which `credential-retrieval-api` Req 17's "audited with
/// its reason" forbids.
///
/// Here rather than in one provider because the STS call the `aws-login` sign-in check and the
/// Identity Center audit lookup share is worded through it from both.
pub(crate) fn sdk_failure<E, R>(
    operation: &str,
    e: aws_sdk_sts::error::SdkError<E, R>,
) -> DaemonError
where
    E: aws_sdk_sts::error::ProvideErrorMetadata + std::error::Error + 'static,
    R: std::fmt::Debug,
{
    use aws_sdk_sts::error::DisplayErrorContext;
    match e.as_service_error().and_then(|service| service.message()) {
        Some(message) => DaemonError::provider(message),
        None => DaemonError::provider(format!("{operation} failed: {}", DisplayErrorContext(&e))),
    }
}

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

    /// The unattended renewal for another account and role of the same sign-in, or `None` for a
    /// source with no such choice. Only `aws-idc-sso` has one (credential-retrieval-api
    /// Requirement 17).
    fn role_renewer<'a>(
        &'a self,
        _account_id: &'a str,
        _role_name: &'a str,
    ) -> Option<Box<dyn Renewer + 'a>> {
        None
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_sts::error::{ConnectorError, ErrorMetadata, SdkError};

    /// `credential-retrieval-api` Req 17 requires an unresolved sign-in audited *with its reason*,
    /// and a failure with no service error has its reason in the source chain alone. A fixed
    /// fallback string made an unreachable STS and a missing role assignment read identically.
    #[test]
    fn a_failure_with_no_service_error_is_named_by_its_source_chain() {
        let unreachable: SdkError<ErrorMetadata, ()> = SdkError::dispatch_failure(
            ConnectorError::io(Box::new(std::io::Error::other("tcp connect refused"))),
        );
        let reason = sdk_failure("get_caller_identity", unreachable).to_string();
        assert!(
            reason.contains("get_caller_identity") && reason.contains("tcp connect refused"),
            "the transport failure names itself: {reason}"
        );

        let refused: SdkError<ErrorMetadata, ()> = SdkError::service_error(
            ErrorMetadata::builder()
                .message("No access to the role 'AdminAccess'")
                .build(),
            (),
        );
        let reason = sdk_failure("get_caller_identity", refused).to_string();
        assert!(
            reason.contains("No access to the role 'AdminAccess'"),
            "and a service error still speaks for itself: {reason}"
        );
    }
}
