//! Caller identity and authorization types for the Unix-domain-socket surface.
//!
//! These were the axum route handlers' shared types; the handlers themselves are gone with
//! the HTTP transport (Requirement 9 AC 3). The types stay because the JSON-RPC dispatcher
//! and the accept loop still resolve and carry a caller decision. Nothing here depends on a
//! transport.

/// Why a caller was refused, distinct so the deny log names the exact fail-closed branch
/// rather than collapsing them all to one message.
#[derive(Clone, Debug)]
pub enum DenyReason {
    /// No `callers/<uid>/owner` file — the caller was never provisioned (deny-by-absence).
    /// Run `creds bootstrap --env <name> <provider>` to provision this uid.
    NoRoot,
    /// `peer_cred()` returned `None` — the kernel did not supply a uid for this connection.
    /// Not a bootstrap problem; likely a platform or socket configuration issue.
    NoPeerCred,
    /// `owner` exists but `owner.trim() != getpwuid(uid).name` — either the uid was recycled
    /// to a different user since provisioning, the username changed, or the owner file was
    /// edited manually.
    OwnerMismatch,
    /// `getpwuid(uid)` returned `Ok(None)`: the uid has no passwd entry at all.
    UnknownUid,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRoot => write!(
                f,
                "not bootstrapped (run: creds bootstrap --env <name> <provider>)"
            ),
            Self::NoPeerCred => write!(f, "kernel did not supply a peer uid for this connection"),
            Self::OwnerMismatch => {
                write!(f, "owner file does not match the uid's current username")
            }
            Self::UnknownUid => write!(f, "uid has no passwd entry"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_reason_display_covers_all_variants() {
        assert_eq!(
            DenyReason::NoRoot.to_string(),
            "not bootstrapped (run: creds bootstrap --env <name> <provider>)"
        );
        assert_eq!(
            DenyReason::NoPeerCred.to_string(),
            "kernel did not supply a peer uid for this connection"
        );
        assert_eq!(
            DenyReason::OwnerMismatch.to_string(),
            "owner file does not match the uid's current username"
        );
        assert_eq!(
            DenyReason::UnknownUid.to_string(),
            "uid has no passwd entry"
        );
    }
}

/// The authorization outcome for a UDS connection, resolved once from the kernel-verified
/// caller uid. `Unresolved` is kept distinct from `Denied` so a transient NSS/LDAP lookup
/// failure (`getpwuid` errored) cannot read as a normal deny in the audit trail — both fail
/// closed, but for different reasons.
#[derive(Clone, Debug)]
pub enum CallerAuth {
    Authorized { uid: u32, root: std::path::PathBuf },
    Denied(DenyReason),
    Unresolved,
}

/// Kernel-reported identity of a Unix-domain-socket peer, from `SO_PEERCRED`, plus the
/// authorization decision resolved from it.
///
/// Resolved once per connection in the accept loop and reused for every request on that
/// connection. The `auth` field carries the decision: the dispatcher serves a credential
/// only when it is `Authorized`, and the verified uid it carries is the sole caller
/// dimension the store lookup accepts.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub uid: Option<u32>,
    pub pid: Option<i32>,
    pub auth: CallerAuth,
    /// The peer's executable, for the presence gate's pending-operation record.
    pub executable: Option<String>,
    /// The uid the peer's login session was opened for, which `sudo` does not change: the
    /// audit user id from the peer's audit token on macOS, `/proc/<pid>/loginuid` on Linux.
    /// Audit-only; never evidence for a decision.
    pub login_uid: Option<u32>,
}
