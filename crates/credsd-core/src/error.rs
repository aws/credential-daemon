//! Unified error type and Result alias for the daemon.

/// Alias for Results returned throughout the daemon.
pub type Result<T> = std::result::Result<T, DaemonError>;

/// Unified error type for all daemon subsystems.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DaemonError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("provider error: {0}")]
    Provider(String),

    #[error("credentials expired")]
    CredentialsExpired,

    /// Named "env" for history: it also carries a credential-addressed miss, and words itself by
    /// which one was asked for.
    #[error("{}", .0.message())]
    EnvNotFound(NotFound),

    /// The credential source has no unattended renewal left; the user must re-authenticate.
    /// Distinct from a transport failure so callers do not mask it as "cannot reach daemon".
    #[error("re-authentication required: {0}")]
    ReauthRequired(String),

    /// The daemon could not be dialled, or the exchange broke at the transport. Never a reachable
    /// daemon's answer. Built by [`DaemonError::unreachable`], which picks the advice.
    #[error("cannot reach the daemon at {socket}: {cause}. {advice}")]
    Unreachable {
        socket: String,
        cause: String,
        advice: &'static str,
    },

    /// A failure the daemon returned, carried exactly as the daemon worded it.
    #[error("{0}")]
    Remote(String),

    /// A gated operation was not performed and waits on this challenge. Its own variant so a
    /// caller can satisfy it and retry rather than report a failure.
    #[error("approval required: {}", .0.description)]
    ApprovalRequired(Box<crate::presence::Challenge>),

    /// `request/approve` did not satisfy the challenge. The request stays pending unless `reason`
    /// is a changed base state.
    #[error("approval refused ({reason:?}): {message} — {remediation}")]
    ApprovalRefused {
        reason: crate::presence::RefusalReason,
        message: String,
        remediation: String,
    },

    /// No pending request by that identifier is visible to this caller.
    #[error("no such pending request")]
    RequestNotFound,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

impl DaemonError {
    /// A failure to exchange with `socket`. `kind` is the I/O error kind when there is one. Only a
    /// missing socket, or one nothing listens on, is told to start the daemon; any other cause
    /// (permission denied, a peer that stops mid-response) points at the daemon and its socket.
    pub fn unreachable(
        socket: &std::path::Path,
        cause: impl std::fmt::Display,
        kind: Option<std::io::ErrorKind>,
    ) -> Self {
        use std::io::ErrorKind::{ConnectionRefused, NotFound};
        let advice = match kind {
            Some(NotFound | ConnectionRefused) => "Start it with 'credsd serve'.",
            _ => "Check that the daemon is running and that this user can reach its socket.",
        };
        Self::Unreachable {
            socket: socket.display().to_string(),
            cause: cause.to_string(),
            advice,
        }
    }

    /// The message without the category prefix `Display` adds. Use this, not `to_string()`, when
    /// one error's text becomes part of another's: the outer error adds its own prefix, and
    /// embedding the full `Display` repeats it (`provider error: ... provider error: ...`).
    pub fn detail(&self) -> String {
        match self {
            Self::Config(m) | Self::Storage(m) | Self::Encryption(m) | Self::Provider(m) => {
                m.clone()
            }
            other => other.to_string(),
        }
    }

    pub fn config(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        debug_assert_categories(&msg, 0);
        Self::Config(msg)
    }

    pub fn provider(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        debug_assert_categories(&msg, 0);
        Self::Provider(msg)
    }

    /// A daemon reply's message, which is often one rendered error and so may carry one category
    /// prefix, never two.
    pub fn remote(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        debug_assert_categories(&msg, 1);
        Self::Remote(msg)
    }
}

/// What a not-found answer named, and whether the request addressed it as an environment or a
/// credential. Displays as the bare name, so code that formats the name keeps working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotFound {
    pub name: String,
    pub kind: Addressed,
}

/// How the request named its subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressed {
    Environment,
    Credential,
}

impl NotFound {
    pub fn environment(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: Addressed::Environment,
        }
    }

    pub fn credential(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: Addressed::Credential,
        }
    }

    fn message(&self) -> String {
        match self.kind {
            Addressed::Environment => format!(
                "env not found: {} (run `creds list` to see configured envs)",
                self.name
            ),
            Addressed::Credential => format!(
                "credential not found: {} (run `creds list` to see your credentials)",
                self.name
            ),
        }
    }
}

impl std::fmt::Display for NotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

#[cfg(test)]
mod not_found_tests {
    use super::*;

    #[test]
    fn a_credential_miss_is_worded_as_a_credential() {
        assert_eq!(
            DaemonError::EnvNotFound(NotFound::credential("ci")).to_string(),
            "credential not found: ci (run `creds list` to see your credentials)"
        );
    }

    #[test]
    fn an_environment_miss_keeps_the_env_wording() {
        assert_eq!(
            DaemonError::EnvNotFound(NotFound::environment("dev")).to_string(),
            "env not found: dev (run `creds list` to see configured envs)"
        );
    }

    #[test]
    fn the_name_displays_bare() {
        assert_eq!(NotFound::credential("ci").to_string(), "ci");
    }
}

/// The variants whose `Display` adds a category prefix to a message.
const PREFIXED: [fn(String) -> DaemonError; 4] = [
    DaemonError::Config,
    DaemonError::Storage,
    DaemonError::Encryption,
    DaemonError::Provider,
];

fn category_count(msg: &str) -> usize {
    PREFIXED
        .iter()
        .map(|variant| {
            msg.matches(variant(String::new()).to_string().as_str())
                .count()
        })
        .sum()
}

/// Debug builds reject a message carrying more category prefixes than `allowed`, so a nested
/// error (`format!("...: {e}")` on a `DaemonError`) fails the first test that reaches it instead
/// of shipping as `provider error: ... provider error: ...`. The fix at the call site is
/// `e.detail()`.
fn debug_assert_categories(msg: &str, allowed: usize) {
    debug_assert!(
        category_count(msg) <= allowed,
        "error message repeats a category prefix; embed `.detail()`, not the error: {msg}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A message that names no category, so it is one a constructor accepts.
    fn plain_message() -> impl Strategy<Value = String> {
        "[a-z0-9 ':.()-]{0,48}".prop_filter("names a category", |m| category_count(m) == 0)
    }

    proptest! {
        /// `detail` is the message alone, so embedding it adds no prefix.
        #[test]
        fn detail_is_the_message_without_its_prefix(
            variant in 0usize..PREFIXED.len(),
            message in plain_message(),
        ) {
            let detail = PREFIXED.get(variant).map(|v| v(message.clone()).detail());
            prop_assert_eq!(detail, Some(message));
        }

        /// One rendered error relayed by the daemon is accepted and shown exactly as sent.
        #[test]
        fn a_relayed_rendered_error_shows_one_prefix(
            variant in 0usize..PREFIXED.len(),
            message in plain_message(),
        ) {
            let Some(rendered) = PREFIXED.get(variant).map(|v| v(message).to_string()) else {
                return Ok(());
            };
            let shown = DaemonError::remote(rendered.clone()).to_string();
            prop_assert_eq!(category_count(&shown), 1);
            prop_assert_eq!(shown, rendered);
        }
    }

    #[test]
    #[should_panic(expected = "repeats a category prefix")]
    fn embedding_a_rendered_error_trips_in_debug_builds() {
        let inner = DaemonError::Encryption("decryption failed".to_owned());
        let _ = DaemonError::provider(format!("no usable key: {inner}"));
    }

    #[test]
    #[should_panic(expected = "repeats a category prefix")]
    fn a_relayed_nested_error_trips_in_debug_builds() {
        let _ = DaemonError::remote("provider error: credential unavailable: provider error: x");
    }
}
