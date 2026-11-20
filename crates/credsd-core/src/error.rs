//! Unified error type and Result alias for the daemon.

/// Alias for Results returned throughout the daemon.
pub type Result<T> = std::result::Result<T, DaemonError>;

/// Category names, each written once (Requirement 1.3). A category variant renders
/// `<name>: <message>`; nothing else adds or removes a category.
pub const CONFIG: &str = "configuration error";
pub const STORAGE: &str = "storage error";
pub const ENCRYPTION: &str = "encryption error";
pub const PROVIDER: &str = "provider error";
pub const REAUTH: &str = "re-authentication required";
pub const IO: &str = "I/O error";
pub const JSON: &str = "serialization error";

/// Every category name, counted by [`prefixes`].
const CATEGORIES: [&str; 7] = [CONFIG, STORAGE, ENCRYPTION, PROVIDER, REAUTH, IO, JSON];

/// Unified error type for all daemon subsystems.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DaemonError {
    #[error("{CONFIG}: {0}")]
    Config(String),

    #[error("{STORAGE}: {0}")]
    Storage(String),

    #[error("{ENCRYPTION}: {0}")]
    Encryption(String),

    #[error("{PROVIDER}: {0}")]
    Provider(String),

    #[error("credentials expired")]
    CredentialsExpired,

    /// Named "env" for history: it also carries a credential-addressed miss, and words itself by
    /// which one was asked for.
    #[error("{}", .0.message())]
    EnvNotFound(NotFound),

    /// The credential source has no unattended renewal left; the user must re-authenticate.
    /// Distinct from a transport failure so callers do not mask it as "cannot reach daemon".
    #[error("{REAUTH}: {0}")]
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

    #[error("{IO}: {0}")]
    Io(#[from] std::io::Error),

    #[error("{JSON}: {0}")]
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

    /// The message without the category prefix `Display` adds. An error built from another error
    /// takes this, never the inner error's `Display`, so rendering adds exactly one prefix
    /// (Requirement 4.2). Rendering never rewrites a message, so this is the only safe way to
    /// embed one error in another.
    pub fn detail(&self) -> String {
        match self {
            Self::Config(m)
            | Self::Storage(m)
            | Self::Encryption(m)
            | Self::Provider(m)
            | Self::ReauthRequired(m) => m.clone(),
            Self::Io(e) => e.to_string(),
            Self::Json(e) => e.to_string(),
            other => other.to_string(),
        }
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn provider(msg: impl Into<String>) -> Self {
        Self::Provider(msg.into())
    }

    /// A daemon reply's message, shown exactly as the daemon worded it.
    pub fn remote(msg: impl Into<String>) -> Self {
        Self::Remote(msg.into())
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

/// Category prefixes in `text`: one per category name at a `<name>: ` boundary. The one count
/// every test uses to assert a rendered error holds exactly one.
pub fn prefixes(text: &str) -> usize {
    CATEGORIES
        .iter()
        .map(|c| text.matches(&format!("{c}: ")).count())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The constructors call sites use to build a category error from a message.
    fn categories() -> [fn(String) -> DaemonError; 5] {
        [
            DaemonError::Config,
            DaemonError::Storage,
            DaemonError::Encryption,
            DaemonError::Provider,
            DaemonError::ReauthRequired,
        ]
    }

    /// A message that holds no category name, so any prefix in the rendered text was added by
    /// rendering.
    fn plain_message() -> impl Strategy<Value = String> {
        "[a-z0-9 ':.()-]{0,48}".prop_filter("holds a category name", |m| prefixes(m) == 0)
    }

    proptest! {
        /// Building errors from errors the way call sites do (outer context plus the inner
        /// error's `detail()`), at any depth and across every category, renders one prefix.
        #[test]
        fn nesting_through_detail_renders_one_prefix(
            root in plain_message(),
            chain in prop::collection::vec((0usize..5, plain_message()), 0..5),
        ) {
            let make = categories();
            let mut err = DaemonError::Encryption(root);
            for (variant, context) in chain {
                err = make[variant](format!("{context}: {}", err.detail()));
            }
            let shown = err.to_string();
            prop_assert_eq!(prefixes(&shown), 1, "{}", shown);
            prop_assert_eq!(prefixes(&err.detail()), 0);
            let relayed = DaemonError::remote(shown.clone()).to_string();
            prop_assert_eq!(relayed, shown);
        }

        /// `detail` is the message alone.
        #[test]
        fn detail_is_the_message_without_its_prefix(
            variant in 0usize..5,
            message in plain_message(),
        ) {
            prop_assert_eq!(categories()[variant](message.clone()).detail(), message);
        }
    }

    #[test]
    fn a_wrapped_error_reads_as_one_sentence() {
        let inner = DaemonError::Encryption("decryption failed".to_owned());
        let outer = DaemonError::provider(format!("no usable key: {}", inner.detail()));
        assert_eq!(
            outer.to_string(),
            "provider error: no usable key: decryption failed"
        );
    }

    /// Rendering never rewrites a message: text that holds a category name of its own is shown
    /// as written (Requirement 4.3).
    #[test]
    fn message_text_naming_a_category_is_shown_unchanged() {
        let message = "server said 'provider error: quota exceeded' for /tmp/provider error: x";
        let err = DaemonError::provider(message);
        assert_eq!(err.to_string(), format!("provider error: {message}"));
        assert_eq!(err.detail(), message);
    }

    /// An error relayed through an RPC error message keeps one prefix: the daemon sends the
    /// error's `detail()`, and the client adds its own category once (Requirement 2.3).
    #[test]
    fn an_error_relayed_through_an_rpc_message_renders_one_prefix() {
        let on_daemon = DaemonError::provider("SSO authentication timed out after 5 minutes");
        let wire_message = on_daemon.detail();
        let on_client = DaemonError::config(format!("auth timed out: {wire_message}"));
        assert_eq!(
            on_client.to_string(),
            "configuration error: auth timed out: SSO authentication timed out after 5 minutes"
        );
        assert_eq!(prefixes(&on_client.to_string()), 1);
    }

    /// `detail` drops the category for every category variant, including the ones that wrap a
    /// typed source (Requirement 3.1).
    #[test]
    fn detail_drops_the_category_of_io_and_json() {
        let io = DaemonError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no such file or directory",
        ));
        assert_eq!(io.detail(), "no such file or directory");
        let json = DaemonError::from(serde_json::from_str::<u8>("x").unwrap_err());
        assert_eq!(prefixes(&json.detail()), 0);
        assert_eq!(prefixes(&json.to_string()), 1);
    }

    #[test]
    fn a_remote_error_is_shown_as_the_daemon_worded_it() {
        let text = "provider error: credential unavailable";
        assert_eq!(DaemonError::remote(text).to_string(), text);
    }
}
