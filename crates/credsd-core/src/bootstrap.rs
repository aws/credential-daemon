//! Small credential-setup helpers shared across the crate.
//!
//! The interactive bootstrap flows live on the daemon (`credsd-daemon`'s `server/bootstrap.rs`),
//! which owns the keystore and the per-uid tree. What remains here is the two secret readers the
//! client uses before handing material to `credential/bootstrap` — one line-oriented and
//! interactive ([`read_secret`]), one whole-content from a file or a pipe ([`read_secret_text`]).

use crate::error::{DaemonError, Result};

/// Read a secret (the long-term secret access key) without echoing it, never from argv.
///
/// On a tty, prompt and disable echo (`rpassword::prompt_password`). When stdin is not a tty —
/// piped from a secret manager, or a CI runner — there is no terminal to prompt or open (opening
/// `/dev/tty` there fails with ENXIO), so read the line straight from stdin instead.
pub fn read_secret(prompt: &str) -> Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        // Interactive: prompt and read with echo disabled.
        return rpassword::prompt_password(prompt)
            .map_err(|e| DaemonError::config(format!("failed to read secret: {}", e)));
    }
    // Piped (secret manager / CI): there is no tty to prompt or open. rpassword's readers touch the
    // terminal even for piped stdin (ENXIO where none exists), so read the line straight from stdin.
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| DaemonError::config(format!("failed to read secret: {}", e)))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Where a bootstrap secret is read from.
///
/// Both variants are the *caller's* decision, not a parse of the path: `-` means stdin by
/// convention in several subcommands, and translating it is the subcommand's job so a file
/// genuinely named `-` stays addressable as `./-`.
#[derive(Debug, Clone, Copy)]
pub enum SecretInput<'a> {
    /// A path read exactly once. The path is never sent to the daemon.
    File(&'a str),
    /// Standard input: a hidden prompt on a terminal, the whole stream when piped.
    Stdin,
}

/// Read an opaque secret from a file or stdin, for a source whose credential *is* the secret.
///
/// Consolidates what `jwt`, `jwt-bearer`, and `static-secret` each need: whole-content ingest of
/// a secret credsd will not interpret. Distinct from [`read_secret`], which collects one line
/// interactively — that is the right shape for a password-like value typed at a prompt, and this
/// is the right shape for material that arrives in a file or a pipe.
///
/// Returns [`Zeroizing`] so the plaintext is scrubbed when the caller drops it rather than
/// lingering in client memory until the allocator happens to reuse the page.
///
/// **Normalization is deliberately minimal**: trailing newlines and carriage returns are
/// stripped and nothing else. `echo "sk-..." > f` appends a newline the user did not intend as
/// part of the secret, so leaving it would seal a value the API rejects for a reason nobody can
/// see. A full `trim()` would go further than that and corrupt a secret whose leading or
/// trailing spaces are real — unknowable for an opaque string, so it is not assumed. Both
/// variants normalize identically, so the same secret seals to the same bytes whether it
/// arrives by file or by pipe.
pub fn read_secret_text(
    input: SecretInput<'_>,
    prompt: &str,
) -> Result<zeroize::Zeroizing<String>> {
    use std::io::{IsTerminal, Read};

    let raw = match input {
        SecretInput::File(path) => {
            zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
                DaemonError::config(format!("cannot read secret from '{path}': {e}"))
            })?)
        }
        // A terminal gets the no-echo single-line prompt: an opaque secret is pasted, and
        // reading to EOF with echo disabled would need raw-mode terminal handling to no benefit.
        // A pipe gets the whole stream, which is what makes a multi-line secret and a secret
        // manager's output work.
        SecretInput::Stdin if std::io::stdin().is_terminal() => {
            zeroize::Zeroizing::new(read_secret(prompt)?)
        }
        SecretInput::Stdin => {
            let mut buf = zeroize::Zeroizing::new(String::new());
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| DaemonError::config(format!("cannot read secret from stdin: {e}")))?;
            buf
        }
    };

    Ok(zeroize::Zeroizing::new(
        raw.trim_end_matches(['\n', '\r']).to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trailing newline is an artifact of how the file was written, not part of the secret.
    /// Leaving it would seal a value the API rejects, with nothing on screen to explain why.
    #[test]
    fn a_trailing_newline_is_stripped_from_a_file_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        std::fs::write(&path, "sk-written-by-echo\n").expect("write");

        let secret =
            read_secret_text(SecretInput::File(path.to_str().expect("utf8")), "").expect("read");
        assert_eq!(secret.as_str(), "sk-written-by-echo");
    }

    /// CRLF too, so a file produced on Windows or by a copy-paste through a Windows editor
    /// seals the same bytes as the Unix original.
    #[test]
    fn a_crlf_terminator_is_stripped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        std::fs::write(&path, "sk-crlf\r\n").expect("write");

        let secret =
            read_secret_text(SecretInput::File(path.to_str().expect("utf8")), "").expect("read");
        assert_eq!(secret.as_str(), "sk-crlf");
    }

    /// Only the terminator is removed. Interior and *leading* whitespace survive, because an
    /// opaque secret may legitimately contain them and credsd cannot tell the difference.
    #[test]
    fn interior_and_leading_whitespace_survive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        std::fs::write(&path, " sk-with spaces \n").expect("write");

        let secret =
            read_secret_text(SecretInput::File(path.to_str().expect("utf8")), "").expect("read");
        assert_eq!(secret.as_str(), " sk-with spaces ");
    }

    /// The error names the path so a mistyped `--secret-file` is self-diagnosing, and carries no
    /// secret material — there is none to carry when the read failed.
    #[test]
    fn an_unreadable_file_names_the_path() {
        let err = read_secret_text(SecretInput::File("/nonexistent/credsd-secret-test"), "")
            .expect_err("missing file must error");
        let text = err.to_string();
        assert!(text.contains("/nonexistent/credsd-secret-test"), "{text}");
        assert!(text.contains("cannot read secret"), "{text}");
    }
}
