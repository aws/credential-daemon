//! Presence gate, client side — SPIKE of `docs/specs/presence-gated-operations`.
//!
//! Satisfies a challenge with a Touch ID signature where a presence key is enrolled and this
//! build has the Secure Enclave shim; otherwise prints the `sudo creds request approve <id>` step.

use std::path::{Path, PathBuf};

use credsd_core::config::platform;
use credsd_core::error::{DaemonError, Result};
use credsd_core::log::escape_terminal;
use credsd_core::presence::{
    self, Accepts, ApproveParams, ApproveResult, Challenge, EnrollParams, EnrollResult, IdParams,
    PendingSummary, StatusResult, METHOD_PRESENCE_ENROLL, METHOD_PRESENCE_REVOKE,
    METHOD_PRESENCE_STATUS, METHOD_REQUEST_APPROVE, METHOD_REQUEST_GET, METHOD_REQUEST_LIST,
    METHOD_REQUEST_WITHDRAW,
};
use credsd_core::rpc::{uds, OkResult};

fn socket() -> PathBuf {
    platform::client_socket_path()
}

async fn call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
    method: &str,
    params: &P,
) -> Result<R> {
    uds::call(&socket(), method, params, None).await
}

/// The client's presence key file (design Decision 10). Only this Mac's Secure Enclave can use
/// `key`, and only with the user present, so the file is not sealed.
#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    version: u32,
    policy: String,
    /// Hex SEC1 uncompressed P-256 — read without the enclave, which would prompt.
    public_key: String,
    /// Hex of the enclave's `dataRepresentation`.
    key: String,
    created_at: String,
}

const KEY_FILE_VERSION: u32 = 1;
const CURRENT: &str = "presence-key.json";
/// A replacement awaiting approval (Requirement 5.14).
const PENDING: &str = "presence-key.pending.json";

impl KeyFile {
    fn fingerprint(&self) -> Option<String> {
        presence::unhex(&self.public_key).map(|k| presence::fingerprint(&k))
    }

    /// An unknown version is treated as absent, never handed to the enclave.
    fn read(path: &Path) -> Option<Self> {
        let file: Self = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        (file.version == KEY_FILE_VERSION).then_some(file)
    }
}

/// The key whose public half has `fingerprint` (Requirement 5.13). A pending replacement that a
/// challenge names has been enrolled, so it is promoted over the key it replaced.
fn key_for(dir: &Path, fingerprint: &str) -> Result<Option<KeyFile>> {
    let matches = |f: &KeyFile| f.fingerprint().as_deref() == Some(fingerprint);
    if let Some(current) = KeyFile::read(&dir.join(CURRENT)).filter(matches) {
        return Ok(Some(current));
    }
    let Some(pending) = KeyFile::read(&dir.join(PENDING)).filter(matches) else {
        return Ok(None);
    };
    std::fs::rename(dir.join(PENDING), dir.join(CURRENT))?;
    Ok(Some(pending))
}

fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Drive a challenge to an outcome: sign it here if possible, else tell the user how to
/// approve it. `true` only when this call approved it.
pub async fn satisfy(challenge: &Challenge) -> Result<bool> {
    println!("{}", approval_banner(&challenge.description));
    match try_sign(challenge).await? {
        Attempt::Approved => return Ok(true),
        Attempt::Failed(reason) => {
            println!("Touch ID was not completed: {reason}.");
            print_sudo(challenge);
        }
        Attempt::Unavailable => {
            print_sudo(challenge);
            if challenge.presence_key.is_none()
                && challenge.accepts == Accepts::Any
                && cfg!(feature = "secure-enclave")
            {
                println!(
                    "To approve with Touch ID instead, enroll a presence key: creds presence enroll"
                );
            }
        }
    }
    Ok(false)
}

enum Attempt {
    Approved,
    /// No presence signature is possible here: no key, no enclave build, or an enrollment,
    /// which only a privileged approval can satisfy.
    Unavailable,
    /// The prompt was shown and not satisfied. The request stays pending: withdrawing it here
    /// would protect nothing — a hostile requester would simply not withdraw — and would take
    /// away the `sudo` fallback from a user who cancelled because Touch ID was out of reach.
    Failed(String),
}

async fn try_sign(challenge: &Challenge) -> Result<Attempt> {
    let (Accepts::Any, Some(fingerprint)) = (challenge.accepts, &challenge.presence_key) else {
        return Ok(Attempt::Unavailable);
    };
    let Some(key) = key_for(&platform::client_dir()?, fingerprint)? else {
        return Ok(Attempt::Unavailable);
    };
    let Some(blob) = presence::unhex(&key.key) else {
        return Ok(Attempt::Unavailable);
    };
    let digest = presence::unhex(&challenge.digest)
        .ok_or_else(|| DaemonError::config("daemon sent a malformed digest"))?;
    let message = presence::signed_message(&challenge.id, &digest);
    // The first line only: a revalidation's description carries whole files, which a Touch ID
    // prompt cannot show. The full text was printed above, and the prompt is not the guarantee.
    let summary = challenge.description.lines().next().unwrap_or_default();
    let reason = format!("approve: {}", one_line(summary));
    match sign(&blob, &message, &reason) {
        Some(Ok(signature)) => {
            let approved: Result<ApproveResult> = call(
                METHOD_REQUEST_APPROVE,
                &ApproveParams {
                    id: challenge.id.clone(),
                    signature: Some(presence::hex(&signature)),
                },
            )
            .await;
            match approved {
                Ok(result) => {
                    println!("✓ {}  [{}]", result.outcome, result.verifier);
                    Ok(Attempt::Approved)
                }
                // Still pending (Requirement 8.3): fall through to the `sudo` path. A changed base
                // state is the one refusal that discards the request, so `sudo` cannot help there.
                Err(DaemonError::ApprovalRefused {
                    reason, message, ..
                }) if reason != credsd_core::presence::RefusalReason::BaseStateChanged => {
                    Ok(Attempt::Failed(message))
                }
                Err(e) => Err(e),
            }
        }
        Some(Err(e)) => Ok(Attempt::Failed(e.to_string())),
        None => Ok(Attempt::Unavailable),
    }
}

#[cfg(all(target_os = "macos", feature = "secure-enclave"))]
fn sign(blob: &[u8], message: &[u8], reason: &str) -> Option<Result<Vec<u8>>> {
    Some(presence::enclave::sign(blob, message, reason))
}

#[cfg(not(all(target_os = "macos", feature = "secure-enclave")))]
fn sign(_: &[u8], _: &[u8], _: &str) -> Option<Result<Vec<u8>>> {
    None
}

fn print_sudo(challenge: &Challenge) {
    println!(
        "\nPending request {id} (expires in {m}m).\nApprove from a privileged session:\n\n  sudo creds request approve {id}\n\nOr withdraw it: creds request withdraw {id}\n",
        id = challenge.id,
        m = challenge.expires_in_secs.div_ceil(60),
    );
}

pub async fn withdraw(id: &str) -> Result<()> {
    let _: OkResult = call(METHOD_REQUEST_WITHDRAW, &IdParams { id: id.to_owned() }).await?;
    println!("✓ withdrew {id}; nothing was changed");
    Ok(())
}

pub async fn approve(id: &str) -> Result<()> {
    let pending: PendingSummary = call(METHOD_REQUEST_GET, &IdParams { id: id.to_owned() }).await?;
    if !is_root() {
        match try_sign(&pending.challenge).await? {
            Attempt::Approved => return Ok(()),
            Attempt::Failed(reason) => {
                return Err(DaemonError::config(format!(
                    "Touch ID was not completed: {reason}. {id} is still pending — approve it \
                     with `sudo creds request approve {id}`, or withdraw it with \
                     `creds request withdraw {id}`"
                )))
            }
            Attempt::Unavailable => {}
        }
        // No usable key: submit without a proof so the daemon states the refusal itself.
        let _: ApproveResult = call(
            METHOD_REQUEST_APPROVE,
            &ApproveParams {
                id: id.to_owned(),
                signature: None,
            },
        )
        .await?;
        return Ok(());
    }

    println!(
        "{}",
        request_header(id, &pending, user_name(pending.owner_uid).as_deref())
    );
    if pending.challenge.accepts == Accepts::Privileged {
        println!(
            "Once enrolled, a signature by this key satisfies any gated operation for uid {}.\n\
             The daemon cannot verify where this key is held. Approve only a key you have just created.\n",
            pending.owner_uid
        );
    }
    print!("Approve? [y/N] ");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        return Err(DaemonError::config("not approved"));
    }
    let result: ApproveResult = call(
        METHOD_REQUEST_APPROVE,
        &ApproveParams {
            id: id.to_owned(),
            signature: None,
        },
    )
    .await?;
    println!("✓ {}  [{}]", result.outcome, result.verifier);
    Ok(())
}

pub async fn list() -> Result<()> {
    let pending: Vec<PendingSummary> = call(METHOD_REQUEST_LIST, &serde_json::json!({})).await?;
    if pending.is_empty() {
        println!("No pending requests.");
        return Ok(());
    }
    println!(
        "{:<18} {:<60} {:<10} EXPIRES IN",
        "ID", "OPERATION", "RAISED BY"
    );
    for p in pending {
        println!(
            "{:<18} {:<60} {:<10} {}m",
            p.challenge.id,
            one_line(&p.challenge.description),
            format!("uid {}", p.owner_uid),
            p.challenge.expires_in_secs.div_ceil(60)
        );
    }
    Ok(())
}

pub async fn enroll(policy: &str) -> Result<()> {
    if is_root() {
        // Let the daemon state the refusal, without creating a key in root's context.
        let _: EnrollResult = call(
            METHOD_PRESENCE_ENROLL,
            &EnrollParams {
                public_key: String::new(),
            },
        )
        .await?;
        return Ok(());
    }
    let path = platform::client_dir()?.join(PENDING);
    let public_key = generate(policy, &path)?;
    let result: EnrollResult = call(
        METHOD_PRESENCE_ENROLL,
        &EnrollParams {
            public_key: presence::hex(&public_key),
        },
    )
    .await?;
    println!(
        "Created a presence key in the Secure Enclave.\n  fingerprint  {}\n  use requires {}\n  key file     {}",
        result.fingerprint,
        if policy == "presence" { "Touch ID or the device passcode" } else { "Touch ID (invalidated if fingerprints change)" },
        path.display()
    );
    print_sudo(&result.challenge);
    println!("Check that the approval shows the same fingerprint.");
    Ok(())
}

/// Writes the new key as the pending replacement, so the enrolled key stays usable until the
/// daemon names the new one (Requirement 5.14).
#[cfg(all(target_os = "macos", feature = "secure-enclave"))]
fn generate(policy: &str, path: &Path) -> Result<Vec<u8>> {
    let flags = presence::enclave::flags_for(policy).ok_or_else(|| {
        DaemonError::config(format!("unknown policy '{policy}' (biometry | presence)"))
    })?;
    let (blob, public_key) = presence::enclave::generate(flags)?;
    write_key_file(
        path,
        &KeyFile {
            version: KEY_FILE_VERSION,
            policy: policy.to_owned(),
            public_key: presence::hex(&public_key),
            key: presence::hex(&blob),
            created_at: chrono::Utc::now().to_rfc3339(),
        },
    )?;
    Ok(public_key)
}

/// `0600`, through a sibling temp file and a rename, so a crash never truncates a key.
#[cfg(all(target_os = "macos", feature = "secure-enclave"))]
fn write_key_file(path: &Path, file: &KeyFile) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?
        .write_all(&serde_json::to_vec_pretty(file)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(not(all(target_os = "macos", feature = "secure-enclave")))]
fn generate(_: &str, _: &Path) -> Result<Vec<u8>> {
    Err(DaemonError::config(
        "presence keys need a macOS build with the `secure-enclave` feature; \
         use sudo creds request approve <id> instead",
    ))
}

pub async fn revoke() -> Result<()> {
    let r: serde_json::Value = call(METHOD_PRESENCE_REVOKE, &serde_json::json!({})).await?;
    println!(
        "✓ presence key {} revoked\n  gated operations now require: sudo creds request approve <id>",
        r.get("revoked").and_then(|v| v.as_str()).unwrap_or("?")
    );
    Ok(())
}

pub async fn status() -> Result<()> {
    let s: StatusResult = call(METHOD_PRESENCE_STATUS, &serde_json::json!({})).await?;
    match s.presence_key {
        Some(fp) => println!(
            "uid {}: presence key {fp}\n  enrolled {}  approved by uid {} (login uid {})\n  {}",
            s.uid,
            s.enrolled_at.unwrap_or_default(),
            s.approved_by_uid.map_or("?".into(), |u| u.to_string()),
            s.approved_by_login_uid
                .map_or("unknown".into(), |u| u.to_string()),
            local_key(&fp),
        ),
        None => println!("uid {}: no presence key enrolled", s.uid),
    }
    Ok(())
}

/// Whether this client holds the enrolled key: the Touch ID path needs it to.
fn local_key(fingerprint: &str) -> String {
    match platform::client_dir().and_then(|dir| Ok((key_for(&dir, fingerprint)?, dir))) {
        Ok((Some(k), dir)) => format!(
            "held here: {} (requires {}, created {})",
            dir.join(CURRENT).display(),
            k.policy,
            k.created_at
        ),
        Ok((None, _)) => "not held by this client; approve with sudo, or re-enroll".to_owned(),
        Err(e) => format!("client key unavailable: {e}"),
    }
}

/// One line of text, escaped. Tab and the Unicode line and paragraph separators are shown as a
/// space, since a renderer would otherwise honor them as a column or line break.
fn escape_line(text: &str) -> String {
    escape_terminal(text)
        .to_string()
        .replace(['\t', '\u{2028}', '\u{2029}'], " ")
}

/// A description as one terminal line, for the list cell and the Touch ID reason. A newline
/// would start a new row that the approver reads as real, so it is flattened too.
///
/// Example: `"ok\nforged row"` renders as `ok forged row` on a single line.
fn one_line(description: &str) -> String {
    escape_line(description).replace('\n', " ")
}

/// A description for the approver's screen, where line breaks are content: a revalidation
/// carries a whole file, one TOML line per line. Each line is escaped on its own. Lines after
/// the first are indented, so no description line can start at column 0 and pass for a header.
///
/// Example: `"[a]\nb = 1"` renders as `[a]` then `    b = 1` on the next line.
fn screen_text(description: &str) -> String {
    description
        .trim_end_matches('\n')
        .split('\n')
        .map(escape_line)
        .collect::<Vec<_>>()
        .join("\n    ")
}

/// The line `satisfy` prints before any Touch ID attempt. The description is escaped here
/// because it is the only text the approver reads before deciding.
fn approval_banner(description: &str) -> String {
    format!("Approval required: {}", screen_text(description))
}

/// The block `approve` prints for an approver. `owner_name` is passed in so the layout is a
/// pure function of its inputs; the passwd lookup stays at the call site.
fn request_header(id: &str, pending: &PendingSummary, owner_name: Option<&str>) -> String {
    format!(
        "\nRequest {} — {}\nRaised by uid {}{}, pid {}, {}, at {}\n  digest {}\n",
        id,
        screen_text(&pending.challenge.description),
        pending.owner_uid,
        owner_name
            .map(|n| format!(" ({})", one_line(n)))
            .unwrap_or_default(),
        pending.owner_pid.map_or("?".into(), |p| p.to_string()),
        // The requester names its own binary, so its path can carry escape sequences or a
        // newline that would rewrite the uid and description lines above it.
        one_line(pending.owner_executable.as_deref().unwrap_or("?")),
        pending.raised_at,
        pending.challenge.digest,
    )
}

fn user_name(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_with(description: &str) -> PendingSummary {
        PendingSummary {
            challenge: Challenge {
                id: "req-1".to_owned(),
                digest: "d1g3st".to_owned(),
                description: description.to_owned(),
                expires_in_secs: 300,
                accepts: Accepts::Any,
                presence_key: None,
            },
            owner_uid: 501,
            owner_pid: Some(42),
            owner_executable: Some("/usr/bin/creds".to_owned()),
            raised_at: "2026-11-02T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn an_approval_banner_shows_the_description_without_hidden_text() {
        assert_eq!(approval_banner("run ok"), "Approval required: run ok");
        assert_eq!(
            approval_banner("x\u{202E}evil\u{1b}[2J"),
            "Approval required: x\u{FFFD}evil\u{FFFD}[2J"
        );
    }

    #[test]
    fn an_approve_header_escapes_the_description_and_names_the_owner() {
        let header = request_header("req-1", &pending_with("ok\u{202E}evil"), Some("alice"));
        assert_eq!(
            header,
            "\nRequest req-1 — ok\u{FFFD}evil\nRaised by uid 501 (alice), pid 42, /usr/bin/creds, at 2026-11-02T00:00:00Z\n  digest d1g3st\n"
        );
        let anonymous = request_header("req-1", &pending_with("x"), None);
        assert!(
            anonymous.contains("Raised by uid 501, pid 42"),
            "{anonymous}"
        );
    }

    /// `creds revalidate` and `sudo creds request approve` show a drifted file here. Each line
    /// of the file must stay on its own line, so the approver can find a changed endpoint.
    #[test]
    fn a_revalidation_keeps_each_file_line_on_its_own_line() {
        let file = "[[credentials]]\nname = \"work\"\nendpoint_url = \"https://a.example\"\n";
        let header = request_header("req-1", &pending_with(file), None);
        assert!(
            header
                .lines()
                .any(|l| l == "Request req-1 — [[credentials]]"),
            "{header}"
        );
        for line in ["name = \"work\"", "endpoint_url = \"https://a.example\""] {
            assert!(
                header.lines().any(|l| l == format!("    {line}")),
                "{header}"
            );
        }
    }

    #[test]
    fn a_list_cell_cannot_break_its_row_or_hide_text() {
        assert_eq!(one_line("ok\nforged row"), "ok forged row");
        assert_eq!(one_line("a\tb"), "a b");
        assert_eq!(one_line("x\u{202E}evil"), "x\u{FFFD}evil");
        assert_eq!(one_line("plain text"), "plain text");
    }

    #[test]
    fn a_description_cannot_forge_a_line_in_the_approve_header() {
        let forged = "ok\n  digest 0000\nRaised by uid 0 (root), pid 1, /bin/sh, at 1970";
        let header = request_header("req-1", &pending_with(forged), None);
        let at_column_0 = |prefix: &str| header.lines().filter(|l| l.starts_with(prefix)).count();
        assert_eq!(at_column_0("Raised by uid"), 1, "{header}");
        assert_eq!(at_column_0("  digest"), 1, "{header}");
        assert_eq!(at_column_0("digest"), 0, "{header}");

        // The approval banner keeps its line breaks, but every continuation line is indented.
        let banner = approval_banner(forged);
        assert!(
            banner.lines().skip(1).all(|l| l.starts_with("    ")),
            "{banner}"
        );

        // The executable path is the caller's own binary, so the caller controls it too.
        let mut pending = pending_with("x");
        pending.owner_executable = Some("/tmp/x\nRaised by uid 0 (root), pid 1".to_owned());
        let header = request_header("req-1", &pending, None);
        let raised = header
            .lines()
            .filter(|l| l.starts_with("Raised by uid"))
            .count();
        assert_eq!(raised, 1, "{header}");

        // Format characters are hidden text too, and a C0-only escape would let them through.
        pending.owner_executable = Some("/tmp/x\u{202E}evil".to_owned());
        let header = request_header("req-1", &pending, None);
        assert!(header.contains("/tmp/x\u{FFFD}evil"), "{header}");

        // U+2028 and U+2029 break a line in renderers that honor them.
        assert!(!one_line("a\u{2028}b\u{2029}c").contains(['\u{2028}', '\u{2029}']));
    }

    fn key_file(public_key: &[u8], version: u32) -> Vec<u8> {
        serde_json::to_vec(&KeyFile {
            version,
            policy: "biometry".to_owned(),
            public_key: presence::hex(public_key),
            key: presence::hex(b"enclave bytes"),
            created_at: "2026-10-05T00:00:00Z".to_owned(),
        })
        .expect("serialize")
    }

    const OLD: [u8; 65] = [4; 65];
    const NEW: [u8; 65] = [5; 65];

    #[test]
    fn only_the_key_a_challenge_names_is_used() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CURRENT), key_file(&OLD, 1)).expect("write");

        let named = key_for(dir.path(), &presence::fingerprint(&OLD)).expect("read");
        assert_eq!(named.map(|k| k.public_key), Some(presence::hex(&OLD)));
        assert!(key_for(dir.path(), &presence::fingerprint(&NEW))
            .expect("read")
            .is_none());
    }

    /// Requirement 5.14: the replacement waits, and replaces the old key once it is enrolled.
    #[test]
    fn a_replacement_displaces_the_old_key_only_once_a_challenge_names_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CURRENT), key_file(&OLD, 1)).expect("write");
        std::fs::write(dir.path().join(PENDING), key_file(&NEW, 1)).expect("write");

        assert!(key_for(dir.path(), &presence::fingerprint(&OLD))
            .expect("read")
            .is_some());
        assert!(dir.path().join(PENDING).exists());

        assert!(key_for(dir.path(), &presence::fingerprint(&NEW))
            .expect("read")
            .is_some());
        assert!(!dir.path().join(PENDING).exists());
        let current = KeyFile::read(&dir.path().join(CURRENT)).expect("current");
        assert_eq!(current.public_key, presence::hex(&NEW));
    }

    #[test]
    fn a_key_file_of_an_unknown_version_is_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CURRENT), key_file(&OLD, 2)).expect("write");
        assert!(key_for(dir.path(), &presence::fingerprint(&OLD))
            .expect("read")
            .is_none());
    }
}
