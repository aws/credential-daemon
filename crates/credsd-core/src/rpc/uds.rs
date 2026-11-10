//! The client half of the transport: one request line out, one response line back.
//!
//! Every client-side call — credential fetch, manifest, config read, mutation — is this
//! exchange, so it is written once here rather than per call site. The hand-rolled copies this
//! replaces had already drifted: one checked for a zero-length read, one did not; one mapped
//! `AUTH_TIMEOUT` to prose, another to a generic provider error.
//!
//! Interactive flows (SSO device code, account/role selection) are *not* this shape — they
//! read many notification lines before the response — and keep their own loop in the client
//! binary.

use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{DaemonError, NotFound, Result};
use crate::rpc::{codec, DomainCode, Id, Outcome, Request, RpcError};

/// Send one request about `subject` and decode its response.
///
/// `subject` is the profile, env, or credential the call is about, or `None` for a call that names
/// none — enumerating every profile, a health probe. It is used only to name what was not found
/// when the daemon answers `ENVIRONMENT_NOT_FOUND`: the daemon deliberately will not say which of
/// "no such profile", "denied", and "unresolved caller" applies (Req 8 AC 3-4), so the name has to
/// come from the caller that asked.
///
/// `Option` rather than a string, because a caller with no subject has no name to supply and every
/// stand-in it might invent is a lie. `credential/list` passed the literal `"credentials"` and so
/// reported an unprovisioned caller as `env not found: credentials` — an env nobody had ever
/// configured, which is the one answer guaranteed to send a reader looking in the wrong place.
pub async fn call<P: Serialize, R: DeserializeOwned>(
    socket: &Path,
    method: &str,
    params: &P,
    subject: Option<&str>,
) -> Result<R> {
    use tokio::io::BufReader;
    use tokio::net::UnixStream;

    // Unencodable params are a client-side bug, not something the daemon said.
    let request = Request::with_params(Id::from(1), method, params)
        .map_err(|e| DaemonError::config(e.message))?;
    let bytes = codec::encode_request(&request)?;

    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|e| io_failure(socket, e))?;
    write_frame(&mut stream, socket, &bytes).await?;

    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    read_frame(&mut reader, socket, &mut line).await?;

    let response = codec::decode_response::<R>(&line).map_err(|e| error_to_daemon(subject, e))?;
    match response.outcome {
        Outcome::Result(result) => Ok(result),
        Outcome::Error(error) => Err(error_to_daemon(subject, error)),
    }
}

/// Deadline for a blocking daemon exchange. Generous enough for a local UDS round trip that only
/// reads config and sealed-token metadata (no network), tight enough that an unresponsive daemon
/// surfaces as an error rather than a hang.
#[cfg(unix)]
const BLOCKING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Blocking sibling of [`call`], for callers that are not on a Tokio runtime.
///
/// The MCP stdio loop (`mcp::serve_stdio`) is a synchronous `loop` running on a runtime worker
/// thread, so it can neither `.await` nor `block_on` the async [`call`] there without panicking.
/// Rather than reimplement the socket exchange (a second copy that could drift on framing or
/// error mapping), this runs the very same async [`call`] on a fresh current-thread runtime inside
/// a dedicated `std::thread`. The dedicated thread is what makes the nested runtime legal: building
/// one on an existing runtime worker panics, but the spawned thread carries no ambient runtime.
///
/// The exchange is bounded by [`BLOCKING_TIMEOUT`] so a daemon that accepts the connection but
/// never writes cannot wedge the MCP loop; the async [`call`] leaves cancellation to its caller's
/// runtime, which this path lacks.
#[cfg(unix)]
pub fn call_blocking<P: Serialize, R: DeserializeOwned + Send + 'static>(
    socket: &Path,
    method: &str,
    params: &P,
    subject: Option<&str>,
) -> Result<R> {
    // Cross the thread boundary with owned, `Send` values. Serializing params to a `Value` up
    // front is also the only `P`-dependent step, so the spawned thread stays fully generic-free.
    // `call_blocking` serves only material-free methods (env status), so no secret is copied here.
    let params = serde_json::to_value(params).map_err(DaemonError::Json)?;
    let socket = socket.to_path_buf();
    let method = method.to_owned();
    let subject = subject.map(str::to_owned);

    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        DaemonError::provider(format!("failed to build blocking runtime: {e}"))
                    })?;
                runtime.block_on(async {
                    tokio::time::timeout(
                        BLOCKING_TIMEOUT,
                        call::<serde_json::Value, R>(&socket, &method, &params, subject.as_deref()),
                    )
                    .await
                    .map_err(|_| {
                        DaemonError::unreachable(
                            &socket,
                            "did not respond within the timeout",
                            None,
                        )
                    })?
                })
            })
            .join()
            .map_err(|_| DaemonError::provider("blocking daemon call thread panicked"))?
    })
}

/// An I/O failure exchanging with the socket is a transport failure. A reachable daemon's answer,
/// including its refusals, never reaches this.
pub fn io_failure(socket: &Path, error: std::io::Error) -> DaemonError {
    DaemonError::unreachable(socket, &error, Some(error.kind()))
}

/// Write one frame to the daemon. Every exchange, one-shot or streaming, classifies a failed write
/// here, so a broken connection reads the same whichever path the caller took.
pub async fn write_frame<W>(writer: &mut W, socket: &Path, bytes: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    writer
        .write_all(bytes)
        .await
        .map_err(|e| io_failure(socket, e))
}

/// Read one newline-terminated frame from the daemon into `line`.
///
/// A line without its newline is a peer that stopped mid-response, not a response to decode, so
/// it is a transport failure like an I/O error. The caller decodes a complete frame.
pub async fn read_frame<R>(reader: &mut R, socket: &Path, line: &mut Vec<u8>) -> Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    let read = reader
        .read_until(b'\n', line)
        .await
        .map_err(|e| io_failure(socket, e))?;
    if !line.ends_with(b"\n") {
        let cause = if read == 0 {
            "closed the connection without responding"
        } else {
            "closed the connection mid-response"
        };
        return Err(DaemonError::unreachable(socket, cause, None));
    }
    Ok(())
}

/// Map a wire failure onto the daemon's error taxonomy.
///
/// `REAUTH_REQUIRED` must land on [`DaemonError::ReauthRequired`] so an interactive `get`/`run`
/// still drives the login flow, and `ENVIRONMENT_NOT_FOUND` on [`DaemonError::EnvNotFound`] naming
/// `subject`. The two auth-lifecycle codes keep their own prose because "timed out" and
/// "cancelled" imply different next actions for a user, as do the config-state codes. Every other
/// failure, envelope-level failures included, reaches the caller as [`DaemonError::Remote`]: the
/// daemon's message, unchanged, so nothing re-prefixes it or tells the user to start a daemon
/// that is already running.
///
/// With no subject there is no env to name, so the daemon's own message is passed through rather
/// than dressed up as a missing env. This path is not the unprovisioned caller — enumeration
/// answers that with an empty list (`dispatch::enumerating_uid`) — it is a genuine anomaly the
/// daemon has already worded.
pub fn error_to_daemon(subject: Option<&str>, error: RpcError) -> DaemonError {
    match error.domain_code() {
        Some(DomainCode::ReauthRequired) => DaemonError::ReauthRequired(error.message),
        Some(DomainCode::EnvironmentNotFound) => match subject {
            Some(subject) => DaemonError::EnvNotFound(NotFound::environment(subject)),
            None => DaemonError::remote(error.message),
        },
        Some(DomainCode::AuthTimeout) => {
            DaemonError::config(format!("auth timed out: {}", error.message))
        }
        Some(DomainCode::AuthCancelled) => {
            DaemonError::config(format!("auth cancelled: {}", error.message))
        }
        Some(DomainCode::ApprovalRequired) => match error.challenge() {
            Some(challenge) => DaemonError::ApprovalRequired(Box::new(challenge)),
            None => DaemonError::remote(error.message),
        },
        Some(DomainCode::ApprovalRefused) => DaemonError::ApprovalRefused {
            reason: error
                .refusal_reason()
                .unwrap_or(crate::presence::RefusalReason::Unknown),
            remediation: error.remediation().unwrap_or_default(),
            message: error.message,
        },
        Some(DomainCode::RequestNotFound) => DaemonError::RequestNotFound,
        Some(DomainCode::ConfigDrifted) => {
            DaemonError::config(format!("config drifted: {}", error.message))
        }
        Some(DomainCode::IntegrityUnverifiable) => {
            DaemonError::config(format!("config unverifiable: {}", error.message))
        }
        Some(DomainCode::CustodyBroken) => {
            DaemonError::config(format!("integrity custody broken: {}", error.message))
        }
        Some(DomainCode::ProviderUnavailable)
        | Some(DomainCode::WrongCredentialType)
        | Some(DomainCode::Internal)
        | Some(DomainCode::Unknown)
        | None => DaemonError::remote(error.message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_domain_code_maps_to_a_distinguishable_daemon_error() {
        let cases = [
            (DomainCode::ReauthRequired, "reauth"),
            (DomainCode::EnvironmentNotFound, "not-found"),
            (DomainCode::AuthTimeout, "timeout"),
            (DomainCode::AuthCancelled, "cancelled"),
            (DomainCode::ProviderUnavailable, "provider"),
            (DomainCode::WrongCredentialType, "provider"),
            (DomainCode::Internal, "provider"),
            (DomainCode::ConfigDrifted, "drifted"),
            (DomainCode::IntegrityUnverifiable, "unverifiable"),
            (DomainCode::CustodyBroken, "custody"),
        ];
        for (code, kind) in cases {
            let mapped = error_to_daemon(Some("dev"), RpcError::domain(code, "boom"));
            let actual = match mapped {
                DaemonError::ReauthRequired(_) => "reauth",
                DaemonError::EnvNotFound(ref env) => {
                    assert_eq!(env.name, "dev", "{code:?} must name the subject asked for");
                    "not-found"
                }
                DaemonError::Config(ref m) if m.starts_with("auth timed out") => "timeout",
                DaemonError::Config(ref m) if m.starts_with("auth cancelled") => "cancelled",
                DaemonError::Config(ref m) if m.starts_with("config drifted") => "drifted",
                DaemonError::Config(ref m) if m.starts_with("config unverifiable") => {
                    "unverifiable"
                }
                DaemonError::Config(ref m) if m.starts_with("integrity custody broken") => {
                    "custody"
                }
                DaemonError::Remote(_) => "provider",
                ref other => panic!("{code:?} mapped to an unexpected variant: {other:?}"),
            };
            assert_eq!(actual, kind, "{code:?}");
        }
    }

    /// `APPROVAL_REQUIRED` surfaces its challenge so a caller can satisfy and retry. One whose
    /// challenge is missing or malformed is still a failure — never mistaken for success.
    #[test]
    fn approval_required_carries_its_challenge_or_fails_plainly() {
        let challenge = crate::presence::Challenge {
            id: "req-1".into(),
            digest: "00".into(),
            description: "replace the sealed secret for credential 'demo'".into(),
            expires_in_secs: 300,
            accepts: crate::presence::Accepts::Any,
            presence_key: None,
        };
        let error = RpcError::approval_required(&challenge, "sudo creds request approve req-1");
        assert_eq!(error.domain_code(), Some(DomainCode::ApprovalRequired));
        match error_to_daemon(Some("demo"), error) {
            DaemonError::ApprovalRequired(c) => assert_eq!(c.id, "req-1"),
            other => panic!("expected ApprovalRequired, got {other:?}"),
        }

        let bare = RpcError::domain(DomainCode::ApprovalRequired, "no challenge attached");
        assert!(matches!(
            error_to_daemon(Some("demo"), bare),
            DaemonError::Remote(_)
        ));
    }

    /// Both refusal codes map to their own variants, carrying the reason and the daemon's
    /// remediation — never folded into a generic failure a caller would have to parse.
    #[test]
    fn refusal_codes_map_to_their_own_variants() {
        use crate::presence::RefusalReason;
        let refused = RpcError::approval_refused(
            RefusalReason::BaseStateChanged,
            "req-1 discarded",
            "re-run the original command",
        );
        match error_to_daemon(None, refused) {
            DaemonError::ApprovalRefused {
                reason,
                remediation,
                ..
            } => {
                assert_eq!(reason, RefusalReason::BaseStateChanged);
                assert_eq!(remediation, "re-run the original command");
            }
            other => panic!("expected ApprovalRefused, got {other:?}"),
        }
        assert!(matches!(
            error_to_daemon(None, RpcError::request_not_found()),
            DaemonError::RequestNotFound
        ));
    }

    /// A call that named no subject must not be reported as a missing env. `credential/list`
    /// with no filter passed the literal `"credentials"` here, so an unprovisioned caller read
    /// as `env not found: credentials` — a name nobody had configured, which is the one answer
    /// guaranteed to send a reader looking in the wrong place. The daemon's own message must
    /// survive instead.
    #[test]
    fn a_subjectless_not_found_names_no_env() {
        let mapped = error_to_daemon(
            None,
            RpcError::domain(
                DomainCode::EnvironmentNotFound,
                "profile or credential not found",
            ),
        );
        match mapped {
            DaemonError::EnvNotFound(ref env) => {
                panic!("a call with no subject must not invent one, got '{env}'")
            }
            DaemonError::Remote(ref message) => {
                assert!(
                    message.contains("profile or credential not found"),
                    "the daemon's message must survive: {message}"
                );
            }
            ref other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// `call_blocking` shares the wire format and error mapping of the async `call`: a result
    /// decodes, and a domain error maps through `error_to_daemon` (here, naming the subject).
    #[cfg(unix)]
    #[test]
    fn call_blocking_round_trips_a_result_and_maps_errors_like_call() {
        use crate::rpc::{codec, HealthResult, Id, Response, PROTOCOL_VERSION};
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        fn serve_once(
            path: std::path::PathBuf,
            response_bytes: Vec<u8>,
        ) -> std::thread::JoinHandle<()> {
            let listener = UnixListener::bind(&path).expect("bind");
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                    let mut line = Vec::new();
                    let _ = reader.read_until(b'\n', &mut line);
                    let _ = stream.write_all(&response_bytes);
                }
            })
        }

        let dir = tempfile::tempdir().expect("tempdir");

        let ok_path = dir.path().join("ok.sock");
        let ok_bytes =
            codec::encode_response(&Response::success(Id::from(1), HealthResult::default()))
                .expect("encode");
        let h = serve_once(ok_path.clone(), ok_bytes);
        let health: HealthResult =
            call_blocking(&ok_path, "system/health", &serde_json::json!({}), None).expect("ok");
        assert_eq!(health.protocol, PROTOCOL_VERSION);
        h.join().ok();

        let err_path = dir.path().join("err.sock");
        let err_bytes = codec::encode_response(&Response::<HealthResult>::failure(
            Id::from(1),
            RpcError::domain(DomainCode::EnvironmentNotFound, "gone"),
        ))
        .expect("encode");
        let h = serve_once(err_path.clone(), err_bytes);
        let err = call_blocking::<_, HealthResult>(
            &err_path,
            "system/health",
            &serde_json::json!({}),
            Some("dev"),
        )
        .expect_err("err");
        assert!(
            matches!(err, DaemonError::EnvNotFound(ref s) if s.name == "dev"),
            "{err:?}"
        );
        h.join().ok();
    }

    /// An envelope-level failure carries no domain code, and must not be mistaken for a missing
    /// profile — that would report "env not found" for a malformed request.
    #[test]
    fn envelope_failures_are_remote_errors_not_missing_profiles() {
        for error in [
            RpcError::invalid_params("bad"),
            RpcError::method_not_found("nope"),
            RpcError::internal("boom"),
            RpcError::parse_error("garbage"),
        ] {
            let mapped = error_to_daemon(Some("dev"), error);
            assert!(
                matches!(mapped, DaemonError::Remote(_)),
                "{mapped:?} must be a remote error"
            );
        }
    }

    proptest::proptest! {
        /// A daemon-returned failure reaches the caller as the daemon worded it. The client used to
        /// re-prefix it (`provider error: provider error: ...`), and `creds get` relabelled it as an
        /// unreachable daemon, sending the operator to start a daemon that was already running.
        #[test]
        fn daemon_message_passes_through_verbatim(
            code in proptest::sample::select(vec![
                DomainCode::ProviderUnavailable,
                DomainCode::WrongCredentialType,
                DomainCode::Internal,
                DomainCode::Unknown,
            ]),
            message in proptest::prelude::any::<String>(),
        ) {
            let mapped = error_to_daemon(Some("dev"), RpcError::domain(code, message.clone()));
            proptest::prop_assert_eq!(mapped.to_string(), message);
        }
    }

    #[cfg(unix)]
    #[test]
    fn absent_socket_is_reported_as_unreachable_with_serve_hint() {
        use crate::rpc::HealthResult;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.sock");
        let err =
            call_blocking::<_, HealthResult>(&path, "system/health", &serde_json::json!({}), None)
                .expect_err("no socket is bound");
        let text = err.to_string();
        assert!(text.starts_with("cannot reach the daemon at "), "{text}");
        assert!(text.ends_with("Start it with 'credsd serve'."), "{text}");
    }

    #[test]
    fn env_not_found_names_the_env_and_the_list_command() {
        let mapped = error_to_daemon(
            Some("does-not-exist"),
            RpcError::domain(
                DomainCode::EnvironmentNotFound,
                "profile or credential not found",
            ),
        );
        assert_eq!(
            mapped.to_string(),
            "env not found: does-not-exist (run `creds list` to see configured envs)"
        );
    }

    /// Binds `path`, reads the request line, writes `reply` verbatim, then closes the connection.
    #[cfg(unix)]
    fn serve_then_close(path: &Path, reply: Vec<u8>) -> std::thread::JoinHandle<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        let listener = UnixListener::bind(path).expect("bind");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = Vec::new();
                let _ = BufReader::new(stream.try_clone().expect("clone"))
                    .read_until(b'\n', &mut request);
                let _ = stream.write_all(&reply);
            }
        })
    }

    /// A peer that drops mid-response is a transport failure, not a daemon answer to be decoded.
    #[cfg(unix)]
    #[test]
    fn connection_dropped_mid_response_is_unreachable() {
        use crate::rpc::{codec, HealthResult, Id, Response};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cut.sock");
        let full = codec::encode_response(&Response::success(Id::from(1), HealthResult::default()))
            .expect("encode");
        let server = serve_then_close(&path, full[..full.len().div_euclid(2)].to_vec());
        let err = call_blocking::<_, HealthResult>(
            &path,
            "system/health",
            &serde_json::json!({}),
            Some("dev"),
        )
        .expect_err("a truncated response is not a result");
        server.join().ok();
        let text = err.to_string();
        assert!(text.starts_with("cannot reach the daemon at "), "{text}");
    }

    #[cfg(unix)]
    proptest::proptest! {
        /// No strict prefix of an encoded response is a response: each one is a peer that dropped
        /// the connection, whatever the daemon's message was and wherever the cut lands.
        #[test]
        fn every_strict_prefix_of_a_response_is_unreachable(
            message in proptest::prelude::any::<String>(),
            cut in proptest::prelude::any::<proptest::sample::Index>(),
        ) {
            use crate::rpc::{codec, HealthResult, Id, Response};
            let full = codec::encode_response(&Response::<HealthResult>::failure(
                Id::from(1),
                RpcError::domain(DomainCode::Internal, message),
            ))
            .expect("encode");
            // `index` is in `0..len`, so the prefix never includes the trailing newline.
            let cut = cut.index(full.len());
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("prefix.sock");
            let server = serve_then_close(&path, full[..cut].to_vec());
            let err = call_blocking::<_, HealthResult>(
                &path,
                "system/health",
                &serde_json::json!({}),
                Some("dev"),
            )
            .expect_err("a strict prefix is not a response");
            server.join().ok();
            proptest::prop_assert!(
                err.to_string().starts_with("cannot reach the daemon at "),
                "cut at {cut} of {}: {err}",
                full.len()
            );
        }
    }

    /// Only a missing socket or one nothing listens on is told to start the daemon. Permission
    /// denied, or a cause with no I/O kind, points at the daemon and its socket instead.
    #[test]
    fn only_a_missing_or_unlistened_socket_is_told_to_start_the_daemon() {
        use std::io::ErrorKind;
        let socket = Path::new("/run/credsd/credsd.sock");

        let refused =
            DaemonError::unreachable(socket, "refused", Some(ErrorKind::ConnectionRefused));
        assert!(
            refused
                .to_string()
                .ends_with("Start it with 'credsd serve'."),
            "{refused}"
        );
        let missing = DaemonError::unreachable(socket, "missing", Some(ErrorKind::NotFound));
        assert!(
            missing
                .to_string()
                .ends_with("Start it with 'credsd serve'."),
            "{missing}"
        );

        for kind in [Some(ErrorKind::PermissionDenied), None] {
            let text = DaemonError::unreachable(socket, "denied", kind).to_string();
            assert!(!text.contains("Start it"), "{text}");
            assert!(
                text.starts_with("cannot reach the daemon at /run/credsd/credsd.sock: denied. "),
                "{text}"
            );
        }
    }
}
