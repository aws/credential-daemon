//! One-shot loopback HTTP server for the OAuth authorization-code redirect.
//!
//! Binds an ephemeral `127.0.0.1` port (the `redirect_uri` the browser is sent
//! back to), accepts exactly one request, extracts `code` + `state`, and returns
//! an HTML page. `state` is compared constant-time against the value we sent, so
//! a mismatched/forged redirect is rejected. No hyper — a raw `TcpListener` is
//! enough for a single request, and keeps this off the async runtime.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use crate::error::{DaemonError, Result};

/// The interactive callback times out if the user never completes the browser flow.
pub const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Port range accepted for a fixed callback port. Ports below `MIN` require root to
/// bind; the daemon runs unprivileged, so they always fail at bind time. `MAX` is the
/// OS limit for TCP port numbers.
pub const CALLBACK_PORT_MIN: u16 = 1024;
pub const CALLBACK_PORT_MAX: u16 = u16::MAX;

pub struct CallbackServer {
    listener: TcpListener,
    port: u16,
}

impl CallbackServer {
    /// Bind an ephemeral loopback port. Bind *before* opening the browser so the
    /// `redirect_uri` (which carries the port) is known up front.
    pub fn bind() -> Result<Self> {
        Self::bind_port(0)
    }

    /// Bind a specific port. Use 0 for ephemeral; callers that need a pre-registered redirect
    /// URI (e.g. Cognito exact-match) supply a fixed port in `1024..=65535`.
    pub fn bind_port(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
            if port != 0 {
                crate::error::DaemonError::provider(format!(
                    "could not bind callback port {port}: {e}"
                ))
            } else {
                e.into()
            }
        })?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    pub fn redirect_uri(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    /// Block (up to `timeout`) for the browser redirect; return the authorization
    /// `code`. Synchronous — run under `spawn_blocking`. Rejects a response whose
    /// `state` does not match `expected_state`, or one missing `code`/`state`.
    pub fn wait(
        self,
        expected_state: &str,
        timeout: Duration,
    ) -> Result<zeroize::Zeroizing<String>> {
        self.listener.set_nonblocking(true)?;
        // `Instant + Duration` panics on overflow. A 5-minute deadline cannot overflow a
        // monotonic clock in practice; falling back to "now" makes the flow fail fast rather
        // than crash if it somehow could.
        let now = Instant::now();
        let deadline = now.checked_add(timeout).unwrap_or(now);

        loop {
            if Instant::now() >= deadline {
                return Err(DaemonError::provider(
                    "OAuth login timed out waiting for the browser redirect (5 minutes)",
                ));
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut buf = [0u8; 8192];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let request = String::from_utf8_lossy(buf.get(..n).unwrap_or_default());

                    let callback = parse_callback(&request);
                    // Only a matching `state` proves the redirect is ours, so nothing else may
                    // end the wait. Anything unmatched is answered and ignored: a browser
                    // preconnect, a favicon probe, or another local process poking the port must
                    // not abort a login that has not happened yet.
                    if !callback
                        .state
                        .as_deref()
                        .is_some_and(|state| state_matches(state, expected_state))
                    {
                        let _ = respond(&mut stream, false);
                        continue;
                    }

                    // Ours. Either outcome is final.
                    if let Some(code) = callback.code {
                        let _ = respond(&mut stream, true);
                        return Ok(zeroize::Zeroizing::new(code));
                    }
                    let _ = respond(&mut stream, false);
                    return Err(DaemonError::provider(match callback.error {
                        // The AS told us why — a denied consent, a rejected scope or dpop_jkt, a
                        // redirect_uri mismatch. Reporting it beats waiting out the full timeout
                        // and then blaming the browser.
                        Some(error) => match callback.error_description {
                            Some(description) => {
                                format!("the identity provider rejected the login: {error}: {description}")
                            }
                            None => format!("the identity provider rejected the login: {error}"),
                        },
                        None => "OAuth callback carried a matching state but no code".to_string(),
                    }));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(DaemonError::Io(e)),
            }
        }
    }
}

/// Constant-time equality for the `state` parameter (guards against a forged
/// redirect and avoids leaking the comparison timing).
pub(crate) fn state_matches(got: &str, expected: &str) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(got.as_bytes(), expected.as_bytes()).is_ok()
}

/// What a redirect carried: the success pair, or the AS's error (RFC 6749 §4.1.2.1).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Callback {
    pub(crate) code: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
}

/// Pull the authorization-response parameters out of the request line's query string.
fn parse_callback(request: &str) -> Callback {
    // First line: `GET /callback?code=…&state=… HTTP/1.1`.
    let Some(line) = request.lines().next() else {
        return Callback::default();
    };
    let Some(target) = line.split_whitespace().nth(1) else {
        return Callback::default();
    };
    let Some(query) = target.split_once('?').map(|(_, q)| q) else {
        return Callback::default();
    };
    parse_query(query)
}

/// Pull the authorization-response parameters out of a bare `code=…&state=…` query string.
///
/// Shared with the cross-device flow, which never sees an HTTP request: the user carries the same
/// query string back by hand, so the parameter names must be decoded in exactly one place.
pub(crate) fn parse_query(query: &str) -> Callback {
    let mut callback = Callback::default();
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            match key {
                "code" => callback.code = Some(percent_decode(value)),
                "state" => callback.state = Some(percent_decode(value)),
                "error" => callback.error = Some(percent_decode(value)),
                "error_description" => callback.error_description = Some(percent_decode(value)),
                _ => {}
            }
        }
    }
    callback
}

/// Minimal `application/x-www-form-urlencoded` decode (`%XX` + `+` → space).
///
/// Driven by the byte iterator rather than an index: `next()` is both the bound check and the
/// advance, so a truncated escape at the end of the input cannot read past it. A malformed escape
/// is kept verbatim, which is what the cursor version did.
fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        u8::try_from((b as char).to_digit(16)?).ok()
    }

    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                // Peek the two hex digits without consuming them, so a malformed escape leaves
                // the iterator where it was.
                let mut probe = bytes.clone();
                let decoded = probe
                    .next()
                    .and_then(hex)
                    .zip(probe.next().and_then(hex))
                    .and_then(|(hi, lo)| hi.checked_mul(16)?.checked_add(lo));
                match decoded {
                    Some(byte) => {
                        out.push(byte);
                        bytes = probe;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn respond(stream: &mut std::net::TcpStream, ok: bool) -> std::io::Result<()> {
    let body = if ok {
        "<html><body><h2>credsd: login complete</h2><p>credsd (the local AWS credential daemon) received your sign-in. You can close this tab and return to the terminal.</p></body></html>"
    } else {
        "<html><body><h2>credsd: login failed</h2><p>credsd (the local AWS credential daemon) could not validate the redirect. Return to the terminal.</p></body></html>"
    };
    let status = if ok { "200 OK" } else { "400 Bad Request" };
    write!(
        stream,
        "HTTP/1.1 {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_code_and_state() {
        let req = "GET /callback?code=abc123&state=xyz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        let parsed = parse_callback(req);
        assert_eq!(parsed.code.as_deref(), Some("abc123"));
        assert_eq!(parsed.state.as_deref(), Some("xyz"));
    }

    /// RFC 6749 §4.1.2.1: a rejection arrives as `error`, not as silence. Capturing it is what
    /// lets a denied consent or a bad scope report its cause instead of a 5-minute timeout.
    #[test]
    fn parses_an_error_redirect() {
        let parsed = parse_callback(
            "GET /callback?error=access_denied&error_description=User%20said%20no&state=xyz HTTP/1.1\r\n\r\n",
        );
        assert_eq!(parsed.error.as_deref(), Some("access_denied"));
        assert_eq!(parsed.error_description.as_deref(), Some("User said no"));
        assert_eq!(parsed.state.as_deref(), Some("xyz"));
        assert!(parsed.code.is_none());
    }

    #[test]
    fn percent_decodes_values() {
        let req = "GET /callback?code=a%2Fb%2Bc&state=s HTTP/1.1\r\n\r\n";
        assert_eq!(parse_callback(req).code.as_deref(), Some("a/b+c"));
    }

    #[test]
    fn missing_params_yield_none() {
        assert_eq!(
            parse_callback("GET /callback HTTP/1.1\r\n\r\n"),
            Callback::default()
        );
        let parsed = parse_callback("GET /callback?code=x HTTP/1.1\r\n\r\n");
        assert_eq!(parsed.code.as_deref(), Some("x"));
        assert_eq!(parsed.state, None);
    }

    /// A truncated escape at the very end of the input must not read past it. The cursor version
    /// bounded this with `i + 2 < len`; the iterator walk has to reach the same answer.
    #[test]
    fn truncated_escape_is_kept_verbatim() {
        for (input, want) in [("%", "%"), ("%4", "%4"), ("a%", "a%"), ("a%4", "a%4")] {
            let req = format!("GET /callback?code={input}&state=s HTTP/1.1\r\n\r\n");
            assert_eq!(
                parse_callback(&req).code.as_deref(),
                Some(want),
                "input {input:?}"
            );
        }
    }

    /// A non-hex escape body is not an escape. `%zz` decodes to itself, not to a dropped byte.
    #[test]
    fn non_hex_escape_is_kept_verbatim() {
        let parsed = parse_callback("GET /callback?code=%zz&state=s HTTP/1.1\r\n\r\n");
        assert_eq!(parsed.code.as_deref(), Some("%zz"));
    }

    /// Upper and lower hex both decode, and a decoded byte is never confused for a delimiter:
    /// `%26` is a literal `&` inside the value, not a pair separator.
    #[test]
    fn decodes_either_hex_case() {
        let parsed = parse_callback("GET /callback?code=%2f%2F&state=a%26b HTTP/1.1\r\n\r\n");
        assert_eq!(parsed.code.as_deref(), Some("//"));
        assert_eq!(parsed.state.as_deref(), Some("a&b"));
    }

    /// The listener must be loopback-only. A bind on `0.0.0.0` would expose the redirect — and
    /// with it the authorization code — to the whole network.
    #[test]
    fn listener_binds_loopback_only() {
        let server = CallbackServer::bind().expect("bind");
        let addr = server.listener.local_addr().expect("local_addr");
        assert!(
            addr.ip().is_loopback(),
            "bound {addr}, which is not loopback"
        );
        assert_ne!(
            addr.port(),
            0,
            "an ephemeral port must be resolved after bind"
        );
    }

    /// bind_port(n) on a port something else holds fails and names that port. The earlier form
    /// released an ephemeral port and rebound it; parallel tests binding ephemeral ports could take
    /// it in between, so it failed intermittently with EADDRINUSE.
    #[test]
    fn bind_port_on_a_held_port_names_it() {
        let held = CallbackServer::bind().expect("probe bind");
        let held_port = held.port;

        let err = CallbackServer::bind_port(held_port)
            .err()
            .expect("bind_port on a held port must fail")
            .to_string();
        assert!(err.contains(&format!("port {held_port}")), "{err}");
        drop(held);
    }

    /// Any local process can reach the loopback port, so a request without our `state` must be
    /// answered and ignored rather than ending the wait. `curl 'http://127.0.0.1:PORT/?code=x'`
    /// used to abort a legitimate login with "state mismatch".
    #[test]
    fn a_stray_request_does_not_abort_the_wait() {
        use std::io::Write as _;

        let server = CallbackServer::bind().expect("bind");
        let port = server.listener.local_addr().expect("addr").port();

        let waiter =
            std::thread::spawn(move || server.wait("the-real-state", Duration::from_secs(10)));

        // Two decoys first: a code with no state, then a code with the wrong state.
        for probe in [
            "GET /?code=injected HTTP/1.1",
            "GET /?code=injected&state=wrong HTTP/1.1",
        ] {
            let mut probe_conn =
                std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
            write!(probe_conn, "{probe}\r\nHost: 127.0.0.1\r\n\r\n").expect("write");
            drop(probe_conn);
        }

        // Then the real redirect, which must be the one that wins.
        let mut real = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        write!(
            real,
            "GET /callback?code=good&state=the-real-state HTTP/1.1\r\n\r\n"
        )
        .expect("write");
        drop(real);

        assert_eq!(waiter.join().expect("join").expect("wait").as_str(), "good");
    }

    /// A matching state with an `error` is ours and is final — it must report the AS's reason
    /// rather than waiting out the deadline and blaming the browser.
    #[test]
    fn a_matching_error_redirect_ends_the_wait_with_its_cause() {
        use std::io::Write as _;

        let server = CallbackServer::bind().expect("bind");
        let port = server.listener.local_addr().expect("addr").port();
        let waiter = std::thread::spawn(move || server.wait("s", Duration::from_secs(10)));

        let mut conn = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        write!(
            conn,
            "GET /callback?error=access_denied&error_description=nope&state=s HTTP/1.1\r\n\r\n"
        )
        .expect("write");
        drop(conn);

        let err = waiter
            .join()
            .expect("join")
            .expect_err("must fail")
            .to_string();
        assert!(err.contains("access_denied"), "{err}");
        assert!(err.contains("nope"), "{err}");
    }

    #[test]
    fn state_compare_is_exact() {
        assert!(state_matches("abc", "abc"));
        assert!(!state_matches("abc", "abd"));
        assert!(!state_matches("abc", "ab"));
    }

    #[test]
    fn redirect_uri_uses_bound_port() {
        let s = CallbackServer::bind().unwrap();
        assert!(s.redirect_uri("/callback").starts_with("http://127.0.0.1:"));
        assert!(s.redirect_uri("/callback").ends_with("/callback"));
    }
}
