//! Unix domain socket setup, permissions, and peer validation.

#[cfg(unix)]
use crate::error::{DaemonError, Result};
#[cfg(unix)]
use crate::server::routes::{CallerAuth, DenyReason};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio::sync::Semaphore;
#[cfg(unix)]
use tracing::{info, warn};

/// Maximum simultaneous open UDS connections across all callers.
#[cfg(unix)]
const MAX_UDS_CONNS: usize = 128;

/// Convert an already-bound std [`UnixListener`] (an init-activated socket, from
/// [`super::activation::activated_listener`]) into the tokio listener `serve` drives.
///
/// This is the single adoption step both paths share: the activated path calls it on the
/// inherited fd, and [`prepare_socket`] ends the manual-`serve` fallback the same way. Nothing
/// here binds or chmods — an activated socket's bind and mode are init's, and the fallback has
/// already done both before reaching the conversion.
#[cfg(unix)]
pub fn adopt_std_listener(std: std::os::unix::net::UnixListener) -> Result<UnixListener> {
    std.set_nonblocking(true)?;
    UnixListener::from_std(std).map_err(Into::into)
}

/// Returns `(parent_mode, socket_mode)` for a socket path.
///
/// System socket → `(0o755, 0o666)`: world-connectable so any local uid can connect; UID auth
/// is the gate (Req 9 AC 5). Any other path (CREDSD_SOCKET override, `socket_path` config key,
/// or a dev `credsd serve`) → `(0o700, 0o600)`: fail-closed — non-root clients cannot connect,
/// which is correct for a non-system socket that was not provisioned for multi-user access.
#[cfg(unix)]
fn socket_modes(path: &Path) -> (u32, u32) {
    let system = credsd_core::config::platform::system_socket_path();
    let canon_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let canon_system = system.canonicalize().unwrap_or(system);
    if canon_path == canon_system {
        (0o755, 0o666)
    } else {
        (0o700, 0o600)
    }
}

/// Bind the UDS listener for the manual-`serve` fallback. Uses [`socket_modes`] to set
/// permissions. Under socket activation init owns the socket and sets its mode; `start` takes
/// [`adopt_std_listener`] and this path never runs.
#[cfg(unix)]
pub fn prepare_socket(path: &Path) -> Result<UnixListener> {
    let parent = path.parent().ok_or_else(|| {
        DaemonError::config(format!(
            "socket path has no parent directory: {}",
            path.display()
        ))
    })?;

    let (parent_mode, socket_mode) = socket_modes(path);

    std::fs::create_dir_all(parent)?;

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(parent_mode))?;

    if path.exists() {
        check_stale_socket(path)?;
    }

    let listener = UnixListener::bind(path)?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode));

    info!(path = %path.display(), "UDS listener bound");
    Ok(listener)
}

#[cfg(unix)]
fn check_stale_socket(path: &Path) -> Result<()> {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(DaemonError::config(
            "another credsd daemon is already running on this socket",
        )),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            warn!(path = %path.display(), "removing stale socket file");
            std::fs::remove_file(path)?;
            Ok(())
        }
        Err(_) => {
            std::fs::remove_file(path)?;
            Ok(())
        }
    }
}

/// Resolve the kernel-verified caller uid to an authorization outcome. Deny-by-absence:
/// a caller is authorized only when `<callers_root>/<uid>/owner` exists and matches the
/// username `getpwuid(uid)` resolves to now (owner-file match detects uid reuse).
///
/// Pure over `(uid, callers_root, passwd lookup)` so tests inject all three. TOCTOU-safe:
/// the caller root is `<callers_root>/<uid>` (uid is the sole path component, never the
/// username) and the `owner` file is opened once — no `exists()`-then-open.
///
/// The fail-closed branches are distinct: `Denied(UnknownUid)` (no passwd entry),
/// `Denied(OwnerMismatch)` (uid reuse), `Denied(NoRoot)` (never provisioned — owner file
/// absent), and `Unresolved` (a transient fault that is not a decision: passwd lookup errored,
/// or the owner file failed to read for a reason other than absence — an NSS/LDAP/FS blip that
/// must not read as a normal deny).
#[cfg(unix)]
pub fn resolve_caller(
    uid: u32,
    callers_root: &Path,
    lookup: impl Fn(u32) -> nix::Result<Option<String>>,
) -> CallerAuth {
    let username = match lookup(uid) {
        Ok(Some(name)) => name,
        Ok(None) => return CallerAuth::Denied(DenyReason::UnknownUid),
        Err(_) => return CallerAuth::Unresolved,
    };
    let root = callers_root.join(uid.to_string());
    match std::fs::read_to_string(root.join("owner")) {
        Ok(owner) if owner.trim() == username => CallerAuth::Authorized { uid, root },
        Ok(_) => CallerAuth::Denied(DenyReason::OwnerMismatch),
        // A missing owner file (or folder) is genuine deny-by-absence. Any other read error
        // (EACCES, EIO) is a transient fault, not a decision — fail closed as `Unresolved`,
        // distinct from a normal deny, mirroring the `getpwuid` Err branch above.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            CallerAuth::Denied(DenyReason::NoRoot)
        }
        Err(_) => CallerAuth::Unresolved,
    }
}

/// The peer's login uid: the audit user id from its audit token. Set when a login session
/// opens and preserved across `sudo`, so it names the human behind a uid-0 approval. `None`
/// when the kernel has no audit user for the session (`AU_DEFAUDITID`).
#[cfg(target_os = "macos")]
fn login_uid(stream: &tokio::net::UnixStream, _pid: Option<i32>) -> Option<u32> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerToken};
    // audit_token_t: [auid, euid, egid, ruid, rgid, pid, asid, pidversion]
    let auid = getsockopt(stream, LocalPeerToken).ok()?.val[0];
    (auid != u32::MAX).then_some(auid)
}

/// The peer's login uid from `/proc/<pid>/loginuid`, set by `pam_loginuid` at login and
/// immutable to the process. `None` when unset (`4294967295`), e.g. for a process no login
/// session started.
#[cfg(target_os = "linux")]
fn login_uid(_stream: &tokio::net::UnixStream, pid: Option<i32>) -> Option<u32> {
    let raw = std::fs::read_to_string(format!("/proc/{}/loginuid", pid?)).ok()?;
    raw.trim().parse::<u32>().ok().filter(|&u| u != u32::MAX)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn login_uid(_stream: &tokio::net::UnixStream, _pid: Option<i32>) -> Option<u32> {
    None
}

/// Production passwd lookup: `getpwuid(uid)` via NSS, returning the username. `None` means
/// the uid has no passwd entry; `Err` is a lookup failure (NSS/LDAP transient).
#[cfg(unix)]
pub fn passwd_lookup(uid: u32) -> nix::Result<Option<String>> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).map(|o| o.map(|u| u.name))
}

/// Accept connections and drive the JSON-RPC codec loop, one task per connection.
///
/// The caller is resolved once per accepted connection via [`resolve_caller`] (Requirement 9
/// AC 6). A denied caller is not dropped at accept: the connection is served so the
/// dispatcher can return a mapped `ENVIRONMENT_NOT_FOUND` rather than a bare reset that reads as
/// a transport failure. Per-request re-sampling (Requirement 14) is a later increment; this
/// keeps the accept-time sample and reuses it for every request on the connection.
#[cfg(unix)]
pub async fn serve(listener: UnixListener, daemon: crate::server::dispatch::Daemon) -> Result<()> {
    use crate::server::routes::{CallerAuth, DenyReason, PeerInfo};

    info!("UDS JSON-RPC listener active");
    let conn_limit = Arc::new(Semaphore::new(MAX_UDS_CONNS));

    loop {
        // Acquire a connection slot before accepting: at the cap this parks the accept loop
        // rather than spawning tasks that immediately drop. The permit is held for the
        // lifetime of the spawned connection task.
        let Ok(permit) = Arc::clone(&conn_limit).acquire_owned().await else {
            return Ok(()); // semaphore is never closed; only if runtime shuts down
        };

        // Transient accept errors (EMFILE, ENOMEM, EINTR) must not kill the daemon;
        // log and continue so existing connections are unaffected. The pause matters: EMFILE
        // persists until a connection closes, so retrying at once spins the CPU and the log.
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "accept() failed, retrying");
                drop(permit);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        let cred = stream.peer_cred().ok();
        let peer_uid = cred.as_ref().map(|c| c.uid());
        let peer_pid = cred.as_ref().and_then(|c| c.pid());

        let auth = match peer_uid {
            Some(uid) => resolve_caller(uid, daemon.callers_root(), passwd_lookup),
            None => CallerAuth::Denied(DenyReason::NoPeerCred),
        };
        match &auth {
            CallerAuth::Authorized { root, .. } => {
                tracing::debug!(uid = peer_uid, pid = peer_pid, root = %root.display(), "accepted UDS connection")
            }
            CallerAuth::Denied(r) => {
                tracing::warn!(uid = peer_uid, reason = ?r, detail = %r, "UDS caller denied")
            }
            CallerAuth::Unresolved => {
                tracing::warn!(
                    uid = peer_uid,
                    "UDS caller passwd lookup failed; failing closed"
                )
            }
        }

        let executable = peer_pid.and_then(|p| u32::try_from(p).ok()).and_then(|p| {
            crate::server::process_tree::binary_path(p)
                .known()
                .map(|p| p.display().to_string())
        });
        let peer = PeerInfo {
            uid: peer_uid,
            pid: peer_pid,
            auth,
            executable,
            login_uid: login_uid(&stream, peer_pid),
        };
        let daemon = daemon.clone();
        tokio::spawn(async move {
            let _permit = permit; // dropped when the connection closes, releasing the slot
            serve_connection(stream, peer, daemon).await;
        });
    }
}

/// Read `\n`-delimited requests, dispatch each, and write responses via an ordered mpsc
/// write channel. Supports streaming notifications for `profile/bootstrap` and
/// `profile/login` by spawning their handlers as separate tokio tasks that send notification
/// bytes through the same channel before the final response.
///
/// Special handling:
/// - `profile/bootstrap` and `profile/login` are spawned as tasks; the loop continues
///   reading while they run (e.g. to receive `profile/bootstrap/respond` notifications).
/// - `profile/bootstrap/respond` is a client-to-daemon notification (no `id`) detected
///   before normal decode and routed into the in-flight `respond_slot`.
/// - Only one bootstrap/login may be in flight at a time; a second attempt returns
///   `PROVIDER_UNAVAILABLE`.
#[cfg(unix)]
async fn serve_connection(
    stream: tokio::net::UnixStream,
    peer: crate::server::routes::PeerInfo,
    daemon: crate::server::dispatch::Daemon,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::server::bootstrap::{handle_profile_bootstrap, handle_profile_login, RespondSlot};
    use crate::server::dispatch::{dispatch, Carrier};
    use credsd_core::rpc::{
        codec, BootstrapRespondParams, DomainCode, Id, Response, RpcError,
        METHOD_PROFILE_BOOTSTRAP, METHOD_PROFILE_BOOTSTRAP_RESPOND, METHOD_PROFILE_LOGIN,
    };
    use serde_json::Value;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::mpsc;

    let (read_half, write_half) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(read_half);

    // All writes (notifications + responses) go through this channel to preserve ordering.
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);

    // Spawn the writer task: drains write_rx into the socket's write half.
    tokio::spawn(async move {
        let mut wh = write_half;
        while let Some(bytes) = write_rx.recv().await {
            if wh.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    // Per-connection state for the in-flight bootstrap/login.
    let respond_slot: RespondSlot = Arc::new(Mutex::new(None));
    let bootstrap_in_flight: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    // Aborted once the connection loop ends, so a client that disconnects mid-login does not
    // leave the spawned task — and the uid's `LoginClaim` it holds — running until
    // `CALLBACK_TIMEOUT`.
    let mut bootstrap_task: Option<tokio::task::JoinHandle<()>> = None;

    let mut line = Vec::new();

    loop {
        line.clear();
        match read_line_bounded(&mut reader, &mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }

        // Detect `profile/bootstrap/respond` BEFORE normal decode: it is a client-to-daemon
        // notification (no `id`) that routes into the respond_slot rather than dispatch.
        // We peek at the raw JSON to check method and id presence without a full decode.
        if let Ok(raw) = serde_json::from_slice::<serde_json::Value>(&line) {
            if raw.get("method").and_then(|m| m.as_str()) == Some(METHOD_PROFILE_BOOTSTRAP_RESPOND)
                && raw.get("id").is_none()
            {
                let params_val = raw
                    .get("params")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                match serde_json::from_value::<BootstrapRespondParams>(params_val) {
                    Ok(params) => {
                        let slot = crate::server::lock(&respond_slot).take();
                        if let Some(tx) = slot {
                            let _ = tx.send(params.selection);
                        } else {
                            tracing::warn!(
                                "environment/bootstrap/respond received with no in-flight bootstrap"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "malformed profile/bootstrap/respond params");
                    }
                }
                continue;
            }
        }

        let request = match codec::decode_request(&line) {
            Ok(r) => r,
            Err(error) => {
                let response: Response<Value> = Response::failure(Id::Null, error);
                if let Ok(bytes) = codec::encode_response(&response) {
                    let _ = write_tx.send(bytes).await;
                }
                break;
            }
        };

        // Bootstrap and login are streamed via spawned tasks.
        if request.method == METHOD_PROFILE_BOOTSTRAP || request.method == METHOD_PROFILE_LOGIN {
            if bootstrap_in_flight.swap(true, Ordering::SeqCst) {
                let response: Response<Value> = Response::failure(
                    request.id,
                    RpcError::domain(
                        DomainCode::ProviderUnavailable,
                        "another bootstrap/login is already in progress on this connection",
                    ),
                );
                if let Ok(bytes) = codec::encode_response(&response) {
                    let _ = write_tx.send(bytes).await;
                }
                continue;
            }

            // Per-uid cap: only one login in flight per uid across all connections.
            // A device flow can block for up to 5 minutes; without this cap a single uid
            // opening many connections could flood the daemon with long-lived tasks.
            let Some(claim) = peer.uid.and_then(|uid| daemon.claim_login(uid)) else {
                bootstrap_in_flight.store(false, Ordering::SeqCst);
                let response: Response<Value> = Response::failure(
                    request.id,
                    RpcError::domain(
                        DomainCode::ProviderUnavailable,
                        "a login is already in progress for this identity",
                    ),
                );
                if let Ok(bytes) = codec::encode_response(&response) {
                    let _ = write_tx.send(bytes).await;
                }
                continue;
            };

            let req = request.clone();
            let method = request.method.clone();
            let req_id = request.id.clone();
            let peer_c = peer.clone();
            let daemon_c = daemon.clone();
            let notif_tx = write_tx.clone();
            let slot = respond_slot.clone();
            let in_flight = bootstrap_in_flight.clone();
            let final_tx = write_tx.clone();

            bootstrap_task = Some(tokio::spawn(async move {
                let result = if method == METHOD_PROFILE_BOOTSTRAP {
                    handle_profile_bootstrap(&req, &peer_c, &daemon_c, notif_tx, slot).await
                } else {
                    handle_profile_login(&req, &peer_c, &daemon_c, notif_tx, slot).await
                };
                // Released before the reply is sent, so a client that retries the moment it reads
                // the reply finds the slot free. A panic or an abort drops `claim` with the future.
                drop(claim);
                in_flight.store(false, Ordering::SeqCst);

                let response: Response<Value> = match result {
                    Ok(value) => Response::success(req_id, value),
                    Err(error) => Response::failure(req_id, error),
                };
                if let Ok(bytes) = codec::encode_response(&response) {
                    let _ = final_tx.send(bytes).await;
                }
            }));

            continue;
        }

        // Normal synchronous dispatch for all other methods.
        let response = dispatch(&request, Carrier::Uds, &peer, &daemon).await;
        match codec::encode_response(&response) {
            Ok(bytes) => {
                if write_tx.send(bytes).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // The connection is gone. A still-running bootstrap/login would otherwise hold its
    // `LoginClaim` until `CALLBACK_TIMEOUT` with nobody left to answer it.
    if let Some(handle) = bootstrap_task {
        handle.abort();
    }
}

/// Read one `\n`-terminated line into `buf`, bounded by [`codec::MAX_LINE_LEN`] so a peer
/// that never sends a newline cannot drive the buffer to grow without limit. Returns the
/// number of bytes read (0 at EOF). Reading byte-at-a-time is cheap over the `BufReader`,
/// which buffers the underlying socket reads.
#[cfg(unix)]
async fn read_line_bounded<R>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use credsd_core::rpc::codec::MAX_LINE_LEN;
    use tokio::io::AsyncReadExt;

    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Ok(buf.len());
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' || buf.len() > MAX_LINE_LEN {
            return Ok(buf.len());
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const UID: u32 = 4242;
    const USER: &str = "alice";

    fn write_owner(callers_root: &Path, contents: &str) -> std::io::Result<()> {
        let root = callers_root.join(UID.to_string());
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("owner"), contents)
    }

    /// `resolve_caller` is pure over `(uid, callers_root, lookup)` with a small finite input
    /// space, so its deny-branch classification is asserted exhaustively rather than by
    /// example: every `{lookup outcome} × {owner state}` combination is driven and its full
    /// mapping checked, including that a lookup error is `Unresolved` and never collapses into
    /// a `Denied` variant (the NSS/LDAP-blip distinction the design requires).
    #[test]
    fn resolve_caller_classifies_every_outcome_exhaustively() {
        #[derive(Clone, Copy)]
        enum Look {
            Named,
            NoEntry,
            Errored,
        }
        #[derive(Clone, Copy)]
        enum OwnerState {
            Absent,
            Matches,
            Mismatch,
        }

        for look in [Look::Named, Look::NoEntry, Look::Errored] {
            for owner in [
                OwnerState::Absent,
                OwnerState::Matches,
                OwnerState::Mismatch,
            ] {
                let tmp = tempfile::tempdir().unwrap();
                match owner {
                    OwnerState::Absent => {}
                    OwnerState::Matches => write_owner(tmp.path(), "alice\n").unwrap(),
                    OwnerState::Mismatch => write_owner(tmp.path(), "bob\n").unwrap(),
                }
                let lookup = move |_uid: u32| -> nix::Result<Option<String>> {
                    match look {
                        Look::Named => Ok(Some(USER.to_string())),
                        Look::NoEntry => Ok(None),
                        Look::Errored => Err(nix::errno::Errno::EIO),
                    }
                };

                let auth = resolve_caller(UID, tmp.path(), lookup);

                match (look, owner) {
                    // A lookup error fails closed as `Unresolved`, distinct from any deny.
                    (Look::Errored, _) => {
                        assert!(matches!(auth, CallerAuth::Unresolved), "lookup error")
                    }
                    // No passwd entry denies regardless of the owner file.
                    (Look::NoEntry, _) => assert!(
                        matches!(auth, CallerAuth::Denied(DenyReason::UnknownUid)),
                        "unknown uid"
                    ),
                    (Look::Named, OwnerState::Absent) => assert!(
                        matches!(auth, CallerAuth::Denied(DenyReason::NoRoot)),
                        "no root"
                    ),
                    (Look::Named, OwnerState::Matches) => assert!(
                        matches!(auth, CallerAuth::Authorized { uid, .. } if uid == UID),
                        "authorized"
                    ),
                    (Look::Named, OwnerState::Mismatch) => assert!(
                        matches!(auth, CallerAuth::Denied(DenyReason::OwnerMismatch)),
                        "owner mismatch"
                    ),
                }
            }
        }
    }

    /// End-to-end over a real socket: the client encodes a `credential/get`, the accept loop
    /// resolves the current uid against a provisioned caller root, the dispatcher serves the
    /// seeded credential, and the client decodes it back to `Credentials`. This is the seam
    /// the transport swap replaces, so it is exercised as a whole rather than only per side.
    #[tokio::test]
    async fn client_and_daemon_round_trip_over_a_real_socket() {
        use crate::server::dispatch::Daemon;
        use credsd_core::config::credentials::{CredentialSource, CredentialSources};
        use credsd_core::config::{DaemonConfig, EnvConfig, SsoConfig};
        use credsd_core::credentials::{CredentialData, Credentials};
        use credsd_core::wire::ClaimedIdentity;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("credsd.sock");
        let callers_root = tmp.path().join("callers");

        // Provision the current uid so `resolve_caller` authorizes the test's own connection.
        let uid = nix::unistd::getuid().as_raw();
        let username = nix::unistd::User::from_uid(nix::unistd::getuid())
            .unwrap()
            .unwrap()
            .name;
        let caller_dir = callers_root.join(uid.to_string());
        std::fs::create_dir_all(&caller_dir).unwrap();
        std::fs::write(caller_dir.join("owner"), format!("{username}\n")).unwrap();

        let key = credsd_core::encryption::generate_key().unwrap();
        let encryption = Arc::new(credsd_core::encryption::EncryptionService::new(key).unwrap());
        let sso = |role: &str| {
            CredentialSource::AwsIdcSso(SsoConfig {
                start_url: "https://example.awsapps.com/start".into(),
                sso_region: "us-east-1".into(),
                account_id: "111111111111".into(),
                role_name: role.into(),
                identity_type: Default::default(),
            })
        };

        let mut config = DaemonConfig::default();
        config.envs.insert("dev".into(), EnvConfig::default());
        // The atom/group scheme: an env whose name is NOT the name of the credential it
        // composes. Resolving `ra-main` requires naming `work` as the authorization context.
        config.envs.insert(
            "work".into(),
            EnvConfig {
                credentials: vec!["ra-main".into()],
                ..Default::default()
            },
        );
        let mut sources = CredentialSources::default();
        sources.insert("dev".into(), sso("Developer"));
        sources.insert("ra-main".into(), sso("Main"));
        let store = Arc::new(crate::credential_store::CredentialStore::new(
            uid,
            &config,
            &sources,
            encryption.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            crate::credential_store::records_verified(),
        ));
        let session = |key: &str| {
            Credentials::session(
                key.into(),
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
                "FwoGZXIvYXdzEBY...".into(),
                chrono::Utc::now() + chrono::Duration::hours(1),
            )
        };
        store
            .inject_for_test_async(uid, "dev", session("AKIAIOSFODNN7EXAMPLE"))
            .await;
        store
            .inject_for_test_async(uid, "ra-main", session("AKIAI44QH8DHBEXAMPLE"))
            .await;
        let daemon = Daemon::with_caller(
            uid,
            config,
            sources,
            store,
            encryption,
            callers_root.clone(),
        );

        let listener = prepare_socket(&socket).unwrap();
        tokio::spawn(async move { serve(listener, daemon).await.ok() });

        let creds = credsd_core::credential_resolve::fetch_from_daemon_uds(
            &socket,
            "dev",
            ClaimedIdentity::Unstated,
        )
        .await
        .expect("client must fetch the seeded credential over the socket");

        match &creds.data {
            CredentialData::SessionCredentials { access_key, .. } => {
                assert_eq!(access_key, "AKIAIOSFODNN7EXAMPLE")
            }
            other => panic!("expected session credentials, got {other:?}"),
        }

        // The atom/group path `credsd exec` relies on: a generated `credential_process` line
        // (`credsd get --env work --credential ra-main`) names the credential and its env
        // together, so the daemon resolves a credential whose name is not itself an env. This
        // is what the transport swap regressed when the client dropped the env context.
        let composed = credsd_core::credential_resolve::fetch_credential_in_env(
            &socket,
            "work",
            "ra-main",
            ClaimedIdentity::Unstated,
        )
        .await
        .expect("a credential must resolve under its env's authority");
        match &composed.data {
            CredentialData::SessionCredentials { access_key, .. } => {
                assert_eq!(access_key, "AKIAI44QH8DHBEXAMPLE")
            }
            other => panic!("expected session credentials, got {other:?}"),
        }

        // The bare credential name is not itself an env, so a request that omits the env
        // context cannot reach it — indistinguishable from an absent subject.
        let no_context = credsd_core::credential_resolve::fetch_from_daemon_uds(
            &socket,
            "ra-main",
            ClaimedIdentity::Unstated,
        )
        .await;
        assert!(matches!(
            no_context,
            Err(credsd_core::error::DaemonError::EnvNotFound(_))
        ));

        // An unknown profile maps back through the wire to the env-not-found the CLI branches on.
        let miss = credsd_core::credential_resolve::fetch_from_daemon_uds(
            &socket,
            "nope",
            ClaimedIdentity::Unstated,
        )
        .await;
        assert!(matches!(
            miss,
            Err(credsd_core::error::DaemonError::EnvNotFound(_))
        ));
    }

    #[test]
    fn socket_modes_system_path_is_world_connectable() {
        let system = credsd_core::config::platform::system_socket_path();
        assert_eq!(socket_modes(&system), (0o755, 0o666));
    }

    #[test]
    fn socket_modes_non_system_path_is_user_only() {
        assert_eq!(socket_modes(Path::new("/tmp/test.sock")), (0o700, 0o600));
    }
}
