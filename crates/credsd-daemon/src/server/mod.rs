//! Credential server. `serve` speaks line-delimited JSON-RPC 2.0 (Requirement 9) over a Unix
//! domain socket, authorized by filesystem deny-by-absence keyed on the kernel-verified peer
//! uid (`callers/<uid>/owner`). Peer credentials are the authentication; there is no bearer
//! token. The socket is intentionally reachable by other local uids — under a system install
//! the daemon runs as the scoped `credsd` user and the socket is world-connectable (systemd
//! `SocketMode=0666`, launchd `SockPathMode` 438), because a connection is not a grant: the
//! sole authorization gate is the `callers/<uid>/owner` deny-by-absence check on the peer uid.
//! The one bearer-authenticated TCP listener is the
//! ephemeral `credsd run` proxy in the client bin; it is a compatibility surface for AWS SDKs,
//! not a credsd API, and it dials this daemon over the same JSON-RPC socket.

#[cfg(unix)]
pub mod activation;
#[cfg(unix)]
pub mod bootstrap;
pub mod classify;
pub mod dispatch;
/// End-to-end tests over a real socket; see `e2e.rs`. Test-only, so it is not compiled into
/// the daemon binary.
///
/// Two separate `cfg` attributes rather than `cfg(all(test, unix))`: clippy recognizes a
/// literal `#[cfg(test)]` as test context, which is what applies `clippy.toml`'s
/// `allow-expect-in-tests` and friends. Folded into an `all(..)` it does not, and every
/// `expect` in the harness trips the never-crash lints.
#[cfg(test)]
#[cfg(unix)]
pub(crate) mod e2e;
#[cfg(unix)]
pub mod integrity;
pub mod presence;
pub mod process_tree;
#[cfg(unix)]
pub mod revalidate;
pub mod routes;
#[cfg(unix)]
pub mod uds;
pub(crate) mod write_lock;

use crate::error::Result;
#[cfg(unix)]
use dispatch::Daemon;
use std::sync::Arc;

/// Take a mutex guard, recovering from poisoning rather than propagating the panic.
///
/// Every mutex in the server guards a plain container — the caller registry, the per-uid lock
/// table, an `Option<Sender>`. No invariant spans a critical section, so a panic elsewhere while
/// the lock was held leaves nothing half-written for the next holder to trip over. Propagating it
/// would take a second, unrelated request down with the first, and on the registry it would
/// permanently wedge the daemon for every uid.
pub fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Start the credential daemon on a Unix domain socket.
///
/// Authorization is filesystem deny-by-absence keyed on the kernel-verified peer uid
/// (`callers/<uid>/owner`); there is no bearer token. The listener is either inherited from
/// init (systemd/launchd socket activation, [`activation::activated_listener`]) — in which
/// case init owns the socket's bind and permissions — or bound here as a manual-`serve`
/// fallback ([`uds::prepare_socket`]). The socket may be reachable by other local uids; the
/// authorization gate is the peer-uid check, not the socket's reachability.
#[cfg(unix)]
pub async fn start(storage_backend: &str, insecure_backend: bool) -> Result<()> {
    let backend = credsd_core::storage::select_backend(Some(storage_backend))?;
    if !insecure_backend && backend == credsd_core::storage::Backend::File {
        return Err(crate::error::DaemonError::config(
            "the file backend stores the encryption key as a plain file readable by your \
             uid — any process you run can exfiltrate sealed credentials. Use a \
             hardware-backed backend (data protection keychain or Secure Enclave on macOS, \
             TPM on Linux), or pass `--insecure-backend` to acknowledge this risk.",
        ));
    }
    let encryption = Arc::new(crate::encryption::open_encryption_with_backend(
        storage_backend,
    )?);

    // The socket path: CREDSD_SOCKET → default (user socket for non-root/non-credsd, system
    // socket otherwise). Config is no longer loaded globally; each caller's config is loaded
    // lazily from callers/<uid>/ on first authorized request.
    let socket_path = credsd_core::config::platform::socket_path_from_env()
        .unwrap_or_else(credsd_core::config::platform::default_socket_path);
    let callers_root = crate::config::platform::callers_dir();

    // Prefer an init-provided socket (systemd/launchd activation): init has already bound and
    // permissioned it, so skip both here. Only the manual-`serve` fallback binds + chmods.
    let listener = match activation::activated_listener()? {
        Some(std) => uds::adopt_std_listener(std)?,
        None => uds::prepare_socket(&socket_path)?,
    };

    // The integrity record follows the enrolled-key registry's custody rule (drift-detection
    // Requirement 10.7): one decision, from the backend, for both.
    let slots = backend == credsd_core::storage::Backend::DataProtectionKeychain;
    let home = credsd_core::config::platform::data_dir();
    let (enrolled_keys, integrity) = if slots {
        let store = || credsd_core::storage::create_storage(backend);
        (
            presence::RegistryCustody::slot(store()?, &home),
            integrity::IntegrityCustody::slot(store()?, &home),
        )
    } else {
        (
            presence::RegistryCustody::beside(&callers_root),
            integrity::IntegrityCustody::beside(&callers_root),
        )
    };
    let daemon = Daemon::new(encryption, callers_root, enrolled_keys, integrity);

    uds::serve(listener, daemon).await
}

/// Reject `serve` on platforms without Unix domain sockets.
///
/// Windows needs a Named Pipe with a user-restricted ACL before a persistent listener is
/// safe; loopback TCP has no UID boundary, so it is not an acceptable substitute here.
#[cfg(not(unix))]
pub async fn start(_storage_backend: Option<&str>, _insecure_backend: bool) -> Result<()> {
    Err(crate::error::DaemonError::config(
        "'credsd serve' is not yet supported on this platform (named pipe transport pending).",
    ))
}
