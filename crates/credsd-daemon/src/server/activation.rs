//! Socket activation: adopt an init-provided listener fd rather than binding one.
//!
//! Under a system service manager the socket is created, bound, and permissioned by init
//! (systemd `.socket`, launchd `Sockets` dict) and the daemon inherits an already-listening
//! fd — init owns the bind and the mode, so the daemon must not bind or chmod. This module
//! turns that inherited fd into a std [`UnixListener`]. A manual `credsd-daemon serve` inherits
//! no such fd and gets `Ok(None)`, so [`super::mod`]'s `start` falls back to
//! [`super::uds::prepare_socket`], which binds and permissions the socket itself.
//!
//! Adoption stops at the std listener on purpose: the caller performs the single
//! `set_nonblocking(true)` + `tokio` conversion ([`super::uds::adopt_std_listener`]) so the
//! activated path and the bind fallback share exactly one route into the async runtime.

#[cfg(unix)]
use crate::error::Result;

/// The plist `Sockets` dict key launchd hands the daemon its socket under. Shared with
/// `install`'s plist renderer so the key it writes and the key this reads cannot drift.
#[cfg(target_os = "macos")]
pub const LAUNCHD_SOCKET_NAME: &str = "Listener";

/// Adopt an init-provided socket, or `Ok(None)` when the daemon was started manually.
///
/// - systemd (Linux): the `listenfd` crate reads `LISTEN_FDS`/`LISTEN_PID`; both unset ->
///   `Ok(None)`.
/// - launchd (macOS): `launch_activate_socket` for [`LAUNCHD_SOCKET_NAME`]; `ENOENT` (this
///   process was not launched by launchd for that key) -> `Ok(None)`.
#[cfg(unix)]
pub fn activated_listener() -> Result<Option<std::os::unix::net::UnixListener>> {
    #[cfg(target_os = "linux")]
    {
        adopt_systemd()
    }
    #[cfg(target_os = "macos")]
    {
        adopt_launchd()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Ok(None)
    }
}

/// systemd passes the first activated socket as fd 3 (`SD_LISTEN_FDS_START`); `listenfd`
/// indexes from 0. It returns `Ok(None)` when `LISTEN_FDS`/`LISTEN_PID` are unset, which is
/// the manual-`serve` fallback.
#[cfg(target_os = "linux")]
fn adopt_systemd() -> Result<Option<std::os::unix::net::UnixListener>> {
    Ok(listenfd::ListenFd::from_env().take_unix_listener(0)?)
}

/// launchd hands the daemon its checked-in socket fd(s) through `launch_activate_socket`,
/// which allocates a fd array the caller owns.
#[cfg(target_os = "macos")]
fn adopt_launchd() -> Result<Option<std::os::unix::net::UnixListener>> {
    use nix::libc::{c_char, c_int, c_void, free};
    use std::os::unix::io::FromRawFd;

    // libSystem export; linked automatically on macOS, so no `#[link]` is needed.
    extern "C" {
        fn launch_activate_socket(
            name: *const c_char,
            fds: *mut *mut c_int,
            cnt: *mut usize,
        ) -> c_int;
    }

    let name = std::ffi::CString::new(LAUNCHD_SOCKET_NAME)
        .map_err(|e| crate::error::DaemonError::config(format!("socket activation name: {e}")))?;
    let mut fds: *mut c_int = std::ptr::null_mut();
    let mut count: usize = 0;

    // SAFETY: `launch_activate_socket` is libSystem's launchd activation entry point. `name`
    // is a valid NUL-terminated C string live for the call. On success it writes, through the
    // out-params, a freshly `malloc`ed array of `count` fds that becomes ours to own — we must
    // `free(fds)` exactly once, which we do below on every path after a `0` return. A nonzero
    // return (e.g. `ENOENT`, "not launched by launchd for this key") allocates nothing, so
    // `fds` stays null and must not be freed.
    let rc = unsafe { launch_activate_socket(name.as_ptr(), &mut fds, &mut count) };
    if rc != 0 {
        return Ok(None);
    }
    if fds.is_null() || count == 0 {
        // SAFETY: freeing a null pointer is a no-op; a non-null pointer here was allocated by
        // the successful call above and is freed exactly once.
        // SAFETY: `fds` is the array `launch_activate_socket` allocated for us. Freeing it is
        // correct even when `count` is 0 — the call still allocated — and there is no fd to leak
        // because none was reported.
        unsafe { free(fds as *mut c_void) };
        return Ok(None);
    }
    // SAFETY: `fds` points to an array of `count >= 1` fds allocated by the call above. We read
    // the first (the socket launchd bound for us) and then free the array; freeing the array
    // does not close the fds it held, so the fd we took remains valid and is owned solely by
    // the `UnixListener` we build from it.
    let fd = unsafe { *fds };
    // SAFETY: same allocation, freed exactly once, and after the read above. Freeing the array
    // does not close the fd it held.
    unsafe { free(fds as *mut c_void) };
    // SAFETY: `fd` is a listening socket fd launchd owns and has handed us exactly once; wrapping
    // it transfers ownership to the listener, which closes it on drop.
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    Ok(Some(listener))
}

// The launchd FFI success path (a real inherited fd) is not unit-testable without a launchd
// supervisor checking a socket in, so it is verified manually against an installed
// LaunchDaemon — the same manual-verification gap `hardening.rs` documents for `PT_DENY_ATTACH`.
#[cfg(all(test, unix))]
mod tests {
    /// With no systemd activation environment, adoption yields `None` so `start` binds the
    /// socket itself. Asserted on Linux, where `listenfd` reads the environment.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_systemd_env_yields_no_listener() {
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_PID");
        assert!(super::activated_listener().unwrap().is_none());
    }

    /// The plist `Sockets` key the daemon reads is the value the install renderer keys the
    /// launchd handoff on. `install`'s own tests assert the rendered plist carries this exact
    /// constant, so the two ends cannot drift; this pins the value it is pinned to.
    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_socket_name_is_listener() {
        assert_eq!(super::LAUNCHD_SOCKET_NAME, "Listener");
    }
}
