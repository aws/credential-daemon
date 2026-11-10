//! Process hardening — deny external inspection of the daemon's address space.
//!
//! Applied once at `serve` startup, before the encryption key or any credential enters
//! memory. Every control is best-effort: a platform that rejects one logs a warning and
//! the daemon keeps serving, because a defense-in-depth measure must not become an outage.
//!
//! Defends against a same-user process that was never granted a profile, and against core
//! files that outlive the process. Does **not** defend against root or `CAP_SYS_PTRACE`,
//! which bypass every control here by design.

/// Apply every anti-inspection control this platform supports.
///
/// Infallible by signature: there is no caller decision to make, and a `Result` would
/// invite a `?` that turns hardening into a startup failure.
pub fn apply() {
    #[cfg(unix)]
    deny_core_files();

    deny_inspection();
}

/// Suppress core files, which would otherwise write the whole address space — encryption
/// key and every refresh token included — to disk on a crash.
///
/// Not gated on build profile: a core file from a debug daemon holds the same live
/// credentials as one from a release daemon.
#[cfg(unix)]
fn deny_core_files() {
    use nix::sys::resource::{setrlimit, Resource};

    // The hard limit too, not just the soft one: a soft limit is raisable by the process,
    // and by anything that can inject code into it — which is the adversary in question.
    match setrlimit(Resource::RLIMIT_CORE, 0, 0) {
        Ok(()) => tracing::info!("hardening: RLIMIT_CORE=0 (core files suppressed)"),
        Err(e) => tracing::warn!(error = %e, "hardening: could not suppress core files"),
    }
}

/// Deny `ptrace` attach and `/proc/<pid>/{mem,maps,environ}` reads.
///
/// Unconditional across build profiles, unlike the macOS counterpart: clearing the
/// dumpable flag blocks *attach* debugging but not *launch* debugging, because the tracer
/// is established by `execve` before this call and clearing the flag does not detach it.
/// `gdb ./credsd-daemon serve` still works, so a debug-build exemption would recover no workflow
/// and would only leave debug daemons inspectable for nothing.
#[cfg(target_os = "linux")]
fn deny_inspection() {
    // `PR_SET_PTRACER` is deliberately not used: it *grants* a nominated process ptrace
    // permission under Yama, the inverse of the intent here.
    match nix::sys::prctl::set_dumpable(false) {
        Ok(()) => {
            tracing::info!("hardening: PR_SET_DUMPABLE=0 (ptrace attach and /proc/pid/mem denied)")
        }
        Err(e) => tracing::warn!(error = %e, "hardening: could not clear the dumpable flag"),
    }
}

/// Deny debugger attachment on macOS.
///
/// Release builds only, unlike the Linux control: `PT_DENY_ATTACH` obstructs
/// launch-under-debugger as well as attach and offers no escape — under a debugger the
/// process exits with status 45 rather than refusing — so applying it to a debug build
/// would make the daemon undebuggable for no gain on any shipped artifact.
#[cfg(target_os = "macos")]
fn deny_inspection() {
    // `cfg!` rather than `#[cfg]` so the block below still type-checks in debug builds —
    // an attribute gate would exempt the crate's only `unsafe` from `clippy` and `test`,
    // which both run in debug.
    if cfg!(debug_assertions) {
        tracing::debug!("hardening: PT_DENY_ATTACH skipped in a debug build");
        return;
    }

    // Darwin-specific, so `nix` has no binding for it: its ptrace support splits into a
    // Linux module and a shared BSD one, and this request has no FreeBSD/NetBSD
    // counterpart to share. The raw call is the only route.
    const PT_DENY_ATTACH: nix::libc::c_int = 31;

    // SAFETY: `ptrace` is a C entry point with no Rust wrapper for this request.
    // PT_DENY_ATTACH ignores `pid`, `addr`, and `data`; a null `addr` is the documented
    // form. It reads and writes no caller-owned memory, so there is no pointer validity
    // or aliasing obligation beyond passing null. The call affects only the calling
    // process's own trace permission.
    let rc = unsafe {
        nix::libc::ptrace(
            PT_DENY_ATTACH,
            0,
            std::ptr::null_mut::<nix::libc::c_char>(),
            0,
        )
    };

    if rc == 0 {
        tracing::info!("hardening: PT_DENY_ATTACH (debugger attachment denied)");
        return;
    }

    // `ptrace(2)` documents this request as success-or-terminate: a process that is
    // already traced *exits* with status ENOTSUP rather than returning it, and a process
    // that is not just sets the flag and returns 0. So there is no expected nonzero return
    // to special-case — anything landing here is genuinely unexplained.
    tracing::warn!(
        error = %std::io::Error::last_os_error(),
        "hardening: PT_DENY_ATTACH returned unexpectedly"
    );
}

/// Reachable on FreeBSD, where `nix` builds and UDS works, and on Windows, where `serve`
/// refuses to start at all. It must not log success — core-file suppression still applies
/// on the Unix platforms here, so this warns about inspection specifically.
///
/// FreeBSD does have an equivalent, `procctl(PROC_TRACE_CTL, PROC_TRACE_CTL_DISABLE)`, so
/// this arm is a gap in coverage rather than in the platform. Wiring it up means a second
/// raw call: `nix` has no `procctl` binding, and `libc`'s constants are gated to the
/// FreeBSD target, which this project does not build.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn deny_inspection() {
    tracing::warn!("hardening: no anti-inspection control available on this platform");
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // Both tests assert the state read back rather than the call's return value: a
    // wrapper returning `Ok(())` for a no-op would pass the weaker form.
    //
    // Hardening is process-global and `cargo test` runs tests as threads of one process,
    // so each of these changes state for the whole test binary. Both are idempotent and
    // harmless there — a panicking test reports through the harness rather than a core
    // file, and nobody attaches a debugger to a running `cargo test`. The macOS
    // `PT_DENY_ATTACH` path is unreachable here by construction (tests are debug
    // builds), which is a known coverage gap verified manually against a release build.
    //
    // The idempotence that makes them order-independent is why they can only assert the
    // suppressed state. A test needing `RLIMIT_CORE != 0` — raising the limit, asserting
    // the default, or checking that a core file *is* produced when unsuppressed — would be
    // at the mercy of execution order no matter how it is written, since the limit is
    // per-process. Such a test has to run in a subprocess.

    #[test]
    fn core_files_are_suppressed() {
        use nix::sys::resource::{getrlimit, Resource};

        deny_core_files();

        let (soft, hard) = getrlimit(Resource::RLIMIT_CORE).unwrap();
        assert_eq!(soft, 0, "soft RLIMIT_CORE");
        assert_eq!(hard, 0, "hard RLIMIT_CORE");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_dumpable_flag_is_cleared() {
        deny_inspection();

        assert!(!nix::sys::prctl::get_dumpable().unwrap());
    }
}
