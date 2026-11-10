//! Platform-specific paths for config, data, and runtime directories.

use crate::error::{DaemonError, Result};
use std::path::PathBuf;

/// Resolve the path to the running `credsd` binary for embedding in generated
/// files (aws-config `credential_process`, launchd `ProgramArguments`).
///
/// Fallback chain: `argv[0]` if absolute + exists (preserves symlinks such as
/// `/opt/homebrew/bin/credsd`, which stay valid across Cellar upgrades) →
/// PATH lookup for a bare `argv[0]` → `current_exe()` (resolves symlinks).
pub fn resolve_binary_path() -> Option<PathBuf> {
    if let Some(arg0) = std::env::args().next() {
        let arg0_path = PathBuf::from(&arg0);
        if arg0_path.is_absolute() && arg0_path.exists() {
            return Some(arg0_path);
        }
        if !arg0.contains(std::path::MAIN_SEPARATOR) {
            if let Some(resolved) = resolve_via_path(&arg0) {
                return Some(resolved);
            }
        }
    }
    std::env::current_exe().ok()
}

/// Like [`resolve_binary_path`] but absolute and symlink-resolved — the file that will actually
/// run, not a name that can be repointed at another one afterwards.
pub fn resolve_binary_path_canonical() -> Result<PathBuf> {
    let path = resolve_binary_path().filter(|p| p.is_absolute()).ok_or_else(|| {
        DaemonError::config(
            "cannot determine binary path. Run install from the installed binary, not a temporary location.",
        )
    })?;

    path.canonicalize().map_err(|e| {
        DaemonError::config(format!(
            "cannot resolve binary path {}: {}",
            path.display(),
            e
        ))
    })
}

/// Where `install` stages a service binary that only root can replace, when the running one lives
/// somewhere a non-root user could rewrite.
///
/// A directory install creates itself, rather than a shared `bin` directory it has to hope about.
/// `/usr/local/bin` was the obvious choice and the wrong one: an Intel Homebrew prefix chowns
/// `/usr/local` to the installing admin user, so on exactly the machines that need staging most the
/// destination fails [`only_root_can_replace`] and install could do nothing but refuse. `/opt` is
/// root-owned on Linux, and on macOS is either root-owned or absent — and a directory root creates
/// under a root-owned parent is trusted by construction, on every machine, with nothing for the
/// user to fix first.
///
/// Deliberately off `PATH`: this is the service's copy, not the CLI. Clients keep using whichever
/// `credsd` their `PATH` resolves, install no longer overwrites the symlink `scripts/install.sh`
/// puts in a `bin` directory, and `uninstall` can remove this copy without removing the command.
///
/// Linux has no Homebrew `/usr/local`, so it uses the conventional home for a program run by
/// another program rather than by users: `libexec` under the locally-built-software prefix.
#[cfg(not(target_os = "linux"))]
pub const SERVICE_BINARY_DIR: &str = "/opt/credsd";
#[cfg(target_os = "linux")]
pub const SERVICE_BINARY_DIR: &str = "/usr/local/libexec/credsd";

/// Where Linux installs staged the service binary before [`SERVICE_BINARY_DIR`] moved to
/// `libexec`. Install and uninstall remove a copy left there.
#[cfg(target_os = "linux")]
pub const LEGACY_SERVICE_BINARY_DIR: &str = "/opt/credsd";

/// Whether `path` names a binary that nobody but root can replace — the precondition for baking
/// it into a service definition.
///
/// The privilege story: [`resolve_binary_path`] feeds the `credential_process` line, which runs
/// as the invoking user and so grants them nothing they did not already have. A service binary
/// feeds launchd `ProgramArguments[0]` / systemd `ExecStart=` beside `UserName=credsd` /
/// `User=credsd`, so whatever file it names is what the *service user* executes — and `credsd`
/// owns the keystore and every `callers/<uid>/` tree at 0700. A user-writable path baked in
/// there means any later same-uid write escalates to the service user at the next socket
/// activation, with no root and no sudo prompt.
///
/// Every ancestor is checked, not just the file: a writable directory anywhere along the path
/// lets an attacker rename or unlink their way to replacing the binary wholesale, so proving the
/// file itself is root-owned proves nothing on its own. Ownership *and* mode both matter — a
/// root-owned file in a group-writable directory is replaceable by that group.
///
/// A path that fails this is not an error on its own: `install` stages a copy into
/// [`SERVICE_BINARY_DIR`] and checks that instead. Unreadable ancestors count as untrusted,
/// which sends the caller down the same staging path.
///
/// Hand this a canonical path. Ancestors are taken from the path as spelled while each one is
/// stat'd through symlinks, so a link partway along it is judged on its target's uid and mode
/// while the target's own parents — whoever can rename the target out from under it — are never
/// looked at. [`resolve_binary_path_canonical`] and `install`'s staging directory both
/// canonicalize first for this reason.
#[cfg(unix)]
pub fn only_root_can_replace(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    path.ancestors().all(|ancestor| {
        std::fs::metadata(ancestor)
            // 0o022 = group-write | other-write.
            .map(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
            .unwrap_or(false)
    })
}

fn resolve_via_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// The daemon's data root. A fixed, well-known system path owned by the `credsd` service
/// user — not a per-user home-directory path. Override with `CREDSD_DATA_DIR` (or the
/// legacy `CREDSD_CONFIG_DIR`) for development and testing.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = data_dir_override() {
        return dir;
    }

    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/credsd")
    }

    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\credsd")
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/var/lib/credsd")
    }
}

/// The data-directory variable in effect and its value: `CREDSD_DATA_DIR`, or the legacy
/// `CREDSD_CONFIG_DIR` when the first is unset. An empty value is no override.
fn data_dir_env() -> Option<(&'static str, std::ffi::OsString)> {
    let (name, value) = match std::env::var_os("CREDSD_DATA_DIR") {
        Some(v) => ("CREDSD_DATA_DIR", v),
        None => ("CREDSD_CONFIG_DIR", std::env::var_os("CREDSD_CONFIG_DIR")?),
    };
    (!value.is_empty()).then_some((name, value))
}

/// The data-directory override, when it names an absolute path. A relative one is ignored here
/// with a warning, as a relative `CREDSD_SOCKET` is, for the client's callers. The daemon does not
/// ignore one: it refuses to start (see [`check_data_dir_override`]).
pub fn data_dir_override() -> Option<PathBuf> {
    let (_, value) = data_dir_env()?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        tracing::warn!(
            path = %path.display(),
            "ignoring CREDSD_DATA_DIR: data directory must be absolute",
        );
        return None;
    }
    Some(path)
}

/// Refuses a relative `CREDSD_DATA_DIR` (or `CREDSD_CONFIG_DIR`) in effect. The daemon calls this
/// before anything reads the data directory. Ignoring a relative one would home the daemon on the
/// platform default and mint a new master key there, which is the failure `storage-backend-per-home`
/// Req 4.5 exists to prevent (Req 4.4).
pub fn check_data_dir_override() -> Result<()> {
    match data_dir_env() {
        Some((name, value)) if !std::path::Path::new(&value).is_absolute() => {
            let path = std::path::Path::new(&value);
            Err(DaemonError::config(format!(
                "{name} must be an absolute path, got {path:?}"
            )))
        }
        _ => Ok(()),
    }
}

/// Data directory for a user-scoped install: under `$HOME` so the running uid can write it.
///
/// macOS: `~/Library/Application Support/credsd`
/// Linux: `$XDG_DATA_HOME/credsd` (default `~/.local/share/credsd`)
///
/// The user-install renderers bake this as `CREDSD_DATA_DIR` in the service env so `data_dir()`
/// resolves here for the daemon. `creds` clients inherit it when the shell env is inherited
/// (e.g. a subprocess launched from the login session).
#[cfg(unix)]
pub fn user_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME").filter(|v| !v.is_empty()).map(|h| {
            PathBuf::from(h)
                .join("Library")
                .join("Application Support")
                .join("credsd")
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let base = std::env::var_os("XDG_DATA_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|v| !v.is_empty())
                    .map(|h| PathBuf::from(h).join(".local").join("share"))
            })?;
        Some(base.join("credsd"))
    }
}

/// Client-owned storage: `~/.credsd/`, the one directory the client writes durable state to
/// (`presence-gated-operations` Requirement 5.12). Fixed under `$HOME` and never derived from
/// `CREDSD_DATA_DIR`: a user-scoped install bakes that variable into the daemon's environment,
/// shells can inherit it, and a client that followed it would write into the daemon's storage.
///
/// Created `0700`; refused when it is not a real directory owned by the running uid.
#[cfg(unix)]
pub fn client_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| DaemonError::config("cannot locate ~/.credsd (HOME unset)"))?;
    ensure_user_owned_dir(&PathBuf::from(home).join(".credsd"))
}

/// Create `dir` at `0700` owned by the running uid, or refuse it. Narrows a wider mode an
/// earlier umask left.
#[cfg(unix)]
pub fn ensure_user_owned_dir(dir: &std::path::Path) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .or_else(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => Ok(()),
            _ => Err(e),
        })?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != nix::unistd::geteuid().as_raw() {
        return Err(DaemonError::config(format!(
            "{} is not a directory owned by this user; refusing to keep credsd state in it",
            dir.display()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir.to_path_buf())
}

/// Cache directory for client-generated files: under `$HOME` so only the running uid controls
/// every component a writer below it creates. Never `/tmp` or a session variable such as
/// `XDG_RUNTIME_DIR` / `TMPDIR`, whose absence used to fall back to a path another local user
/// can pre-create.
///
/// macOS: `~/Library/Caches/credsd`
/// Linux: `$XDG_CACHE_HOME/credsd` (default `~/.cache/credsd`)
#[cfg(unix)]
pub fn user_cache_dir() -> Option<PathBuf> {
    cache_dir_from(std::env::var_os("HOME"), std::env::var_os("XDG_CACHE_HOME"))
}

#[cfg(unix)]
fn cache_dir_from(
    home: Option<std::ffi::OsString>,
    xdg_cache_home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    let home = home.filter(|v| !v.is_empty()).map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = {
        let _ = xdg_cache_home;
        home?.join("Library").join("Caches")
    };
    #[cfg(not(target_os = "macos"))]
    let base = xdg_cache_home
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| home.map(|h| h.join(".cache")))?;
    Some(base.join("credsd"))
}

/// Log file for a user-scoped install: inside `user_data_dir()` so the uid can write it.
#[cfg(unix)]
pub fn user_log_file_path() -> Option<PathBuf> {
    user_data_dir().map(|d| d.join("credsd.log"))
}

/// Alias kept for compatibility with call sites that still spell `config_dir`.
pub fn config_dir() -> PathBuf {
    data_dir()
}

/// Default log file for a service install, used when neither `--log-file` nor
/// the `log.file` config key names one. credsd owns this file (open, append,
/// rotate); the platform service manager is never in the logging path.
/// A system path, not a home-directory one: the daemon runs as the scoped `credsd` user, which
/// has no home and cannot write into the installing user's `~/Library/Logs`. Deriving this from
/// `$HOME` would bake the *installer's* home into the service definition and leave the daemon
/// with nowhere to log.
pub fn log_file_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Logs/credsd/credsd.log")
    }

    #[cfg(target_os = "linux")]
    {
        if data_dir_overridden() {
            data_dir().join("credsd.log")
        } else {
            PathBuf::from(SYSTEM_LOG_DIR).join("credsd.log")
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        data_dir().join("credsd.log")
    }
}

/// The Linux system log directory, which the service unit declares as `LogsDirectory=credsd`.
#[cfg(target_os = "linux")]
pub const SYSTEM_LOG_DIR: &str = "/var/log/credsd";

/// A development data root keeps its log beside it, so one instance stays in one directory.
#[cfg(target_os = "linux")]
fn data_dir_overridden() -> bool {
    std::env::var_os("CREDSD_DATA_DIR").is_some() || std::env::var_os("CREDSD_CONFIG_DIR").is_some()
}

/// Root of the per-caller authorization tree: `<data_dir>/callers`. Each authorized
/// caller has a `<uid>/` folder holding an `owner` file (the resolved username at
/// provision time). Deny-by-absence: no folder means the caller cannot connect.
pub fn callers_dir() -> PathBuf {
    data_dir().join("callers")
}

/// The authorization root for one caller uid. The uid is the *only* path component —
/// the username is stored inside `owner`, never in the path, so an NSS/LDAP name with
/// `/`, `@`, or spaces cannot inject into the path or lock the caller out.
pub fn caller_root(uid: u32) -> PathBuf {
    callers_dir().join(uid.to_string())
}

/// The `owner` file inside a caller root, holding the username resolved at provision
/// time. On connect the daemon compares `getpwuid(uid)` to this to detect uid reuse.
pub fn caller_owner_file(uid: u32) -> PathBuf {
    caller_root(uid).join("owner")
}

/// The per-user config file path for the calling process's own UID.
/// This is the file that `credsd config set/get/unset` reads and writes;
/// use this path (not `config_dir()/config.toml`) when telling a user where
/// their config lives.
#[cfg(unix)]
pub fn caller_config_path_for_current_user() -> PathBuf {
    let uid = nix::unistd::getuid().as_raw();
    caller_root(uid).join("config.toml")
}

/// UIDs with a provisioned caller root, for the daemon's background warm loop. Empty
/// when the dir is absent (deny-by-absence: nobody can connect yet).
pub fn provisioned_caller_uids() -> Vec<u32> {
    std::fs::read_dir(callers_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
        .collect()
}

/// Provision the current process's caller root (`callers/<uid>/owner`), so the daemon
/// authorizes this uid. Bootstrap runs client-side and calls this with the client's own
/// `getuid()` + username, so daemon and client agree in single-user runs. The `owner`
/// file is written 0600 (same as `credentials.toml`) via the shared config-file writer.
///
/// Every daemon-facing client command calls this before contacting the daemon, not just
/// bootstrap: it is idempotent (a no-op once `owner` records the current username), so it
/// also self-migrates an install bootstrapped before caller roots existed — the first
/// post-upgrade `get`/`run`/`exec`/`login` provisions instead of getting a 403.
#[cfg(unix)]
pub fn provision_caller() -> Result<PathBuf> {
    let uid = nix::unistd::getuid().as_raw();
    let name = nix::unistd::User::from_uid(nix::unistd::getuid())
        .map_err(|e| DaemonError::config(format!("passwd lookup failed: {e}")))?
        .ok_or_else(|| DaemonError::config("current uid has no passwd entry"))?
        .name;
    provision_caller_at(&callers_dir(), uid, &name)
}

/// Provision the caller root for an arbitrary `uid` by looking up the username via
/// `getpwuid(uid)`. Called by the daemon's bootstrap handler on `Denied(NoRoot)` — the
/// daemon owns `callers/` and is the sole writer, so it auto-provisions on first bootstrap.
/// Idempotent: if `owner` already records the correct username, this is a no-op.
#[cfg(unix)]
pub fn provision_caller_for_uid(uid: u32) -> Result<PathBuf> {
    let name = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .map_err(|e| DaemonError::config(format!("passwd lookup failed: {e}")))?
        .ok_or_else(|| DaemonError::config(format!("uid {uid} has no passwd entry")))?
        .name;
    provision_caller_at(&callers_dir(), uid, &name)
}

/// Write `<callers_root>/<uid>/owner` = `name` (0700 dir, 0600 file) and return the caller
/// root. Idempotent: a no-op when `owner` already records `name`, so callers on the hot
/// `get` path do not rewrite it; a mismatched or absent `owner` is (re)written, which is
/// both first-time provisioning and uid-reuse re-provisioning by the legitimate owner. Pure
/// over `(callers_root, uid, name)` so it is testable without touching the passwd db.
#[cfg(unix)]
pub fn provision_caller_at(
    callers_root: &std::path::Path,
    uid: u32,
    name: &str,
) -> Result<PathBuf> {
    let root = callers_root.join(uid.to_string());
    let owner_file = root.join("owner");
    if std::fs::read_to_string(&owner_file).is_ok_and(|o| o.trim() == name) {
        return Ok(root);
    }
    std::fs::create_dir_all(&root)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    }
    super::write_config_file(&owner_file, &format!("{name}\n"))?;
    Ok(root)
}

/// Windows named-pipe path for this user.
#[cfg(target_os = "windows")]
pub fn runtime_dir() -> PathBuf {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into());
    PathBuf::from(format!(r"\\.\pipe\credsd-{}", user))
}

/// The socket path named by `CREDSD_SOCKET`, if it names a usable one.
///
/// A blank value reads as unset, so an exported-but-empty variable falls through to the
/// config key instead of resolving to an empty path.
///
/// A relative value is refused rather than resolved. Both ends resolve the socket
/// independently — the daemon binds it, every client dials it — so honoring a path that
/// depends on the working directory would let two processes with the same environment
/// disagree about which file to use. The config key rejects relative paths at validation
/// time (see `DaemonConfig::validate`); this is the same rule for the env var, enforced at
/// the only point where a non-fallible resolver can act on it.
pub fn socket_path_from_env() -> Option<PathBuf> {
    let value = std::env::var("CREDSD_SOCKET").ok()?;
    if value.trim().is_empty() {
        return None;
    }

    let path = PathBuf::from(value);
    if !path.is_absolute() {
        tracing::warn!(
            path = %path.display(),
            "ignoring CREDSD_SOCKET: socket path must be absolute",
        );
        return None;
    }
    Some(path)
}

/// The scoped OS user (and group) the daemon runs as under a system install. The daemon
/// owns the keystore + config tree; all runtime is UDS-mediated, so this user needs no
/// elevation. `install` provisions it; the units run the daemon as it.
pub const CREDSD_USER: &str = "credsd";
pub const CREDSD_GROUP: &str = "credsd";

/// The fixed, uid-independent socket path a system-installed daemon binds and every client
/// dials. One `credsd`-owned daemon serves many client uids from this single socket, so the
/// path cannot depend on the connecting uid.
///
/// This is the one constant the install renderer (systemd `ListenStream=` / launchd
/// `SockPathName`), the client dial, and the daemon's bind fallback all read, so the three
/// locations cannot drift. Linux uses `/run/credsd` to match systemd `RuntimeDirectory=credsd`;
/// macOS uses `/var/run/credsd` (launchd creates the parent when it binds the socket).
#[cfg(unix)]
pub fn system_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/run/credsd/credsd.sock")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/run/credsd/credsd.sock")
    }
}

/// The socket path for a user-scoped install: inside `user_data_dir()` so it is always under
/// a directory the login user owns at 0700. Placing it in `/tmp` would allow
/// a local attacker to pre-create the parent and substitute their own socket.
///
/// Returns `None` when `$HOME` is unset — callers must surface this as a configuration error.
#[cfg(unix)]
pub fn user_socket_path() -> Option<PathBuf> {
    user_data_dir().map(|d| d.join("credsd.sock"))
}

/// The socket path for the daemon's bind fallback and `effective_socket_path` when neither
/// `CREDSD_SOCKET` nor the `socket_path` config key is set.
///
/// Returns [`user_socket_path`] for a non-root, non-credsd uid (user-install mode) so the
/// daemon binds a socket it owns. Returns [`system_socket_path`] for root and for the
/// scoped `credsd` OS user (system-install mode). Clients use [`client_socket_path`]
/// instead, which probes for a live user socket before falling back to the system socket.
pub fn default_socket_path() -> PathBuf {
    #[cfg(unix)]
    {
        let euid = nix::unistd::geteuid();
        if !euid.is_root() {
            let is_credsd = nix::unistd::User::from_name(CREDSD_USER)
                .ok()
                .flatten()
                .is_some_and(|u| u.uid == euid);
            if !is_credsd {
                if let Some(p) = user_socket_path() {
                    return p;
                }
            }
        }
        system_socket_path()
    }

    #[cfg(target_os = "windows")]
    {
        runtime_dir()
    }
}

/// The socket a *client* dials: `CREDSD_SOCKET`, then a live user-install socket if one exists,
/// then the system socket.
///
/// Deliberately not [`super::DaemonConfig::effective_socket_path`], which also consults the
/// `socket_path` key. Under a system install the daemon owns `callers/<uid>/config.toml` at 0700
/// and is its sole reader and writer (Req 15), so a client that tried to honor that key would
/// have to read a file it cannot open — and the old idiom swallowed that failure into
/// `DaemonConfig::default()`, arriving at this same default by way of a silent error. Asking for
/// the default directly is the honest spelling of what actually happens. `CREDSD_SOCKET` stays
/// the override for tests and for a dev daemon bound somewhere writable.
///
/// Under a user install no env var is set in the user's shell. Instead this probes
/// `user_socket_path()`: if the file exists as a socket the user daemon is running there, so
/// route to it rather than the system socket. A user with no user-install falls through to the
/// system socket, which is always the final fallback.
pub fn client_socket_path() -> PathBuf {
    if let Some(p) = socket_path_from_env() {
        tracing::info!(socket = %p.display(), source = "CREDSD_SOCKET", "client socket path");
        return p;
    }
    #[cfg(unix)]
    if let Some(user) = user_socket_path() {
        use std::os::unix::fs::FileTypeExt;
        if user
            .metadata()
            .ok()
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
        {
            tracing::info!(socket = %user.display(), source = "user-socket probe", "client socket path");
            return user;
        }
    }
    let p = system_socket_path();
    tracing::info!(socket = %p.display(), source = "system default", "client socket path");
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that read or mutate the process-global `CREDSD_CONFIG_DIR` /
    /// `CREDSD_DATA_DIR` env vars. `cargo test` runs a crate's tests on many threads in one
    /// process, so one test's env write races another's config-path read — observed as a flaky
    /// `caller_config_path_has_correct_structure` failure under the parallel coverage run. Poison
    /// is ignored (`into_inner`): a panic in one guarded test must not fail the others for the
    /// wrong reason.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A world-writable directory anywhere on the path is refused. Written as a mode check rather
    /// than an ownership check on purpose: the suite runs as root in CI containers, where a
    /// tempdir *is* root-owned, so an owner-based negative test would silently pass for the wrong
    /// reason. Mode 0777 is untrusted regardless of who runs the test.
    #[cfg(unix)]
    #[test]
    fn a_world_writable_directory_on_the_path_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("credsd");
        std::fs::write(&binary, b"#!/bin/sh\n").expect("write");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777))
            .expect("chmod");

        assert!(
            !only_root_can_replace(&binary),
            "a world-writable parent must not be trusted"
        );
    }

    /// The daemon runs as `credsd`, whose home is `/var/empty`. A default log path derived from
    /// `$HOME` would name the *installing* user's directory, which install then bakes into the
    /// service definition — leaving the daemon unable to write its own log, and silently, since
    /// logging is the thing that broke.
    #[test]
    fn the_default_log_path_is_not_under_any_home_directory() {
        let log = log_file_path();
        assert!(log.is_absolute(), "{}", log.display());
        for home in ["/Users", "/home"] {
            assert!(!log.starts_with(home), "{}", log.display());
        }
    }

    /// The service unit names `LogsDirectory=credsd` for exactly this directory.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_default_linux_log_is_under_var_log() {
        if data_dir_overridden() {
            return;
        }
        assert_eq!(log_file_path(), PathBuf::from("/var/log/credsd/credsd.log"));
    }

    /// The positive case, on a path both supported platforms ship root-owned: the check must not
    /// be so strict that a correctly installed binary is rejected.
    #[cfg(unix)]
    #[test]
    fn a_root_owned_system_path_is_accepted() {
        let system_binary = std::path::Path::new("/usr/bin/env");
        if !system_binary.exists() {
            return;
        }
        assert!(
            only_root_can_replace(system_binary),
            "{} must be trusted",
            system_binary.display()
        );
    }

    #[test]
    fn default_socket_path_ends_with_sock() {
        let path = default_socket_path();
        #[cfg(unix)]
        assert!(path.to_str().unwrap().ends_with("credsd.sock"));
        #[cfg(target_os = "windows")]
        assert!(path.to_str().unwrap().contains("credsd-"));
    }

    /// The system socket is uid-independent (one `credsd` daemon serves many client uids),
    /// absolute, and the single source the install renderer, the client, and the daemon
    /// fallback share — so `system_socket_path()` is the path a root-or-credsd process
    /// binds and is also the path `client_socket_path()` falls back to when no user daemon
    /// is running.
    #[cfg(unix)]
    #[test]
    fn system_socket_path_is_absolute_uid_independent_and_the_default() {
        let path = system_socket_path();
        assert!(path.is_absolute());
        let uid = nix::unistd::getuid().as_raw().to_string();
        assert!(
            !path.to_str().unwrap().contains(&uid),
            "system socket path must not encode a uid"
        );
        // The system socket is the final fallback for client_socket_path when no user
        // socket exists. Without this, a system-install client dials a path that doesn't
        // exist and every credential command fails silently.
        if socket_path_from_env().is_none() {
            let user_live = user_socket_path().is_some_and(|p| {
                use std::os::unix::fs::FileTypeExt;
                p.metadata()
                    .ok()
                    .map(|m| m.file_type().is_socket())
                    .unwrap_or(false)
            });
            if !user_live {
                assert_eq!(
                    client_socket_path(),
                    path,
                    "client must fall back to the system socket when no user daemon is running"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn cache_dir_is_under_home() {
        let home = Some("/home/alice".into());
        #[cfg(target_os = "macos")]
        let expected = "/home/alice/Library/Caches/credsd";
        #[cfg(not(target_os = "macos"))]
        let expected = "/home/alice/.cache/credsd";
        assert_eq!(
            cache_dir_from(home.clone(), None),
            Some(PathBuf::from(expected))
        );
        assert_eq!(
            cache_dir_from(home, Some("".into())),
            Some(PathBuf::from(expected))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cache_dir_honors_xdg_cache_home() {
        assert_eq!(
            cache_dir_from(Some("/home/alice".into()), Some("/home/alice/xdg".into())),
            Some(PathBuf::from("/home/alice/xdg/credsd"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_dir_needs_home() {
        assert_eq!(cache_dir_from(None, None), None);
        assert_eq!(cache_dir_from(Some("".into()), None), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_client_dir_is_created_owner_only_and_a_symlink_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().expect("tempdir");
        let dir = home.path().join(".credsd");
        let mode =
            |p: &std::path::Path| std::fs::metadata(p).expect("stat").permissions().mode() & 0o777;

        ensure_user_owned_dir(&dir).expect("create");
        assert_eq!(mode(&dir), 0o700);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        ensure_user_owned_dir(&dir).expect("reuse");
        assert_eq!(mode(&dir), 0o700);

        let elsewhere = home.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("mkdir");
        let link = home.path().join("linked");
        std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");
        assert!(ensure_user_owned_dir(&link).is_err());
    }

    /// `provision_caller_at` is the migration seam: it must be safe to call on every
    /// daemon-facing command (idempotent, self-healing) so an install bootstrapped before
    /// caller roots existed provisions on its next `get`/`run`/`login` instead of 403ing.
    /// Driven over the full owner-state space — absent (first run / post-upgrade), matching
    /// (steady state), and a different name (uid reuse) — against the same on-disk layout the
    /// daemon's `resolve_caller` reads, plus the 0700/0600 permission contract.
    #[cfg(unix)]
    #[test]
    fn provision_caller_at_is_idempotent_and_self_heals() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let uid = 4242;

        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        // Absent owner → first-time provision writes `<uid>/owner` = name, 0700 dir / 0600 file.
        let caller = provision_caller_at(root, uid, "alice").unwrap();
        let owner = caller.join("owner");
        assert_eq!(std::fs::read_to_string(&owner).unwrap().trim(), "alice");
        assert_eq!(mode(&caller), 0o700);
        assert_eq!(mode(&owner), 0o600);

        // Matching owner → idempotent no-op that still returns Ok, so the hot `get` path can
        // call it unconditionally without rewriting.
        provision_caller_at(root, uid, "alice").unwrap();
        assert_eq!(std::fs::read_to_string(&owner).unwrap().trim(), "alice");

        // Post-upgrade self-heal: a caller root that never existed is (re)created on the next
        // call — the deny-by-absence 403 turns into a served request.
        std::fs::remove_dir_all(&caller).unwrap();
        assert!(!owner.exists());
        provision_caller_at(root, uid, "alice").unwrap();
        assert_eq!(std::fs::read_to_string(&owner).unwrap().trim(), "alice");

        // uid reuse: a different current owner overwrites the stale username, so the legitimate
        // new owner is authorized rather than denied on OwnerMismatch forever.
        provision_caller_at(root, uid, "bob").unwrap();
        assert_eq!(std::fs::read_to_string(&owner).unwrap().trim(), "bob");
    }

    #[test]
    fn config_dir_honors_env_override_then_falls_back() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os("CREDSD_CONFIG_DIR");
        std::env::set_var("CREDSD_CONFIG_DIR", "/tmp/credsd-test-override");
        assert_eq!(config_dir(), PathBuf::from("/tmp/credsd-test-override"));

        std::env::remove_var("CREDSD_CONFIG_DIR");
        assert_ne!(config_dir(), PathBuf::from("/tmp/credsd-test-override"));

        if let Some(v) = prev {
            std::env::set_var("CREDSD_CONFIG_DIR", v);
        }
    }

    /// A relative override names a different directory from each working directory, so it
    /// is ignored like a relative `CREDSD_SOCKET`; an empty one is ignored too.
    #[test]
    fn only_an_absolute_data_dir_override_is_honored() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev_data = std::env::var_os("CREDSD_DATA_DIR");
        let prev_config = std::env::var_os("CREDSD_CONFIG_DIR");
        std::env::remove_var("CREDSD_CONFIG_DIR");
        let default = {
            std::env::remove_var("CREDSD_DATA_DIR");
            data_dir()
        };

        std::env::set_var("CREDSD_DATA_DIR", "/tmp/credsd-abs-home");
        assert_eq!(
            data_dir_override(),
            Some(PathBuf::from("/tmp/credsd-abs-home"))
        );
        assert_eq!(data_dir(), PathBuf::from("/tmp/credsd-abs-home"));

        for relative in ["home", "./home", "../home", ""] {
            std::env::set_var("CREDSD_DATA_DIR", relative);
            assert_eq!(data_dir_override(), None, "{relative:?}");
            assert_eq!(data_dir(), default, "{relative:?}");
        }

        match prev_data {
            Some(v) => std::env::set_var("CREDSD_DATA_DIR", v),
            None => std::env::remove_var("CREDSD_DATA_DIR"),
        }
        if let Some(v) = prev_config {
            std::env::set_var("CREDSD_CONFIG_DIR", v);
        }
    }

    proptest::proptest! {
        /// A relative override is refused by name and an absolute one passes. Ignoring a relative
        /// one would home the daemon on the platform default and mint a key there (Req 4.4).
        #[test]
        fn a_data_dir_override_must_be_absolute(
            relative in "[a-z][a-z0-9./ ]{0,24}",
            absolute in "/[a-z0-9./ ]{0,24}",
        ) {
            let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let prev_data = std::env::var_os("CREDSD_DATA_DIR");
            let prev_config = std::env::var_os("CREDSD_CONFIG_DIR");
            std::env::remove_var("CREDSD_CONFIG_DIR");
            std::env::set_var("CREDSD_DATA_DIR", &relative);
            let refused = check_data_dir_override().err().map(|e| e.to_string());
            std::env::set_var("CREDSD_DATA_DIR", &absolute);
            let accepted = check_data_dir_override().is_ok();
            match prev_data {
                Some(v) => std::env::set_var("CREDSD_DATA_DIR", v),
                None => std::env::remove_var("CREDSD_DATA_DIR"),
            }
            if let Some(v) = prev_config {
                std::env::set_var("CREDSD_CONFIG_DIR", v);
            }
            proptest::prop_assert!(
                refused
                    .as_deref()
                    .is_some_and(|e| e.contains("CREDSD_DATA_DIR") && e.contains("absolute")),
                "relative {relative:?} was not refused: {refused:?}"
            );
            proptest::prop_assert!(accepted, "absolute {absolute:?} was refused");
        }
    }

    #[cfg(unix)]
    #[test]
    fn caller_config_path_has_correct_structure() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let path = caller_config_path_for_current_user();
        // filename is config.toml
        assert_eq!(path.file_name().unwrap(), "config.toml");
        // parent dir is inside callers_dir() (i.e. callers/<uid>/)
        let parent = path.parent().unwrap();
        assert_eq!(parent.parent().unwrap(), callers_dir());
    }
}
