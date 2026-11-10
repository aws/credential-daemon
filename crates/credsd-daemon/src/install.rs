//! No static plist or unit files are shipped: the binary renders its own service definition
//! from its own path, so it is the source of truth for it.
//!
//! System services are socket-activated — init binds `platform::system_socket_path()` and hands
//! the daemon the listening fd — so one `credsd`-owned daemon serves every local uid.
//!
//! This module implements the macOS LaunchDaemon and Linux systemd (system) paths. Windows
//! Task Scheduler is a separate follow-up; on unsupported platforms the commands return the
//! "no supported service manager" error.

use crate::error::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct InstallOpts {
    pub log_file: Option<PathBuf>,
    pub storage_backend: Option<String>,
    pub quiet: bool,
    pub user: bool,
    #[cfg_attr(
        not(target_os = "macos"),
        expect(dead_code, reason = "only the macOS user install prompts")
    )]
    pub skip_security_warning: bool,
}

/// Read back out of the installed service definition, never probed: the data protection
/// keychain's availability probe writes and deletes an item, and `status` is a read.
#[derive(Debug, serde::Serialize)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub binary_path: Option<String>,
    pub args: Vec<String>,
    pub storage_backend: Option<String>,
    pub data_dir: Option<String>,
    pub socket_path: Option<String>,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl ServiceStatus {
    fn absent() -> Self {
        Self {
            installed: false,
            running: false,
            binary_path: None,
            args: Vec::new(),
            storage_backend: None,
            data_dir: None,
            socket_path: None,
        }
    }

    /// `data_dir` only when the definition names one, as a user-scoped install does;
    /// otherwise the daemon resolves `platform::data_dir()` and that is what is reported.
    fn installed(
        binary_path: Option<String>,
        args: Vec<String>,
        running: bool,
        data_dir: Option<String>,
        socket_path: Option<String>,
    ) -> Self {
        Self {
            installed: true,
            running,
            binary_path,
            storage_backend: backend_from_args(&args),
            args,
            data_dir: data_dir
                .or_else(|| Some(crate::config::platform::data_dir().display().to_string())),
            socket_path,
        }
    }
}

/// The backend baked into a service definition's arguments. `install` always bakes one, so
/// `None` means a hand-written definition or one predating that.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn backend_from_args(args: &[String]) -> Option<String> {
    args.windows(2).find_map(|pair| match pair {
        [flag, value] if flag == "--storage-backend" => Some(value.clone()),
        _ => None,
    })
}

fn build_serve_args(opts: &InstallOpts) -> Vec<String> {
    let mut args = Vec::new();
    if !opts.user {
        args.push("--system".to_string());
    }
    if opts
        .storage_backend
        .as_deref()
        .map(|s| s == "file")
        .unwrap_or(false)
    {
        args.push("--insecure-backend".to_string());
    }
    args
}

/// Only bake `--log-file` when the operator passed it explicitly. When absent, the daemon
/// applies the documented precedence at startup (flag > [log] in config.toml > env > default)
/// as the service account, not as root. Baking a platform default here would break that
/// precedence and would prevent [log] file from ever taking effect.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn resolve_log_file(opts: &InstallOpts) -> Option<PathBuf> {
    opts.log_file.clone()
}

/// Returns `true` when every ancestor of `path` is a directory another local user cannot
/// substitute: a writable ancestor lets them replace a binary baked into a LaunchAgent /
/// user unit, gaining code execution as the served user at login.
#[cfg(target_os = "macos")]
fn all_ancestors_user_only(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let uid = nix::unistd::getuid().as_raw();
    let trusted_gid = trusted_group_gid();
    path.ancestors().all(|ancestor| {
        std::fs::metadata(ancestor)
            .map(|m| ancestor_trusted(m.uid(), m.gid(), m.mode(), uid, trusted_gid))
            .unwrap_or(false)
    })
}

/// Pure half of [`all_ancestors_user_only`], so the policy is testable without a tree whose
/// ownership only root can create.
#[cfg(target_os = "macos")]
fn ancestor_trusted(
    anc_uid: u32,
    anc_gid: u32,
    mode: u32,
    uid: u32,
    trusted_gid: Option<u32>,
) -> bool {
    if anc_uid != 0 && anc_uid != uid {
        return false;
    }
    if mode & 0o002 != 0 {
        return false;
    }
    if mode & 0o020 == 0 {
        return true;
    }
    const S_IFDIR: u32 = 0o040000;
    anc_uid == 0 && mode & S_IFDIR != 0 && trusted_gid.is_some_and(|g| g == anc_gid)
}

/// The gid a root-owned ancestor may additionally be group-writable by: macOS grants
/// `/Applications` to `admin`.
#[cfg(target_os = "macos")]
fn trusted_group_gid() -> Option<u32> {
    use std::sync::OnceLock;
    static GID: OnceLock<Option<u32>> = OnceLock::new();
    *GID.get_or_init(|| {
        nix::unistd::Group::from_name("admin")
            .ok()
            .flatten()
            .map(|g| g.gid.as_raw())
    })
}

/// `log_file` is baked in so the service manager stays out of the logging path, which is the
/// only arrangement in which credsd's size-based rotation can fire.
///
/// `pub` so the binary crate can assert every flag emitted here parses: a definition `serve`
/// would reject fails at startup, where nobody is watching.
pub fn program_arguments(opts: &InstallOpts, log_file: Option<&Path>) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(ref backend) = opts.storage_backend {
        args.push("--storage-backend".to_string());
        args.push(backend.clone());
    }
    if let Some(log) = log_file {
        args.push("--log-file".to_string());
        args.push(log.display().to_string());
    }
    args.push("serve".to_string());
    args.extend(build_serve_args(opts));
    args
}

/// The break-glass alternative for editing config as the service user is `sudo -u credsd`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn require_root() -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    Err(crate::error::DaemonError::config(
        "credsd install/uninstall must run as root (sudo): it provisions the 'credsd' service \
         user and writes system-level service units. Runtime is unprivileged; only install \
         needs root.",
    ))
}

/// Root-owned on every supported platform; ordered so the `sbin` copy of an administrative tool
/// wins where distributions ship both.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const TOOL_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// `install` runs as root, so *how* the program name becomes a path is a privilege boundary.
/// `Command::new("chown")` resolves it through the invoking user's `PATH`, and macOS `sudo` uses
/// `env_reset` without `secure_path`, so `sudo credsd install` keeps that `PATH` — a same-uid
/// attacker's `~/bin/chown` would then run as root. (On Debian/RHEL `secure_path` narrows this to
/// `sudo -E`, `su`, and root shells, which is a smaller hole, not a closed one.) Resolving here
/// means the only file that can be executed is one already in a root-owned system directory.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn tool_path(program: &str) -> Result<std::path::PathBuf> {
    TOOL_DIRS
        .iter()
        .map(|dir| Path::new(dir).join(program))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            crate::error::DaemonError::config(format!(
                "cannot find '{program}' in {}",
                TOOL_DIRS.join(":")
            ))
        })
}

/// The `PATH` is narrowed too, so anything the tool itself execs resolves the same way.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn tool_command(program: &str) -> Result<std::process::Command> {
    let mut cmd = std::process::Command::new(tool_path(program)?);
    cmd.env("PATH", TOOL_DIRS.join(":"));
    Ok(cmd)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_tool(program: &str, args: &[&str]) -> Result<()> {
    let status = tool_command(program)?
        .args(args)
        .status()
        .map_err(|e| crate::error::DaemonError::config(format!("failed to run {program}: {e}")))?;
    if status.success() {
        return Ok(());
    }
    Err(crate::error::DaemonError::config(format!(
        "{program} {} exited with failure",
        args.join(" ")
    )))
}

/// Mint (or load) the master encryption key as the current process, which is root during
/// install. `own_tree()` must follow, to chown the created key files to the service user.
///
/// Not for the Secure Enclave — see `macos::mint_enclave_key_under_launchd`. The TPM is fine,
/// its gate being access to the device node.
///
/// KKRS is skipped: its key lives in the kernel user-keyring (per-uid), which root cannot
/// create on behalf of `credsd`. The KKRS reboot-recovery path in `open_encryption_with_backend`
/// handles the first startup as the service user.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn init_keystore(backend: &str) -> Result<()> {
    if backend == credsd_core::storage::Backend::KernelKeyring.as_str() {
        return Ok(());
    }
    credsd_core::encryption::ensure_system_service_key(backend).map_err(|e| {
        crate::error::DaemonError::config(format!(
            "failed to initialize keystore for backend '{backend}': {e}. \
                 Re-run 'sudo credsd install' to retry."
        ))
    })
}

/// `-R` belongs here and nowhere else: this is a directory credsd alone uses, and a reinstall has
/// to repair a tree an earlier one left behind. See [`create_owned_dir`].
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn own_tree() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let root = crate::config::platform::data_dir();
    if let Ok(m) = std::fs::symlink_metadata(&root) {
        if m.file_type().is_symlink() {
            return Err(crate::error::DaemonError::config(format!(
                "refusing to install: data directory {} is a symlink. Remove it before installing.",
                root.display(),
            )));
        }
        let service_uid = service_user_uid().unwrap_or(u32::MAX);
        if m.uid() != 0 && m.uid() != service_uid {
            return Err(crate::error::DaemonError::config(format!(
                "refusing to install: data directory {} already exists and is owned by uid {} \
                 (expected root or '{}'). Remove it or correct its ownership before installing.",
                root.display(),
                m.uid(),
                crate::config::platform::CREDSD_USER,
            )));
        }
    }
    create_owned_dir(&root, 0o755)?;
    // -h (lchown) so chown never follows symlinks a service-uid attacker may have planted
    // inside a pre-existing data tree.
    run_tool(
        "chown",
        &["-Rh", &service_owner(), &root.display().to_string()],
    )
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn service_owner() -> String {
    format!(
        "{}:{}",
        crate::config::platform::CREDSD_USER,
        crate::config::platform::CREDSD_GROUP
    )
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn service_user_uid() -> Result<u32> {
    nix::unistd::User::from_name(crate::config::platform::CREDSD_USER)
        .ok()
        .flatten()
        .map(|user| user.uid.as_raw())
        .ok_or_else(|| {
            crate::error::DaemonError::config(format!(
                "service user '{}' does not exist after provisioning it",
                crate::config::platform::CREDSD_USER
            ))
        })
}

/// Create the log file's directory and hand it to the service user. credsd opens, appends to and
/// rotates its own log, so the directory has to be writable by `credsd` — a root-owned one leaves
/// the daemon with nowhere to log, and the failure is invisible precisely because logging is what
/// broke.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn own_log_dir(log_file: &Path) -> Result<()> {
    own_log_dir_for_uid(log_file, service_user_uid()?)
}

/// Only a directory that is install's to give: one that does not exist yet, or one the service
/// user already owns.
///
/// `--log-file` names an arbitrary path, so chowning its parent unconditionally would seize
/// whatever the caller named — `--log-file /var/log/credsd.log` hands every other service's logs
/// to `credsd`, and `--log-file /credsd.log` hands it `/`. Somebody else's directory is refused
/// rather than left alone, because credsd creates and rotates files *in* it, so one it cannot
/// write reproduces the invisible failure this path exists to close.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn own_log_dir_for_uid(log_file: &Path, service_uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let Some(dir) = log_file.parent() else {
        return Ok(());
    };

    // `symlink_metadata`, not `metadata`: a symlink here would have the ownership check read its
    // target, and a dangling one would read as absent and send install down the create path.
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) if !metadata.is_dir() => Err(not_a_directory(dir)),
        Ok(metadata) if metadata.uid() == service_uid => restrict_dir(dir, LOG_DIR_MODE),
        Ok(metadata) => Err(crate::error::DaemonError::config(format!(
            "refusing to install: log directory {} already exists and is owned by uid {}, not \
             '{}'. install does not take ownership of a directory it did not create — point \
             --log-file at a directory of its own, or chown this one to '{}'.",
            dir.display(),
            metadata.uid(),
            crate::config::platform::CREDSD_USER,
            crate::config::platform::CREDSD_USER,
        ))),
        // No such directory: install creates it, so it is install's to give away.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_owned_dir(dir, LOG_DIR_MODE),
        Err(e) => Err(crate::error::DaemonError::config(format!(
            "cannot inspect log directory {}: {}",
            dir.display(),
            e
        ))),
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn not_a_directory(dir: &Path) -> crate::error::DaemonError {
    crate::error::DaemonError::config(format!(
        "refusing to install: {} exists and is not a directory (a symlink is refused, not \
         followed). Remove it before installing.",
        dir.display()
    ))
}

/// Not recursive, unlike [`own_tree`]. Callers reach this for a directory that did not exist a
/// moment ago, so there is nothing legitimate underneath, while a `--log-file` under a
/// user-writable ancestor gives that user a window to plant entries inside the new directory for
/// a recursive `chown` to walk.
///
/// `mode` applies only to `dir` itself, and only when this call creates it: ancestors keep the
/// umask so the service user can still traverse them.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn create_owned_dir(dir: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let cannot_create = |e: std::io::Error| {
        crate::error::DaemonError::config(format!(
            "cannot create directory {}: {}",
            dir.display(),
            e
        ))
    };
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(cannot_create)?;
    }
    match std::fs::DirBuilder::new().mode(mode).create(dir) {
        Ok(()) => {}
        // `mkdir` reports EEXIST for a symlink too, dangling or not — which is what a symlink
        // planted between the caller's check and this call looks like.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if !std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()) {
                return Err(not_a_directory(dir));
            }
        }
        Err(e) => return Err(cannot_create(e)),
    }
    // -h (lchown): a directory swapped for a symlink after the check above still has only the
    // link chowned, never what it points at.
    run_tool(
        "chown",
        &["-h", &service_owner(), &dir.display().to_string()],
    )
}

/// The log holds profile names, role ARNs and caller usernames. Its files are created 0600, but
/// only the directory keeps other uids from listing it or catching a rotation in flight.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const LOG_DIR_MODE: u32 = 0o700;

/// An earlier install created the log directory at the umask, and `create_owned_dir` does not
/// touch a directory that already exists.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn restrict_dir(dir: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        crate::error::DaemonError::config(format!("cannot restrict {}: {}", dir.display(), e))
    })
}

/// The binary the service definition will name, and where it came from.
///
/// `copied_from` is `None` when the running binary was already safe to bake in. When it is `Some`,
/// the service will run a *different* file from the one the user invoked, which they have to be told
/// — see [`ServiceBinary::warning`].
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Debug)]
struct ServiceBinary {
    path: PathBuf,
    copied_from: Option<PathBuf>,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl ServiceBinary {
    /// Staging is invisible otherwise, and its consequence is not: rebuilding or upgrading the
    /// binary they invoked leaves the service on the old copy. A user who is never told that
    /// debugs a daemon that ignores their changes.
    fn warning(&self) -> Option<String> {
        let src = self.copied_from.as_ref()?;
        Some(format!(
            "warning: {src} can be modified by a non-root user, and the service runs as '{user}', \
             so install staged a root-owned copy of it at {dst}.\n         \
             The service runs that copy: rebuilding or upgrading {src} does NOT update the \
             service. Re-run `sudo credsd install` to stage a new build, `credsd status` to see \
             which file the service runs, and `sudo credsd uninstall` to remove the copy.",
            src = src.display(),
            dst = self.path.display(),
            user = crate::config::platform::CREDSD_USER,
        ))
    }
}

/// Copying rather than refusing is the point. Every documented way to obtain credsd — a build
/// tree, `cargo install`, a Homebrew prefix — leaves the binary somewhere its owner can rewrite,
/// and baking that path in next to `User=credsd` would hand the service user to whoever owns it
/// (see `platform::only_root_can_replace`). Telling the user to copy it themselves asks them to
/// perform, by hand, the one step install is for.
///
/// Written through a temporary file and renamed: `fs::copy` onto the destination would fail with
/// `ETXTBSY` while an installed daemon is running it, and a half-written binary would be worse.
/// A destination directory that is not root-owned refuses before anything is written, which is
/// also what makes the temporary name safe to write to.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn stage_service_binary() -> Result<ServiceBinary> {
    stage_service_binary_in(
        Path::new(crate::config::platform::SERVICE_BINARY_DIR),
        crate::config::platform::resolve_binary_path_canonical()?,
    )
}

/// Parameterized so the early-return and refusal branches are reachable from a test without root.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn stage_service_binary_in(configured_dir: &Path, src: PathBuf) -> Result<ServiceBinary> {
    use crate::config::platform;

    if platform::only_root_can_replace(&src) {
        return Ok(ServiceBinary {
            path: src,
            copied_from: None,
        });
    }

    let context = |e: std::io::Error| {
        crate::error::DaemonError::config(format!(
            "cannot stage the service binary in {}: {}",
            configured_dir.display(),
            e
        ))
    };

    // Trust is settled on the deepest ancestor that already exists, and settled before anything is
    // created. Three things fall out of that ordering. A refused install leaves no directory
    // behind. Whatever root creates *below* an anchor only root can write is trusted by
    // construction, so one check covers the whole path — which is why the destination is a
    // directory install creates (`platform::SERVICE_BINARY_DIR`) and not a shared `bin`. And the
    // message names the component actually at fault, rather than the binary's location, which
    // staging does not depend on.
    //
    // The anchor is canonicalized because `only_root_can_replace` walks the ancestors of the path
    // it is handed while stat'ing each one through symlinks: on an unresolved path, a root-owned
    // directory symlinked into a user-writable tree passes on its target's uid and mode while the
    // target's real parents — whoever can rename the target out from under it — go unchecked.
    let anchor = configured_dir
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .unwrap_or(Path::new("/"))
        .canonicalize()
        .map_err(context)?;
    if !platform::only_root_can_replace(&anchor) {
        return Err(crate::error::DaemonError::config(format!(
            "refusing to install: {anchor} is not root-owned, or is writable by a non-root user, \
             so anything install put under it — including the binary the service runs as \
             '{user}' — could be replaced afterwards. Nothing was written. Restore {anchor} to \
             root ownership (mode 755 or stricter) and run install again.",
            anchor = anchor.display(),
            user = platform::CREDSD_USER,
        )));
    }

    std::fs::create_dir_all(configured_dir).map_err(context)?;
    let dir = configured_dir.canonicalize().map_err(context)?;

    #[cfg(target_os = "macos")]
    if let Some(bundle) = bundle_root(&src) {
        return stage_service_bundle_in(&dir, bundle, &src);
    }

    let dst = dir.join("credsd");
    let tmp = dir.join(".credsd.staging");

    let staged = write_root_owned_copy(&src, &tmp);
    if staged.is_err() {
        // A staging file left behind is the hazard `write_root_owned_copy` documents, so a failed
        // install must not leave one for the next one to find.
        let _ = std::fs::remove_file(&tmp);
    }
    staged?;

    std::fs::rename(&tmp, &dst).map_err(context)?;
    Ok(ServiceBinary {
        path: dst,
        copied_from: Some(src),
    })
}

/// The application bundle a daemon executable lives inside, if it lives in one:
/// `<name>.app/Contents/MacOS/<exe>`. Its entitlements are authorized by the bundle's
/// `embedded.provisionprofile`, so an executable copied out alone is killed by AMFI at exec.
#[cfg(target_os = "macos")]
fn bundle_root(binary: &Path) -> Option<&Path> {
    let macos_dir = binary.parent()?;
    let contents = macos_dir.parent()?;
    let bundle = contents.parent()?;
    (macos_dir.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle.extension()? == "app")
        .then_some(bundle)
}

/// Fixed, so `uninstall` finds a staged bundle without knowing the source's name.
#[cfg(target_os = "macos")]
const SERVICE_BUNDLE_NAME: &str = "Credsd.app";
#[cfg(target_os = "macos")]
const STAGING_BUNDLE_NAME: &str = ".credsd.staging.app";
#[cfg(target_os = "macos")]
const SUPERSEDED_BUNDLE_NAME: &str = ".credsd.superseded.app";

/// `/bin/cp -R` rather than a walk here, because macOS `fs::copy` preserves the source's owner
/// when root calls it while `cp` creates each file as the caller. `chmod -R go-w` follows since
/// modes come from the source; `only_root_can_replace` is then asserted rather than assumed.
#[cfg(target_os = "macos")]
fn stage_service_bundle_in(dir: &Path, bundle: &Path, src: &Path) -> Result<ServiceBinary> {
    let context = |e: std::io::Error| {
        crate::error::DaemonError::config(format!(
            "cannot stage the service bundle in {}: {}",
            dir.display(),
            e
        ))
    };
    let rel = src.strip_prefix(bundle).map_err(|_| {
        crate::error::DaemonError::config(format!(
            "{} is not inside {}",
            src.display(),
            bundle.display()
        ))
    })?;

    let tmp = dir.join(STAGING_BUNDLE_NAME);
    let dst = dir.join(SERVICE_BUNDLE_NAME);
    let superseded = dir.join(SUPERSEDED_BUNDLE_NAME);

    let _ = std::fs::remove_dir_all(&tmp);
    let (from, to) = (bundle.display().to_string(), tmp.display().to_string());
    run_tool("cp", &["-R", &from, &to])?;
    run_tool("chmod", &["-R", "go-w", &to])?;

    // `rename` cannot replace a non-empty directory, so the previous bundle moves aside
    // first. A daemon running from it keeps its open inode, so no `ETXTBSY` care is needed.
    let _ = std::fs::remove_dir_all(&superseded);
    let had_previous = dst.exists();
    if had_previous {
        std::fs::rename(&dst, &superseded).map_err(context)?;
    }
    if let Err(e) = std::fs::rename(&tmp, &dst) {
        if had_previous {
            let _ = std::fs::rename(&superseded, &dst);
        }
        return Err(context(e));
    }

    // Kept until the check below passes: discarding it first would leave a reinstall that
    // fails here with neither bundle, and a service definition naming a path inside one.
    let staged = dst.join(rel);
    if !crate::config::platform::only_root_can_replace(&staged) {
        let _ = std::fs::remove_dir_all(&dst);
        if had_previous {
            let _ = std::fs::rename(&superseded, &dst);
        }
        return Err(crate::error::DaemonError::config(format!(
            "refusing to install: the staged copy of {src} at {staged} is still replaceable by \
             a non-root user, so the service would not be safe to point at it. The staged copy \
             was removed and any previously installed bundle restored. Check the ownership and \
             modes inside {bundle}.",
            src = src.display(),
            staged = staged.display(),
            bundle = bundle.display(),
        )));
    }
    let _ = std::fs::remove_dir_all(&superseded);

    Ok(ServiceBinary {
        path: staged,
        copied_from: Some(src.to_path_buf()),
    })
}

/// Safe for `uninstall` to do because [`platform::SERVICE_BINARY_DIR`] is off `PATH` and only ever
/// holds this copy: no client is resolving `credsd` through it, so removing it cannot take the CLI
/// away. Leaving it would leave a root-owned binary behind forever on a machine that asked for the
/// service to be gone.
///
/// Best-effort. A machine that never staged has nothing here, and a failure to remove an inert file
/// must not fail an uninstall that already removed the service definition.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn remove_staged_binary() {
    remove_staged_binary_in(Path::new(crate::config::platform::SERVICE_BINARY_DIR));
    #[cfg(target_os = "linux")]
    remove_staged_binary_in(Path::new(
        crate::config::platform::LEGACY_SERVICE_BINARY_DIR,
    ));
}

/// An earlier install's copy in `legacy_dir` is root-owned, so it passes the check that decides
/// whether to stage, and `sudo /opt/credsd/credsd install` bakes that very file into the unit.
/// Removing it then would leave the unit naming a deleted binary.
#[cfg(target_os = "linux")]
fn remove_superseded_staged_binary(service_binary: &Path, legacy_dir: &Path) {
    if !service_binary.starts_with(legacy_dir) {
        remove_staged_binary_in(legacy_dir);
    }
}

/// Removes only the two names staging writes; `remove_dir` then succeeds only if nothing else is
/// there, so a directory something else also uses is left in place.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn remove_staged_binary_in(dir: &Path) {
    let _ = std::fs::remove_file(dir.join("credsd"));
    let _ = std::fs::remove_file(dir.join(".credsd.staging"));
    #[cfg(target_os = "macos")]
    for bundle in [
        SERVICE_BUNDLE_NAME,
        STAGING_BUNDLE_NAME,
        SUPERSEDED_BUNDLE_NAME,
    ] {
        let _ = std::fs::remove_dir_all(dir.join(bundle));
    }
    let _ = std::fs::remove_dir(dir);
}

/// `fs::copy` cannot be used here. macOS routes it through `copyfile`, which preserves the source's
/// owner when the caller is root, so the staging file would spend the whole copy — and every
/// instruction up to a chown that followed it — owned and writable by whoever owns the build
/// artifact. Unix checks permissions at `open`, and neither `chown` nor `rename` changes the inode,
/// so a writable fd obtained inside that window stays writable afterwards: a handle on the binary
/// the service user executes, held by a same-uid process that never needed root.
///
/// The leftover case is worse than the race, because it needs no timing at all. A staging file
/// abandoned by a failed install is owned by that same non-root user, and a copy that reused it
/// would truncate *their* inode and rename it into place — so the file must be created here, never
/// reused, which is what `create_new` is for. Root can unlink a stale one first; a non-root user
/// cannot put it back, because the caller has already proven this directory is root-writable only.
///
/// Mode starts at 0o700 so a partially written binary is never executable, and widens to 0o755 only
/// once the bytes are all there. Ownership needs no correcting: root created the file.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn write_root_owned_copy(src: &Path, tmp: &Path) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let context = |e: std::io::Error| {
        crate::error::DaemonError::config(format!("cannot write {}: {}", tmp.display(), e))
    };

    let _ = std::fs::remove_file(tmp);
    let mut staged = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(tmp)
        .map_err(context)?;
    let mut source = std::fs::File::open(src).map_err(|e| {
        crate::error::DaemonError::config(format!("cannot read {}: {}", src.display(), e))
    })?;

    std::io::copy(&mut source, &mut staged).map_err(context)?;
    std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(0o755)).map_err(context)
}

#[cfg(target_os = "macos")]
const USER_INSTALL_WARNING: &str = "\
WARNING: user-scoped install — secrets live in your home directory.

A system install stores sealed key material under the 'credsd' OS user, which
your processes cannot read directly. A user install stores it under your uid:
any process running as your OS user can copy the sealed blobs and attempt
offline attacks or replay them on another machine.

Only proceed if sudo credsd install is not an option.
Type 'yes' to continue: ";

/// Reads /dev/tty, not stdin, so a redirect or a script cannot answer the prompt.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn confirm_typed_yes(warning: &str) -> Result<bool> {
    use std::io::{BufRead, Write};

    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| crate::error::DaemonError::config(format!("cannot open /dev/tty: {e}")))?;

    write!(tty, "{warning}")
        .map_err(|e| crate::error::DaemonError::config(format!("cannot write to /dev/tty: {e}")))?;
    tty.flush()
        .map_err(|e| crate::error::DaemonError::config(format!("cannot flush /dev/tty: {e}")))?;

    let mut line = String::new();
    std::io::BufReader::new(&tty)
        .read_line(&mut line)
        .map_err(|e| {
            crate::error::DaemonError::config(format!("cannot read from /dev/tty: {e}"))
        })?;
    Ok(line.trim() == "yes")
}

#[cfg(target_os = "macos")]
fn user_launch_agents_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| crate::error::DaemonError::config("$HOME is not set"))?;
    Ok(home.join("Library").join("LaunchAgents"))
}

/// A Linux daemon runs only as the system service: a user-scoped one would hold the master key
/// and every caller record under the uid it serves, where any process that uid runs can reach
/// them. `credsd serve` stays available for running the daemon as yourself on purpose.
#[cfg(target_os = "linux")]
fn user_install_unsupported() -> crate::error::DaemonError {
    crate::error::DaemonError::config(
        "user-scoped installs are not supported on Linux. Run 'sudo credsd install' to install \
         the system service, or 'credsd serve' to run the daemon as yourself.",
    )
}

/// Which backend to bake in, answered for the process that will *serve* rather than this one.
///
/// They differ on the default path alone: `auto_detect` probes the data protection keychain and
/// the probe succeeds here — root, in a login session, from the entitled in-bundle binary —
/// while failing for every LaunchDaemon. So a macOS system install pins the enclave instead.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn resolve_install_backend(opts: &InstallOpts) -> Result<credsd_core::storage::Backend> {
    #[cfg(target_os = "macos")]
    if opts.storage_backend.is_none() && !opts.user {
        use credsd_core::storage::Backend;
        if Backend::SecureEnclave.is_available() {
            return Ok(Backend::SecureEnclave);
        }
        // Two situations, and only one is about this Mac: the signed release compiles the
        // enclave out, so there a user install is the answer rather than other hardware.
        if !Backend::COMPILED.contains(&Backend::SecureEnclave) {
            return Err(crate::error::DaemonError::config(
                "this build does not install a system service. It is the signed release, whose \
                 keystore is the data protection keychain — reachable only from a login \
                 session, so only from a user-scoped service. Run 'credsd install --user' \
                 instead. A system service is what a build from source installs; see \
                 docs/install.md.",
            ));
        }
        return Err(crate::error::DaemonError::config(
            "a system install has no usable keystore on this Mac: it has no reachable Secure \
             Enclave, and a LaunchDaemon has no login session, so the data protection keychain \
             is not an option either. Run 'credsd install --user' to install a user-scoped \
             service instead.",
        ));
    }
    credsd_core::storage::select_backend(opts.storage_backend.as_deref())
}

/// Whether to refuse a user install that resolved `backend`, and why. The keychain is the only
/// keystore a user-scoped service may hold its key in: it gates on an entitlement, where the
/// enclave's `0600` key file is open to every other process running as that same login uid.
#[cfg(target_os = "macos")]
fn user_install_refusal(backend: credsd_core::storage::Backend) -> Option<String> {
    if backend == credsd_core::storage::Backend::DataProtectionKeychain {
        return None;
    }
    Some(format!(
        "a user install requires the data protection keychain, and this build resolved \
         '{backend}'. That keychain is authorized by the signed release's provisioning profile, \
         so a build from source cannot reach it: install the system service with 'sudo credsd \
         install' instead, or use the signed release for a user-scoped one. See docs/install.md.",
        backend = backend.as_str(),
    ))
}

/// The mirror of [`user_install_refusal`], and reached only for a backend named explicitly:
/// `resolve_install_backend` pins the default. Without it, an explicit `--storage-backend
/// data-protection-keychain` installs a LaunchDaemon whose key only the installer could open.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn system_install_refusal(backend: credsd_core::storage::Backend) -> Option<String> {
    if credsd_core::storage::reachable_by_system_service(backend) {
        return None;
    }
    Some(format!(
        "a system service cannot use the '{backend}' keystore: it is reachable only from a \
         login session, and the service runs as a shell-less account that has none. Install a \
         user-scoped service with 'credsd install --user' instead, or name a keystore a system \
         service can reach. See docs/install.md.",
        backend = backend.as_str(),
    ))
}

/// A baked backend is only worth refusing a reinstall over if the service could have used it: a
/// system definition naming the keychain has nothing sealed under it, so there is nothing to
/// orphan. A user install compares in full, and an unparseable name keeps conflicting.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn conflicting_installed_backend(installed: Option<String>, user: bool) -> Option<String> {
    let installed = installed?;
    if user {
        return Some(installed);
    }
    match credsd_core::storage::Backend::parse(&installed) {
        Some(b) if !credsd_core::storage::reachable_by_system_service(b) => None,
        _ => Some(installed),
    }
}

/// A reinstall that changes the baked backend leaves every credential sealed under the old key
/// with nothing to open it. Refuse rather than orphan them silently.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn reinstall_backend_conflict(installed: Option<&str>, resolved: &str) -> Option<String> {
    let installed = installed.filter(|b| *b != resolved)?;
    Some(format!(
        "refusing to install: the installed service uses the '{installed}' keystore and this \
         install would switch it to '{resolved}', leaving every credential sealed under the old \
         key undecryptable. Keep it with '--storage-backend {installed}', or delete the old key \
         first with 'credsd uninstall --purge-key --storage-backend {installed}' and install \
         again."
    ))
}

pub fn install(opts: &InstallOpts) -> Result<()> {
    #[cfg(target_os = "linux")]
    if opts.user {
        return Err(user_install_unsupported());
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        // First, before resolution: `sudo` makes this root with `$HOME=/var/root`, so the
        // LaunchAgent would land in a home no one logs into. `install_user`'s ancestor rules
        // cannot answer instead — they would refuse a bundle under the caller's own home.
        #[cfg(target_os = "macos")]
        if opts.user && nix::unistd::geteuid().is_root() {
            return Err(crate::error::DaemonError::config(
                "do not run 'credsd install --user' under sudo: a user-scoped service runs as \
                 the account that uses it, and under sudo this would write a LaunchAgent into \
                 root's home directory. Re-run it as yourself, without sudo. 'sudo credsd \
                 install' — without --user — is the system service.",
            ));
        }

        // Resolve the backend once so --storage-backend is always baked into the service
        // definition. This means `serve` can refuse to start without it and cannot silently
        // auto-detect a different backend between installs.
        let resolved = resolve_install_backend(opts)?;
        // Per scope: the two installs have separate keystores and data dirs.
        #[cfg(target_os = "macos")]
        let installed = macos::installed_backend(opts.user);
        #[cfg(target_os = "linux")]
        let installed = linux::installed_backend();
        let installed = conflicting_installed_backend(installed, opts.user);
        if let Some(conflict) = reinstall_backend_conflict(installed.as_deref(), resolved.as_str())
        {
            return Err(crate::error::DaemonError::config(conflict));
        }
        let opts_with_backend = InstallOpts {
            storage_backend: Some(resolved.as_str().to_string()),
            ..opts.clone()
        };
        let opts = &opts_with_backend;

        #[cfg(target_os = "macos")]
        if opts.user {
            if let Some(refusal) = user_install_refusal(resolved) {
                return Err(crate::error::DaemonError::config(refusal));
            }
            if !opts.skip_security_warning && !confirm_typed_yes(USER_INSTALL_WARNING)? {
                return Err(crate::error::DaemonError::config("user install cancelled"));
            }
            return macos::install_user(opts);
        }
        if let Some(refusal) = system_install_refusal(resolved) {
            return Err(crate::error::DaemonError::config(refusal));
        }
        require_root()?;

        // Only a failed *fresh* install rolls back: an existing definition names the staged
        // path and may be running from it. Asked of the system definition rather than
        // `status`, which reports a user install that has artifacts of its own.
        #[cfg(target_os = "macos")]
        let nothing_installed_before = !macos::system_definition_exists();
        #[cfg(target_os = "linux")]
        let nothing_installed_before = !linux::system_definition_exists();
        // Before anything is created, the only moment "this install made it" is visible.
        let data_dir = crate::config::platform::data_dir();
        let data_dir_was_absent = !data_dir.exists();
        let binary = stage_service_binary()?;
        if !opts.quiet {
            if let Some(warning) = binary.warning() {
                eprintln!("{warning}");
            }
        }
        #[cfg(target_os = "macos")]
        let result = macos::install(&binary.path, opts);
        #[cfg(target_os = "linux")]
        let result = linux::install(&binary.path, opts).map(|()| {
            remove_superseded_staged_binary(
                &binary.path,
                Path::new(crate::config::platform::LEGACY_SERVICE_BINARY_DIR),
            );
        });
        if result.is_err() && nothing_installed_before {
            // The definition first: both platforms write it before loading it, so a failure at
            // the load leaves one naming a path the lines below delete.
            #[cfg(target_os = "macos")]
            macos::remove_system_definition();
            #[cfg(target_os = "linux")]
            linux::remove_system_definition();
            remove_staged_binary();
            // The mint happens inside the platform install, so a failure after it leaves a key
            // behind — and a key nothing has adopted is exactly what the backend-switch guard
            // is built to be suspicious of, so the next install would refuse rather than
            // retry. Only a directory this install created: one that was already there holds
            // somebody's credentials.
            if data_dir_was_absent {
                let _ = std::fs::remove_dir_all(&data_dir);
            }
        }
        result
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = opts;
        Err(unsupported())
    }
}

/// `purge_key` runs after the definition is gone, and runs even when there was none: a key left
/// by an aborted install is exactly the state with nothing to uninstall.
pub fn uninstall(
    quiet: bool,
    user: bool,
    purge_key: bool,
    storage_backend: Option<&str>,
) -> Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        #[cfg(target_os = "macos")]
        if user {
            macos::uninstall_user(quiet)?;
            return purge_key_if_asked(purge_key, user, storage_backend, quiet);
        }
        #[cfg(target_os = "linux")]
        if user {
            return Err(user_install_unsupported());
        }
        require_root()?;
        #[cfg(target_os = "macos")]
        macos::uninstall(quiet)?;
        #[cfg(target_os = "linux")]
        linux::uninstall(quiet)?;
        remove_staged_binary();
        purge_key_if_asked(purge_key, user, storage_backend, quiet)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (quiet, user, purge_key, storage_backend);
        Err(unsupported())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
const PURGE_WARNING: &str = "\
WARNING: deleting the master encryption key — every credential sealed under it
becomes permanently undecryptable.

The sealed blobs are moved to quarantine under the data directory first, but
nothing can open them afterwards: the key they need will not exist. Every
environment has to be re-imported with 'credsd bootstrap --env <env>'.

Type 'yes' to continue: ";

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn purge_key_if_asked(
    purge_key: bool,
    user: bool,
    storage_backend: Option<&str>,
    quiet: bool,
) -> Result<()> {
    if !purge_key {
        return Ok(());
    }
    let backend = storage_backend.ok_or_else(|| {
        crate::error::DaemonError::config(
            "--purge-key requires --storage-backend: name the keystore holding the key to \
             delete (e.g. --storage-backend data-protection-keychain). It is not inferred, \
             because the key worth deleting is usually the one an install is switching away \
             from, not the one it is selecting.",
        )
    })?;

    // KKRS answers for the calling uid, not the machine, so a root search of the service
    // account's key succeeds and finds nothing — printing as "nothing to delete" over a live
    // key. Every other backend errors when it cannot reach its keystore.
    if backend == credsd_core::storage::Backend::KernelKeyring.as_str() {
        return Err(crate::error::DaemonError::config(
            "--purge-key cannot delete a 'kkrs' key: the kernel keyring is per-uid, so this \
             process can only reach its own, not the service account's. The key does not \
             survive a reboot, which is what clears it.",
        ));
    }

    // The removal above booted out this scope's service only; one in the other scope can still
    // be holding the same keystore.
    if status().map(|s| s.running).unwrap_or(false) {
        return Err(crate::error::DaemonError::config(
            "refusing to delete the encryption key while a credsd service is still running. \
             Remove or stop it first, then re-run.",
        ));
    }

    let data_dir = if user {
        crate::config::platform::user_data_dir().ok_or_else(|| {
            crate::error::DaemonError::config(
                "$HOME is not set; cannot determine the user data directory",
            )
        })?
    } else {
        crate::config::platform::data_dir()
    };

    if !confirm_typed_yes(PURGE_WARNING)? {
        return Err(crate::error::DaemonError::config("purge cancelled"));
    }

    if credsd_core::encryption::purge_encryption_key(backend, &data_dir)? {
        if !quiet {
            println!(
                "encryption key deleted from the '{backend}' keystore. Sealed credentials were \
                 moved to {}/quarantine and cannot be decrypted. Each user's integrity record \
                 will not open under a new key, so each user runs 'creds revalidate' (its \
                 approval replaces the record), then re-imports each environment with \
                 'credsd bootstrap --env <env>'.",
                data_dir.display()
            );
        }
    } else if !quiet {
        println!("no encryption key in the '{backend}' keystore; nothing to delete");
    }
    Ok(())
}

pub fn status() -> Result<ServiceStatus> {
    #[cfg(target_os = "macos")]
    {
        macos::status()
    }
    #[cfg(target_os = "linux")]
    {
        linux::status()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(unsupported())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn unsupported() -> crate::error::DaemonError {
    crate::error::DaemonError::config(
        "no supported service manager detected. Start it manually with 'credsd serve'.",
    )
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{InstallOpts, ServiceStatus};
    use crate::config::platform::{system_socket_path, CREDSD_GROUP, CREDSD_USER};
    use crate::error::{DaemonError, Result};
    use std::path::{Path, PathBuf};

    /// LaunchDaemon / LaunchAgent label. Reverse-DNS matching the app bundle identifier
    /// (`com.amazon.aws.credsd.daemon`) per Apple convention. Distinct from the credential-store
    /// key `storage::SERVICE_NAME`, so relabeling the service never moves stored secrets.
    const LABEL: &str = "com.amazon.aws.credsd.daemon";

    /// Label of the one-shot job that mints the enclave key. Distinct from [`LABEL`], so the
    /// service's own registration is never what gets booted out.
    const MINT_LABEL: &str = "com.amazon.aws.credsd.mint";

    /// The mint job's stdout and stderr, removed again when the job is done. launchd
    /// discards a job's stderr unless it names a file, and `init` logs there.
    const MINT_LOG_DIR: &str = "/Library/Logs/credsd-mint";

    /// Covers launchd scheduling the job at all; the enclave operation is milliseconds.
    const MINT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

    fn plist_path() -> PathBuf {
        PathBuf::from("/Library/LaunchDaemons").join(format!("{}.plist", LABEL))
    }

    fn mint_plist_path() -> PathBuf {
        PathBuf::from("/Library/LaunchDaemons").join(format!("{}.plist", MINT_LABEL))
    }

    /// Unregister `label`, by label rather than by plist path: a registration outlives the
    /// file it came from, and one left behind fails every later `bootstrap` with
    /// `Bootstrap failed: 5: Input/output error` until a bootout or a reboot.
    ///
    /// Best-effort: "was not registered" is the common case and reports as a failure.
    fn bootout_registration(label: &str) {
        if let Ok(mut cmd) = super::tool_command("launchctl") {
            let _ = cmd.arg("bootout").arg(format!("system/{label}")).status();
        }
    }

    /// Mint the enclave key from inside launchd, as the service account, via a one-shot job.
    /// The key binds to the launchd context that minted it, so a key minted by `install`
    /// itself fails to unwrap in the service whatever uid it drops to.
    ///
    /// Skipped when a key is already there, and must be: the enclave would mint a second one
    /// and orphan everything sealed under the first.
    fn mint_enclave_key_under_launchd(binary: &Path, backend: &str) -> Result<()> {
        if credsd_core::encryption::system_service_key_present(backend)? {
            return Ok(());
        }

        let log_dir = Path::new(MINT_LOG_DIR);
        let log = log_dir.join("mint.log");
        super::create_owned_dir(log_dir, 0o700)?;
        let _ = std::fs::remove_file(&log);

        let path = mint_plist_path();
        let job = render_mint_plist(binary, backend, &log, data_dir_override().as_deref());
        std::fs::write(&path, job).map_err(|e| {
            DaemonError::config(format!(
                "cannot write the key-mint job {}: {e}",
                path.display()
            ))
        })?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        }

        bootout_registration(MINT_LABEL);
        let minted = run_launchctl(&["bootstrap", "system"], &path, &log)
            .and_then(|()| wait_for_minted_key(backend));

        // The bootout either way, so an interrupted install leaves no label behind.
        bootout_registration(MINT_LABEL);
        let _ = std::fs::remove_file(&path);
        let job_output = std::fs::read_to_string(&log).unwrap_or_default();
        let _ = std::fs::remove_dir_all(log_dir);

        minted.map_err(|e| {
            DaemonError::config(format!(
                "could not mint the Secure Enclave key as '{user}' under launchd: {e}\n{output}\
                 The key has to be minted from inside launchd — the enclave binds it to that \
                 context — so this cannot fall back to minting here.",
                user = CREDSD_USER,
                output = if job_output.trim().is_empty() {
                    String::new()
                } else {
                    format!("the job reported:\n{}\n", job_output.trim())
                },
            ))
        })
    }

    /// Poll for the key, not the job: launchd reports a one-shot job's exit only while it
    /// still remembers it.
    fn wait_for_minted_key(backend: &str) -> Result<()> {
        let started = std::time::Instant::now();
        loop {
            if credsd_core::encryption::system_service_key_present(backend)? {
                return Ok(());
            }
            if started.elapsed() >= MINT_TIMEOUT {
                return Err(DaemonError::config(format!(
                    "no key appeared within {}s",
                    MINT_TIMEOUT.as_secs()
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Carried into the job, which starts from launchd's environment and not this one.
    fn data_dir_override() -> Option<String> {
        crate::config::platform::data_dir_override().map(|p| p.display().to_string())
    }

    /// A job that runs once and exits, so: no `Sockets`, no `KeepAlive`.
    fn render_mint_plist(
        binary: &Path,
        backend: &str,
        log: &Path,
        data_dir: Option<&str>,
    ) -> String {
        let mut s = String::new();
        s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        s.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
        s.push_str("<plist version=\"1.0\">\n<dict>\n");
        s.push_str(&format!(
            "    <key>Label</key>\n    <string>{}</string>\n",
            xml_escape(MINT_LABEL)
        ));
        s.push_str(&format!(
            "    <key>UserName</key>\n    <string>{}</string>\n",
            xml_escape(CREDSD_USER)
        ));
        s.push_str(&format!(
            "    <key>GroupName</key>\n    <string>{}</string>\n",
            xml_escape(CREDSD_GROUP)
        ));
        s.push_str("    <key>ProgramArguments</key>\n    <array>\n");
        for arg in [
            &binary.display().to_string(),
            "--storage-backend",
            backend,
            "init",
        ] {
            s.push_str(&format!("        <string>{}</string>\n", xml_escape(arg)));
        }
        s.push_str("    </array>\n");
        if let Some(data_dir) = data_dir {
            s.push_str("    <key>EnvironmentVariables</key>\n    <dict>\n");
            s.push_str(&format!(
                "        <key>CREDSD_DATA_DIR</key>\n        <string>{}</string>\n",
                xml_escape(data_dir)
            ));
            s.push_str("    </dict>\n");
        }
        for (key, value) in [("StandardOutPath", log), ("StandardErrorPath", log)] {
            s.push_str(&format!(
                "    <key>{key}</key>\n    <string>{}</string>\n",
                xml_escape(&value.display().to_string())
            ));
        }
        s.push_str("    <key>RunAtLoad</key>\n    <true/>\n");
        s.push_str("</dict>\n</plist>\n");
        s
    }

    pub fn install(binary: &Path, opts: &InstallOpts) -> Result<()> {
        ensure_service_account()?;

        let backend = opts.storage_backend.as_deref().ok_or_else(|| {
            crate::error::DaemonError::config(
                "storage backend not resolved — re-run credsd install",
            )
        })?;

        // First in both cases: the enclave mint writes its own key material there, as the
        // service account.
        super::own_tree()?;
        if backend == credsd_core::storage::Backend::SecureEnclave.as_str() {
            mint_enclave_key_under_launchd(binary, backend)?;
        } else {
            super::init_keystore(backend)?;
            // Root created those key files; hand them to the service account.
            super::own_tree()?;
        }

        let path = plist_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                DaemonError::config(format!(
                    "cannot create LaunchDaemons directory {}: {}",
                    dir.display(),
                    e
                ))
            })?;
        }

        let log_file = super::resolve_log_file(opts);
        let default_log = crate::config::platform::log_file_path();
        // Always prepare the log directory: the daemon uses the platform default when no
        // explicit --log-file was passed, so install must create and protect that directory
        // regardless of whether the path is baked into the service definition.
        let log_dir_path: &Path = log_file.as_deref().unwrap_or(&default_log);
        super::own_log_dir(log_dir_path)?;

        let args = super::program_arguments(opts, log_file.as_deref());
        let log_for_error: &Path = log_file.as_deref().unwrap_or(&default_log);

        let updating = path.exists();
        bootout_registration(LABEL);

        // The mint ran under this override, so the service reads the same home and slot.
        let plist = render_plist(
            LABEL,
            binary,
            &args,
            &system_socket_path(),
            data_dir_override().as_deref(),
        );
        std::fs::write(&path, plist).map_err(|e| {
            DaemonError::config(format!("cannot write plist {}: {}", path.display(), e))
        })?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        }

        run_launchctl(&["bootstrap", "system"], &path, log_for_error)?;

        if !opts.quiet {
            if updating {
                println!("credsd service updated and restarted");
            } else {
                println!("credsd installed as a system service. It will start on demand.");
            }
        }
        Ok(())
    }

    pub fn uninstall(quiet: bool) -> Result<()> {
        let path = plist_path();
        if !path.exists() {
            // No file, but possibly still a registration — the two are independent, and a
            // stray one fails the next install's bootstrap.
            bootout_registration(LABEL);
            bootout_registration(MINT_LABEL);
            if !quiet {
                println!("no credsd service installed");
            }
            return Ok(());
        }

        bootout_registration(LABEL);
        std::fs::remove_file(&path).map_err(|e| {
            DaemonError::config(format!("cannot remove plist {}: {}", path.display(), e))
        })?;

        if !quiet {
            println!("credsd service removed. The daemon is no longer running or auto-started.");
        }
        Ok(())
    }

    /// Undo what [`install`] wrote, for a failed install to roll back. Silent: the install's
    /// own error is what the operator needs. Both labels, the mint job being part of it.
    pub fn remove_system_definition() {
        bootout_registration(LABEL);
        bootout_registration(MINT_LABEL);
        let _ = std::fs::remove_file(plist_path());
        let _ = std::fs::remove_file(mint_plist_path());
    }

    fn user_plist_path() -> Result<PathBuf> {
        Ok(super::user_launch_agents_dir()?.join(format!("{}.plist", LABEL)))
    }

    /// Point this process's `data_dir()` at the directory the user plist bakes for the daemon.
    /// The master key's slot and its storage location both derive from `data_dir()`, so the key
    /// this process mints is the one the daemon looks up.
    fn bind_data_dir(data_dir: &std::path::Path) {
        std::env::set_var("CREDSD_DATA_DIR", data_dir);
    }

    pub fn install_user(opts: &super::InstallOpts) -> Result<()> {
        use crate::config::platform::{user_data_dir, user_socket_path};

        let data_dir = user_data_dir().ok_or_else(|| {
            DaemonError::config("$HOME is not set; cannot determine user data directory")
        })?;
        let socket = user_socket_path().ok_or_else(|| {
            DaemonError::config("$HOME is not set; cannot determine user socket path")
        })?;

        // UDS path limit: 104 bytes on macOS (sun_path is [u8; 104], NUL-terminated).
        // >= because the NUL terminator consumes the 104th byte.
        const UDS_MAX: usize = 104;
        let sock_str = socket.display().to_string();
        if sock_str.len() >= UDS_MAX {
            return Err(DaemonError::config(format!(
                "user socket path is too long ({} bytes, max {UDS_MAX}): {sock_str}",
                sock_str.len()
            )));
        }

        let binary = crate::config::platform::resolve_binary_path_canonical()?;

        if !super::all_ancestors_user_only(&binary) {
            return Err(DaemonError::config(format!(
                "binary path {} has a group- or other-writable ancestor; baking it into \
                 a user service would let other local users execute code as you at login. \
                 Install from a path only you can write.",
                binary.display()
            )));
        }

        // Before the keystore: the enclave writes key material here, and `create_dir_all`
        // down there would create the parent at the umask.
        crate::config::platform::ensure_user_owned_dir(&data_dir)?;

        bind_data_dir(&data_dir);

        // For user installs, the current user is the service user — call init directly.
        let backend = opts.storage_backend.as_deref().ok_or_else(|| {
            crate::error::DaemonError::config(
                "storage backend not resolved — re-run credsd install",
            )
        })?;
        credsd_core::encryption::init_encryption_with_backend(Some(backend))
            .map_err(|e| DaemonError::config(format!("failed to initialize keystore: {e}")))?;

        let log_file = super::resolve_log_file(opts);
        let args = super::program_arguments(opts, log_file.as_deref());

        let path = user_plist_path()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                DaemonError::config(format!(
                    "cannot create LaunchAgents directory {}: {e}",
                    dir.display()
                ))
            })?;
        }

        // Unload any existing job before rewriting the plist. `bootout gui/<uid>` restarts
        // the session on Ventura+; `unload` removes just this job from the running domain.
        if path.exists() {
            let _ = run_launchctl_user(&["unload", &path.display().to_string()]);
        }

        let plist = render_user_plist(LABEL, &binary, &args, &socket, &data_dir);
        std::fs::write(&path, &plist).map_err(|e| {
            DaemonError::config(format!("cannot write plist {}: {e}", path.display()))
        })?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        }

        run_launchctl_user(&["load", &path.display().to_string()])?;

        if !opts.quiet {
            println!("credsd user service installed. It will start on login.");
        }
        Ok(())
    }

    pub fn uninstall_user(quiet: bool) -> Result<()> {
        let path = match user_plist_path() {
            Ok(p) => p,
            Err(_) => {
                if !quiet {
                    println!("no credsd user service installed");
                }
                return Ok(());
            }
        };
        if !path.exists() {
            if !quiet {
                println!("no credsd user service installed");
            }
            return Ok(());
        }

        let _ = run_launchctl_user(&["unload", &path.display().to_string()]);
        std::fs::remove_file(&path).map_err(|e| {
            DaemonError::config(format!("cannot remove plist {}: {e}", path.display()))
        })?;

        if !quiet {
            println!("credsd user service removed.");
        }
        Ok(())
    }

    fn run_launchctl_user(args: &[&str]) -> Result<()> {
        let status = super::tool_command("launchctl")?
            .args(args)
            .status()
            .map_err(|e| DaemonError::config(format!("failed to run launchctl: {e}")))?;
        if !status.success() {
            return Err(DaemonError::config(format!(
                "launchctl {} exited with failure",
                args.join(" "),
            )));
        }
        Ok(())
    }

    /// Like `render_plist` but for `~/Library/LaunchAgents`: no `UserName`/`GroupName`
    /// (runs as the current user). Sets `CREDSD_SOCKET` and `CREDSD_DATA_DIR` so both the
    /// daemon and `creds` clients resolve user-owned paths without any extra shell config.
    fn render_user_plist(
        label: &str,
        binary: &std::path::Path,
        args: &[String],
        socket_path: &std::path::Path,
        data_dir: &std::path::Path,
    ) -> String {
        let mut s = String::new();
        s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        s.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
        s.push_str("<plist version=\"1.0\">\n<dict>\n");
        s.push_str(&format!(
            "    <key>Label</key>\n    <string>{}</string>\n",
            xml_escape(label)
        ));
        s.push_str("    <key>ProgramArguments</key>\n    <array>\n");
        s.push_str(&format!(
            "        <string>{}</string>\n",
            xml_escape(&binary.display().to_string())
        ));
        for arg in args {
            s.push_str(&format!("        <string>{}</string>\n", xml_escape(arg)));
        }
        s.push_str("    </array>\n");
        s.push_str("    <key>EnvironmentVariables</key>\n    <dict>\n");
        s.push_str(&format!(
            "        <key>CREDSD_SOCKET</key>\n        <string>{}</string>\n",
            xml_escape(&socket_path.display().to_string())
        ));
        s.push_str(&format!(
            "        <key>CREDSD_DATA_DIR</key>\n        <string>{}</string>\n",
            xml_escape(&data_dir.display().to_string())
        ));
        s.push_str("    </dict>\n");
        s.push_str("    <key>Sockets</key>\n    <dict>\n");
        s.push_str(&format!(
            "        <key>{}</key>\n",
            xml_escape(crate::server::activation::LAUNCHD_SOCKET_NAME)
        ));
        s.push_str("        <dict>\n");
        s.push_str(&format!(
            "            <key>SockPathName</key>\n            <string>{}</string>\n",
            xml_escape(&socket_path.display().to_string())
        ));
        s.push_str("            <key>SockPathMode</key>\n            <integer>384</integer>\n"); // 0o600 — user-only
        s.push_str("        </dict>\n    </dict>\n");
        s.push_str("    <key>RunAtLoad</key>\n    <true/>\n");
        s.push_str("    <key>KeepAlive</key>\n    <dict>\n        <key>SuccessfulExit</key>\n        <false/>\n    </dict>\n");
        s.push_str("    <key>ThrottleInterval</key>\n    <integer>5</integer>\n");
        s.push_str("    <key>ProcessType</key>\n    <string>Background</string>\n");
        s.push_str("</dict>\n</plist>\n");
        s
    }

    pub fn status() -> Result<ServiceStatus> {
        let path = user_plist_path()
            .ok()
            .filter(|p| p.exists())
            .unwrap_or_else(plist_path);
        if !path.exists() {
            return Ok(ServiceStatus::absent());
        }

        let contents = std::fs::read_to_string(&path).map_err(|e| {
            DaemonError::config(format!("cannot read plist {}: {}", path.display(), e))
        })?;
        let program_args = parse_program_arguments(&contents);
        let binary_path = program_args.first().cloned();
        let args = program_args.into_iter().skip(1).collect();

        Ok(ServiceStatus::installed(
            binary_path,
            args,
            is_running(),
            plist_string_after_key(&contents, "CREDSD_DATA_DIR"),
            plist_string_after_key(&contents, "SockPathName"),
        ))
    }

    /// Whether a LaunchDaemon definition is already in place.
    pub fn system_definition_exists() -> bool {
        plist_path().exists()
    }

    /// The backend baked into one scope's definition. Not via [`status`], which reports
    /// whichever definition exists.
    pub fn installed_backend(user: bool) -> Option<String> {
        let path = if user {
            user_plist_path().ok()?
        } else {
            plist_path()
        };
        let contents = std::fs::read_to_string(path).ok()?;
        let args: Vec<String> = parse_program_arguments(&contents)
            .into_iter()
            .skip(1)
            .collect();
        super::backend_from_args(&args)
    }

    /// The first `<string>` after `<key>key</key>` — enough for the flat values `status`
    /// reports, and the same text-level reading `parse_program_arguments` does.
    fn plist_string_after_key(plist: &str, key: &str) -> Option<String> {
        plist
            .split_once(&format!("<key>{key}</key>"))
            .and_then(|(_, rest)| rest.split_once("<string>"))
            .and_then(|(_, rest)| rest.split_once("</string>"))
            .map(|(value, _)| xml_unescape(value.trim()))
    }

    /// This is the riskiest install surface (multi-step `dscl`, no in-process API), so it is
    /// guarded by an existence check and verified manually against a real machine rather than in
    /// unit tests — the same manual-verification posture `hardening.rs` documents.
    fn ensure_service_account() -> Result<()> {
        if nix::unistd::User::from_name(CREDSD_USER)
            .ok()
            .flatten()
            .is_some()
        {
            return Ok(());
        }

        let id = free_system_id()?;
        let id = id.to_string();
        let user_rec = format!("/Users/{CREDSD_USER}");
        let group_rec = format!("/Groups/{CREDSD_GROUP}");

        super::run_tool("dscl", &[".", "-create", &group_rec])?;
        super::run_tool("dscl", &[".", "-create", &group_rec, "PrimaryGroupID", &id])?;
        super::run_tool("dscl", &[".", "-create", &user_rec])?;
        super::run_tool(
            "dscl",
            &[".", "-create", &user_rec, "UserShell", "/usr/bin/false"],
        )?;
        super::run_tool(
            "dscl",
            &[
                ".",
                "-create",
                &user_rec,
                "RealName",
                "credsd service account",
            ],
        )?;
        super::run_tool("dscl", &[".", "-create", &user_rec, "UniqueID", &id])?;
        super::run_tool("dscl", &[".", "-create", &user_rec, "PrimaryGroupID", &id])?;
        super::run_tool(
            "dscl",
            &[".", "-create", &user_rec, "NFSHomeDirectory", "/var/empty"],
        )?;
        Ok(())
    }

    /// First id in the macOS system range (200..500) free as both a uid and a gid, so the user
    /// and its matching group can share one number.
    fn free_system_id() -> Result<u32> {
        for id in 200u32..500 {
            let uid_taken = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(id))
                .ok()
                .flatten()
                .is_some();
            let gid_taken = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(id))
                .ok()
                .flatten()
                .is_some();
            if !uid_taken && !gid_taken {
                return Ok(id);
            }
        }
        Err(DaemonError::config(
            "no free system id in 200..500 for the credsd service account",
        ))
    }

    fn is_running() -> bool {
        // `output()` rather than `status()`, so launchctl's job dictionary is captured and
        // discarded rather than leaking onto our stdout.
        let uid = nix::unistd::getuid().as_raw();
        let user_running = super::tool_command("launchctl")
            .and_then(|mut cmd| {
                cmd.arg("print")
                    .arg(format!("gui/{uid}/{LABEL}"))
                    .output()
                    .map_err(Into::into)
            })
            .map(|o| o.status.success())
            .unwrap_or(false);
        if user_running {
            return true;
        }
        super::tool_command("launchctl")
            .and_then(|mut cmd| {
                cmd.arg("print")
                    .arg(format!("system/{LABEL}"))
                    .output()
                    .map_err(Into::into)
            })
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn run_launchctl(subcommand: &[&str], plist: &Path, log_file: &Path) -> Result<()> {
        let status = super::tool_command("launchctl")?
            .args(subcommand)
            .arg(plist)
            .status()
            .map_err(|e| {
                DaemonError::config(format!(
                    "failed to run launchctl (is this macOS with launchd?): {}",
                    e
                ))
            })?;
        if !status.success() {
            return Err(DaemonError::config(format!(
                "launchctl {} exited with failure; check the service log ({})",
                subcommand.join(" "),
                log_file.display()
            )));
        }
        Ok(())
    }

    /// Socket-activated: the
    /// `Sockets` dict checks in `socket_path`, so launchd binds it and hands the daemon the
    /// listening fd (see `server::activation`). The dict key is
    /// [`server::activation::LAUNCHD_SOCKET_NAME`], shared so the key launchd is told and the key
    /// the daemon reads cannot drift.
    ///
    /// **`SockPathMode` is 0o666 — world-connectable, deliberately.** The daemon serves many
    /// client uids from one socket and there is no OS group that enumerates them, so a
    /// restrictive mode would deny every ordinary uid rather than the wrong ones. A connection
    /// is not a grant: `callers/<uid>/owner` deny-by-absence on the kernel-verified peer uid is
    /// the sole authorization gate. systemd's `SocketMode=0666` is the same decision.
    ///
    /// No `StandardOutPath`/`StandardErrorPath` keys are emitted: credsd writes its own log file
    /// (baked into `args` as `--log-file`), so launchd stays out of the logging path — what keeps
    /// the daemon's size-based rotation the single writer.
    pub(super) fn render_plist(
        label: &str,
        binary: &Path,
        args: &[String],
        socket_path: &Path,
        data_dir: Option<&str>,
    ) -> String {
        let mut s = String::new();
        s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        s.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
        s.push_str("<plist version=\"1.0\">\n");
        s.push_str("<dict>\n");
        s.push_str("    <key>Label</key>\n");
        s.push_str(&format!("    <string>{}</string>\n", xml_escape(label)));
        s.push_str("    <key>UserName</key>\n");
        s.push_str(&format!(
            "    <string>{}</string>\n",
            xml_escape(CREDSD_USER)
        ));
        s.push_str("    <key>GroupName</key>\n");
        s.push_str(&format!(
            "    <string>{}</string>\n",
            xml_escape(CREDSD_GROUP)
        ));
        s.push_str("    <key>ProgramArguments</key>\n");
        s.push_str("    <array>\n");
        s.push_str(&format!(
            "        <string>{}</string>\n",
            xml_escape(&binary.display().to_string())
        ));
        for arg in args {
            s.push_str(&format!("        <string>{}</string>\n", xml_escape(arg)));
        }
        s.push_str("    </array>\n");
        if let Some(data_dir) = data_dir {
            s.push_str("    <key>EnvironmentVariables</key>\n    <dict>\n");
            s.push_str(&format!(
                "        <key>CREDSD_DATA_DIR</key>\n        <string>{}</string>\n",
                xml_escape(data_dir)
            ));
            s.push_str("    </dict>\n");
        }
        s.push_str("    <key>Sockets</key>\n");
        s.push_str("    <dict>\n");
        s.push_str(&format!(
            "        <key>{}</key>\n",
            xml_escape(crate::server::activation::LAUNCHD_SOCKET_NAME)
        ));
        s.push_str("        <dict>\n");
        s.push_str("            <key>SockPathName</key>\n");
        s.push_str(&format!(
            "            <string>{}</string>\n",
            xml_escape(&socket_path.display().to_string())
        ));
        // plist integers are base-10, so 0o666 is written as its decimal value 438 — the classic
        // launchd gotcha (an octal-looking 666 here would be 0o1232).
        s.push_str("            <key>SockPathMode</key>\n");
        s.push_str("            <integer>438</integer>\n");
        s.push_str("        </dict>\n");
        s.push_str("    </dict>\n");
        s.push_str("    <key>RunAtLoad</key>\n");
        s.push_str("    <true/>\n");
        s.push_str("    <key>KeepAlive</key>\n");
        s.push_str("    <dict>\n");
        s.push_str("        <key>SuccessfulExit</key>\n");
        s.push_str("        <false/>\n");
        s.push_str("    </dict>\n");
        s.push_str("    <key>ThrottleInterval</key>\n");
        s.push_str("    <integer>5</integer>\n");
        s.push_str("    <key>ProcessType</key>\n");
        s.push_str("    <string>Background</string>\n");
        s.push_str("</dict>\n");
        s.push_str("</plist>\n");
        s
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    fn parse_program_arguments(plist: &str) -> Vec<String> {
        let Some(array) = plist
            .split_once("<key>ProgramArguments</key>")
            .and_then(|(_, rest)| rest.split_once("<array>"))
            .and_then(|(_, rest)| rest.split_once("</array>"))
            .map(|(array, _)| array)
        else {
            return Vec::new();
        };

        // `skip(1)` drops the text before the first `<string>`; an unterminated final entry is
        // filtered out rather than yielding a truncated argument.
        array
            .split("<string>")
            .skip(1)
            .filter_map(|chunk| chunk.split_once("</string>"))
            .map(|(value, _)| xml_unescape(value))
            .collect()
    }

    fn xml_unescape(s: &str) -> String {
        s.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn sample_plist() -> String {
            render_plist(
                LABEL,
                Path::new("/opt/homebrew/bin/credsd"),
                &[
                    "--storage-backend".to_string(),
                    "file".to_string(),
                    "serve".to_string(),
                ],
                &system_socket_path(),
                None,
            )
        }

        #[test]
        fn plist_runs_as_the_scoped_credsd_user() {
            let plist = sample_plist();
            assert!(plist.contains("<key>UserName</key>"));
            assert!(plist.contains(&format!("<string>{CREDSD_USER}</string>")));
            assert!(plist.contains("<key>GroupName</key>"));
            assert!(plist.contains(&format!("<string>{CREDSD_GROUP}</string>")));
        }

        /// The `Sockets` dict is keyed on exactly the constant `server::activation` reads back,
        /// checks in the uid-independent system socket path, and encodes the world-connectable
        /// 0o666 as its decimal 438 — the launchd base-10 gotcha. Written as `{:}` of the octal
        /// literal so a decimal-looking `666` cannot creep back in.
        #[test]
        fn plist_socket_activation_matches_daemon_contract() {
            let plist = sample_plist();
            assert!(plist.contains("<key>Sockets</key>"));
            assert!(plist.contains(&format!(
                "<key>{}</key>",
                crate::server::activation::LAUNCHD_SOCKET_NAME
            )));
            assert!(plist.contains(&format!(
                "<string>{}</string>",
                system_socket_path().display()
            )));
            assert!(plist.contains("<key>SockPathMode</key>"));
            assert!(plist.contains(&format!("<integer>{}</integer>", 0o666)));
        }

        #[test]
        fn plist_contains_binary_and_args() {
            let plist = sample_plist();
            assert!(plist.contains(&format!("<string>{LABEL}</string>")));
            assert!(plist.contains("<string>/opt/homebrew/bin/credsd</string>"));
            assert!(plist.contains("<string>serve</string>"));
            assert!(plist.contains("<string>--storage-backend</string>"));
            assert!(plist.contains("<key>RunAtLoad</key>"));
        }

        #[test]
        fn program_arguments_round_trip() {
            let plist = render_plist(
                LABEL,
                Path::new("/usr/local/bin/credsd"),
                &[
                    "--log-file".to_string(),
                    "/tmp/credsd.log".to_string(),
                    "serve".to_string(),
                ],
                &system_socket_path(),
                None,
            );
            let parsed = parse_program_arguments(&plist);
            assert_eq!(
                parsed,
                vec![
                    "/usr/local/bin/credsd",
                    "--log-file",
                    "/tmp/credsd.log",
                    "serve"
                ]
            );
        }

        #[test]
        fn plist_never_captures_stdio() {
            // Two writers would race the same file.
            let plist = sample_plist();
            assert!(!plist.contains("StandardErrorPath"));
            assert!(!plist.contains("StandardOutPath"));
        }

        /// The one-shot mint job, which is the only context that produces an enclave key the
        /// service can unwrap. Every property here is load-bearing: the service account,
        /// because the key binds to the account that minted it as well as to launchd; its own
        /// label, so the service's registration is never what gets booted out; `RunAtLoad`
        /// with no `KeepAlive`, so it runs once instead of being restarted forever; and a log
        /// path, because `init` logs to stderr and launchd discards that unless a job names a
        /// file — a silent mint failure is what made this unexplainable.
        #[test]
        fn the_mint_job_runs_once_as_the_service_account() {
            let binary = Path::new("/opt/credsd/credsd");
            let job = render_mint_plist(
                binary,
                "secure-enclave",
                Path::new("/Library/Logs/credsd-mint/mint.log"),
                None,
            );

            assert!(job.contains(&format!("<string>{MINT_LABEL}</string>")));
            assert!(!job.contains(&format!("<string>{LABEL}</string>")), "{job}");
            assert!(job.contains(&format!("<string>{CREDSD_USER}</string>")));
            assert!(job.contains(&format!("<string>{CREDSD_GROUP}</string>")));
            assert_eq!(
                parse_program_arguments(&job),
                vec![
                    "/opt/credsd/credsd",
                    "--storage-backend",
                    "secure-enclave",
                    "init"
                ]
            );
            assert!(job.contains("<key>RunAtLoad</key>"));
            assert!(
                !job.contains("KeepAlive"),
                "a one-shot job must not restart"
            );
            assert!(!job.contains("Sockets"), "the mint serves nothing");
            assert!(job.contains("<key>StandardErrorPath</key>"));
            assert!(job.contains("/Library/Logs/credsd-mint/mint.log"));
            assert!(
                !job.contains("EnvironmentVariables"),
                "no override, no env dict"
            );
        }

        /// launchd starts the job from its own environment, so a data-directory override the
        /// installing process is working under has to be carried in, or the job mints into the
        /// default directory while install prepared another.
        #[test]
        fn the_mint_job_carries_a_data_dir_override() {
            let job = render_mint_plist(
                Path::new("/opt/credsd/credsd"),
                "secure-enclave",
                Path::new("/Library/Logs/credsd-mint/mint.log"),
                Some("/tmp/alt-data-dir"),
            );
            assert!(job.contains("<key>CREDSD_DATA_DIR</key>"));
            assert!(job.contains("<string>/tmp/alt-data-dir</string>"));
        }

        /// What `status` reports back about a user install comes out of the plist it rendered,
        /// so the two have to agree on where those values are written.
        #[test]
        fn status_values_round_trip_through_the_user_plist() {
            let data_dir = Path::new("/Users/someone/Library/Application Support/credsd");
            let socket = data_dir.join("credsd.sock");
            let plist = render_user_plist(
                LABEL,
                Path::new("/opt/credsd/Credsd.app/Contents/MacOS/credsd"),
                &[
                    "--storage-backend".to_string(),
                    "data-protection-keychain".to_string(),
                    "serve".to_string(),
                ],
                &socket,
                data_dir,
            );
            assert_eq!(
                super::super::backend_from_args(&parse_program_arguments(&plist)[1..]),
                Some("data-protection-keychain".to_string())
            );
            assert_eq!(
                plist_string_after_key(&plist, "CREDSD_DATA_DIR").as_deref(),
                Some(data_dir.to_str().unwrap())
            );
            assert_eq!(
                plist_string_after_key(&plist, "SockPathName").as_deref(),
                Some(socket.to_str().unwrap())
            );
        }

        /// The system plist names no data dir, so `status` must not invent one — the daemon
        /// resolves `platform::data_dir()` there, and that is what has to be reported.
        #[test]
        fn the_system_plist_carries_a_socket_but_no_data_dir() {
            let plist = sample_plist();
            assert_eq!(plist_string_after_key(&plist, "CREDSD_DATA_DIR"), None);
            assert_eq!(
                plist_string_after_key(&plist, "SockPathName").as_deref(),
                Some(system_socket_path().to_str().unwrap())
            );
        }

        #[test]
        fn xml_escape_round_trips() {
            let raw = "a & b < c > d";
            assert_eq!(xml_unescape(&xml_escape(raw)), raw);
        }

        /// A system install run under a data-dir override mints into the override's slot, so the
        /// service definition carries the same directory and the daemon opens that slot.
        #[test]
        fn system_install_carries_the_data_dir_it_minted_into() {
            let _lock = crate::server::e2e::DATA_DIR_ENV_LOCK.blocking_lock();
            let root = tempfile::tempdir().unwrap();
            let data_dir = root.path().join("cred&sd<1>");
            let _restore =
                crate::server::e2e::EnvVarGuard::set("CREDSD_DATA_DIR", data_dir.to_str().unwrap());
            let plist = render_plist(
                LABEL,
                Path::new("/usr/local/bin/credsd"),
                &["serve".to_string()],
                &system_socket_path(),
                data_dir_override().as_deref(),
            );
            let baked = plist_string_after_key(&plist, "CREDSD_DATA_DIR").unwrap();
            let ns = credsd_core::storage::instance_namespace;
            assert_eq!(
                ns(&crate::config::platform::data_dir()),
                ns(Path::new(&baked)),
                "installer and system daemon must derive one master-key slot"
            );

            let none = render_plist(
                LABEL,
                Path::new("/usr/local/bin/credsd"),
                &["serve".to_string()],
                &system_socket_path(),
                None,
            );
            assert!(!none.contains("CREDSD_DATA_DIR"));
        }

        /// The key `install --user` mints must sit in the slot the daemon opens. Both derive the
        /// slot from `data_dir()`; the daemon reads it from the plist's `CREDSD_DATA_DIR`, the
        /// installer from its own environment after `bind_data_dir`. A name XML has to escape
        /// checks that the round trip through the plist names the same home.
        #[test]
        fn install_mints_into_the_slot_the_daemon_opens() {
            let _lock = crate::server::e2e::DATA_DIR_ENV_LOCK.blocking_lock();
            let _restore = crate::server::e2e::EnvVarGuard::set("CREDSD_DATA_DIR", "");
            let root = tempfile::tempdir().unwrap();
            let data_dir = root.path().join("Application Support").join("cred&sd<1>");
            let plist = render_user_plist(
                LABEL,
                Path::new("/Users/example/bin/credsd"),
                &["serve".to_string()],
                &root.path().join("credsd.sock"),
                &data_dir,
            );
            let baked = plist_string_after_key(&plist, "CREDSD_DATA_DIR").unwrap();

            bind_data_dir(&data_dir);

            let ns = credsd_core::storage::instance_namespace;
            assert_eq!(
                ns(&crate::config::platform::data_dir()),
                ns(Path::new(&baked)),
                "installer and daemon must derive one master-key slot"
            );
        }

        fn sample_user_plist() -> String {
            render_user_plist(
                LABEL,
                Path::new("/Users/example/bin/credsd"),
                &["serve".to_string()],
                Path::new("/Users/example/Library/Application Support/credsd/credsd.sock"),
                Path::new("/Users/example/Library/Application Support/credsd"),
            )
        }

        #[test]
        fn user_plist_has_no_username_or_groupname() {
            let plist = sample_user_plist();
            assert!(
                !plist.contains("UserName"),
                "user plist must not set UserName"
            );
            assert!(
                !plist.contains("GroupName"),
                "user plist must not set GroupName"
            );
        }

        #[test]
        fn user_plist_sock_path_mode_is_user_only() {
            // 0o600 = 384 decimal — user-read/write, no group/other access.
            let plist = sample_user_plist();
            assert!(
                plist.contains(&format!("<integer>{}</integer>", 0o600)),
                "SockPathMode must be 0o600 ({}), got plist:\n{plist}",
                0o600
            );
        }

        #[test]
        fn user_plist_socket_binds_the_user_path() {
            let plist = sample_user_plist();
            assert!(
                plist.contains("Application Support/credsd/credsd.sock"),
                "plist must bind the user socket path"
            );
        }

        #[test]
        fn user_plist_sets_credsd_data_dir() {
            let plist = sample_user_plist();
            assert!(
                plist.contains("CREDSD_DATA_DIR"),
                "user plist must set CREDSD_DATA_DIR"
            );
            assert!(
                plist.contains("Application Support/credsd</string>"),
                "CREDSD_DATA_DIR must point to the user data dir"
            );
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{InstallOpts, ServiceStatus};
    use crate::config::platform::{system_socket_path, CREDSD_GROUP, CREDSD_USER};
    use crate::error::{DaemonError, Result};
    use std::path::{Path, PathBuf};

    /// systemd unit base name. A short name (`credsd`) per Linux convention — unit names are
    /// conventionally short (`credsd.service`), not reverse-DNS. Distinct from the macOS launchd
    /// `LABEL` and from the credential-store key `storage::SERVICE_NAME`. A `.socket` activates the
    /// `.service` of the same base name.
    const SYSTEMD_UNIT: &str = "credsd";

    fn service_unit_name() -> String {
        format!("{SYSTEMD_UNIT}.service")
    }

    fn socket_unit_name() -> String {
        format!("{SYSTEMD_UNIT}.socket")
    }

    /// Read by system `systemctl`, not the per-user `systemctl --user` search path.
    fn unit_dir() -> PathBuf {
        PathBuf::from("/etc/systemd/system")
    }

    fn service_unit_path() -> PathBuf {
        unit_dir().join(service_unit_name())
    }

    fn socket_unit_path() -> PathBuf {
        unit_dir().join(socket_unit_name())
    }

    /// Undo what [`install`] wrote, for a failed install to roll back. Silent: the install's
    /// own error is what the operator needs. The same teardown [`uninstall`] runs, and in the
    /// same order — systemd cannot resolve a unit whose file is already gone, so `enable`'s
    /// `sockets.target` symlink would outlive it.
    pub fn remove_system_definition() {
        let log_file = crate::config::platform::log_file_path();
        let _ = run_systemctl(&["disable", "--now", &socket_unit_name()], &log_file);
        let _ = run_systemctl(&["stop", &service_unit_name()], &log_file);
        let _ = std::fs::remove_file(service_unit_path());
        let _ = std::fs::remove_file(socket_unit_path());
        let _ = run_systemctl(&["daemon-reload"], &log_file);
    }

    pub fn install(binary: &Path, opts: &InstallOpts) -> Result<()> {
        ensure_service_user()?;

        // Mint (or load) the master key before own_tree so the recursive chown covers
        // any key files created here.
        let backend = opts.storage_backend.as_deref().ok_or_else(|| {
            crate::error::DaemonError::config(
                "storage backend not resolved — re-run credsd install",
            )
        })?;
        super::init_keystore(backend)?;

        // Recursively chown data_dir to credsd, including any key material created above.
        super::own_tree()?;
        restrict_data_root()?;

        let dir = unit_dir();
        if !dir.exists() {
            std::fs::create_dir_all(&dir).map_err(|e| {
                DaemonError::config(format!(
                    "cannot create systemd system directory {}: {}",
                    dir.display(),
                    e
                ))
            })?;
        }

        let log_file = super::resolve_log_file(opts);
        let default_log = crate::config::platform::log_file_path();
        let log_dir_path: &Path = log_file.as_deref().unwrap_or(&default_log);
        super::own_log_dir(log_dir_path)?;

        let args = super::program_arguments(opts, log_file.as_deref());
        let updating = service_unit_path().exists();

        let logs_directory =
            log_dir_path.parent() == Some(Path::new(crate::config::platform::SYSTEM_LOG_DIR));
        write_unit(
            &service_unit_path(),
            // install created and minted into this home, so the service reads the same one.
            &render_service(
                binary,
                &args,
                tpm_device_group(opts),
                logs_directory,
                crate::config::platform::data_dir_override()
                    .map(|p| p.display().to_string())
                    .as_deref(),
            ),
        )?;
        write_unit(&socket_unit_path(), &render_socket(&system_socket_path()))?;

        run_systemctl(&["daemon-reload"], log_dir_path)?;
        run_systemctl(&["enable", "--now", &socket_unit_name()], log_dir_path)?;
        let _ = run_systemctl(&["try-restart", &service_unit_name()], log_dir_path);

        if !opts.quiet {
            if updating {
                println!("credsd service updated and restarted");
            } else {
                println!("credsd installed as a system service. It will start on demand.");
            }
        }
        Ok(())
    }

    pub fn uninstall(quiet: bool) -> Result<()> {
        if !service_unit_path().exists() && !socket_unit_path().exists() {
            if !quiet {
                println!("no credsd service installed");
            }
            return Ok(());
        }

        // disable --now stops the socket/service and removes the sockets.target symlink;
        // best-effort, mirroring the macOS bootout.
        let log_file = crate::config::platform::log_file_path();
        let _ = run_systemctl(&["disable", "--now", &socket_unit_name()], &log_file);
        let _ = run_systemctl(&["stop", &service_unit_name()], &log_file);
        remove_unit(&socket_unit_path())?;
        remove_unit(&service_unit_path())?;
        let _ = run_systemctl(&["daemon-reload"], &log_file);

        if !quiet {
            println!("credsd service removed. The daemon is no longer running or auto-started.");
        }
        Ok(())
    }

    pub fn status() -> Result<ServiceStatus> {
        let path = service_unit_path();
        if !path.exists() {
            return Ok(ServiceStatus::absent());
        }

        let contents = std::fs::read_to_string(&path).map_err(|e| {
            DaemonError::config(format!("cannot read unit {}: {}", path.display(), e))
        })?;
        let exec = parse_exec_start(&contents);
        let binary_path = exec.first().cloned();
        let args = exec.into_iter().skip(1).collect();

        Ok(ServiceStatus::installed(
            binary_path,
            args,
            is_running(),
            None,
            Some(system_socket_path().display().to_string()),
        ))
    }

    /// Whether unit files are already in place. Either one counts: a half-written pair is
    /// still not this install's to remove.
    pub fn system_definition_exists() -> bool {
        service_unit_path().exists() || socket_unit_path().exists()
    }

    /// The backend baked into the installed unit; `None` when nothing is installed.
    pub fn installed_backend() -> Option<String> {
        let contents = std::fs::read_to_string(service_unit_path()).ok()?;
        let args: Vec<String> = parse_exec_start(&contents).into_iter().skip(1).collect();
        super::backend_from_args(&args)
    }

    fn write_unit(path: &Path, contents: &str) -> Result<()> {
        std::fs::write(path, contents).map_err(|e| {
            DaemonError::config(format!("cannot write unit {}: {}", path.display(), e))
        })?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
        Ok(())
    }

    fn remove_unit(path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        std::fs::remove_file(path).map_err(|e| {
            DaemonError::config(format!("cannot remove unit {}: {}", path.display(), e))
        })
    }

    /// Provision the `credsd` service user idempotently. `useradd --system` also creates a
    /// matching primary group on the distributions that enable `USERGROUPS_ENAB` (the default),
    /// giving the `credsd:credsd` owner the units and `own_tree` reference. A user that already
    /// resolves is treated as success.
    fn ensure_service_user() -> Result<()> {
        if nix::unistd::User::from_name(CREDSD_USER)
            .ok()
            .flatten()
            .is_some()
        {
            return Ok(());
        }
        super::run_tool(
            "useradd",
            &[
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                CREDSD_USER,
            ],
        )
    }

    fn is_running() -> bool {
        // --quiet suppresses the "active"/"inactive" word so it never leaks onto our stdout.
        super::tool_command("systemctl")
            .and_then(|mut cmd| {
                cmd.args(["is-active", "--quiet", &service_unit_name()])
                    .status()
                    .map_err(Into::into)
            })
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn run_systemctl(args: &[&str], log_file: &Path) -> Result<()> {
        let status = super::tool_command("systemctl")?
            .args(args)
            .status()
            .map_err(|e| {
                DaemonError::config(format!(
                    "failed to run systemctl (is this Linux with systemd?): {}",
                    e
                ))
            })?;
        if !status.success() {
            return Err(DaemonError::config(format!(
                "systemctl {} exited with failure; check the service log ({})",
                args.join(" "),
                log_file.display()
            )));
        }
        Ok(())
    }

    /// `StateDirectoryMode=` only applies to a directory systemd creates, and an earlier install
    /// left `/var/lib/credsd` at the umask, listing every provisioned uid under `callers/`.
    fn restrict_data_root() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::config::platform::data_dir();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| DaemonError::config(format!("cannot restrict {}: {}", root.display(), e)))
    }

    const TPM_GROUP: &str = "tss";

    /// `/dev/tpmrm0` is `root:tss 0660` on the distributions that ship `tpm2-tss`, so a
    /// service account outside `tss` selects the TPM backend (the probe only checks that the
    /// node exists) and then cannot open it. Named only when the daemon will use the TPM, and
    /// only when the group exists: systemd refuses to start a unit naming a missing group.
    ///
    /// A TPM with no group installs anyway but says so: the daemon would otherwise fail at first
    /// bootstrap with nothing pointing at the cause, and the unit is only re-rendered by
    /// another install.
    fn tpm_device_group(opts: &InstallOpts) -> Option<&'static str> {
        let uses_tpm = credsd_core::storage::select_backend(opts.storage_backend.as_deref())
            .is_ok_and(|b| b == credsd_core::storage::Backend::Tpm);
        if !uses_tpm {
            return None;
        }
        let group_exists = nix::unistd::Group::from_name(TPM_GROUP)
            .ok()
            .flatten()
            .is_some();
        if !group_exists && !opts.quiet {
            eprintln!(
                "warning: TPM backend selected but the `{TPM_GROUP}` group does not exist; \
                 install tpm2-tss and re-run `credsd install`"
            );
        }
        group_exists.then_some(TPM_GROUP)
    }

    /// No `[Install]` — the `.socket` owns activation. `RuntimeDirectory=credsd` is what makes
    /// `/run/credsd`, the parent of [`system_socket_path`], exist and be credsd-owned.
    /// `RuntimeDirectoryPreserve=yes` keeps it when the service stops: systemd otherwise deletes
    /// it, and with it the socket the still-listening `.socket` unit bound inside it.
    ///
    /// No `StandardOutput=`/`StandardError=` file target: credsd writes its own log via
    /// `--log-file`, which keeps its size-based rotation the single writer. `LogsDirectory=` is
    /// named only when that log is in `/var/log/credsd`, so a custom `--log-file` does not get
    /// an empty directory created beside it.
    pub(super) fn render_service(
        binary: &Path,
        args: &[String],
        supplementary_group: Option<&str>,
        logs_directory: bool,
        data_dir: Option<&str>,
    ) -> String {
        let mut exec = systemd_quote(&binary.display().to_string());
        for arg in args {
            exec.push(' ');
            exec.push_str(&systemd_quote(arg));
        }
        let mut s = String::new();
        s.push_str("[Unit]\n");
        s.push_str("Description=AWS credential daemon (credsd)\n");
        s.push('\n');
        s.push_str("[Service]\n");
        s.push_str("Type=simple\n");
        s.push_str(&format!("User={CREDSD_USER}\n"));
        s.push_str(&format!("Group={CREDSD_GROUP}\n"));
        if let Some(group) = supplementary_group {
            s.push_str(&format!("SupplementaryGroups={group}\n"));
        }
        if let Some(data_dir) = data_dir {
            s.push_str(&format!(
                "Environment={}\n",
                systemd_quote_environment(&format!("CREDSD_DATA_DIR={data_dir}"))
            ));
        }
        s.push_str(&format!("ExecStart={}\n", exec));
        s.push_str("RuntimeDirectory=credsd\n");
        s.push_str("RuntimeDirectoryPreserve=yes\n");
        s.push_str("StateDirectory=credsd\n");
        s.push_str("StateDirectoryMode=0700\n");
        if logs_directory {
            s.push_str("LogsDirectory=credsd\n");
            s.push_str("LogsDirectoryMode=0700\n");
        }
        s.push_str("Restart=on-failure\n");
        s.push_str("RestartSec=5\n");
        s
    }

    /// Render the `.socket` unit: init binds [`system_socket_path`] and hands the activated fd to
    /// the service (see `server::activation`). `SocketUser`/`SocketGroup` are `credsd` so the
    /// daemon owns the socket, but `SocketMode=0666` leaves it world-connectable: one daemon
    /// serves many client uids and no OS group enumerates them, so a narrower mode would deny
    /// every ordinary uid. A connection is not a grant — the `callers/<uid>/owner` peer-uid
    /// check is the authorization gate. launchd's `SockPathMode` 438 matches.
    pub(super) fn render_socket(socket_path: &Path) -> String {
        let mut s = String::new();
        s.push_str("[Unit]\n");
        s.push_str("Description=AWS credential daemon socket (credsd)\n");
        s.push('\n');
        s.push_str("[Socket]\n");
        s.push_str(&format!("ListenStream={}\n", socket_path.display()));
        s.push_str("SocketMode=0666\n");
        s.push_str(&format!("SocketUser={CREDSD_USER}\n"));
        s.push_str(&format!("SocketGroup={CREDSD_GROUP}\n"));
        s.push_str("RemoveOnStop=yes\n");
        s.push('\n');
        s.push_str("[Install]\n");
        s.push_str("WantedBy=sockets.target\n");
        s
    }

    /// Quote one `Environment=` assignment: wrap in double quotes and escape `\` and `"`, `%`
    /// (specifier), and the newline/carriage-return that would otherwise break the line. `$` is
    /// left alone: `Environment=` does no variable expansion, so a doubled `$` would reach the
    /// daemon as two characters. Backslash is escaped first so the escapes introduced afterward
    /// are not re-doubled.
    fn systemd_quote_environment(s: &str) -> String {
        let escaped = s
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        format!("\"{}\"", escaped)
    }

    /// Quote one ExecStart token: the `Environment=` quoting plus `$` doubled, since `ExecStart=`
    /// does variable expansion. `parse_exec_start` reverses this exactly.
    fn systemd_quote(s: &str) -> String {
        systemd_quote_environment(s).replace('$', "$$")
    }

    /// Extract the double-quoted tokens from the unit's `ExecStart=` line. Only parses the shape
    /// `render_service` emits (every token double-quoted), the same self-referential contract
    /// `macos::parse_program_arguments` keeps.
    fn parse_exec_start(unit: &str) -> Vec<String> {
        let Some(line) = unit
            .lines()
            .find(|l| l.trim_start().starts_with("ExecStart="))
        else {
            return Vec::new();
        };
        let value = line.trim_start().strip_prefix("ExecStart=").unwrap_or("");

        // `any` consumes up to and including the opening quote, and yields false at end of input,
        // which is what ends the outer loop.
        let mut chars = value.chars();
        let mut out = Vec::new();
        while chars.any(|c| c == '"') {
            let mut token = String::new();
            loop {
                match chars.next() {
                    None | Some('"') => break,
                    Some('\\') => match chars.next() {
                        Some('n') => token.push('\n'),
                        Some('r') => token.push('\r'),
                        Some(other) => token.push(other),
                        // A trailing backslash escapes nothing; keep it verbatim.
                        None => {
                            token.push('\\');
                            break;
                        }
                    },
                    Some(c) => token.push(c),
                }
            }
            out.push(token.replace("%%", "%").replace("$$", "$"));
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn service_runs_as_credsd_without_user_scope_or_install() {
            let unit = render_service(
                Path::new("/usr/local/bin/credsd"),
                &[
                    "--storage-backend".to_string(),
                    "file".to_string(),
                    "serve".to_string(),
                ],
                None,
                false,
                None,
            );
            assert!(unit.contains("ExecStart="));
            assert!(unit.contains("\"/usr/local/bin/credsd\""));
            assert!(unit.contains("\"serve\""));
            assert!(unit.contains(&format!("User={CREDSD_USER}")));
            assert!(unit.contains(&format!("Group={CREDSD_GROUP}")));
            assert!(unit.contains("RuntimeDirectory=credsd\n"));
            // Without it, a stopped or crashed service takes the socket file with it while the
            // .socket unit still reports active.
            assert!(unit.contains("RuntimeDirectoryPreserve=yes\n"));
            assert!(unit.contains("StateDirectory=credsd\n"));
            assert!(unit.contains("StateDirectoryMode=0700\n"));
            assert!(unit.contains("Restart=on-failure"));
            assert!(unit.contains("RestartSec=5"));
            // Activation is the socket's job: the service carries no [Install]/WantedBy, and the
            // ExecStart is never invoked with the per-user --user scope.
            assert!(!unit.contains("[Install]"));
            assert!(!unit.contains("WantedBy="));
            assert!(!unit.contains("--user"));
        }

        #[test]
        fn service_names_no_supplementary_group_unless_given() {
            let serve = ["serve".to_string()];
            let unit = render_service(
                Path::new("/usr/local/bin/credsd"),
                &serve,
                None,
                false,
                None,
            );
            assert!(!unit.contains("SupplementaryGroups="));

            let unit = render_service(
                Path::new("/usr/local/bin/credsd"),
                &serve,
                Some("tss"),
                false,
                None,
            );
            assert!(unit.contains("SupplementaryGroups=tss\n"));
            // The primary identity is unchanged: the group adds device access, nothing else.
            assert!(unit.contains(&format!("User={CREDSD_USER}")));
            assert!(unit.contains(&format!("Group={CREDSD_GROUP}")));
        }

        #[test]
        fn logs_directory_is_named_only_when_asked() {
            let serve = ["serve".to_string()];
            let path = Path::new("/usr/local/bin/credsd");
            assert!(!render_service(path, &serve, None, false, None).contains("LogsDirectory="));
            let unit = render_service(path, &serve, None, true, None);
            assert!(unit.contains("LogsDirectory=credsd\n"));
            assert!(unit.contains("LogsDirectoryMode=0700\n"));
        }

        #[test]
        fn tpm_group_is_omitted_for_a_non_tpm_backend() {
            let opts = InstallOpts {
                storage_backend: Some("file".to_string()),
                ..Default::default()
            };
            assert_eq!(tpm_device_group(&opts), None);
        }

        #[test]
        fn socket_is_world_connectable_and_binds_the_system_path() {
            let unit = render_socket(&system_socket_path());
            assert!(unit.contains(&format!("ListenStream={}", system_socket_path().display())));
            assert!(unit.contains("SocketMode=0666"));
            assert!(unit.contains(&format!("SocketUser={CREDSD_USER}")));
            assert!(unit.contains(&format!("SocketGroup={CREDSD_GROUP}")));
            assert!(unit.contains("WantedBy=sockets.target"));
            // `RuntimeDirectoryPreserve=yes` keeps `/run/credsd`, so nothing else unlinks the
            // socket after an uninstall.
            assert!(unit.contains("RemoveOnStop=yes\n"));
        }

        #[test]
        fn exec_start_round_trip() {
            let unit = render_service(
                Path::new("/usr/local/bin/credsd"),
                &[
                    "--log-file".to_string(),
                    "/tmp/credsd.log".to_string(),
                    "serve".to_string(),
                ],
                None,
                false,
                None,
            );
            let parsed = parse_exec_start(&unit);
            assert_eq!(
                parsed,
                vec![
                    "/usr/local/bin/credsd",
                    "--log-file",
                    "/tmp/credsd.log",
                    "serve"
                ]
            );
        }

        #[test]
        fn service_never_captures_stdio_to_file() {
            // Two writers would race the same file.
            let unit = render_service(
                Path::new("/usr/local/bin/credsd"),
                &[
                    "--log-file".to_string(),
                    "/var/log/credsd/credsd.log".to_string(),
                    "serve".to_string(),
                ],
                None,
                true,
                None,
            );
            for target in [
                "StandardOutput=file:",
                "StandardOutput=append:",
                "StandardOutput=truncate:",
                "StandardError=file:",
                "StandardError=append:",
                "StandardError=truncate:",
            ] {
                assert!(!unit.contains(target));
            }
        }

        /// A system install under a data-dir override names the same directory to the service,
        /// quoted so systemd reads it back verbatim.
        #[test]
        fn the_unit_carries_a_data_dir_override() {
            let serve = ["serve".to_string()];
            let dir = "/srv/cred sd/%h$x";
            let unit = render_service(
                Path::new("/usr/local/bin/credsd"),
                &serve,
                None,
                false,
                Some(dir),
            );
            assert!(
                unit.contains("Environment=\"CREDSD_DATA_DIR=/srv/cred sd/%%h$x\"\n"),
                "{unit}"
            );
            let none = render_service(
                Path::new("/usr/local/bin/credsd"),
                &serve,
                None,
                false,
                None,
            );
            assert!(!none.contains("Environment="));
        }

        /// Reads the `Environment=` value the way systemd does: strip the quotes, undo the C-style
        /// escapes, and collapse `%%` to `%`. `$` has no meaning in this context and stays literal.
        fn parse_environment(unit: &str) -> String {
            let line = unit
                .lines()
                .find_map(|l| l.strip_prefix("Environment="))
                .expect("unit has an Environment= line");
            let inner = line
                .strip_prefix('"')
                .and_then(|l| l.strip_suffix('"'))
                .expect("Environment= value is quoted");
            let mut out = String::new();
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => out.push(match chars.next() {
                        Some('n') => '\n',
                        Some('r') => '\r',
                        Some(other) => other,
                        None => panic!("dangling backslash in {inner:?}"),
                    }),
                    '%' => {
                        assert_eq!(chars.next(), Some('%'), "lone % in {inner:?}");
                        out.push('%');
                    }
                    other => out.push(other),
                }
            }
            out
        }

        proptest::proptest! {
            /// A data directory reads back from `Environment=` exactly as it was given, `$` included.
            /// Doubling `$` here would name a different home than the installer minted into.
            #[test]
            fn environment_value_round_trips_a_data_dir(
                dir in "/[a-z$%\\\\\"\n\r ]{0,24}",
            ) {
                let unit = render_service(
                    Path::new("/usr/local/bin/credsd"),
                    &["serve".to_string()],
                    None,
                    false,
                    Some(dir.as_str()),
                );
                proptest::prop_assert_eq!(
                    parse_environment(&unit),
                    format!("CREDSD_DATA_DIR={dir}")
                );
            }
        }

        #[test]
        fn quote_round_trips_metacharacters() {
            let weird = "/home/a b/%$\\\"\n\rx/credsd";
            let unit = render_service(Path::new(weird), &["serve".to_string()], None, false, None);
            let parsed = parse_exec_start(&unit);
            assert_eq!(parsed, vec![weird, "serve"]);
        }

        proptest::proptest! {
            /// The escape/unescape contract holds for arbitrary strings, not just the hand-picked
            /// cases above.
            #[test]
            fn exec_start_round_trips_arbitrary(
                binary in "[^\u{0}]{1,32}",
                args in proptest::collection::vec("[^\u{0}]{0,16}", 0..4),
            ) {
                let unit = render_service(Path::new(&binary), &args, None, false, None);
                let parsed = parse_exec_start(&unit);
                let mut expected = vec![binary];
                expected.extend(args);
                proptest::prop_assert_eq!(parsed, expected);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_options_yields_system_flag_only() {
        assert_eq!(build_serve_args(&InstallOpts::default()), vec!["--system"]);
    }

    #[cfg(target_os = "macos")]
    mod ancestor_trust {
        use super::super::ancestor_trusted;

        const ME: u32 = 501;
        const ADMIN: u32 = 80;
        const WHEEL: u32 = 0;
        const OTHER_USER: u32 = 502;
        const DIR: u32 = 0o040000;

        #[test]
        fn root_owned_unwritable_is_trusted() {
            assert!(ancestor_trusted(0, WHEEL, 0o755, ME, Some(ADMIN)));
        }

        #[test]
        fn own_unwritable_is_trusted() {
            assert!(ancestor_trusted(ME, 20, 0o700, ME, Some(ADMIN)));
        }

        #[test]
        fn third_party_owner_is_rejected() {
            assert!(!ancestor_trusted(OTHER_USER, 20, 0o755, ME, Some(ADMIN)));
        }

        #[test]
        fn other_writable_is_rejected() {
            assert!(!ancestor_trusted(0, WHEEL, 0o757, ME, Some(ADMIN)));
        }

        #[test]
        fn root_owned_trusted_group_writable_dir_is_accepted() {
            assert!(ancestor_trusted(0, ADMIN, DIR | 0o775, ME, Some(ADMIN)));
        }

        /// The exception admits a directory. A root-owned, group-writable *file* — a daemon
        /// binary anyone in the group could overwrite in place — is still refused.
        #[test]
        fn root_owned_trusted_group_writable_file_is_rejected() {
            assert!(!ancestor_trusted(0, ADMIN, 0o775, ME, Some(ADMIN)));
        }

        #[test]
        fn trusted_group_plus_other_writable_is_rejected() {
            assert!(!ancestor_trusted(0, ADMIN, DIR | 0o777, ME, Some(ADMIN)));
        }

        #[test]
        fn root_owned_other_group_writable_is_rejected() {
            assert!(!ancestor_trusted(0, 99, DIR | 0o775, ME, Some(ADMIN)));
        }

        #[test]
        fn own_group_writable_is_rejected() {
            assert!(!ancestor_trusted(ME, ADMIN, DIR | 0o775, ME, Some(ADMIN)));
        }

        #[test]
        fn without_a_trusted_group_every_group_writable_is_rejected() {
            assert!(!ancestor_trusted(0, ADMIN, DIR | 0o775, ME, None));
        }
    }

    /// The real predicate agrees with the pure one about this machine's `/Applications`,
    /// which is the whole reason the exception exists.
    #[cfg(target_os = "macos")]
    #[test]
    fn applications_directory_is_trusted_on_macos() {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata("/Applications").expect("/Applications exists on macOS");
        let uid = nix::unistd::getuid().as_raw();
        assert!(
            ancestor_trusted(m.uid(), m.gid(), m.mode(), uid, trusted_group_gid()),
            "/Applications ({:o}, uid {}, gid {}) must be an acceptable ancestor",
            m.mode() & 0o777,
            m.uid(),
            m.gid()
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn the_baked_backend_is_read_back_out_of_the_definition() {
        let args = program_arguments(
            &InstallOpts {
                storage_backend: Some("secure-enclave".to_string()),
                ..Default::default()
            },
            None,
        );
        assert_eq!(
            backend_from_args(&args),
            Some("secure-enclave".to_string()),
            "{args:?}"
        );
        assert_eq!(backend_from_args(&["serve".to_string()]), None);
        // A trailing flag with no value must not read the next definition line as one.
        assert_eq!(backend_from_args(&["--storage-backend".to_string()]), None);
    }

    /// The rollback a failed fresh install runs. Asserted on a real directory because the
    /// claim is about the filesystem, not about the call: the staged copy and the directory
    /// holding it both have to be gone, or the next install reads the machine as dirty.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn removing_a_staged_binary_takes_its_directory_with_it() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("credsd");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::write(dir.join("credsd"), b"#!/bin/sh\n").expect("staged binary");

        remove_staged_binary_in(&dir);

        assert!(!dir.exists(), "{} survived", dir.display());
    }

    /// A directory holding anything else is left alone: `remove_dir` is not recursive, so the
    /// staged names go and the directory stays. Nothing else writes there today, and the next
    /// install overwrites the copy rather than being confused by it.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn removing_a_staged_binary_spares_a_directory_something_else_uses() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("credsd");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::write(dir.join("credsd"), b"#!/bin/sh\n").expect("staged binary");
        std::fs::write(dir.join("something-else"), b"x").expect("other file");

        remove_staged_binary_in(&dir);

        assert!(dir.exists(), "a shared directory must survive");
        assert!(!dir.join("credsd").exists(), "the staged copy must not");
    }

    /// The three supported macOS paths are the signed release with `install --user` and a
    /// source build with `sudo install`. A user install is therefore the keychain or nothing:
    /// an enclave resolution means a build from source, which must be sent to the system
    /// service rather than given a LaunchAgent whose key any same-uid process could use.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_user_install_is_the_keychain_or_a_refusal() {
        use credsd_core::storage::Backend;
        assert_eq!(
            user_install_refusal(Backend::DataProtectionKeychain),
            None,
            "the released artifact's own path"
        );
        for backend in [Backend::SecureEnclave, Backend::File, Backend::Tpm] {
            let refusal = user_install_refusal(backend)
                .unwrap_or_else(|| panic!("{backend:?} must be refused for a user install"));
            assert!(refusal.contains(backend.as_str()), "{refusal}");
            assert!(refusal.contains("sudo credsd install"), "{refusal}");
        }
    }

    /// The mirror of the above, and the gate an explicit `--storage-backend` otherwise walks
    /// past: subtracting the enclave from the released daemon only closes the default path, so
    /// `sudo credsd install --storage-backend data-protection-keychain` reached a mint that
    /// succeeds as root in a login session and a service that could never repeat it. Every
    /// other backend a system service can hold must still pass.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_system_install_refuses_only_a_keystore_it_could_never_reach() {
        use credsd_core::storage::Backend;
        for backend in [Backend::SecureEnclave, Backend::Tpm, Backend::File] {
            assert_eq!(system_install_refusal(backend), None, "{backend:?}");
        }
        let refusal = system_install_refusal(Backend::DataProtectionKeychain)
            .expect("the keychain must be refused for a system install");
        assert!(refusal.contains("data-protection-keychain"), "{refusal}");
        assert!(refusal.contains("credsd install --user"), "{refusal}");
    }

    /// Asked before the tty prompt and before the running-service check, so this exercises the
    /// guard alone. KKRS answers for the calling uid, so a root purge of the service account's
    /// key searches the wrong keyring, finds nothing, and would report success.
    #[cfg(target_os = "linux")]
    #[test]
    fn purging_a_kkrs_key_is_refused_rather_than_reported_as_absent() {
        let err = purge_key_if_asked(true, false, Some("kkrs"), true)
            .expect_err("kkrs must be refused")
            .to_string();
        assert!(err.contains("per-uid"), "{err}");
    }

    /// A system definition naming the data protection keychain is the bug, not a backend the
    /// install is switching away from: that service could never reach it. Refusing over it
    /// would block every repair install on a machine the old resolution had already touched.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn an_unreachable_installed_backend_is_not_a_conflict_for_a_system_install() {
        let keychain = || Some("data-protection-keychain".to_string());
        assert_eq!(conflicting_installed_backend(keychain(), false), None);
        assert_eq!(conflicting_installed_backend(keychain(), true), keychain());
        // Reachable, and unparseable, both still compare.
        for name in ["tpm", "file", "something-this-build-never-heard-of"] {
            assert_eq!(
                conflicting_installed_backend(Some(name.to_string()), false),
                Some(name.to_string())
            );
        }
        assert_eq!(conflicting_installed_backend(None, false), None);
    }

    /// Reinstalling the same backend is the normal upgrade path and must stay silent; changing
    /// it orphans every sealed credential, so that one is refused with both names in the message.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn only_a_backend_change_blocks_a_reinstall() {
        assert_eq!(reinstall_backend_conflict(Some("tpm"), "tpm"), None);
        assert_eq!(reinstall_backend_conflict(None, "tpm"), None);
        let conflict =
            reinstall_backend_conflict(Some("data-protection-keychain"), "secure-enclave")
                .expect("a backend change must be refused");
        assert!(conflict.contains("data-protection-keychain"), "{conflict}");
        assert!(conflict.contains("secure-enclave"), "{conflict}");
        assert!(conflict.contains("--purge-key"), "{conflict}");
    }

    /// A reinstall whose new bundle fails the ownership check must leave the working one in
    /// place: the service definition names a path inside it, so losing both leaves a plist
    /// pointing at nothing. The check fails here for free — a tempdir is not root-owned — which
    /// is the same branch a bundle with group-writable modes takes.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_rejected_bundle_restores_the_one_it_replaced() {
        let src_root = tempfile::tempdir().expect("tempdir");
        let bundle = src_root.path().join("Credsd.app");
        let macos_dir = bundle.join("Contents/MacOS");
        std::fs::create_dir_all(&macos_dir).expect("bundle layout");
        let src = macos_dir.join("credsd");
        std::fs::write(&src, b"#!/bin/sh\n").expect("daemon binary");

        let staging = tempfile::tempdir().expect("tempdir");
        let installed = staging.path().join(SERVICE_BUNDLE_NAME);
        std::fs::create_dir_all(installed.join("Contents/MacOS")).expect("previous bundle");
        let marker = installed.join("Contents/MacOS/credsd");
        std::fs::write(&marker, b"the working install\n").expect("previous binary");

        let err = stage_service_bundle_in(staging.path(), &bundle, &src)
            .expect_err("a non-root-owned staging dir must be refused")
            .to_string();

        assert!(err.contains("restored"), "{err}");
        assert!(
            marker.exists(),
            "the previously installed bundle must survive"
        );
        assert_eq!(
            std::fs::read(&marker).expect("read"),
            b"the working install\n",
            "the previous bundle must not be replaced by the rejected one"
        );
        assert!(
            !staging.path().join(STAGING_BUNDLE_NAME).exists(),
            "the staging copy must not be left behind"
        );
        assert!(
            !staging.path().join(SUPERSEDED_BUNDLE_NAME).exists(),
            "the move-aside copy must not be left behind"
        );
    }

    /// Only the bundle layout the daemon actually ships in is staged as a bundle. A plain
    /// binary that merely sits under some `.app` is not one: staging its whole grandparent
    /// would copy an unrelated tree into the service's directory.
    #[cfg(target_os = "macos")]
    #[test]
    fn bundle_root_matches_only_the_shipped_layout() {
        let bundle = Path::new("/Applications/Credsd.app");
        assert_eq!(
            bundle_root(&bundle.join("Contents/MacOS/credsd")),
            Some(bundle)
        );
        for not_a_bundle in [
            "/Applications/Credsd.app/Contents/Resources/creds",
            "/Applications/Credsd.app/credsd",
            "/opt/credsd/credsd",
            "/usr/local/bin/credsd",
            "credsd",
        ] {
            assert_eq!(
                bundle_root(Path::new(not_a_bundle)),
                None,
                "{not_a_bundle} must not be staged as a bundle"
            );
        }
    }

    /// Refused before root, the backend probe, or the prompt, so it writes nothing on any host.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_refuses_user_install_and_uninstall() {
        let opts = InstallOpts {
            user: true,
            ..Default::default()
        };
        let err = install(&opts).unwrap_err().to_string();
        assert!(err.contains("sudo credsd install"), "{err}");
        assert!(uninstall(true, true, false, None).is_err());
    }

    #[test]
    fn user_install_yields_empty_serve_args() {
        let opts = InstallOpts {
            user: true,
            ..Default::default()
        };
        assert!(build_serve_args(&opts).is_empty());
    }

    /// The privilege boundary: `install` runs as root, so a tool it spawns must come from a
    /// root-owned directory and never from whatever `PATH` the invoking user brought along.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn tools_resolve_only_inside_the_system_directories() {
        let resolved = tool_path("sh").expect("sh must exist on a supported platform");
        assert!(resolved.is_absolute(), "{}", resolved.display());
        assert!(
            TOOL_DIRS
                .iter()
                .any(|dir| resolved.parent() == Some(Path::new(dir))),
            "{} is outside {}",
            resolved.display(),
            TOOL_DIRS.join(":")
        );
    }

    /// A tool planted on `PATH` must be invisible here. This is the exact `sudo credsd install`
    /// exposure on macOS, where sudo's `env_reset` keeps the caller's `PATH` for want of a
    /// `secure_path`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_tool_planted_on_path_is_not_resolved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let planted = dir.path().join("credsd-not-a-real-tool");
        std::fs::write(&planted, "#!/bin/sh\nexit 0\n").expect("write");

        // Set on this Command rather than the process env: `tool_path` must ignore `PATH`
        // entirely, so there is nothing to poison globally and no test-ordering hazard.
        let err = tool_path("credsd-not-a-real-tool")
            .expect_err("a tool that exists only on PATH must not resolve");
        assert!(
            err.to_string().contains("cannot find"),
            "unexpected error: {err}"
        );
    }

    /// Whatever the tool itself execs must be resolved the same way, so the child's `PATH` is
    /// the fixed list and not an inherited one.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn spawned_tools_get_the_fixed_path() {
        let cmd = tool_command("sh").expect("sh must exist on a supported platform");
        let path = cmd
            .get_envs()
            .find(|(k, _)| *k == std::ffi::OsStr::new("PATH"))
            .and_then(|(_, v)| v)
            .expect("PATH must be set on the command");
        assert_eq!(path, std::ffi::OsStr::new(&TOOL_DIRS.join(":")));
    }

    #[test]
    fn serve_bakes_insecure_backend_flag_for_file_backend() {
        let with_file = InstallOpts {
            storage_backend: Some("file".to_string()),
            ..Default::default()
        };
        assert_eq!(
            build_serve_args(&with_file),
            vec!["--system", "--insecure-backend"]
        );
        let with_file_user = InstallOpts {
            storage_backend: Some("file".to_string()),
            user: true,
            ..Default::default()
        };
        assert_eq!(
            build_serve_args(&with_file_user),
            vec!["--insecure-backend"]
        );
    }

    #[test]
    fn program_arguments_place_globals_before_serve() {
        let opts = InstallOpts {
            storage_backend: Some("file".to_string()),
            log_file: Some(PathBuf::from("/tmp/credsd.log")),
            quiet: false,
            ..Default::default()
        };
        let args = program_arguments(&opts, Some(Path::new("/tmp/credsd.log")));
        let serve_idx = args.iter().position(|a| a == "serve").unwrap();
        let backend_idx = args.iter().position(|a| a == "--storage-backend").unwrap();
        let logfile_idx = args.iter().position(|a| a == "--log-file").unwrap();
        assert!(backend_idx < serve_idx);
        assert!(logfile_idx < serve_idx);
        // `--insecure-backend` follows `serve` (serve-level flag, not global).
        let insecure_idx = args
            .iter()
            .position(|a| a == "--insecure-backend")
            .expect("--insecure-backend must be baked for file backend");
        assert!(insecure_idx > serve_idx);
    }

    #[test]
    fn program_arguments_bakes_log_file_only_when_explicit() {
        // --log-file is only baked when the operator passed it; otherwise the daemon applies
        // the documented precedence (flag > config > env > default) at startup as the service account.
        let without = program_arguments(&InstallOpts::default(), None);
        assert!(
            !without.contains(&"--log-file".to_string()),
            "must not bake --log-file when not explicit"
        );

        let args = program_arguments(
            &InstallOpts::default(),
            Some(Path::new("/var/log/credsd/credsd.log")),
        );
        let logfile_idx = args.iter().position(|a| a == "--log-file").unwrap();
        assert_eq!(args[logfile_idx + 1], "/var/log/credsd/credsd.log");
        assert!(logfile_idx < args.iter().position(|a| a == "serve").unwrap());
    }

    /// A binary only root can replace is baked in where it stands: no copy, and nothing written to
    /// the staging directory. `/bin/sh` stands in for an installed binary because both supported
    /// platforms ship it root-owned.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_trusted_binary_is_used_where_it_stands() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = PathBuf::from("/bin/sh");
        if !crate::config::platform::only_root_can_replace(&src) {
            return; // Nothing to assert on a host where even /bin/sh is not root-owned.
        }

        let staged = stage_service_binary_in(dir.path(), src.clone()).expect("trusted src");
        assert_eq!(staged.path, src);
        assert_eq!(staged.copied_from, None, "a trusted binary is not copied");
        assert!(staged.warning().is_none(), "no copy means no warning");
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("readdir").count(),
            0,
            "a trusted binary must not be copied anywhere"
        );
    }

    /// The warning names both files and points at the recovery commands, so a user whose service
    /// silently runs a copy of an older build can find out why. Constructed directly because the
    /// copy branch that produces it needs root to reach.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_staged_copy_warns_which_binary_the_service_runs() {
        let binary = ServiceBinary {
            path: PathBuf::from("/opt/credsd/credsd"),
            copied_from: Some(PathBuf::from("/home/dev/target/debug/credsd")),
        };
        let warning = binary.warning().expect("a copy must warn");
        assert!(
            warning.contains("/home/dev/target/debug/credsd"),
            "{warning}"
        );
        assert!(warning.contains("/opt/credsd/credsd"), "{warning}");
        assert!(warning.contains("does NOT update the service"), "{warning}");
        assert!(warning.contains("credsd install"), "{warning}");
    }

    /// A destination whose ancestors are not root-owned is refused, and refused *before* anything
    /// is created — a rejected install leaves no directory behind. The tempdir stands in for a
    /// user-owned prefix, the Intel Homebrew `/usr/local` case that motivated staging into a
    /// directory install creates rather than a shared `bin`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn an_untrusted_destination_is_refused_before_anything_is_created() {
        if nix::unistd::geteuid().is_root() {
            return; // Under root the tempdir is root-owned, i.e. trusted, and there is no refusal.
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("credsd");
        std::fs::write(&src, b"not really a binary").expect("write src");
        let dst_dir = dir.path().join("bin");

        let err = stage_service_binary_in(&dst_dir, src)
            .expect_err("a destination under a non-root-owned prefix must be refused");
        assert!(
            err.to_string().contains("refusing to install"),
            "unexpected error: {err}"
        );
        assert!(
            !dst_dir.exists(),
            "{} was created by a refused install",
            dst_dir.display()
        );
    }

    /// The daemon's bundle identifier. Kept in sync with the literal in `build.rs` by
    /// [`embedded_plist_identity`], which reads the plist actually embedded in the binary. A
    /// build script cannot import a crate const, so this is the crate-side copy the test pins.
    const BUNDLE_IDENTIFIER: &str = "com.amazon.aws.credsd.daemon";

    /// The Info.plist `build.rs` embeds in the binary's `__TEXT,__info_plist` section, read as
    /// the linker sees it. `build.rs` cannot import a crate const — a build script does not link
    /// the crate it builds — so the identifier is a literal there, and this pins that literal to
    /// [`BUNDLE_IDENTIFIER`]. An identifier is baked into signatures and Keychain item ownership,
    /// so drift is expensive to discover after signing.
    #[test]
    fn embedded_plist_identity() {
        let plist = include_str!(concat!(env!("OUT_DIR"), "/Info.plist"));
        assert!(
            plist.contains(&format!(
                "<key>CFBundleIdentifier</key>\n    <string>{BUNDLE_IDENTIFIER}</string>"
            )),
            "CFBundleIdentifier is not {BUNDLE_IDENTIFIER}:\n{plist}"
        );
        // A `[[bin]]` rename that left build.rs behind cannot silently drop the section — Cargo
        // rejects a `rustc-link-arg-bin` naming no bin target — but nothing but this checks that
        // the embedded plist still names the binary it is embedded in, which is what a packaging
        // or signing script keys on.
        assert!(
            plist.contains(&format!(
                "<key>CFBundleExecutable</key>\n    <string>{}</string>",
                env!("CARGO_BIN_NAME")
            )),
            "CFBundleExecutable is not the bin name {}:\n{plist}",
            env!("CARGO_BIN_NAME")
        );
        assert!(
            plist.contains(&format!("<string>{}</string>", env!("CARGO_PKG_VERSION"))),
            "no substituted version in:\n{plist}"
        );
        assert!(
            !plist.contains('@'),
            "unsubstituted placeholder in:\n{plist}"
        );
    }

    /// A directory the service user already owns is the re-install case, and the one thing
    /// `own_log_dir` may do quietly — beyond narrowing the umask mode an earlier install left.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn an_already_owned_log_dir_is_kept_and_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        // No chown is attempted, so this passes without root — which is the point of the split.
        own_log_dir_for_uid(&dir.path().join("credsd.log"), uid).expect("an owned dir is fine");
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, LOG_DIR_MODE);
    }

    /// A symlink in the log directory's place is how a user who can write its parent gets root's
    /// chown pointed elsewhere. Live or dangling, it must be refused before any chown runs —
    /// these pass without root because neither reaches one.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_symlinked_log_dir_is_refused_live_or_dangling() {
        use std::os::unix::fs::MetadataExt;
        let parent = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");
        let uid = nix::unistd::geteuid().as_raw();
        let before = std::fs::metadata(target.path()).unwrap().uid();

        for (name, points_at) in [
            ("live", target.path().to_path_buf()),
            ("dangling", parent.path().join("missing")),
        ] {
            let link = parent.path().join(name);
            std::os::unix::fs::symlink(&points_at, &link).unwrap();
            let err = own_log_dir_for_uid(&link.join("credsd.log"), uid)
                .expect_err("a symlinked log directory must be refused")
                .to_string();
            assert!(err.contains("is not a directory"), "{name}: {err}");
        }
        assert_eq!(std::fs::metadata(target.path()).unwrap().uid(), before);
    }

    /// The race itself: the caller saw nothing, then a symlink appeared before `mkdir`. EEXIST
    /// from `mkdir` must not read as "already there, carry on".
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_symlink_planted_before_mkdir_is_refused() {
        let parent = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");
        let link = parent.path().join("logs");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();
        let err = create_owned_dir(&link, LOG_DIR_MODE)
            .expect_err("EEXIST on a symlink must be refused")
            .to_string();
        assert!(err.contains("is not a directory"), "{err}");
    }

    /// `sudo /opt/credsd/credsd install` bakes the legacy copy into the unit; deleting it then
    /// leaves `ExecStart` naming a missing file.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_legacy_copy_the_unit_still_names_is_kept() {
        let legacy = tempfile::tempdir().expect("tempdir");
        let binary = legacy.path().join("credsd");
        std::fs::write(&binary, b"").unwrap();

        remove_superseded_staged_binary(&binary, legacy.path());
        assert!(binary.exists(), "the binary the unit names was removed");

        remove_superseded_staged_binary(
            Path::new("/usr/local/libexec/credsd/credsd"),
            legacy.path(),
        );
        assert!(!binary.exists(), "a superseded legacy copy was left behind");
    }

    /// The two paths that motivated the guard. `--log-file` is a plain flag, so both are one
    /// plausible typo away, and chowning the parent unconditionally handed `/var/log` — every
    /// other service's logs — or `/` itself to the `credsd` service account.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_shared_system_log_dir_is_refused_by_name() {
        for log in ["/var/log/credsd.log", "/credsd.log"] {
            let err = own_log_dir_for_uid(Path::new(log), u32::MAX)
                .expect_err("a directory owned by somebody else must be refused");
            let err = err.to_string();
            let dir = Path::new(log).parent().unwrap().display().to_string();
            assert!(err.contains("refusing to install"), "{log}: {err}");
            assert!(err.contains(&dir), "{log}: {err} does not name {dir}");
        }
    }

    proptest::proptest! {
        /// Whatever `--log-file` names, install must not take over a directory that already
        /// belongs to somebody else — and must not have touched its ownership on the way to
        /// saying so. `u32::MAX` stands in for the service uid because no directory can own it,
        /// which makes every pre-existing parent here somebody else's.
        ///
        /// Generated over path *shapes* rather than a fixed list because the guard hinges on
        /// `Path::parent`, whose answer for a trailing separator, a `..`, or a dotfile is exactly
        /// where a hand-written case list stops looking.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        #[test]
        fn no_log_path_takes_a_directory_install_did_not_create(
            // Existing directories only: a missing parent is install's to create, a different
            // branch, and generating one under /etc would have a root test run create it.
            parent in proptest::sample::select(vec!["/", "/etc", "/var", "/var/log", "/usr", "/tmp"]),
            name in "[a-zA-Z0-9._-]{1,12}|[.][.]|x/",
        ) {
            use std::os::unix::fs::MetadataExt;

            let before = std::fs::metadata(parent).expect("sampled dirs exist").uid();
            let log = PathBuf::from(format!("{parent}/{name}"));
            // Only exercise shapes whose parent is the sampled directory; anything else is the
            // create branch, which this property says nothing about.
            proptest::prop_assume!(log.parent() == Some(Path::new(parent)));

            proptest::prop_assert!(
                own_log_dir_for_uid(&log, u32::MAX).is_err(),
                "{} must not be taken over", log.display()
            );
            proptest::prop_assert_eq!(
                std::fs::metadata(parent).expect("still there").uid(),
                before,
                "ownership of {} changed", parent
            );
        }

        #[test]
        fn program_arguments_always_contain_serve(
            backend in proptest::option::of("[a-z]{1,8}"),
            quiet in proptest::bool::ANY,
        ) {
            let opts = InstallOpts {
                storage_backend: backend,
                log_file: None,
                quiet,
                ..Default::default()
            };
            let args = program_arguments(&opts, None);
            proptest::prop_assert!(args.contains(&"serve".to_string()));
        }
    }
}
