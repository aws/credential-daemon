//! Secure storage abstraction and platform backend selection.

#[cfg(target_os = "windows")]
mod dpapi;
// Opt-in on macOS: every Mac with a Secure Enclave has a hardware-bound backend for each install
// scope, so the official build omits `file`. The feature exists for Macs without one (VMs,
// pre-T2 Intel). Elsewhere there is no guarantee of hardware-backed storage, so it is always in.
#[cfg(any(not(target_os = "macos"), feature = "file"))]
mod file;
// Opt-in behind the `kkrs` feature and absent from every shipped build; see
// `docs/specs/kkrs-encryption-backend/` for what has to be fixed before it ships.
#[cfg(all(target_os = "linux", feature = "kkrs"))]
pub(crate) mod linux_kkrs;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod secure_enclave;
#[cfg(target_os = "linux")]
mod tpm;
#[cfg(target_os = "windows")]
mod windows;

use crate::error::{DaemonError, Result};
#[cfg(unix)]
use std::path::{Path, PathBuf};

/// Credential-store namespace — the key under which the daemon files secrets.
///
/// Used as the macOS Keychain service name (`storage::macos`) and the Linux
/// kernel-keyring description prefix (`SERVICE_NAME:<key_id>`). Deliberately its
/// own identity, distinct from the OS service labels (the launchd label and
/// systemd unit name in `install`): those follow per-platform naming conventions
/// (reverse-DNS on macOS, a short name on Linux) and could be renamed for
/// branding, but this is *where credentials live*, so it stays stable so a label
/// rename never orphans stored secrets.
pub const SERVICE_NAME: &str = "com.amazon.aws.credsd";

/// The instance namespace of `home`: the discriminator that keys a slot a backend holds outside
/// the home it belongs to (`storage-backend-per-home` Requirements 5.1-5.3). Two homes on one
/// machine, under one uid, derive different namespaces, so neither reads the other's slot as its
/// own.
///
/// Derived from the home's path, so it needs no stored state and nothing a caller can write
/// decides it. The deepest existing ancestor is resolved and the remainder appended, so a home
/// yields the same namespace before and after it is created — on macOS `/var/...` and
/// `/private/var/...` are one home, and `canonicalize` alone would answer differently depending
/// on whether the leaf exists yet. Moving a home changes its namespace; its slots stay with the
/// path they were written under.
///
/// The walk is component by component. While the prefix exists, the filesystem resolves it, so
/// `..` after an existing prefix steps up from the resolved directory as the kernel would. Once a
/// component is missing, the rest is lexical: `.` is dropped and `..` removes the previous missing
/// component, which cannot be a symlink. For example, with only `/tmp` existing,
/// `/tmp/new/../home` resolves `/tmp`, holds `new` as missing, pops it at `..`, and ends at
/// `/tmp/home` — the directory `create_dir_all` makes for that path — so creating it does not
/// move the namespace (Requirement 5.2).
pub fn instance_namespace(home: &std::path::Path) -> String {
    use std::path::Component;
    // `join` keeps an absolute `home` as it is, so only a relative one meets the cwd.
    let absolute = std::env::current_dir()
        .map(|cwd| cwd.join(home))
        .unwrap_or_else(|_| home.to_path_buf());
    let mut resolved = std::path::PathBuf::new();
    let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => resolved.push(component),
            Component::CurDir => {}
            Component::ParentDir if missing.is_empty() => {
                resolved.pop();
            }
            Component::ParentDir => {
                missing.pop();
            }
            Component::Normal(name) if missing.is_empty() => {
                match resolved.join(name).canonicalize() {
                    Ok(next) => resolved = next,
                    Err(_) => missing.push(name),
                }
            }
            Component::Normal(name) => missing.push(name),
        }
    }
    let full = missing.iter().fold(resolved, |path, name| path.join(name));
    let digest = crate::presence::sha256(full.as_os_str().as_encoded_bytes());
    crate::presence::hex(&digest[..8])
}

/// Platform credential storage abstraction (Keychain, DPAPI, file-based).
pub trait SecureStorage: Send + Sync {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<()>;
    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>>;
    fn delete(&self, key_id: &str) -> Result<()>;
    fn exists(&self, key_id: &str) -> Result<bool>;
    fn backend_name(&self) -> &'static str;
    /// Runtime availability probe. Returns `false` if the backend requires hardware
    /// or entitlements absent on this host. Default: `true`.
    fn is_available(&self) -> bool {
        true
    }
}

/// Available platform storage backends for encryption key persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// macOS Data Protection Keychain — SE-backed, device-bound. Requires the daemon's
    /// `keychain-access-groups` entitlement (`packaging/credsd.entitlements`).
    DataProtectionKeychain,
    SecureEnclave,
    Dpapi,
    CredentialManager,
    Tpm,
    /// Kernel keyring (KKRS), Linux only — master key in kernel memory, wiped on
    /// reboot. Compiled only with the `kkrs` feature; explicit opt-in only, never
    /// auto-detected.
    KernelKeyring,
    File,
    /// A storage backend not recognised by this version.
    Unknown,
}

impl Backend {
    /// The backends this binary was built with, whether or not this host can use them. Printed
    /// by `credsd --version` so a release build can be checked for what it ships.
    pub const COMPILED: &'static [Backend] = &[
        #[cfg(target_os = "macos")]
        Self::DataProtectionKeychain,
        #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
        Self::SecureEnclave,
        #[cfg(target_os = "windows")]
        Self::Dpapi,
        #[cfg(target_os = "windows")]
        Self::CredentialManager,
        #[cfg(all(target_os = "linux", feature = "tpm"))]
        Self::Tpm,
        #[cfg(all(target_os = "linux", feature = "kkrs"))]
        Self::KernelKeyring,
        #[cfg(any(not(target_os = "macos"), feature = "file"))]
        Self::File,
    ];

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "data-protection-keychain" => Some(Self::DataProtectionKeychain),
            "secure-enclave" => Some(Self::SecureEnclave),
            "dpapi" => Some(Self::Dpapi),
            "credential-manager" => Some(Self::CredentialManager),
            "tpm" => Some(Self::Tpm),
            "kkrs" => Some(Self::KernelKeyring),
            "file" => Some(Self::File),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DataProtectionKeychain => "data-protection-keychain",
            Self::SecureEnclave => "secure-enclave",
            Self::Dpapi => "dpapi",
            Self::CredentialManager => "credential-manager",
            Self::Tpm => "tpm",
            Self::KernelKeyring => "kkrs",
            Self::File => "file",
            Self::Unknown => "unknown",
        }
    }

    pub fn is_available(&self) -> bool {
        match self {
            Self::DataProtectionKeychain => {
                #[cfg(target_os = "macos")]
                {
                    macos::DataProtectionKeychainStorage::new().is_available()
                }
                #[cfg(not(target_os = "macos"))]
                {
                    false
                }
            }
            Self::SecureEnclave => Self::probe_secure_enclave(),
            Self::Dpapi => cfg!(target_os = "windows"),
            Self::CredentialManager => {
                cfg!(target_os = "windows") && Self::probe_credential_manager()
            }
            // The device node alone is not a usable TPM: a build without the `tpm` feature has
            // no seam to reach it, and selecting it would read a sealed key as lost TPM state.
            Self::Tpm => Self::COMPILED.contains(&Self::Tpm) && Self::probe_tpm(),
            Self::KernelKeyring => Self::COMPILED.contains(&Self::KernelKeyring),
            Self::File => Self::COMPILED.contains(&Self::File),
            Self::Unknown => false,
        }
    }

    /// Whether *this process* can use the Secure Enclave — hardware present, the
    /// `secure-enclave` feature compiled in, and the shim reachable. Not merely "this Mac has an
    /// enclave": a build without the feature must never be offered a backend whose seal fails.
    fn probe_secure_enclave() -> bool {
        #[cfg(target_os = "macos")]
        {
            secure_enclave::available()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    fn probe_tpm() -> bool {
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new("/dev/tpmrm0").exists()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn probe_credential_manager() -> bool {
        #[cfg(target_os = "windows")]
        {
            let storage = windows::CredentialManagerStorage::new();
            let probe_id = "credsd-probe-cm";
            match storage.store(probe_id, b"probe") {
                Ok(_) => {
                    let _ = storage.delete(probe_id);
                    true
                }
                Err(_) => false,
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }
}

/// Select storage backend: the explicit arg (`--storage-backend`), else auto-detect.
///
/// There is deliberately no environment-variable route. Anything running as the daemon's uid
/// can set one (a shell profile, `launchctl setenv`), which would make the backend a same-uid
/// downgrade lever.
pub fn select_backend(explicit: Option<&str>) -> Result<Backend> {
    if let Some(s) = explicit {
        let b = Backend::parse(s).ok_or_else(|| {
            let valid: Vec<&str> = Backend::COMPILED.iter().map(Backend::as_str).collect();
            DaemonError::config(format!(
                "unknown storage backend '{}'. Valid: {}",
                s,
                valid.join(", ")
            ))
        })?;
        if !b.is_available() {
            let feature_gated_here = match b {
                Backend::File | Backend::SecureEnclave => cfg!(target_os = "macos"),
                Backend::Tpm | Backend::KernelKeyring => cfg!(target_os = "linux"),
                _ => false,
            };
            if feature_gated_here && !Backend::COMPILED.contains(&b) {
                return Err(DaemonError::config(format!(
                    "storage backend '{s}' is not compiled into this build; rebuild with \
                     `--features {s}`"
                )));
            }
            if b == Backend::CredentialManager {
                return Err(DaemonError::config(
                    "Storage backend 'credential-manager' requires an interactive logon session. \
                     Connect via RDP/console, or change storage_backend to 'dpapi' and re-bootstrap.",
                ));
            }
            return Err(DaemonError::config(format!(
                "storage backend '{}' is not available on this platform",
                s
            )));
        }
        return Ok(b);
    }
    auto_detect()
}

/// Auto-detect the storage backend when none is explicitly requested.
///
/// On Linux this resolves to `tpm` iff a usable TPM 2.0 device is present, and
/// otherwise returns a configuration error requiring an explicit choice — it
/// never silently falls back to `file` (or `kkrs`), because those software-only
/// backends carry materially weaker/different guarantees and a silent fallback
/// would be a silent posture change. See `docs/specs/tpm-encryption-backend/`.
fn auto_detect() -> Result<Backend> {
    #[cfg(target_os = "macos")]
    {
        // Data Protection Keychain first: in a user-scoped install it is the only custody the
        // caller's uid cannot read, so it must win over `secure-enclave`'s 0600 file. A
        // LaunchDaemon has no login session to reach it, so a system install falls through to
        // `secure-enclave`, the only hardware-bound backend reachable there. Neither available
        // is an error, never `file`, which is used only when named.
        if Backend::DataProtectionKeychain.is_available() {
            Ok(Backend::DataProtectionKeychain)
        } else if Backend::SecureEnclave.is_available() {
            Ok(Backend::SecureEnclave)
        } else {
            Err(DaemonError::config(
                "no hardware-backed storage available (no entitled data protection keychain, no \
                 reachable Secure Enclave). On a Mac without a Secure Enclave, build with \
                 `--features file` and re-run with `--storage-backend file` — note the `file` \
                 backend protects the encryption key with filesystem permissions only.",
            ))
        }
    }

    #[cfg(target_os = "windows")]
    {
        Ok(Backend::Dpapi)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if Backend::Tpm.is_available() {
            Ok(Backend::Tpm)
        } else {
            Err(DaemonError::config(
                "no hardware-backed storage available (no usable TPM 2.0 device, or this \
                 build lacks the `tpm` feature). \
                 Re-run with an explicit backend, e.g. `--storage-backend file` — \
                 note the `file` backend protects \
                 the encryption key with filesystem permissions only.",
            ))
        }
    }
}

/// Whether a *system service*'s own process could reach `b`. Only the data protection keychain
/// is excluded: it needs a login session, which a LaunchDaemon has none of.
pub fn reachable_by_system_service(b: Backend) -> bool {
    !matches!(b, Backend::DataProtectionKeychain)
}

/// [`Backend::COMPILED`] narrowed to [`reachable_by_system_service`].
pub fn system_service_backends() -> Vec<Backend> {
    Backend::COMPILED
        .iter()
        .copied()
        .filter(|&b| reachable_by_system_service(b))
        .collect()
}

/// Number of quarantine generations kept after a recovery event; older ones are
/// pruned. Removing older generations is the only delete recovery performs —
/// bounded self-cleanup of our own backups.
#[cfg(unix)]
const QUARANTINE_GENERATIONS: usize = 3;

/// Move sealed credential artifacts a regenerated master key can no longer
/// decrypt out of the scanned credential trees and into a timestamped quarantine
/// generation under the daemon data dir. Invoked by the key-init path after a TPM
/// unseal failure or a KKRS keyring loss (Linux only), and by `uninstall --purge-key`.
///
/// Non-destructive: after a TPM reset or a kernel-keyring wipe the old `.enc`
/// blobs are permanently undecryptable, so they are moved aside — not deleted —
/// for possible off-line recovery, while `credential_status` reads a clean "no
/// session". Shared by the TPM and KKRS backends; one daemon-wide master key
/// protects every blob, so the helper scans both the daemon tree
/// (`callers/*/credentials/*/*.enc`) and the legacy standalone tree
/// (`credentials/*/*.enc`).
#[cfg(target_os = "linux")]
pub(crate) fn quarantine_sealed_credentials_after_reseal() {
    quarantine_sealed_credentials_in(&crate::config::platform::data_dir());
}

/// [`quarantine_sealed_credentials_after_reseal`] parameterized on the data dir, so a
/// user-scoped caller can name its own. Best-effort: logs and continues per file so recovery
/// never wedges startup.
#[cfg(unix)]
pub(crate) fn quarantine_sealed_credentials_in(data_dir: &Path) {
    let orphans = collect_orphan_enc_files(data_dir);
    if orphans.is_empty() {
        return;
    }
    let quarantine_root = data_dir.join("quarantine");
    let generation = match create_generation_dir(&quarantine_root) {
        Some(g) => g,
        None => return,
    };
    for (src, rel) in orphans {
        move_into_quarantine(&src, &generation, &rel);
    }
    prune_generations(&quarantine_root, QUARANTINE_GENERATIONS);
}

/// Collect every sealed `*.enc` file under the daemon and legacy credential
/// trees, each paired with its path relative to `data_dir` (mirrored under the
/// quarantine generation). A top-level loose file or a non-`.enc` file is left
/// untouched.
#[cfg(unix)]
fn collect_orphan_enc_files(data_dir: &Path) -> Vec<(PathBuf, PathBuf)> {
    let mut out = Vec::new();
    collect_enc_in_cred_tree(&data_dir.join("credentials"), data_dir, &mut out);
    if let Ok(callers) = std::fs::read_dir(data_dir.join("callers")) {
        for uid in callers.flatten() {
            let uid_path = uid.path();
            if uid_path.is_dir() {
                collect_enc_in_cred_tree(&uid_path.join("credentials"), data_dir, &mut out);
            }
        }
    }
    out
}

/// Collect `<cred_tree>/<name>/*.enc` into `out`, paired with the path relative
/// to `data_dir`. Only files directly inside a `<name>/` dir are collected, so a
/// loose file at the tree root is left alone.
#[cfg(unix)]
fn collect_enc_in_cred_tree(cred_tree: &Path, data_dir: &Path, out: &mut Vec<(PathBuf, PathBuf)>) {
    let entries = match std::fs::read_dir(cred_tree) {
        Ok(e) => e,
        Err(_) => return,
    };
    for name in entries.flatten() {
        let name_path = name.path();
        if !name_path.is_dir() {
            continue;
        }
        let files = match std::fs::read_dir(&name_path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(dir = %name_path.display(), "quarantine: cannot list credential dir: {e}");
                continue;
            }
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension().and_then(|s| s.to_str()) == Some("enc") {
                if let Ok(rel) = path.strip_prefix(data_dir) {
                    out.push((path.clone(), rel.to_path_buf()));
                }
            }
        }
    }
}

/// Create `quarantine/` and a fresh timestamped generation dir under it (both
/// `0700`). The name is a filesystem-safe, lexically sortable UTC timestamp; a
/// same-second collision gets a numeric suffix so two events never merge.
#[cfg(unix)]
fn create_generation_dir(quarantine_root: &Path) -> Option<PathBuf> {
    if let Err(e) = create_dir_0700(quarantine_root) {
        tracing::warn!(dir = %quarantine_root.display(), "quarantine: cannot create root: {e}");
        return None;
    }
    use std::os::unix::fs::DirBuilderExt;
    let stamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
    // Exclusive, non-recursive create: `DirBuilder::create` fails with `AlreadyExists` rather
    // than succeeding idempotently the way `create_dir_all` would. An `exists()`-then-create
    // check is a TOCTOU — two concurrent recoveries that pick the same timestamp would both
    // pass it and merge into one generation dir, silently overwriting same-named blobs. Here
    // the loser of the race gets `AlreadyExists` and takes the next suffix instead.
    let mut n: u32 = 0;
    loop {
        let candidate = if n == 0 {
            quarantine_root.join(&stamp)
        } else {
            quarantine_root.join(format!("{stamp}.{n}"))
        };
        match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => return Some(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                n = n.saturating_add(1);
                if n == u32::MAX {
                    tracing::warn!(dir = %candidate.display(), "quarantine: generation-dir suffixes exhausted");
                    return None;
                }
            }
            Err(e) => {
                tracing::warn!(dir = %candidate.display(), "quarantine: cannot create generation dir: {e}");
                return None;
            }
        }
    }
}

/// Move one sealed file into the generation dir, mirroring its relative path and
/// keeping `0600`. `rename` within a filesystem; fsync'd copy-then-remove across
/// mounts, which is inherently non-atomic (see the EXDEV branch).
#[cfg(unix)]
fn move_into_quarantine(src: &Path, generation: &Path, rel: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let dest = generation.join(rel);
    if let Some(parent) = dest.parent() {
        if let Err(e) = create_dir_0700(parent) {
            tracing::warn!(file = %src.display(), "quarantine: cannot create destination dir: {e}");
            return;
        }
    }
    if std::fs::rename(src, &dest).is_err() {
        // Cross-filesystem rename fails with EXDEV; fall back to copy + remove.
        // A cross-fs move is inherently copy-then-unlink — no rename spans mounts
        // atomically — so fsync the copy and the directory entry that now names it
        // before unlinking the original: a crash mid-move can then never lose both
        // copies. If the unlink itself fails the original simply survives (a stale
        // session, logged below) — never data loss.
        if let Err(e) = std::fs::copy(src, &dest) {
            tracing::warn!(file = %src.display(), "quarantine: cannot copy sealed file: {e}");
            return;
        }
        let durable = std::fs::File::open(&dest)
            .and_then(|f| f.sync_all())
            .and_then(|()| match dest.parent() {
                Some(parent) => std::fs::File::open(parent).and_then(|d| d.sync_all()),
                None => Ok(()),
            });
        if let Err(e) = durable {
            tracing::warn!(file = %dest.display(), "quarantine: cannot fsync quarantined copy, keeping original: {e}");
            return;
        }
        if let Err(e) = std::fs::remove_file(src) {
            tracing::warn!(file = %src.display(), "quarantine: moved but cannot remove original: {e}");
        }
    }
    let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600));
}

/// Keep the newest `keep` generation dirs (names sort chronologically), removing
/// older ones. This is the only delete: bounded self-cleanup of our own backups.
#[cfg(unix)]
fn prune_generations(quarantine_root: &Path, keep: usize) {
    let mut gens: Vec<PathBuf> = match std::fs::read_dir(quarantine_root) {
        Ok(e) => e
            .flatten()
            .map(|d| d.path())
            .filter(|p| p.is_dir())
            .collect(),
        Err(_) => return,
    };
    if gens.len() <= keep {
        return;
    }
    gens.sort();
    let remove_count = gens.len().saturating_sub(keep);
    for old in gens.into_iter().take(remove_count) {
        if let Err(e) = std::fs::remove_dir_all(&old) {
            tracing::warn!(dir = %old.display(), "quarantine: cannot prune old generation: {e}");
        }
    }
}

/// Create a directory (and parents) restricted to `0700`.
#[cfg(unix)]
fn create_dir_0700(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    Ok(())
}

/// Construct the storage implementation for a given backend.
pub fn create_storage(backend: Backend) -> Result<Box<dyn SecureStorage>> {
    match backend {
        Backend::DataProtectionKeychain => {
            #[cfg(target_os = "macos")]
            {
                let dp = macos::DataProtectionKeychainStorage::new();
                if dp.is_available() {
                    Ok(Box::new(dp))
                } else {
                    Err(DaemonError::config(
                        "data-protection-keychain requires the daemon's keychain-access-groups \
                         entitlement (94KV3E626L.com.amazon.aws.credsd.daemon), which only the \
                         signed release build carries; use 'secure-enclave'",
                    ))
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(DaemonError::config(
                    "data-protection-keychain backend requires macOS",
                ))
            }
        }
        Backend::Dpapi => {
            #[cfg(target_os = "windows")]
            {
                let ds = dpapi::DpapiStorage::new();
                maybe_migrate_from_credential_manager(&ds);
                Ok(Box::new(ds))
            }
            #[cfg(not(target_os = "windows"))]
            {
                Err(DaemonError::config("dpapi backend requires Windows"))
            }
        }
        Backend::CredentialManager => {
            #[cfg(target_os = "windows")]
            {
                if !Backend::probe_credential_manager() {
                    return Err(DaemonError::config(
                        "Storage backend 'credential-manager' requires an interactive logon session. \
                         Connect via RDP/console, or change storage_backend to 'dpapi' and re-bootstrap.",
                    ));
                }
                Ok(Box::new(windows::CredentialManagerStorage::new()))
            }
            #[cfg(not(target_os = "windows"))]
            {
                Err(DaemonError::config(
                    "credential-manager backend requires Windows",
                ))
            }
        }
        Backend::SecureEnclave => {
            #[cfg(target_os = "macos")]
            {
                if !Backend::probe_secure_enclave() {
                    return Err(DaemonError::config(
                        "storage backend 'secure-enclave' is unavailable: either this build lacks \
                         the `secure-enclave` feature or this Mac has no Secure Enclave. \
                         Without one, build with `--features file` and re-run with \
                         `--storage-backend file`.",
                    ));
                }
                secure_enclave::production_storage()
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(DaemonError::config("secure-enclave backend requires macOS"))
            }
        }
        Backend::Tpm => {
            #[cfg(target_os = "linux")]
            {
                tpm::production_storage()
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(DaemonError::config("tpm backend requires Linux"))
            }
        }
        Backend::KernelKeyring => {
            #[cfg(all(target_os = "linux", feature = "kkrs"))]
            {
                Ok(Box::new(linux_kkrs::KkrsStorage::new()))
            }
            #[cfg(all(target_os = "linux", not(feature = "kkrs")))]
            {
                Err(DaemonError::config(
                    "storage backend 'kkrs' is not compiled into this build; rebuild with \
                     `--features kkrs`",
                ))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(DaemonError::config("kkrs backend requires Linux"))
            }
        }
        Backend::File => {
            #[cfg(any(not(target_os = "macos"), feature = "file"))]
            {
                Ok(Box::new(file::FileStorage::new()))
            }
            #[cfg(all(target_os = "macos", not(feature = "file")))]
            {
                Err(DaemonError::config(
                    "storage backend 'file' is not compiled into this build; rebuild with \
                     `--features file`",
                ))
            }
        }
        Backend::Unknown => Err(crate::error::DaemonError::config("unknown storage backend")),
    }
}

#[cfg(target_os = "windows")]
fn maybe_migrate_from_credential_manager(dpapi_storage: &dpapi::DpapiStorage) {
    use crate::storage::SecureStorage;

    // If we cannot stat the DPAPI slot, assume the key may already be there and skip migration.
    if dpapi_storage
        .exists("daemon-encryption-key")
        .unwrap_or(true)
    {
        return;
    }

    let cm = windows::CredentialManagerStorage::new();
    // If we cannot stat the CM slot, skip migration rather than risk a bad store.
    if !cm.exists("daemon-encryption-key").unwrap_or(false) {
        return;
    }

    match cm.retrieve("daemon-encryption-key") {
        Ok(key_data) => {
            if let Err(e) = dpapi_storage.store("daemon-encryption-key", &key_data) {
                tracing::warn!(
                    "failed to migrate encryption key to DPAPI: {}. Run 'credsd bootstrap' to re-authenticate.",
                    e
                );
                return;
            }
            let _ = cm.delete("daemon-encryption-key");
            tracing::info!("migrated encryption key from Credential Manager to DPAPI");
        }
        Err(e) => {
            tracing::warn!(
                "cannot read encryption key from Credential Manager (session type may not support it): {}. \
                 Run 'credsd bootstrap' to re-authenticate.",
                e
            );
        }
    }
}

#[cfg(target_os = "windows")]
pub use dpapi::DpapiStorage;
#[cfg(any(not(target_os = "macos"), feature = "file"))]
pub use file::FileStorage;
#[cfg(target_os = "windows")]
pub use windows::CredentialManagerStorage;

#[cfg(test)]
mod tests {
    use super::*;

    /// Requirements 5.2-5.3 of `storage-backend-per-home`: distinct between homes, and the same
    /// answer for one home whether or not it exists yet, so creating a home does not orphan the
    /// slots written under it.
    #[test]
    fn an_instance_namespace_is_per_home_and_survives_the_homes_creation() {
        let parent = tempfile::tempdir().expect("tempdir");
        let home = parent.path().join("home-a");

        let before = instance_namespace(&home);
        std::fs::create_dir(&home).expect("create");
        assert_eq!(before, instance_namespace(&home), "stable across creation");

        assert_ne!(
            before,
            instance_namespace(&parent.path().join("home-b")),
            "two homes under one parent are two namespaces"
        );
        assert_eq!(before.len(), 16);
    }

    /// A symlinked prefix and its target are one home, as `/var` and `/private/var` are on
    /// macOS, and a `..` after it steps up from the target, as the kernel resolves it.
    #[cfg(unix)]
    #[test]
    fn an_instance_namespace_resolves_an_existing_symlinked_prefix() {
        let root = tempfile::tempdir().expect("tempdir");
        let real = root.path().join("real").join("inner");
        std::fs::create_dir_all(&real).expect("create");
        std::os::unix::fs::symlink(&real, root.path().join("link")).expect("symlink");

        assert_eq!(
            instance_namespace(&root.path().join("link").join("home")),
            instance_namespace(&real.join("home")),
        );
        assert_eq!(
            instance_namespace(&root.path().join("link").join("..").join("home")),
            instance_namespace(&root.path().join("real").join("home")),
        );
    }

    /// Once a component is missing, later names are not looked up next to the existing
    /// prefix: `x/a` with `x` missing is not `a/x` because `a` happens to exist.
    #[test]
    fn an_instance_namespace_does_not_skip_a_missing_component() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join("a")).expect("create");
        let home = root.path().join("x").join("a");

        let before = instance_namespace(&home);
        assert_ne!(before, instance_namespace(&root.path().join("a").join("x")));
        std::fs::create_dir_all(&home).expect("create");
        assert_eq!(before, instance_namespace(&home), "stable across creation");
    }

    /// A relative home resolves against the working directory, `..` included.
    #[test]
    fn a_relative_instance_namespace_matches_its_absolute_form() {
        let cwd = std::env::current_dir().expect("cwd");
        let base = cwd.file_name().expect("cwd has a name");
        let relative = std::path::Path::new("..")
            .join(base)
            .join("credsd-ns-probe");
        assert_eq!(
            instance_namespace(&relative),
            instance_namespace(&cwd.join("credsd-ns-probe")),
        );
    }

    #[test]
    fn parse_dpapi() {
        assert_eq!(Backend::parse("dpapi"), Some(Backend::Dpapi));
    }

    #[test]
    fn parse_credential_manager() {
        assert_eq!(
            Backend::parse("credential-manager"),
            Some(Backend::CredentialManager)
        );
    }

    #[test]
    fn parse_all_backends() {
        assert!(Backend::parse("data-protection-keychain").is_some());
        assert!(Backend::parse("secure-enclave").is_some());
        assert!(Backend::parse("dpapi").is_some());
        assert!(Backend::parse("credential-manager").is_some());
        assert!(Backend::parse("tpm").is_some());
        assert!(Backend::parse("kkrs").is_some());
        assert!(Backend::parse("file").is_some());
        assert!(Backend::parse("unknown").is_none());
    }

    /// The one backend a system service cannot reach is the one that needs a login session.
    /// Everything else this build compiled in stays a candidate, so the narrowing cannot
    /// quietly hide a keystore the service really does hold its key in.
    #[test]
    fn only_the_login_session_backend_is_out_of_reach_for_a_system_service() {
        assert!(!reachable_by_system_service(
            Backend::DataProtectionKeychain
        ));
        let candidates = system_service_backends();
        for b in Backend::COMPILED.iter().copied() {
            assert_eq!(
                candidates.contains(&b),
                b != Backend::DataProtectionKeychain,
                "{b:?}"
            );
        }
        #[cfg(not(target_os = "macos"))]
        assert_eq!(candidates, Backend::COMPILED, "a no-op off macOS");
    }

    /// Removed, not deprecated: its items are readable and replaceable by any process running
    /// as the uid. The bare `keychain` alias goes with it.
    #[test]
    fn legacy_keychain_names_do_not_parse() {
        assert_eq!(Backend::parse("legacy-keychain"), None);
        assert_eq!(Backend::parse("keychain"), None);
    }

    #[test]
    fn as_str_round_trips() {
        for name in [
            "data-protection-keychain",
            "secure-enclave",
            "dpapi",
            "credential-manager",
            "tpm",
            "kkrs",
            "file",
        ] {
            let backend = Backend::parse(name).unwrap();
            assert_eq!(backend.as_str(), name);
        }
    }

    #[test]
    fn kkrs_is_available_only_when_compiled() {
        assert_eq!(
            Backend::KernelKeyring.is_available(),
            cfg!(all(target_os = "linux", feature = "kkrs"))
        );
    }

    /// Without the feature, naming `kkrs` is refused as a build mismatch, never as an unknown
    /// name: the variant still parses, so a stale `--storage-backend kkrs` says how to get it.
    #[cfg(all(target_os = "linux", not(feature = "kkrs")))]
    #[test]
    fn kkrs_without_the_feature_is_refused_as_not_compiled() {
        assert!(!Backend::COMPILED.contains(&Backend::KernelKeyring));
        let err = select_backend(Some("kkrs")).unwrap_err().to_string();
        assert!(err.contains("--features kkrs"), "unexpected: {err}");
        let err = create_storage(Backend::KernelKeyring)
            .err()
            .expect("kkrs must not be constructible without the feature")
            .to_string();
        assert!(err.contains("--features kkrs"), "unexpected: {err}");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn create_kkrs_errors_off_linux_and_mentions_linux() {
        let err = create_storage(Backend::KernelKeyring)
            .err()
            .expect("kkrs must error off Linux")
            .to_string();
        assert!(err.to_lowercase().contains("linux"), "unexpected: {err}");
    }

    /// The list names what this build can use, so it cannot advertise a backend that would
    /// then be refused as not compiled.
    #[test]
    fn select_unknown_lists_exactly_the_compiled_backends() {
        let err = select_backend(Some("nope")).unwrap_err().to_string();
        for b in Backend::COMPILED {
            assert!(
                err.contains(b.as_str()),
                "valid list must mention {b:?}: {err}"
            );
        }
        assert_eq!(
            err.contains("kkrs"),
            Backend::COMPILED.contains(&Backend::KernelKeyring),
            "{err}"
        );
    }

    proptest::proptest! {
        /// Property 4: auto_detect never returns KernelKeyring, for any simulated
        /// TPM-availability state. auto_detect takes no inputs, so the property is
        /// that its result is never KKRS however often it is called.
        #[test]
        fn prop_auto_detect_never_kkrs(_iter in 0u32..256) {
            if let Ok(b) = auto_detect() {
                proptest::prop_assert_ne!(b, Backend::KernelKeyring);
            }
        }
    }

    #[test]
    fn auto_detect_resolves_or_requires_explicit() {
        let result = auto_detect();
        // macOS: `data-protection-keychain` on a binary entitled to it, else `secure-enclave` when
        // this process can reach an enclave, otherwise a config error that steers to an explicit
        // choice — never a silent `file` fallback.
        #[cfg(target_os = "macos")]
        match result {
            Ok(b) => assert!(
                matches!(b, Backend::DataProtectionKeychain | Backend::SecureEnclave),
                "unexpected backend: {b:?}"
            ),
            Err(e) => assert!(
                e.to_string().contains("hardware-backed"),
                "unexpected error: {e}"
            ),
        }
        #[cfg(target_os = "windows")]
        assert_eq!(result.unwrap(), Backend::Dpapi);
        // Linux (and other unix): `tpm` when a device is present, otherwise a
        // config error that steers to an explicit choice — never a silent
        // `file`/`kkrs` fallback.
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        match result {
            Ok(b) => assert_eq!(b, Backend::Tpm),
            Err(e) => assert!(
                e.to_string().contains("hardware-backed"),
                "unexpected error: {e}"
            ),
        }
    }

    /// The environment is writable by every process running as the daemon's uid, so it must not
    /// be able to choose the backend. Nothing else reads this variable, so setting it here
    /// cannot disturb a parallel test.
    #[test]
    fn environment_does_not_select_the_backend() {
        std::env::set_var("CREDSD_STORAGE_BACKEND", "file");
        let selected = select_backend(None);
        std::env::remove_var("CREDSD_STORAGE_BACKEND");
        assert_ne!(selected.ok(), Some(Backend::File));
    }

    /// A backend this binary was not built with must never report itself usable. Without this,
    /// a `tpm`-less build on a host with `/dev/tpmrm0` auto-selected `tpm` and then read the
    /// sealed key it could not unseal as lost TPM state, quarantining every credential.
    #[test]
    fn an_available_backend_is_always_a_compiled_one() {
        for b in [Backend::Tpm, Backend::SecureEnclave, Backend::File] {
            if b.is_available() {
                assert!(
                    Backend::COMPILED.contains(&b),
                    "{b:?} available but not compiled"
                );
            }
        }
        let file_compiled = cfg!(any(not(target_os = "macos"), feature = "file"));
        assert_eq!(Backend::COMPILED.contains(&Backend::File), file_compiled);
        assert_eq!(Backend::File.is_available(), file_compiled);
    }

    #[cfg(all(target_os = "linux", not(feature = "tpm")))]
    #[test]
    fn tpm_without_the_feature_names_the_feature() {
        let err = select_backend(Some("tpm")).unwrap_err().to_string();
        assert!(err.contains("--features tpm"), "unexpected: {err}");
    }

    /// The message must name the fix, or a VM user is left with "not available" and no route.
    #[cfg(all(target_os = "macos", not(feature = "file")))]
    #[test]
    fn file_off_macos_feature_names_the_feature() {
        let err = select_backend(Some("file")).unwrap_err().to_string();
        assert!(err.contains("--features file"), "unexpected: {err}");
        let err = create_storage(Backend::File).err().unwrap().to_string();
        assert!(err.contains("--features file"), "unexpected: {err}");
    }

    #[test]
    fn compiled_backends_are_unique_and_named() {
        for (i, b) in Backend::COMPILED.iter().enumerate() {
            assert!(!Backend::COMPILED[..i].contains(b), "duplicate: {b:?}");
            assert_eq!(Backend::parse(b.as_str()), Some(*b));
        }
    }

    #[test]
    fn select_backend_rejects_unknown() {
        let result = select_backend(Some("nonexistent"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown storage backend"));
    }

    /// On non-macOS, `create_storage(DataProtectionKeychain)` must return Err — never a silent
    /// plaintext fallback.
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn keychain_backend_errors_on_non_macos() {
        let result = create_storage(Backend::DataProtectionKeychain);
        assert!(result.is_err(), "expected Err, got Ok");
    }

    #[cfg(unix)]
    fn mode_of(p: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// Recovery moves sealed files from BOTH the daemon and legacy trees into one
    /// quarantine generation — mirroring the relative path, keeping `0600`, and
    /// leaving non-`.enc` and top-level loose files untouched. Nothing is deleted;
    /// the scanned trees are left clean of `.enc`.
    #[cfg(unix)]
    #[test]
    fn quarantine_moves_both_trees_and_keeps_perms() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let daemon = root.join("callers/1000/credentials/dev");
        std::fs::create_dir_all(&daemon).unwrap();
        std::fs::write(daemon.join("sso_token.enc"), b"daemon").unwrap();
        std::fs::write(daemon.join("keep.txt"), b"note").unwrap(); // non-.enc survives

        let legacy = root.join("credentials/legacy");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("oauth_token.enc"), b"legacy").unwrap();
        std::fs::write(root.join("credentials/loose.enc"), b"loose").unwrap(); // top-level survives

        quarantine_sealed_credentials_in(root);

        assert!(!daemon.join("sso_token.enc").exists(), "daemon .enc moved");
        assert!(
            !legacy.join("oauth_token.enc").exists(),
            "legacy .enc moved"
        );
        assert!(daemon.join("keep.txt").exists(), "non-.enc must survive");
        assert!(
            root.join("credentials/loose.enc").exists(),
            "top-level loose file must survive"
        );

        let quarantine = root.join("quarantine");
        assert_eq!(mode_of(&quarantine), 0o700, "quarantine/ must be 0700");
        let gens: Vec<_> = std::fs::read_dir(&quarantine)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(gens.len(), 1);
        let gen = &gens[0];
        assert_eq!(mode_of(gen), 0o700, "generation dir must be 0700");

        let moved_daemon = gen.join("callers/1000/credentials/dev/sso_token.enc");
        let moved_legacy = gen.join("credentials/legacy/oauth_token.enc");
        assert_eq!(std::fs::read(&moved_daemon).unwrap(), b"daemon");
        assert_eq!(std::fs::read(&moved_legacy).unwrap(), b"legacy");
        assert_eq!(mode_of(&moved_daemon), 0o600, "moved file must be 0600");
    }

    /// Recovery prunes quarantine to the newest `QUARANTINE_GENERATIONS`: seed
    /// more than that many old generations, run one more recovery, and confirm the
    /// oldest are removed while the newest (including the new one) survive.
    #[cfg(unix)]
    #[test]
    fn quarantine_prunes_to_newest_n() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let quarantine = root.join("quarantine");

        // Seed old generations with sortable names strictly older than "now".
        let old: Vec<String> = (1..=QUARANTINE_GENERATIONS + 2)
            .map(|i| format!("2020-01-01T00-00-{i:02}Z"))
            .collect();
        for name in &old {
            std::fs::create_dir_all(quarantine.join(name)).unwrap();
        }

        // An orphan so this recovery actually creates a new generation and prunes.
        let legacy = root.join("credentials/legacy");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("jwt.enc"), b"x").unwrap();

        quarantine_sealed_credentials_in(root);

        let remaining: std::collections::BTreeSet<String> = std::fs::read_dir(&quarantine)
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        assert_eq!(
            remaining.len(),
            QUARANTINE_GENERATIONS,
            "must keep exactly N generations"
        );
        // The two oldest seeded generations are pruned.
        assert!(!remaining.contains(&old[0]));
        assert!(!remaining.contains(&old[1]));
        // The newest seeded one survives.
        assert!(remaining.contains(old.last().unwrap()));
    }

    /// No credential trees at all: recovery is a no-op and creates no quarantine.
    #[cfg(unix)]
    #[test]
    fn quarantine_no_trees_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        quarantine_sealed_credentials_in(dir.path());
        assert!(!dir.path().join("quarantine").exists());
    }

    /// Consecutive generations never merge — a same-second collision is
    /// disambiguated so two recovery events get distinct dirs.
    #[cfg(unix)]
    #[test]
    fn quarantine_generations_never_collide() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("quarantine");
        let g1 = create_generation_dir(&root).unwrap();
        let g2 = create_generation_dir(&root).unwrap();
        assert_ne!(g1, g2, "two events must not share a generation dir");
        assert!(g1.is_dir() && g2.is_dir());
    }
}
