//! Secure Enclave storage backend (`Backend::SecureEnclave`), macOS only.
//!
//! Wraps the AES-256 master key to a P-256 key pair resident in the Secure Enclave. Two
//! artifacts live on disk under `<data_dir>/secure-enclave/`, both `0600` inside a `0700`
//! directory: `<key_id>.sekey` holds the enclave key's `dataRepresentation` (opaque, only this
//! machine's enclave can unwrap it) and `<key_id>.sealed` holds the ECIES-wrapped master key.
//! Neither file is secret-bearing on its own, and neither is usable on another machine.
//!
//! The enclave is reached through CryptoKit rather than `SecItem`, because the `SecItem` route
//! goes via the data protection keychain, which Apple documents as unavailable to `launchd`
//! daemons regardless of packaging. See `docs/key-security.md` for the full constraint and
//! `swift/SecureEnclaveShim.swift` for the boundary.
//!
//! As with `tpm`, all *logic* here — file layout, permissions, get-or-create, recovery — is
//! compiled and unit-tested against a fake seam without the `secure-enclave` feature. Only the
//! Swift-linked seam is feature-gated, so the interesting code is always under test even on
//! platforms that cannot reach an enclave.
//!
//! The key binds to the launchd context that minted it, not just to the uid: a key minted
//! outside launchd fails to unwrap in the service with `key agreement failed (-6)`, so the
//! system install mints through a one-shot LaunchDaemon (`install::macos`).

use crate::error::{DaemonError, Result};
use crate::storage::SecureStorage;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Keychain protection class the enclave key is created under.
///
/// A parameter rather than a constant because which class a daemon can actually use is the open
/// question this backend exists to settle. CryptoKit's own default is `AfterFirstUnlock`, which
/// fails with `errSecInteractionNotAllowed` before any user has logged in — and on macOS "first
/// unlock" means "first login", which an SSH session satisfies. `Always` is the only class with
/// no login dependency and is deprecated; see the shim's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protection {
    /// Unavailable until some user has logged in. CryptoKit's default.
    AfterFirstUnlockThisDeviceOnly,
    /// No login dependency. Deprecated by Apple at macOS 10.14; the only class a boot-start
    /// daemon can rely on.
    #[default]
    Always,
    /// Unavailable whenever the device is locked. Listed for completeness; hostile to a daemon.
    WhenUnlockedThisDeviceOnly,
}

impl Protection {
    /// Discriminant passed across the C boundary. Must match `protectionClass` in the shim.
    #[cfg(feature = "secure-enclave")]
    fn selector(self) -> u32 {
        match self {
            Self::AfterFirstUnlockThisDeviceOnly => 0,
            Self::Always => 1,
            Self::WhenUnlockedThisDeviceOnly => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AfterFirstUnlockThisDeviceOnly => "after-first-unlock",
            Self::Always => "always",
            Self::WhenUnlockedThisDeviceOnly => "when-unlocked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "after-first-unlock" => Some(Self::AfterFirstUnlockThisDeviceOnly),
            "always" => Some(Self::Always),
            "when-unlocked" => Some(Self::WhenUnlockedThisDeviceOnly),
            _ => None,
        }
    }

    /// Read the protection class from `CREDSD_SE_PROTECTION`, defaulting to `Always`.
    pub fn from_env() -> Result<Self> {
        match std::env::var("CREDSD_SE_PROTECTION") {
            Ok(s) => Self::parse(&s).ok_or_else(|| {
                DaemonError::config(format!(
                    "invalid CREDSD_SE_PROTECTION '{s}'. Valid: after-first-unlock, always, when-unlocked"
                ))
            }),
            Err(_) => Ok(Self::default()),
        }
    }
}

/// `SecAccessControlCreateFlags` value used when creating the enclave key.
///
/// Zero — no flags. User presence is deliberately *not* requested: `LAContext` is usable only
/// from a user login context and cannot be moved between security contexts, so a presence
/// requirement makes a daemon key strictly unusable rather than more protected. Key agreement
/// does not need `privateKeyUsage`, which gates signing.
#[cfg(feature = "secure-enclave")]
const ACCESS_FLAGS: u32 = 0;

/// The Secure Enclave operations this backend needs, behind a seam so the storage logic is
/// testable without an enclave. Mirrors `TpmSeam`.
pub(crate) trait SeSeam: Send + Sync {
    /// Generate an enclave-resident key, returning its persistable representation.
    fn generate(&self, protection: Protection) -> Result<Vec<u8>>;
    /// ECIES-seal `plaintext` to the key described by `key_blob`.
    fn wrap(&self, key_blob: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    /// Recover a plaintext sealed by [`SeSeam::wrap`].
    fn unwrap(&self, key_blob: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

/// A `SecureStorage` that wraps values to a Secure Enclave key via a [`SeSeam`].
pub(crate) struct SecureEnclaveStorage<S: SeSeam> {
    dir: PathBuf,
    seam: S,
    protection: Protection,
}

impl<S: SeSeam> SecureEnclaveStorage<S> {
    pub(crate) fn new_in(dir: PathBuf, seam: S, protection: Protection) -> Self {
        Self {
            dir,
            seam,
            protection,
        }
    }

    fn sealed_path(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{key_id}.sealed"))
    }

    fn key_path(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{key_id}.sekey"))
    }

    /// Return this key id's enclave key, generating and persisting one if absent.
    ///
    /// One enclave key per `key_id` rather than one per machine: it keeps `delete` total (no
    /// shared key to orphan or to strand another id on) and costs one extra hardware keygen per
    /// id, of which there is currently one.
    fn key_blob(&self, key_id: &str) -> Result<Vec<u8>> {
        let path = self.key_path(key_id);
        // Open with O_NOFOLLOW so the fd, the fstat, and the read are all on the same inode —
        // no window for a symlink swap between the ownership check and the read.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let open_result = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path);
            match open_result {
                Ok(f) => {
                    let m = f.metadata().map_err(|e| {
                        DaemonError::Storage(format!(
                            "cannot stat enclave key {}: {e}",
                            path.display()
                        ))
                    })?;
                    use std::os::unix::fs::MetadataExt;
                    let uid = nix::unistd::getuid().as_raw();
                    if m.uid() != uid || m.mode() & 0o177 != 0 {
                        return Err(DaemonError::Storage(format!(
                        "enclave key {} has unexpected owner (uid {}, want {}) or mode ({:#o}); \
                         refusing to use a file this process did not create",
                        path.display(),
                        m.uid(),
                        uid,
                        m.mode() & 0o777,
                    )));
                    }
                    use std::io::Read;
                    let mut buf = Vec::new();
                    { f }.read_to_end(&mut buf).map_err(|e| {
                        DaemonError::Storage(format!(
                            "cannot read enclave key '{}' ({}): {e}",
                            key_id,
                            path.display()
                        ))
                    })?;
                    return Ok(buf);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(DaemonError::Storage(format!(
                        "cannot open enclave key {}: {e}",
                        path.display()
                    )));
                }
            } // end #[cfg(unix)] open block
        }
        #[cfg(not(unix))]
        if path.exists() {
            return std::fs::read(&path).map_err(|e| {
                DaemonError::Storage(format!(
                    "cannot read enclave key '{}' ({}): {e}",
                    key_id,
                    path.display()
                ))
            });
        }
        let blob = self.seam.generate(self.protection)?;
        // O_EXCL|O_NOFOLLOW: refuse symlinks and refuse adopting a file another process created.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|e| {
                    DaemonError::Storage(format!(
                        "cannot create enclave key {}: {e}",
                        path.display()
                    ))
                })?;
            f.write_all(&blob).map_err(|e| {
                DaemonError::Storage(format!("cannot write enclave key {}: {e}", path.display()))
            })?;
        }
        #[cfg(not(unix))]
        write_private(&path, &blob)?;
        Ok(blob)
    }
}

/// Distinguishes "no key stored" from "stored but unwrappable", so the key-init path can tell a
/// first run from a recovery. Mirrors the TPM backend's marker.
const ABSENT_MARKER: &str = "no sealed key present";

impl<S: SeSeam> SecureStorage for SecureEnclaveStorage<S> {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }

        let key_blob = self.key_blob(key_id)?;
        let sealed = self.seam.wrap(&key_blob, data)?;
        write_private(&self.sealed_path(key_id), &sealed)
    }

    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        let path = self.sealed_path(key_id);
        if !path.exists() {
            return Err(DaemonError::Storage(ABSENT_MARKER.to_owned()));
        }
        let sealed = std::fs::read(&path)?;

        // A sealed blob with no enclave key beside it is unrecoverable, not absent — fail into
        // recovery rather than reporting a clean first run and silently discarding credentials.
        let key_path = self.key_path(key_id);
        if !key_path.exists() {
            return Err(DaemonError::Storage(format!(
                "sealed key '{key_id}' has no enclave key at {}; the master key cannot be recovered",
                key_path.display()
            )));
        }
        // key_blob() opens with O_NOFOLLOW and validates uid/mode — do not bypass with a direct read.
        let key_blob = self.key_blob(key_id).map_err(|e| {
            DaemonError::Storage(format!(
                "sealed key '{key_id}' exists but its enclave key cannot be read: {e}"
            ))
        })?;

        self.seam
            .unwrap(&key_blob, &sealed)
            .map(|plaintext| plaintext.to_vec())
            .map_err(|e| {
                DaemonError::Storage(format!(
                    "could not unwrap key '{key_id}' (enclave key from another machine, or a \
                     protection class this process cannot satisfy): {e}"
                ))
            })
    }

    fn delete(&self, key_id: &str) -> Result<()> {
        for path in [self.sealed_path(key_id), self.key_path(key_id)] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(DaemonError::Storage(format!(
                        "cannot delete '{}': {e}",
                        path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    fn exists(&self, key_id: &str) -> Result<bool> {
        let path = self.sealed_path(key_id);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(DaemonError::Storage(format!(
                "cannot stat sealed key '{}': {e}",
                path.display()
            ))),
        }
    }

    fn backend_name(&self) -> &'static str {
        "secure-enclave"
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW: refuse to write through a symlink planted at this path.
        // create(true) + truncate allows overwriting an existing sealed blob.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| DaemonError::Storage(format!("cannot open {}: {e}", path.display())))?;
        f.write_all(bytes)
            .map_err(|e| DaemonError::Storage(format!("cannot write {}: {e}", path.display())))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
        Ok(())
    }
}

pub(crate) fn storage_dir() -> PathBuf {
    crate::config::platform::data_dir().join("secure-enclave")
}

/// Whether a usable Secure Enclave is reachable from this process.
///
/// A capability probe, not a hardware probe: it answers "can *this* process use the enclave",
/// which is the question backend selection needs. Without the `secure-enclave` feature it is
/// always false, so auto-detect can never pick a backend whose seal would fail.
pub(crate) fn available() -> bool {
    #[cfg(feature = "secure-enclave")]
    {
        swift::available()
    }
    #[cfg(not(feature = "secure-enclave"))]
    {
        false
    }
}

/// Construct the production Secure Enclave storage.
pub(crate) fn production_storage() -> Result<Box<dyn SecureStorage>> {
    let protection = Protection::from_env()?;
    let dir = storage_dir();
    tracing::debug!(
        protection = protection.as_str(),
        "initializing secure-enclave storage backend"
    );

    #[cfg(feature = "secure-enclave")]
    {
        Ok(Box::new(SecureEnclaveStorage::new_in(
            dir,
            swift::SwiftSeam,
            protection,
        )))
    }
    #[cfg(not(feature = "secure-enclave"))]
    {
        Ok(Box::new(SecureEnclaveStorage::new_in(
            dir,
            UnsupportedSeam,
            protection,
        )))
    }
}

/// Seam used when credsd is built without the `secure-enclave` feature: no Swift is linked, so
/// every operation reports why rather than pretending to succeed.
#[cfg(not(feature = "secure-enclave"))]
pub(crate) struct UnsupportedSeam;

#[cfg(not(feature = "secure-enclave"))]
impl SeSeam for UnsupportedSeam {
    fn generate(&self, _protection: Protection) -> Result<Vec<u8>> {
        Err(unsupported())
    }

    fn wrap(&self, _key_blob: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(unsupported())
    }

    fn unwrap(&self, _key_blob: &[u8], _ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(unsupported())
    }
}

#[cfg(not(feature = "secure-enclave"))]
fn unsupported() -> DaemonError {
    DaemonError::config(
        "secure-enclave backend requires building credsd with the `secure-enclave` feature",
    )
}

/// The Swift boundary. Compiled only under the `secure-enclave` feature, where `build.rs` has
/// linked `libcredsd_se.a`.
#[cfg(feature = "secure-enclave")]
mod swift {
    use super::{Protection, Result, SeSeam, ACCESS_FLAGS};
    use crate::error::DaemonError;
    use zeroize::Zeroizing;

    /// Enough for any output this API produces: an enclave key representation is a few hundred
    /// bytes and a wrapped 32-byte master key is 65 + 32 + 16. Sized generously because the
    /// shim reports the required length on overflow, so a too-small buffer is a clear error
    /// rather than truncation — see `call`.
    const BUFFER: usize = 4096;

    extern "C" {
        fn credsd_se_available() -> i32;
        fn credsd_se_generate(
            protection: u32,
            flags: u32,
            out: *mut u8,
            cap: usize,
            len: *mut usize,
        ) -> i32;
        fn credsd_se_wrap(
            key_blob: *const u8,
            key_blob_len: usize,
            plaintext: *const u8,
            plaintext_len: usize,
            out: *mut u8,
            cap: usize,
            len: *mut usize,
        ) -> i32;
        fn credsd_se_unwrap(
            key_blob: *const u8,
            key_blob_len: usize,
            ciphertext: *const u8,
            ciphertext_len: usize,
            out: *mut u8,
            cap: usize,
            len: *mut usize,
        ) -> i32;
    }

    /// Human-readable form of the shim's status codes. Must match the `err*` constants in
    /// `swift/SecureEnclaveShim.swift`.
    fn describe(code: i32) -> &'static str {
        match code {
            -1 => "no Secure Enclave on this machine",
            -2 => "output buffer too small",
            -3 => "could not build the access control object",
            -4 => {
                "enclave key generation failed (a daemon before first login cannot use a \
                   login-dependent protection class)"
            }
            -5 => {
                "the stored enclave key could not be rehydrated (wrong machine, or a \
                   protection class this process cannot satisfy)"
            }
            -6 => "key agreement failed",
            -7 => "seal failed",
            -8 => "open failed (wrong key, or tampered ciphertext)",
            -9 => "invalid input",
            _ => "unknown error",
        }
    }

    /// Runs one shim call against a stack buffer and returns the bytes it wrote.
    ///
    /// SAFETY: every `unsafe` block below is the same shape, which is the point of the shim's
    /// memory contract. `out` is a live, uniquely-borrowed buffer of exactly `cap` bytes and
    /// `len` is a live `usize`; the Swift side writes at most `cap` bytes, always writes `len`,
    /// and never retains either pointer past the call. Input slices are borrowed for the
    /// duration of the call and Swift copies from them immediately. No allocation crosses the
    /// boundary in either direction, so there is nothing to free and no ownership to transfer.
    fn call(
        op: impl FnOnce(*mut u8, usize, *mut usize) -> i32,
        what: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut buf = Zeroizing::new(vec![0u8; BUFFER]);
        let mut len: usize = 0;
        let code = op(buf.as_mut_ptr(), BUFFER, &mut len);
        if code != 0 {
            return Err(DaemonError::Storage(format!(
                "secure enclave {what} failed: {} ({code})",
                describe(code)
            )));
        }
        if len > BUFFER {
            return Err(DaemonError::Storage(format!(
                "secure enclave {what} needs a {len}-byte buffer; {BUFFER} available"
            )));
        }
        buf.truncate(len);
        Ok(buf)
    }

    /// Whether the linked shim reports a usable enclave.
    pub(crate) fn available() -> bool {
        // SAFETY: takes no arguments, dereferences nothing, and returns a plain `Int32`.
        unsafe { credsd_se_available() == 1 }
    }

    pub(crate) struct SwiftSeam;

    impl SeSeam for SwiftSeam {
        fn generate(&self, protection: Protection) -> Result<Vec<u8>> {
            call(
                // SAFETY: `out` is a live buffer of exactly `cap` bytes and `len` a live
                // `usize`, both supplied by `call` and outliving this invocation. The shim
                // writes at most `cap` bytes, always writes `len`, and retains neither pointer
                // past return. `protection` and the flags are plain integers.
                |out, cap, len| unsafe {
                    credsd_se_generate(protection.selector(), ACCESS_FLAGS, out, cap, len)
                },
                "key generation",
            )
            .map(|b| b.to_vec())
        }

        fn wrap(&self, key_blob: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
            call(
                // SAFETY: as `generate`, plus two input slices passed as pointer/length pairs.
                // Both are borrowed for the duration of the call and the shim copies from them
                // before returning, so neither escapes.
                |out, cap, len| unsafe {
                    credsd_se_wrap(
                        key_blob.as_ptr(),
                        key_blob.len(),
                        plaintext.as_ptr(),
                        plaintext.len(),
                        out,
                        cap,
                        len,
                    )
                },
                "wrap",
            )
            .map(|b| b.to_vec())
        }

        fn unwrap(&self, key_blob: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            call(
                // SAFETY: identical contract to `wrap` — two borrowed input slices as
                // pointer/length pairs, one caller-owned output buffer, nothing retained.
                |out, cap, len| unsafe {
                    credsd_se_unwrap(
                        key_blob.as_ptr(),
                        key_blob.len(),
                        ciphertext.as_ptr(),
                        ciphertext.len(),
                        out,
                        cap,
                        len,
                    )
                },
                "unwrap",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// XOR mask the fake applies so its output never contains the input verbatim. Not
    /// cryptography — just enough that `sealed_file_holds_wrapped_form` is a real assertion
    /// about the storage layer rather than a property of the fake.
    const FAKE_MASK: u8 = 0x5a;

    /// Stands in for the enclave: "wrapping" prefixes the key blob so a mismatched key is
    /// detectable, and masks the payload so the plaintext is not recoverable by inspection.
    struct FakeSeam {
        key: Vec<u8>,
    }

    impl Default for FakeSeam {
        fn default() -> Self {
            Self {
                key: b"fake-enclave-key".to_vec(),
            }
        }
    }

    impl SeSeam for FakeSeam {
        fn generate(&self, _protection: Protection) -> Result<Vec<u8>> {
            Ok(self.key.clone())
        }

        fn wrap(&self, key_blob: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
            let mut out = key_blob.to_vec();
            out.push(0xff);
            out.extend(plaintext.iter().map(|b| b ^ FAKE_MASK));
            Ok(out)
        }

        fn unwrap(&self, key_blob: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            let split = ciphertext
                .iter()
                .position(|b| *b == 0xff)
                .ok_or_else(|| DaemonError::Storage("malformed".into()))?;
            if &ciphertext[..split] != key_blob {
                return Err(DaemonError::Storage("wrong enclave key".into()));
            }
            Ok(Zeroizing::new(
                ciphertext
                    .iter()
                    .skip(split.saturating_add(1))
                    .map(|b| b ^ FAKE_MASK)
                    .collect(),
            ))
        }
    }

    fn storage(dir: &Path) -> SecureEnclaveStorage<FakeSeam> {
        SecureEnclaveStorage::new_in(dir.to_path_buf(), FakeSeam::default(), Protection::Always)
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        let key = b"encryption-key-bytes-here-32byte";
        s.store("daemon-encryption-key", key).unwrap();
        assert!(s.exists("daemon-encryption-key").unwrap());
        assert_eq!(s.retrieve("daemon-encryption-key").unwrap(), key);
    }

    #[test]
    fn store_persists_both_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        s.store("k", b"secret").unwrap();
        assert!(dir.path().join("k.sealed").exists());
        assert!(
            dir.path().join("k.sekey").exists(),
            "enclave key not written"
        );
    }

    /// The storage layer must persist the seam's output, never the value it was handed. Guards
    /// against a `store` that writes `data` instead of `sealed`. Confidentiality against real
    /// crypto is asserted in `hardware_round_trip`.
    #[test]
    fn sealed_file_holds_wrapped_form() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        let secret = b"plaintext-master-key-do-not-leak";
        s.store("k", secret).unwrap();
        let on_disk = std::fs::read(dir.path().join("k.sealed")).unwrap();
        assert!(
            !on_disk.windows(secret.len()).any(|w| w == secret),
            "plaintext found in the sealed file"
        );
    }

    #[test]
    fn absent_key_reports_absent_not_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        let err = s.retrieve("missing").unwrap_err().to_string();
        assert!(err.contains(ABSENT_MARKER), "unexpected error: {err}");
    }

    /// A sealed blob whose enclave key is gone is unrecoverable, and must say so rather than
    /// look like a first run — otherwise the key-init path would mint a new master key and
    /// silently strand every cached credential.
    #[test]
    fn sealed_without_enclave_key_is_unrecoverable_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        s.store("k", b"secret").unwrap();
        std::fs::remove_file(dir.path().join("k.sekey")).unwrap();

        let err = s.retrieve("k").unwrap_err().to_string();
        assert!(
            !err.contains(ABSENT_MARKER),
            "must not report absent: {err}"
        );
        assert!(
            err.contains("cannot be recovered"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn enclave_key_is_reused_across_stores() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        s.store("k", b"first").unwrap();
        let first = std::fs::read(dir.path().join("k.sekey")).unwrap();
        s.store("k", b"second").unwrap();
        assert_eq!(first, std::fs::read(dir.path().join("k.sekey")).unwrap());
        assert_eq!(s.retrieve("k").unwrap(), b"second");
    }

    #[test]
    fn delete_removes_both_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        s.store("k", b"secret").unwrap();
        s.delete("k").unwrap();
        assert!(!s.exists("k").unwrap());
        assert!(!dir.path().join("k.sekey").exists());
    }

    #[cfg(unix)]
    #[test]
    fn artifacts_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        s.store("k", b"secret").unwrap();
        for name in ["k.sealed", "k.sekey"] {
            let mode = std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name} is {mode:o}");
        }
    }

    /// A `.sekey` file that anyone can read (mode 0o644) must be refused — if the check were
    /// removed or the mask loosened, `retrieve` would silently use a key another process could read.
    #[cfg(unix)]
    #[test]
    fn overly_permissive_enclave_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        s.store("k", b"secret").unwrap();
        let sekey = dir.path().join("k.sekey");
        std::fs::set_permissions(&sekey, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = s.retrieve("k").unwrap_err().to_string();
        assert!(
            err.contains("unexpected owner") || err.contains("mode"),
            "must refuse overly-permissive key; got: {err}"
        );
    }

    #[test]
    fn protection_round_trips() {
        for name in ["after-first-unlock", "always", "when-unlocked"] {
            assert_eq!(Protection::parse(name).unwrap().as_str(), name);
        }
        assert!(Protection::parse("nonexistent").is_none());
    }

    #[test]
    fn protection_default_is_always() {
        assert_eq!(Protection::default(), Protection::Always);
    }

    #[test]
    fn backend_name_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(storage(dir.path()).backend_name(), "secure-enclave");
    }

    /// Exercises the real enclave. Ignored by default: CI runners are virtualized and have no
    /// Secure Enclave, so this can only pass on real hardware with the feature enabled. Run
    /// with `cargo test --features secure-enclave -- --ignored`.
    #[cfg(feature = "secure-enclave")]
    #[test]
    #[ignore = "requires Secure Enclave hardware"]
    fn hardware_round_trip() {
        assert!(available(), "no Secure Enclave available");
        let dir = tempfile::tempdir().unwrap();
        let s = SecureEnclaveStorage::new_in(
            dir.path().to_path_buf(),
            swift::SwiftSeam,
            Protection::Always,
        );
        let key = b"encryption-key-bytes-here-32byte";
        s.store("daemon-encryption-key", key).unwrap();
        assert_eq!(s.retrieve("daemon-encryption-key").unwrap(), key);

        // The enclave-wrapped form must not carry the master key in the clear.
        let sealed = std::fs::read(dir.path().join("daemon-encryption-key.sealed")).unwrap();
        assert!(
            !sealed.windows(key.len()).any(|w| w == key),
            "master key found in the sealed file"
        );

        // And the enclave key blob is not the master key either.
        let blob = std::fs::read(dir.path().join("daemon-encryption-key.sekey")).unwrap();
        assert!(
            !blob.windows(key.len()).any(|w| w == key),
            "master key found in the enclave key blob"
        );
    }
}
