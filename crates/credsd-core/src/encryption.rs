//! AES-256-GCM envelope encryption for secrets at rest.

use std::io::Write as _;
use std::path::Path;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{DaemonError, Result};

/// Ciphertext plus nonce produced by AES-256-GCM encryption.
///
/// Both fields are binary. Serde would render a `Vec<u8>` as a JSON array of
/// integers in a text format like JSON, so each is encoded as a base64 string
/// via [`b64`] — compact and readable in the sealed file rather than a wall of
/// decimal bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
}

/// Serde codec that renders a `Vec<u8>` field as a standard-alphabet base64
/// string instead of serde_json's default array-of-integers.
mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        STANDARD.decode(&encoded).map_err(serde::de::Error::custom)
    }
}

/// AES-256-GCM envelope encryption for credential-at-rest protection.
pub struct EncryptionService {
    key_bytes: Vec<u8>,
}

impl EncryptionService {
    pub fn new(key_bytes: Vec<u8>) -> Result<Self> {
        if key_bytes.len() != 32 {
            return Err(DaemonError::Encryption(format!(
                "key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }
        Ok(Self { key_bytes })
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        self.encrypt_with_aad(plaintext, &[])
    }

    pub(crate) fn decrypt(&self, data: &EncryptedData) -> Result<Vec<u8>> {
        self.decrypt_with_aad(data, &[])
    }

    fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| DaemonError::Encryption("failed to generate nonce".into()))?;

        let unbound = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| DaemonError::Encryption("invalid key".into()))?;
        let key = LessSafeKey::new(unbound);

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| DaemonError::Encryption("encryption failed".into()))?;

        Ok(EncryptedData {
            ciphertext: in_out,
            nonce: nonce_bytes.to_vec(),
        })
    }

    fn decrypt_with_aad(&self, data: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes: [u8; 12] = data
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| DaemonError::Encryption("invalid nonce length".into()))?;

        let unbound = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| DaemonError::Encryption("invalid key".into()))?;
        let key = LessSafeKey::new(unbound);

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = data.ciphertext.clone();
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| DaemonError::Encryption("decryption failed".into()))?;

        Ok(plaintext.to_vec())
    }
}

impl Drop for EncryptionService {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

/// On-disk secret storage. Every credential secret — the SSO refresh token and the IAM-user key
/// pair alike — is persisted through [`seal_to_file`](EncryptionService::seal_to_file) and read
/// back through [`open_from_file`](EncryptionService::open_from_file), so there is exactly one
/// audited path by which secret material reaches or leaves disk. The protections are structural:
/// nothing writes cleartext (the only write path encrypts), the file is always `0600` under a
/// `0700` dir, and reads hand back a [`Zeroizing`] buffer that scrubs itself on drop.
impl EncryptionService {
    /// Encrypt `plaintext` and persist it as `json(EncryptedData)` at `path`, creating the parent
    /// directory (`0700`) and tightening the file to `0600`.
    pub fn seal_to_file(&self, path: &Path, plaintext: &[u8]) -> Result<()> {
        let data_dir = crate::config::platform::data_dir();
        let rel = path.strip_prefix(&data_dir).unwrap_or(path);
        let aad = rel.as_os_str().as_encoded_bytes();
        let payload = serde_json::to_vec(&self.encrypt_with_aad(plaintext, aad)?)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        // Write to a sibling .tmp file, sync to disk, then rename atomically so a
        // crash mid-write never truncates the live file (AC 6.4).
        let parent = path.parent().unwrap_or(Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        tmp.write_all(&payload)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Read and decrypt a file written by [`seal_to_file`](Self::seal_to_file), returning the
    /// plaintext in a [`Zeroizing`] buffer that scrubs itself on drop. A missing file, a malformed
    /// blob, or a wrong key all surface as errors; callers add credential-specific guidance.
    pub fn open_from_file(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let data_dir = crate::config::platform::data_dir();
        let rel = path.strip_prefix(&data_dir).unwrap_or(path);
        let aad = rel.as_os_str().as_encoded_bytes();
        let data: EncryptedData = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|e| DaemonError::Encryption(format!("sealed file is malformed: {}", e)))?;
        Ok(Zeroizing::new(self.decrypt_with_aad(&data, aad)?))
    }

    /// Re-encrypt a sealed file at `current_path` so it is bound to `new_path` as AAD.
    /// Called before renaming a file from a staging location to its final committed location;
    /// the provider sealed the file with the staging path as AAD, but `open_from_file` at the
    /// final path would derive a different AAD and fail authentication.
    pub fn rebind_file(&self, current_path: &Path, new_path: &Path) -> Result<()> {
        let plaintext = self.open_from_file(current_path)?;
        let data_dir = crate::config::platform::data_dir();
        let new_rel = new_path.strip_prefix(&data_dir).unwrap_or(new_path);
        let new_aad = new_rel.as_os_str().as_encoded_bytes();
        let payload = serde_json::to_vec(&self.encrypt_with_aad(&plaintext, new_aad)?)?;
        let parent = current_path.parent().unwrap_or(Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        tmp.write_all(&payload)?;
        tmp.as_file().sync_all()?;
        tmp.persist(current_path).map_err(|e| e.error)?;
        Ok(())
    }

    /// The bytes [`seal_to_file`](Self::seal_to_file) writes, for a holder that is not a file — a
    /// `SecureStorage` slot.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.encrypt(plaintext)?)?)
    }

    /// The inverse of [`seal`](Self::seal).
    pub fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let encrypted: EncryptedData = serde_json::from_slice(sealed)
            .map_err(|e| DaemonError::Encryption(format!("sealed file is malformed: {}", e)))?;
        Ok(Zeroizing::new(self.decrypt(&encrypted)?))
    }
}

/// A string secret that resists accidental disclosure: its `Debug` is redacted (so a stray `{:?}`,
/// log line, or panic can't print it), it zeroizes on drop, and the cleartext is reachable only
/// through [`expose_secret`](Self::expose_secret). Serde is transparent — the raw value is written
/// only where the surrounding payload is itself encrypted at rest (e.g. inside a sealed key file).
///
/// Wrap any provider's in-memory secret field in this: the guarantee is structural, so it carries
/// forward to credential kinds not yet written.
///
/// Deliberately NOT `Serialize`: a `SecretString` can be read back from an (encrypted) file via
/// `Deserialize`, but it cannot be *written* anywhere — so no struct holding one can accidentally be
/// serialized into a log, config, or TOML in the clear. Persisting a secret means encrypting a
/// plain representation, not serializing the `SecretString` itself. This makes the invariant
/// structural rather than a doc comment.
#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// The cleartext. Named to keep every read of a secret greppable and deliberate.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// Generate a random 32-byte AES-256 key from the system CSPRNG.
///
/// Fallible rather than panicking: a CSPRNG that will not produce bytes has no safe fallback —
/// anything this returned instead would be a key an attacker could predict — so the failure has
/// to reach the caller, which is already returning `Result`.
pub fn generate_key() -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut key = vec![0u8; 32];
    rng.fill(&mut key)
        .map_err(|_| DaemonError::Encryption("system RNG failed".into()))?;
    Ok(key)
}

/// Base name of the slot holding the daemon's envelope-encryption key.
const ENCRYPTION_KEY_ID: &str = "daemon-encryption-key";

/// The slot holding the master key for the home at `home`.
///
/// A keychain or kernel-keyring slot is found by its name alone, so a bare name is shared by
/// every home on the machine under this uid. A second home would then adopt the first home's
/// key and open its sealed blobs, since their AAD is only the home-relative path. Keyed by the
/// home, as the other per-home slots are (storage-backend-per-home Req 5.1).
fn key_slot(home: &Path) -> String {
    format!(
        "{ENCRYPTION_KEY_ID}.{}",
        crate::storage::instance_namespace(home)
    )
}

/// Returns the name of the first compiled backend (other than `selected`) that already holds the
/// encryption key, or `None` if no other backend has it. Used to detect silent backend switches.
///
/// Note: `create_storage` has side effects for some backends — macOS Data Protection Keychain
/// writes and deletes a probe item to test entitlement availability; TPM opens the device node.
/// A probe error is treated as "no key" (the backend is inaccessible), which is the safe
/// fail-closed behavior: if we cannot reach the old backend, we cannot verify it holds the key,
/// so we proceed rather than blocking on an unreachable backend.
///
/// `candidates` is what the process that will *open* this key could reach, which is not always
/// every compiled backend: a key in an unreachable one belongs to another install scope.
fn other_backend_with_key(
    selected: crate::storage::Backend,
    candidates: &[crate::storage::Backend],
    home: &Path,
) -> Option<&'static str> {
    let slot = key_slot(home);
    candidates
        .iter()
        .copied()
        .filter(|&b| b != selected)
        .find_map(|b| {
            crate::storage::create_storage(b)
                .ok()
                .filter(|s| s.exists(&slot).unwrap_or(false))
                .map(|_| b.as_str())
        })
}

/// Initialize the encryption service, loading or generating a key in the given storage backend.
///
/// On a fresh install this mints a new key; on reinstall it loads the existing one. This is the
/// only path that mints on first run. If the key is present but cannot be unsealed (e.g. TPM
/// reset), this returns an error rather than auto-recovering — use [`rekey_encryption_with_backend`]
/// to explicitly quarantine the stale blobs and re-seal a fresh key.
///
/// Lives in `credsd-core` rather than the daemon: it only touches storage + encryption.
/// For `serve`, use [`open_encryption_with_backend`].
pub fn init_encryption_with_backend(explicit: Option<&str>) -> Result<EncryptionService> {
    encryption_impl(explicit, true, crate::storage::Backend::COMPILED)
}

/// Whether the system service's keystore holds a key, asked without opening it — for the
/// enclave, the only question a process outside launchd can answer about one.
pub fn system_service_key_present(explicit: &str) -> Result<bool> {
    let backend = crate::storage::select_backend(Some(explicit))?;
    let home = crate::config::platform::data_dir();
    crate::storage::create_storage(backend)?.exists(&key_slot(&home))
}

/// As [`init_encryption_with_backend`], but for a key the *system service* will open rather
/// than this process. The switch guard runs against [`crate::storage::system_service_backends`]
/// only, since this process can reach keystores that service cannot.
///
/// An enclave key is not minted here at all — it would bind to this launchd context and fail to
/// unwrap in the daemon — so an existing one is adopted unopened and a missing one is an error
/// pointing at `credsd install`. The TPM takes no such exception.
pub fn ensure_system_service_key(explicit: &str) -> Result<()> {
    let backend = crate::storage::select_backend(Some(explicit))?;
    if backend == crate::storage::Backend::SecureEnclave {
        if system_service_key_present(explicit)? {
            return Ok(());
        }
        return Err(DaemonError::config(
            "a Secure Enclave key for the system service cannot be minted here: the enclave \
             binds a key to the launchd context that created it, so this one would not unwrap \
             in the daemon. Run 'sudo credsd install', which mints it through a one-shot \
             launchd job and then installs the service.",
        ));
    }
    encryption_impl(
        Some(explicit),
        true,
        &crate::storage::system_service_backends(),
    )
    .map(|_| ())
}

/// Explicitly recover from a hardware key loss: quarantine all sealed credential blobs that
/// the current key can no longer decrypt, then mint and seal a fresh key.
///
/// This is a **destructive, irreversible operation**. Only proceed when the existing key is
/// confirmed unreadable (e.g. TPM unsealing fails). If the key is still readable this function
/// returns an error — a working key means there is nothing to recover from.
///
/// Distinct from rotation (re-encrypt all blobs under a new key, retaining both) and rewrap
/// (keep the same master key, re-seal under a new hardware binding). Those are out of scope here.
///
/// Use this after a TPM reset, firmware-induced PCR 7 violation, or any other event that
/// makes the sealed key unreadable. All cached credentials require re-authentication afterward.
#[cfg(target_os = "linux")]
pub fn rekey_encryption_with_backend(explicit: &str) -> Result<EncryptionService> {
    let backend = crate::storage::select_backend(Some(explicit))?;
    let store = crate::storage::create_storage(backend)?;
    let slot = key_slot(&crate::config::platform::data_dir());

    // Refuse if the key is still readable: quarantining credentials on a healthy host
    // permanently destroys them. Only proceed when retrieval actually fails.
    if store.exists(&slot)? && store.retrieve(&slot).is_ok() {
        return Err(DaemonError::config(
            "the existing encryption key is readable — there is nothing to recover from. \
             'credsd init --reset' is only for hardware key loss (TPM reset, PCR 7 violation). \
             Running it on a healthy system permanently destroys all sealed credentials.",
        ));
    }

    tracing::warn!(
        backend = backend.as_str(),
        "explicit rekey: key is unreadable; quarantining sealed credentials and generating a fresh key"
    );
    crate::storage::quarantine_sealed_credentials_after_reseal();
    let key = generate_key()?;
    store.store(&slot, &key)?;
    EncryptionService::new(key)
}

/// Delete the master key from `explicit`'s keystore, quarantining the sealed blobs under
/// `data_dir` first. Returns whether a key was there to delete.
///
/// Quarantine before delete, so a failure between the two leaves a key that still opens the
/// moved blobs.
#[cfg(unix)]
pub fn purge_encryption_key(explicit: &str, data_dir: &std::path::Path) -> Result<bool> {
    let backend = crate::storage::select_backend(Some(explicit))?;
    let store = crate::storage::create_storage(backend)?;
    let slot = key_slot(data_dir);
    if !store.exists(&slot)? {
        return Ok(false);
    }
    crate::storage::quarantine_sealed_credentials_in(data_dir);
    store.delete(&slot)?;
    tracing::warn!(
        backend = backend.as_str(),
        data_dir = %data_dir.display(),
        "encryption key purged; sealed credentials quarantined"
    );
    Ok(true)
}

/// Open the encryption service with an existing key; refuse to mint if no key is present.
///
/// For `serve`: a missing key means `credsd init` was never run or the keystore was wiped.
/// Run `credsd init --storage-backend <b>` or re-run `sudo credsd install`.
/// KKRS reboot recovery (only in builds with the `kkrs` feature) is still performed here — it is
/// the KKRS backend's normal startup behavior, not a destructive operation. TPM unseal failure returns an error; use
/// `credsd init --reset --storage-backend tpm` to recover.
pub fn open_encryption_with_backend(explicit: &str) -> Result<EncryptionService> {
    // Unused without `allow_first_run_mint`: open-only never reaches the switch guard.
    encryption_impl(Some(explicit), false, crate::storage::Backend::COMPILED)
}

fn no_key_error(backend: crate::storage::Backend) -> DaemonError {
    DaemonError::config(format!(
        "no encryption key found for backend '{}'; \
         run 'credsd init --storage-backend {}' to initialize, \
         or re-run 'sudo credsd install'.",
        backend.as_str(),
        backend.as_str()
    ))
}

fn encryption_impl(
    explicit: Option<&str>,
    allow_first_run_mint: bool,
    candidates: &[crate::storage::Backend],
) -> Result<EncryptionService> {
    let backend = crate::storage::select_backend(explicit)?;
    let store = crate::storage::create_storage(backend)?;
    open_or_mint(
        store.as_ref(),
        backend,
        &crate::config::platform::data_dir(),
        allow_first_run_mint,
        candidates,
    )
}

/// Load the master key for `home` from `store`, minting one only when `allow_first_run_mint`.
fn open_or_mint(
    store: &dyn crate::storage::SecureStorage,
    backend: crate::storage::Backend,
    home: &Path,
    allow_first_run_mint: bool,
    candidates: &[crate::storage::Backend],
) -> Result<EncryptionService> {
    let slot = key_slot(home);
    let is_file = backend == crate::storage::Backend::File;

    let key_bytes = if store.exists(&slot)? {
        match store.retrieve(&slot) {
            Ok(key) => key,
            // TPM unseal failure — refuse in both serve and init paths. Recovery is always
            // explicit: the operator runs `credsd init --reset --storage-backend tpm`, which quarantines
            // the undecryptable blobs and mints a fresh key. This prevents silent credential
            // destruction whether triggered from serve or from a reinstall.
            Err(e) if backend == crate::storage::Backend::Tpm => {
                return Err(DaemonError::config(format!(
                    "the TPM-sealed encryption key could not be unsealed (TPM error: {e}). \
                     Common causes: TPM was cleared or replaced, the key was sealed under a \
                     policy this build does not support, or /dev/tpmrm0 is inaccessible. \
                     Run 'credsd init --reset --storage-backend tpm' to recover: it will quarantine \
                     the undecryptable credential blobs and mint a fresh key. Each user's \
                     integrity record was sealed under the old key and will not open, so each \
                     user then runs 'creds revalidate' (its approval replaces the record), and \
                     re-bootstraps each environment with 'credsd bootstrap --env <env>'.",
                )));
            }
            Err(e) => return Err(e),
        }
    } else {
        // Key absent. In init mode, check for a silent backend switch and then mint.
        // In open-only (serve) mode, error unless this is a KKRS reboot recovery.
        if allow_first_run_mint {
            // Before minting a fresh key, check whether any other compiled backend already
            // holds one — a backend switch would orphan all sealed credentials.
            if let Some(other) = other_backend_with_key(backend, candidates, home) {
                return Err(DaemonError::config(format!(
                    "refusing to mint a new key: backend '{selected}' has no key but '{other}' does. \
                     To keep using the existing key: re-run with '--storage-backend {other}'. \
                     To switch to '{selected}': remove the encryption key from the '{other}' \
                     keystore, then re-run 'credsd init --storage-backend {selected}'. \
                     All cached credentials will need to be re-imported after switching \
                     ('credsd bootstrap --env <env>' for each environment).",
                    selected = backend.as_str(),
                )));
            }
        }

        // On Linux with the KKRS backend this is where a reboot (or a mid-session
        // keyring wipe) surfaces — the kernel clears the user keyring on reboot, so
        // "absent" is the reboot signal, not the retrieve-error branch above. Classify
        // against the boot sentinel and signal re-auth + purge undecryptable sealed
        // files + regenerate, rather than silently minting a new key.
        // This is a hardware-driven recovery re-key and applies even in open-only mode.
        #[cfg(all(target_os = "linux", feature = "kkrs"))]
        {
            if backend == crate::storage::Backend::KernelKeyring {
                crate::storage::linux_kkrs::recover_absent_key_from_proc(store, &slot)?
            } else if allow_first_run_mint {
                let key = generate_key()?;
                store.store(&slot, &key)?;
                key
            } else {
                return Err(no_key_error(backend));
            }
        }
        #[cfg(not(all(target_os = "linux", feature = "kkrs")))]
        {
            if allow_first_run_mint {
                let key = generate_key()?;
                store.store(&slot, &key)?;
                key
            } else {
                return Err(no_key_error(backend));
            }
        }
    };

    if is_file {
        tracing::warn!(
            backend = backend.as_str(),
            "encryption key protected by filesystem permissions only — \
             any process running as this user can read the key and exfiltrate sealed credentials"
        );
    } else {
        tracing::info!(backend = backend.as_str(), "encryption key loaded");
    }

    EncryptionService::new(key_bytes)
}

/// Initialize encryption using the auto-detected storage backend.
pub fn init_encryption() -> Result<EncryptionService> {
    init_encryption_with_backend(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes every test in this module that sets `CREDSD_DATA_DIR`. It must be one shared
    /// lock: a function-local `static` is a separate mutex per test, so two tests each holding
    /// their own still race on the one process environment. That surfaced as
    /// `other_backend_with_key_detects_key_in_file_backend` reading `None` when the path-binding
    /// test moved the data dir between its store and its lookup.
    static DATA_DIR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn round_trip() {
        let key = generate_key().unwrap();
        let svc = EncryptionService::new(key).unwrap();
        let plaintext = b"aws session credentials here";
        let encrypted = svc.encrypt(plaintext).unwrap();
        let decrypted = svc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_key().unwrap();
        let key2 = generate_key().unwrap();
        let svc1 = EncryptionService::new(key1).unwrap();
        let svc2 = EncryptionService::new(key2).unwrap();
        let encrypted = svc1.encrypt(b"secret").unwrap();
        assert!(svc2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = generate_key().unwrap();
        let svc = EncryptionService::new(key).unwrap();
        let mut encrypted = svc.encrypt(b"secret").unwrap();
        if let Some(byte) = encrypted.ciphertext.first_mut() {
            *byte ^= 0xff;
        }
        assert!(svc.decrypt(&encrypted).is_err());
    }

    #[test]
    fn invalid_key_length() {
        assert!(EncryptionService::new(vec![0u8; 16]).is_err());
    }

    #[test]
    fn encrypted_data_serializes() {
        let key = generate_key().unwrap();
        let svc = EncryptionService::new(key).unwrap();
        let encrypted = svc.encrypt(b"test").unwrap();
        let json = serde_json::to_string(&encrypted).unwrap();
        // Binary fields must serialize as base64 strings, not serde's default
        // array-of-integers: assert the JSON carries string values and no `[`.
        assert!(
            json.contains("\"ciphertext\":\"") && json.contains("\"nonce\":\""),
            "fields must be base64 strings: {json}"
        );
        assert!(!json.contains('['), "no array-of-integers encoding: {json}");
        let deserialized: EncryptedData = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.nonce, encrypted.nonce);
        assert_eq!(deserialized.ciphertext, encrypted.ciphertext);
    }

    #[test]
    fn seal_to_file_round_trips() {
        let svc = EncryptionService::new(generate_key().unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.enc");
        svc.seal_to_file(&path, b"long-term key material").unwrap();
        assert_eq!(
            &*svc.open_from_file(&path).unwrap(),
            b"long-term key material"
        );
    }

    #[test]
    fn open_from_file_wrong_key_fails() {
        let svc1 = EncryptionService::new(generate_key().unwrap()).unwrap();
        let svc2 = EncryptionService::new(generate_key().unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.enc");
        svc1.seal_to_file(&path, b"secret").unwrap();
        assert!(svc2.open_from_file(&path).is_err());
    }

    #[test]
    fn seal_to_file_is_0600() {
        let svc = EncryptionService::new(generate_key().unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.enc");
        svc.seal_to_file(&path, b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "sealed file must be 0600, got {:o}", mode);
        }
    }

    #[test]
    fn open_from_file_rejects_garbage() {
        let svc = EncryptionService::new(generate_key().unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.enc");
        std::fs::write(&path, b"not encrypted json").unwrap();
        let err = svc.open_from_file(&path).unwrap_err().to_string();
        assert!(err.contains("malformed"), "unexpected: {}", err);
    }

    /// The guard must never report the selected backend as the "other" holder,
    /// regardless of which backends are compiled or have keys on this host.
    #[test]
    fn other_backend_with_key_never_returns_selected() {
        for &b in crate::storage::Backend::COMPILED {
            let result = other_backend_with_key(
                b,
                crate::storage::Backend::COMPILED,
                &crate::config::platform::data_dir(),
            );
            if let Some(name) = result {
                assert_ne!(
                    name,
                    b.as_str(),
                    "other_backend_with_key({:?}) must not return the selected backend",
                    b
                );
            }
        }
    }

    /// Plant a key in the File backend and verify the guard finds it when a different
    /// backend is selected. Uses CREDSD_DATA_DIR to isolate from the real data dir.
    #[cfg(any(not(target_os = "macos"), feature = "file"))]
    #[test]
    fn other_backend_with_key_detects_key_in_file_backend() {
        use crate::storage::{Backend, FileStorage, SecureStorage};

        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("CREDSD_DATA_DIR", dir.path());

        let file_store = FileStorage::new();
        let key = generate_key().unwrap();
        file_store.store(&key_slot(dir.path()), &key).unwrap();

        // Any selected backend other than File should now see File holds the key.
        let non_file = Backend::COMPILED
            .iter()
            .copied()
            .find(|&b| b != Backend::File);

        let result = non_file.map(|b| other_backend_with_key(b, Backend::COMPILED, dir.path()));

        let _ = file_store.delete(&key_slot(dir.path()));
        std::env::remove_var("CREDSD_DATA_DIR");

        if let Some(found) = result {
            assert_eq!(
                found,
                Some("file"),
                "expected file backend to be detected as holding the key"
            );
        }
        // If no other compiled backend exists (single-backend build), the test is vacuous but correct.
    }

    /// The system-service path accepts an enclave key that is already there without opening it
    /// — a reinstall runs as root while that file belongs to the service account, and the
    /// backend refuses a key file owned by another uid on purpose — and refuses to mint one
    /// when it is absent, because a key minted outside launchd does not unwrap in the daemon.
    /// Returns early where there is no enclave to select: CI runners are virtualized.
    #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
    #[test]
    fn the_system_service_path_adopts_an_enclave_key_but_will_not_mint_one() {
        if !crate::storage::Backend::SecureEnclave.is_available() {
            return;
        }
        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("CREDSD_DATA_DIR", dir.path());
        let refused = ensure_system_service_key("secure-enclave");

        // The sealed half alone: `exists` is a stat of it, while opening the key needs the
        // `.sekey` beside it, so an attempt to open this would have to fail.
        let enclave = dir.path().join("secure-enclave");
        std::fs::create_dir_all(&enclave).unwrap();
        std::fs::write(
            enclave.join(format!("{}.sealed", key_slot(dir.path()))),
            b"sealed",
        )
        .unwrap();
        let ensured = ensure_system_service_key("secure-enclave");
        let opened = init_encryption_with_backend(Some("secure-enclave"));
        std::env::remove_var("CREDSD_DATA_DIR");

        let refusal = refused
            .expect_err("minting here must be refused")
            .to_string();
        assert!(refusal.contains("sudo credsd install"), "{refusal}");
        assert!(ensured.is_ok(), "{:?}", ensured.err());
        assert!(opened.is_err(), "opening it must be what fails");
    }

    /// The guard consults only the keystores the opening process could reach. A key in a backend
    /// outside that set belongs to another install scope, with its own data directory and its own
    /// credentials, so it must not block a mint — which is what refused every correct macOS
    /// system install on a machine where a user install had left a keychain key.
    #[cfg(any(not(target_os = "macos"), feature = "file"))]
    #[test]
    fn the_switch_guard_ignores_backends_outside_the_candidate_list() {
        use crate::storage::{Backend, FileStorage, SecureStorage};

        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("CREDSD_DATA_DIR", dir.path());

        let file_store = FileStorage::new();
        file_store
            .store(&key_slot(dir.path()), &generate_key().unwrap())
            .unwrap();

        let without_file: Vec<Backend> = Backend::COMPILED
            .iter()
            .copied()
            .filter(|&b| b != Backend::File)
            .collect();
        let selected = without_file.first().copied();
        let seen = selected.map(|b| other_backend_with_key(b, Backend::COMPILED, dir.path()));
        let hidden = selected.map(|b| other_backend_with_key(b, &without_file, dir.path()));

        let _ = file_store.delete(&key_slot(dir.path()));
        std::env::remove_var("CREDSD_DATA_DIR");

        if selected.is_some() {
            assert_eq!(
                seen,
                Some(Some("file")),
                "in the candidate list it is found"
            );
            assert_eq!(hidden, Some(None), "outside it, it must not block a mint");
        }
    }

    /// Purge deletes the key and leaves the sealed blobs in quarantine rather than in place:
    /// a blob still sitting in `credentials/` after the key is gone reads as a live session the
    /// daemon can never open.
    #[cfg(any(not(target_os = "macos"), feature = "file"))]
    #[test]
    fn purge_quarantines_sealed_blobs_then_deletes_the_key() {
        use crate::storage::{FileStorage, SecureStorage};

        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        std::env::set_var("CREDSD_DATA_DIR", data_dir);

        let store = FileStorage::new();
        store
            .store(&key_slot(dir.path()), &generate_key().unwrap())
            .unwrap();
        let sealed = data_dir.join("callers/501/credentials/dev/session.enc");
        std::fs::create_dir_all(sealed.parent().unwrap()).unwrap();
        std::fs::write(&sealed, b"sealed").unwrap();

        let purged = purge_encryption_key("file", data_dir);
        let second = purge_encryption_key("file", data_dir);
        std::env::remove_var("CREDSD_DATA_DIR");

        assert!(purged.unwrap(), "a key was there to delete");
        assert!(!second.unwrap(), "purging again finds nothing");
        assert!(!store.exists(&key_slot(dir.path())).unwrap());
        assert!(!sealed.exists(), "sealed blob must be moved aside");
        assert!(
            data_dir.join("quarantine").is_dir(),
            "sealed blob must land in quarantine"
        );
    }

    // Exercises the strip_prefix → relative-path branch: two files inside data_dir get
    // distinct relative AADs, so copying foo/ra_key.enc → bar/ra_key.enc fails.
    #[test]
    fn open_from_file_relative_path_binding_via_data_dir() {
        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let data_dir = tempfile::tempdir().unwrap();
        std::env::set_var("CREDSD_DATA_DIR", data_dir.path());

        let svc = EncryptionService::new(generate_key().unwrap()).unwrap();
        let path_a = data_dir.path().join("foo").join("ra_key.enc");
        let path_b = data_dir.path().join("bar").join("ra_key.enc");
        std::fs::create_dir_all(path_a.parent().unwrap()).unwrap();
        std::fs::create_dir_all(path_b.parent().unwrap()).unwrap();
        svc.seal_to_file(&path_a, b"private key material").unwrap();
        std::fs::copy(&path_a, &path_b).unwrap();
        let result = svc.open_from_file(&path_b);

        std::env::remove_var("CREDSD_DATA_DIR");
        assert!(result.is_err(), "cross-slot copy must fail authentication");
    }

    // Req 1.2: copy to a different path fails authentication.
    #[test]
    fn open_from_file_different_path_fails() {
        let svc = EncryptionService::new(generate_key().unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("foo.enc");
        let path_b = dir.path().join("bar.enc");
        svc.seal_to_file(&path_a, b"secret").unwrap();
        std::fs::copy(&path_a, &path_b).unwrap();
        assert!(svc.open_from_file(&path_b).is_err());
    }

    // Req 2.2: file sealed before this change (empty AAD) fails to open at any path.
    #[test]
    fn open_from_file_rejects_legacy_empty_aad() {
        let svc = EncryptionService::new(generate_key().unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.enc");
        // Simulate a pre-upgrade sealed file: raw encrypt with empty AAD written directly.
        let legacy = serde_json::to_vec(&svc.encrypt(b"old creds").unwrap()).unwrap();
        std::fs::write(&path, &legacy).unwrap();
        assert!(svc.open_from_file(&path).is_err());
    }

    /// A keychain-style store: one slot namespace shared by every home on the machine under
    /// one uid, which is the shape that let a second home adopt the first home's key.
    #[derive(Default)]
    struct MachineSlots(std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>);

    impl crate::storage::SecureStorage for MachineSlots {
        fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(key_id.to_owned(), data.to_vec());
            Ok(())
        }
        fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(key_id)
                .cloned()
                .ok_or_else(|| DaemonError::config("no such slot"))
        }
        fn delete(&self, key_id: &str) -> Result<()> {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(key_id);
            Ok(())
        }
        fn exists(&self, key_id: &str) -> Result<bool> {
            Ok(self
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key(key_id))
        }
        fn backend_name(&self) -> &'static str {
            "machine-slots"
        }
    }

    // storage-backend-per-home Req 5.1: a second home on this machine and uid must not adopt
    // the first home's master key just because the slot name is the same.
    #[test]
    fn a_second_home_does_not_adopt_the_first_homes_key() {
        use crate::storage::Backend;

        let machine = MachineSlots::default();
        let home_a = tempfile::tempdir().unwrap();
        let home_b = tempfile::tempdir().unwrap();

        let minted = open_or_mint(&machine, Backend::File, home_a.path(), true, &[]);
        let adopted = open_or_mint(&machine, Backend::File, home_b.path(), false, &[]);

        assert!(minted.is_ok(), "home A mints its key");
        assert!(adopted.is_err(), "home B must not open home A's master key");
    }

    /// The path a home names once it exists, with `.` dropped and `..` popping the previous
    /// segment: the lexical model of what `key_slot` must agree with. `None` when a `..` would
    /// climb above `root`, so a generated home never leaves its tempdir.
    fn lexical_home(segs: &[&str]) -> Option<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for s in segs {
            match *s {
                "." => {}
                ".." => {
                    out.pop()?;
                }
                name => out.push(name.to_owned()),
            }
        }
        (!out.is_empty()).then_some(out)
    }

    // Req 5.1/5.2, on a real filesystem: a home's slot is the same before and after the home
    // is created, including `.` and `..` segments that pass through directories which do not
    // exist yet, and two homes get the same slot only when they name the same directory.
    proptest::proptest! {
        #[test]
        fn key_slot_is_per_home_and_stable(
            a in proptest::collection::vec(proptest::sample::select(vec!["a", "b", ".", ".."]), 1..6),
            b in proptest::collection::vec(proptest::sample::select(vec!["a", "b", ".", ".."]), 1..6),
        ) {
            let (Some(norm_a), Some(norm_b)) = (lexical_home(&a), lexical_home(&b)) else {
                return Ok(());
            };
            let root = tempfile::tempdir().unwrap();
            let join = |segs: &[&str]| segs.iter().fold(root.path().to_path_buf(), |p, s| p.join(s));
            let (home_a, home_b) = (join(&a), join(&b));

            let before_a = key_slot(&home_a);
            let before_b = key_slot(&home_b);
            proptest::prop_assert_eq!(before_a == before_b, norm_a == norm_b);

            // Created by its lexical form: `create_dir_all` cannot make a path ending in `.`.
            let made = |norm: &[String]| norm.iter().fold(root.path().to_path_buf(), |p, s| p.join(s));
            std::fs::create_dir_all(made(&norm_a)).unwrap();
            proptest::prop_assert_eq!(&key_slot(&home_a), &before_a, "creating a home moved its slot");
            std::fs::create_dir_all(made(&norm_b)).unwrap();
            proptest::prop_assert_eq!(&key_slot(&home_b), &before_b, "creating a home moved its slot");
        }
    }
}
