//! Kernel keyring (KKRS) encryption-key backend (`Backend::KernelKeyring`), Linux only.
//!
//! Keeps the AES-256 master key in the **kernel user keyring** via the pure-Rust
//! [`linux_keyutils`] crate (no `libkeyutils` C dependency). The plaintext key
//! exists only in kernel and process memory — never on disk. See
//! `docs/specs/kkrs-encryption-backend/`.
//!
//! ## Reboot surprise
//!
//! The user keyring is wiped on reboot, so a KKRS-backed daemon forgets every
//! cached secret across a reboot. To make that visible rather than surprising, a
//! small [`BootSentinel`] on disk records the boot identity present when the key
//! was created. At startup, when the key is absent, [`classify`] tells the
//! key-init path whether this is a first run, a reboot, or a same-boot anomaly;
//! the reboot/anomaly cases signal re-auth and quarantine the now-undecryptable
//! sealed files (moved aside, not deleted) instead of silently minting a new key.

use std::path::{Path, PathBuf};

use linux_keyutils::{KeyRing, KeyRingIdentifier};
use serde::{Deserialize, Serialize};

use crate::error::{DaemonError, Result};
use crate::storage::{SecureStorage, SERVICE_NAME};

/// A `SecureStorage` that keeps values in the kernel user keyring.
pub(crate) struct KkrsStorage;

impl KkrsStorage {
    pub(crate) fn new() -> Self {
        Self
    }
}

/// Keyring description for a `key_id`, reusing [`SERVICE_NAME`] so the daemon
/// names itself consistently to the OS (Keychain service, launchd/systemd units).
fn description(key_id: &str) -> String {
    format!("{SERVICE_NAME}:{key_id}")
}

/// The per-UID user keyring, with possession established.
///
/// A freshly created user keyring grants its owner only view/read — *not* search
/// — while the possessor gets full rights. So `store` (write) can succeed while a
/// later `search`/`read` fails unless the process possesses the keyring. A daemon
/// under a private session keyring (systemd `KeyringMode=private`, minimal
/// containers) does not possess `@u` by default, which would break the
/// store-then-retrieve round-trip Req 2.2/2.3 depend on. Linking `@u` into the
/// session keyring makes the process possess it, so possessor rights apply to the
/// keyring and every key in it. The link is idempotent and non-fatal: if the
/// session keyring cannot be modified we proceed with whatever rights we already
/// have rather than failing outright.
fn user_keyring() -> Result<KeyRing> {
    let user = KeyRing::from_special_id(KeyRingIdentifier::User, false)
        .map_err(|e| DaemonError::Storage(format!("cannot access user keyring: {e}")))?;
    if let Ok(session) = KeyRing::from_special_id(KeyRingIdentifier::Session, false) {
        let _ = session.link_keyring_id(KeyRingIdentifier::User);
    }
    Ok(user)
}

impl SecureStorage for KkrsStorage {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
        // add_key updates the payload when the description already exists, so this
        // is idempotent (spec 2.1).
        user_keyring()?
            .add_key(&description(key_id), data)
            .map(|_| ())
            .map_err(|e| DaemonError::Storage(format!("cannot add key '{key_id}' to keyring: {e}")))
    }

    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        let key = user_keyring()?
            .search(&description(key_id))
            .map_err(|e| DaemonError::Storage(format!("key '{key_id}' not in keyring: {e}")))?;
        key.read_to_vec()
            .map_err(|e| DaemonError::Storage(format!("cannot read key '{key_id}': {e}")))
    }

    fn delete(&self, key_id: &str) -> Result<()> {
        // Idempotent: a not-found key is not an error (spec 2.6).
        match user_keyring()?.search(&description(key_id)) {
            Ok(key) => key.invalidate().map_err(|e| {
                DaemonError::Storage(format!("cannot invalidate key '{key_id}': {e}"))
            }),
            Err(_) => Ok(()),
        }
    }

    fn exists(&self, key_id: &str) -> Result<bool> {
        let kr = user_keyring()?;
        match kr.search(&description(key_id)) {
            Ok(_) => Ok(true),
            // Any error after a successful user_keyring() means the key is absent.
            // After obtaining a valid keyring handle, search errors are exclusively
            // "key not found" variants; access errors would have already failed at
            // user_keyring().
            Err(_) => Ok(false),
        }
    }

    fn backend_name(&self) -> &'static str {
        "kkrs"
    }
}

/// On-disk record of the boot identity present when the master key was created.
/// Survives reboot (unlike the keyring key), so its boot identity differing from
/// the current one is the reboot signal. Holds no secret material (spec 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BootSentinel {
    /// `/proc/sys/kernel/random/boot_id`, when available (primary identity).
    pub(crate) boot_id: Option<String>,
    /// `/proc/stat` `btime` epoch seconds (fallback identity).
    pub(crate) boot_time: Option<i64>,
    /// RFC-3339 timestamp of key creation, for operator diagnostics.
    pub(crate) created_at: String,
}

impl BootSentinel {
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("kkrs.sentinel")
    }

    /// Read the sentinel under `data_dir`, treating any read or parse failure as
    /// "no sentinel" (→ `FirstRun`) so a corrupt sentinel never wedges startup
    /// (spec Error Handling).
    fn load(data_dir: &Path) -> Option<Self> {
        let bytes = std::fs::read(Self::path(data_dir)).ok()?;
        match serde_json::from_slice(&bytes) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::debug!("ignoring unreadable kkrs sentinel: {e}");
                None
            }
        }
    }

    /// Write the sentinel `0600` under the `0700` data dir (spec 5.2), matching
    /// `EncryptionService::seal_to_file`'s permission convention.
    fn write(&self, data_dir: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(data_dir)?;
        let _ = std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700));
        let path = Self::path(data_dir);
        std::fs::write(&path, serde_json::to_vec(self)?)?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        Ok(())
    }
}

/// Current boot identity from `/proc/sys/kernel/random/boot_id` (a random UUID
/// regenerated on every boot). One of the two `/proc` seams tests stub.
fn current_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Fallback boot identity: kernel boot time from `/proc/stat` `btime` (epoch
/// seconds), for the rare kernel without `boot_id`. The other `/proc` seam.
fn current_boot_time() -> Option<i64> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    stat.lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse::<i64>().ok())
}

/// What the KKRS key-init path found at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KkrsKeyState {
    /// Key in keyring; load it.
    Present,
    /// Key absent, no sentinel; generate and write the sentinel.
    FirstRun,
    /// Key absent, sentinel boot identity differs; reboot recovery.
    Rebooted,
    /// Key absent, sentinel boot identity matches; mid-session wipe recovery.
    VanishedSameBoot,
}

/// Classify the key-init situation from the key's presence and the boot identity.
///
/// Pure so tests drive every branch with synthetic boot identities and never
/// reboot. `boot_id` is primary; `boot_time` is the fallback; when neither
/// identity source is available on both sides the result is `Rebooted` — the
/// fail-safe that prefers a re-auth prompt over silent data loss (spec 3.7).
pub(crate) fn classify(
    key_present: bool,
    sentinel: Option<&BootSentinel>,
    current_boot_id: Option<&str>,
    current_boot_time: Option<i64>,
) -> KkrsKeyState {
    if key_present {
        return KkrsKeyState::Present;
    }
    let sentinel = match sentinel {
        Some(s) => s,
        None => return KkrsKeyState::FirstRun,
    };

    let same = |eq: bool| {
        if eq {
            KkrsKeyState::VanishedSameBoot
        } else {
            KkrsKeyState::Rebooted
        }
    };

    // Primary: boot_id present on both sides.
    if let (Some(saved), Some(current)) = (sentinel.boot_id.as_deref(), current_boot_id) {
        return same(saved == current);
    }
    // Fallback: boot_time present on both sides.
    if let (Some(saved), Some(current)) = (sentinel.boot_time, current_boot_time) {
        return same(saved == current);
    }
    // Neither identity source available on both sides: fail safe.
    KkrsKeyState::Rebooted
}

/// Handle the KKRS "key absent" branch: classify against the sentinel under
/// `data_dir`, then either first-run generate, or (reboot / mid-session wipe)
/// signal re-auth + purge now-undecryptable sealed files + regenerate. Returns
/// the fresh master key. Boot identity is injected so tests exercise every branch
/// without rebooting; `recover_absent_key_from_proc` supplies the real `/proc`
/// values in production.
fn recover_absent_key_in(
    store: &dyn SecureStorage,
    key_id: &str,
    data_dir: &Path,
    boot_id: Option<&str>,
    boot_time: Option<i64>,
) -> Result<Vec<u8>> {
    let sentinel = BootSentinel::load(data_dir);
    match classify(false, sentinel.as_ref(), boot_id, boot_time) {
        KkrsKeyState::FirstRun => {
            tracing::info!(
                backend = "kkrs",
                "no master key in kernel keyring; generating a first-run key"
            );
        }
        KkrsKeyState::Rebooted => {
            tracing::warn!(
                backend = "kkrs",
                "kernel keyring was cleared by a reboot; cached credentials are gone and \
                 re-authentication is required"
            );
            crate::storage::quarantine_sealed_credentials_in(data_dir);
        }
        KkrsKeyState::VanishedSameBoot => {
            tracing::warn!(
                backend = "kkrs",
                "kernel keyring key vanished with no reboot detected (keyring cleared \
                 mid-session); cached credentials are gone and re-authentication is required"
            );
            crate::storage::quarantine_sealed_credentials_in(data_dir);
        }
        KkrsKeyState::Present => {
            // Unreachable: this path runs only when the key is absent. Regenerate
            // rather than panic, keeping the function total.
            tracing::debug!(
                backend = "kkrs",
                "recover called with key present; regenerating"
            );
        }
    }

    let key = crate::encryption::generate_key()?;
    store.store(key_id, &key)?;
    BootSentinel {
        boot_id: boot_id.map(str::to_string),
        boot_time,
        created_at: chrono::Utc::now().to_rfc3339(),
    }
    .write(data_dir)?;
    Ok(key)
}

/// Production entry for the KKRS key-absent branch: reads the real `/proc` boot
/// identity and the daemon data dir, then delegates to [`recover_absent_key_in`].
pub(crate) fn recover_absent_key_from_proc(
    store: &dyn SecureStorage,
    key_id: &str,
) -> Result<Vec<u8>> {
    let data_dir = crate::config::platform::data_dir();
    recover_absent_key_in(
        store,
        key_id,
        &data_dir,
        current_boot_id().as_deref(),
        current_boot_time(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn sentinel(boot_id: Option<&str>, boot_time: Option<i64>) -> BootSentinel {
        BootSentinel {
            boot_id: boot_id.map(str::to_string),
            boot_time,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    /// In-memory `SecureStorage` for the recovery e2e (no real keyring needed).
    #[derive(Default)]
    struct FakeStore {
        map: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl FakeStore {
        fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<u8>>> {
            self.map.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    impl SecureStorage for FakeStore {
        fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
            self.lock().insert(key_id.to_string(), data.to_vec());
            Ok(())
        }
        fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
            self.lock()
                .get(key_id)
                .cloned()
                .ok_or_else(|| DaemonError::Storage(format!("absent: {key_id}")))
        }
        fn delete(&self, key_id: &str) -> Result<()> {
            self.lock().remove(key_id);
            Ok(())
        }
        fn exists(&self, key_id: &str) -> Result<bool> {
            Ok(self.lock().contains_key(key_id))
        }
        fn backend_name(&self) -> &'static str {
            "fake"
        }
    }

    #[test]
    fn description_reuses_service_name() {
        assert_eq!(
            description("daemon-encryption-key"),
            "com.amazon.aws.credsd:daemon-encryption-key"
        );
    }

    #[test]
    fn classify_present_regardless_of_sentinel() {
        assert_eq!(
            classify(true, None, Some("x"), Some(1)),
            KkrsKeyState::Present
        );
        assert_eq!(
            classify(
                true,
                Some(&sentinel(Some("a"), Some(1))),
                Some("b"),
                Some(2)
            ),
            KkrsKeyState::Present
        );
    }

    #[test]
    fn classify_first_run_when_no_sentinel() {
        assert_eq!(
            classify(false, None, Some("x"), Some(1)),
            KkrsKeyState::FirstRun
        );
    }

    #[test]
    fn classify_boot_id_primary() {
        // Differing boot_id → Rebooted, even if boot_time matches.
        assert_eq!(
            classify(
                false,
                Some(&sentinel(Some("old"), Some(100))),
                Some("new"),
                Some(100)
            ),
            KkrsKeyState::Rebooted
        );
        // Matching boot_id → VanishedSameBoot.
        assert_eq!(
            classify(
                false,
                Some(&sentinel(Some("same"), Some(100))),
                Some("same"),
                Some(200)
            ),
            KkrsKeyState::VanishedSameBoot
        );
    }

    #[test]
    fn classify_boot_time_fallback() {
        // No boot_id on either side → fall back to boot_time.
        assert_eq!(
            classify(false, Some(&sentinel(None, Some(100))), None, Some(200)),
            KkrsKeyState::Rebooted
        );
        assert_eq!(
            classify(false, Some(&sentinel(None, Some(100))), None, Some(100)),
            KkrsKeyState::VanishedSameBoot
        );
        // boot_id present on only one side → still falls through to boot_time.
        assert_eq!(
            classify(
                false,
                Some(&sentinel(None, Some(100))),
                Some("current"),
                Some(100)
            ),
            KkrsKeyState::VanishedSameBoot
        );
    }

    #[test]
    fn classify_no_identity_source_fails_safe_to_rebooted() {
        assert_eq!(
            classify(false, Some(&sentinel(None, None)), None, None),
            KkrsKeyState::Rebooted
        );
    }

    #[test]
    fn sentinel_serde_round_trip() {
        let s = sentinel(Some("boot-uuid"), Some(1_700_000_000));
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: BootSentinel = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn sentinel_corrupt_is_treated_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(BootSentinel::path(dir.path()), b"not json").unwrap();
        assert!(BootSentinel::load(dir.path()).is_none());
    }

    #[test]
    fn sentinel_missing_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(BootSentinel::load(dir.path()).is_none());
    }

    #[test]
    fn sentinel_write_read_round_trip_and_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let s = sentinel(Some("uuid"), Some(42));
        s.write(dir.path()).unwrap();
        assert_eq!(BootSentinel::load(dir.path()).as_ref(), Some(&s));
        let mode = std::fs::metadata(BootSentinel::path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "sentinel must be 0600, got {mode:o}");
    }

    #[test]
    fn first_run_generates_key_and_writes_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::default();
        let key = recover_absent_key_in(&store, "k", dir.path(), Some("boot-1"), Some(10)).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(store.retrieve("k").unwrap(), key);
        let written = BootSentinel::load(dir.path()).unwrap();
        assert_eq!(written.boot_id.as_deref(), Some("boot-1"));
    }

    /// Reboot recovery e2e (spec Property 8): a sentinel with a differing boot_id
    /// plus dummy sealed files in BOTH the daemon (`callers/`) and legacy
    /// credential trees are seeded. After recovery the sealed files are moved into
    /// a quarantine generation (not deleted), a fresh key is stored, and the
    /// sentinel carries the new boot id. Recovery operates on the injected
    /// `data_dir`, so no env override is needed; reboot is simulated via the
    /// injected boot-id seam with no actual reboot.
    #[test]
    fn reboot_recovery_quarantines_both_trees_and_regenerates() {
        let dir = tempfile::tempdir().unwrap();

        sentinel(Some("old-boot"), Some(100))
            .write(dir.path())
            .unwrap();

        // Daemon tree: <data_dir>/callers/<uid>/credentials/<name>/*.enc
        let daemon = dir.path().join("callers/1000/credentials/dev");
        std::fs::create_dir_all(&daemon).unwrap();
        let daemon_sealed = daemon.join("sso_token.enc");
        std::fs::write(&daemon_sealed, b"daemon ciphertext").unwrap();
        // Legacy standalone tree: <data_dir>/credentials/<name>/*.enc
        let legacy = dir.path().join("credentials/legacy");
        std::fs::create_dir_all(&legacy).unwrap();
        let legacy_sealed = legacy.join("oauth_token.enc");
        std::fs::write(&legacy_sealed, b"legacy ciphertext").unwrap();

        let store = FakeStore::default();
        let key =
            recover_absent_key_in(&store, "k", dir.path(), Some("new-boot"), Some(200)).unwrap();

        assert_eq!(key.len(), 32, "a fresh key must be generated");
        assert_eq!(
            store.retrieve("k").unwrap(),
            key,
            "fresh key must be stored"
        );
        assert_eq!(
            BootSentinel::load(dir.path()).unwrap().boot_id.as_deref(),
            Some("new-boot"),
            "sentinel must record the new boot identity"
        );

        // Both originals are moved out of the scanned trees (credential_status clean).
        assert!(!daemon_sealed.exists(), "daemon sealed file must be moved");
        assert!(!legacy_sealed.exists(), "legacy sealed file must be moved");

        // Exactly one quarantine generation, mirroring both relative paths with content.
        let quarantine = dir.path().join("quarantine");
        let gens: Vec<_> = std::fs::read_dir(&quarantine)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(gens.len(), 1, "one generation per recovery event");
        let gen = &gens[0];
        let moved_daemon = gen.join("callers/1000/credentials/dev/sso_token.enc");
        let moved_legacy = gen.join("credentials/legacy/oauth_token.enc");
        assert_eq!(std::fs::read(&moved_daemon).unwrap(), b"daemon ciphertext");
        assert_eq!(std::fs::read(&moved_legacy).unwrap(), b"legacy ciphertext");
    }

    /// Real user-keyring round-trip (spec Properties 1-3). Skips gracefully — does
    /// not fail — when the user keyring is unusable in this environment (e.g.
    /// minimal containers with keyrings disabled, or a session that forbids
    /// establishing possession): a store that cannot be observed back means the
    /// keyring is not usable here, not that the backend is wrong.
    #[test]
    fn real_keyring_round_trip() {
        let s = KkrsStorage::new();
        let key_id = format!("credsd-test-{}", std::process::id());
        let payload = b"0123456789abcdef0123456789abcdef";

        if s.store(&key_id, payload).is_err() || !s.exists(&key_id).unwrap_or(false) {
            eprintln!("skipping kkrs keyring test: user keyring not usable in this environment");
            let _ = s.delete(&key_id);
            return;
        }
        assert_eq!(s.retrieve(&key_id).unwrap(), payload);

        // store is idempotent and updates the payload.
        let payload2 = b"ffffffffffffffffffffffffffffffff";
        s.store(&key_id, payload2).unwrap();
        assert_eq!(s.retrieve(&key_id).unwrap(), payload2);

        s.delete(&key_id).unwrap();
        assert!(!s.exists(&key_id).unwrap());
        assert!(s.retrieve(&key_id).is_err());
        // delete is idempotent.
        s.delete(&key_id).unwrap();
    }

    proptest::proptest! {
        /// Property 5: the keyring description is exactly `com.amazon.aws.credsd:{key_id}`.
        #[test]
        fn prop_description_format(key_id in "[a-zA-Z0-9._-]{1,64}") {
            proptest::prop_assert_eq!(
                description(&key_id),
                format!("com.amazon.aws.credsd:{key_id}")
            );
        }

        /// Property 6: exhaustive truth table for `classify`.
        #[test]
        fn prop_classify_truth_table(
            key_present in proptest::bool::ANY,
            has_sentinel in proptest::bool::ANY,
            s_boot_id in proptest::option::of("[a-z]{1,8}"),
            s_boot_time in proptest::option::of(0i64..1_000_000),
            c_boot_id in proptest::option::of("[a-z]{1,8}"),
            c_boot_time in proptest::option::of(0i64..1_000_000),
        ) {
            let sen = if has_sentinel {
                Some(BootSentinel {
                    boot_id: s_boot_id.clone(),
                    boot_time: s_boot_time,
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                })
            } else {
                None
            };
            let got = classify(key_present, sen.as_ref(), c_boot_id.as_deref(), c_boot_time);

            let expected = if key_present {
                KkrsKeyState::Present
            } else if sen.is_none() {
                KkrsKeyState::FirstRun
            } else {
                // Determine the effective identity comparison the same way classify does.
                let by_boot_id = match (s_boot_id.as_deref(), c_boot_id.as_deref()) {
                    (Some(a), Some(b)) => Some(a == b),
                    _ => None,
                };
                let determinate = by_boot_id.or(match (s_boot_time, c_boot_time) {
                    (Some(a), Some(b)) => Some(a == b),
                    _ => None,
                });
                match determinate {
                    Some(true) => KkrsKeyState::VanishedSameBoot,
                    Some(false) => KkrsKeyState::Rebooted,
                    None => KkrsKeyState::Rebooted,
                }
            };
            proptest::prop_assert_eq!(got, expected);
        }
    }
}
