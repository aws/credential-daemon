//! AES-GCM sealed integrity snapshots for load-bearing config files.
//!
//! Each load-bearing file (`config.toml`, `credentials.toml`) has a companion
//! `*_snapshot.enc` file containing its canonical form sealed under the master key.
//! Any change to the config file outside the daemon is detected by decrypting the
//! snapshot and comparing the stored canonical form to the current file's form.
//!
//! A snapshot sits beside its file, so whoever can delete or restore the file can delete or
//! restore the snapshot too. The integrity record, held in daemon-owned storage, pins which
//! snapshot is current ([`Pin`]); [`assess`] consults it (drift-detection Requirement 10).

use std::path::{Path, PathBuf};

use aws_lc_rs::digest;

use crate::config::{credentials::CredentialSources, DaemonConfig};
use crate::encryption::EncryptionService;
use crate::error::Result;

/// Companion snapshot path: `config.toml` → `config_snapshot.enc`.
pub fn snapshot_path(config_path: &Path) -> PathBuf {
    let stem = config_path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy();
    config_path.with_file_name(format!("{stem}_snapshot.enc"))
}

/// SHA-256 of `bytes`. Used for the in-memory DoS-resistant hash cache.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, bytes);
    let slice: &[u8] = d.as_ref();
    // SHA-256 always produces 32 bytes; the slice-to-array conversion cannot fail.
    slice.try_into().unwrap_or([0u8; 32])
}

/// Result of a snapshot verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftStatus {
    /// Snapshot matches the current file. `hash` is cached for DoS-resistant re-checks.
    Valid { hash: [u8; 32] },
    /// Snapshot exists and decrypts, but does not match the current canonical form.
    Drifted,
    /// The file exists but no companion snapshot does. Drift (Requirement 2.3).
    Missing,
    /// No file, and nothing says there should be one: the integrity record marks it absent, or
    /// the caller has neither a record nor a file nor a snapshot (unprovisioned).
    Absent,
    /// The file is gone but the integrity record names a snapshot of it, or, with no record, a
    /// snapshot of it remains. Drift (Requirement 10.3): deletion does not read as absence.
    /// Revalidation records it as absent (Requirement 4.1).
    Deleted,
    /// The integrity record could not be opened (Requirement 10.6). Not drift: nothing records
    /// what the files should hold, so revalidation here replaces the record rather than repairing
    /// it, and its approval says so.
    Unverifiable,
}

/// What the integrity record says about one load-bearing file (Requirement 10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pin {
    /// The file is meant to be absent.
    Absent,
    /// SHA-256 of the canonical form the file's current snapshot seals.
    Snapshot([u8; 32]),
}

impl DriftStatus {
    /// Nothing to refuse: the file matches its snapshot, or there is no file to serve from.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. } | Self::Absent)
    }

    pub fn cached_hash(&self) -> Option<[u8; 32]> {
        match self {
            Self::Valid { hash } => Some(*hash),
            _ => None,
        }
    }
}

/// Seal `canonical` bytes to the companion snapshot file beside `config_path`.
///
/// Uses `EncryptionService::seal_to_file` for atomic write (tmp + rename) and 0600 mode.
/// Normal writes put the file first and the snapshot second. A credential removal is the
/// exception: it seals the text it is about to write first, so a failed seal leaves the file
/// as checked. A crash between that seal and the rename leaves the snapshot ahead of the file;
/// verification then reads it as drift, failing closed until revalidated.
pub fn seal(enc: &EncryptionService, canonical: &[u8], config_path: &Path) -> Result<()> {
    enc.seal_to_file(&snapshot_path(config_path), canonical)
}

/// Verify the stored snapshot against the current `canonical` form of `config_path`.
///
/// Does NOT perform a hash pre-check — callers that have a cached hash should compare
/// `sha256(canonical) == cached_hash` before calling this to avoid unnecessary decryption.
pub fn verify(enc: &EncryptionService, canonical: &[u8], config_path: &Path) -> DriftStatus {
    let snap = snapshot_path(config_path);
    // `exists()` maps any metadata error to false, which would read an unreadable snapshot as
    // Missing; `try_exists` errors fall through to the open below, which fails closed.
    if !snap.try_exists().unwrap_or(true) {
        return DriftStatus::Missing;
    }
    // The daemon holds the master key in memory, so a snapshot that will not open under it is
    // damaged or was sealed under another key: either way its file is in drift (Requirement 2.4).
    match enc.open_from_file(&snap) {
        Err(_) => DriftStatus::Drifted,
        Ok(stored) => {
            if stored.as_slice() == canonical {
                DriftStatus::Valid {
                    hash: sha256(canonical),
                }
            } else {
                DriftStatus::Drifted
            }
        }
    }
}

/// The drift status of the load-bearing file at `path`, whose current canonical form is
/// `canonical`, against what the integrity record says of it. `pin` is `None` when the caller has
/// no record. The one place that decides what a missing file means, so the load path, the write
/// check, and revalidation cannot disagree about it.
///
/// - Record names a snapshot: a missing file is `Deleted` (Requirement 10.3), and a snapshot that
///   verifies but seals a different canonical form than the record names is `Drifted`
///   (Requirement 10.4) — a restored earlier pair.
/// - Record marks the file absent: absent is `Absent`; a file that has appeared is `Drifted`.
/// - No record: neither file nor snapshot is `Absent` (unprovisioned); a snapshot alone is
///   `Deleted`; a file is in drift even when its snapshot verifies (Requirement 10.5), because
///   nothing says that snapshot is the latest one.
///
/// A file or snapshot whose existence cannot be determined fails closed as `Drifted`.
pub fn assess(
    enc: &EncryptionService,
    canonical: &[u8],
    path: &Path,
    pin: Option<Pin>,
) -> DriftStatus {
    let file = path.try_exists();
    match (pin, file) {
        (_, Err(_)) => DriftStatus::Drifted,
        (Some(Pin::Absent), Ok(false)) => DriftStatus::Absent,
        (Some(Pin::Absent), Ok(true)) => DriftStatus::Drifted,
        (Some(Pin::Snapshot(_)), Ok(false)) => DriftStatus::Deleted,
        (Some(Pin::Snapshot(pinned)), Ok(true)) => match verify(enc, canonical, path) {
            DriftStatus::Valid { hash } if hash == pinned => DriftStatus::Valid { hash },
            DriftStatus::Valid { .. } => DriftStatus::Drifted,
            other => other,
        },
        (None, Ok(false)) => match snapshot_path(path).try_exists() {
            Ok(false) => DriftStatus::Absent,
            Ok(true) => DriftStatus::Deleted,
            Err(_) => DriftStatus::Drifted,
        },
        (None, Ok(true)) => match verify(enc, canonical, path) {
            DriftStatus::Valid { .. } => DriftStatus::Drifted,
            other => other,
        },
    }
}

// ── Canonical form ────────────────────────────────────────────────────────────
//
// Deterministic JSON with BTreeMap ordering. AES-GCM authenticates the payload,
// so the form just needs to be deterministic and injective. JSON struct types give
// injectivity: field names are quoted and typed, so no field value can forge another
// field's structure. HashMaps are converted to BTreeMaps before serialization.
//
// Excluded (not load-bearing): socket_path, log, auth, static_secret.secret_source,
// static_secret.expires_at (user-declared expiry is in credentials.toml but not used
// for routing decisions — the daemon serves the secret, it doesn't gate on expiry here).

use std::collections::BTreeMap;

/// Canonical form of `config.toml` for `uid`. Sealed into `config_snapshot.enc`.
///
/// Covers every field that determines what the daemon serves or whom it serves it to:
/// all environments with their ordered credential lists, identity types, SDK/CLI
/// settings, projections, and region. Excludes socket_path, log, and auth config.
pub fn canonical_config(uid: u32, path: &Path, config: &DaemonConfig) -> Result<Vec<u8>> {
    let envs: BTreeMap<&str, serde_json::Value> = config
        .envs
        .iter()
        .map(|(name, env)| {
            let creds = env.credential_list(name);
            let projections: BTreeMap<&str, String> = env
                .projections
                .iter()
                .map(|(k, v)| (k.as_str(), v.to_string()))
                .collect();
            let v = serde_json::json!({
                "credentials": creds,
                "identity_type": env.identity_type,
                "region": env.region,
                "sdk": env.sdk,
                "cli": env.cli,
                "projections": projections,
            });
            (name.as_str(), v)
        })
        .collect();

    let canonical = serde_json::json!({
        "scheme": "v1",
        "kind": "config",
        "uid": uid,
        "path": path.to_string_lossy().as_ref(),
        "envs": envs,
    });

    serde_json::to_vec(&canonical).map_err(|e| crate::error::DaemonError::config(e.to_string()))
}

/// Canonical form of `credentials.toml` for `uid`. Sealed into `credentials_snapshot.enc`.
///
/// Covers every field of every credential source — provider type, ARNs, endpoints,
/// role names, regions, token URLs, scopes, etc. A change to any provider-specific
/// field changes what credential material is fetched.
pub fn canonical_credentials(
    uid: u32,
    path: &Path,
    sources: &CredentialSources,
) -> Result<Vec<u8>> {
    let creds: BTreeMap<&str, serde_json::Value> = sources
        .iter()
        .map(|(name, source)| {
            let v = serde_json::to_value(source)
                .map_err(|e| crate::error::DaemonError::config(e.to_string()))?;
            Ok::<_, crate::error::DaemonError>((name.as_str(), v))
        })
        .collect::<std::result::Result<_, _>>()?;

    let canonical = serde_json::json!({
        "scheme": "v1",
        "kind": "credentials",
        "uid": uid,
        "path": path.to_string_lossy().as_ref(),
        "credentials": creds,
    });

    serde_json::to_vec(&canonical).map_err(|e| crate::error::DaemonError::config(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{generate_key, EncryptionService};
    use tempfile::tempdir;

    fn make_enc() -> EncryptionService {
        EncryptionService::new(generate_key().unwrap()).unwrap()
    }

    #[test]
    fn snapshot_path_derives_correctly() {
        let config = std::path::Path::new("/tmp/callers/501/config.toml");
        assert_eq!(
            snapshot_path(config),
            std::path::PathBuf::from("/tmp/callers/501/config_snapshot.enc")
        );
        let creds = std::path::Path::new("/tmp/callers/501/credentials.toml");
        assert_eq!(
            snapshot_path(creds),
            std::path::PathBuf::from("/tmp/callers/501/credentials_snapshot.enc")
        );
    }

    #[test]
    fn missing_snapshot_reports_missing() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let enc = make_enc();
        let canonical = b"some canonical bytes";
        assert_eq!(verify(&enc, canonical, &config_path), DriftStatus::Missing);
    }

    #[test]
    fn sealed_and_verified_round_trip() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let enc = make_enc();
        let canonical = b"canonical form v1";

        seal(&enc, canonical, &config_path).unwrap();

        let status = verify(&enc, canonical, &config_path);
        assert!(status.is_valid(), "expected Valid, got {:?}", status);
        assert_eq!(status.cached_hash(), Some(sha256(canonical)));
    }

    #[test]
    fn changed_config_reports_drifted() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let enc = make_enc();

        seal(&enc, b"original canonical", &config_path).unwrap();

        let status = verify(&enc, b"modified canonical", &config_path);
        assert_eq!(status, DriftStatus::Drifted);
    }

    #[test]
    fn a_snapshot_sealed_under_another_key_is_drift() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let enc1 = make_enc();
        let enc2 = make_enc();

        seal(&enc1, b"canonical", &config_path).unwrap();

        let status = verify(&enc2, b"canonical", &config_path);
        assert_eq!(status, DriftStatus::Drifted);
    }

    /// Requirement 2.4: a damaged snapshot puts its file in drift even when the integrity record
    /// names it, which is how a damaged snapshot is told from an unopenable record (2.11).
    #[test]
    fn a_damaged_snapshot_the_record_names_is_drift() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let enc = make_enc();
        seal(&enc, b"canonical", &config_path).unwrap();
        let pin = Some(Pin::Snapshot(sha256(b"canonical")));
        assert!(assess(&enc, b"canonical", &config_path, pin).is_valid());

        std::fs::write(snapshot_path(&config_path), b"{\"truncated").unwrap();
        assert_eq!(
            assess(&enc, b"canonical", &config_path, pin),
            DriftStatus::Drifted
        );
    }

    #[test]
    fn unreadable_snapshot_location_is_not_reported_missing() {
        // A regular file in the parent position makes the snapshot's existence check fail with
        // ENOTDIR, independent of uid, so this holds under root too.
        let dir = tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a dir").unwrap();
        let config_path = blocker.join("config.toml");

        let status = verify(&make_enc(), b"canonical", &config_path);
        assert_eq!(status, DriftStatus::Drifted);
    }

    #[test]
    fn assess_reads_an_unprovisioned_file_as_absent() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let status = assess(&make_enc(), b"empty", &config_path, None);
        assert_eq!(status, DriftStatus::Absent);
        assert!(status.is_valid());
    }

    /// Requirement 10.3: a file the record names is drift when it is missing, whether or not its
    /// snapshot went with it. With no record, a snapshot left behind is the same deletion.
    #[test]
    fn assess_reads_a_deleted_file_as_deleted_not_absent() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let enc = make_enc();
        let pin = Some(Pin::Snapshot(sha256(b"original canonical")));
        assert_eq!(
            assess(&enc, b"empty", &config_path, pin),
            DriftStatus::Deleted
        );

        seal(&enc, b"original canonical", &config_path).unwrap();
        for pin in [pin, None] {
            let status = assess(&enc, b"empty", &config_path, pin);
            assert_eq!(status, DriftStatus::Deleted, "{pin:?}");
            assert!(!status.is_valid());
        }
    }

    #[test]
    fn assess_verifies_a_present_file_against_its_snapshot_and_the_record() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let enc = make_enc();
        let pin = Some(Pin::Snapshot(sha256(b"canonical")));
        assert_eq!(
            assess(&enc, b"canonical", &config_path, pin),
            DriftStatus::Missing
        );

        seal(&enc, b"canonical", &config_path).unwrap();
        assert!(assess(&enc, b"canonical", &config_path, pin).is_valid());
        assert_eq!(
            assess(&enc, b"edited", &config_path, pin),
            DriftStatus::Drifted
        );
    }

    /// Requirement 10.4: an earlier pair restored together verifies on its own, and only the
    /// record tells it from the current one.
    #[test]
    fn assess_reads_a_restored_earlier_pair_as_drifted() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let enc = make_enc();
        seal(&enc, b"earlier", &config_path).unwrap();
        assert!(verify(&enc, b"earlier", &config_path).is_valid());
        assert_eq!(
            assess(
                &enc,
                b"earlier",
                &config_path,
                Some(Pin::Snapshot(sha256(b"current")))
            ),
            DriftStatus::Drifted
        );
    }

    /// A file the record marks absent is absent only while it stays gone: a restored pair is
    /// drift even though its snapshot verifies.
    #[test]
    fn assess_reads_a_file_the_record_marks_absent_as_drift_once_it_appears() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let enc = make_enc();
        assert_eq!(
            assess(&enc, b"canonical", &config_path, Some(Pin::Absent)),
            DriftStatus::Absent
        );
        std::fs::write(&config_path, "").unwrap();
        seal(&enc, b"canonical", &config_path).unwrap();
        assert_eq!(
            assess(&enc, b"canonical", &config_path, Some(Pin::Absent)),
            DriftStatus::Drifted
        );
    }

    /// Requirement 10.5: a root written before the record existed is in drift, even though every
    /// snapshot in it verifies.
    #[test]
    fn assess_reads_a_verified_file_with_no_record_as_drifted() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let enc = make_enc();
        seal(&enc, b"canonical", &config_path).unwrap();
        assert_eq!(
            assess(&enc, b"canonical", &config_path, None),
            DriftStatus::Drifted
        );
        assert_eq!(
            assess(&make_enc(), b"canonical", &config_path, None),
            DriftStatus::Drifted
        );
    }

    #[test]
    fn sha256_is_deterministic() {
        let h1 = sha256(b"hello");
        let h2 = sha256(b"hello");
        assert_eq!(h1, h2);
        assert_ne!(sha256(b"hello"), sha256(b"world"));
    }
}
