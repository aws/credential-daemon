//! The per-caller integrity record (`drift-detection` Requirement 10; design Decisions 10-12).
//!
//! A snapshot sits in the caller root beside its file, so a same-uid process that can delete or
//! restore the file can delete or restore the snapshot with it. The record names each
//! load-bearing file's current snapshot by the SHA-256 of the canonical form it seals, or marks
//! the file absent, and is held where no caller uid can write: a keychain item under
//! `data-protection-keychain`, otherwise a sealed file beside `callers/` owned by the service
//! account. The record carries no counter; custody is what keeps an earlier copy from being put
//! back, so custody is checked before every read rather than assumed from install.
//!
//! Every write to a load-bearing file passes through [`verify_for_write`], and every renewal that
//! seals material one names through [`verify_for_renewal`], under the caller's write lock; both
//! are the one shared check (Requirement 5.8). The check is enforced by type, not convention: it
//! demands a [`Held`] proof of the lock and yields the [`Verified`] token that every daemon-side
//! snapshot seal and record write requires.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use credsd_core::config::snapshot::{self, DriftStatus, Pin};
use credsd_core::config::{credentials, DaemonConfig};
use credsd_core::encryption::EncryptionService;
use credsd_core::rpc::{DomainCode, RpcError};
use serde::{Deserialize, Serialize};

use crate::server::bootstrap::TomlFiles;
use crate::server::dispatch::{checked_text, internal, records_unchanged, Daemon};
use crate::server::revalidate::{CONFIG, CREDENTIALS};
use crate::server::write_lock::Held;

/// The `SecureStorage` slot prefix for a sealed record under `data-protection-keychain`. One slot
/// holds one caller root's record: [`record_slot`] keys it by the home's instance namespace and
/// the caller's uid, so no other home or uid reads it as its own.
pub const RECORD_SLOT: &str = "integrity-record";

/// The slot holding `uid`'s record in the home whose instance namespace is `ns`
/// (`storage-backend-per-home` Requirements 5.1-5.3). A keychain item is named by nothing but
/// this string, so what the name does not distinguish, the backend does not either.
fn record_slot(ns: &str, uid: u32) -> String {
    format!("{RECORD_SLOT}.{ns}.{uid}")
}

const SCHEME: &str = "v1";

/// What the record says about both load-bearing files of one caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub config: Pin,
    pub credentials: Pin,
}

impl Record {
    /// The record of a caller root that holds neither file: the base a first write builds on.
    pub const UNPROVISIONED: Self = Self {
        config: Pin::Absent,
        credentials: Pin::Absent,
    };

    pub fn get(&self, name: &str) -> Pin {
        if name == CONFIG {
            self.config
        } else {
            self.credentials
        }
    }

    pub fn set(&mut self, name: &str, pin: Pin) {
        if name == CONFIG {
            self.config = pin;
        } else {
            self.credentials = pin;
        }
    }

    /// Pin `canonical` as the form `name`'s current snapshot seals.
    pub fn pin_sealed(&mut self, name: &str, canonical: &[u8]) {
        self.set(name, Pin::Snapshot(snapshot::sha256(canonical)));
    }

    fn encode(&self, uid: u32) -> Result<Vec<u8>, RpcError> {
        let entry = |pin: Pin| match pin {
            Pin::Absent => WireEntry {
                snapshot_sha256: None,
                absent: true,
            },
            Pin::Snapshot(hash) => WireEntry {
                snapshot_sha256: Some(credsd_core::presence::hex(&hash)),
                absent: false,
            },
        };
        let wire = Wire {
            scheme: SCHEME.to_owned(),
            uid,
            files: [
                (CONFIG.to_owned(), entry(self.config)),
                (CREDENTIALS.to_owned(), entry(self.credentials)),
            ]
            .into_iter()
            .collect(),
        };
        serde_json::to_vec(&wire).map_err(|e| internal(e.to_string()))
    }

    /// Anything but exactly the shape [`encode`](Self::encode) writes, for this uid, is refused:
    /// a record that says less than it should cannot be completed from the files on disk.
    fn decode(uid: u32, plaintext: &[u8]) -> Result<Self, String> {
        let wire: Wire = serde_json::from_slice(plaintext).map_err(|e| e.to_string())?;
        if wire.scheme != SCHEME {
            return Err(format!("unknown record scheme '{}'", wire.scheme));
        }
        if wire.uid != uid {
            return Err(format!("the record held is for uid {}", wire.uid));
        }
        if wire.files.len() != 2 {
            return Err("the record does not name exactly the two load-bearing files".to_owned());
        }
        let pin = |name: &str| match wire.files.get(name) {
            Some(WireEntry {
                snapshot_sha256: Some(hex),
                absent: false,
            }) => credsd_core::presence::unhex(hex)
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .map(Pin::Snapshot)
                .ok_or_else(|| format!("{name}: snapshot_sha256 is not a SHA-256")),
            Some(WireEntry {
                snapshot_sha256: None,
                absent: true,
            }) => Ok(Pin::Absent),
            _ => Err(format!("{name}: entry is missing or malformed")),
        };
        Ok(Self {
            config: pin(CONFIG)?,
            credentials: pin(CREDENTIALS)?,
        })
    }
}

/// The record's plaintext before sealing (design.md, Data shapes).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    scheme: String,
    uid: u32,
    files: std::collections::BTreeMap<String, WireEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    absent: bool,
}

/// Where the records are held, chosen from the storage backend exactly as the enrolled-key
/// registry's custody is (`presence-gated-operations` Decision 8).
pub enum IntegrityCustody {
    /// A directory of `<uid>.enc` files.
    File(PathBuf),
    /// One slot per caller root, named by [`record_slot`] from `home`'s instance namespace.
    Slot {
        store: Box<dyn credsd_core::storage::SecureStorage>,
        ns: String,
    },
}

impl IntegrityCustody {
    /// `<data_dir>/integrity/`, beside `callers/` and never inside a caller root.
    pub fn beside(callers_root: &Path) -> Self {
        Self::File(
            callers_root
                .parent()
                .unwrap_or(callers_root)
                .join("integrity"),
        )
    }

    /// Slots in `store`, scoped to the home at `home`. The file custody dies with the home it
    /// sits in; a slot outlives it, so the home is what the slot's name carries.
    pub fn slot(store: Box<dyn credsd_core::storage::SecureStorage>, home: &Path) -> Self {
        Self::Slot {
            store,
            ns: credsd_core::storage::instance_namespace(home),
        }
    }
}

/// The paths whose custody holds the record and the enrolled-key registry when they are files
/// (Requirement 10.8): each directory, every ancestor of it up to and including the data dir, and
/// every entry inside each directory. A directory that does not exist yet passes — there is no
/// earlier copy in it to restore, and creating it needs write access to an ancestor, which is
/// itself checked.
pub struct CustodyCheck {
    data_dir: PathBuf,
    dirs: Vec<PathBuf>,
}

impl CustodyCheck {
    pub fn new(data_dir: PathBuf, dirs: Vec<PathBuf>) -> Self {
        Self { data_dir, dirs }
    }

    /// `Err` names the first path that failed and why. Nothing is repaired: a repair would bless
    /// whatever a caller placed there while custody was broken (design Decision 12).
    pub fn verify(&self) -> Result<(), String> {
        let mut paths: Vec<&Path> = Vec::new();
        for dir in &self.dirs {
            let mut at = dir.as_path();
            loop {
                if !paths.contains(&at) {
                    paths.push(at);
                }
                match at.parent() {
                    Some(parent) if at != self.data_dir && parent.starts_with(&self.data_dir) => {
                        at = parent;
                    }
                    _ => break,
                }
            }
        }
        for path in paths {
            custodied(path)?;
        }
        for dir in &self.dirs {
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{}: {e}", dir.display())),
            };
            for entry in entries {
                let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
                custodied(&entry.path())?;
            }
        }
        Ok(())
    }
}

/// One path: not a symlink, owned by the service account (this process's effective uid) or root,
/// and not writable by group or other. Absence passes; any other stat failure does not.
#[cfg(unix)]
fn custodied(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if meta.file_type().is_symlink() {
        return Err(format!("{} is a symlink", path.display()));
    }
    let service = nix::unistd::geteuid().as_raw();
    if meta.uid() != 0 && meta.uid() != service {
        return Err(format!(
            "{} is owned by uid {}, not the service account (uid {service}) or root",
            path.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is writable by group or other (mode {:o})",
            path.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

/// No custody check exists here, so custody cannot be shown to hold: refuse.
#[cfg(not(unix))]
fn custodied(path: &Path) -> Result<(), String> {
    Err(format!(
        "{}: custody verification is not implemented on this platform",
        path.display()
    ))
}

/// Why a caller's record could not be relied on. The two have different remedies, so they stay
/// apart all the way to the wire (Requirement 11.2).
#[derive(Debug)]
pub enum Unverifiable {
    /// Custody is broken (Requirements 10.8-10.10): an operator restores it and restarts.
    Custody(String),
    /// The record is held but will not open or decode (Requirement 10.6): revalidation replaces it
    /// under an approval that discloses there is nothing to compare the files against.
    Unopenable(String),
}

impl Unverifiable {
    pub fn refusal(self) -> RpcError {
        match self {
            Self::Custody(reason) => custody_broken(&reason),
            Self::Unopenable(reason) => unverifiable(&reason),
        }
    }
}

pub struct Integrity {
    custody: IntegrityCustody,
    /// `Some` wherever the record is a custodied file. A keychain item's custody is its access
    /// group, which no mode bit expresses.
    check: Option<CustodyCheck>,
    /// The first custody breach observed, held until the process exits (Requirement 10.10).
    breach: std::sync::OnceLock<String>,
    encryption: Arc<EncryptionService>,
}

impl Integrity {
    pub fn new(
        custody: IntegrityCustody,
        check: Option<CustodyCheck>,
        encryption: Arc<EncryptionService>,
    ) -> Self {
        Self {
            custody,
            check,
            breach: std::sync::OnceLock::new(),
            encryption,
        }
    }

    /// Requirement 10.8, logged with the failing path. Run before each read of a record, before
    /// each write, and at startup. A breach latches (Requirement 10.10): once seen, it is reported
    /// for the life of the process even after ownership and modes are restored, since an earlier
    /// record or registry could have been put back while custody was broken.
    pub fn verify_custody(&self) -> Result<(), String> {
        if let Some(reason) = self.breach.get() {
            return Err(reason.clone());
        }
        let Some(check) = &self.check else {
            return Ok(());
        };
        check.verify().map_err(|reason| {
            tracing::error!(
                event = "integrity.custody_failed",
                reason = reason.as_str(),
                "custody of the integrity record or enrolled-key registry is broken; serving \
                 nothing they govern, and repairing nothing, until the daemon restarts"
            );
            self.breach.get_or_init(|| reason).clone()
        })
    }

    /// `uid`'s record, or `None` when it has none. An error is never read as "none": that would
    /// let a record that will not open be replaced by one built from the files on disk.
    pub fn read(&self, uid: u32) -> Result<Option<Record>, Unverifiable> {
        self.verify_custody().map_err(Unverifiable::Custody)?;
        let opened = match &self.custody {
            IntegrityCustody::File(dir) => match self.encryption.open_from_file(&file_of(dir, uid))
            {
                Ok(plain) => Ok(plain),
                Err(credsd_core::error::DaemonError::Io(e))
                    if e.kind() == std::io::ErrorKind::NotFound =>
                {
                    return Ok(None)
                }
                Err(e) => Err(e.detail()),
            },
            IntegrityCustody::Slot { store, ns } => {
                let slot = record_slot(ns, uid);
                match store.exists(&slot) {
                    Ok(false) => return Ok(None),
                    Ok(true) => store
                        .retrieve(&slot)
                        .and_then(|sealed| self.encryption.open(&sealed))
                        .map_err(|e| e.detail()),
                    Err(e) => Err(e.detail()),
                }
            }
        };
        opened
            .and_then(|plain| Record::decode(uid, &plain))
            .map(Some)
            .map_err(|reason| {
                tracing::error!(
                    event = "integrity.unreadable",
                    uid,
                    reason = reason.as_str(),
                    "integrity record did not open; serving nothing it governs and leaving it in \
                     place"
                );
                Unverifiable::Unopenable(reason)
            })
    }

    /// Replace the verified caller's record with the one `verified` carries. Called after the
    /// snapshots it names are sealed (Requirement 5.6); a failure fails the operation (Requirement
    /// 5.7). Consumes the token: each record write follows its own check.
    pub fn write(&self, verified: Verified) -> Result<(), RpcError> {
        let Verified { uid, record } = verified;
        self.verify_custody()
            .map_err(|reason| custody_broken(&reason))?;
        let plain = record.encode(uid)?;
        match &self.custody {
            IntegrityCustody::File(dir) => self.encryption.seal_to_file(&file_of(dir, uid), &plain),
            IntegrityCustody::Slot { store, ns } => self
                .encryption
                .seal(&plain)
                .and_then(|sealed| store.store(&record_slot(ns, uid), &sealed)),
        }
        .map_err(|e| {
            internal(format!(
                "the integrity record could not be updated: {}",
                e.detail()
            ))
        })
    }
}

fn file_of(dir: &Path, uid: u32) -> PathBuf {
    dir.join(format!("{uid}.enc"))
}

/// The refusal for a caller whose record will not open (Requirement 10.6). The record is not
/// rebuilt silently; revalidation replaces it, under an approval that shows both files in full and
/// says there is no record to compare them against.
pub fn unverifiable(reason: &str) -> RpcError {
    RpcError::domain(
        DomainCode::IntegrityUnverifiable,
        format!(
            "the integrity record for this user cannot be opened ({reason}), so config cannot be \
             verified. Review config.toml and credentials.toml, then run: creds revalidate. \
             Approval replaces the record and trusts the files as they are"
        ),
    )
}

/// The refusal while custody is broken (Requirements 10.8-10.10). No client action remedies it.
pub fn custody_broken(reason: &str) -> RpcError {
    RpcError::domain(
        DomainCode::CustodyBroken,
        format!(
            "custody of the integrity record or enrolled-key registry is broken ({reason}); \
             nothing they govern is served, written, or approved. An operator must restore \
             ownership and modes, inspect the record and registry, and restart the daemon"
        ),
    )
}

/// The canonical form `name`'s snapshot seals, from the file's text. Parse failures and
/// serialization failures both mean there is no form a snapshot could match.
pub(crate) fn canonical_of(
    uid: u32,
    name: &str,
    text: &str,
) -> credsd_core::error::Result<Vec<u8>> {
    let rel = Path::new("callers").join(uid.to_string()).join(name);
    if name == CONFIG {
        let config = DaemonConfig::from_text(text)
            .map_err(|e| credsd_core::error::DaemonError::config(e.to_string()))?;
        snapshot::canonical_config(uid, &rel, &config)
    } else {
        snapshot::canonical_credentials(uid, &rel, &credentials::from_text(text)?)
    }
}

/// Which load-bearing files a write targets (Requirement 5.2: its target file must not be in
/// drift).
pub(crate) const BOTH: &[&str] = &[CONFIG, CREDENTIALS];

/// Proof that the shared check (Requirement 5.8) passed for one caller under its write lock,
/// carrying the record the operation updates once it has sealed. Only this module makes one, and
/// only from a check given a [`Held`] for the same uid.
#[must_use = "a Verified is the only way to seal a snapshot or write the integrity record"]
pub(crate) struct Verified {
    uid: u32,
    record: Record,
}

impl Verified {
    fn new(held: &Held<'_>, uid: u32, record: Record) -> Result<Self, RpcError> {
        if held.uid() != uid {
            return Err(internal(format!(
                "the write lock held is uid {}'s, not uid {uid}'s",
                held.uid()
            )));
        }
        Ok(Self { uid, record })
    }

    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    /// Pin `canonical` as the form `name`'s current snapshot seals.
    pub(crate) fn pin_sealed(&mut self, name: &str, canonical: &[u8]) {
        self.record.pin_sealed(name, canonical);
    }

    pub(crate) fn set(&mut self, name: &str, pin: Pin) {
        self.record.set(name, pin);
    }

    /// Seal `canonical` as the snapshot of the verified caller's load-bearing file `name`.
    pub(crate) fn seal_snapshot(
        &self,
        encryption: &EncryptionService,
        name: &str,
        canonical: &[u8],
    ) -> credsd_core::error::Result<()> {
        let path = credsd_core::config::platform::caller_root(self.uid).join(name);
        #[allow(
            clippy::disallowed_methods,
            reason = "the one sanctioned daemon-side call: everything else seals through this \
                      method, so a seal cannot happen without the check that produced `self`"
        )]
        snapshot::seal(encryption, canonical, &path)
    }

    #[cfg(test)]
    pub(crate) fn for_test(uid: u32, record: Record) -> Self {
        Self { uid, record }
    }
}

/// The one drift check every write runs (Requirement 5.8), from `files` — the bytes the write
/// will edit, read under the caller's write lock, which `held` proves — immediately before the
/// write. Returns the token the write's seals and record update require.
///
/// Refuses when the record cannot be relied on (10.6, 10.8), when any of `targets` is in drift
/// (5.2), including a file the record names that has gone (10.3) and a restored earlier pair
/// (10.4), and, with no record at all, when the root holds anything (10.5). An unprovisioned root
/// still passes this check; its token carries [`Record::UNPROVISIONED`].
pub(crate) fn verify_for_write(
    daemon: &Daemon,
    held: &Held<'_>,
    uid: u32,
    files: &TomlFiles,
    targets: &[&str],
) -> Result<Verified, RpcError> {
    let record = verify_records(&daemon.integrity, &daemon.encryption, uid, files, targets)?;
    Verified::new(held, uid, record)
}

/// The same check as [`verify_for_write`], run before the lock is taken so a request is refused
/// before a provider flow or a challenge it could only end in refusal. Advisory: it yields no
/// token, so nothing can be sealed on it.
pub(crate) fn precheck_for_write(
    daemon: &Daemon,
    uid: u32,
    files: &TomlFiles,
    targets: &[&str],
) -> Result<(), RpcError> {
    verify_records(&daemon.integrity, &daemon.encryption, uid, files, targets).map(drop)
}

/// [`verify_for_write`] for a credential renewal, which edits neither file but seals material both
/// name (Requirement 5.8). It reads the files itself, under the lock `held` proves. A state that
/// loaded verified may have drifted since, and a renewal is not a request that would reload it.
pub(crate) fn verify_for_renewal(
    integrity: &Integrity,
    encryption: &EncryptionService,
    held: &Held<'_>,
    uid: u32,
) -> Result<Verified, RpcError> {
    let files = TomlFiles::read(uid).map_err(|e| internal(e.to_string()))?;
    let record = verify_records(integrity, encryption, uid, &files, BOTH)?;
    Verified::new(held, uid, record)
}

/// Revalidation's form of the shared check (Requirement 4.10): the files still hold the bytes the
/// approval showed, and the record is still in the state the approval was shown. It does not
/// refuse over drift, since ratifying drift is what revalidation is for.
///
/// `replaces_record` is whether the approval was raised over a record that would not open
/// (Requirement 10.6). Such an approval builds the record afresh, and only while the record still
/// will not open; one raised over a readable record never replaces an unopenable one.
pub(crate) fn verify_for_revalidation(
    daemon: &Daemon,
    held: &Held<'_>,
    uid: u32,
    checked: &TomlFiles,
    replaces_record: bool,
) -> Result<Verified, RpcError> {
    records_unchanged(uid, checked)?;
    let record = match (daemon.integrity.read(uid), replaces_record) {
        (Ok(record), false) => record.unwrap_or(Record::UNPROVISIONED),
        (Err(Unverifiable::Unopenable(_)), true) => Record::UNPROVISIONED,
        (Ok(_), true) => {
            daemon.evict_caller(uid);
            return Err(RpcError::invalid_params(
                "the integrity record opens now, so this approval no longer describes the state \
                 it would apply to. Run: creds revalidate again",
            ));
        }
        (Err(e), _) => return Err(e.refusal()),
    };
    Verified::new(held, uid, record)
}

fn verify_records(
    integrity: &Integrity,
    encryption: &EncryptionService,
    uid: u32,
    files: &TomlFiles,
    targets: &[&str],
) -> Result<Record, RpcError> {
    let record = integrity.read(uid).map_err(Unverifiable::refusal)?;
    let checked: &[&str] = if record.is_some() { targets } else { BOTH };
    for &name in checked {
        let bytes = if name == CONFIG {
            &files.config
        } else {
            &files.credentials
        };
        let canonical = canonical_of(uid, name, checked_text(bytes)?).map_err(|e| {
            RpcError::domain(
                DomainCode::ConfigDrifted,
                format!(
                    "{name} does not parse, so it has been changed outside the daemon; nothing is \
                     written over it. Correct or restore it, then run: creds revalidate ({})",
                    e.detail()
                ),
            )
        })?;
        let status = snapshot::assess(
            encryption,
            &canonical,
            &credsd_core::config::platform::caller_root(uid).join(name),
            record.map(|r| r.get(name)),
        );
        if !status.is_valid() {
            return Err(write_refusal(name, &status));
        }
    }
    Ok(record.unwrap_or(Record::UNPROVISIONED))
}

/// A write refused over `name`'s drift status.
fn write_refusal(name: &str, status: &DriftStatus) -> RpcError {
    let message = match status {
        DriftStatus::Deleted => format!(
            "{name} has been deleted outside the daemon while its sealed snapshot is still on \
             record; nothing is written over a deletion. Run: creds revalidate to record it as \
             absent"
        ),
        DriftStatus::Unverifiable => return unverifiable("see the daemon log"),
        _ => format!(
            "{name} does not match its sealed snapshot, or that snapshot is not the one the \
             integrity record names; nothing is written over drift. Review it, then run: creds \
             revalidate"
        ),
    };
    RpcError::domain(DomainCode::ConfigDrifted, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Slots(Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>);

    impl credsd_core::storage::SecureStorage for Slots {
        fn store(&self, key_id: &str, data: &[u8]) -> credsd_core::error::Result<()> {
            crate::server::lock(&self.0).insert(key_id.to_owned(), data.to_vec());
            Ok(())
        }
        fn retrieve(&self, key_id: &str) -> credsd_core::error::Result<Vec<u8>> {
            crate::server::lock(&self.0)
                .get(key_id)
                .cloned()
                .ok_or_else(|| credsd_core::error::DaemonError::config("absent"))
        }
        fn delete(&self, key_id: &str) -> credsd_core::error::Result<()> {
            crate::server::lock(&self.0).remove(key_id);
            Ok(())
        }
        fn exists(&self, key_id: &str) -> credsd_core::error::Result<bool> {
            Ok(crate::server::lock(&self.0).contains_key(key_id))
        }
        fn backend_name(&self) -> &'static str {
            "test"
        }
    }

    fn encryption() -> Arc<EncryptionService> {
        use credsd_core::encryption::{generate_key, EncryptionService};
        Arc::new(EncryptionService::new(generate_key().expect("key")).expect("encryption"))
    }

    #[test]
    fn a_record_round_trips_and_names_each_file_by_snapshot_or_absence() {
        let record = Record {
            config: Pin::Snapshot([7; 32]),
            credentials: Pin::Absent,
        };
        let plain = record.encode(501).expect("encode");
        let value: serde_json::Value = serde_json::from_slice(&plain).expect("json");
        assert_eq!(value["scheme"], "v1");
        assert_eq!(value["uid"], 501);
        assert_eq!(
            value["files"]["config.toml"]["snapshot_sha256"],
            credsd_core::presence::hex(&[7; 32])
        );
        assert_eq!(value["files"]["credentials.toml"]["absent"], true);
        assert_eq!(Record::decode(501, &plain).expect("decode"), record);
    }

    /// A record that says less than it should is refused, not completed: completing it from the
    /// files on disk would ratify whatever they hold (Requirement 10.6).
    #[test]
    fn a_record_for_another_uid_or_of_another_shape_does_not_decode() {
        let plain = Record::UNPROVISIONED.encode(501).expect("encode");
        assert!(Record::decode(502, &plain).is_err());
        for bad in [
            r#"{"scheme":"v2","uid":501,"files":{"config.toml":{"absent":true},"credentials.toml":{"absent":true}}}"#,
            r#"{"scheme":"v1","uid":501,"files":{"config.toml":{"absent":true}}}"#,
            r#"{"scheme":"v1","uid":501,"files":{"config.toml":{"absent":false},"credentials.toml":{"absent":true}}}"#,
            r#"{"scheme":"v1","uid":501,"files":{"config.toml":{"absent":true,"snapshot_sha256":"00"},"credentials.toml":{"absent":true}}}"#,
            r#"{"scheme":"v1","uid":501,"files":{"config.toml":{"snapshot_sha256":"00"},"credentials.toml":{"absent":true}}}"#,
            r#"{"scheme":"v1","uid":501,"files":{"config.toml":{"absent":true},"credentials.toml":{"absent":true}},"extra":1}"#,
        ] {
            assert!(Record::decode(501, bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_file_custody_sits_beside_callers_never_inside_a_caller_root() {
        let IntegrityCustody::File(dir) = IntegrityCustody::beside(Path::new("/data/callers"))
        else {
            panic!("file custody");
        };
        assert_eq!(dir, Path::new("/data/integrity"));
    }

    #[test]
    fn a_slot_custody_holds_one_record_per_caller_and_refuses_another_uids_bytes() {
        use credsd_core::storage::SecureStorage;
        let slots = Slots::default();
        let home = Path::new("/data/home-a");
        let ns = credsd_core::storage::instance_namespace(home);
        let integrity = Integrity::new(
            IntegrityCustody::slot(Box::new(slots.clone()), home),
            None,
            encryption(),
        );
        assert!(integrity.read(501).expect("read").is_none());
        let record = Record {
            config: Pin::Snapshot([1; 32]),
            credentials: Pin::Absent,
        };
        integrity
            .write(Verified::for_test(501, record))
            .expect("write");
        assert_eq!(integrity.read(501).expect("read"), Some(record));
        assert!(
            integrity.read(502).expect("read").is_none(),
            "each caller has its own slot, so another uid is unprovisioned rather than wedged"
        );

        let sealed = slots.retrieve(&record_slot(&ns, 501)).expect("sealed");
        slots
            .store(&record_slot(&ns, 502), &sealed)
            .expect("forge 502's slot from 501's record");
        assert!(
            integrity.read(502).is_err(),
            "the uid the record names is checked against the slot it was found in"
        );
    }

    /// `storage-backend-per-home` Requirements 5.1-5.3. Two homes share the keychain and the
    /// master key, so the slot's name is the only thing keeping their records apart: a home that
    /// holds neither load-bearing file must read as unprovisioned (Requirement 10.5) rather than
    /// inherit a record describing files that were never in it.
    #[test]
    fn a_record_is_not_read_by_another_home_on_the_same_machine() {
        let slots = Slots::default();
        let encryption = encryption();
        let home_of = |path: &str| {
            Integrity::new(
                IntegrityCustody::slot(Box::new(slots.clone()), Path::new(path)),
                None,
                encryption.clone(),
            )
        };
        let record = Record {
            config: Pin::Snapshot([3; 32]),
            credentials: Pin::Absent,
        };
        home_of("/data/home-a")
            .write(Verified::for_test(501, record))
            .expect("write");
        assert_eq!(
            home_of("/data/home-a").read(501).expect("read"),
            Some(record),
            "a home reads back its own record"
        );
        assert_eq!(
            home_of("/data/home-b").read(501).expect("read"),
            None,
            "a second home is unprovisioned, not in drift over the first home's record"
        );
    }

    /// A file custody: a record sealed for one uid's path does not open as another's, and a
    /// record that will not open is an error, never "no record".
    #[test]
    fn a_file_record_that_will_not_open_is_unverifiable_not_absent() {
        let _lock = crate::server::e2e::DATA_DIR_ENV_LOCK.blocking_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = crate::server::e2e::EnvVarGuard::set("CREDSD_DATA_DIR", dir.path());
        let integrity_dir = dir.path().join("integrity");
        let integrity = Integrity::new(
            IntegrityCustody::File(integrity_dir.clone()),
            None,
            encryption(),
        );
        integrity
            .write(Verified::for_test(501, Record::UNPROVISIONED))
            .expect("write");
        std::fs::copy(integrity_dir.join("501.enc"), integrity_dir.join("502.enc")).expect("copy");
        assert!(integrity.read(501).expect("read").is_some());
        assert!(integrity.read(502).is_err(), "path binding refuses a copy");
        std::fs::write(integrity_dir.join("501.enc"), b"{}").expect("corrupt");
        let err = integrity
            .read(501)
            .expect_err("a corrupt record does not read");
        assert!(matches!(err, Unverifiable::Unopenable(_)), "{err:?}");
        assert_eq!(
            err.refusal().domain_code(),
            Some(DomainCode::IntegrityUnverifiable),
            "an unopenable record is not reported as drift (Requirement 11.2)"
        );
    }

    /// Requirement 10.10: once custody is seen broken, restoring the modes does not lift the
    /// refusal; only a new process does.
    #[cfg(unix)]
    #[test]
    fn a_custody_breach_latches_until_restart() {
        use std::os::unix::fs::PermissionsExt;
        let data = tempfile::tempdir().expect("tempdir");
        let data_dir = data.path().to_path_buf();
        let dir = data_dir.join("integrity");
        std::fs::create_dir(&dir).expect("create");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let integrity = || {
            Integrity::new(
                IntegrityCustody::File(dir.clone()),
                Some(CustodyCheck::new(data_dir.clone(), vec![dir.clone()])),
                encryption(),
            )
        };
        let running = integrity();
        running.verify_custody().expect("intact custody passes");

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).expect("chmod");
        running.verify_custody().expect_err("a breach refuses");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let err = running
            .verify_custody()
            .expect_err("the breach holds after the mode is restored");
        assert!(err.contains("writable by group or other"), "{err}");
        assert!(matches!(running.read(501), Err(Unverifiable::Custody(_))));
        assert_eq!(
            running
                .write(Verified::for_test(501, Record::UNPROVISIONED))
                .expect_err("no write while latched")
                .domain_code(),
            Some(DomainCode::CustodyBroken)
        );

        integrity()
            .verify_custody()
            .expect("a restarted daemon sees custody restored");
    }

    /// The Testing section of design.md: for each path Requirement 10.8 names, a group-writable
    /// directory, a symlinked directory, and (where the suite can produce one) a foreign-owned
    /// file each refuse, and nothing in that path is changed afterwards.
    #[cfg(unix)]
    #[test]
    fn a_broken_custody_refuses_and_is_left_as_found() {
        use std::os::unix::fs::PermissionsExt;
        for which in ["integrity", "presence"] {
            let data = tempfile::tempdir().expect("tempdir");
            let data_dir = data.path().to_path_buf();
            let dirs = vec![data_dir.join("integrity"), data_dir.join("presence")];
            for dir in &dirs {
                std::fs::create_dir(dir).expect("create");
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
                std::fs::write(dir.join("held.enc"), b"sealed").expect("write");
                std::fs::set_permissions(
                    dir.join("held.enc"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .expect("chmod");
            }
            let check = CustodyCheck::new(data_dir.clone(), dirs);
            check.verify().expect("intact custody passes");
            let target = data_dir.join(which);

            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o770))
                .expect("chmod");
            let err = check
                .verify()
                .expect_err("a group-writable directory refuses");
            assert!(err.contains("writable by group or other"), "{err}");
            let mode = std::fs::metadata(&target)
                .expect("stat")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o770, "{which}: the mode is not repaired");
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
                .expect("chmod");

            std::fs::set_permissions(
                target.join("held.enc"),
                std::fs::Permissions::from_mode(0o602),
            )
            .expect("chmod");
            let err = check.verify().expect_err("an other-writable file refuses");
            assert!(err.contains("held.enc"), "{err}");
            std::fs::set_permissions(
                target.join("held.enc"),
                std::fs::Permissions::from_mode(0o600),
            )
            .expect("chmod");

            let real = data_dir.join(format!("{which}.real"));
            std::fs::rename(&target, &real).expect("move aside");
            std::os::unix::fs::symlink(&real, &target).expect("symlink");
            let err = check.verify().expect_err("a symlinked directory refuses");
            assert!(err.contains("is a symlink"), "{err}");
            assert!(
                std::fs::symlink_metadata(&target)
                    .expect("lstat")
                    .file_type()
                    .is_symlink(),
                "{which}: the symlink is left in place"
            );
            std::fs::remove_file(&target).expect("unlink");
            std::fs::rename(&real, &target).expect("restore");

            // A foreign owner needs a chown, which only root can make; as root, hand the file to
            // an unprivileged uid. Unprivileged, the case cannot be produced and is skipped.
            if nix::unistd::geteuid().is_root() {
                let file = target.join("held.enc");
                std::os::unix::fs::chown(&file, Some(65534), None).expect("chown");
                let err = check.verify().expect_err("a foreign-owned file refuses");
                assert!(err.contains("owned by uid 65534"), "{err}");
                use std::os::unix::fs::MetadataExt;
                assert_eq!(std::fs::metadata(&file).expect("stat").uid(), 65534);
            }
        }
    }

    /// A data dir that is itself group-writable fails the ancestor check for both directories.
    #[cfg(unix)]
    #[test]
    fn a_group_writable_data_dir_refuses() {
        use std::os::unix::fs::PermissionsExt;
        let data = tempfile::tempdir().expect("tempdir");
        let check = CustodyCheck::new(
            data.path().to_path_buf(),
            vec![data.path().join("integrity")],
        );
        check.verify().expect("absent directories pass");
        std::fs::set_permissions(data.path(), std::fs::Permissions::from_mode(0o775))
            .expect("chmod");
        assert!(check.verify().is_err());
    }
}
