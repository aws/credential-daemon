//! Presence gate (`presence-gated-operations`).
//!
//! A gated operation becomes a [`Pending`] held in memory (design Decision 3) and the client
//! receives a [`Challenge`]. A challenge is satisfied by a presence signature over its digest,
//! from a key enrolled for the operation's owner, or by a connection whose kernel-reported uid is
//! 0. The operation is then performed from the pending record, never from re-sent arguments.
//! Which operations are gated is the built-in list of Requirement 1.7, fixed here.
//!
//! Enrolled public keys persist in the enrolled-key registry, sealed under the master key, in
//! daemon-owned storage outside every caller root (`presence-gated-operations` Requirements 5.4,
//! 5.10, 5.11; design Decision 8).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use credsd_core::encryption::EncryptionService;
use credsd_core::log::{escape_log, EscapeLog};
use credsd_core::presence::{
    self, Accepts, ApproveParams, Challenge, EnrollResult, PendingSummary, RefusalReason,
    StatusResult,
};
use credsd_core::rpc::RpcError;
use serde::{Deserialize, Serialize};

use crate::server::routes::PeerInfo;

const TTL: Duration = Duration::from_secs(15 * 60);

/// How long an approved bootstrap waits to be re-sent. Short, because it authorizes an
/// overwrite of sealed material and nothing about it is visible once granted.
const AUTHORIZATION_TTL: Duration = Duration::from_secs(5 * 60);

pub enum Op {
    ConfigSet {
        environment: String,
        key: String,
        value: String,
        /// SHA-256 of `config.toml` when the request was raised (Requirement 2.2 base state).
        base: [u8; 32],
    },
    Enroll {
        public_key: Vec<u8>,
    },
    /// A bootstrap that would overwrite an existing credential or repoint an existing
    /// environment. Approval performs nothing: it grants a one-use authorization the client
    /// spends by re-sending the identical bootstrap, because an interactive provider flow cannot
    /// be replayed from a pending record and the secrets it carries must not wait in one.
    Bootstrap {
        environment: String,
        credential: String,
        /// SHA-256 of the re-serialized bootstrap params. The params themselves, which carry the
        /// secret, are never held.
        params: [u8; 32],
        /// SHA-256 of every subject record the bootstrap would replace.
        base: [u8; 32],
    },
    /// Remove one key from an environment. Performed on approval.
    ConfigUnset {
        environment: String,
        key: String,
        base: [u8; 32],
    },
    /// An import batch that would bind into existing environments or replace sealed material
    /// left on disk. Like [`Op::Bootstrap`], approval grants a re-send of these exact params,
    /// because the batch carries long-term keys that must not wait in a pending record.
    Import {
        /// The profiles that would overwrite, which the challenge names and the base covers.
        environments: Vec<String>,
        params: [u8; 32],
        base: [u8; 32],
    },
    /// Delete a credential's source entry and its sealed material. Performed on approval.
    RemoveCredential {
        credential: String,
        base: [u8; 32],
    },
    /// Delete an environment. Its credentials are left in place. Performed on approval.
    RemoveEnvironment {
        environment: String,
        base: [u8; 32],
    },
    /// Reseal the snapshots of the caller root's drifted load-bearing files. Performed on
    /// approval. `files` is the set the challenge showed as drifted: a file it named as unchanged
    /// is never resealed, even if its snapshot went missing after the challenge was raised.
    /// `deleted` is the set it showed as deleted, which approval records as absent.
    /// `replaces_record` is set when the challenge was raised over an integrity record that would
    /// not open, and said so; approval then builds the record afresh (drift-detection 10.6).
    Revalidate {
        files: Vec<&'static str>,
        deleted: Vec<&'static str>,
        base: [u8; 32],
        replaces_record: bool,
    },
}

impl Op {
    /// The base state this operation was raised against, or `None` for one that has no subject
    /// records to go stale.
    pub fn recorded_base(&self) -> Option<[u8; 32]> {
        match self {
            Self::ConfigSet { base, .. }
            | Self::ConfigUnset { base, .. }
            | Self::Bootstrap { base, .. }
            | Self::Import { base, .. }
            | Self::RemoveCredential { base, .. }
            | Self::RemoveEnvironment { base, .. }
            | Self::Revalidate { base, .. } => Some(*base),
            Self::Enroll { .. } => None,
        }
    }

    /// The params digest and base an approval of this operation authorizes a re-send of, for
    /// the operations performed by re-send rather than from the pending record.
    fn authorization(&self) -> Option<([u8; 32], [u8; 32])> {
        match self {
            Self::Bootstrap { params, base, .. } | Self::Import { params, base, .. } => {
                Some((*params, *base))
            }
            _ => None,
        }
    }
}

pub struct Pending {
    pub id: String,
    pub op: Op,
    pub owner_uid: u32,
    owner_pid: Option<i32>,
    owner_executable: Option<String>,
    accepts: Accepts,
    raised_at: chrono::DateTime<chrono::Utc>,
    expires: Instant,
    digest: [u8; 32],
    description: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Enrolled {
    public_key: String,
    fingerprint: String,
    enrolled_at: String,
    approved_by_uid: u32,
    approved_by_login_uid: Option<u32>,
}

/// An approved bootstrap, spendable once by an identical re-send against the same base state.
struct Authorization {
    owner_uid: u32,
    params: [u8; 32],
    base: [u8; 32],
    expires: Instant,
    pending_operation: String,
}

#[derive(Default)]
struct Inner {
    pending: HashMap<String, Pending>,
    enrolled: HashMap<u32, Enrolled>,
    authorized: Vec<Authorization>,
}

/// The `SecureStorage` slot prefix for a sealed registry under `data-protection-keychain`. One
/// slot holds one home's registry; [`registry_slot`] keys it by the home's instance namespace.
pub const REGISTRY_SLOT: &str = "presence-enrolled";

/// The slot holding the registry of the home whose instance namespace is `ns`
/// (`storage-backend-per-home` Requirements 5.1-5.3). A home that enrolled no key has no slot,
/// rather than inheriting the keys another home enrolled.
fn registry_slot(ns: &str) -> String {
    format!("{REGISTRY_SLOT}.{ns}")
}

/// Where the sealed enrolled-key registry is held. Chosen from the storage backend (design
/// Decision 8): the backend's keychain slot under `data-protection-keychain`, a file otherwise.
pub enum RegistryCustody {
    File(PathBuf),
    /// One slot per home, named by [`registry_slot`] from `home`'s instance namespace.
    Slot {
        store: Box<dyn credsd_core::storage::SecureStorage>,
        ns: String,
    },
}

impl RegistryCustody {
    /// `<data_dir>/presence/enrolled.enc`, beside `callers/` and never inside a caller root.
    pub fn beside(callers_root: &Path) -> Self {
        Self::File(
            callers_root
                .parent()
                .unwrap_or(callers_root)
                .join("presence")
                .join("enrolled.enc"),
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

    /// The directory a file custody holds the registry in, whose custody drift-detection
    /// Requirement 10.8 verifies. `None` for a slot, whose custody is its access group.
    pub fn dir(&self) -> Option<&Path> {
        match self {
            Self::File(path) => path.parent(),
            Self::Slot { .. } => None,
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::Slot { store, ns } => {
                format!("{} slot '{}'", store.backend_name(), registry_slot(ns))
            }
        }
    }

    fn read(&self, encryption: &EncryptionService) -> Option<credsd_core::error::Result<Vec<u8>>> {
        let result = match self {
            Self::File(path) => match encryption.open_from_file(path) {
                Ok(p) => Ok(p.to_vec()),
                Err(credsd_core::error::DaemonError::Io(e))
                    if e.kind() == std::io::ErrorKind::NotFound =>
                {
                    return None
                }
                Err(e) => Err(e),
            },
            Self::Slot { store, ns } => {
                let slot = registry_slot(ns);
                match store.exists(&slot) {
                    Ok(false) => return None,
                    Ok(true) => store
                        .retrieve(&slot)
                        .and_then(|b| encryption.open(&b))
                        .map(|p| p.to_vec()),
                    Err(e) => return Some(Err(e)),
                }
            }
        };
        Some(result)
    }

    fn write(
        &self,
        encryption: &EncryptionService,
        plaintext: &[u8],
    ) -> credsd_core::error::Result<()> {
        match self {
            Self::File(path) => encryption.seal_to_file(path, plaintext),
            Self::Slot { store, ns } => {
                store.store(&registry_slot(ns), &encryption.seal(plaintext)?)
            }
        }
    }
}

pub struct Presence {
    inner: Mutex<Inner>,
    custody: RegistryCustody,
    encryption: Arc<EncryptionService>,
    /// Set when the registry would not open at startup (Requirement 5.11). No key from it is
    /// trusted, and nothing is written over it until an operator moves it aside.
    unreadable: Option<String>,
}

impl Presence {
    #[cfg(test)]
    pub fn new(custody: RegistryCustody, encryption: Arc<EncryptionService>) -> Self {
        Self::open(custody, encryption, None)
    }

    /// Load the registry from `custody`, unless `custody_breach` says the registry's custody failed its check
    /// (drift-detection Requirement 10.8). Then the registry is not read at all and is treated as
    /// one that did not open: no key in it is trusted, and nothing is written over it.
    pub fn open(
        custody: RegistryCustody,
        encryption: Arc<EncryptionService>,
        custody_breach: Option<String>,
    ) -> Self {
        let loaded = match custody_breach {
            Some(reason) => Some(Err(credsd_core::error::DaemonError::config(format!(
                "custody check failed: {reason}"
            )))),
            None => custody
                .read(&encryption)
                .map(|r| r.and_then(|plain| serde_json::from_slice(&plain).map_err(Into::into))),
        };
        let (enrolled, unreadable) = match loaded {
            None => (HashMap::new(), None),
            Some(Ok(enrolled)) => (enrolled, None),
            Some(Err(e)) => {
                tracing::error!(
                    event = "presence.registry_unreadable",
                    custody = custody.describe().as_str(),
                    error = %e,
                    "enrolled-key registry did not decrypt or authenticate; trusting no presence \
                     key from it and leaving it in place"
                );
                (HashMap::new(), Some(e.to_string()))
            }
        };
        Self {
            inner: Mutex::new(Inner {
                pending: HashMap::new(),
                enrolled,
                authorized: Vec::new(),
            }),
            custody,
            encryption,
            unreadable,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        let mut inner = crate::server::lock(&self.inner);
        let now = Instant::now();
        inner.pending.retain(|id, p| {
            let live = p.expires > now;
            if !live {
                audit("expired", id, None, "discarded");
            }
            live
        });
        inner.authorized.retain(|a| {
            let live = a.expires > now;
            if !live {
                audit(
                    "authorization_expired",
                    &a.pending_operation,
                    None,
                    "discarded unspent",
                );
            }
            live
        });
        inner
    }

    fn pending(peer: &PeerInfo, uid: u32, op: Op, description: String) -> Pending {
        let accepts = match op {
            Op::Enroll { .. } => Accepts::Privileged,
            Op::ConfigSet { .. }
            | Op::ConfigUnset { .. }
            | Op::Bootstrap { .. }
            | Op::Import { .. }
            | Op::RemoveCredential { .. }
            | Op::RemoveEnvironment { .. }
            | Op::Revalidate { .. } => Accepts::Any,
        };
        let id = presence::new_request_id();
        let mut pending = Pending {
            id: id.clone(),
            op,
            owner_uid: uid,
            owner_pid: peer.pid,
            owner_executable: peer.executable.clone(),
            accepts,
            raised_at: chrono::Utc::now(),
            expires: Instant::now().checked_add(TTL).unwrap_or_else(Instant::now),
            digest: [0; 32],
            description,
        };
        pending.digest = presence::sha256(canonical(&pending).as_bytes());
        pending
    }

    pub fn raise(&self, peer: &PeerInfo, uid: u32, op: Op, description: String) -> Challenge {
        let pending = Self::pending(peer, uid, op, description);
        let ancestry = crate::server::process_tree::ancestry_field(peer.pid);
        log_raised(peer, &pending, ancestry.as_deref());
        let mut inner = self.lock();
        insert(&mut inner, pending)
    }

    /// Requirement 2.2: the requesting uid is recorded as the subject. A second pending
    /// enrollment for the same uid discards both (design decision — not re-queueable).
    pub fn enroll(
        &self,
        peer: &PeerInfo,
        uid: u32,
        public_key: Vec<u8>,
    ) -> Result<EnrollResult, RpcError> {
        if public_key.len() != 65 || public_key.first() != Some(&0x04) {
            return Err(RpcError::invalid_params(
                "public_key must be an uncompressed P-256 point",
            ));
        }
        let fingerprint = presence::fingerprint(&public_key);
        let ancestry = crate::server::process_tree::ancestry_field(peer.pid);
        // The enrolled-key read, the collision check and the insert share one lock. Released
        // between them, an enrollment landing in the gap would be described as replacing nothing
        // and then replace a key on approval, and two concurrent enrollments would each see none
        // pending and both be queued.
        let challenge = {
            let mut inner = self.lock();
            let other = inner
                .pending
                .values()
                .find(|p| p.owner_uid == uid && matches!(p.op, Op::Enroll { .. }))
                .map(|p| {
                    (
                        p.id.clone(),
                        p.owner_pid,
                        escape_log(p.owner_executable.as_deref().unwrap_or("?")).to_string(),
                    )
                });
            if let Some((other_id, pid, exe)) = other {
                inner.pending.remove(&other_id);
                audit("enroll_collision", &other_id, None, "both discarded");
                return Err(RpcError::invalid_params(format!(
                    "another enrollment was pending for uid {uid} — {other_id}, raised by pid {} \
                     ({exe}); both were discarded; if you did not start the other one, something \
                     running as you did",
                    pid.map_or("?".into(), |p| p.to_string())
                )));
            }
            // `install_key` (below) unconditionally replaces any key already enrolled for `uid` --
            // the only fact that distinguishes a first enrollment from a hijack of the approver
            // seat. Name it so the privileged approve screen, which prints only this description,
            // discloses the replacement.
            at_enroll_gap(&mut inner);
            let description = match inner.enrolled.get(&uid) {
                Some(k) => format!(
                    "enroll presence key {fingerprint} for uid {uid}, replacing currently-enrolled key {}",
                    k.fingerprint
                ),
                None => format!("enroll presence key {fingerprint} for uid {uid}"),
            };
            let pending = Self::pending(peer, uid, Op::Enroll { public_key }, description);
            log_raised(peer, &pending, ancestry.as_deref());
            insert(&mut inner, pending)
        };
        Ok(EnrollResult {
            challenge,
            fingerprint,
        })
    }

    /// Owners see their own; uid 0 sees every uid's (Requirement 2.7).
    pub fn get(&self, peer_uid: u32, id: &str) -> Result<PendingSummary, RpcError> {
        let inner = self.lock();
        match inner.pending.get(id) {
            Some(p) if peer_uid == 0 || p.owner_uid == peer_uid => {
                Ok(summary_of(p, &inner.enrolled))
            }
            _ => Err(RpcError::request_not_found()),
        }
    }

    pub fn list(&self, peer_uid: u32) -> Vec<PendingSummary> {
        let inner = self.lock();
        let mut out: Vec<_> = inner
            .pending
            .values()
            .filter(|p| peer_uid == 0 || p.owner_uid == peer_uid)
            .map(|p| summary_of(p, &inner.enrolled))
            .collect();
        out.sort_by(|a, b| a.raised_at.cmp(&b.raised_at));
        out
    }

    pub fn withdraw(&self, peer_uid: u32, id: &str) -> Result<(), RpcError> {
        let mut inner = self.lock();
        match inner.pending.get(id) {
            Some(p) if p.owner_uid == peer_uid => {
                inner.pending.remove(id);
                audit("withdrawn", id, None, "discarded");
                Ok(())
            }
            _ => Err(RpcError::request_not_found()),
        }
    }

    /// Verify the proof for `params.id` and, if it holds, remove and return the pending
    /// operation for the caller to perform. Satisfiable at most once (Requirement 7.8).
    pub fn take_approved(
        &self,
        peer: &PeerInfo,
        params: &ApproveParams,
    ) -> Result<(Pending, &'static str), RpcError> {
        let peer_uid = peer.uid.ok_or_else(RpcError::request_not_found)?;
        let mut inner = self.lock();
        let pending = match inner.pending.get(&params.id) {
            Some(p) if peer_uid == 0 || p.owner_uid == peer_uid => p,
            _ => return Err(RpcError::request_not_found()),
        };
        // Every refusal here leaves the request pending (Requirement 8.3), so each names the
        // verifier that remains.
        let sudo = format!("sudo creds request approve {}", params.id);
        let refuse = |reason: RefusalReason, message: String, remediation: String| {
            audit("approve", &params.id, Some(false), &message);
            RpcError::approval_refused(reason, message, remediation)
        };
        let verifier = if peer_uid == 0 {
            "privileged_approval"
        } else if let Some(sig) = &params.signature {
            if pending.accepts == Accepts::Privileged {
                return Err(refuse(
                    RefusalReason::PrivilegedOnly,
                    format!("{} accepts privileged approval only", params.id),
                    sudo,
                ));
            }
            let Some(key) = inner
                .enrolled
                .get(&pending.owner_uid)
                .and_then(|k| presence::unhex(&k.public_key))
            else {
                return Err(refuse(
                    RefusalReason::NoPresenceKey,
                    format!("no presence key is enrolled for uid {}", pending.owner_uid),
                    format!("{sudo}, or enroll one: creds presence enroll"),
                ));
            };
            let message = presence::signed_message(&pending.id, &pending.digest);
            // Malformed rather than refused: hex is a property of the request, not of the proof.
            let sig = presence::unhex(sig)
                .ok_or_else(|| RpcError::invalid_params("signature is not hex"))?;
            if !presence::verify(&key, &message, &sig) {
                return Err(refuse(
                    RefusalReason::SignatureInvalid,
                    "the signature does not verify under the enrolled presence key".to_owned(),
                    sudo,
                ));
            }
            "presence_signature"
        } else {
            return Err(refuse(
                RefusalReason::NotSatisfied,
                format!(
                    "{} needs a presence signature or a privileged approval, and this \
                     connection carried neither",
                    params.id
                ),
                sudo,
            ));
        };
        let pending = inner
            .pending
            .remove(&params.id)
            .ok_or_else(RpcError::request_not_found)?;
        Ok((pending, verifier))
    }

    /// Record that the owner may perform the bootstrap `pending` describes once, against the
    /// base state it was approved for.
    pub fn authorize(&self, pending: &Pending) {
        let Some((params, base)) = pending.op.authorization() else {
            return;
        };
        let mut inner = self.lock();
        // One authorization per subject: a later approval replaces an earlier one and restarts
        // the window. That is intended. Each approval carries its own presence proof, so the
        // window never extends without one.
        inner.authorized.retain(|a| {
            !(a.owner_uid == pending.owner_uid && a.params == params && a.base == base)
        });
        inner.authorized.push(Authorization {
            owner_uid: pending.owner_uid,
            params,
            base,
            expires: Instant::now()
                .checked_add(AUTHORIZATION_TTL)
                .unwrap_or_else(Instant::now),
            pending_operation: pending.id.clone(),
        });
    }

    /// Spend a matching authorization, returning the request it was granted for. A
    /// re-send whose params or base state differ by a byte finds none and is gated afresh.
    pub fn spend(&self, owner_uid: u32, params: &[u8; 32], base: &[u8; 32]) -> Option<String> {
        let mut inner = self.lock();
        let at = inner
            .authorized
            .iter()
            .position(|a| a.owner_uid == owner_uid && a.params == *params && a.base == *base)?;
        Some(inner.authorized.swap_remove(at).pending_operation)
    }

    pub fn install_key(
        &self,
        uid: u32,
        public_key: &[u8],
        approver: &PeerInfo,
    ) -> Result<String, RpcError> {
        let fingerprint = presence::fingerprint(public_key);
        let mut inner = self.lock();
        let mut next = inner.enrolled.clone();
        next.insert(
            uid,
            Enrolled {
                public_key: presence::hex(public_key),
                fingerprint: fingerprint.clone(),
                enrolled_at: chrono::Utc::now().to_rfc3339(),
                approved_by_uid: approver.uid.unwrap_or(u32::MAX),
                approved_by_login_uid: approver.login_uid,
            },
        );
        self.persist(&next)?;
        inner.enrolled = next;
        Ok(fingerprint)
    }

    pub fn revoke(&self, uid: u32) -> Result<String, RpcError> {
        let mut inner = self.lock();
        let mut next = inner.enrolled.clone();
        let removed = next.remove(&uid).ok_or_else(|| {
            RpcError::invalid_params(format!("no presence key enrolled for uid {uid}"))
        })?;
        self.persist(&next)?;
        inner.enrolled = next;
        // A pending enrollment's challenge names the key it would replace. That key is gone
        // now, so the enrollment would describe a replacement that will not happen.
        let stale: Vec<String> = inner
            .pending
            .values()
            .filter(|p| p.owner_uid == uid && matches!(p.op, Op::Enroll { .. }))
            .map(|p| p.id.clone())
            .collect();
        for id in stale {
            inner.pending.remove(&id);
            audit("enroll_revoked", &id, None, "discarded");
        }
        Ok(removed.fingerprint)
    }

    pub fn status(&self, uid: u32) -> StatusResult {
        let inner = self.lock();
        let k = inner.enrolled.get(&uid);
        StatusResult {
            uid,
            presence_key: k.map(|k| k.fingerprint.clone()),
            enrolled_at: k.map(|k| k.enrolled_at.clone()),
            approved_by_uid: k.map(|k| k.approved_by_uid),
            approved_by_login_uid: k.and_then(|k| k.approved_by_login_uid),
        }
    }

    pub fn fingerprint_for(&self, uid: u32) -> Option<String> {
        crate::server::lock(&self.inner)
            .enrolled
            .get(&uid)
            .map(|k| k.fingerprint.clone())
    }

    /// Persist before the in-memory table changes, so a failed write never leaves a key trusted
    /// that a restart would forget, or a revocation that a restart would undo.
    fn persist(&self, enrolled: &HashMap<u32, Enrolled>) -> Result<(), RpcError> {
        if let Some(reason) = &self.unreadable {
            return Err(RpcError::internal(format!(
                "the enrolled-key registry at {} did not open ({reason}); it is left in place for \
                 diagnosis, and enrollment and revocation stay refused until it is moved aside",
                self.custody.describe()
            )));
        }
        let plaintext =
            serde_json::to_vec(enrolled).map_err(|e| RpcError::internal(e.to_string()))?;
        self.custody
            .write(&self.encryption, &plaintext)
            .map_err(|e| RpcError::internal(e.to_string()))
    }
}

/// The digest's preimage. Every field that decides what is performed, or for whom, is in it.
fn canonical(p: &Pending) -> String {
    let mut f = format!("v1\nid={}\n", p.id);
    match &p.op {
        Op::ConfigSet {
            environment,
            key,
            value,
            base,
        } => {
            f += &format!(
                "op=config/set\narg.environment={environment}\narg.key={key}\narg.value={value}\nbase={}\n",
                presence::hex(base)
            );
        }
        Op::Enroll { public_key } => {
            f += &format!(
                "op=presence/enroll\narg.public_key={}\n",
                presence::hex(public_key)
            );
        }
        Op::Bootstrap {
            environment,
            credential,
            params,
            base,
        } => {
            f += &format!(
                "op=environment/bootstrap\narg.environment={environment}\narg.credential={credential}\nparams={}\nbase={}\n",
                presence::hex(params),
                presence::hex(base)
            );
        }
        Op::ConfigUnset {
            environment,
            key,
            base,
        } => {
            f += &format!(
                "op=config/unset\narg.environment={environment}\narg.key={key}\nbase={}\n",
                presence::hex(base)
            );
        }
        Op::Import {
            environments,
            params,
            base,
        } => {
            f += &format!(
                "op=environment/import\narg.environments={}\nparams={}\nbase={}\n",
                environments.join(","),
                presence::hex(params),
                presence::hex(base)
            );
        }
        Op::RemoveCredential { credential, base } => {
            f += &format!(
                "op=credential/remove\narg.credential={credential}\nbase={}\n",
                presence::hex(base)
            );
        }
        Op::RemoveEnvironment { environment, base } => {
            f += &format!(
                "op=environment/remove\narg.environment={environment}\nbase={}\n",
                presence::hex(base)
            );
        }
        Op::Revalidate {
            files,
            deleted,
            base,
            replaces_record,
        } => {
            f += &format!(
                "op=file/revalidate\narg.files={}\narg.deleted={}\narg.replaces_record={}\n\
                 base={}\n",
                files.join(","),
                deleted.join(","),
                replaces_record,
                presence::hex(base)
            );
        }
    }
    f += &format!(
        "owner_uid={}\naccepts={:?}\nraised_at={}\n",
        p.owner_uid,
        p.accepts,
        p.raised_at.to_rfc3339()
    );
    f
}

// Test seam: runs inside `enroll`'s lock, after the collision check and before the enrolled key
// is read for the description. A test installs a key here to land a concurrent install in the
// exact spot a second lock hold would have left open, without sleeps or sampling.
#[cfg(test)]
type EnrollGapHook = Box<dyn FnOnce(&mut Inner)>;

#[cfg(test)]
thread_local! {
    static AT_ENROLL_GAP: std::cell::RefCell<Option<EnrollGapHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn at_enroll_gap(inner: &mut Inner) {
    if let Some(hook) = AT_ENROLL_GAP.with(|h| h.borrow_mut().take()) {
        hook(inner);
    }
}

#[cfg(not(test))]
fn at_enroll_gap(_: &mut Inner) {}

fn insert(inner: &mut Inner, pending: Pending) -> Challenge {
    let challenge = challenge_of(&pending, &inner.enrolled);
    inner.pending.insert(pending.id.clone(), pending);
    challenge
}

/// `ancestry` is walked by the caller before it takes the lock: the walk reads the process table,
/// which is no work to do while every other presence operation waits.
fn log_raised(peer: &PeerInfo, pending: &Pending, ancestry: Option<&str>) {
    tracing::info!(
        event = "presence.raised",
        pending_operation = pending.id.as_str(),
        owner_uid = pending.owner_uid,
        owner_pid = peer.pid,
        owner_executable = peer.executable.as_deref(),
        owner_ancestry = ancestry,
        description = %logged_description(&pending.description),
        "presence gate: challenge raised"
    );
}

/// The part of a challenge description the audit log records: its first line. A revalidation's
/// description carries the drifted files' raw text, and `credentials.toml` can still hold legacy
/// secret fields the parser accepts and ignores, so the full text goes to the approver only.
fn logged_description(description: &str) -> EscapeLog<&str> {
    escape_log(description.lines().next().unwrap_or_default())
}

fn challenge_of(p: &Pending, enrolled: &HashMap<u32, Enrolled>) -> Challenge {
    Challenge {
        id: p.id.clone(),
        digest: presence::hex(&p.digest),
        description: p.description.clone(),
        expires_in_secs: p
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs(),
        accepts: p.accepts,
        presence_key: enrolled.get(&p.owner_uid).map(|k| k.fingerprint.clone()),
    }
}

fn summary_of(p: &Pending, enrolled: &HashMap<u32, Enrolled>) -> PendingSummary {
    PendingSummary {
        challenge: challenge_of(p, enrolled),
        owner_uid: p.owner_uid,
        owner_pid: p.owner_pid,
        owner_executable: p.owner_executable.clone(),
        raised_at: p.raised_at.to_rfc3339(),
    }
}

fn audit(event: &str, id: &str, proof_verified: Option<bool>, outcome: &str) {
    tracing::info!(
        event = format!("presence.{event}").as_str(),
        pending_operation = id,
        proof_verified,
        outcome,
        "presence gate"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::routes::CallerAuth;
    use credsd_core::storage::SecureStorage;

    fn encryption(byte: u8) -> Arc<EncryptionService> {
        Arc::new(EncryptionService::new(vec![byte; 32]).expect("key"))
    }

    fn root_peer() -> PeerInfo {
        PeerInfo {
            uid: Some(0),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: None,
            login_uid: Some(501),
        }
    }

    /// A revalidation's description is whole files; the audit log keeps its summary line only.
    #[test]
    fn the_audit_log_records_only_a_descriptions_first_line() {
        let description = "revalidate drifted config files: credentials.toml\n\n\
                           credentials.toml has drifted. Current contents:\n\n  \
                           client_secret = \"s3cr3t\"\n";
        assert_eq!(
            logged_description(description).to_string(),
            "revalidate drifted config files: credentials.toml"
        );
        assert_eq!(
            logged_description("set region = us-east-1 on environment 'dev'").to_string(),
            "set region = us-east-1 on environment 'dev'"
        );
        assert_eq!(logged_description("").to_string(), "");
    }

    /// The first line is the only text the log keeps, and it is caller-chosen (a path or a
    /// profile name), so a bidi override in it must not reach the audit line unescaped.
    #[test]
    fn the_audit_log_escapes_format_characters_in_the_first_line() {
        let description = "revalidate \u{202E}lmth.exe\u{2066}\nrest of the description";
        assert_eq!(
            logged_description(description).to_string(),
            "revalidate \\x202Elmth.exe\\x2066"
        );
    }

    /// Concurrent enrollments for one uid must never leave two pending: the collision rule
    /// discards both, and a check-then-insert split across two lock acquisitions let every racer
    /// see none pending and queue its own. Repeated so the old interleaving would be hit.
    #[test]
    fn concurrent_enrollments_for_one_uid_never_leave_two_pending() {
        let owner = PeerInfo {
            uid: Some(501),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: None,
            login_uid: None,
        };
        let key = vec![0x04; 65];
        for _ in 0..200 {
            let gate = Presence::new(
                RegistryCustody::File(std::env::temp_dir().join("credsd-unused-registry.enc")),
                encryption(1),
            );
            let barrier = std::sync::Barrier::new(8);
            std::thread::scope(|scope| {
                for _ in 0..8 {
                    scope.spawn(|| {
                        barrier.wait();
                        let _ = gate.enroll(&owner, 501, key.clone());
                    });
                }
            });
            let pending = gate
                .lock()
                .pending
                .values()
                .filter(|p| p.owner_uid == 501 && matches!(p.op, Op::Enroll { .. }))
                .count();
            assert!(
                pending <= 1,
                "{pending} enrollments left pending for one uid"
            );
        }
    }

    /// An install that lands between the enrollment's collision check and its description read
    /// must be named by the challenge: the description and `presence_key` are built from one
    /// state. Forced through the test seam, so the interleaving is not sampled. Checked by hand:
    /// with the enrolled-key read moved into its own lock hold ahead of the collision check, and
    /// the seam kept in the gap, this test fails. The seam itself exists only in test builds.
    #[test]
    fn an_install_landing_before_the_description_is_named_in_the_challenge() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = Presence::new(
            RegistryCustody::File(dir.path().join("enrolled.enc")),
            encryption(1),
        );
        let key = |byte: u8| {
            let mut k = vec![0x04; 65];
            k[1] = byte;
            k
        };
        let owner = PeerInfo {
            uid: Some(501),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: None,
            login_uid: None,
        };
        let installed = presence::fingerprint(&key(1));
        let installed_for_hook = installed.clone();
        AT_ENROLL_GAP.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |inner: &mut Inner| {
                inner.enrolled.insert(
                    501,
                    Enrolled {
                        public_key: presence::hex(&key(1)),
                        fingerprint: installed_for_hook,
                        enrolled_at: String::new(),
                        approved_by_uid: 0,
                        approved_by_login_uid: None,
                    },
                );
            }));
        });
        let enrolled = gate.enroll(&owner, 501, key(2)).expect("enroll");
        assert_eq!(
            enrolled.challenge.presence_key.as_deref(),
            Some(installed.as_str())
        );
        assert_eq!(
            enrolled.challenge.description,
            format!(
                "enroll presence key {} for uid 501, replacing currently-enrolled key {installed}",
                enrolled.fingerprint
            )
        );
    }

    /// The collision rule is per uid: an enrollment for one uid never discards another uid's
    /// pending enrollment. Both uids' enrollments must stay pending.
    #[test]
    fn an_enrollment_for_another_uid_is_not_a_collision() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = Presence::new(
            RegistryCustody::File(dir.path().join("enrolled.enc")),
            encryption(1),
        );
        let owner = |uid: u32| PeerInfo {
            uid: Some(uid),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: None,
            login_uid: None,
        };
        let key = vec![0x04; 65];
        gate.enroll(&owner(501), 501, key.clone())
            .expect("first uid enrolls");
        gate.enroll(&owner(502), 502, key)
            .expect("a second uid enrolls without colliding");
        let pending = gate
            .lock()
            .pending
            .values()
            .filter(|p| matches!(p.op, Op::Enroll { .. }))
            .count();
        assert_eq!(pending, 2, "both uids' enrollments stay pending");
    }

    /// The collision error quotes the other enrollment's executable path. The requester names
    /// that binary itself, so its escape sequences and newlines must reach the caller escaped.
    #[test]
    fn a_collision_error_escapes_the_other_requesters_executable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = Presence::new(
            RegistryCustody::File(dir.path().join("enrolled.enc")),
            encryption(1),
        );
        let owner = |executable: Option<&str>| PeerInfo {
            uid: Some(501),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: executable.map(String::from),
            login_uid: None,
        };
        let key = vec![0x04; 65];
        gate.enroll(&owner(Some("/tmp/x\x1b[2K\nforged")), 501, key.clone())
            .expect("first enrollment is pending");
        let err = gate
            .enroll(&owner(None), 501, key)
            .expect_err("a second enrollment for the uid collides");
        assert!(
            !err.message.contains('\x1b') && !err.message.contains('\n'),
            "raw control bytes reached the error: {:?}",
            err.message
        );
        assert!(
            err.message.contains("/tmp/x\\x1B[2K\\x0Aforged"),
            "{}",
            err.message
        );
    }

    /// A pending enrollment describes the key it would replace. Revoking that key first must
    /// discard the enrollment, or its challenge names a replacement that will not happen.
    #[test]
    fn revoke_discards_the_uids_pending_enrollment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = Presence::new(
            RegistryCustody::File(dir.path().join("enrolled.enc")),
            encryption(1),
        );
        let key = |byte: u8| {
            let mut k = vec![0x04; 65];
            k[1] = byte;
            k
        };
        let owner = PeerInfo {
            uid: Some(501),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: None,
            login_uid: None,
        };
        gate.install_key(501, &key(1), &root_peer())
            .expect("enroll a key to revoke");
        gate.enroll(&owner, 501, key(2)).expect("enroll");
        let other = PeerInfo {
            uid: Some(502),
            ..owner.clone()
        };
        gate.enroll(&other, 502, key(3))
            .expect("another uid's enrollment is pending");
        gate.raise(
            &owner,
            501,
            Op::RemoveEnvironment {
                environment: "dev".into(),
                base: [0; 32],
            },
            "remove environment 'dev'".into(),
        );
        gate.revoke(501).expect("revoke");
        let other_ops = gate
            .lock()
            .pending
            .values()
            .filter(|p| p.owner_uid == 501 && matches!(p.op, Op::RemoveEnvironment { .. }))
            .count();
        assert_eq!(other_ops, 1, "revoke discarded a non-enrollment operation");
        let other_pending = gate
            .lock()
            .pending
            .values()
            .filter(|p| p.owner_uid == 502 && matches!(p.op, Op::Enroll { .. }))
            .count();
        assert_eq!(
            other_pending, 1,
            "revoke discarded another uid's enrollment"
        );
        let pending = gate
            .lock()
            .pending
            .values()
            .filter(|p| p.owner_uid == 501 && matches!(p.op, Op::Enroll { .. }))
            .count();
        assert_eq!(
            pending, 0,
            "the pending enrollment outlived the key it named"
        );
    }

    /// Only a 65-byte key with leading 0x04 is enrolled. Every length and leading byte is
    /// checked, so a mutated `||` in the guard fails on one of the mixed-up inputs. The guard
    /// does not check the curve, so the name does not claim it.
    #[test]
    fn enroll_accepts_only_a_65_byte_key_led_by_0x04() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = Presence::new(
            RegistryCustody::File(dir.path().join("enrolled.enc")),
            encryption(1),
        );
        let owner = PeerInfo {
            uid: Some(501),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: None,
            login_uid: None,
        };
        for len in (0..=130usize).filter(|&len| len != 65) {
            assert!(
                gate.enroll(&owner, 501, vec![0x04; len]).is_err(),
                "length {len} accepted"
            );
        }
        for first in 0..=255u8 {
            let mut key = vec![0x04; 65];
            key[0] = first;
            // Only the one valid key is accepted, so the uid never has two enrollments pending.
            let accepted = gate.enroll(&owner, 501, key).is_ok();
            assert_eq!(accepted, first == 0x04, "leading byte {first:#04x}");
        }
    }

    /// `install_key` (Requirement 5.1) replaces any key already enrolled for the uid with no
    /// is-already-enrolled check of its own; the one surface that can disclose the replacement
    /// before approval is the challenge description printed by `creds request approve`. A first
    /// enrollment names no prior key; a second must name the one it would destroy.
    #[test]
    fn a_second_enrollment_names_the_key_it_would_replace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = Presence::new(
            RegistryCustody::File(dir.path().join("enrolled.enc")),
            encryption(1),
        );
        let owner = PeerInfo {
            uid: Some(501),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: None,
            login_uid: None,
        };
        let first_key = vec![0x04; 65];
        let first = gate
            .enroll(&owner, 501, first_key.clone())
            .expect("first enrollment");
        assert!(
            !gate.lock().pending[&first.challenge.id]
                .description
                .contains("replacing"),
            "a first enrollment has nothing to replace"
        );
        gate.lock().pending.remove(&first.challenge.id);
        gate.install_key(501, &first_key, &root_peer())
            .expect("commit the first key so a second enrollment sees it enrolled");

        let mut second_key = vec![0x04; 65];
        second_key[64] = 0x01;
        let second = gate
            .enroll(&owner, 501, second_key)
            .expect("second enrollment");
        let description = gate.lock().pending[&second.challenge.id]
            .description
            .clone();
        assert!(
            description.contains(&format!(
                "replacing currently-enrolled key {}",
                first.fingerprint
            )),
            "{description}"
        );
    }

    /// An owner approving with no proof is refused as `not_satisfied` — a code, not invalid
    /// params — with a remediation naming the verifier that remains, and the request stays
    /// pending so that verifier still works (Requirements 8.2, 8.3, 8.6). The peer is synthesized
    /// so the case holds whoever runs the suite: a test process running as root is itself a
    /// privileged approver.
    #[test]
    fn an_unproven_owner_approval_is_refused_and_stays_pending() {
        let gate = Presence::new(
            RegistryCustody::File(std::env::temp_dir().join("credsd-unused-registry.enc")),
            encryption(1),
        );
        let owner = PeerInfo {
            uid: Some(501),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: None,
            login_uid: None,
        };
        let challenge = gate.raise(
            &owner,
            501,
            Op::RemoveEnvironment {
                environment: "dev".into(),
                base: [0; 32],
            },
            "remove environment 'dev'".into(),
        );
        let unproven = ApproveParams {
            id: challenge.id.clone(),
            signature: None,
        };
        let refused = gate
            .take_approved(&owner, &unproven)
            .err()
            .expect("an owner with no proof is refused");
        assert_eq!(
            refused.domain_code(),
            Some(credsd_core::rpc::DomainCode::ApprovalRefused)
        );
        assert_eq!(refused.refusal_reason(), Some(RefusalReason::NotSatisfied));
        assert!(refused
            .remediation()
            .is_some_and(|r| r.contains(&format!("sudo creds request approve {}", challenge.id))));

        let (approved, verifier) = gate
            .take_approved(&root_peer(), &unproven)
            .expect("still pending, so a privileged approval satisfies it");
        assert_eq!(approved.id, challenge.id);
        assert_eq!(verifier, "privileged_approval");
    }

    /// Another uid's request and a request that does not exist produce the same error, field
    /// for field, so a caller cannot learn that someone else has an approval outstanding
    /// (Requirement 8.4).
    #[test]
    fn another_uids_request_is_indistinguishable_from_none() {
        let gate = Presence::new(
            RegistryCustody::File(std::env::temp_dir().join("credsd-unused-registry.enc")),
            encryption(1),
        );
        let owner = PeerInfo {
            uid: Some(501),
            pid: None,
            auth: CallerAuth::Unresolved,
            executable: None,
            login_uid: None,
        };
        let challenge = gate.raise(
            &owner,
            501,
            Op::RemoveEnvironment {
                environment: "dev".into(),
                base: [0; 32],
            },
            "remove environment 'dev'".into(),
        );
        let other = PeerInfo {
            uid: Some(502),
            ..owner
        };
        let theirs = gate
            .take_approved(
                &other,
                &ApproveParams {
                    id: challenge.id.clone(),
                    signature: None,
                },
            )
            .err()
            .expect("refused");
        let absent = gate
            .take_approved(
                &other,
                &ApproveParams {
                    id: "req-does-not-exist".into(),
                    signature: None,
                },
            )
            .err()
            .expect("refused");
        assert_eq!(
            serde_json::to_value(&theirs).unwrap(),
            serde_json::to_value(&absent).unwrap()
        );
        assert_eq!(
            theirs.domain_code(),
            Some(credsd_core::rpc::DomainCode::RequestNotFound)
        );
    }

    const KEY: [u8; 65] = [4; 65];

    #[derive(Default, Clone)]
    struct Slots(Arc<Mutex<HashMap<String, Vec<u8>>>>);

    impl SecureStorage for Slots {
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

    #[test]
    fn an_enrolled_key_survives_a_restart_and_is_never_on_disk_in_plaintext() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("presence").join("enrolled.enc");
        let fingerprint = Presence::new(RegistryCustody::File(path.clone()), encryption(1))
            .install_key(501, &KEY, &root_peer())
            .expect("install");

        let on_disk = std::fs::read_to_string(&path).expect("read");
        assert!(!on_disk.contains(&fingerprint));
        assert!(!on_disk.contains(&presence::hex(&KEY)));

        let reloaded = Presence::new(RegistryCustody::File(path), encryption(1));
        assert_eq!(reloaded.fingerprint_for(501), Some(fingerprint));
    }

    /// Requirement 5.11: trust nothing, write nothing over it, and refuse to enroll on top.
    #[test]
    fn a_registry_that_does_not_open_is_trusted_for_nothing_and_left_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("enrolled.enc");
        Presence::new(RegistryCustody::File(path.clone()), encryption(1))
            .install_key(501, &KEY, &root_peer())
            .expect("install");
        let sealed = std::fs::read(&path).expect("read");

        let other_key = Presence::new(RegistryCustody::File(path.clone()), encryption(2));
        assert_eq!(other_key.fingerprint_for(501), None);
        assert!(other_key.install_key(502, &KEY, &root_peer()).is_err());
        assert!(other_key.revoke(501).is_err());
        assert_eq!(std::fs::read(&path).expect("read"), sealed);

        std::fs::write(&path, b"{\"not\":\"sealed\"}").expect("write");
        let tampered = Presence::new(RegistryCustody::File(path), encryption(1));
        assert_eq!(tampered.fingerprint_for(501), None);
    }

    #[test]
    fn a_slot_custody_holds_the_same_sealed_registry() {
        let slots = Slots::default();
        let home = Path::new("/data/home-a");
        let custody = || RegistryCustody::slot(Box::new(slots.clone()), home);
        let fingerprint = Presence::new(custody(), encryption(1))
            .install_key(501, &KEY, &root_peer())
            .expect("install");

        let ns = credsd_core::storage::instance_namespace(home);
        let sealed = slots.retrieve(&registry_slot(&ns)).expect("slot written");
        assert!(encryption(1).open(&sealed).is_ok());

        let reloaded = Presence::new(custody(), encryption(1));
        assert_eq!(reloaded.fingerprint_for(501), Some(fingerprint));
        reloaded.revoke(501).expect("revoke");
        let after = Presence::new(custody(), encryption(1));
        assert_eq!(after.fingerprint_for(501), None);
    }

    /// `storage-backend-per-home` Requirements 5.1-5.3: a home is born with no enrolled key,
    /// rather than inheriting the approval authority another home on the machine enrolled.
    #[test]
    fn a_registry_is_not_read_by_another_home_on_the_same_machine() {
        let slots = Slots::default();
        let home_of = |path: &str| {
            Presence::new(
                RegistryCustody::slot(Box::new(slots.clone()), Path::new(path)),
                encryption(1),
            )
        };
        let fingerprint = home_of("/data/home-a")
            .install_key(501, &KEY, &root_peer())
            .expect("install");
        assert_eq!(
            home_of("/data/home-a").fingerprint_for(501),
            Some(fingerprint)
        );
        assert_eq!(
            home_of("/data/home-b").fingerprint_for(501),
            None,
            "a second home trusts no key the first enrolled"
        );
    }

    #[test]
    fn the_file_custody_sits_beside_callers_never_inside_a_caller_root() {
        let RegistryCustody::File(path) = RegistryCustody::beside(Path::new("/data/callers"))
        else {
            panic!("file custody");
        };
        assert_eq!(path, Path::new("/data/presence/enrolled.enc"));
    }
}
