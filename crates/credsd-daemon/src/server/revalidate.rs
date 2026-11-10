//! `file/revalidate`: ratify a caller root's hand-edited load-bearing files by resealing their
//! snapshots (drift-detection Requirement 4). The only way a drifted file becomes valid again.
//!
//! A snapshot seals a whole file, so the unit of revalidation is the caller root: every drifted
//! file is shown in full under one challenge, and approval reseals exactly those files from the
//! bytes that were shown (design Decision 9). A drifted file that has been deleted is named as
//! deleted, and approval records it as absent in the integrity record (Requirement 4.1).
//!
//! It is also the recovery for a record that will not open (Requirement 10.6). Nothing then says
//! what either file should hold, so every file present is shown as drifted, the challenge says
//! that there is no record to compare against, and approval builds the record afresh.

use credsd_core::config::platform;
use credsd_core::config::snapshot::{self, DriftStatus, Pin};
use credsd_core::log::escape_terminal;
use credsd_core::rpc::{OkResult, RevalidateParams};
use credsd_core::rpc::{Request, RpcError};
use serde_json::Value;

use crate::server::bootstrap::{records_base_of, TomlFiles};
use crate::server::dispatch::{authorized_uid, checked_text, internal, to_value, Daemon};
use crate::server::integrity::{canonical_of, verify_for_revalidation, Record, Unverifiable};
use crate::server::presence::Op;
use crate::server::routes::PeerInfo;
use crate::server::write_lock::Held;

pub(crate) const CONFIG: &str = "config.toml";
pub(crate) const CREDENTIALS: &str = "credentials.toml";

enum State {
    Absent,
    Unchanged,
    Drifted,
    /// Gone while the record (or a leftover snapshot) says it should be there.
    Deleted,
}

pub(crate) async fn handle(
    request: &Request,
    peer: &PeerInfo,
    daemon: &Daemon,
) -> Result<Value, RpcError> {
    let uid = authorized_uid(peer)?;
    let _: RevalidateParams = request.params_as()?;
    let _guard = daemon.bootstrap_lock(uid).lock_owned().await;
    let files = TomlFiles::read(uid).map_err(|e| internal(e.to_string()))?;
    let (record, unopenable) = match daemon.integrity.read(uid) {
        Ok(record) => (record, None),
        Err(Unverifiable::Unopenable(reason)) => (None, Some(reason)),
        Err(custody) => return Err(custody.refusal()),
    };
    let config = state(uid, CONFIG, &files.config, record, daemon)?;
    let credentials = state(uid, CREDENTIALS, &files.credentials, record, daemon)?;

    let named = |wanted: fn(&State) -> bool| -> Vec<&'static str> {
        [(CONFIG, &config), (CREDENTIALS, &credentials)]
            .into_iter()
            .filter(|(_, s)| wanted(s))
            .map(|(name, _)| name)
            .collect()
    };
    let drifted = named(|s| matches!(s, State::Drifted));
    let deleted = named(|s| matches!(s, State::Deleted));
    if drifted.is_empty() && deleted.is_empty() && unopenable.is_none() {
        // The records verify now, so a state cached while they did not is stale. It would
        // otherwise refuse until a file changed, since revalidation then writes nothing.
        daemon.evict_caller(uid);
        return to_value(OkResult {});
    }

    let all: Vec<&str> = drifted.iter().chain(&deleted).copied().collect();
    let mut description = match &unopenable {
        None => format!("revalidate drifted config files: {}\n", all.join(", ")),
        Some(reason) => format!(
            "replace the integrity record for uid {uid}, which cannot be opened ({}).\n\nThere \
             is no record to compare these files against, so this cannot show what changed or \
             tell a restored earlier copy from the current one. Approving trusts the files \
             exactly as shown below.\n",
            escape_terminal(reason)
        ),
    };
    for (name, bytes, state) in [
        (CONFIG, &files.config, &config),
        (CREDENTIALS, &files.credentials, &credentials),
    ] {
        description.push('\n');
        match state {
            State::Drifted => {
                description.push_str(&format!("{name} has drifted. Current contents:\n\n"));
                for line in checked_text(bytes)?.lines() {
                    description.push_str(&format!("  {}\n", escape_terminal(line)));
                }
            }
            State::Unchanged => {
                description.push_str(&format!("{name} is unchanged and will not be resealed.\n"))
            }
            State::Absent => {
                description.push_str(&format!("{name} does not exist and will not be sealed.\n"))
            }
            State::Deleted => description.push_str(&format!(
                "{name} has been deleted. Approving records it as absent: every credential it \
                 named stops being served.\n"
            )),
        }
    }
    if !drifted.is_empty() {
        description.push_str("\nApproving re-seals the contents shown above.");
    }

    let base = records_base_of(uid, &files, &[]).map_err(|e| internal(e.to_string()))?;
    let challenge = daemon.presence.raise(
        peer,
        uid,
        Op::Revalidate {
            files: drifted,
            deleted,
            base,
            replaces_record: unopenable.is_some(),
        },
        description,
    );
    let remediation = format!("sudo creds request approve {}", challenge.id);
    Err(RpcError::approval_required(&challenge, remediation))
}

/// Reseal the snapshots of `names` from the bytes the approval checked, record `deleted` as
/// absent, and pin both in the integrity record, after the snapshots (Requirement 5.6). The caller
/// has confirmed the base state is unchanged; the base check, under the lock `held` proves, is
/// this operation's form of the shared write check (Requirement 5.8). A file the challenge showed
/// as unchanged keeps the pin it had. `replaces_record` builds the record afresh in place of one
/// that would not open (Requirement 10.6).
pub(crate) fn apply(
    held: &Held<'_>,
    uid: u32,
    names: &[&'static str],
    deleted: &[&'static str],
    replaces_record: bool,
    checked: &TomlFiles,
    daemon: &Daemon,
) -> Result<String, RpcError> {
    let mut verified = verify_for_revalidation(daemon, held, uid, checked, replaces_record)?;
    for name in names {
        let bytes = match *name {
            CONFIG => &checked.config,
            _ => &checked.credentials,
        };
        let canonical = canonical(uid, name, bytes)?;
        verified
            .seal_snapshot(&daemon.encryption, name, &canonical)
            .map_err(|e| internal(e.to_string()))?;
        verified.pin_sealed(name, &canonical);
    }
    for name in deleted {
        verified.set(name, Pin::Absent);
    }
    daemon.integrity.write(verified)?;
    daemon.evict_caller(uid);
    let all: Vec<&str> = names.iter().chain(deleted).copied().collect();
    if replaces_record {
        tracing::warn!(
            event = "integrity.replaced",
            uid,
            files = all.join(","),
            "an integrity record that would not open was replaced on approval"
        );
        let what = if all.is_empty() {
            "no file".to_owned()
        } else {
            all.join(", ")
        };
        return Ok(format!(
            "integrity record replaced for uid {uid}; {what} revalidated"
        ));
    }
    Ok(format!("{} revalidated for uid {uid}", all.join(", ")))
}

fn state(
    uid: u32,
    name: &str,
    bytes: &[u8],
    record: Option<Record>,
    daemon: &Daemon,
) -> Result<State, RpcError> {
    let path = platform::caller_root(uid).join(name);
    let canonical = canonical(uid, name, bytes)?;
    match snapshot::assess(
        &daemon.encryption,
        &canonical,
        &path,
        record.map(|r| r.get(name)),
    ) {
        DriftStatus::Absent => Ok(State::Absent),
        DriftStatus::Deleted => Ok(State::Deleted),
        DriftStatus::Valid { .. } => Ok(State::Unchanged),
        DriftStatus::Drifted | DriftStatus::Missing => Ok(State::Drifted),
        DriftStatus::Unverifiable => {
            Err(Unverifiable::Unopenable("see the daemon log".into()).refusal())
        }
    }
}

/// The canonical form the snapshot of `name` seals, from `bytes`. A file that does not parse has
/// no canonical form, so there is nothing a snapshot could ratify until it is fixed.
fn canonical(uid: u32, name: &str, bytes: &[u8]) -> Result<Vec<u8>, RpcError> {
    canonical_of(uid, name, checked_text(bytes)?).map_err(|e| {
        RpcError::domain(
            credsd_core::rpc::DomainCode::ConfigDrifted,
            format!(
                "{name} does not parse, so there is nothing to revalidate until it is corrected \
                 or restored: {}",
                e.detail()
            ),
        )
    })
}
