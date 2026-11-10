# Design: Drift Detection

## Shape

Three mechanisms composing into one property:

1. **A sealed snapshot for each load-bearing file** — the canonical form of `config.toml` (or
   `credentials.toml`) is AES-GCM encrypted under the master key with the snapshot file's own
   path as AAD, and stored as a companion `config_snapshot.enc` file.
2. **An integrity record per caller** — held in daemon-owned storage, naming the current snapshot
   of each load-bearing file by the SHA-256 of the canonical form it seals, or recording the file
   as absent.
3. **Verification at load** — the daemon decrypts the snapshot, compares the canonical form, and
   checks the snapshot is the one the record names, before the file is used. Mismatch, absence of
   a snapshot, a snapshot the record does not name, or a file the record names but that is missing
   is drift.

The property: the daemon never acts on a config file it cannot attribute to its latest authorized
write.

## Decisions

### 1. Path binding via AAD closes the oracle

The previous design sealed the canonical form with `Aad::empty()`. Every seal in the daemon uses
the same master key. Three providers seal caller-supplied bytes verbatim: `jwt_bearer.rs` (the
assertion), `jwt.rs`, and `client_credentials.rs`. An attacker could bootstrap a `jwt-bearer`
credential with assertion bytes equal to the canonical form of a hand-edited config, then copy
`jwt_assertion.enc` over `config_snapshot.enc`. It decrypts, the comparison passes, the
hand-edit is served.

`sealed-file-path-binding` closes this. Every `seal_to_file` call now passes the file's
destination path **relative to the data dir** as AES-GCM AAD. Using the relative destination
means moving the data dir does not break every snapshot. A blob sealed at a different relative
path fails to decrypt when opened as the snapshot — the GCM authentication tag covers the AAD
and decryption with the wrong AAD fails cryptographically.

The attacker cannot strip the AAD: it is not stored in the file but is committed into the
authentication tag. Without the master key, no valid tag can be produced for different AAD.

### 2. The canonical form is built from the typed config struct

Canonicalization runs after deserialization, over `EnvConfig` / `CredentialSource`, never over
TOML text. Comments, key order, whitespace, and quoting style cannot affect a snapshot.

Unknown config keys the struct does not deserialize are invisible to the canonical form. The
record types reject unknown fields — an unknown key is a load error. This means a downgraded
binary cannot load a config a newer binary wrote with a new field; it sees a load error rather
than silently serving wrong state.

### 3. Length-prefixed canonical form

A snapshot proves bytes are unchanged. It proves nothing about the file unless distinct file
states yield distinct bytes (Requirement 1.9). Length-prefixed encoding prevents field names or
values from forging structure:

```
str(x)  = <decimal byte length of x> ":" x LF
form    = str(scheme) str(kind) str(caller-uid) str(relative-path) field*
field   = str(<component count>) str(component)+ str(type) str(value)
type    = "s" (string) | "i" (integer) | "b" (boolean)
```

Fields are sorted by path. Optional absent fields are omitted. List elements keep their order.

### 4. Relative path and caller uid in the form

Requirement 1.7 puts the file's path relative to the data dir and the owner uid at the head of
the form. Without them, copying a file to a different caller root produces the same canonical
form. Using the relative path means moving the data dir does not drift every file — the relative
path is stable within the data dir.

### 5. Canonical form in the payload enables diff display

The snapshot payload is the canonical form bytes sealed directly:

```
ciphertext = AES-256-GCM(master_key, nonce, canonical_form_bytes, aad=snapshot_path)
```

Storing the canonical form (rather than a hash of it) means revalidation can show a diff between
the stored canonical form and the current file, without any additional companion file.

### 6. Refuse daemon writes while drifted

A daemon write that proceeds on a drifted file launders the hand-edit. The sequence: edit
`config.toml`, then trigger any daemon write to that file, and the edit would be sealed without
approval.

Every daemon write path that touches a load-bearing file MUST verify non-drift before proceeding.

The check is one shared step, not one per handler (Requirement 5.8). A handler that writes without
it ratifies a hand-edit in both the snapshot and the integrity record, which defeats Requirement 10
for that caller. The step runs under the same lock as the write it guards, so a write landing
between check and write is either refused or never happens. The same holds for login: it writes no
load-bearing file, but it seals fresh material for whatever the records name, so a planted record
it reads unverified would be sealed and served. Renewal is the same case: it updates no record and
writes no load-bearing file, but it seals material for a credential the records name, so it runs
the check under the per-uid write lock before it seals. Keeping refresh off the record (Rejected
alternatives) is about what refresh writes, not about whether it checks.

### 7. Drift is a context field; refusal is hardcoded pending Cedar

Until `cedar-authz` is implemented, the refusal is hardcoded in the dispatch layer, as presence
shipped. The block SHALL NOT wait on Cedar.

### 8. Ratification pins the contents it presented

A pending revalidation records the SHA-256 of the canonical form it presented as the base state
(Requirement 4.10). An edit after presentation discards the pending revalidation.

### 9. Revalidation addresses the caller root, not an entry

A snapshot seals a whole file, so the smallest unit revalidation can ratify is a file. A
selector naming one environment or credential would still reseal every other entry in that
file, approving edits the approver was never pointed at. `file/revalidate` therefore takes no
selector: the daemon derives the caller root from the peer uid, presents every drifted file in
full as one challenge description, and on approval reseals exactly those files.

The pending operation is `Op::Revalidate { files, deleted, base, replaces_record }`. `files` is
the set the challenge showed as drifted, `deleted` the set it showed as deleted, and
`replaces_record` whether it was raised over a record that would not open (Decision 13). `files` is
the set the challenge showed as drifted, so a file it named as unchanged is never resealed, even if that file's snapshot
goes missing before approval. Its base is the same two-file digest every other gated operation on a
caller root records (`records_base`), so an edit to either file — including one that is not being
resealed — discards it. Apply reads nothing fresh: it
canonicalizes the bytes the approval checked and seals that, so what is sealed is what was
shown even if the file moves between the base check and the seal.

Presentation escapes C0/C1 control characters and ANSI sequences in the daemon, before the text
becomes the challenge description, so every renderer — the requesting client and the `sudo`
approver alike — shows the same escaped text.

### 10. The integrity record pins the snapshots, and custody makes it hold

A snapshot sits in the caller root beside its file, so a caller who can delete or restore the file
can delete or restore the snapshot with it. A sealed snapshot defeats forgery but not that: an
earlier snapshot decrypts as validly as the current one, and a deleted one leaves nothing to check.

The integrity record closes both without changing the snapshot. It holds, per load-bearing file,
the SHA-256 of the canonical form the current snapshot seals, or an absence mark. Verification
adds one comparison: the snapshot that decrypts and matches its file must also be the one the
record names (Requirement 10.4). A restored earlier pair fails it; a deleted file the record names
is drift (Requirement 10.3).

What makes the record hold is where it is kept, not its seal: in storage the caller cannot write
there is no earlier record to restore and no way to delete it. This is `presence-gated-operations`
Decision 8 applied to a second record, chosen from the backend the same way:

| Backend | Record custody |
|---|---|
| `data-protection-keychain` | keychain item `integrity-record`, in the daemon's access group |
| every other backend | `<data_dir>/integrity/<uid>.enc`, beside `callers/`, owned by the daemon's uid: the service account in a system install |

Writes keep the existing order and add one step: file, then snapshot, then record (Requirement
5.6). A crash before the record is updated leaves it naming the earlier snapshot, which is drift —
the same outcome, and the same remedy, as a crash between file and snapshot.

### 11. Deletion is drift

Were deletion read as absence, a same-uid process could delete a credential's entry and sealed
files and bootstrap the same name as a first write — which no gate covers — so the environment
would serve a credential its owner never approved. With the record naming the file, deletion is
drift (Requirement 10.3), and revalidation records an intended deletion as absent (Requirement
4.1). A caller root with no record and no files is unprovisioned (Requirement 10.5).

### 12. Custody is verified, not assumed

Neither the integrity record nor the enrolled-key registry carries a counter or generation, by
design: custody is what stops an earlier copy from being put back. That makes custody load-bearing,
so the daemon checks it rather than trusting that install set it once (Requirement 10.8). If the
owner or mode of `<data_dir>/integrity/` or `<data_dir>/presence/` drifts so that a caller can
write there, restoring an earlier record or registry would re-trust superseded state, such as a
revoked presence key. The daemon refuses rather than repairs: a repair would bless whatever a
caller placed there while custody was broken.

A breach latches until the daemon restarts (Requirement 10.10). Restoring the modes does not
restore trust: while they were wrong, an earlier sealed record or registry could have been put
back, and it verifies as soon as the modes are right again. The daemon cannot tell whether the
window was used, so it asks for an attestation, and on a system install a restart is one, because
only root can restart the service.

The check applies only where the record is a custodied file. A keychain item's custody is the
access group, not a mode bit. The insecure posture has no custody to check; resisting rollback
there would need a counter that cannot itself be rolled back, such as a TPM NV index, which this
spec does not provide.

The check keys on what it observes, not on the posture. Which custody holds the record is chosen
from the backend, in one place, as the registry's is; each path then passes or fails on the owner
and mode the daemon finds on it, measured against its own uid. How the daemon was started is a
claim about the posture, not an observation of it, and a check gated on a claim is skipped
whenever the claim is wrong, which is exactly when it is needed. An observed-owner check needs no
posture at all: in a system install it enforces the service account's custody, and in the
insecure posture, where the daemon runs as the caller, a caller-owned tree passes, which is the
absence of custody Requirement 9.5 already states.

### 13. Every condition is recoverable, and its code says how

Each refusal maps to one next action, and a client should be able to pick it from the error code
without parsing the message (Requirement 11.2). So each condition has its own code:
`CONFIG_DRIFTED` (revalidate), `INTEGRITY_UNVERIFIABLE` (review, then revalidate with disclosure),
and `CUSTODY_BROKEN` (operator action and restart, nothing a client can do). The message still names
the action, for a client that knows only the code's family. Pre-release, a new code costs no
compatibility.

Damage is not key loss (Requirement 2.11). The running daemon holds its master key, so a snapshot
that will not open is damaged or foreign, and is drift (2.4). A record that will not open is
unverifiable, damaged or sealed under another key; the two cannot be told apart and need the same
recovery. Only a key that cannot be obtained is key-unavailable, and that stops the daemon at
startup (2.7), before any request could be refused over it.

An unverifiable record must have a way back, or one corrupt file locks its owner out for good.
The record exists so that ratifying the files on disk is never a side effect; it does not forbid
ratifying them as a decision. Recovery is therefore revalidation (Requirement 4.13): both files
shown in full, under the same presence gate as any revalidation, with a challenge that says there
is no record to compare against, so the approver cannot see what changed or spot a restored
earlier copy. The approval's fingerprint carries `replaces_record`, so an approval shown as a
replacement cannot be applied as an ordinary revalidation, nor the reverse. A custody breach gets
no such path: while it latches, the approver's view itself could have been restored from an
earlier state (Decision 12).

## Rejected alternatives

**No recovery for an unverifiable record.** Safe, but turns one damaged file into a permanent
lockout with no remedy a user can run. Disclosed revalidation ratifies only by decision. Decision 13.

**Reusing `CONFIG_DRIFTED` for every refusal, with the remedy only in the message.** Makes the
client's next action depend on parsing prose, and a custody breach reads as drift. Decision 13.

**Reading deletion as absence.** Lets delete-then-bootstrap substitute a credential without an
approval. Decision 11.

**A monotonic counter.** It detects an earlier copy only if the counter cannot itself be rolled
back, which needs the custody the record already has. With that custody it adds nothing.
Decision 10.

**Replacing the snapshots with one manifest in daemon-owned storage.** Covers sealed credential
files too, but touches every write path including credential refresh, puts a keychain write on
every refresh, and widens an unreadable reference to the whole caller. The integrity record closes
deletion and replay of the load-bearing files with the snapshots unchanged. Decision 10.

**Per-environment or per-credential revalidation.** The snapshot is whole-file, so a narrower
selector reseals more than it names. Splitting the snapshot per entry would make the selector
honest, but multiplies sealed companions and leaves file-level structure (an entry's removal,
Requirement 9.3) without a seal of its own. Decision 9.


**AES-GCM with `Aad::empty()`.** Oracle exposure via shared master key. Decision 1.

**Hash in SecureStorage instead of sealed snapshot.** Avoids the oracle without needing
`sealed-file-path-binding`. But requires a SecureStorage slot per config file (TPM NV space
concern), loses diff display (no canonical form stored), and adds SecureStorage reads on every
load. With path binding available, AES-GCM sealed snapshot is simpler and provides diff display.

**Delimited text canonical form.** User-controlled content can forge delimiters. Decision 3.

**Absolute path in the canonical form.** Moving the data directory drifts everything. Relative
path is stable within the data dir. Decision 4.

**Storing only a hash in the payload.** Would prevent diff display at revalidation. Decision 5.

## Platform considerations

**Custody is per backend, behind one seam.** The record's custody is chosen from the storage
backend, as the enrolled-key registry's is. A future backend adds an arm; verification does not
change. A two-way door.

**Mode bits are the boundary for file custody.** On a system install, POSIX ownership of
`<data_dir>/integrity/` keeps callers out of the record. A platform without mode bits needs an ACL
with the same meaning — no caller identity may write the directory. Per-platform work behind the
same seam.

## Data shapes

A `config.toml` under drift detection — unchanged, no embedded field:

```toml
[environments.work]
credentials      = ["build-cert", "sso-admin"]
identity_type    = "human"
region           = "us-west-2"

[environments.work.sdk]
endpoint_url     = "https://vpce-0abc.execute-api.us-west-2.vpce.amazonaws.com"
```

Its companion `config_snapshot.enc` (AES-GCM ciphertext; plaintext = canonical form bytes,
AAD = path of the snapshot file relative to the data dir).

The integrity record's plaintext, before sealing:

```json
{
  "scheme": "v1",
  "uid": 501,
  "files": {
    "config.toml":      { "snapshot_sha256": "9f2c…" },
    "credentials.toml": { "absent": true }
  }
}
```

Audit fields:

| Field | Source |
|---|---|
| `evidence.config_drifted` | this spec's verification |

## Evaluation order

```
read integrity record ──► unreadable or custody fails ──► unverifiable (Req 11)
          │
load file ──► decrypt snapshot (AAD = snapshot path)
                    │
     no snapshot ───┴─── decrypted OK
          │                     │
       drift             compare canonical bytes
                                │
                    match ──────┴────── mismatch
                      │                    │
           record names this snapshot?   drift
                      │
              yes ────┴──── no
               │             │
             Valid         drift
               │
          build Cedar request (or hardcoded check)
                      │
              allow ──► perform
                      │
              deny ──► salvageable with presence?
                            │
                  drift denies ──── revalidation: gate + re-seal
```

## Correctness properties

1. **No file is used unverified.** Snapshot check precedes use.
2. **Oracle closed.** Path binding prevents credential blob transplant into snapshot slot.
3. **The normal path never drifts.** Every daemon write re-seals or fails.
4. **Daemon writes refuse while drifted.** Laundering prevented.
5. **What is sealed is what was shown.** Revalidation discarded if file changes before approval.
6. **Neither deletion nor a restored pair goes unnoticed** wherever the record's custody holds.
7. **Custody is checked, not assumed.** A broken custody path is refused, never repaired.

## Testing

- **Every write path checks drift.** Enumerate every RPC method that can write a load-bearing
  file or seal material one names, and assert each refuses while its target file is in drift.
  Derive the list from the dispatcher, not a hand-written list, so a new mutating method added
  without the shared check fails the test (Requirement 5.8).
- **Custody failures refuse.** For each path Requirement 10.8 names: a group-writable directory, a
  foreign-owned file, and a symlinked directory. In each case the daemon refuses, and nothing in
  that path is changed afterwards.

## Error handling

| Condition | Behaviour | Criterion |
|---|---|---|
| Canonical form mismatch | drift; service refused | 2.2, 3.1 |
| No snapshot | drift | 2.3 |
| Snapshot fails to open, however damaged | drift | 2.4, 2.11 |
| Master key cannot be obtained | daemon does not start; key recovery named | 2.7 |
| Snapshot OK, credential blob fails | distinct credential-data failure | 2.8 |
| Unknown field in config | load error | Decision 2 |
| File edited between presentation and approval | revalidation discarded | 4.10 |
| Daemon write while drifted | refused; revalidation named | 5.2 |
| Snapshot cannot be sealed | operation fails; config not written | 5.4 |
| Snapshot is not the one the record names | drift | 10.4 |
| File the record names is missing | drift | 10.3 |
| Files or snapshots present, no record | drift | 10.5 |
| Integrity record will not open | `INTEGRITY_UNVERIFIABLE`: nothing served or written for the caller; record left until a disclosed revalidation replaces it | 4.13, 10.6, 11 |
| Integrity record cannot be updated | operation fails | 5.7 |
| Shared drift check cannot run | operation fails; nothing written | 5.8 |
| Custody check fails | `CUSTODY_BROKEN`: nothing governed by the record or registry served, written, or approved; path logged; not repaired; latched until restart; revalidation refused | 10.8, 10.9, 10.10, 11 |
| Renewal while records are in drift or unverifiable | nothing sealed; cached expiry unchanged | 5.8 |

## File changes

| File | Role |
|---|---|
| `crates/credsd-core/src/config/snapshot.rs` | Canonical form, seal, verify (uses `seal_to_file` path-bound AAD from `sealed-file-path-binding`); `assess` consults the integrity record |
| `crates/credsd-daemon/src/server/integrity.rs` | New. Integrity record custody (keychain item or service-owned file), read, update; custody latch; the shared write check and its `Verified` token |
| `crates/credsd-core/src/config/mod.rs` | Unknown-field rejection; canonicalization |
| `crates/credsd-core/src/config/credentials.rs` | Unknown-field rejection; canonicalization |
| `crates/credsd-daemon/src/server/dispatch.rs` | Verify on load; drift guard before every daemon write; custody before each serve and approval |
| `crates/credsd-daemon/src/server/revalidate.rs` | New. Present escaped contents of drifted files, raise the challenge, re-seal on approval; replace an unopenable record with disclosure |
| `crates/credsd-daemon/src/server/presence.rs` | `Op::Revalidate { files, deleted, base, replaces_record }` |
| `crates/credsd-daemon/src/server/write_lock.rs` | `Held` proof the shared check demands |
| `crates/credsd-daemon/src/credential_store.rs` | Shared check before each renewal seal |
| `crates/credsd-daemon/clippy.toml` | Forbids a direct `snapshot::seal`; seals go through `Verified` |
| `crates/credsd-core/src/rpc/mod.rs` | `INTEGRITY_UNVERIFIABLE`, `CUSTODY_BROKEN` domain codes |
| `crates/credsd-core/src/rpc/uds.rs` | Client maps each code to its own error |
| `crates/credsd-daemon/src/authorization.rs` | `config_drifted` context; hardcoded drift forbid |
| `crates/credsd-daemon/src/server/bootstrap.rs` | Re-seal on bootstrap, login, import |
| `crates/credsd-core/src/rpc/methods.rs` | `file/revalidate`, no parameters |
| `crates/credsd/src/main.rs` | `creds revalidate`, no selector |
| `crates/credsd-core/src/credential_status.rs` | Drift status in `list` |
