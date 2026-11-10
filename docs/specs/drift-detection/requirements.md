---
status: accepted
created: 2026-09-30
---

# Requirements: Drift Detection

**Depends on:** `sealed-file-path-binding` (complete) — path binding is what closes
the oracle attack on the snapshot (see Requirement 1.3). `presence-gated-operations` — supplies
the gate that revalidation passes through, and the custody rule (its Decision 8) the integrity
record is held under.

## Summary

The daemon's authority over a credential rests on records it does not exclusively write. A
caller's `config.toml` and `credentials.toml` are files on a filesystem, owned by the uid whose
credentials they describe, and reachable by every process running as that uid. A process that
edits them directly changes what the daemon serves and to whom, without the daemon ever
authorizing the change.

This spec seals each load-bearing file's canonical form as an AES-GCM encrypted companion
(`config_snapshot.enc`, `credentials_snapshot.enc`) using the master key and the companion
file's own path as AAD. Any change to the config file outside the daemon is detected by
decrypting the snapshot and comparing the stored canonical form to the current file.

A snapshot proves the daemon sealed a canonical form. Held beside its file, it cannot prove that
form is the latest one the daemon sealed, or that a missing file was meant to be missing: whoever
can delete or restore a file can delete or restore its snapshot too. Each caller therefore also has
an **integrity record**, held in daemon-owned storage, naming the current snapshot of each
load-bearing file or recording that the file is absent. A deleted file, or a file restored together
with an earlier snapshot, no longer matches the record and is in drift.

## Install shape scope

Snapshots and the integrity record work the same way on every install. What differs is where the
record is held, and so what it protects against:

| Install | Integrity record custody | Deletion and restore by a same-uid process |
|---|---|---|
| Official signed `--user` (macOS LaunchAgent, `data-protection-keychain`) | a keychain item in the daemon's access group | detected: the process can write the caller root, not the record |
| System install (macOS LaunchDaemon, Linux system unit) | a sealed file owned by the `credsd` service account, outside every caller root | not reachable: `callers/<uid>/` is owned by the service account at 0700 |
| Insecure posture (open-source build running as the caller) | a sealed file the caller can write | not detected; the user is warned (`presence-gated-operations` Requirement 7.8) |

The signed `--user` install is the shape this spec protects. On a system install the caller's uid
cannot reach these files at all; the mechanism runs unchanged so behaviour is the same everywhere.

## Threat model

The adversary is a process running under the same OS uid as the credential owner, on the
protected install shape. It can read, write, delete, and restore every file in that uid's caller
root, including earlier copies it saved. It cannot read the master key or write to the data
protection keychain without the daemon's code signature.

The goal is detection and refusal, not prevention.

## Terminology

- **Load-bearing file** — `config.toml` or `credentials.toml` for a caller root.
- **Canonical form** — a load-bearing file's deterministic byte serialization, covering every
  field that changes what the daemon serves or whom it serves it to.
- **Sealed snapshot** — the load-bearing file's canonical form encrypted under the master key
  with the snapshot file's path as AES-GCM AAD, stored as a companion file.
- **Integrity record** — one per caller: for each load-bearing file, the SHA-256 of the canonical
  form its current snapshot seals, or a mark that the file is absent. Sealed under the master key
  and held in daemon-owned storage.
- **Daemon-owned storage** — storage no caller uid can write, as `presence-gated-operations`
  Decision 8 defines it.
- **Drift** — the state of a load-bearing file whose canonical form does not match its snapshot,
  that has no snapshot, whose snapshot is not the one the integrity record names, or that the
  record names but that is missing. Drift is the one condition revalidation remedies. An
  unverifiable caller root and an unavailable master key are not drift (Requirement 11).
- **Unverifiable** — the state of both load-bearing files in a caller root whose integrity record
  cannot be read or opened (Requirement 10.6), or whose custody check fails (Requirement 10.8).
- **Per-uid write lock** — the one lock every daemon write into a caller's root holds, so that
  writes to one caller root never interleave.
- **Renewal** — the daemon obtaining fresh credential material from a provider and sealing it for
  a credential `credentials.toml` names, whether on a background schedule or on demand while
  serving a request.
- **Revalidation** — the gated operation that re-seals the snapshot with the current canonical
  form, by which an owner attests to the file's present contents.

## User Experience

What a user sees is in `ux.md`. The approval step is `presence-gated-operations/ux.md`.

## Requirements

### Requirement 1: Every load-bearing file is sealed as an encrypted snapshot

#### Acceptance Criteria

1.1. For each load-bearing file, the daemon SHALL maintain a companion sealed snapshot.
     The companion files are `config_snapshot.enc` (beside `config.toml`) and
     `credentials_snapshot.enc` (beside `credentials.toml`).

1.2. The snapshot SHALL be stored as a companion file adjacent to the config file it seals.
     It SHALL NOT embed a signature or seal inside the config file itself.

1.3. The snapshot SHALL be AES-256-GCM encrypted under the master key. The snapshot file's
     destination path **relative to the data dir** SHALL be passed as AES-GCM AAD. Using the
     relative destination (not the absolute path) means moving the data dir does not invalidate
     every snapshot. This is what closes the oracle attack: any sealed file produced at a
     different relative path fails to decrypt when opened as the snapshot, because AES-GCM
     authentication covers the AAD and decryption with the wrong AAD fails. **This requirement
     depends on `sealed-file-path-binding` being in effect — without it, the oracle attack is
     live. The AAD convention (relative destination path, purpose tag, scheme version, uid)
     must be settled once in the generic backends spec; this spec and `sealed-file-path-binding`
     both defer to it.**

1.4. The sealed payload SHALL be the canonical form bytes directly:
     ```
     ciphertext = AES-256-GCM(master_key, nonce, canonical_form_bytes, aad=snapshot_path)
     ```
     Storing the canonical form enables diff display at revalidation without additional storage.

1.5. The canonical form SHALL be a deterministic byte serialization of the config file's loaded
     structure. Comments, map key order, whitespace, and quoting style SHALL NOT affect it.

1.6. The canonical form SHALL include every field whose value changes what the daemon serves or
     whom it serves it to. For `config.toml`: all environment entries, ordered credential lists,
     identity types, SDK/CLI projection settings, and access control fields. For
     `credentials.toml`: every credential's source type and provider configuration.

1.7. The canonical form SHALL include the file's path relative to the data dir and the owner uid,
     so that copying a file to a different caller root produces a different canonical form.
     Using the relative path (not the absolute path) means moving the data dir does not drift
     every file — the relative path is stable within the data dir.

1.8. An environment's ordered credential list SHALL be canonicalized in order.

1.9. The canonical form SHALL be unambiguous: two file states that differ in any included field
     SHALL produce different bytes. Length-prefixed encoding is used to prevent field names or
     values from forging structure.

### Requirement 2: Drift is detected on load, before the file is used

#### Acceptance Criteria

2.1. The daemon SHALL verify a load-bearing file's snapshot when it loads the file, before the
     file is used for any purpose.

2.2. A file whose canonical form does not match the snapshot SHALL be in drift.

2.3. A file carrying no snapshot SHALL be in drift. Absence SHALL NOT be an exemption.

2.4. A snapshot that fails to open under the daemon's master key — wrong AAD, corrupted or
     truncated ciphertext, or sealed under another key — SHALL place its file in drift. A running
     daemon holds its master key, so a snapshot that will not open is never a key-unavailable
     condition (Requirement 2.7).

2.5. Drift SHALL be determined per load-bearing file.

2.6. The daemon SHALL detect drift introduced while it is running. Detection happens when a
     caller's files are loaded (Requirement 2.1): on the caller's first request after the daemon
     starts, after the caller's state is evicted, and when a load-bearing file changes
     (Requirement 2.9). A change that touches only a snapshot or the integrity record is detected
     at the next load at the latest, and by any operation under Requirement 5.8 that runs before
     then.

2.7. WHEN the master key cannot be obtained (locked keychain, backend change, key loss), the
     condition is key-unavailable. It SHALL be reported when the daemon starts, which it SHALL
     refuse to do, and SHALL name the key's recovery as the remedy; it is never a per-request
     refusal. Because credential blobs, snapshots, and integrity records are sealed under the
     same key, recovering with a new key leaves none of them able to open: each caller's record
     is then recovered under Requirement 4.13, and each credential re-authenticated
     (Requirement 2.8).

2.8. WHEN a snapshot decrypts and drift check passes but a credential blob subsequently fails to
     decrypt, the daemon SHALL report a distinct credential-data failure, separate from drift.
     Re-authentication is required for that credential.

2.9. The daemon MAY cache the canonical form hash in memory after first successful load to avoid
     re-decrypting the snapshot on every mtime-triggered check (DoS resistance against rapid
     `touch` loops). The cache SHALL be invalidated when the caller state is evicted.

2.10. A load-bearing file that does not parse SHALL be in drift. Every file the daemon writes
      parses, so one that does not was modified after its last seal. Revalidation cannot seal a
      file with no canonical form, so the refusal SHALL say to correct or restore the file and
      then revalidate.

2.11. Damage to a snapshot and damage to the integrity record SHALL NOT be reported as
      key-unavailable; only a master key that cannot be obtained is (Requirement 2.7). A snapshot
      that will not open is drift (Requirement 2.4). A record that will not open is unverifiable
      (Requirement 10.6), whether it is damaged or was sealed under another key: the two cannot be
      told apart, and both are recovered the same way (Requirement 4.13).

### Requirement 3: Drift blocks credential operations

#### Acceptance Criteria

3.1. WHEN a `config.toml` is in drift, THEN the system SHALL NOT serve any credential governed
     by that config.

3.2. WHEN a `credentials.toml` is in drift, THEN the system SHALL NOT serve any credential whose
     source is in that file.

3.3. A drift refusal SHALL name the drifted file and SHALL state that revalidation is the
     remedy. A refusal for any condition that is not drift follows Requirement 11 instead.

3.4. There SHALL NOT be a flag, environment variable, or parameter that bypasses drift refusal.

3.5. A drifted file SHALL remain enumerable. `credential/list` SHALL report it with drift status.

3.6. Drift SHALL NOT cause the system to delete, rewrite, or quarantine the file.

3.7. Reading a drifted config value SHALL be allowed (warning deferred — see Deferred Features).
     Credential material SHALL NOT be returned for a drifted file.

3.8. WHEN a selection composes credentials from a drifted file alongside undrifted ones, THEN
     the system SHALL refuse the selection.

3.9. Refusal on drift SHALL NOT be salvageable by presence. Revalidation is the only remedy.

### Requirement 4: Revalidation is the only way to ratify a file, and it is gated

#### Acceptance Criteria

4.1. The system SHALL provide an operation, spelled `revalidate`, that re-seals the snapshot of
     every drifted load-bearing file in the caller's own caller root with its current canonical
     form, and for a drifted file that has been deleted, records it in the integrity record as
     absent.

4.2. Revalidation SHALL be a gated operation. It SHALL NOT complete on the caller's uid alone.

4.3. Revalidation SHALL address a caller root as a whole. It SHALL NOT accept a narrower
     selector such as an environment or a credential: a snapshot covers its whole file, so
     ratifying one entry's contents would ratify every other edit in the same file.

4.4. BEFORE soliciting a verifier, the system SHALL present the full current contents of every
     file the revalidation would seal, and SHALL name every file it would record as deleted. The
     contents SHALL be the challenge's description. A
     load-bearing file that is not in drift SHALL be named as unchanged and SHALL NOT be resealed.
     A diff view (old canonical form vs. current file) is deferred; the canonical form in the
     snapshot enables it as a future enhancement.

4.5. Revalidation SHALL seal the contents that were presented under Requirement 4.4.

4.6. WHEN no load-bearing file in the caller root is in drift, revalidation SHALL succeed without
     raising a challenge and SHALL leave every snapshot as it was.

4.7. The caller root revalidated SHALL be the one owned by the caller's uid, as the daemon derives
     it from the connection's peer credentials. No parameter SHALL name a caller root.

4.8. WHEN the gate is not satisfied, the file SHALL remain in drift.

4.9. WHEN revalidation addresses several files, one gate SHALL cover the set.

4.10. The base state SHALL be a digest of both load-bearing files' bytes as presented, including
      a file that is not resealed. WHEN either file is edited between presentation and approval,
      the revalidation SHALL be discarded unperformed.

4.11. WHEN revalidation proceeds through `sudo creds request approve <id>`, the elevated process SHALL
      fetch and display the pending file contents directly from the daemon rather than
      rendering a client-supplied description. The daemon's rendering is the authoritative
      display; a replaced or wrapped `creds` binary that shows benign contents cannot
      substitute for it. The Touch ID reason string is client-supplied and SHOULD name the
      operation and caller root but SHALL NOT be relied on as a complete description; this
      limitation is accepted.

4.12. The display of file contents during revalidation SHALL escape control characters
      (C0 and C1 ranges), Unicode format characters (general category Cf, except the joiners
      ZWNJ and ZWJ), and ANSI escape sequences before rendering. Hand-edited values
      do not pass through `config set` validation and this is the first point at which
      they are rendered to a user.

4.13. WHEN the integrity record cannot be opened (Requirement 10.6), revalidation SHALL be its
      recovery. With nothing recording what either file should hold, every load-bearing file
      present SHALL be shown in full as drifted, and a file absent with a snapshot beside it as
      deleted. The challenge SHALL disclose that the record cannot be opened, that there is no
      record to compare the files against, and that approval trusts them exactly as shown, so it
      cannot reveal what changed or tell a restored earlier copy from the current one. It passes
      the same presence gate as any revalidation. Approval SHALL build the record afresh from what
      it reseals, and SHALL be refused, unperformed, if the record opens by then. Revalidation
      SHALL NOT be a remedy for a custody breach (Requirement 10.10).

### Requirement 5: Every daemon write re-seals the snapshot

#### Acceptance Criteria

5.1. Any daemon operation that writes a load-bearing file SHALL re-seal the companion snapshot
     in the same operation.

5.2. BEFORE writing a load-bearing file, the daemon SHALL verify the file is not in drift. A
     daemon write SHALL NOT proceed while its target file is in drift. This prevents a
     concurrent hand-edit from being laundered: edit `config.toml`, trigger any daemon write to
     that file, and the edit would otherwise be sealed without approval.

5.3. The config file SHALL be written first; the snapshot SHALL follow. A crash after the config
     write but before the snapshot write leaves the snapshot stale — ordinary drift, which is
     the correct outcome for any config change. The user runs `creds revalidate`, same path as
     any intentional hand-edit.

5.4. WHEN the snapshot cannot be sealed, the daemon SHALL fail and SHALL NOT write the config.

5.5. A daemon operation that writes several load-bearing files SHALL re-seal a snapshot for each.

5.6. Any daemon operation that re-seals a snapshot SHALL update the integrity record in the same
     operation, after the snapshot. A crash after the snapshot but before the record leaves the
     record naming the earlier snapshot — ordinary drift, remedied by `creds revalidate`.

5.7. WHEN the integrity record cannot be updated, the daemon SHALL fail the operation.

5.8. Every daemon operation that writes a load-bearing file, or seals material a load-bearing
     file names, SHALL perform the Requirement 5.2 check, and the Requirement 10 comparison,
     through a single shared verification step, immediately before the write and under the
     caller's per-uid write lock, held across both the check and the write. This covers at least
     environment bootstrap, import, and login; credential removal; environment removal;
     `config set` and `config unset`; the commit of an approved request; revalidation; and
     renewal, background and on demand. Revalidation's base check (Requirement 4.10) is its form
     of this check. An operation that cannot perform the check, or whose check fails, SHALL fail
     and SHALL NOT write. A refused renewal seals nothing and leaves the cached credential's
     expiry where it was.

### Requirement 6: Only the verified load path reads load-bearing files

#### Acceptance Criteria

6.1. No daemon code path that reads a load-bearing file and uses its contents to make a serving
     decision SHALL do so without first verifying drift. Direct reads that bypass the verified
     load (e.g. `config/get`, the `envs_using` guard in `credential/remove`) SHALL either be
     routed through the verified load or shown to not affect serving decisions.

### Requirement 7: Drift is evidence, and refusal is policy

#### Acceptance Criteria

7.1. The request context SHALL carry whether the subject file is in drift, derived by the daemon
     from its own verification.

7.2. Revalidation SHALL be a distinct action.

7.3. The refusal in Requirement 3 SHALL be expressed as a built-in policy rule. Until
     `cedar-authz` is implemented, the refusal SHALL be hardcoded in the dispatch layer, as
     presence shipped with authorization hardcoded pending Cedar. The block SHALL NOT
     wait on Cedar.

7.4. The built-in floor SHALL forbid serving credentials from a drifted file, and SHALL forbid
     revalidation without verified presence.

### Requirement 8: Drift decisions are auditable

#### Acceptance Criteria

8.1. A refusal under Requirement 3 SHALL emit an audit record.

8.2. Every audit record for an evaluation whose subject is a load-bearing file SHALL carry the
     file's drift state.

### Requirement 9: The detection boundary is stated

#### Acceptance Criteria

9.1. A snapshot covers load-bearing metadata. Tamper-detection on credential blobs is AES-GCM's
     job. Location-binding for the snapshot is `sealed-file-path-binding`'s job; that spec binds
     the snapshot file's path as AES-GCM AAD. Credential blobs do NOT yet have location binding —
     an owner's uid can swap `.enc` blobs between credentials on the protected install shape.
     Location binding for credential blobs belongs in a pending generic backends spec that states
     AAD invariants (purpose tag, scheme version, uid, destination path relative to data dir) as
     requirements on every seal under the master key. This spec SHALL NOT be read as providing
     location binding for credential blobs until that spec lands.

9.2. Deletion of a load-bearing file is detected by the integrity record (Requirement 10.3), not
     by the file's own snapshot.

9.3. Removal of a credential from an environment's membership places that environment in drift.

9.4. The daemon's own root configuration is not a load-bearing file under this spec.

9.5. Replay of a load-bearing file is detected where the integrity record's custody holds. An
     attacker who archives a legitimately sealed `(config.toml_v1, config_snapshot_v1.enc)` pair
     and restores both is caught because the restored snapshot is not the one the record names
     (Requirement 10.4). Restoring an earlier record is prevented by its custody, not its seal. In
     the insecure posture the record is a file the caller can restore, and the system SHALL NOT
     claim replay resistance there. Replay of sealed credential files is outside this spec.

9.6. Upgrade: a caller root written before the integrity record existed has snapshots and no
     record, so it is in drift on the first daemon start after upgrade (Requirement 10.5). This is
     acceptable pre-release. There is no automatic recording on upgrade; that would launder any
     attacker-placed state. A record held under a slot name that no longer identifies the home
     (Requirement 10.2) reads as no record and reaches the same state by the same remedy: the
     unreachable record is not carried forward under the new name, since nothing outside the
     record says which home it was for.

9.7. Downgrade: a newer daemon may write a config using a canonical form version an older binary
     does not recognize. An older binary SHALL treat it as drift rather than silently re-sealing
     under an older canonical form.

### Requirement 10: Each caller's snapshots are pinned by an integrity record

#### Acceptance Criteria

10.1. The daemon SHALL maintain one integrity record for each caller root that holds a
      load-bearing file. For each load-bearing file it SHALL hold either the SHA-256 of the
      canonical form the file's current snapshot seals, or a mark that the file is absent.

10.2. The integrity record SHALL be sealed with AES-256-GCM under the master key and held in
      daemon-owned storage: under the `data-protection-keychain` backend, a keychain item in the
      daemon's access group; under every other backend, a file outside every caller root, in a
      directory the daemon's service account owns, with its path relative to the data dir as AAD.
      It SHALL NOT be held inside the caller root it describes, and SHALL record the caller's uid.

      A record SHALL describe exactly one caller root in one home. Where the record is a file it
      is inside the home and dies with it. Where it is a keychain item it outlives the home, so
      the item's name SHALL carry the home's instance namespace (`storage-backend-per-home`
      Requirements 5.1-5.3) and the caller's uid. A record written for one home SHALL NOT be read
      as another home's, and the uid a record names SHALL be checked against the slot it was
      found in.

10.3. A load-bearing file that the integrity record names but that is missing SHALL be in drift.
      Deletion SHALL NOT read as absence.

10.4. A load-bearing file whose snapshot verifies but seals a canonical form whose SHA-256 differs
      from the integrity record SHALL be in drift.

10.5. A caller root that holds a load-bearing file or a snapshot and has no integrity record SHALL
      be in drift. A caller root that holds neither and has no record SHALL be unprovisioned, not
      in drift. "No record" means no record for that caller root in that home: a first write to a
      second home on a machine where another home holds records is unprovisioned, since no record
      describes the files it is about to write.

10.6. WHEN the integrity record cannot be read or opened, THEN the daemon SHALL treat both
      load-bearing files in that caller root as unverifiable and SHALL serve nothing governed by
      them. It SHALL NOT discard, replace, or rebuild the record from the files on disk, which
      would ratify whatever they hold, except through the approved revalidation of Requirement
      4.13, whose disclosure is what makes ratifying them a decision rather than a side effect.
      No other write is a remedy: bootstrap would replace the record without that disclosure.

10.7. The integrity record SHALL be held under the custody rule of `presence-gated-operations`
      Decision 8, the same rule that holds the enrolled-key registry: custody, not the seal, is
      what prevents an earlier record from being restored. That rule fixes where a record is
      held, not under what name. A keychain item's custody is its access group, which the name
      does not weaken, so the scoping Requirement 10.2 puts in the name is independent of it.

10.8. Wherever the integrity record is a file under Requirement 10.7, the daemon SHALL verify, at
      startup and before each read of the record, that the record's directory, the enrolled-key
      registry's directory, and every ancestor of those directories up to and including the data
      dir are owned by the daemon's own uid (or root), are not writable by group or other, and
      are not symlinks. The same SHALL hold for each file inside those directories. WHEN any
      check fails, THEN the daemon SHALL serve nothing governed by the integrity record or the
      registry, SHALL log which path failed and why, and SHALL NOT repair ownership or modes
      itself. The daemon SHALL decide whether this check applies from the record's custody, and
      what each path passes from the owner and mode it observes on that path. It SHALL NOT decide
      either from the posture: not from how the daemon was started (such as `credsd serve
      --system`) and not from an inference about the install. In a system install the daemon's
      uid is the service account, so the check holds the record and registry to the custody of
      Requirement 10.7. In the insecure posture the daemon's uid is the caller's, so a
      caller-owned tree passes, and the check adds nothing to Requirement 9.5. In an official
      user-scoped install the record is a keychain item, whose custody is its access group, and
      this check does not apply. "System install", "official user-scoped install", "insecure
      posture" and "service account" are as `presence-gated-operations` defines them.

10.9. A custody breach is any of these, on any path Requirement 10.8 names: the path is a
      symlink; it is owned by a uid other than the daemon's own or root; it is writable by
      group or other; or it exists and cannot be examined. A breach SHALL take effect immediately:
      the daemon SHALL check custody before each serving decision, each write under Requirement
      5.8, and each approval, as well as at startup and before each read of the record.

10.10. A custody breach SHALL latch. Once the daemon observes one, it SHALL stay in force until the
       daemon restarts, even after ownership and modes are restored. While custody was broken, an
       earlier sealed record or registry could have been put back, and it would verify once
       custody is restored. On a system install, restarting the daemon requires root, so a restart
       is the operator's attestation that custody is restored and the record and registry were
       inspected. In any other posture a restart is not a root action and attests nothing; there
       the latch holds the refusal only for the life of the process. Revalidation is no remedy
       while the latch holds.

### Requirement 11: Each refusal names its own condition and remedy

#### Acceptance Criteria

11.1. A refusal to serve or to write SHALL report exactly one of these conditions, and only that
      condition's remedy:

| Condition | Arises from | Remedy the refusal states | Code |
|---|---|---|---|
| Drift | Requirement 2.2, 2.3, 2.4, 2.10, 10.3, 10.4, 10.5 | `creds revalidate` (Requirement 3.3); for a file that does not parse, correct or restore it first (Requirement 2.10) | `CONFIG_DRIFTED` |
| Unverifiable record | Requirement 10.6 | review both files, then `creds revalidate`, whose approval replaces the record (Requirement 4.13) | `INTEGRITY_UNVERIFIABLE` |
| Custody breach | Requirement 10.8, 10.9 | an operator restores custody, inspects the record and registry, and restarts the daemon (Requirement 10.10); no client action is offered | `CUSTODY_BROKEN` |
| Credential-data failure | Requirement 2.8 | re-authenticate that credential | existing credential codes |

A master key that cannot be obtained is not in this table: it stops the daemon at startup
(Requirement 2.7), so no request is refused over it.

11.2. Each condition in Requirement 11.1 SHALL be reported under its own error code, so a client
      can infer the next action from the code alone, and its message SHALL name that action. No
      condition SHALL be reported under another's code: a custody breach reported as drift would
      offer revalidation where Requirement 10.10 forbids it, and an unverifiable record reported
      as drift would hide that its revalidation trusts the files without a comparison.

## Non-Goals

- **Preventing the edit.** A process with write access can change the file.
- **Backup restore.** A user restoring their own backup is a different case from an attacker
  replaying an old approved pair (which is Requirement 9.5). These are not the same non-goal.
- **Authenticating sealed credential blobs.** Tamper-detection is AES-GCM; path-binding is
  `sealed-file-path-binding`.
- **Proving presence.** That is `presence-gated-operations`'.
- **The policy engine.** That is `cedar-authz`'.
- **Replay of sealed credential files.** Restoring an earlier sealed token is not detected by
  this spec.
- **The insecure posture.** The integrity record has no custody to back it there (Requirement 9.5).

## Relationship to adjacent specs

**`sealed-file-path-binding` (complete, prerequisite).** Landed before this spec was
implemented. Path binding via AES-GCM AAD is what closes the oracle attack on the snapshot.
Together these two specs mean routing metadata and material blobs are each bound to their
on-disk locations.

**`presence-gated-operations`.** This spec is a consumer twice over. Revalidation is a gated
operation; its description is the current contents of the files it would seal (Requirement 4.4),
and its base state is a digest of the load-bearing files' bytes as presented (Requirement 4.10).
The integrity record is held under that spec's custody rule (its Decision 8). Neither spec needs
the other's internals: the gate does not know what the record holds, and this spec does not know
which verifier satisfied a revalidation.

**`storage-backend-per-home` (draft).** A backend change that cannot carry the master key
leaves existing snapshots unreadable. Because credential blobs are also sealed under the same
key, all credentials in the caller root are inaccessible. The remedy is re-bootstrap (Req 2.7),
not revalidation — re-sealing also requires the key.

## Deferred Features

### Warning on config read for drifted envs

`creds config get` on a drifted env currently succeeds silently. Future: carry a warning.

### Separate `creds envs list` and `creds credentials list`

Tracked separately; out of scope for drift detection.
