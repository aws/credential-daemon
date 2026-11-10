# User Experience: Drift Detection

Companion to `requirements.md` and `design.md`. This document shows what a user sees
in every scenario — normal operation, drift detection, recovery, and edge cases.
The approval step is `presence-gated-operations/ux.md` and is identical here.

## Normal path — sealing is invisible

Every command that writes `config.toml` or `credentials.toml` re-seals the snapshot
atomically. Under normal use the user never sees sealing.

```
$ creds config set sdk.endpoint_url https://vpce.example.com --env work
ok
```

## Drift detected — use path (hard block)

```
$ vi $(creds config path)/work/config.toml   # direct edit outside the daemon

$ creds get --env work --format credential-process
error: environment 'work' configuration has drifted from its sealed snapshot
       run: creds revalidate
```

Only the affected env is blocked. Other envs work normally. `creds list` has one row per
credential, not per env: a credential composed into several envs appears once. Per-env
output is not part of `creds list`.

```
$ creds list
CREDENTIAL      MODE               STATUS
build-cert      aws-roles-anywhere DRIFT (config.toml)
gh-token        static-secret      active
```

## Recovery — approval screen

`creds revalidate` takes no selector. A snapshot covers its whole file, so revalidation
addresses the caller root: it presents every drifted file in full, and one approval reseals
them all. A file that has not drifted is named as unchanged and left alone.

```
$ creds revalidate

config.toml has drifted. Current contents:

  [environments.work]
  credentials      = ["build-cert"]
  identity_type    = "human"
  region           = "us-west-2"

  [environments.work.sdk]
  endpoint_url     = "https://evil.example.com"

credentials.toml is unchanged and will not be resealed.

Approving re-seals the contents shown above.

  [Touch ID: "Approve: revalidate drifted config files"]

✓ config.toml revalidated
```

When both files have drifted, both are shown under one approval:

```
$ creds revalidate

config.toml has drifted. Current contents:

  ...

credentials.toml has drifted. Current contents:

  [build-cert]
  type             = "aws-roles-anywhere"
  trust_anchor_arn = "arn:aws:rolesanywhere::999999999999:trust-anchor/attacker"
  profile_arn      = "arn:aws:rolesanywhere::999999999999:profile/attacker"
  role_arn         = "arn:aws:iam::999999999999:role/attacker"

Approving re-seals the contents shown above.

  [Touch ID: "Approve: revalidate drifted config files"]

✓ config.toml, credentials.toml revalidated
```

A deleted file is named as deleted, and approving records it as absent:

```
$ creds revalidate

credentials.toml has been deleted. Approving records it as absent: every credential it named
stops being served.

config.toml is unchanged and will not be resealed.

  [Touch ID: "Approve: revalidate drifted config files"]

✓ credentials.toml revalidated
```

With nothing drifted there is nothing to approve:

```
$ creds revalidate
nothing to revalidate: config.toml and credentials.toml match their snapshots
```

Without a presence key the last step is `sudo creds request approve <id>`. In this path the
elevated process fetches and displays the pending contents itself from the daemon — not
from a client-rendered copy — so an attacker who replaces `creds` cannot control what
the user sees at the approval step. The Touch ID reason string (if shown) is
client-supplied and names the operation only; it is not a complete description of the
contents being approved.

If either file changes between presentation and approval:

```
$ sudo creds request approve req-4c88e2
error: req-4c88e2 discarded — the records it would seal changed after they were shown
       run 'creds revalidate' to review the new state
```

## Credential use under credentials.toml drift

```
$ creds get --env work --format credential-process
error: config drifted: environment 'work' credential sources (credentials.toml) have
       drifted from their sealed snapshot; run: creds revalidate
```

## Master key unavailable — the daemon does not start

The running daemon holds its master key, so no request is ever refused over it. If the key cannot
be obtained (locked keychain, backend change, key loss), the daemon refuses to start and names the
key's recovery (Requirement 2.7). A snapshot that will not open under the key the daemon holds is
damaged or foreign, and is reported as drift (Requirement 2.4), never as a lost key.

After recovering with a new key, nothing sealed under the old one opens: each caller's integrity
record is unverifiable and is recovered as below, and each credential is re-authenticated.

## Integrity record unreadable — disclosed revalidation

If the integrity record cannot be opened (the keychain item unreadable, the file corrupted, or
sealed under another key), the daemon cannot tell which snapshots are current. It serves and writes
nothing governed by the caller's config, and does not rebuild the record from what is on disk on
its own:

```
$ creds get --env work --format credential-process
error: config unverifiable: the integrity record for this user cannot be opened (<reason>),
       so config cannot be verified. Review config.toml and credentials.toml, then run:
       creds revalidate. Approval replaces the record and trusts the files as they are
```

`creds revalidate` is the recovery (Requirement 4.13). Every file present is shown in full as
drifted, under a challenge that says what approval cannot do:

```
replace the integrity record for uid 501, which cannot be opened (<reason>).

There is no record to compare these files against, so this cannot show what changed or tell a
restored earlier copy from the current one. Approving trusts the files exactly as shown below.

config.toml has drifted. Current contents:
  ...
```

It passes the same presence gate as any revalidation. The refusal carries
`INTEGRITY_UNVERIFIABLE`, never `CONFIG_DRIFTED` (Requirement 11.2), so a client can tell that the
revalidation it offers has no comparison behind it.

## Custody broken — operator action and restart

If the custody check fails (Requirement 10.8), nothing governed by the record or the enrolled-key
registry is served, written, or approved, and the refusal outlasts the repair until the daemon
restarts (Requirement 10.10):

```
$ creds get --env work --format credential-process
error: integrity custody broken: custody of the integrity record or enrolled-key registry is
       broken (<path and reason>); nothing they govern is served, written, or approved. An
       operator must restore ownership and modes, inspect the record and registry, and restart
       the daemon
```

The code is `CUSTODY_BROKEN`. No client action is offered, revalidation included.

## `creds list` under drift

```
$ creds list
CREDENTIAL      MODE               STATUS
build-cert      aws-roles-anywhere DRIFT (config.toml)
api-key         static-secret      DRIFT (credentials.toml)
gh-token        static-secret      active
```

## Operations table

| Operation | config.toml drifted | credentials.toml drifted |
|---|---|---|
| `creds get --env <e>` | blocked | blocked |
| `creds config set/unset` | blocked | allowed |
| `creds config get` | allowed (warning deferred) | allowed |
| `creds list` | allowed — shows DRIFT | allowed — shows DRIFT |
| `creds bootstrap` (existing) | blocked | blocked |
| `creds bootstrap` / `creds import` (new entry) | blocked | blocked |
| `creds revalidate` | allowed — this is the remedy | allowed |

## Security notes for implementers

### Write ordering and atomicity

True two-file atomicity is not achievable on POSIX without a write-ahead log. The
implementation minimizes the drift window via:

1. **Atomic single-file writes.** Each file is written to a temp path then
   `rename()`d into place. A crash during a write leaves the old version intact;
   there is never a partially-written `config.toml` or `config_snapshot.enc`.

2. **Config before snapshot.** Within a write operation, `config.toml` is
   fsynced and renamed first; `config_snapshot.enc` follows. This ordering means:

   | Crash point | Result |
   |---|---|
   | Before config rename | Both files old — consistent, valid |
   | After config, before snapshot | Config new, snapshot old — **drift** |
   | After snapshot, before integrity record | Snapshot new, record names the old one — **drift** |

   The drift case is correct: the config genuinely changed. The user runs
   `creds revalidate`, which is also the path for any intentional hand-edit.

3. **Missing snapshot is drift.** Req 2.3 treats absence the same as mismatch. A crash that
   leaves `config.toml` without its companion `config_snapshot.enc` surfaces as drift on the
   next load; the user runs `creds revalidate` to re-seal. This is the same path as any
   intentional hand-edit, and it prevents the laundering attack (delete snapshot, edit file,
   trigger a daemon write to re-seal without approval).

The window between the two renames is sub-millisecond under normal conditions.
An attacker who can inject a file between the two renames is already operating
at a level of access that this mechanism does not protect against.

### Display escaping

Hand-edited values do not pass through `config set` validation; revalidation is the first
point at which they are rendered. The implementation SHALL escape C0 and C1 control
characters and ANSI escape sequences before displaying file contents or a diff. An
unescaped terminal control sequence in a config value could misrepresent what the user is
approving.

### DoS resistance

A same-uid process can call `touch config.toml` in a loop, and each mtime change triggers a
reload and a snapshot decrypt. Requirement 2.9 permits caching the SHA-256 of the last verified
canonical form so that a tight `touch` loop costs hash computations only; the daemon does not
cache it yet, so each reload decrypts.

Deletion of `config_snapshot.enc` causes a drift error on every credential request until
the owner revalidates. This denies service but
does not silently reroute credentials — it is visible and self-correcting once the owner
responds.

### Snapshot payload

The snapshot seals the canonical form bytes directly with the snapshot file's path as AES-GCM
AAD:

```
ciphertext = AES-256-GCM(master_key, nonce, canonical_form_bytes, aad=snapshot_path)
```

On mtime-triggered freshness checks the daemon decrypts and compares canonical forms. The daemon
MAY cache the canonical form hash in memory after first load to skip re-decryption when the
config file's mtime changes but the hash hasn't (DoS resistance against rapid `touch` loops).

### Replay and deletion — detected where custody holds

A same-uid process that saved a legitimately sealed `(config.toml, config_snapshot.enc)` pair and
restores both later is detected: the snapshot decrypts and matches its file, but it is not the
snapshot the integrity record names. Deleting a file the record names is detected the same way.
Neither can be hidden by also restoring or deleting the record, because the record is held where
the caller cannot write.

| Install | Restored pair | Deletion |
|---|---|---|
| Signed `--user` (keychain custody) | detected | detected |
| System install | not reachable by the caller's uid | not reachable by the caller's uid |
| Insecure posture (caller-writable record) | not detected | not detected |

In the insecure posture the record is a file the caller can restore or delete together with the
config, so neither is detected; the daemon's startup warning says so.

Restoring an earlier sealed credential file (a token, a key) is outside this spec.

## Deferred UX

These UX flows are planned but not in scope for the initial implementation.

### Warning on config read (deferred)

Future: `creds config get` on a drifted env carries a warning so the user knows the
value is unapproved. Current behavior: read succeeds silently; only credential
operations are blocked.

### Diff view during revalidation (deferred)

A diff (old canonical form from snapshot vs. current file) is deferred. The canonical form
stored in the snapshot enables it as a future enhancement; for v1, full current contents only.
