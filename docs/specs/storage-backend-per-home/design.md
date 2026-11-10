# Design: storage backend as a per-home property

## Overview

The backend a home was sealed with is recorded in that home's `config.toml`
`[storage]` section and is authoritative for the home's lifetime. `serve` reads
it before initializing encryption: on a fresh home it resolves a backend from the
seed (flag > env > auto-detect) and writes it; on an initialized home it uses the
recorded value and refuses to start if a flag/env asks for a different one. A
`--home` option turns a directory into a complete instance (home + derived socket
+ derived log) so one daemon per backend can run side by side. Backends whose
secret lives outside the home (`kkrs` in the kernel keyring; macOS keychain /
Secure Enclave) key that secret by an instance namespace derived from the home so
two homes do not collide.

The plist/systemd argument is one way a home gets *seeded*; it is validated
against the record like any other seed and is not itself authoritative.

## Interim implementation note

An interim security fix ships ahead of the full
design. It provides the security-critical subset without the config.toml record:

- `install` always resolves the backend and writes `--storage-backend <name>` into
  the service definition (plist / unit). The baked flag is the current authority.
- `serve` gates on `--storage-backend` being present; no auto-detect path at
  serve-time.
- `init_encryption_with_backend` checks other compiled backends for an existing key
  before minting a new one; refuses if another holds the key (inline with Req 3).
- `instance_namespace` (Decision 5) keys the master-key slot (Req 5.1) and the two
  keychain slots that hold per-home daemon state: the integrity record and the
  enrolled-key registry (Req 5.1a).

The design below remains the full target. Until the config.toml record exists, the
baked plist/unit arg IS the authority rather than a seed validated against a record
(the resolve-table in Decision 2 is the target behavior, not the current one).

The master key slot is `daemon-encryption-key.{ns}`, keyed like the per-home slots
(Req 5.1). Without it, two homes on one machine under the same backend shared a master
key and each could open the other's sealed blobs at the same relative path. The rename
orphans every credential sealed under the old name; pre-launch, existing installs
re-bootstrap rather than migrate.

## Key Design Decisions

### 1. The record lives in the home-root `config.toml`, in a `[storage]` section

`DaemonConfig` (`config/mod.rs`) serializes to the home-root
`data_dir()/config.toml` (`DaemonConfig::config_path()`) and carries a
`[storage]` section:

```toml
[storage]
backend = "tpm"   # concrete resolved name, never "auto"
```

`DaemonConfig` carries `storage: Option<StorageConfig>` with a single
`backend: Option<String>` field. A missing `[storage]` / missing key reads as
"not yet recorded", the first-serve trigger (Req 1.1). The daemon does not load
config globally — each caller's config loads per-uid (`server/mod.rs`) — so the
record is read and written through a targeted home-root seam:
`config::storage_backend(dir) -> Option<Backend>` and
`record_storage_backend(dir, Backend)` (Req 1.4).

The record is complementary to the kkrs **sentinel** and tpm **sidecar**: those
track the master key's *state* (boot identity / sealing policy); `[storage].backend`
tracks *which backend owns the home*. On recovery the recorded backend is what
tells the key-init path which store to purge and re-seal into.

### 2. `serve` resolves the backend before touching encryption

`serve` resolves the backend before initializing encryption
(`server::start`, `server/mod.rs`):

```
recorded = config::storage_backend(data_dir())
seed     = select_backend_arg (flag)
backend  = resolve(recorded, seed)?    // see state table
init_encryption_with_backend(backend)
```

`resolve(recorded, seed)`:

| recorded | seed | outcome |
|---|---|---|
| none | Some(b) | use `b`; **record it** (Req 1.1) |
| none | none | `b = auto_detect()`; use + **record** `b` (Req 1.1–1.2) |
| Some(r) | none | use `r`, no warning (Req 2.2) |
| Some(r) | Some(r) | use `r`, confirming no-op (Req 2.3) |
| Some(r) | Some(b≠r) | **error, refuse to serve** (Req 3.1–3.3) |

The record write happens *before* `init_encryption_with_backend` so a home is
never left with sealed blobs but no record; the conflict error is returned before
any store is constructed so a refused serve has no side effects (Req 3.2).

### 3. Conflict fails; it never falls through to recovery

A different seed against a recorded home is an operator mistake, not a lost key.
Serving anyway would construct the wrong store, fail to unseal, and trigger the
purge-and-re-seal recovery path — silently destroying cached credentials. So the
conflict is caught at resolve time and returns `DaemonError::config` naming both
backends and pointing at the re-seal path, and recovery is never entered on this
branch (Req 3.3). In-place migration is deliberately a separate, explicit command
(Req 3.4) and not part of serve.

### 4. `--home` derives a complete instance

A `--home <path>` flag on the daemon sets `CREDSD_DATA_DIR` (the same mechanism
`--config-dir` uses, `main.rs`) and, when the respective override is absent,
derives:
- socket → `<path>/credsd.sock`
- log → `<path>/credsd.log`

Explicit `--socket`/`CREDSD_SOCKET` and `--config-dir`/`CREDSD_DATA_DIR` take
precedence over the derived values (Req 4.3); `--home` is a defaulting layer over
those knobs, not a separate resolution path. This makes the side-by-side test a
two-liner:

```
credsd serve --home /tmp/home-tpm  --storage-backend tpm
credsd serve --home /tmp/home-kkrs --storage-backend kkrs
```

### 5. Instance namespace for out-of-home secrets

Define a stable per-home discriminator:

```
ns = hex(truncate(sha256(canonical(data_dir())), 8))   // 16 hex chars
```

Path-derived, so it needs no stored state, is stable across restarts of the same
home, and differs between homes (Req 5.1–5.2). Backends consume it:

- **kkrs** — keyring description incorporates `ns`:
  `"{SERVICE_NAME}:{ns}:{key_id}"` (`SERVICE_NAME` at `storage/mod.rs:19`). Two
  homes → two descriptions → no shared/clobbered key.
- **secure-enclave / keychain (macOS)** — the item's account name incorporates
  `ns`. Not the access group: that is one fixed entry of the daemon's
  `keychain-access-groups` entitlement, and per-home groups would mean per-home
  entitlements. The group is the custody boundary and the name is not, so the
  name is the part that can carry `ns` and the part whose carrying it costs
  nothing.
- **file** — the master-key slot is named `daemon-encryption-key.{ns}` like every
  other backend's, so one rule covers all backends (Req 5.1). The sealed blobs
  themselves stay in the home; the slot name is what two homes would otherwise share.
- **tpm** — same master-key slot naming for its sealed key file. It MUST NOT pin a fixed
  machine-global persistent handle or NV index two homes would share (Req 5.3) — transient
  handles or an `ns`-derived index instead.

Beyond the master key, two keychain slots hold per-home daemon state and are
keyed the same way (Req 5.1a): `integrity-record.{ns}.{uid}`, one per caller
root, and `presence-enrolled.{ns}`, one per home. Each describes files or
approval authority belonging to one home, so the home is in the name.

`ns` is derived by resolving the deepest existing ancestor of the home path and
appending the remainder, rather than by `canonicalize` alone. A home yields the
same `ns` before and after it is created, and a symlinked prefix (`/var` →
`/private/var`) resolves to one home rather than two.

The walk goes component by component. While a prefix exists it is resolved by the
filesystem, so a `..` after an existing prefix steps up from the resolved directory,
as the kernel would. Once a component is missing, the rest is applied lexically: `.`
is dropped and `..` removes the previous missing component; a `..` with no missing
component before it steps up from the resolved prefix, as above. At hash time a missing
component is not a symlink, so this matches what the path names once it is created as
a directory. The guarantee holds only if no missing component is later created as a
symlink: a component created as a symlink changes what the path resolves to, so the
home derives a different `ns` and its earlier slots are unreachable (the relocation
case in Req 5.1). Without
it, a home such as `/tmp/new/../home` would hash differently before and after
`/tmp/new` exists, and creating the home would orphan its slots (Req 5.2).

This design owns the *contract* (the `ns` derivation and the rule that
out-of-home slots must be keyed by it). Each backend spec implements it
(Req 5.4); see the compatibility section.

## Correctness properties

- **P1 — first serve is idempotent in its record.** Serving a fresh home twice
  in a row records the same concrete backend both times and the second serve
  takes the "recorded, no seed" path. *Validates: 1.1, 1.2, 2.1.*
- **P2 — recorded beats auto-detect.** Given a recorded backend, no serve path
  invokes `auto_detect()`. *Validates: 2.1.*
- **P3 — conflict is inert.** A serve whose seed differs from the record returns
  an error and constructs no store, opens no key, reads no credential, and does
  not modify the home. *Validates: 3.1–3.3.*
- **P4 — matching seed is a no-op.** A serve whose seed equals the record neither
  warns nor rewrites `config.toml`. *Validates: 2.3.*
- **P5 — `--home` isolation.** Two `serve --home` instances with different homes
  and different backends resolve distinct sockets, distinct records, and (for
  kkrs) distinct keyring descriptions. *Validates: 4.1, 5.1, 5.2.*
- **P6 — override precedence.** An explicit `--socket` alongside `--home` yields
  the explicit socket, not the derived one. *Validates: 4.3.*

## Error handling

- Missing / unreadable home-root `config.toml` on read → treated as "no record"
  (first-serve), not a hard error, consistent with the tolerant
  `read_if_present` loader used for config.
- A `[storage].backend` naming an unknown/unavailable backend → the
  `select_backend` validation error (`storage/mod.rs:105`), surfaced at resolve
  time before encryption init.
- Backend conflict (Req 3.1) → `DaemonError::config`, message names recorded vs
  requested and the re-seal path; no recovery, no partial write.
- Record write failure after resolving a fresh backend → hard error before
  encryption init, so a home is never sealed without its record.

## File changes

| File | Change |
|---|---|
| `crates/credsd-core/src/config/mod.rs` | Add `StorageConfig { backend }`, `storage` field on `DaemonConfig`, and `storage_backend(dir)` / `record_storage_backend(dir, Backend)` helpers (targeted home-root read/write, comment-preserving like the env writers). |
| `crates/credsd-core/src/storage/mod.rs` | Add `instance_namespace(dir) -> String` (sha256-of-canonical-path, truncated). Thread `ns` into backend construction where relevant. |
| `crates/credsd-daemon/src/server/mod.rs` | Resolve the backend (Decision 2) and write the record before `init_encryption_with_backend`. |
| `crates/credsd-daemon/src/main.rs` | Add `--home`; derive socket/log defaults; keep explicit overrides winning. |
| `crates/credsd/src/main.rs` | Add `--home` symmetrically for client socket derivation; `import` resolves the backend from the home record rather than the raw flag. |
| `crates/credsd-daemon/src/install.rs` | Seed the record at install (write `[storage].backend`); the baked plist arg is a seed, not the authority. |

## Compatibility contract for the pending backend specs

This spec is orthogonal to but must be compatible with `tpm-encryption-backend`,
`kkrs-encryption-backend`, and the secure-enclave work. Each must absorb one
item:

- **kkrs** — namespace the keyring description by `ns` (Decision 5). This
  resolves the open "how do two kkrs instances not collide" question; without it
  filesystem isolation is a lie for kkrs. The kkrs recovery/purge helper keys off
  the home path, so it composes.
- **tpm** — the sealed blob is named by the `ns`-keyed slot like every backend's
  (Req 5.1), and avoids any fixed machine-global persistent handle / NV index two
  homes would share (Req 5.3).
- **secure-enclave (macOS)** — namespace the keychain item label / access-group
  by `ns`, same as kkrs.

The `[storage].backend` record also gives all three a durable, explicit home for
their "explicit opt-in, no silent fallback" guarantee: the operator's choice is
the seed written on first serve, auto-detect runs only when seeding a fresh home,
and a conflicting later flag errors instead of silently downgrading.
