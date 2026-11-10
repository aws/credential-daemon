# Storage backend as a per-home property

**Status:** draft (spec phase — approval means "proceed to implementation")

> **Interim implementation shipped.**
> Before the full config.toml-record design is implemented, three security-critical
> behaviors are in place:
> - `install` resolves and bakes `--storage-backend <name>` into the plist / systemd
>   unit, so the daemon is always started with an explicit backend (covers the
>   spirit of Reqs 1–2 at install time rather than at first-serve time).
> - `serve` refuses to start without `--storage-backend` (closes the silent
>   auto-detect path).
> - `init_encryption_with_backend` refuses to mint a new key when another compiled
>   backend already holds one (covers Req 3's conflict-refusal intent).
> - `instance_namespace` keys the two keychain slots holding per-home daemon state,
>   the integrity record and the enrolled-key registry (Req 5.1a), and the master-key
>   slot (Req 5.1). Renaming the master-key slot orphans every credential sealed under
>   the old name; pre-launch, existing installs re-bootstrap rather than migrate.
>
> These are interim controls; the full design (Reqs 1–5 below) is the target.
> Until the config.toml record is implemented, the baked plist / unit arg IS the
> backend authority — the design's "seed validated against a config.toml record"
> model is not yet active.

## Introduction

The encryption-key storage backend (`keychain`, `dpapi`, `credential-manager`,
`tpm`, `file`, and the `kkrs` / secure-enclave backends) seals the master key,
and the master key seals every credential blob under a home — a data directory
holding `config.toml`, the `callers/<uid>/` trees, and the sealed blobs. Those
blobs are decryptable **only** by the backend that sealed them. The backend is
therefore a property of the home for its entire lifetime, not of a process
invocation: a home served with a different backend than the one that sealed it
cannot unseal its blobs and would fall into the reboot/unseal recovery path
(purge + re-seal), destroying the cached credentials.

This spec makes that property explicit and durable. A home records its backend in
`config.toml` the first time it is served; later serves read the recorded value
rather than re-choosing it, and a flag or environment variable naming a different
backend is refused rather than silently applied. A `--home` option bundles a data
directory, its socket, and its log into one instance, so a single machine can run
one instance per backend — the primary use being to exercise `tpm`, `kkrs`, and
(on macOS) secure-enclave side by side. Backends whose secret lives outside the
home (the kernel keyring for `kkrs`; the macOS keychain / Secure Enclave) key that
secret by a per-home namespace so two homes on one machine do not collide.

## Terminology

- **Home** — a data directory (`data_dir()`, overridable via `CREDSD_DATA_DIR`,
  `--config-dir`, or the new `--home`). Holds `config.toml`, the `callers/<uid>/`
  trees, and the sealed credential blobs.
- **Home backend** — the storage backend recorded in a home's `config.toml`
  `[storage]` section. Authoritative for that home's lifetime.
- **Seed** — a `--storage-backend` flag supplied when a home has no recorded
  backend yet; it initializes the record.
- **Instance namespace** — a stable discriminator derived from the home, used by
  backends whose secret does not live inside the home (kernel keyring, macOS
  keychain / Secure Enclave) so two homes on one machine do not collide.

## Requirements

### Requirement 1: First serve records the backend

**As** an operator, **I want** the first `serve` against a fresh home to settle
the backend once, **so that** the decision is durable and not re-litigated per
process.

1.1. WHEN `serve` starts against a home whose `config.toml` has no `[storage]`
     backend recorded, THEN the system SHALL resolve the backend from the seed
     (explicit `--storage-backend` > auto-detect) and
     SHALL write it to `config.toml` `[storage].backend` before initializing
     encryption.

1.2. The recorded value SHALL be the concrete resolved backend name (never
     "auto"), so a later read is unambiguous even if auto-detection would now
     resolve differently.

1.3. WHEN the home has no `config.toml` at all, THEN first serve SHALL create it
     with the `[storage]` section, owned and permissioned as the daemon's other
     home-root files are.

1.4. Recording the backend SHALL NOT depend on loading the full per-caller
     config model; it is a targeted read/write of the home-root `config.toml`.

### Requirement 2: Subsequent serves use the recorded backend

**As** an operator, **I want** later serves to honor what the home was
initialized with, **so that** I cannot silently corrupt it by passing a
different flag.

2.1. WHEN `serve` starts against a home with a recorded `[storage].backend`,
     THEN the system SHALL initialize encryption with the recorded backend and
     SHALL NOT re-run auto-detection.

2.2. WHEN no seed is supplied, THEN the recorded backend SHALL be used with no
     warning.

2.3. WHEN a seed (flag or env) is supplied that **equals** the recorded backend,
     THEN it SHALL be treated as a confirming no-op (no warning, no rewrite).

### Requirement 3: Conflict handling

**As** an operator, **I want** a mismatched backend to be refused, not silently
applied, **because** applying it is destructive.

3.1. WHEN a seed (flag or env) is supplied that **differs** from the recorded
     backend, THEN the system SHALL refuse to serve and SHALL exit with a
     configuration error naming both the recorded and the requested backend and
     stating that changing a home's backend requires an explicit re-seal.

3.2. The refusal in 3.1 SHALL happen before any encryption initialization, key
     access, or credential read, so a conflicting serve has no side effects.

3.3. The system SHALL NOT silently fall back to the recovery/purge path on a
     backend conflict — a conflict is an operator error to correct, not a lost
     key to recover from.

3.4. An explicit re-seal path (decrypt-under-old, re-seal-under-new, rewrite the
     record) MAY be provided as a separate command; it is out of scope for the
     serve path and is a Non-Goal of this spec beyond leaving room for it.

### Requirement 4: `--home` bundles a home instance

**As** a developer, **I want** one flag that defines a complete instance, **so
that** I can run one daemon per backend without wiring several paths by hand.

4.1. The daemon SHALL accept `--home <path>` that sets the home (`data_dir`) and,
     unless separately overridden, derives the socket at `<path>/credsd.sock`
     and the log at `<path>/credsd.log`.

4.2. `--home` SHALL compose with `--storage-backend` so that
     `serve --home <path> --storage-backend <b>` seeds a fresh home per Req 1 and
     is validated per Req 2/3 thereafter.

4.3. Explicit `--socket` / `CREDSD_SOCKET` and `--config-dir` /
     `CREDSD_DATA_DIR` SHALL take precedence over the values `--home` derives, so
     a home path and an explicit socket/data-dir compose predictably.

4.4. A relative `CREDSD_DATA_DIR` / `CREDSD_CONFIG_DIR` in effect for the daemon,
     `install` included, SHALL be rejected with a configuration error that names the
     variable and says it must be absolute. The daemon SHALL NOT start, and SHALL NOT
     fall back to the platform default home. A relative `CREDSD_SOCKET` is ignored
     because that fails loudly and writes nothing: the client cannot reach a daemon
     and no file is created. Ignoring a relative data directory does not fail
     loudly: the daemon would home on the platform default and mint a new master key
     there, which is the failure 4.5 exists to prevent. A relative path also names a
     different home from each working directory (Req 5.2). This requirement covers the
     daemon binary; the client's handling of `CREDSD_SOCKET` is unchanged.

4.5. A system install run under a data-dir override SHALL carry that directory into
     the service definition (the launchd plist or systemd unit). The installer mints
     the master key under the override, so a daemon started on the platform default
     home would look in a slot no key was minted into.

### Requirement 5: Per-home namespacing for all backends

**As** a developer running two homes at once, **I want** each home's key material
and daemon state isolated, **because** a slot named the same on one machine is one
slot to every home that reads it, whether or not its secret is stored in the home.

5.1. Every backend SHALL key its master-key slot by an **instance namespace**
     derived deterministically and stably from the home. This applies uniformly,
     including backends whose secret lives inside the home (`file`, `tpm`), so one
     rule covers every backend and no backend's slot name is a bare, shared constant.
     Because the namespace is derived from the home's path, every slot, including an
     in-home one, belongs to that path: relocating a home (a rename, a restore to a
     different path, a changed `$HOME`) is not supported, and a home whose path
     changes SHALL be bootstrapped again rather than migrated.

5.1a. The same SHALL hold for every slot such a backend holds on a home's
      behalf, not only the master key. The integrity record (`drift-detection`
      Requirement 10.2) and the enrolled-key registry
      (`presence-gated-operations` Decision 8) each describe one home's state and
      outlive the home wherever they are slots rather than files, so each SHALL
      be keyed by the instance namespace. A slot whose name does not distinguish
      the home is read by the next home as its own, and the state it describes —
      which files a caller root should hold, which keys may approve — is then
      applied to a home it was never about.

5.2. The instance namespace SHALL be stable across restarts of the same home and
     distinct between two different homes on the same machine and uid. It SHALL
     give one home the same answer whether or not that home exists on disk yet,
     so creating a home does not orphan the slots already keyed to it. This holds
     for a home path that contains `.` or `..` segments, including ones that
     pass through a directory that does not exist yet.

5.3. Backends SHALL NOT rely on any machine-global, home-independent handle that two
     homes would share (e.g. a fixed TPM persistent handle or NV index). The
     namespace in 5.1 is the only machine-global discriminator a backend uses for its
     slots; a sealed blob that lives in the home is isolated by the home directory and
     its slot is still keyed by the namespace (5.1).

5.4. This spec defines the namespacing **contract**; each backend spec
     (`kkrs-encryption-backend`, `tpm-encryption-backend`, secure-enclave) SHALL
     satisfy it in that backend's own design.

## Non-Goals

- **Arbitrary many instances / a general instance manager.** The goal is one
  home per backend, primarily for development and testing. Two homes of the
  *same* backend on one machine need not be made ergonomic, and nothing here
  promises they can serve concurrently. This bounds the ergonomics, not Req 5:
  that requirement is unconditional, so two such homes still isolate from each
  other, and a second home is still an unprovisioned one rather than one holding
  another home's state.
- **Online backend migration.** Changing a home's backend in place (Req 3.4) is
  left to a future explicit re-seal command; this spec only reserves the
  behavior and refuses the unsafe silent path.
- **Reconciling `--storage-backend` on client verbs.** How the flag behaves on
  daemon-backed verbs (`get` and the like), which do not initialize
  encryption, is an adjacent ergonomics concern tracked separately. This spec
  defines only the serve-time home model.
- **Changing which backend auto-detect picks.** The precedence change specified
  by the tpm/kkrs specs (Linux auto-detect errors instead of defaulting to
  `file`) is theirs; here auto-detect is only invoked as a seed for a fresh home.
