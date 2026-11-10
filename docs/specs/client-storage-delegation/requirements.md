# Requirements: Client Storage Delegation

**Status:** accepted
**Feature:** `client-storage-delegation`
**Scope:** Remove every client-side access to the platform `SecureStorage`
backend (macOS Keychain, Windows DPAPI/Credential Manager, Linux TPM/file). All
storage access — sealing, unsealing, key load — moves behind the daemon over the
UDS RPC. The client binary (`credsd`) and any other consumer that links
`credsd-core` become pure daemon clients.

## Introduction

credsd protects every at-rest secret with an AES-256-GCM master key held by a
`SecureStorage` backend. The daemon opens that backend at startup
(`server/mod.rs`) and is the intended sole owner of it. Three client-side paths
still open the backend directly by calling
`encryption::init_encryption_with_backend` → `storage::create_storage`:

1. `credsd import` (`cmd_import`, `main.rs`) — seals imported IAM-user keys.
2. An agent-facing enumeration tool linking `credsd-core` — decrypts sealed
   material to report credential freshness.
3. `reauth::login` (`reauth.rs`) — dead code with no binary caller.

Beyond the keychain-hygiene motivation, these paths are **already incorrect** in
the daemon's per-caller model. The daemon reads and writes a *per-uid* config
tree under `callers/<uid>/`; these three paths read and write the *legacy flat*
tree under `config_dir()`. Concretely:

- `cmd_import` writes `config_dir()/credentials.toml` and
  `data_dir()/credentials/<cred>` — a tree the daemon never reads. Imported
  credentials are therefore invisible to the running daemon.
- The enumeration tool loads config via `DaemonConfig::load_with_credentials()` →
  `load_from(config_dir())`, so its reported envs and statuses reflect the flat
  tree, not what the daemon actually serves from `callers/<uid>/`.

Delegating storage access to the daemon is the mechanism that also fixes this
tree divergence: the daemon is the single reader/writer of the per-uid tree, so
routing import and status through it makes the client's view and mutations land
where the daemon serves from.

### Terminology

- **Client** — the `credsd` binary and any consumer that links `credsd-core`,
  including run-time ease-of-use tooling built on the API. Each links
  `credsd-core` but must not open storage.
- **Per-uid tree** — `callers/<uid>/config.toml`, `callers/<uid>/credentials.toml`,
  `callers/<uid>/credentials/<cred>/`. The daemon's authoritative store.
- **Flat tree** — the legacy `config_dir()/…` layout the client paths use today.
- **Storage access** — any call reaching `storage::create_storage`,
  `SecureStorage::{store,retrieve,delete,exists}`, or
  `encryption::init_encryption*` from client code.

## Requirements

### Requirement 1: No client-side storage access

**User story:** As a security reviewer, I want a single process (the daemon) to
hold the master key and touch the platform keystore, so the attack surface for
key exfiltration is one well-scoped service user rather than every invocation of
the CLI.

#### Acceptance Criteria

1.1. Client code SHALL NOT call `encryption::init_encryption`,
     `encryption::init_encryption_with_backend`, `storage::create_storage`, or
     any `SecureStorage` method. This is verifiable by grep: after this change,
     the only non-test references to those symbols SHALL be in
     `credsd-daemon` and in `credsd-core`'s storage/encryption modules
     themselves.

1.2. The daemon SHALL remain the sole opener of the `SecureStorage` backend
     (`server/mod.rs` startup path), unchanged by this feature.

1.3. Any client operation that previously required a decrypt or a seal SHALL
     obtain the result over the UDS RPC instead, or SHALL report a clear
     "daemon required / not reachable" error when the daemon is unavailable.

### Requirement 2: Import through the daemon (`environment/import`)

**User story:** As a user migrating existing `~/.aws/credentials` profiles into
credsd, I want import to seal my keys where the daemon serves them, without the
CLI opening the keychain.

#### Acceptance Criteria

2.1. The client SHALL read and parse the AWS shared-credentials file and the
     AWS config file (`$AWS_CONFIG_FILE`, default `~/.aws/config`) client-side
     (both live under the client's `$HOME`, which the scoped daemon user cannot
     read). A profile's `region` is resolved from the credentials-file key, then
     `--region`, `AWS_REGION`, `AWS_DEFAULT_REGION`, and last the config file.
     Discovery, filtering to complete static-key profiles, and INI parsing SHALL
     remain client-side (existing `import::discover_*` logic), including its
     zeroization of secret material.

2.2. The client SHALL send the discovered profiles to the daemon in a single
     `environment/import` RPC carrying, per profile: name, access key id, secret
     access key, region, and identity type. The RPC SHALL NOT be a streaming
     method (it is non-interactive).

2.3. The daemon SHALL, for each profile, in `callers/<uid>/`:
     seal the key pair (`iam_user::persist_key_pair`), write the `iam-user`
     credential source to `credentials.toml`, and wrap it in a same-named
     one-to-one env in `config.toml` — the same effect as an `iam-user`
     `environment/bootstrap`, but for N profiles under **one** per-uid write lock and
     with a **single** caller-cache eviction after all writes.

2.4. The daemon SHALL skip a profile WHEN its name fails `validate_name`, OR no
     region resolves for it (empty region), OR a credential of that name already
     exists in the caller's `credentials.toml` (import is additive, never a
     clobber). Skips SHALL NOT abort the batch.

2.5. WHEN the request sets `dry_run`, the daemon SHALL evaluate 2.4 against the
     caller's real per-uid tree and return the would-import / would-skip
     decision per profile, and SHALL write nothing.

2.6. The `environment/import` result SHALL report a per-profile outcome
     (imported / skipped-with-reason) so the client can print the summary. The
     daemon SHALL NOT write to the client's stdout/stderr; the client binary
     prints outcomes.

2.7. WHEN the calling uid has no provisioned caller root directory
     (`Denied(NoRoot)` — no `callers/<uid>/` root, i.e. a first-time caller; not
     the root *user*), the daemon SHALL auto-provision `callers/<uid>/owner`
     before writing, matching `environment/bootstrap` behavior. All other deny
     reasons SHALL be refused as not-found.

2.8. WHEN the client finds no importable profiles, it SHALL report that and send
     no RPC.

### Requirement 3: A blocking UDS exchange for synchronous consumers

**User story:** As a consumer running a synchronous loop on an async runtime's
worker thread, I want a blocking UDS exchange, so that I can reach the daemon
without opening storage and without rewriting the loop.

#### Acceptance Criteria

3.1. *Not a core requirement.*

3.2. `credsd-core` SHALL provide a **blocking** UDS exchange for a consumer
     whose synchronous loop runs on a `#[tokio::main]` worker thread and
     therefore cannot `block_on` an async call there.

3.3. *Not a core requirement.*

3.4. *Not a core requirement.*

> Enumerating credentials with their freshness for an agent harness is
> run-time ease-of-use tooling's (see Non-Goals). Such tooling relies on 1.1,
> 1.3, 3.2, and `credential/list`'s daemon-computed status.

### Requirement 4: Remove dead `reauth::login`

**User story:** As a maintainer, I want no unreachable code path that opens the
keychain and writes the wrong (flat) config tree.

#### Acceptance Criteria

4.1. `reauth::login` SHALL be removed, along with any helpers left with no
     remaining caller after its removal.

4.2. Removal SHALL be verified to break no build target and no test. `credsd
     login` / `credsd bootstrap` (no provider) re-auth SHALL continue to work
     via their existing daemon RPCs (`environment/login`), which do not depend on
     `reauth::login`.

### Requirement 5: `--storage-backend` is not supported by the client

**User story:** As a user, I don't want a client flag that silently diverges
from the backend the daemon actually booted with.

#### Acceptance Criteria

5.1. `--storage-backend` is not supported by the
     client; the client opens no storage backend. The daemon's startup-selected
     backend is authoritative for all sealed material.

5.2. No client command SHALL accept `--storage-backend`. Backend selection
     belongs to the daemon, from its own startup config/flags.

### Requirement 6: Security

**User story:** As a security reviewer, I want import's bulk secret material
handled no more exposed than a single-credential `environment/bootstrap` already
is — the same in-memory zeroization, log/`Debug` redaction, and local-socket-only
path.

#### Acceptance Criteria

6.1. Secret access keys carried by `environment/import` SHALL reuse the existing
     zeroizing wire type conventions (as `ProviderParamsIamUser` already does:
     `Zeroize` with the secret field zeroized and redacted from `Debug`).

6.2. The typed secret buffers SHALL zeroize: the client's parse buffers use
     `Zeroizing`, the `ImportProfile` wire type zeroizes its secret on drop
     (Req 6.1), and the daemon's typed material zeroizes after sealing. The
     serialized transport buffers — the JSON `Vec<u8>` written to the socket and
     any intermediate `serde_json::Value` — are NOT scrubbed and hold the secret
     in plaintext until dropped; this matches the existing `environment/bootstrap`
     path and is tracked as a separate hardening follow-up rather than promised
     here.

6.3. No secret value SHALL be logged on either side. Per-profile audit/log lines
     SHALL name the credential and outcome only.

6.4. The UDS authorization model SHALL be unchanged: `environment/import` SHALL be
     subject to the same peer-uid authorization (with the bootstrap-style
     first-time auto-provision of 2.7) as other mutating methods.

## Non-Goals

- **Migrating existing flat-tree data** into the per-uid tree. Users who
  imported under the old client path have data the daemon never read; a separate
  migration (or a re-import) is out of scope here.
- **Changing the retrieval methods** (`get`, `get_batch`, `list`, `describe`) or
  the streaming `environment/bootstrap` / `environment/login` handlers.
- **Changing which backend the daemon selects** or how it selects it.
- **A Windows/named-pipe client transport.** This feature follows the existing
  `#[cfg(unix)]` UDS surface; non-unix client commands remain stubbed as they are
  today.
- **Run-time tooling.** Serving an agent harness, launching a process with
  credentials, and the tools either exposes are run-time ease-of-use tooling,
  future development built on this API. This spec binds such tooling only as a
  client: Requirement 1 and 3.2.
