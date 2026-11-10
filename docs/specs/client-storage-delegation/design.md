# Design: Client Storage Delegation

**Status:** accepted
**Feature:** `client-storage-delegation`
**Requirements:** `docs/specs/client-storage-delegation/requirements.md`

## Overview

The daemon is the sole owner of the platform keystore. It opens the
`SecureStorage` backend at startup, holds the AES-256 master key, and is the only
process that seals, unseals, or reads sealed material. The client — the `credsd`
binary and any consumer that links `credsd-core` — is a pure daemon client: it calls
neither `create_storage`, `init_encryption*`, nor any `SecureStorage` method. The
only non-test references to those symbols are in `credsd-daemon` and in
`credsd-core`'s `storage/` and `encryption.rs` modules, enforced by a source-scan
test.

Every client operation that needs sealed material obtains it over the UDS RPC:

- `credsd import` parses the AWS shared-credentials and config files client-side — they live
  under the caller's `$HOME`, which the scoped daemon user cannot read — and sends
  the discovered profiles to the daemon over `environment/import`. The daemon seals
  each key pair and writes the per-uid tree, so imported credentials land where
  the daemon serves them.
- A consumer that enumerates credentials with their freshness — run-time
  ease-of-use tooling serving an agent harness, for instance — sources them from
  the daemon (`credential/list`), over a blocking UDS call when it runs a
  synchronous loop. It reads no per-uid config and opens no storage.

These build on primitives the daemon already provides: `rpc::uds::call` (the
client transport), the per-uid seal-and-write behind `environment/bootstrap`, and the
per-uid freshness `status_of` surfaces through `list`/`describe`. `environment/import`
is one new non-streaming method over those primitives, and enumeration reuses the
existing `credential/list`.

## Key design decisions

### 1. Batched `environment/import`, not a loop of `environment/bootstrap`

Import today is "parse the whole file once, then loop the writes." The batched
method preserves that shape while moving the write loop server-side:

- **One** per-uid write lock (`bootstrap_lock(uid)`) held across all N writes,
  vs N acquire/release cycles.
- **One** `evict_caller(uid)` after the batch, vs N evictions each forcing a
  caller-state reload.
- Dedupe (`validate_name` + already-exists) and `dry_run` are evaluated once,
  server-side, against the caller's real `credentials.toml` — the only place
  that view is authoritative. A client-side loop would evaluate dedupe against a
  tree the daemon doesn't serve, reintroducing the divergence this feature
  removes.

The per-profile seal+write reuses `bootstrap_iam_user`'s internals; the batch
handler is a loop over the same primitives under a single lock.

### 2. Synchronous consumers use a blocking UDS exchange

A consumer may run a synchronous `loop` — over stdin, for instance — called from
a `#[tokio::main]` async `main`, so it runs on a runtime worker thread. Calling
the async `rpc::uds::call` there is not possible: `block_on` from within a
runtime context panics, and making the whole loop async is a larger refactor
than a consumer should have to carry.

Decision: `call_blocking` is a **synchronous** entry point that runs the same
async `rpc::uds::call` on a fresh current-thread runtime inside a dedicated
`std::thread`, bounded by a timeout. The dedicated thread carries no ambient
runtime, so building one there is legal where `block_on` on the worker would
panic; reusing `call` means there is one socket-exchange implementation, so wire
format and error mapping cannot drift.

*(Alternatives considered: a second socket exchange built on
`std::os::unix::net::UnixStream` — rejected because a hand-written copy of the
framing and error mapping drifts from `call`; and `spawn_blocking` +
`Handle::block_on` — rejected because it complicates the entrypoint and still
requires an ambient runtime the sync loop does not have.)*

### 3. Enumeration sources from `credential/list`, no new status method

`credential/list` already returns each credential's `environment`, `kind`, and
daemon-computed `status`, so a consumer builds its enumeration from that one call
— it never reads the per-uid tree (unreadable under a system install, where it is
`0700` and owned by the scoped daemon user) and opens no storage. No new
daemon-side status surface is introduced. How a consumer shapes that enumeration
is not a core decision.

## Architecture

### Import flow (after)

```
credsd import
  └─ client: import::discover_aws_profiles(path, region)   [reads $HOME/.aws/credentials and $HOME/.aws/config]
  └─ client: build ImportParams { profiles: [ {name, akid, secret, region, itype}, … ], dry_run }
  └─ client: rpc::uds::call(socket, "environment/import", &params, "import")
        └─ daemon dispatch → import handler:
             authorize_for_bootstrap(peer)         [auto-provisions on NoRoot]
             lock = bootstrap_lock(uid).lock().await
             for p in profiles:
                 decide(p.name, &p.region, existing) [validate_name + no-region + already-exists]
                 if dry_run or skip: record outcome, continue
                 persist_key_pair(enc, caller_root/credentials/<name>, akid, secret)
                 upsert_credential_at(caller_root/credentials.toml, name, IamUser{…})
                 append same-named 1:1 env to caller_root/config.toml
                 record outcome
             evict_caller(uid)
             return ImportResult { outcomes: [ {name, status, reason?}, … ] }
  └─ client: print per-profile outcomes + summary to stderr
```

The daemon never reads the client's `~/.aws/credentials`; the client never opens
storage.

## Components and interfaces

### 1. New method `environment/import` (`credsd-core/src/rpc/methods.rs`)

New `Method::ProfileImport` variant and wire types:

```rust
pub struct ImportParams {
    pub profiles: Vec<ImportProfile>,
    #[serde(default)]
    pub dry_run: bool,
}

// Reuses the zeroizing conventions of ProviderParamsIamUser.
#[derive(Zeroize)]
pub struct ImportProfile {
    #[zeroize(skip)] pub name: String,
    #[zeroize(skip)] pub access_key_id: String,
    pub secret_access_key: String,       // zeroized; redacted from Debug
    #[zeroize(skip)] pub region: String,
    #[zeroize(skip)] pub identity_type: Option<String>,
}

pub struct ImportResult { pub outcomes: Vec<ImportOutcome> }
pub struct ImportOutcome {
    pub name: String,
    pub status: ImportStatus,            // Imported | Skipped | WouldImport | WouldSkip
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
```

`Method::ProfileImport` is routed in the **non-streaming** `dispatch::handle`
arm (like `config_set`), not the `uds.rs` streaming path used by bootstrap/login.

### 2. Import handler (`credsd-daemon/src/server/`)

Add `handle_profile_import(request, peer, daemon)`:

- `let uid = authorize_for_bootstrap(peer)?;` (reuses the bootstrap authorizer so
  first-time callers auto-provision — Req 2.7).
- Acquire `daemon.bootstrap_lock(uid)` once.
- Load the caller's existing `credentials.toml` (per-uid) for the dedupe check.
- Loop profiles: `decide()` (lift `validate_name` + already-exists from
  `import.rs::decide`), then on import seal + write via the same primitives
  `bootstrap_iam_user` uses. Collect outcomes.
- `evict_caller(uid)` once after the loop.
- Return `ImportResult`.

The seal+write per profile is factored so both `bootstrap_iam_user` and the
import loop call it (avoid duplicating the persist/upsert/env-append sequence).

### 3. Client `cmd_import` (`credsd/src/main.rs`)

- Keep the discovery call (`import::discover_aws_profiles`) client-side.
- Map `Discovered` → `ImportProfile`, build `ImportParams`, call
  `rpc::uds::call(socket, "environment/import", …)`.
- No client-side provisioning: the daemon auto-provisions `callers/<uid>/owner`
  on the first authorized request, exactly as `environment/bootstrap` does.
- Print outcomes from `ImportResult` to stderr; summary line as today.
- Drop the `EncryptionService` and `--storage-backend` usage here.

### 4. Blocking transport helper (`credsd-core/src/rpc/uds.rs`)

`call_blocking<P, R>(socket, method, params, subject) -> Result<R>` is the
synchronous entry point for a consumer whose loop runs on a runtime worker
thread and can neither `.await` nor `block_on` there. Rather than a second
copy of the socket exchange, it runs the same async `call` on a current-thread
runtime inside a dedicated `std::thread` (which carries no ambient runtime, so the
nested runtime is legal), bounded by a timeout so an unresponsive daemon cannot
wedge the loop. Wire format and error mapping are `call`'s, by construction.

### 5. Enumeration tool

*Not a core component.*

### 6. Delete `reauth::login` (`credsd-core/src/reauth.rs`)

Remove `pub async fn login` and any helper (e.g. an unused targets resolver) with
no remaining caller. `reauth_one` / `resolve_reauth_targets` are retained only if
still referenced; otherwise removed too. Verify with build + test.

### 7. `--storage-backend` cleanup (`credsd/src/main.rs`)

Remove the flag from `import` handling and from the `login`/`bootstrap`
signatures that already ignore it (`_storage_backend`). The `sb` binding at the
dispatch site is removed if it has no remaining consumer. Daemon backend
selection is untouched.

## Data models

Wire additions live in `credsd-core/src/rpc/methods.rs` alongside the existing
`Provider*` params, reusing `Zeroize` derives. No storage-layer types change.

## Correctness properties

1. **No client storage access.** grep for `create_storage` / `init_encryption` /
   `SecureStorage` outside daemon + storage/encryption modules returns only test
   references. *(Req 1.1 — enforceable as a test or CI grep.)*
2. **Import lands in the served tree.** After `credsd import`, a subsequent
   `credsd list` (daemon-backed) shows the imported credentials. *(Fixes the
   flat-vs-per-uid divergence.)*
3. **Additive import.** A profile whose name already exists per-uid is skipped,
   not clobbered; the batch continues. *(Req 2.4.)*
4. **Dry-run writes nothing.** `dry_run` returns would-import/would-skip and the
   caller's tree is byte-identical before and after. *(Req 2.5.)*
5. **First-time import provisions.** Import from a never-bootstrapped uid
   provisions `callers/<uid>/owner` and succeeds. *(Req 2.7.)*
6. *Not a core property.*
7. **Secret non-exposure.** `ImportProfile` zeroizes its secret and redacts it
   from `Debug`; no secret appears in logs on either side. *(Req 6.)*

## Error handling

- `environment/import`: `validate_name` failure and already-exists are *per-profile
  skips*, not batch errors. A seal or file-write failure for one profile is an
  `Internal` domain error that aborts the batch (the caller retries); the per-uid
  lock guarantees no interleaving with a concurrent write.
- Client `import`: a transport error from `call` maps through `error_to_daemon`
  as other client commands do.

## Testing strategy

- **Daemon unit/integration** (`server/bootstrap.rs` / dispatch tests): import a
  batch into a temp `callers/<uid>/`; assert credentials.toml + config.toml +
  sealed dirs; assert dedupe skip, dry-run no-write, first-time provisioning,
  and single eviction.
- **Import mapping** (`import.rs`): discovery/parse tests already exist and stay;
  add `Discovered → ImportProfile` mapping coverage.
- **Blocking transport** (`rpc::uds`): round-trip `call_blocking` against a
  throwaway UDS echo of the daemon codec; assert parity with async `call` error
  mapping.
- **Regression grep test** for property 1.
- Build + full test after `reauth::login` deletion (Req 4.2).

## File changes

| File | Change |
|---|---|
| `credsd-core/src/rpc/methods.rs` | New `Method::ProfileImport`, `ImportParams`, `ImportProfile`, `ImportResult`, `ImportOutcome`, `ImportStatus`. |
| `credsd-core/src/rpc/uds.rs` | New `call_blocking` (runs the async `call` on a current-thread runtime in a dedicated `std::thread`, under a timeout). |
| `credsd-core/src/import.rs` | Keep discovery/parse; factor `decide` so the daemon reuses it (or move dedupe to daemon); drop `run(EncryptionService)`. |
| `credsd-core/src/reauth.rs` | Delete `login` and now-unused helpers. |
| `credsd-daemon/src/server/dispatch.rs` | Route `Method::ProfileImport` in `handle`. |
| `credsd-daemon/src/server/bootstrap.rs` | Add `handle_profile_import`; factor the per-credential seal+write out of `bootstrap_iam_user` for reuse. |
| `credsd/src/main.rs` | `cmd_import` → RPC; print outcomes; remove `--storage-backend` from `import` (and the ignored `_storage_backend` on login/bootstrap); drop `sb` if unused. |

## Security considerations

- The socket now carries bulk IAM secret material on import. This is the same
  material `environment/bootstrap` already carries for a single iam-user credential;
  the wire type reuses its zeroizing/redaction. The socket is the existing
  peer-authenticated UDS — no new exposure surface.
- Removing client storage access shrinks the key-exfiltration surface to the
  daemon's service user. A compromised CLI invocation can no longer read the
  master key or sealed material directly; it can only ask the daemon, subject to
  UDS authorization.
- `reauth::login` removal eliminates a code path that both opened the keychain
  and wrote the wrong tree — a latent correctness and audit gap.
