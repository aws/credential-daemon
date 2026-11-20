---
status: accepted
created: 2026-08-26
spec: credential-retrieval-api
---

# Design Document: Credential Retrieval API

## Overview

`requirements.md` settles the protocol (JSON-RPC 2.0, line-delimited, Requirement 9), the
method surface (five names, Requirement 10), and the per-carrier exposure matrix
(Requirement 13). This document covers what those leave to implementation: where the code
lives, which module owns the envelope, how a request becomes a dispatch, how a `DaemonError`
becomes a wire failure, and how caller identity is re-sampled per request.

It also discharges the three questions the requirements explicitly delegate here:

| Delegated question | Where asked | Answer |
|---|---|---|
| Do the three JSON-RPC surfaces share **one** envelope implementation or three hand-rolled ones? | Dependencies, final bullet | One. `src/rpc` is it; MCP keeps only MCP-specific payloads. See [One envelope](#one-envelope-not-three). |
| Relationship between `credential/list` and the Manifest | Req 13 AC 7 | Already settled in `requirements.md` (two methods, 2026-08-24). Recorded here as the module layout that follows from it. |
| Whether domain failures are `error` objects or result-with-flag | Open Decision 5 | `error` objects with the domain code in `error.data.code`; the MCP adapter translates to `isError` at its own boundary. Implemented. |

**Scope boundary.** This design does not settle Open Decision 1's surviving half (which
boundary applies when profile and credential disagree), Open Decision 2 (scope on
aggregates), or Open Decision 4 (Manifest authorization). Those gate behavior, and the
[Deferred](#deferred-by-open-decisions) section states what an increment must therefore
refuse to build rather than guess at.

## Architecture

Four layers, each with one job. The split is what lets the wire contract be tested without a
socket and the socket be tested without a credential store.

```
   run-time tooling ───────────────────┐  UDS clients; any HTTP or model-facing stdio
                                       │  they serve is theirs, not the daemon's
   foreign shim ───────────────────────┤
   credential_process ─────────────────┤  line-delimited JSON-RPC 2.0 over UDS
   creds get ──────────────────────────┤
                                       ▼
              ┌────────────────────────────────────────────────┐
              │ transport   src/server/uds.rs                  │  accept, read lines,
              │             peer credentials, per-request      │  bound buffers, write lines
              │             re-sample (Req 14)                 │
              └────────────────────────┬───────────────────────┘
                                       ▼
              ┌────────────────────────────────────────────────┐
              │ codec       src/rpc/codec.rs                   │  bytes ↔ envelope
              │             pure functions, no I/O             │  MAX_LINE_LEN, batch refusal
              └────────────────────────┬───────────────────────┘
                                       ▼
              ┌────────────────────────────────────────────────┐
              │ protocol    src/rpc/mod.rs + src/rpc/methods.rs│  envelope + method surface
              │             types only, no behavior            │  name validation on deserialize
              └────────────────────────┬───────────────────────┘
                                       ▼
              ┌────────────────────────────────────────────────┐
              │ dispatch    src/server/dispatch.rs (to build)  │  method → handler,
              │             carrier exposure, error mapping    │  Req 13 AC 1-2
              └────────────────────────┬───────────────────────┘
                                       ▼
                   credential_store / config / classify — unchanged
```

`src/rpc` holds no behavior on purpose: it is the shape everything else is written against,
so a client, a server, and a test can all depend on it without depending on each other. The
codec is pure functions over `&[u8]` for the same reason — framing is testable without a
transport, which is where the `-32700` / `-32600` split is asserted.

## One envelope, not three

The requirements' final Dependencies bullet asks whether three surfaces speaking one protocol
share one implementation of the envelope and framing, noting "two hand-rolled copies already
exist or are specified." They should share one, and it should be `src/rpc`.

**Current state.** The MCP envelope has its own `JsonRpcRequest` / `JsonRpcResponse` /
`JsonRpcError` with `i64` codes. The plugin framework specifies a third
(`src/plugins/protocol.rs`) that does not exist yet — which is the cheapest moment to decide
this, because a copy not yet written costs nothing to not write.

**Why `src/rpc` is the one to keep.** It is strictly stronger than the MCP copy on four
fail-closed properties, each of which is a defect the MCP envelope currently has:

| Property | `src/rpc` | MCP envelope |
|---|---|---|
| `jsonrpc` member | one-variant enum — only `"2.0"` deserializes | `String`, any value accepted |
| `result` + `error` both present | rejected by hand-written `Deserialize` | derived; silently keeps one |
| Positional (array) params | rejected — `params` is `Map` | accepted |
| Line length | bounded by `MAX_LINE_LEN` | unbounded |

**Migration is a separate increment, and deliberately last.** MCP has a live wire contract
with harnesses; `src/rpc` does not yet have a single caller. Porting MCP onto the shared
envelope while the shared envelope is still settling would couple two risks that are cheap
apart. Order: build the UDS surface on `src/rpc`, then port MCP, then write the plugin
framework against it directly.

### Two constraints the shared envelope must absorb first

Recording these because "share the envelope" is not free, and discovering either one
mid-migration would invite loosening the credsd surface to accommodate MCP.

1. **MCP has notifications; the credsd surface must not.** `Request.id` is `Id`, not
   `Option<Id>`, which is correct for a retrieval API — Requirement 10's "Genuinely open"
   note observes retrieval always needs a response. But MCP sends
   `notifications/initialized`, which has no `id`. The resolution is a **distinct
   `Notification` type** in `src/rpc`, not an optional `id` on `Request`. Making `id`
   optional would let an id-less `credential/get` deserialize, and a retrieval whose
   response goes nowhere is a request whose failure nobody reads.

2. **The dispatcher is heterogeneous; `Response<T>` is generic.** Five methods return five
   result types, so a dispatcher cannot name one `T`. Handlers return
   `Result<serde_json::Value, RpcError>` — serializing their own typed result — and the
   dispatcher emits `Response<Value>`. Typed `Response<T>` stays the client-side and
   test-side view, where `T` is known. This keeps the strict `Deserialize` where it earns its
   keep (a client parsing a daemon's reply) without forcing the server to erase types before
   it has to.

## Method dispatch and carrier exposure

Requirement 13 AC 1 requires exposure to be explicit rather than incidental — "a method
reachable on one carrier MUST NOT become reachable on another merely because one dispatcher
serves both." The daemon serves one carrier, UDS, so the exposure table has one column; it
stays data rather than control flow scattered through handlers, so a second carrier cannot be
added without a row per method.

```rust
pub enum Carrier { Uds }

// The exposure matrix of Req 13 AC 2, as one table. Adding a method without adding a row
// does not compile.
fn exposed(method: &str, carrier: Carrier) -> bool
```

| Method | UDS | Enforcement |
|---|---|---|
| `credential/get` | yes | returns Material |
| `environment/credentials` | yes | returns Material |
| `credential/list` | yes | capped at name/kind/status by the *type*, not the handler |
| `environment/describe` | yes | carries projection inputs |
| `system/health` | yes | no Material, no config |

Which of these a model reaches is decided by the run-time tooling that faces it, under
Requirement 13's line; the daemon tells that tooling apart from other callers by caller
verification, not by carrier.

Two properties this shape buys, both required:

- **A method not exposed on a carrier returns `-32601` method-not-found, never a permission
  error** (Req 13 AC 5). The exposure check therefore runs *before* the handler lookup and
  emits the same error an unknown method would — a permission error would confirm the method
  exists.
- **`credential/list`'s cap is structural.** `ListResult` cannot carry `source` or `default`
  because `CredentialSummary` has no such fields. Requirement 13
  AC 4's "nothing more" is enforced by the type, so a handler cannot widen it and a reviewer
  does not have to notice.

## Error mapping

Requirement 8 AC 1's split — numeric for envelope, `data.code` for domain — is implemented in
`src/rpc/mod.rs`. What remains is the mapping from the existing `DaemonError` to it. This
table is the contract; a variant missing from it must not fall through to a default.

| `DaemonError` | Wire | Notes |
|---|---|---|
| `EnvNotFound(_)` | `ENVIRONMENT_NOT_FOUND` | Also the response for *not authorized* and for a credential the context does not reach (Req 8 AC 3-4). The three are indistinguishable to the caller and distinct in the audit record. |
| `ReauthRequired(_)` | `REAUTH_REQUIRED` + `data.environment`, `data.remediation` | The one domain code with required context; remedy is a login, not a policy change (Req 3 AC 5). |
| `Provider(_)` | `PROVIDER_UNAVAILABLE` | Transient; remedy is retry. |
| `CredentialsExpired` | `REAUTH_REQUIRED` | Same remedy, same code — expiry is not its own branch for a caller. |
| `Config(_)`, `Storage(_)`, `Encryption(_)`, `Io(_)`, `Json(_)`, `Toml(_)` | `INTERNAL` | Message must not echo config content or paths beyond what the operator already knows. |
| caller config fails validation (not a `DaemonError`) | `CONFIG_INVALID` | Raised at dispatch for `credential/get`, `credential/list` and `credential/tag`; nothing is served. The message names the credential and key, never a value. Unlike `CONFIG_DRIFTED` (remedy: revalidate), the remedy is to edit the file, then revalidate. |
| kind mismatch (not a `DaemonError`) | `WRONG_CREDENTIAL_TYPE` | Raised at the handler: an `access_token` credential requested where session credentials are required. |

Two rules that are easy to violate later:

- **No message may echo caller-supplied input.** `RpcError::message` is a log sink, so
  echoing a name is the log-forging vector `validate_name` exists to close. The boundary
  reports the field and the rule, never the value — already implemented as `NAME_RULE`
  (`src/rpc/methods.rs:36`).
- **Scope failures have no codes yet, deliberately.** Requirement 8 AC 2's two scope
  conditions stay unnamed until the Requested_Scope grammar exists, because AC 5 makes codes
  additive-only and a name coined before its domain is permanent. Both are unreachable
  while nothing populates a `Scope`.

## Name validation at deserialize time

Every name field validates during deserialization rather than in a handler
(`profile_name`, `optional_credential_name` — `src/rpc/methods.rs:43-67`). The reasoning is
worth keeping because the alternative looks equivalent and is not: placing the check in the
dispatcher would let a future method forget it, and would let an invalid name exist as a
`String` long enough to reach a log.

A syntactically invalid name is `-32602`, where the HTTP surface returned `404
ENVIRONMENT_NOT_FOUND`. This is not a Requirement 8 AC 3-4 violation: malformed syntax is
decidable from the request alone, without consulting any config or keystore, so it cannot
serve as an existence oracle. What AC 3-4 forbid is distinguishing *well-formed and absent*
from *well-formed and forbidden*, and those remain identical.

## Credential-addressed `credential/get`

`GetParams.environment` is optional (Requirement 10 AC 6). The handler branches on the form of
the request, never on what the caller's config happens to contain:

1. Neither `environment` nor `credential`: `-32602`, before any config or keystore is read
   (AC 9).
2. The audit record and the drift and custody refusal run for both forms before anything can
   miss (AC 10).
3. Credential-addressed (`credential` only): look the credential up in the caller's
   `credentials.toml` sources. Present: serve it from the store under its own restrictions.
   Absent, or the caller unauthorized: `CREDENTIAL_NOT_FOUND` with one fixed message (AC 11).
4. Environment-addressed: the environment must exist; with `credential`, the environment's
   `credentials` list must contain it; without, the first entry is served. Any miss is
   `ENVIRONMENT_NOT_FOUND`. The credential is then served by the same store lookup as step 3,
   so naming an environment cannot reach material the credential-addressed form would refuse
   (AC 8).

`REAUTH_REQUIRED` data names the credential, and its remediation is `credential/login` for
that credential (AC 12).

### Where each restriction lives

| Restriction | Lives on | Applies to |
|---|---|---|
| `identity_type` | the credential source | every request for that credential |
| Approval and presence gates | the credential (gated operations) | every write to it |
| Drift and custody | the caller root | every request |
| `claim`, `scope` | the request | that request |
| Environment `identity_type`, boundary, region | the environment | only requests that name it; narrow only |

### No implicit environments (Requirement 16)

`credential/bootstrap` and `credential/import` write `credentials.toml` and its snapshot only.
`config.toml` is not touched, so its snapshot is not resealed by a credential write.
`EnvConfig::credential_list` returns the explicit list only; an empty list composes nothing.

### `environment/credentials`

Renamed from `credential/get_batch`. It runs one environment-addressed get per entry of the
environment's list, in order, and fails the whole call on the first error (Requirement 3).

## Role selection for `aws-idc-sso` (Requirement 17)

`GetParams` carries `account_id` and `role_name` as two flat optional fields, each validated on
deserialize like a name. The handler adds two steps to the order above:

1. After the neither-subject check, one of the two without the other is `-32602`, before any
   config or keystore read (AC 1).
2. After the credential resolves, a pair on a source other than `aws-idc-sso` is
   `ROLE_SELECTION_UNSUPPORTED`, a domain refusal, since resolved config decides it (AC 3).
   A pair equal to the stored one is dropped, so it shares the default's cache entry (AC 4).
   Any other pair not in the credential's `allowed_roles` is `ROLE_NOT_ALLOWED`, naming the
   credential (AC 10). Both a served and a refused pair log `credential.role_selected` with the
   credential, account, role, and `outcome` (`allowed` or `refused`) (AC 8).

`allowed_roles` lives on the SSO credential's config and on `ProviderParamsSso`, so it is set by
`creds bootstrap aws-idc-sso --allow-role ACCOUNT_ID:ROLE_NAME` and stored with the rest of the
sealed entry. Changing it is a re-bootstrap over an existing credential, which the Req 1.7
overwrite gate already holds for approval; the approval binds the digest of the params, list
included, and its description names every listed pair.

The store keys its cache by `(uid, credential, pair)`, where `pair` is `None` for the stored
account and role, and its renewal turn locks by `(uid, credential)`, so the pairs of one
credential renew in turn and at most one refresh-token grant is in flight (AC 6). Neither grows
with the pairs a caller names: there is one turn lock per credential, and each cache insert drops
expired entries. A pair renews
through `CredentialProvider::role_renewer`, which only the SSO provider implements: it shares the
provider's sealed token and refresh path and differs only in the account and role it passes to
`GetRoleCredentials`. The background loop warms the stored pair. A selected pair renews on
demand, and only a successful renewal is cached, so the cache holds pairs the user actually has.

Restrictions need no new code (AC 7): drift, custody, `identity_type`, and environment narrowing
all run on the credential before the pair is read, and the pair only changes the call to
Identity Center.

### Repeating a bootstrap (AC 11)

A client that names one credential per Identity Center sign-in signs in again whenever the
session expires, and it has one verb for a sign-in: `credential/bootstrap`. So bootstrap is
idempotent in its settings. The entry gate asks what a bootstrap would overwrite, and a sign-in
that leaves every stored setting as it found it overwrites only the session, which is the thing
the sign-in replaces by definition. `credential/login` is the re-authentication a
`REAUTH_REQUIRED` points at (AC 5); which of the two a client uses is its own choice.

The decision is taken twice, where `aws-login`'s is: in `admit` and again in `commit_bootstrap`
under the per-caller write lock. `overwrite_reason` reports that the credential holds an entry or
sealed material, and `same_provider_source` clears that reason when the stored source matches the
request. The SSO arm compares `start_url`, `sso_region`, `identity_type`, `account_id`,
`role_name`, and `allowed_roles` against the entry, reading the `TomlFiles` bytes the write check
verified rather than the file again, so a swap after the check cannot exempt a replace.

The commit comparison is the one AC 11 names, because it holds the lock the write holds: it
compares the staged `SsoConfig`, the settings the sign-in ran on, against the entry as it then
stands. The entry check decides nothing the commit check does not decide again; it is there to
refuse a replace before the user is sent to a browser. Where the two disagree the entry changed
while the provider flow waited on a person, and the sign-in is discarded with the refusal that
says the credential changed while the user was signing in, rather than installed over settings
nobody approved. `aws-login` reaches commit for its own reason — its gate turns on who signed in,
which nothing knows until the sign-in returns — but the shape is one shape: the entry refuses
early where it can, and the lock decides.

Settings the request omits are read from the entry, not resolved again: `bootstrap_sso` takes the
stored `SsoConfig` as its starting point for a credential that has one, so `ListAccounts` and
`ListAccountRoles` run only for a credential with no entry to read. Without that, a repeat
bootstrap of a user with several accounts would send `select_account` and wait for a
`credential/bootstrap/respond` that a non-interactive sign-in never sends.

"Omitted" has to be a value the wire carries, so `ProviderParamsSso.allowed_roles` is
`Option<Vec<RolePair>>`: a `Vec` under `#[serde(default)]` reads an absent list and an empty one
as the same thing, and AC 11 turns on the difference between them — absent keeps the stored list,
`[]` clears it under approval. `account_id` and `role_name` are already `Option<String>`, so they
need no change. The wire stays additive; a Rust caller building the struct literally gains one
field to name.

The rule is "every stored setting equal", not a list of settings a repeat may change. One
comparison is cheaper to hold than a per-field policy, and it keeps the gate table reading as a
single rule — a sign-in that changes nothing but the session — with one definition per source.
A pair the allowed list already names is deliberately inside the gate: `account_id` and
`role_name` are the pair a request naming none is served, so moving the default changes what
every such consumer receives, even though a request naming the pair could already reach it. The
narrower reading — ungate a move within the allowed list, since reach does not widen — buys a
client nothing, because a client re-authenticating names no pair at all.

A replace discloses what it replaces. `describe_overwrite` carries one clause per changed
setting, named by its stored key with its old and new value, the clauses joined with `; ` as
`credential/import` joins its per-profile ones and appended as the `identity_type` clause is. A
changed `start_url` or `sso_region` repoints the stored pair and the allowed list at an instance
where a different administrator decides who holds them, so a single parenthetical enumerates what
the new sign-in keeps, as `environment/remove` enumerates the credentials it leaves in place:

```
replace existing credential 'dev' (source and sealed material) with a new credential; change start_url from A to B; change sso_region from C to D (kept on the new sign-in: account 111122223333 role Admin, allowed_roles 111122223333/Admin and 444455556666/ReadOnly)
```

Nothing is written before the sign-in succeeds. The device flow runs first, and only its success
reaches `write_caller_state_locked`, the credentials snapshot reseal, and the cache eviction, so
a failed, timed-out, or cancelled sign-in leaves the stored settings and the old sign-in as they
were — as `aws sso login` writes a changed region only after a successful login.

#### Who signed in

`SsoProvider::signed_in_user` brokers role credentials for a pair and reads the session name
`sts:GetCallerIdentity` returns, reusing `aws_login::parse_caller_arn` on the
`assumed-role/AWSReservedSSO_<permission-set>_<hash>/<user>` form rather than a second parser.
`audit_sso_signed_in_user` emits it as its own `sso.signed_in` record, not a field of `bootstrap
complete`, because the lookup has an unresolved outcome to express and the reason for it is the
useful half of that record. The session name is Identity Center's rendering of an IdP user name,
and on a first bootstrap the pair comes from `ListAccounts`/`ListAccountRoles`, so every field of
the record is remote data and goes through `escape_log`.

It runs on each path that completes a fresh sign-in, after the pair is final so the lookup uses
the pair the sign-in is stored with: in `bootstrap_sso`, where no lock is held across the flow,
and in `login_sso`, where the device flow already runs under the per-caller write lock and one
more call is noise beside it. Not on the unattended renew path: a refresh uses the same user's
refresh token, so the user cannot have changed, and a silent background renewal should not mint
credentials.

The outcome is audited and nothing else — neither call site applies `?` to it — so an unresolved
identity leaves the sign-in successful, which is what Requirement 17's "Who signed in" requires of
a credential whose stored pair the instance may no longer assign.

## Socket discovery

Clients resolve the socket path in this priority order (`client_socket_path()` in
`credsd-core/src/config/platform.rs`):

1. **`--socket` CLI flag / `CREDSD_SOCKET` env var** — if either is set and non-empty,
   always used. `--socket` sets `CREDSD_SOCKET` early in `main()` so all call sites see it.
   A relative path is warned and ignored; both ends resolve independently so a relative path
   can disagree across processes with different working directories.
2. **User socket probe** (Unix only) — if `user_socket_path()` resolves (requires `$HOME`)
   and the resulting path exists as a socket file, the user daemon is running there and the
   client routes to it. This makes user installs zero-config: no env var, no shell setup.
   - macOS: `~/Library/Application Support/credsd/credsd.sock`
   - Linux: `~/.local/share/credsd/credsd.sock`
3. **System socket** — the platform default.
   - macOS: `/var/run/credsd/credsd.sock`
   - Linux: `/run/credsd/credsd.sock`

Every selection is logged at `INFO` level with the chosen path and the source that won
(`CREDSD_SOCKET`, `user-socket probe`, or `system default`).

The daemon's `CREDSD_SOCKET` env var exists because a foreign shim cannot read
`config.toml` — which is the entire point of the port — so the daemon publishes the path it
bound rather than expecting the shim to re-derive it. A blank value reads as unset.

## Per-request caller identification

Requirement 14 AC 1 requires re-sampling on every Material-returning request, not once per
connection. `verify_peer_uid` samples once at accept (`src/server/uds.rs:60-75`), which was
near enough under HTTP/1.1 and is not under a long-lived JSON-RPC session.

The design must not assume platform uniformity — AC 6 makes that explicit, and AC 7 requires
explicit degradation where a platform cannot refresh.

| Platform | Mechanism | Refreshes? | Design consequence |
|---|---|---|---|
| macOS | `LOCAL_PEERPID` | **Yes** — tracks the last writer (verified, see requirements Rationale) | Re-sample per request; identity is the process actually making this request. |
| Linux | `SO_PEERCRED` | **No** — documented as a `connect(2)`-time snapshot | Unsuitable for AC 1. Candidate analogue is `SO_PASSCRED` + `SCM_CREDENTIALS`. **Untested; MUST be verified before AC 1 is relied on here.** |
| Windows | named pipes | no equivalent | `windows-named-pipe-transport` owns it. |

Until the Linux mechanism is verified, the Linux path **must report the indeterminate
classification** `caller-verification-policy` Req 7.5 already requires to be structurally
distinct from "walk completed, no agent found". The failure mode AC 7 exists to prevent is an
implementation that re-samples on macOS, reports the connect-time snapshot on Linux, and emits
identical audit fields on both — the fields would agree and the guarantees would not.

Identity is the tuple `(pid, start_time)`, never the PID alone (AC 2), plus a re-resolved
binary path, because `execve` preserves both PID and start time and so is invisible to the
tuple (AC 3). The ancestry walk may be cached keyed on the tuple (AC 5), so an unchanged
caller costs one `getsockopt`.

**What this does not buy.** Re-sampling does not prevent FD inheritance or `SCM_RIGHTS`
passing, and the daemon cannot set `FD_CLOEXEC` on a client's descriptor. It converts a silent
capability transfer into an attributable one — detective, not preventive, which is the posture
`caller-verification-policy` already adopts. Documentation MUST state this (AC 8). The residual
risk is that AC 4's change-audit is emitted and never read, in which case re-sampling is cost
without control.

## Mutation methods

Six UDS-only methods let the caller manage their own `callers/<uid>/` tree. All are caller-scoped
daemon-side: the daemon resolves the caller uid from `SO_PEERCRED` and opens the caller's own
`callers/<uid>/config.toml` or `callers/<uid>/credentials.toml` — a caller cannot name another
uid's folder. An unauthorized caller receives the code the method returns for any other miss, so
the two are indistinguishable (Req 8 AC 3–4): `ENVIRONMENT_NOT_FOUND` on the environment-addressed
methods, and `CREDENTIAL_NOT_FOUND` on `credential/remove` and `credential/logout`, which pass the
one credential access check (Req 8 AC 7-8, Req 15 AC 4).

| Method | Params | Result | Errors |
|---|---|---|---|
| `config/set` | `{environment, key, value, request_id?}` | `OkResult {ok: true}` | `ENVIRONMENT_NOT_FOUND`, `INTERNAL` |
| `config/get` | `{environment, key, request_id?}` | `ConfigGetResult {value?}` | `ENVIRONMENT_NOT_FOUND`, `INTERNAL` |
| `config/unset` | `{environment, key, request_id?}` | `OkResult {ok: true}` | `ENVIRONMENT_NOT_FOUND`, `INTERNAL` |
| `credential/remove` | `{credential, request_id?}` | `OkResult {ok: true}` | `CREDENTIAL_NOT_FOUND`, `INTERNAL` |
| `credential/logout` | `{credential, request_id?}` | `LogoutResult {signed_out, provider, start_url?, access_token_expires_at?}` | `CREDENTIAL_NOT_FOUND`, `LOGOUT_UNSUPPORTED_SOURCE`, `-32602` (Invalid params), `CONFIG_DRIFTED`, `INTERNAL` |
| `environment/remove` | `{environment, request_id?}` | `OkResult {ok: true}` | `ENVIRONMENT_NOT_FOUND`, `INTERNAL` |

All six are UDS-only (`Carrier::Uds`). `config/set`, `config/get`,
`config/unset`, and `environment/remove` take `environment` as an env name; `credential/remove` and
`credential/logout` take `credential` as a credential name. `environment` and `credential` are validated at deserialize time by
`config::credentials::validate_name` — an invalid name is `-32602` and the message carries the rule
(`NAME_RULE`) and never the offending value. `-32602` is the code JSON-RPC 2.0 reserves for Invalid
params ([JSON-RPC 2.0, Error object](https://www.jsonrpc.org/specification#error_object)); the daemon
defines it as `CODE_INVALID_PARAMS`.

Updated carrier exposure table (extends the table in [Method dispatch and carrier exposure](#method-dispatch-and-carrier-exposure)):

| Method | UDS | Enforcement |
|---|---|---|
| `config/set` | yes | mutates caller data |
| `config/get` | yes | reads caller config |
| `config/unset` | yes | mutates caller data |
| `credential/remove` | yes | mutates caller data |
| `credential/logout` | yes | deletes caller session material |
| `environment/remove` | yes | mutates caller data |

**Caller-scoping invariant.** The daemon derives the caller's `callers/<uid>/` root from the
kernel-verified peer uid, never from a method parameter. A caller that names an `environment` it
has not provisioned gets `ENVIRONMENT_NOT_FOUND`, and one that names a `credential` it does not hold
gets `CREDENTIAL_NOT_FOUND`; it cannot influence the path the daemon opens.

### Signing out with `credential/logout` (Requirement 15 AC 12-19)

`credential/logout` is how `aws logout` signs out without approval. Under the caller's write lock it
runs the shared write check first, then looks the credential up, then deletes everything in the
credential's data directory (`callers/<uid>/credentials/<name>/`) except `identity.enc`, and the
`.replaced-*` archives of it that hold only sign-in output. A `.replaced-<name>.<id>` archive is
the set-aside copy left when the credential was replaced. A successful replace deletes it at once;
only a failed cleanup or restore, which is logged, leaves one behind. A logout deletes such an
archive for the same reason `credential/remove` does: so the old sign-in cannot be restored by
renaming it back. But an archive can hold a prior source's key, such as an IAM secret key from
before a re-bootstrap to `aws-login`, which a logout is refused for (AC 13). Nothing records an
archive's source once its entry is replaced, so its files decide: a logout deletes an archive only
when every file in it is in the data-directory table below or is `identity.enc`, and leaves any
other for the gated `credential/remove`. It writes neither TOML file and does not touch the integrity record, so nothing it does reads as drift. It
evicts the caller's cached state, so a held session is not served after the logout returns.

**What a logout ends.** The method is named for what it does, and it pairs with `credential/login`:
it ends the sign-in of one credential that stays configured. The credential's entry, its source
settings, and the caller's other credentials are untouched, and the next `credential/login` signs
it back in. For `aws-idc-sso` a logout also calls the SSO service's `Logout`, so the session ends
server-side as well when SSO accepts it, in the same vocabulary SSO uses. `creds logout --credential <name>` and
`aws logout` call it.

**What the result reports** (AC 17-18). An error may leave the logout partly done. Retrying the
same logout is safe and finishes it. Once the local deletion has happened the logout succeeds,
and `LogoutResult.provider` says what happened at the identity provider:

| `provider` | When | `signed_out` | Also carries |
|---|---|---|---|
| `ended` | `aws-idc-sso`, and SSO accepted `Logout` | `true` | |
| `token_rejected` | `aws-idc-sso`, and SSO refused the access token or the refresh before it as invalid or expired; the portal session may still be live | `true` | |
| `local_only` | `aws-login` or `aws-web-identity`, neither of which has an end-session endpoint; or `aws-idc-sso` with local material deleted but no sealed token to send | `true` | |
| `failed` | `aws-idc-sso`, and `Logout` or the refresh before it was refused for another reason or timed out, or the sealed token was unreadable | `true` | `start_url`, the portal to sign out at; `access_token_expires_at`, the expiry of the newest access token SSO issued, sealed or refreshed for the logout, when the sealed token was readable |
| `none` | no sealed session; nothing deleted, nothing sent | `false` | |

The `Logout` call goes first, since it needs the sealed access token. An expired access token
is refreshed first when a refresh token is sealed with it, since that refresh token can keep the
portal session live. The refreshed tokens stay in memory for that one call and are never sealed.
The refresh and `Logout` share one 30 s
bound, connect to response with any retries inside it, not the shared SSO client's timeouts and
retries, so both always end inside the logout's 60 s lock hold (drift-detection Requirement 5.9)
and the hold never cancels a logout before it deletes. A call that hits the bound reports
`failed`. A lock wait past 10 s or a hold past 60 s is `INTERNAL` and deletes nothing: the wait
lands before the logout starts, and the local deletion does not yield, so the hold can cancel only
at the refresh or `Logout` call. Any other `INTERNAL` is a local step that failed and may leave the logout partly done, for example
after SSO accepted `Logout`. The daemon cannot make the SSO sign-out and the local deletion one
atomic step, so a retry finishes whatever is left. That retry still holds the sealed token, so
it sends `Logout` again, and SSO refuses a token the first call invalidated. A refusal of the
token as invalid or expired is `token_rejected`, not `failed`: nothing sealed can act, and the
daemon keeps no record on disk that the first call succeeded. An expired access token with no
refresh token gets the same answer while the portal session may still be live, so `creds logout`
says only that the token no longer works at SSO and that the portal session may still be live.
Only `ended`, an accepted `Logout`, lets it say the portal session ended. An earlier draft reported a refused
`Logout` as `PROVIDER_UNAVAILABLE` after deleting the session. That error reads as retryable when
state had already changed, and the retry then found no session, returned success, and hid the
session still live at SSO. `creds logout` exits 1 on `failed` and warns with the start URL to
sign out at and the access token's expiry, which the SSO session may outlast, so a script still
sees the incomplete sign-out.

**Sign-in output.** A credential's data may be one of three kinds:

| Kind | Examples | Where it lives | A logout |
|---|---|---|---|
| Security-relevant metadata | authorization and token endpoints, SSO start URL, region, role ARN, client id | `credentials.toml` | keeps it |
| Intermediate sign-in data | refresh tokens, SSO access token and client registration, IdP access and ID tokens, the DPoP key | sealed in the data directory | deletes it |
| Resulting credentials | AWS session credentials | sealed in the data directory, or only in the daemon's memory | deletes the sealed copy; eviction drops the in-memory one |

Sign-in output is the second and third kinds: what a sign-in returns and the daemon seals. The
metadata is what the next sign-in needs, so a logout keeps it and a re-login needs no reconfiguring.

`credential/logout` applies only to the three sources whose data directory holds nothing but
sign-in output, and `credential/login` rebuilds every file in it:

| Source | Data directory |
|---|---|
| `aws-login` | `aws_login_token.enc` (AWS session credentials and refresh token), `dpop_key.enc` |
| `aws-idc-sso` | `sso_token.enc` (SSO access and refresh token, client registration, and copies of the start URL and region whose source stays in `credentials.toml`) |
| `aws-web-identity` | `oauth_token.enc` (IdP access, ID, and refresh token) |

The AWS credentials an `aws-idc-sso` or `aws-web-identity` credential yields are held only in
memory and go with the eviction. Every other source keeps material only a bootstrap supplies (an IAM
key, a Roles Anywhere private key, a static secret, a JWT, an OAuth client secret), so a logout of one
is refused with `LOGOUT_UNSUPPORTED_SOURCE` rather than reduced to "delete the cache". That is a
domain code, not `-32602`: the source comes from resolved config, not the request, and envelope
codes carry no domain meaning (Requirement 8 AC 1).

**When it is ungated.** A logout is never presence-gated (presence-gated-operations Requirement 1.7),
and that holds only because it is refused for every source but the three above. For those,
`credential/login` is ungated and replaces the same material with whatever the next sign-in
returns, and a logout does strictly less: it ends the session and leaves the next sign-in to restore
it. Gating it would protect nothing a same-uid caller cannot already do through login, and would put
`sudo` on every `aws logout`. A logout of material only a bootstrap can restore would destroy what
login cannot rebuild, so it is refused rather than gated. Being ungated does not skip the other
checks: the caller must be authorized over UDS, and the shared write check must pass, so a drifted
caller gets `CONFIG_DRIFTED` before the name is looked up.

The exemption rests on one condition: no `credential/login` parameter selects or changes the
principal beyond what the sign-in itself decides. The only such parameter is the
`aws-idc-sso` `provider` (Requirement 17 AC 11), and a change through it is gated. A logout then a
login gives a caller nothing a login alone does not: `aws-login` and `aws-web-identity` pin no
principal, so whoever signs in becomes it, and an `aws-idc-sso` credential pins its account and
role but any SSO user with that role may sign in, as the AWS CLI's own login allows. The exemption
does not depend on `identity.enc`. For `aws-login` a logout keeps that record, so the next login
still refuses a different principal (aws-login-identity Requirement 3.6), but the argument holds
without it. Any login parameter added later that selects a principal, such as an account, role,
start URL, or region passed through from a client, must be gated or must trigger a re-examination
of this exemption.

**Claims do not apply.** A logout takes no `claim` and is not checked against the credential's
`identity_type` (Requirement 15 AC 19), matching login. A caller whose claim bars it from
retrieving a credential may still sign that credential out: the claim is self-reported and only
adds restriction, a logout yields no material, and an ungated login could already replace the
session it ends.

Open questions:

- **Identity record.** A logout keeps `identity.enc`, the record of who signed in that
  aws-login-identity defines, so the next sign-in compares against it. Only `aws-login` writes it.
- **MFA sessions.** An `aws-iam-user` credential with MFA keeps a session file next to its key. A
  logout that drops only the session would be a sign-out for it; it is currently refused.

## Increments

Ordered so each lands independently and nothing depends on an unsettled decision.

| # | Increment | Status |
|---|---|---|
| 1 | Wire types: envelope, method surface, codec, name validation | **Shipped** — `src/rpc/{mod,methods,codec}.rs` |
| 2 | Socket discovery from `CREDSD_SOCKET` | **Shipped** — `src/config/{mod,platform}.rs` |
| 3 | Dispatcher + UDS transport: read lines, dispatch, exposure table, error mapping. `system/health`, `credential/list`, `environment/describe` handlers (no Material) | Next |
| 4 | `credential/get` and `environment/credentials` handlers; all-or-none enforced daemon-side | After 3 |
| 5 | Per-request peer re-sampling (Req 14), macOS first, Linux gated on verification | Parallel with 4; blocks nothing else |
| 6 | Client: a sync JSON-RPC client for `creds get` and `credential_process` | After 3 |
| 7 | Legacy UDS routes deleted (Req 9 AC 3) | After 6 |
| 8 | `Notification` type in `src/rpc`, so an MCP envelope can port onto the shared one | Last — see [One envelope](#one-envelope-not-three) |

Increment 3 before 4 is deliberate: it exercises the dispatcher, the exposure table, and the
error mapping with no Material in play, so the first Material-bearing handler lands on a path
that already works.

**A sync client, not an async one.** Increment 6's consumers are `credential_process` (a
subprocess that makes one call and exits) and the planned Strands Box seam, which is
deliberately synchronous. A line-delimited protocol over `UnixStream` needs `BufReader` and
`serde_json` and nothing else — the module doc's claim that a consumer needs no more than that
is only true if credsd's own client demonstrates it.

## Deferred by open decisions

Stated as prohibitions because each is a place an increment would otherwise guess, and the
guess would ship.

- **Boundary application (Open Decision 1, surviving half).** Which boundary applies when
  `profile` and `credential` disagree is blocked by the `scope-down-plugin` base-directory
  question. No increment may implement boundary application. The `credential` field is safe to
  carry meanwhile only because it is optional and its absence means "the profile's configured
  credential". **An increment MUST reject a `credential`
  value naming anything other than that**, rather than honoring it unrestricted.
- **Scope on aggregates (Open Decision 2).** `GetBatchParams::scope` exists as a field;
  applying it does not. Leaning reject, decided with Req 7 AC 3. Nothing populates a scope, so
  this is unreachable rather than latent.
- **Manifest authorization (Open Decision 4).** Whether existence-disclosure is its own
  decision, and whether it defaults more permissive than material, applies to both
  `credential/list` and `environment/describe`.
- **Transport batches stay prohibited.** A top-level JSON array is `-32602`
  (`src/rpc/codec.rs:61`). Accepting batches later is easy; withdrawing them once shims batch
  is not.
- **Notifications** on the credsd surface — no method needs one.

## Coherence issues — resolved

1. **`profile` → `environment` on the wire.** Decision: the wire follows the rename.
   All method names (`profile/describe` → `environment/describe`, `profile/bootstrap` →
   `environment/bootstrap`, `profile/login` → `environment/login`, `env/remove` →
   `environment/remove`), all `profile` param/result field names, and `DomainCode::ProfileNotFound`
   → `DomainCode::EnvironmentNotFound` (`ENVIRONMENT_NOT_FOUND`) are renamed in this commit.
   This is a breaking wire change accepted under the Requirement 11 AC 3 pre-launch waiver,
   which covers every wire change before the first general-availability release;
   `PROTOCOL_VERSION` is not bumped.

   Under the same policy, `CredentialResult.expires_at` becomes nullable (`DateTime | null`,
   `null` = the credential does not expire; see Requirement 4 as amended and
   `docs/specs/static-secret-credentials/`). Field always present. Another breaking wire change
   accepted pre-launch, and `PROTOCOL_VERSION` is likewise not bumped for want of deployed
   consumers.

2. **`CredentialSourceType` is missing `RolesAnywhere`.** A third supported source was added
   (`config/credentials.rs:34`), and the wire enum has only `Sso` and `IamUser` plus
   `#[serde(other)] Unsupported` (`src/rpc/methods.rs:335`). `#[serde(other)]` covers
   deserialization only, so there is no serialize path: a mapping would have to report a
   fully-supported source as `Unsupported`, whose own doc says "a source type this build has no
   provider for". Additive and consistent with Requirement 10's "Source type mirrors
   `CredentialSource`'s *variants*", so this is a fix rather than a decision — but it must land
   before increment 3 writes the first mapping.

3. **Glossary casing.** Requirement 10 notes the Glossary spells kinds kebab-case
   (`session-credentials`, `access-token`) while the shipped wire strings are snake_case, and
   states the Glossary should be corrected rather than the code. Not done here, to keep the
   move of `requirements.md` into `docs/` reviewable as a pure rename.

4. **`Material` has one variant.** `CredentialType` has `AccessToken` and
   `SessionCredentials`; `Material` (`src/rpc/methods.rs:436`) carries only
   `SessionCredentials`. This is consistent — an `access_token` retrieval fails
   `WRONG_CREDENTIAL_TYPE` rather than returning token bytes — but it means a manifest can
   report a kind that no material response can carry. Requirement 7 AC 3 obliges defining
   projectability per projection; that definition does not exist yet.

## File changes

| File | Change |
|---|---|
| `src/rpc/mod.rs` | **Shipped.** Envelope: `Request`, `Response`, `Outcome`, `RpcError`, `DomainCode`, `Id`, `Version`, numeric codes, `PROTOCOL_VERSION`. |
| `src/rpc/methods.rs` | **Shipped.** Five method constants, params/result types, `Material`, `Scope`, name validation on deserialize. |
| `src/rpc/codec.rs` | **Shipped.** `encode_*` / `decode_*`, `MAX_LINE_LEN`, batch refusal, `-32700`/`-32600` split. |
| `src/rpc/notification.rs` | New, increment 8. `Notification` type so MCP can share the envelope without `Request.id` becoming optional. |
| `src/rpc/client.rs` | New, increment 6. Sync `UnixStream` client: connect, one call, typed `Response<T>`. |
| `src/server/dispatch.rs` | New, increment 3. `Carrier`, exposure table, method → handler, `DaemonError` → wire mapping. |
| `src/server/uds.rs` | Line-oriented read loop replacing the HTTP service; per-request peer re-sample (increment 5). `verify_peer_uid` keeps its accept-time role as the first check. |
| `src/server/mod.rs` | `uds_router` deleted (Req 9 AC 3). `start()` serves the dispatcher over UDS. |
| `src/server/routes.rs` | Native credential routes deleted. |
| `src/config/mod.rs`, `src/config/platform.rs` | **Shipped.** `CREDSD_SOCKET` resolution and platform default. |
| `crates/credsd-core/src/rpc/methods.rs` | `GetParams.environment` optional (Req 10 AC 6). |
| `crates/credsd-daemon/src/server/dispatch.rs` | `get` serves a credential-addressed request from the credential alone; environment-addressed requests narrow (Req 10 AC 6-13). Method renames. |
| `crates/credsd-daemon/src/server/bootstrap.rs` | Bootstrap and import write the credential only (Req 16). |
| `crates/credsd-core/src/config/mod.rs` | `credential_list` drops the implicit one-to-one default (Req 16 AC 3). |
| `crates/credsd-core/src/rpc/{methods,uds}.rs`, `crates/credsd-client/src/lib.rs` | `CREDENTIAL_NOT_FOUND`; renamed methods; bootstrap and login params are credential-addressed. |
| `docs/api/openrpc.json`, `docs/reference/api.md`, user docs | Credential-addressed get, renames, no default environments. |
| `crates/credsd-core/src/rpc/methods.rs` | `GetParams.account_id` and `role_name`, validated on deserialize (Req 17 AC 1-2). |
| `crates/credsd-core/src/providers/{mod,sso}.rs` | `CredentialProvider::role_renewer`; the SSO provider renews any pair from its one token (Req 17 AC 4-5). |
| `crates/credsd-daemon/src/credential_store.rs` | Cache and renewal turns keyed by pair (Req 17 AC 6). |
| `crates/credsd-daemon/src/server/dispatch.rs` | Pair checks, default-pair folding, and the audit line (Req 17 AC 1, 3, 4, 8). |
| `crates/credsd-core/src/rpc/methods.rs` | `ProviderParamsSso.allowed_roles` is `Option<Vec<RolePair>>`, so absent and empty differ (Req 17 AC 11). |
| `crates/credsd-daemon/src/server/bootstrap.rs` | `same_provider_source` reads an `aws-idc-sso` entry at the entry check and again at commit against the staged source; `bootstrap_sso` keeps a stored pair instead of prompting; `describe_overwrite` names each changed setting and what the sign-in keeps (Req 17 AC 11). |

## Security considerations

- **No bearer token on UDS.** Peer credentials are the authentication; there is no listener a
  non-owning user can reach (Req 9 AC 5). A compatibility proxy's bearer token and the rule that
  a model never receives Material are run-time tooling's to enforce (Req 13).
- **`Material` and `CredentialResult` are `Zeroize + ZeroizeOnDrop`**, and `Material`'s
  `Debug` is hand-written so no secret reaches a log through `{:?}` on it or on any struct
  containing it. `Scope`'s `Debug` is likewise redacting, because a scope may name resources
  that are themselves sensitive and the audit contract requires a digest rather than the
  document.
- **Denial does not disclose membership.** A failed aggregate returns one error and no
  per-element array, so a partial read cannot reconstruct which credential was restricted
  (Req 3 AC 2-3). The audit record has it; the caller does not.
- **A connection is a capability on every platform.** Re-sampling identifies the current
  writer; it does not prevent an FD from being inherited or passed. Attributable, not
  preventable (Req 14 AC 8).
- **An SSO credential reaches only its allowed roles.** A caller allowed to get an `aws-idc-sso`
  credential can get its stored account and role and the pairs its `allowed_roles` names, and no
  other, even when the sign-in holds more (Req 17 AC 10). An absent or empty list allows only the
  stored pair. The list changes only through the presence-gated re-bootstrap (Req 1.7), and the
  daemon audits each selected pair.
- **Bounded input.** `MAX_LINE_LEN` caps the buffer one message can force a transport to hold,
  so a peer that never sends a newline cannot drive it to grow without limit.
