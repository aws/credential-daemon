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
| `credential/get_batch` | yes | returns Material |
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
  because `CredentialSummary` has no such fields (`src/rpc/methods.rs:243`). Requirement 13
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
| kind mismatch (not a `DaemonError` today) | `WRONG_CREDENTIAL_TYPE` | Raised at the handler: an `access_token` credential requested where session credentials are required. |

Two rules that are easy to violate later:

- **No message may echo caller-supplied input.** `RpcError::message` is a log sink, so
  echoing a name is the log-forging vector `validate_name` exists to close. The boundary
  reports the field and the rule, never the value — already implemented as `NAME_RULE`
  (`src/rpc/methods.rs:36`).
- **Scope failures have no codes yet, deliberately.** Requirement 8 AC 2's two scope
  conditions stay unnamed until the Requested_Scope grammar exists, because AC 5 makes codes
  additive-only and a name coined before its domain is permanent. Both are unreachable today:
  nothing populates a `Scope`.

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

Five UDS-only methods let the caller manage their own `callers/<uid>/` tree. All are caller-scoped
daemon-side: the daemon resolves the caller uid from `SO_PEERCRED` and opens the caller's own
`callers/<uid>/config.toml` or `callers/<uid>/credentials.toml` — a caller cannot name another
uid's folder. An unauthorized caller receives `ENVIRONMENT_NOT_FOUND` per the indistinguishability
rule (Req 8 AC 3–4).

| Method | Params | Result | Errors |
|---|---|---|---|
| `config/set` | `{environment, key, value, request_id?}` | `OkResult {ok: true}` | `ENVIRONMENT_NOT_FOUND`, `INTERNAL` |
| `config/get` | `{environment, key, request_id?}` | `ConfigGetResult {value?}` | `ENVIRONMENT_NOT_FOUND`, `INTERNAL` |
| `config/unset` | `{environment, key, request_id?}` | `OkResult {ok: true}` | `ENVIRONMENT_NOT_FOUND`, `INTERNAL` |
| `credential/remove` | `{credential, request_id?}` | `OkResult {ok: true}` | `ENVIRONMENT_NOT_FOUND`, `INTERNAL` |
| `environment/remove` | `{environment, request_id?}` | `OkResult {ok: true}` | `ENVIRONMENT_NOT_FOUND`, `INTERNAL` |

All five are UDS-only (`Carrier::Uds`). `config/set`, `config/get`,
`config/unset`, and `environment/remove` take `environment` as an env name; `credential/remove` takes
`credential` as a credential name. `environment` and `credential` are validated at deserialize time by
`config::credentials::validate_name` — an invalid name is `-32602` and the message carries the rule
(`NAME_RULE`) and never the offending value.

Updated carrier exposure table (extends the table in [Method dispatch and carrier exposure](#method-dispatch-and-carrier-exposure)):

| Method | UDS | Enforcement |
|---|---|---|
| `config/set` | yes | mutates caller data |
| `config/get` | yes | reads caller config |
| `config/unset` | yes | mutates caller data |
| `credential/remove` | yes | mutates caller data |
| `environment/remove` | yes | mutates caller data |

**Caller-scoping invariant.** The daemon derives the caller's `callers/<uid>/` root from the
kernel-verified peer uid, never from a method parameter. A caller that names an `environment` it
has not provisioned gets `ENVIRONMENT_NOT_FOUND`; it cannot influence the path the daemon opens.

## Increments

Ordered so each lands independently and nothing depends on an unsettled decision.

| # | Increment | Status |
|---|---|---|
| 1 | Wire types: envelope, method surface, codec, name validation | **Shipped** — `src/rpc/{mod,methods,codec}.rs` |
| 2 | Socket discovery from `CREDSD_SOCKET` | **Shipped** — `src/config/{mod,platform}.rs` |
| 3 | Dispatcher + UDS transport: read lines, dispatch, exposure table, error mapping. `system/health`, `credential/list`, `environment/describe` handlers (no Material) | Next |
| 4 | `credential/get` and `credential/get_batch` handlers; all-or-none enforced daemon-side | After 3 |
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
  credential" — the behavior that exists today. **An increment MUST reject a `credential`
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
   This is a breaking wire change accepted pre-launch. Requirement 11 AC 3 requires a version
   increment for breaking changes; `PROTOCOL_VERSION` is not bumped because no deployed
   production consumers exist yet.

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
- **Bounded input.** `MAX_LINE_LEN` caps the buffer one message can force a transport to hold,
  so a peer that never sends a newline cannot drive it to grow without limit.
