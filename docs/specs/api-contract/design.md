# Design: API Contract

## Overview

The contract is an OpenRPC document. Its component schemas come from `schemars` derives on the
wire types in `credsd-core::rpc` and `credsd-core::presence`. Its methods come from a table in
`credsd-daemon` that is built from the `Method` enum, so the dispatcher and the contract share one
list. A test renders the document and compares it with `docs/api/openrpc.json`. A second test
compares that file with the base branch's copy and classifies the differences.

## Key Design Decisions

### 1. OpenRPC, not OpenAPI or Smithy

OpenRPC is the JSON-RPC counterpart of OpenAPI. A method name is a JSON-RPC method, `params` is the
request's `params` object, `result` is the response's `result`, and `errors` are JSON-RPC error
objects. Its schemas are JSON Schema, which is what serde's output already is. Nothing is
translated, so nothing can be translated wrongly.

### 2. Generated from the code, committed as a file

The wire types already are the contract: `deny_unknown_fields`, defaults, and skip rules decide
what the daemon accepts. A hand-written document would be a second copy that drifts. Generating
it makes the document true by construction. Committing it makes every wire change a visible diff
in review and lets clients read the contract without building the daemon.

### 3. Extensions carry what OpenRPC does not

| Extension | Where | Meaning |
|---|---|---|
| `x-carriers` | method | carriers that expose the method (`uds`, `stdio`) |
| `x-gated` | method | the presence `Op` the method raises |
| `x-streaming` | method | notifications emitted and accepted while in flight |
| `x-deny-unknown-params` | method | unknown params are rejected, not ignored |
| `x-aliases` | method, param | older names still accepted |
| `x-secret` | schema member | carries secret material |
| `x-open-enum` | schema | unrecognised values are accepted without failing |
| `x-feature` | schema variant | present only in builds with that Cargo feature |
| `x-notifications` | root | notifications in both directions |
| `x-error-data` | root | `data` schemas for domain errors, keyed by `DomainCode` |
| `x-prelaunch-waiver` | `info` | breaking changes allowed without a major bump |

Notifications are kept out of `methods` because OpenRPC methods are client-to-server calls with a
result, and `notifications/progress` flows the other way. Error `data` schemas are kept out of the
error objects because OpenRPC error objects admit no extensions.

### 4. Schema derivation stays out of shipped binaries

`schemars` is an optional dependency of `credsd-core` behind a `schema` feature. Only
`credsd-daemon`'s dev-dependency on `credsd-core` enables it, and the generator is a `#[cfg(test)]`
module. A release build compiles neither the derives nor the generator.

### 5. The method table is the exposure table

`Method` already has an exhaustive exposure match per carrier. The table adds one entry per
variant: summary, description, error list, gated `Op`, and streaming. It is a `match` on `Method`,
so a new variant without an entry does not compile. Carriers are read from the exposure match,
not restated.

## Architecture

```
wire types (credsd-core, #[cfg_attr(feature = "schema", derive(JsonSchema))])
        │ schemars
        ▼
component schemas ──┐
                    ├─▶ render() ─▶ OpenRPC document ─▶ compare with docs/api/openrpc.json
method table ───────┘    (sorted, 2-space JSON, trailing newline)
(credsd-daemon, cfg(test))
```

### Commands

- Regenerate: `CREDSD_UPDATE_CONTRACT=1 cargo test -p credsd-daemon contract::`
- Check: `cargo test -p credsd-daemon contract::` (part of `cargo test`)
- Compatibility: `CREDSD_CONTRACT_BASE=<path> cargo test -p credsd-daemon contract::compat`. CI
  writes `<path>` from `git show origin/<base>:docs/api/openrpc.json`. When the variable is unset
  the test is skipped, so a local run needs no git state.

### Compatibility check

A walk over the two documents, keyed by method name, parameter name, schema name, and member name.
It understands only the constructs the generator emits: `type`, `properties`, `required`,
`additionalProperties`, `enum`, `const`, `oneOf`, `items`, `$ref`, `default`, `format`,
`pattern`, `minLength`, `maxLength`, `minimum`, `maximum`, and the extensions above. Meeting
anything else is a test failure, so a new construct is added to the checker before it is used.
Each difference becomes a line naming its path and class. The test fails on any breaking line
unless Requirement 5.5 allows it.

### serde attributes and their schemas

| serde | Contract |
|---|---|
| `deny_unknown_fields` | `additionalProperties: false`; method gets `x-deny-unknown-params` |
| `default`, `default = "f"` | not required; `default` set to the value `f` returns |
| `skip_serializing_if` | not required; omitted from output |
| `Option<T>` without skip | required, `oneOf [T, null]` |
| `tag = "type"` | `oneOf` of objects, each with `type: {const}` |
| `#[serde(other)]` variant | `x-open-enum: true`; the catch-all is not listed |
| `deserialize_with` validator | the validator's rule as `pattern`/`format`/`not`, checked by Requirement 5.7 |
| `transparent` over `Value` | an empty schema (any JSON) |

A validator whose rule JSON Schema cannot express states the rule in `description`. Requirement
5.7's example round trip is what keeps such a rule honest.

## File changes

| File | Change |
|---|---|
| `docs/api/openrpc.json` | the contract |
| `crates/credsd-core/Cargo.toml` | optional `schemars`, `schema` feature |
| `crates/credsd-core/src/rpc/*.rs`, `presence.rs`, `credentials.rs`, `projection.rs`, `config/mod.rs` | `cfg_attr` derives and schema attributes on wire types |
| `crates/credsd-daemon/Cargo.toml` | dev-dependency enables `credsd-core/schema` |
| `crates/credsd-daemon/src/server/contract.rs` | `#[cfg(test)]`: method table, renderer, current-file test, compatibility test |
| `.github/workflows/ci.yml` | compatibility step against the base branch |
| `AGENTS.md` | pointer to the contract and the regenerate command |

## Testing Strategy

- **Current:** the rendered document equals the committed file (5.1).
- **Complete:** every `Method` variant and every notification appears (1.2), enforced by the
  exhaustive match and by a test over `Method::all`.
- **Valid:** the document validates against the OpenRPC meta-schema, vendored as test data, and
  each component schema against JSON Schema draft 7 (5.6).
- **Faithful:** per wire type, a representative value serializes to JSON that validates against
  its schema, and each published example deserializes (5.7). Values with secrets use fixed
  placeholders.
- **Compatible:** the classifier's own unit tests cover each rule in 5.3 with a before/after pair.

## Rejected alternatives

**OpenAPI 3.1.** It models HTTP paths and verbs. JSON-RPC is one endpoint whose body varies by
method, which OpenAPI can express only as one large `oneOf` that tooling cannot use. The Unix
socket carrier is not HTTP.

**Smithy.** It is independent of protocol and expressive, but it defines no JSON-RPC protocol.
Using it means writing a protocol trait and a code generator, and maintaining a Java and Gradle
toolchain beside a Rust workspace.

**AsyncAPI.** It fits the progress notifications and fits request and response poorly.

**JSON Schema alone.** It covers types but has no notion of a method, its errors, or its carrier.
OpenRPC contains JSON Schema, so nothing is lost by using it.

**A hand-maintained contract checked by round-trip tests.** It needs no new dependency, but every
type change needs a matching hand edit, and the round trip catches only what its examples
exercise. Deriving the schemas catches every member.
