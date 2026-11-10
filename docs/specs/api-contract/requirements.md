# Requirements: API Contract

**Status:** draft (spec phase — approval means "proceed to implementation")
**Feature:** `api-contract`
**Scope:** the JSON-RPC 2.0 surface the daemon serves on every carrier.

## Introduction

The daemon's API is described by one machine-readable document, `docs/api/openrpc.json`, in
OpenRPC format. The document is the contract a client builds against and the record a reviewer
reads to see what a change does to the wire. It is generated from the Rust types that serialize
the wire, so it cannot drift from them, and CI refuses a change that alters the wire without
updating it or that breaks compatibility without a version change.

Behavior lives elsewhere. The contract fixes shape: method names, parameters, results, error codes,
which carrier exposes each method, and which methods are gated. What a method does, and when it
refuses, stays in the feature specs (`credential-retrieval-api`, `presence-gated-operations`,
`drift-detection`, and the rest), which refer to methods by their names in the contract.

### Terminology

- **Contract** — `docs/api/openrpc.json`.
- **Wire type** — a Rust type that is serialized into, or deserialized from, a request, a
  response, an error's `data`, or a notification.
- **Method table** — the in-code list, one entry per dispatchable method and notification, that
  carries what the types cannot: summary, errors, carriers, gating, and streaming.
- **Breaking change** — a change that a client built against the base contract can observe as a
  failure or a changed meaning (Requirement 5.3).

## Requirements

### Requirement 1: One contract, in OpenRPC

**User story:** As a client author, I want one document that names every method and its exact
shapes, so that I can build and test a client without reading the daemon's source.

#### Acceptance Criteria

1.1. The contract SHALL be a single OpenRPC 1.3 document at `docs/api/openrpc.json`, and SHALL
     validate against the OpenRPC meta-schema.

1.2. The contract SHALL describe every method the daemon dispatches on any carrier, and every
     notification in either direction. A method or notification the daemon handles and the
     contract omits is a defect in the contract.

1.3. Each method SHALL use `paramStructure: "by-name"`. Each parameter SHALL state whether it is
     required. A method whose parameters reject unknown members SHALL say so with
     `x-deny-unknown-params: true`; any other method ignores unknown members.

1.4. Each schema SHALL describe what the daemon accepts and emits, including defaults, `null` for
     a member serialized as `null`, and omission for a member skipped when empty. An enum that
     accepts unrecognised values without failing SHALL be marked `x-open-enum: true`.

1.5. Every member that carries secret material SHALL be marked `x-secret: true`. The contract
     SHALL contain no secret values, including in examples.

1.6. The contract SHALL be serialized deterministically: the same wire types and method table
     always produce byte-identical output.

### Requirement 2: Errors are part of the contract

**User story:** As a client author, I want to know which failures a method can return, so that I
handle each one and not a catch-all.

#### Acceptance Criteria

2.1. Each method SHALL list every error it can return, as references to `components.errors`.

2.2. JSON-RPC envelope errors (`-32700`, `-32600`, `-32601`, `-32602`, `-32603`) SHALL appear
     under their own codes.

2.3. A domain failure SHALL appear as an error with code `-32000` and `data.code` set to its
     `DomainCode` string. Each `DomainCode` the daemon emits SHALL have exactly one entry in
     `components.errors`.

2.4. WHEN a domain error carries members in `data` beyond `code`, THEN the schema of its `data`
     SHALL be published under the top-level `x-error-data`, keyed by the `DomainCode` string.

### Requirement 3: Carriers, gating, and streaming are stated

#### Acceptance Criteria

3.1. Each method SHALL list the carriers that expose it in `x-carriers`. The list SHALL equal the
     daemon's exposure table for that method.

3.2. Each method that raises a presence challenge SHALL name the gated operation in `x-gated`.

3.3. Each method that streams SHALL state, in `x-streaming`, the notifications it emits and the
     client notifications it accepts while in flight.

3.4. Notifications SHALL be listed under the top-level `x-notifications`, each with its name,
     its direction (`server-to-client` or `client-to-server`), and the schema of its params.

3.5. WHILE a method or parameter is accepted under an older name, the older name SHALL be listed
     in `x-aliases` on the method or parameter it resolves to.

### Requirement 4: The code is the source of truth

**User story:** As a maintainer, I want the contract derived from the code, so that it is true by
construction and a reviewer never has to compare prose against a diff.

#### Acceptance Criteria

4.1. The schemas in the contract SHALL be derived from the wire types. The method-level members
     SHALL be derived from the method table.

4.2. The method table SHALL be built so that adding a dispatchable method without an entry fails
     to compile or fails a test.

4.3. The contract SHALL NOT be edited by hand. It SHALL be regenerated by a documented command,
     and the regenerated file SHALL be committed.

4.4. Deriving the contract SHALL NOT add code, dependencies, or behavior to a shipped binary.

### Requirement 5: Every change is validated

**User story:** As a reviewer, I want CI to tell me whether a change touches the wire and whether
it breaks clients, so that I do not have to infer either from the code.

#### Acceptance Criteria

5.1. CI SHALL regenerate the contract and SHALL fail WHEN the result differs from the committed
     file. The failure SHALL name the regenerate command.

5.2. CI SHALL compare the contract on the change against the contract on its base branch, and
     SHALL classify each difference as breaking or additive.

5.3. The following SHALL be classified as breaking:
     - a method or notification removed or renamed without an alias;
     - a parameter added as required, or made required;
     - a parameter, result member, or error-data member removed or renamed without an alias;
     - a type narrowed, including an enum value removed or a closed enum made from an open one;
     - a member's `null`, default, or omission behavior changed;
     - an error code removed from a method, or a `DomainCode` repurposed;
     - a carrier removed from a method, or `x-gated` added to one.

5.4. Every other difference SHALL be classified as additive.

5.5. WHEN a change contains a breaking difference, THEN CI SHALL fail unless the change also
     raises the major of `info.version`, or `info.x-prelaunch-waiver` is `true`.

5.6. CI SHALL validate the contract against the OpenRPC meta-schema, and SHALL validate each
     component schema as a JSON Schema.

5.7. For each wire type, CI SHALL serialize at least one representative value and validate it
     against the type's schema, and SHALL validate that the type deserializes each example the
     contract publishes.

### Requirement 6: Versioning

#### Acceptance Criteria

6.1. `info.version` SHALL be `MAJOR.MINOR.PATCH`. MAJOR SHALL equal the protocol version the
     daemon reports from `system/health`.

6.2. A breaking change SHALL raise MAJOR and the reported protocol version together. An additive
     change SHALL raise MINOR. A change only to descriptions or summaries SHALL raise PATCH.

6.3. `info.x-prelaunch-waiver` records `credential-retrieval-api` Requirement 11 AC 3. It SHALL be
     removed at the first external release and SHALL NOT be restored.

### Requirement 7: Relationship to feature specs

#### Acceptance Criteria

7.1. A feature spec that defines a method's behavior SHALL refer to the method by its name in the
     contract, and SHALL NOT restate its parameter or result shapes.

7.2. WHEN the contract and a feature spec's acceptance criteria disagree, THEN the disagreement is
     a spec-coherence conflict (`AGENTS.md`, Spec Coherence) and SHALL be resolved in the same
     change that introduces it.

7.3. `docs/reference/api.md` remains the human-oriented guide. Where it and the contract disagree
     on a shape, the contract is correct.

## Non-Goals

- **Describing behavior.** Preconditions, refusals, and side effects stay in the feature specs.
- **Generating clients.** The contract makes generation possible; this spec does not require it.
- **The HTTP credential endpoint.** It is not a JSON-RPC surface.
- **MCP framing on the stdio carrier.** The contract describes the methods that carrier exposes,
  not the MCP envelope around them.
