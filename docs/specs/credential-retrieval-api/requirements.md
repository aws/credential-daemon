---
status: accepted
created: 2026-08-14
---

# Requirements Document: Credential Retrieval API

## Introduction

An earlier change decoupled profiles from credential sources in the data model: a credential source is
a named, shareable entry in `credentials.toml`, and a profile references one. The retrieval
API did not follow. It still asks exactly one question — *"give me the credentials for
profile P"* — in two wire formats: `/credentials/:profile` returns the native `Credentials`
type, `/container_credentials/:profile` returns the ECS container-credentials contract
(`src/server/mod.rs:124-136`). Both resolve through `credential_store.get(profile)`.

Three consequences motivate this spec:

1. **Granularity is unavailable.** A caller cannot ask for one credential. It can only ask
   for a profile and receive whatever that profile happens to resolve to. This forecloses
   profiles that aggregate more than one credential, and it makes the authorization subject
   a profile *name* rather than the material that name reaches — the alias problem.
2. **Scope-down has no input surface.** `scope-down-plugin` Layer 2 requires the caller to
   supply a session policy per invocation. There is no request parameter for it, and adding
   one is not a wire-format detail: it changes what a request *is*, what may be cached, and
   what the response means.
3. **Foreign shims cannot participate.** Any execution shim credsd does not own — a language
   SDK plugin, a container init, a CI runner, a generated `credential_process` entry — must
   today either read `config.toml` itself or accept the one question the API asks. Reading
   the config file re-couples the shim to a layout this project keeps changing.

**Goal:** a retrieval API granular enough to name a single credential, self-describing
enough that a shim credsd does not own can discover what it needs, and shaped so
scope-down's parameters are first-class rather than bolted on.

### Organizing principle: logical questions versus transport questions

This spec is deliberately split, because the two halves have different maturity and
different blast radius.

**Part I — Logical model.** What is being asked, by whom, with what parameters, and what the
answer means. This is what scope-down depends on, what a foreign shim must understand, and
what cannot be changed later without breaking every consumer. Transport-independent: every
criterion in Part I holds whether the bytes move over HTTP, a named pipe, or a library call.

**Part II — Transport binding.** How the logical model is expressed on the wire. **JSON-RPC
2.0 is the protocol for every credsd API**, carried over a Unix domain socket by
`credsd serve`. HTTP and model-facing stdio belong to run-time tooling that requires them for
compatibility (see Non-Goals). This is a consolidation onto precedent, not a new choice:
JSON-RPC 2.0 has precedent twice, hand-rolled for MCP and specified for plugin stdio
(`plugin-framework` design). What remains open is the method
namespace and, more consequentially, which methods each carrier exposes.

A uniform protocol makes Part I's transport-independence real rather than aspirational, and
it **dissolves the seam the prior draft of this spec identified.** That draft argued a
logical decision in Requirement 4 forced a verb in Requirement 10: scope is a large
structured input, so it must travel in a body, so retrieval must be `POST`. Under JSON-RPC
there is one message shape — method plus structured `params` — so the forcing disappears and
the question is withdrawn rather than answered.

Three new seams replace it, all sharper than the one they retire:

- **Carrier determines surface, not semantics (Requirement 13).** The daemon serves one
  carrier, UDS, and tells callers apart by caller verification rather than by carrier. This is
  where the "is atomic retrieval agent-reachable?" question lands, and the line is **settled**:
  run-time tooling that faces a model may let it learn what exists and ask for a projection over
  it; it never hands the model Material.
- **A protocol feature can defeat a logical invariant (Requirement 3 / Open Decision 3).**
  JSON-RPC batching returns independent per-element results, which reconstructs a partially
  satisfied aggregate — precisely what all-or-none prohibits.
- **Session lifetime versus caller identity (Requirement 14).** Long-lived sessions turn a
  connect-time identity check into a bearer capability. Re-sampling per request restores it,
  and on macOS the kernel cooperates more than expected — but not uniformly across platforms.

| Question | Half | Status |
|---|---|---|
| What may be named as a retrieval subject | Logical (Req 1) | Proposed |
| What the authorization decision is *about* | Logical (Req 2) | Proposed; conflicts with an accepted spec — see Spec Conflicts |
| Whether an aggregate may be partially satisfied | Logical (Req 3) | Proposed |
| Whether scope is a request parameter, and its shape | Logical (Req 4) | Proposed |
| Whether a scoped result may be cached or reused | Logical (Req 5) | Proposed |
| How a shim discovers what exists without reading config | Logical (Req 6) | Proposed |
| What kinds of credential exist and which are projectable | Logical (Req 7) | Proposed |
| How failures are distinguished | Logical (Req 8) | Proposed |
| Protocol, framing, authentication | Transport (Req 9) | **Settled — JSON-RPC 2.0** |
| Method names and params shape | Transport (Req 10) | Narrowed; encoding settled, naming open |
| Versioning and compatibility | Transport (Req 11) | Open |
| Relationship to SDK-compatible surfaces | Transport (Req 12) | Proposed |
| Which methods each carrier exposes | Transport (Req 13) | **Settled — one carrier (UDS); no Material to a model** |
| Whether caller identity is re-sampled per request | Transport (Req 14) | Proposed; Linux mechanism unverified |

### Non-Goals

- **This is not the AWS-SDK-compatible surface.** SDK compatibility stays a *projection* at
  the edge: an ephemeral proxy run-time tooling starts, and `credential_process` entries in a
  generated AWS config. See Requirement 12.
- **Not run-time tooling.** Launching a process with credentials, serving an agent harness over
  MCP, and SDK compatibility endpoints are run-time ease-of-use tooling, future development built
  on this API. This spec states only what that tooling may rely on and the lines it is held to
  (Requirements 12 and 13).
- **Not a policy language.** Scope and boundary *documents* are specified by
  `scope-down-plugin`. This spec governs only how a scope reaches the daemon and what the
  daemon does with the fact that one was supplied.
- **Not a decision on where boundaries attach.** That is a live conflict with an accepted
  spec; it is recorded in Open Decisions with a favored option, not settled here.
- **Not multi-credential profiles.** M:N profile→credential is out of scope. The API MUST
  NOT foreclose it (Requirement 1 AC 5), which is a constraint, not an adoption.

## Glossary

- **Material**: the secret bytes a retrieval produces — an AWS session credential, an access
  token. The thing whose disclosure is being controlled.
- **Retrieval_Subject**: what a request names. Exactly two kinds: a **Credential** (a
  `credentials.toml` entry — one unit of material) or a **Profile** (an aggregate of
  credentials plus subprocess configuration).
- **Atomic_Retrieval**: a request whose subject is a Credential. Produces material for
  exactly one credential.
- **Aggregate_Retrieval**: a request whose subject is a Profile. Produces, or authorizes,
  material for every credential that profile names.
- **Authorization_Context**: the profile under whose authority a retrieval is evaluated.
  Distinct from the subject: the context supplies *restriction* (boundary, region, subprocess
  config), the subject identifies *material*.
- **Credential_Kind**: the discriminant of the material — today `session-credentials` or
  `access-token` (`CredentialData` in `src/credentials.rs`). Not the same as the credential
  *source* type (`sso`, and future source types), which describes how material is obtained.
- **Requested_Scope**: a session policy supplied by the caller on a single retrieval, which
  can only narrow. Layer 2 of `scope-down-plugin`.
- **Boundary**: a session policy applied unconditionally by the daemon, which the caller
  cannot broaden or bypass. Layer 1 of `scope-down-plugin`.
- **Effective_Permissions**: `Role ∩ Boundary ∩ Requested_Scope`, per `scope-down-plugin`
  Req 1 AC 5.
- **Foreign_Shim**: an execution shim credsd does not own, which obtains material through
  this API — a language SDK credential provider, a container init, a CI runner, a
  `credential_process` entry in a generated AWS config.
- **Projection**: rendering material into an execution environment (env vars, a generated
  AWS config file, an intercepted request). Distinct from retrieval: retrieval answers
  *what*, projection decides *how it appears*.
- **Manifest**: the non-secret description of a profile — which credentials it names, their
  kinds, their status, and the inputs a Projection needs — obtainable without obtaining
  material. Distinct from **Enumeration**, which lists credentials and is capped at name, kind,
  and status (Requirement 13 AC 4).

---

# Part I — Logical Model

Every criterion in this part is transport-independent.

## Requirement 1: Two Retrieval Subjects

**User Story:** As an author of a foreign shim, I want to name exactly the credential I
need, so that I am not forced to accept whatever a profile resolves to and am not obliged to
parse credsd's config files to find out what that will be.

### Acceptance Criteria

1. THE API MUST support exactly two Retrieval_Subjects: a Credential (Atomic_Retrieval) and
   a Profile (Aggregate_Retrieval). No third subject is introduced.
2. Atomic_Retrieval MUST produce material for exactly one credential, or fail. It MUST NOT
   fall back to a default, a sibling, or a profile-shaped result.
3. Aggregate_Retrieval MUST be defined in terms of Atomic_Retrieval: the aggregate result
   is the composition of the atomic results for every credential the profile names, subject
   to Requirement 3.
4. THE two subjects MUST be distinguishable in a request without ambiguity. A single opaque
   name field whose meaning depends on which namespace happens to contain it is prohibited:
   profile names and credential names share a namespace shape (both validated by
   `config::credentials::validate_name`) and a name may exist in both files.
5. THE API MUST NOT assume a profile names at most one credential. Response shapes and params
   schemas MUST remain well-formed if a profile later names several. This is a
   forward-compatibility constraint only; M:N is not adopted by this spec.
6. WHEN a profile names exactly one credential (the shipped cardinality), Aggregate_Retrieval
   MUST remain a distinct operation from Atomic_Retrieval on that credential, because the two
   differ in Authorization_Context (Requirement 2) and in what they return (Requirement 6).

## Requirement 2: Authorization Subject and Restriction Context

**User Story:** As a security engineer, I want the authorization decision to be about the
material being disclosed rather than about a name that reaches it, so that two names for one
credential cannot carry two different verdicts.

### Rationale

An authorization decision needs a subject identical to the thing whose disclosure it
controls. Today the subject is a profile name while the controlled thing is material
reachable through N names, so the decision is over an alias — and aliases can disagree. This
is the mechanism: under N:1, an agent-restricted
profile and an agent-permitted profile can be aliases for identical material, so a caller
denied one asks for the other and receives the same bytes.

Anchoring the decision on the credential dissolves this rather than validating around it:
there is exactly one decision per unit of material, and the field that could disagree with
itself stops existing.

**Decision and restriction are separate concerns and do not want the same anchor.**
Authorization asks *may this caller see this material?* — that is about material.
Restriction asks *what may be done with it?* — `boundary_policy`, region, subprocess
configuration — and `scope-down-plugin` Req 1 AC 4 with its 2026-08-13 amendment
deliberately places that on the profile, so that two profiles may share one login with
different boundaries.

### Acceptance Criteria

1. THE authorization decision for any retrieval MUST be evaluated per credential. For
   Aggregate_Retrieval this means one decision per credential the profile names, not one
   decision on the profile.
2. THE Authorization_Context MUST supply restriction, not identity: boundary, region, and
   subprocess configuration come from the profile; the decision subject is the credential.
3. Atomic_Retrieval MUST NOT return material that has escaped a restriction the same
   material would have carried under Aggregate_Retrieval. Concretely: if profile P applies a
   boundary to credential C, no Atomic_Retrieval of C may yield unbounded material.
4. AC 3 is a security invariant and MUST be satisfied structurally, not by convention. The
   candidate mechanisms are enumerated in Open Decisions; **the favored one is that
   Atomic_Retrieval carries an Authorization_Context — the request names both the profile
   under whose authority it is made and the credential it selects.** Under that mechanism a
   request for a credential the named profile does not reach MUST fail (Requirement 8 AC 4),
   and the boundary that applies is the context profile's.
5. THE system MUST NOT introduce a per-credential copy of any field that already exists per
   profile for restriction purposes. Duplicating `boundary_policy` or `region` onto credential
   sources recreates the disagreement problem on the other axis.
6. WHEN Requirement 2 is implemented, THE `identity_type`-based Agent_Restricted_Profile
   determination in `caller-verification-policy` Req 7.4 MUST be reconciled with it. That
   requirement currently mandates the profile as the determinant and explicitly forbids a new
   field; AC 1 here makes the credential the decision subject. **This is a spec conflict
   requiring approval — see Spec Conflicts. It MUST NOT be resolved by unilaterally editing
   either spec.**

## Requirement 3: Aggregate Retrieval Is All-or-None

**User Story:** As an operator, I want a profile request to either fully succeed or fully
fail, so that a subprocess never runs in an environment that looks configured but is silently
missing a credential.

### Rationale

The all-or-none rule is worth stating precisely, because it does **not** buy confidentiality.
A caller denied profile P because credential C1 is restricted can request C2 directly and
receive exactly the material P would have handed it — the per-credential decisions already
determine what is disclosable. What the rule buys is:

- **Integrity.** A partially satisfied aggregate produces an execution environment that
  presents as configured and fails at an arbitrary later point, possibly after side effects.
- **Oracle suppression.** A partial response discloses *which* credential was restricted,
  turning a denial into a discovery primitive.

Framed this way, the aggregate rule carries no policy of its own: it is a fold over the
per-credential decisions, and enforcement effort belongs entirely at the per-credential
decision.

### Acceptance Criteria

1. WHEN any credential in an Aggregate_Retrieval is denied, THE system MUST fail the entire
   request and return no material for any credential in it.
2. THE aggregate verdict MUST be the most restrictive of the per-credential verdicts. There
   is no partial-success result and no per-credential status array in a material-bearing
   response.
3. A failed Aggregate_Retrieval MUST NOT disclose which credential caused the failure to the
   caller. The audit record MUST record it (see `caller-verification-policy` for the audit
   contract).
4. AC 3 constrains the error body only. THE Manifest operation (Requirement 6) MAY disclose
   per-credential status to a caller authorized to see the manifest, because a manifest
   carries no material.
5. WHEN an Aggregate_Retrieval fails because a credential has no valid session (as opposed to
   being denied), THE system MUST distinguish that case in the error code (Requirement 8),
   because the remedy is a login rather than a policy change. This distinction MUST NOT leak
   which credential when the failure is a denial.

## Requirement 4: Scope as a Request Parameter

**User Story:** As an agent harness, I want to supply a session policy with a retrieval, so
that each operation receives credentials scoped to exactly what it needs.

### Rationale

A Requested_Scope is a structured document, not a flag. `scope-down-plugin` caps inline
session policies at 2048 characters and contemplates larger policies via managed ARNs or
`GetScopedCredential`.

Under JSON-RPC this costs nothing: `params` is a structured object, so a policy document is
an ordinary field of it. Worth recording that the prior HTTP draft of this spec treated the
parameter's size as the one place the logical and transport halves collided — a body-only
parameter forcing `POST`, foreclosing a cacheable `GET`. That collision was an artifact of
HTTP and is gone. The 2048-character limit remains, but it is an STS constraint on the
policy, not a property of the transport.

### Acceptance Criteria

1. THE API MUST accept an optional Requested_Scope on Atomic_Retrieval.
2. A Requested_Scope MUST be accepted as an inline policy document. It MAY additionally be
   accepted as a reference (`file://`, `name://`) per `scope-down-plugin` Req 7; if a
   reference form is accepted, resolution MUST happen daemon-side and the resolved document
   MUST be subject to the same validation as an inline one.
3. THE Requested_Scope MUST compose by intersection only: `Role ∩ Boundary ∩
   Requested_Scope`. THE system MUST NOT provide any parameter that broadens, replaces, or
   suppresses a Boundary.
4. WHEN a Requested_Scope is supplied on an Aggregate_Retrieval, THE system MUST either apply
   it to every credential in the aggregate or reject the request. It MUST NOT apply a scope
   to some credentials and not others. *Which of the two is not settled — see Open
   Decisions; applying one policy document across heterogeneous credential kinds is not
   generally meaningful.*
5. IF a Requested_Scope is malformed, or exceeds the size limit, THE system MUST fail the
   retrieval with a distinct error code and MUST NOT fall back to unscoped material. Silent
   downgrade from scoped to unscoped is a privilege-escalation path.
6. THE absence of a Requested_Scope MUST mean "boundary-scoped", never "unscoped".
7. THE system MUST record in the audit trail whether a scope was supplied and a stable digest
   of it, without recording the document itself (a scope may name resources that are
   themselves sensitive).

## Requirement 5: Freshness, Caching, and Scope Identity

**User Story:** As an author of a foreign shim, I want to know when I may reuse material and
when I must re-ask, so that I neither hammer the daemon nor serve a credential whose
authority no longer matches what I asked for.

### Rationale

`CredentialStore` caches by credential name alone (`src/credential_store.rs:24-27`). Once a
scope is a request parameter, that key is unsound: a scoped result served from a cache
populated by a differently-scoped or unscoped request has the wrong authority. This is a
correctness requirement, not an optimization.

### Acceptance Criteria

1. THE cache identity of a retrieval result MUST include the Requested_Scope, not only the
   credential. Two retrievals of one credential with different scopes are different results.
2. A scoped result MUST NOT be served to a request with a different scope, or with no scope.
3. AN unscoped (boundary-only) result MUST NOT be served to a request that supplied a scope.
4. Every material-bearing response MUST carry either an absolute expiry or an explicit null
   meaning the credential does not expire. Relative lifetimes remain prohibited: a shim's clock
   skew must not silently extend a credential's life. A null expiry is not a relative lifetime —
   it states there is no expiry to skew — so it does not reintroduce that risk. (A source with
   no issuer-stated lifetime, e.g. `static-secret`, uses null; see
   `docs/specs/static-secret-credentials/`.)
5. THE response MUST distinguish "this material is cached and shared" from "this material was
   minted for this request", so a shim can decide whether local caching is appropriate. Under
   Requirement 3 a shared session is reusable across profiles naming the same credential; a
   scoped session generally is not.
6. THE API MUST NOT require a shim to cache in order to be well-behaved. Rate limits or
   refresh coalescing are daemon-side concerns; a shim that re-asks per operation MUST remain
   correct, and the daemon's existing per-credential coalescing (one provider, one refresh
   timer) already makes that affordable.

## Requirement 6: Discovery Without Material

**User Story:** As an author of a foreign shim, I want to discover what credentials exist and
what kind they are without obtaining any of them and without reading credsd's config files,
so that my shim does not break when the config layout changes.

### Rationale

Run-time tooling that generates an AWS config file needs, under Requirement 12, one
`credential_process` entry per credential, each a per-credential retrieval. Generating it requires knowing
the aggregate's membership. Any consumer that must read `config.toml` or `credentials.toml`
to learn that is coupled to a layout that has changed twice in this release cycle
(`secrets.toml` → `credentials.toml`; `mode`/`sso` → source entries).

### Acceptance Criteria

1. THE API MUST provide a Manifest operation that returns, for a profile: every credential it
   names, each credential's Credential_Kind, each credential's source type, and each
   credential's session status.
2. THE Manifest MUST contain no material and no value that would be secret if logged.
3. THE Manifest MUST be sufficient to construct a projection without reading any credsd
   config file. If a projection needs a datum, the Manifest carries it.
4. THE Manifest MUST report per-credential session status even where a material-bearing
   response would not (Requirement 3 AC 4), so that a shim can tell the user which login is
   missing.
5. Authorization for the Manifest MUST be evaluated separately from authorization for
   material. Learning that a credential exists is not learning its bytes; the two decisions
   MAY differ.
6. THE Manifest MUST identify the designated default credential of a profile if one exists,
   because an environment projection has exactly one ambient credential slot. *Whether profiles gain a default-credential field is deferred to whichever spec
   adopts M:N; under the shipped 1:1 cardinality the sole credential is the default.*

### Settled, 2026-08-24 — the Manifest is `environment/describe`, and it is not `credential/list`

AC 3 obliges the Manifest to carry projection data. AC 1 keys the Manifest on a profile. Both
are intentional: AC 3 exists so an execution shim building an environment — env vars, a
generated AWS config file — has an API surface for it and never parses `config.toml`. That is
the coupling the One-Way-Door section warns returns informally if the Manifest is incomplete.

AC 3 collides with Requirement 13 AC 4, which caps the model-facing `credential/list` at a
credential's name, Credential_Kind, and session status — "**and nothing more**". One method
cannot satisfy both, and a per-carrier field set is not the escape: Requirement 13 AC 6 permits
carrier-specific *exposure* and prohibits carrier-specific *semantics*.

**Resolution: two methods, which settles Requirement 13 AC 7.** The subject decides where a
datum lives. Region and the SDK/CLI knobs are properties of a *profile*, not of a credential,
so they belong to a profile-subject method:

| Method | Subject | Returns |
|---|---|---|
| `environment/describe` | profile | AC 1's credential entries **plus** the projection inputs AC 3 obliges |
| `credential/list` | credential | name, Credential_Kind, session status — nothing more (Req 13 AC 4) |

`environment/describe` is the Manifest operation of AC 1-6. `credential/list` is a narrower,
separately-authorized enumeration that happens to overlap it on three fields; it is not a
projection of the Manifest type and MUST NOT grow toward one, because Requirement 13 AC 4 binds
it and Requirement 11 AC 2 makes any field it gains permanent.

The projection inputs AC 3 obliges today, all from `ProfileConfig` (`src/config/mod.rs:116-129`):
`region`, the up-to-15 fields of `SdkSettings` (`:63-94`), and the 5 fields of `CliSettings`
(`:96-108`). `identity_type` is excluded — it is an authorization input, not a projection one,
and disclosing it would tell a caller how it will be classified. `credential` is excluded as a
field because AC 1's entries already name the membership.

*Amendment note. No acceptance criterion changed. AC 3's obligation stands verbatim; what is
new is naming the method that discharges it, which Requirement 13 AC 7 explicitly delegated.
An earlier draft of this section proposed narrowing AC 3 to credential discovery only — that
was wrong, and rejected: Requirement 6's own user story says "without reading credsd's config
files", which covers projection data, so AC 3 was never overreach.*

## Requirement 7: Credential Kinds and Projectability

**User Story:** As an author of a foreign shim, I want to know before I ask whether the
material I would receive is something I can consume, so that a type mismatch is a
configuration error rather than a runtime failure.

### Rationale

`CredentialData` is already heterogeneous, and `serve_container_credentials` returns a
runtime `400 WRONG_CREDENTIAL_TYPE` when a profile yields an access token rather than session
credentials (`src/server/routes.rs:159-173`). With a Manifest and an explicit kind, that
becomes a check the shim or the daemon performs at composition time.

### Acceptance Criteria

1. Every material-bearing response MUST carry an explicit Credential_Kind discriminant. A
   consumer MUST NOT have to infer kind from which fields are present.
2. THE Manifest MUST report Credential_Kind per credential, so a shim can determine
   consumability before requesting material.
3. THE system MUST define, per projection, which Credential_Kinds are projectable. An
   `access-token` credential is not projectable into the AWS ambient credential slot.
4. WHEN a profile's designated default credential is not projectable into the environment
   slot, THE system SHOULD surface this at configuration time rather than at spawn time.
5. Adding a Credential_Kind MUST NOT require a change to the retrieval request shape. Kind is
   a property of the answer, not of the question.

## Requirement 8: Error Taxonomy

**User Story:** As an author of a foreign shim, I want machine-readable failure
classification, so that my shim can retry, prompt for login, or fail hard as appropriate
without parsing prose.

### Acceptance Criteria

1. Every failure MUST carry a stable machine-readable code alongside human-readable text. THE
   code MUST be a domain string in the style of an unprefixed domain
   string (`ENVIRONMENT_NOT_FOUND`, `CONFIG_ERROR`, `UNSUPPORTED`), not a numeric
   JSON-RPC code. Numeric codes (`-32700`, `-32601`, `-32602`) are reserved for envelope
   failures — unparseable message, unknown method, malformed params — and MUST NOT be
   overloaded to carry domain meaning. The distinction matters because a shim must be able to
   tell "credsd rejected my request" from "credsd did not understand my request."
2. THE taxonomy MUST distinguish at minimum: unknown subject; known subject but not
   authorized; authorized but no valid session (remedy: login); authorized but material is
   not of a consumable kind; scope malformed or oversized; scope rejected by policy;
   transient upstream failure (remedy: retry).
3. "Unknown subject" and "not authorized" MUST be distinguishable to the *audit record* and
   MUST NOT be distinguishable to an unauthorized *caller*, preserving the existing
   attributable-miss behavior (`profile_not_found` in `src/server/routes.rs`).
4. WHEN a request names a credential that its Authorization_Context does not reach
   (Requirement 2 AC 4), THE response MUST be indistinguishable from that for a credential
   that does not exist.
5. Codes MUST be additive-only. Removing or repurposing a code is a breaking change under
   Requirement 11.
6. WHETHER a domain failure is returned as a JSON-RPC `error` object or as a successful result
   carrying an error flag MUST be decided once and applied uniformly (Open Decision 5). Both
   conventions exist in an MCP envelope, for a defensible reason on the MCP side:
   a `tools/call` failure rides inside a success envelope with `isError: true` because the
   error must reach the model. A shim-facing API has no such requirement.

### Implementation status, 2026-08-21 — AC 2 partially met

Five of AC 2's seven conditions have codes: `ENVIRONMENT_NOT_FOUND` (unknown subject, and by AC 3-4
also not-authorized), `REAUTH_REQUIRED` (no valid session), `WRONG_CREDENTIAL_TYPE` (material not
of a consumable kind), `PROVIDER_UNAVAILABLE` (transient upstream), and `INTERNAL`.

The two scope conditions — scope malformed or oversized, and scope rejected by policy — are
**deliberately unnamed** until the Requested_Scope grammar exists. AC 5 makes codes additive-only,
so a name coined before its domain is permanent, and both conditions are unreachable today
because nothing can populate a scope. The first three names are carried over byte-identically
from the HTTP surface (`src/server/routes.rs:166`, `:214`, `:249`) rather than coined here, so the
transport port does not rename a code a caller may already branch on.

# Part II — Transport Binding

## Requirement 9: Settled Transport Facts

JSON-RPC 2.0 is the protocol for every credsd API. This is uniform across carriers and is not
open. Recorded so Part I's implementation cannot drift from it.

### Acceptance Criteria

1. THE wire protocol for every credsd API MUST be JSON-RPC 2.0: `credsd serve` carries it
   over a Unix domain socket, and the plugin framework carries it over a child process's
   stdio. A model-facing stdio carrier is run-time tooling's, not the daemon's.
2. HTTP is not a credsd API surface. New credsd functionality MUST NOT be added over HTTP. Where SDK
   compatibility requires HTTP, it is served by run-time tooling (see Non-Goals), never by the
   daemon.
3. THE existing UDS routes (`/health`, `/credentials/:profile`,
   `/container_credentials/:profile` — `src/server/mod.rs:124-136`) are therefore
   transitional. Migrating them is in scope for this spec's implementation, and under AC 2
   only the container-credentials shape survives, inside run-time tooling's compatibility proxy.
4. Message framing MUST follow the convention already established in both existing JSON-RPC
   surfaces: one JSON object per line, newline-terminated (`credsd-core`'s `rpc::codec`;
   `plugin-framework` design). A second framing (`Content-Length` headers) MUST NOT be
   introduced.
5. THERE MUST be no bearer token on the UDS surface. Peer credentials are the authentication:
   there is no listener a non-owning user can reach (`src/server/mod.rs:33-37`).
6. Caller PID MUST be acquired from kernel peer credentials, per `caller-verification-policy`
   Req 1.2. THE system MUST NOT reintroduce TCP port-to-PID resolution (Req 1.5). Note that
   `verify_peer_uid` samples the peer once per *connection* (`src/server/uds.rs:60-75`), whose
   meaning a long-lived JSON-RPC session changes — see One-Way Door Risks.
7. *Not a core requirement.*
8. *Not a core requirement.*
9. THE carrier MUST NOT be the place any Part I semantic is expressed implicitly. A JSON-RPC
   error object carries no meaning not also present in the Requirement 8 code, and no HTTP
   status in the compatibility shim adds any.

## Requirement 10: Method Surface and Params Shape

**User Story:** As an implementer, I want method names and params shape settled before code,
so that the API surface is not an accident of the first handler written.

### What the protocol settles

JSON-RPC has one message shape — a method name plus a structured `params` object — which
retires four questions the HTTP draft carried:

1. Requested_Scope is an ordinary `params` field. No size ceiling beyond the policy's own, no
   query-string escaping, and no appearance in a request line that lands in an access log or a
   process listing.
2. There is no verb, so there is no verb question. The prior draft's open decision on keeping a
   `GET` form for unscoped retrieval is **withdrawn** as an HTTP artifact.
3. There is no route, so the subject distinction (Requirement 1 AC 4) is carried by the method
   name and params schema rather than by path structure — which is a stronger guarantee, since
   a method name cannot be ambiguous the way `/{name}` can.
4. Requirement 5's cache identity becomes purely daemon-internal: no JSON-RPC intermediary
   caches, so the unsound-cache-key problem has no external component to reason about.

### Acceptance Criteria

1. Each logical operation MUST be a distinct method. Overloading one method on the shape of
   its params to mean two operations is prohibited (Requirement 1 AC 4).
2. Method names MUST distinguish Atomic_Retrieval, Aggregate_Retrieval, and Manifest.
3. Params MUST be a named object, never positional. JSON-RPC permits array params;
   forward-compatible field addition (Requirement 11 AC 2) requires objects.
4. Requested_Scope MUST be a params field of the retrieval methods (Requirement 4).
5. THE credsd method namespace MUST NOT collide with MCP's reserved methods (`initialize`,
   `tools/list`, `tools/call`), so that one dispatcher can serve both carriers if
   Requirement 13 permits it.

### Settled, 2026-08-21

The method surface is fixed at three names in the singular `credential/` namespace, plus two
non-retrieval methods. Slash style, matching MCP's convention and what is already in the tree,
and consistent with the names Open Decision 6 already used when it resolved.

A namespace is an interface in the Java sense — semantically related operations over one
subject. That is why the Manifest is not a `credential/` method: its subject is a profile, and
Requirement 6's "Settled, 2026-08-24" records the collision that forced the split.

| Method | Operation | AC satisfied |
|---|---|---|
| `credential/get` | Atomic_Retrieval — one credential | 10 AC 1-2, 1 AC 4 |
| `credential/get_batch` | Aggregate_Retrieval — N credentials, all-or-none | 10 AC 1-2, 3 |
| `credential/list` | Enumeration — no material, capped | 13 AC 4, 10 AC 2 |
| `environment/describe` | Manifest — credential entries plus projection inputs, no material | 6, 10 AC 2 |
| `system/health` | Liveness and protocol version | 11 AC 5 |

**`credential/get_batch` names a profile, credsd determines the membership, and the all-or-none
property is an invariant credsd enforces rather than a contract the caller is trusted to
honor.** This is the decision worth not re-deriving. Four things follow from it:

1. The params subject is a **profile**, not a caller-supplied list of credentials. A
   `{ requests: [...] }` shape was built first and rejected: a caller-composed set is a third
   Retrieval_Subject, which AC 1 prohibits outright, and AC 3 defines the aggregate as the
   composition of the atomics "for every credential *the profile names*" — membership is
   credsd's to determine, not the caller's to assert.
2. That is also what makes "enforced by credsd" mean anything. If the caller composed the set,
   credsd would only be failing a caller-chosen batch atomically; it would not be enforcing any
   property *of the aggregate*, because the aggregate would not exist as a daemon-side concept.
3. Requirement 3 is therefore discharged inside the daemon. The call returns either every
   credential the profile names or exactly one error and no material — never a per-element
   result array, never a partial-success flag. A caller cannot opt out by reading past a failed
   element, because there is no element-level result to read. Result entries are
   self-describing (each names its credential) precisely because the caller did not supply the
   list and so has no index to match against.
4. It keeps Requirement 1 AC 6 satisfiable at 1:1. `credential/get_batch { profile }` and
   `credential/get { profile, credential }` stay type-distinct even when the profile reaches a
   single credential — which is every profile today — so the Aggregate subject never collapses
   into the Atomic one.

Separately, giving the aggregate its own method is what makes Open Decision 3 resolvable without
loss. JSON-RPC's own batch semantics are per-element and would surprise a generic client into
reading a partial result as success; that is precisely why transport batches stay prohibited.
Naming the aggregate gets the grouping without inheriting the semantics.

**Names are validated at deserialize time, and a malformed name is an envelope failure.**
`config::credentials::validate_name` was previously enforced only on write paths, because the
HTTP router filtered the request path incidentally: a name containing `/` could not route, and
the request line bounded its length. JSON params remove both accidents, so every name field
validates during deserialization and an invalid name is not constructible as a typed value —
placing the check in the dispatcher would let a future method forget it, and would let an
invalid name exist long enough to reach a log (the hazard `src/server/classify.rs:279-282`
documents).

Two consequences worth stating before a shim depends on them:

- A syntactically invalid name now yields numeric `-32602`, where the HTTP surface returned
  `404 ENVIRONMENT_NOT_FOUND`. This is **not** a violation of Requirement 8 AC 3-4, which require
  "unknown subject" and "not authorized" to be indistinguishable. Malformed syntax is a third
  outcome and discloses nothing about existence: it is decidable from the request alone, without
  consulting any config or keystore, so it cannot be used as an existence oracle. What AC 3-4
  forbid is distinguishing *well-formed and absent* from *well-formed and forbidden*, and those
  two remain identical.
- The rejection message MUST NOT echo the offending input, even though `validate_name`'s own
  messages do (`src/config/credentials.rs:144`, `:153`, `:162`). Those messages are written for a
  human editing a config file; on this surface the same text lands in `RpcError::message`, which
  is the log-forging vector the validation exists to close. The boundary reports the field and
  the rule, never the value.

**Wire vocabularies are reused from the tree, not redefined, and the wire case is snake_case
for the kind discriminant.** Requirement 7 AC 1's Credential_Kind is `src/credentials.rs`'s
existing `CredentialType` (`access_token`, `session_credentials`), and the material payload's
`type` tag carries those same two values rather than a parallel set — a consumer that reads a
manifest entry's kind and a material response's tag must not get two names for one thing.
Source type mirrors `CredentialSource`'s *variants* — including its `#[serde(other)]` catch-all,
so an unrecognized source lists rather than breaking the manifest — and session status
transcribes the eight states `src/credential_status.rs` already distinguishes rather than
collapsing them, because collapsing is the choice Requirement 11's additive-only rule would make
permanent.

**Reuse applies to vocabularies, not to spellings: every enum on this wire is snake_case.**
`CredentialSource` tags itself kebab-case, but those tags are spelled for `credentials.toml` — a
file a shim never reads, which is the entire point of Requirement 6 AC 3 — so inheriting the
spelling would buy no compatibility while splitting the casing of a single protocol. A consumer
would read `kind: "session_credentials"` beside `source: "iam-user"` in one manifest entry and
reasonably file it as a bug. `CredentialType`'s snake_case is genuinely load-bearing, because it
is already serialized into sealed on-disk records; `CredentialSourceType` and `SessionStatus` are
new on the wire and follow it.

Note a prose inconsistency in this document, resolved in favor of the code: the Glossary spells
the kinds kebab-case (`session-credentials`, `access-token`) while the shipped wire strings are
snake_case. The Glossary is not a wire contract and the shipped strings win; the Glossary should
be corrected rather than the code.

Authorization_Context is a **per-call params field**, not a per-session establishment. Every
method carries the profile that supplies authority in its own params, and `credential/get`
additionally carries the credential that selects material; there is no establishment step and no
session state in which a context could persist. This resolves that sub-item of the list below and
is compatible only with Open Decision 1's option 3 — see that decision, which stays open on its
other half.

### Genuinely open

- Whether notifications (id-less requests) have any use here. Retrieval always needs a
  response; `plugin-framework` uses one for `shutdown`.
- The `Requested_Scope` payload grammar. AC 4 fixes it as a params field of the retrieval
  methods; its internal shape is Requirement 4's and `scope-down-plugin`'s to settle. The first
  increment carries it as a placeholder type so the field exists before the grammar does,
  because adding the field later is the breaking change and adding variants inside it is not.

## Requirement 11: Versioning and Compatibility

### Acceptance Criteria

1. THE API MUST carry an explicit version identifier. A foreign shim compiled against one
   version MUST be able to detect that it is talking to another.
2. Additive changes — a new Credential_Kind, a new error code, a new Manifest field — MUST
   NOT require a version increment.
3. Removing a field, repurposing an error code, or changing a default MUST require one.
   **Pre-launch waiver:** the `profile` → `environment` wire rename (method names, field names,
   `ENVIRONMENT_NOT_FOUND` → `ENVIRONMENT_NOT_FOUND`) is a breaking change accepted without a
   version increment. No deployed consumers exist; this waiver expires at first external release.
4. THE version MUST NOT be inferred from the credsd binary version. A shim cannot assume the
   daemon it reached is the binary it shipped with.
5. THE version MUST be reported by an explicit method — MCP's `initialize` handshake is the
   precedent and the natural model. Neither a route prefix nor a header exists under JSON-RPC,
   so the prior draft's framing of this as open is moot. What remains open is whether credsd's
   API version is a distinct value from the MCP `protocolVersion` (`2024-11-05`); it should
   be, since the two evolve independently.

## Requirement 12: Relationship to the SDK-Compatible Surfaces

**User Story:** As a maintainer, I want SDK compatibility to live at the edge, so that the
daemon API is free to have the shape Part I requires.

### Acceptance Criteria

1. THE AWS SDK contract (`AWS_CONTAINER_CREDENTIALS_FULL_URI`, `credential_process`) MUST be
   satisfied by projections at the edge, not by the shape of the daemon API. This spec's API
   is free of SDK compatibility obligations.
2. *Not a core requirement.*
3. *Not a core requirement.*
4. *Not a core requirement.*
5. *Not a core requirement.*
6. *Not a core requirement.*

## Requirement 13: Method Exposure per Carrier

**User Story:** As a security engineer, I want each carrier to expose only the methods
appropriate to what it can authenticate, so that a model-facing surface cannot reach material
that a shim-facing surface guards.

### Rationale

A uniform protocol does not imply a uniform surface, and conflating the two is the main risk
the JSON-RPC consolidation introduces. The daemon serves one carrier, UDS, and every client —
a person's CLI, a shim, run-time tooling that faces a model — reaches it there. The daemon
therefore tells callers apart by caller verification, not by carrier. Exposure to a model is
the responsibility of the run-time tooling that faces the model; this requirement states the
line that tooling is held to and the caps it may rely on.

**The dividing line is Material, and it is now settled: a model may learn what credentials
exist and ask for a projection over them; it may never receive the bytes.** A credential in a
model's context is a credential in a transcript.

That gives enumeration a job for model-facing tooling rather than making it a courtesy.
A projection request is how a model uses a credential, and to compose one the model must be able to name
what it is projecting — the `--secret` arguments contemplated by `secrets-source-plugin`,
alongside the profile it already names. Without enumeration the model would be guessing names,
or the harness would be reading `credentials.toml`, which is the coupling Requirement 6
exists to remove. Enumeration is exactly what a model legitimately needs and Material is
exactly what it does not, so the two land on opposite sides of one line.

### Acceptance Criteria

1. THE method exposure per carrier MUST be explicit, not incidental. A method reachable on one
   carrier MUST NOT become reachable on another merely because one dispatcher serves both.
2. THE exposure matrix is:

   | Method | UDS (`serve`) | Rationale |
   |---|---|---|
   | Atomic_Retrieval (`credential/get`) | yes | returns Material; never handed to a model |
   | Aggregate_Retrieval (profile) | yes | returns Material; never handed to a model |
   | Enumeration (`credential/list`) | yes | no Material; capped by AC 4 so model-facing tooling may expose it |
   | Manifest (`environment/describe`) | yes | no Material, but carries projection inputs a model has no use for; AC 4's limit is what makes enumeration a separate method |

   UDS is the only carrier the daemon serves.

3. *Not a core requirement.*
4. `credential/list` MUST return enough for a model to name a credential or secret in a
   projection request — the name, its Credential_Kind (Requirement 7 AC 2), and its session
   status — and nothing more. It MUST NOT return Material, and MUST NOT return a value that
   becomes Material by accumulation. The cap binds the method's result type, so run-time
   tooling that exposes enumeration to a model can rely on it.
5. WHEN a method is not exposed on a carrier, THE response MUST be method-not-found
   (`-32601`), never a permission error. A permission error confirms the method exists, which
   is the disclosure Requirement 8 AC 3-4 works to prevent.
6. Requirement 3's all-or-none rule and Requirement 8 AC 3-4's indistinguishability MUST hold
   identically on every carrier. Carrier-specific *exposure* is permitted; carrier-specific
   *semantics* are not.
7. ~~THE relationship between `credential/list` and the per-profile Manifest (Requirement 6) MUST
   be settled in `design.md`: whether they are one method with an optional profile filter or
   two.~~ **SETTLED, 2026-08-24 — two methods.** `credential/list` enumerates credentials and is
   capped by AC 4; `environment/describe` is Requirement 6's Manifest and carries the projection
   inputs Requirement 6 AC 3 obliges. One method could not do both without a per-carrier field
   set, which AC 6 prohibits. Open Decision 4 (Manifest authorization) applies to both, and AC
   4's disclosure limit binds `credential/list`.
   *This does not weaken the "dividing line is Material" rationale above. That line fixes what a
   model may never receive; it does not oblige exposing every non-Material method. `environment/describe`
   is withheld from a model because AC 4 caps what enumeration may disclose, not because it is
   Material.*
8. *Not a core requirement.*

## Requirement 14: Per-Request Caller Identification

**User Story:** As a security engineer, I want the caller re-identified on every request that
returns Material, so that a long-lived session is not a one-time trust establishment.

### Rationale — and the handle-inheritance question, tested

`verify_peer_uid` samples the peer once, at accept (`src/server/uds.rs:60-75`). Under HTTP/1.1
that was near enough to per-request. A long-lived JSON-RPC session inverts it: one sample would
authorize every later request for the connection's lifetime.

The obvious objection to re-sampling is handle inheritance — a connected socket FD survives
`fork` (unless `FD_CLOEXEC`, which is the *client's* choice and so not enforceable by the
daemon), survives `execve`, and can be passed to an unrelated process via `SCM_RIGHTS`. If peer
credentials were a snapshot taken at `connect`, re-sampling would return a frozen value and buy
nothing. **On Linux that is exactly the documented behaviour** — `unix(7)` specifies
`SO_PEERCRED` as the credentials in effect at the time of `connect(2)`.

Darwin behaves differently, and the difference is favourable. Tested on this machine with a
connector that forks a child sharing the FD:

```
1: connector pid=26822                               -> PEERPID=26822 PEEREPID=26822
2: inherited-child pid=26823 (connector STILL ALIVE) -> PEERPID=26823 PEEREPID=26823
3: connector again pid=26822                          -> PEERPID=26822 PEEREPID=26822
```

`LOCAL_PEERPID` tracks the process that **last wrote to the socket**, following the identity
back and forth while both processes were alive. So on macOS re-sampling does what the intuition
wants: it identifies the process actually making this request, and an inherited or passed FD is
attributed to whoever is using it rather than to whoever obtained it.

Two limits survive, and both are limits on *prevention*, not on identification:

- **FD transfer stays undetectable.** You always learn who is writing now; you never learn how
  they got the FD. Re-sampling converts a silent capability transfer into an attributable one —
  a detective control, which is the posture `caller-verification-policy` already adopts.
- **`exec` is invisible to the identity tuple.** `execve` preserves both PID and process start
  time, so a `(pid, start_time)` pair cannot see it. A re-resolved binary path can.

### Acceptance Criteria

1. Caller identity MUST be re-sampled on every request that returns Material, not once per
   connection.
2. THE identity MUST be the tuple `(pid, start_time)`, never the PID alone. Start time defeats
   PID recycling and is already collected — `ProcessFacts.start_time` and the per-ancestor
   `start_time` in `src/server/process_tree.rs`, which already compares parent and child start
   times to detect ordering anomalies.
3. Re-sampling MUST re-resolve the caller's binary path, not only the tuple, because AC 2's
   tuple cannot detect `exec`-replacement (see Rationale).
4. WHEN a re-sample differs from the identity established at accept, THE system MUST re-run
   classification and MUST emit an audit record of the change. It MUST NOT assume hostility — a
   legitimate shim may fork a worker — and MUST NOT assume benignity.
5. THE ancestry walk MAY be cached keyed on the AC 2 tuple, so an unchanged caller costs one
   `getsockopt` per request. Sampling cost is therefore not an argument against AC 1.
6. Per-platform refresh behaviour MUST be established before implementation, and MUST NOT be
   assumed uniform:
   - **macOS:** `LOCAL_PEERPID` refreshes to the last writer. Verified (see Rationale).
   - **Linux:** `SO_PEERCRED` is documented as a connect-time snapshot and is therefore
     unsuitable for AC 1. The candidate analogue is `SO_PASSCRED` with `SCM_CREDENTIALS`, where
     the kernel attaches the sending process's credentials per message. **This MUST be verified
     on Linux before AC 1 is relied upon there** — it is untested, and this spec does not
     assert it.
   - **Windows:** named pipes have no equivalent of either mechanism;
     `windows-named-pipe-transport` owns the question.
7. WHERE a platform cannot refresh the identity, THE system MUST NOT present a stale value as
   fresh. It MUST degrade explicitly to the indeterminate classification
   `caller-verification-policy` Req 7.5 already requires to be structurally distinct from
   "walk completed, no agent found".
8. THE system MUST NOT claim that re-sampling prevents FD transfer. Documentation of this
   control MUST state that `SCM_RIGHTS` passing is attributable but not preventable, consistent
   with `caller-verification-policy`'s detective-not-boundary framing (that spec, line 19 and
   Req 7.5).
9. AC 1 preserves a claim `caller-verification-policy` already makes and that this spec would
   otherwise quietly weaken: that "the starting caller PID is sound (kernel-provided)" while
   only the upward walk is evadable. Without AC 1, a long-lived session degrades the sound part
   to sound-at-connect.

---

## Requirement 15: Mutation Methods

**User Story:** As a developer, I want to manage my credential configuration through the same UDS
interface I use to retrieve credentials, without elevated privileges or direct file access.

### Rationale

Mutation goes over UDS for the same reason retrieval does: the daemon is the single authoritative
writer scoped to each caller's `callers/<uid>/` tree. Direct file writes by the client process
would bypass the daemon's ownership invariant and would be unavailable once the daemon runs as a
separate `credsd` OS user.

### Acceptance Criteria

1. THE system MUST expose five mutation methods over UDS: `config/set`, `config/get`,
   `config/unset`, `credential/remove`, and `environment/remove`.
2. ALL five methods MUST be UDS-only. They MUST NOT be reachable on any other carrier. The exposure table
   MUST enforce this at dispatch, not in individual handlers (consistent with Req 13 AC 1–2).
3. THE daemon MUST derive the caller's storage root from the kernel-verified peer uid (via
   `SO_PEERCRED`), never from a method parameter. A method parameter that names a profile or
   credential is an index into the caller's own tree, not an absolute path.
4. AN unauthorized caller (Denied or Unresolved per the caller-auth model) MUST receive
   `ENVIRONMENT_NOT_FOUND`, consistent with Req 8 AC 3–4's indistinguishability rule.
5. `environment` and `credential` parameters MUST be validated at deserialize time by
   `config::credentials::validate_name`. An invalid name MUST produce `-32602` with `NAME_RULE`
   in the message and MUST NOT echo the offending value.
6. `config/set`, `config/get`, `config/unset`, and `environment/remove` operate on `environment`
   (an env name). `credential/remove` operates on `credential` (a credential name). An
   `environment` that does not exist in the caller's config MUST yield `ENVIRONMENT_NOT_FOUND`.
7. ALL mutation methods MUST return `OkResult {ok: true}` on success. `config/get` MUST return
   `ConfigGetResult {value: Option<String>}` where `None` means the key is not set.
8. THE daemon MUST be the sole writer of `callers/<uid>/config.toml` and
   `callers/<uid>/credentials.toml`. Client processes MUST NOT write these files directly; they
   MUST go through the mutation methods.
9. EVERY bootstrap, import, or login that writes sealed material MUST emit one audit record per
   credential written, when the write commits, naming the operation, the environment and credential,
   and the caller: its uid, login uid, pid, executable, and ancestry. A write that fails MUST NOT
   emit one. The record for a challenge raised under `presence-gated-operations` MUST name the same
   caller ancestry. Ancestry is process names and pids, never a command line, and no record carries
   credential material.

---

## One-Way Door Risks

- **⚠️ The subject distinction (Requirement 1).** Once foreign shims exist that name
  credentials, collapsing back to profile-only retrieval breaks every one of them. Chosen
  because the alternative — a single opaque name — is ambiguous by construction (AC 4) and
  because the authorization argument in Requirement 2 requires a credential-shaped subject.
- **⚠️ A connection is a capability, on every platform (Requirement 14).** Re-sampling
  identifies the current writer but cannot prevent an FD from being inherited or passed, and the
  daemon cannot set `FD_CLOEXEC` on a client's descriptor. The residual risk is not that the
  wrong process is misidentified — it is that correct identification of an unexpected process
  is only useful if something consumes the signal. If AC 4's change-audit is emitted and never
  read, re-sampling is cost without control.
- **⚠️ Platform divergence in peer-credential freshness (Requirement 14 AC 6).** macOS refreshes
  to the last writer; Linux's `SO_PEERCRED` is a connect-time snapshot. A design that assumes
  uniform behaviour would silently be strong on one platform and vacuous on another, while
  reporting the same audit fields on both — which is worse than being weak openly. AC 7's
  explicit degradation is the mitigation, and it only works if it is built in from the start.
- **⚠️ JSON-RPC batching versus all-or-none (Requirement 3).** A batch is an array of
  independent requests yielding independent results. A batch of N Atomic_Retrievals therefore
  reconstructs an Aggregate_Retrieval *with per-element success and failure* — exactly the
  partial satisfaction Requirement 3 prohibits and exactly the oracle it suppresses. This is a
  protocol feature quietly defeating a Part I invariant. Accepting batches later is easy;
  withdrawing them once shims batch is not.
- **⚠️ Error codes as contract (Requirement 8).** Shims will branch on codes. The taxonomy is
  additive-only from first release; a wrong initial cut is carried indefinitely.
- **⚠️ Manifest as the anti-coupling mechanism (Requirement 6).** If the Manifest is
  incomplete, shims will read config files anyway and the coupling this spec removes returns
  informally, which is worse than an explicit dependency.
- **⚠️ Authorization anchor (Requirement 2).** Moving the decision subject from profile to
  credential changes what audit records mean historically. Records emitted before the change
  attribute decisions to profiles; correlating across the boundary requires the mapping at
  the time of the record.

## Open Decisions

### 1. How Requirement 2 AC 3 is satisfied structurally — **gates the rest of this spec**

Atomic_Retrieval must not yield material that escapes a restriction the same material would
carry under Aggregate_Retrieval. Three mechanisms:

1. **Boundaries move to the credential.** Simplest to reason about; contradicts
   `scope-down-plugin` Req 1 AC 4 and its 2026-08-13 amendment, and loses the case that
   amendment was written to preserve — two profiles sharing one login with different
   boundaries.
2. **Atomic_Retrieval carries a boundary reference from the caller.** The caller selects its
   own restriction, which is not a restriction. Only viable if the reference is
   authenticated, at which point it is a profile under another name.
3. **Atomic_Retrieval carries an Authorization_Context** — the request names a profile
   (authority) and a credential (material selector); the boundary applied is the context
   profile's; naming a credential the profile does not reach fails as not-found.
   *Currently favored.* Keeps the decision per-credential (so the alias problem stays
   dissolved) while keeping restriction per-profile (so no accepted spec is contradicted on
   that axis), and it is what a generated `credential_process` line can express, since it can
   carry both names.

Option 3 rests on a distinction worth stating: authorization *anchored* on the credential is
not the same claim as authorization *invoked* at a credential-only endpoint.

**Partially discharged, 2026-08-21 — still open.** The dependent question this decision was
gating has been answered from the other end: Requirement 10 settles Authorization_Context as a
per-call params field, because Aggregate_Retrieval is a batch whose element type *is* the atomic
params shape, leaving no session in which to establish a context. That eliminates options 1 and
2 structurally — the shipped params carry both a profile and a credential name, which only
option 3 uses — so method-surface work is no longer blocked on this decision.

What stays open is the half this decision actually owns: *which boundary gets applied* when the
two names disagree, and where that boundary is resolved from. That remains blocked by the
`scope-down-plugin` base-directory question (Spec Conflicts item 2), and no increment may
implement boundary application until it settles. Carrying the `credential` field while the
boundary logic is absent is safe only because the field is optional and its absence means "the
profile's configured credential", which is the behavior that exists today; an increment MUST
reject a `credential` value that names anything other than that until this is resolved, rather
than honoring it unrestricted.

### 2. Scope on Aggregate_Retrieval (Requirement 4 AC 4)

Apply one document to every credential, or reject scoped aggregates outright. Applying one
policy across heterogeneous Credential_Kinds is not generally meaningful — a session policy
has no interpretation for an `access-token` credential. Rejecting is the smaller surface and
loses little if the granular path exists. Leaning reject; decide with Requirement 7 AC 3.

### 3. ~~Whether JSON-RPC batch requests are accepted~~ — **RESOLVED, 2026-08-21**

Transport-level batches are prohibited; a top-level JSON array is rejected with
`ERR_INVALID_PARAMS`. Domain-level batching exists instead, as `credential/get_batch` — see
Requirement 10 "Settled".

Recorded because the resolution turns on a distinction that reads as a contradiction otherwise:
the reason to reject transport batches is *exactly* the reason to provide a domain batch. The
rule this spec needs — any element failing fails the whole call — is not JSON-RPC's batch
semantics, so a generic client library applied to a transport batch would read a partial result
as success. Naming the aggregate as its own method makes the invariant a property of that
method's contract, which a generic library cannot misread because it never sees elements.

The code is the **numeric** `-32602`. Recorded explicitly because this criterion was first
resolved the other way, as a domain string code named `ERR_INVALID_PARAMS`, and that was wrong
on two counts. Requirement 8 AC 1 reserves numerics for envelope failures and enumerates
"malformed params" as one of them, so a message whose top-level shape this API does not accept
is squarely envelope-level rather than domain-level. And the `ERR_INVALID_PARAMS` this decision
names is an existing MCP envelope constant, `ERR_INVALID_PARAMS: i64 = -32602`, so the
decision was already pointing at the numeric constant, not proposing a new string. AC 1's domain-code examples (`ENVIRONMENT_NOT_FOUND`, `CONFIG_ERROR`, `UNSUPPORTED`) carry
no `ERR_` prefix, which is the tell: in this codebase an `ERR_`-prefixed name *is* a numeric
envelope code and an unprefixed one is a domain string. Domain codes introduced by this API
MUST follow the unprefixed form.

### 4. Manifest authorization relative to material authorization (Requirement 6 AC 5)

Whether existence-disclosure is its own decision, and if so whether it defaults more
permissive than material. Interacts with Requirement 8 AC 3-4 — a permissive Manifest
partially defeats the indistinguishability those criteria require — and with what run-time
tooling exposes to a model, since the Manifest is the one retrieval-adjacent operation plausibly
exposed there.

### 5. Domain failures as JSON-RPC `error`, or as result-with-flag (Requirement 8 AC 6)

An MCP envelope carries both conventions. Leaning: real JSON-RPC `error` objects
with the domain code in `error.data` for the credsd API, and the MCP adapter translating to
`isError` at the boundary — that keeps the model-facing quirk where it is required instead of
propagating it into the shim-facing contract. Decide alongside Requirement 13.

### 6. ~~Whether atomic retrieval is exposed over stdio~~ — **RESOLVED, 2026-08-17**

Resolved into Requirement 13 AC 2-4 rather than left open. Run-time tooling that faces a model
never exposes `credential/get` to it under any configuration; it may expose `credential/list`,
because a model must be able to name what it is projecting to compose a projection request. A model may learn what
exists and ask for execution over it; it never receives bytes.

Recorded because the resolution has a consequence worth not re-litigating: this is a hard
exposure rule, not a default. Tooling that faces a model carries deliberately no flag that turns
`credential/get` on, so no deployment can be talked into it. Requirement 2's per-credential authorization
decision still earns its keep — it governs UDS callers, which include shims an agent spawned.

### 7. Whether Linux can satisfy Requirement 14 AC 1 at all

**Direction chosen, 2026-08-21; the Linux mechanism remains untested.** The connection stays
open across requests and peer identity is resampled per request, rather than constraining
session lifetime to one retrieval per connection.

This deliberately declines the uniform option. The reasoning is worth recording, because the
uniform option is the safer-looking one: one-connection-per-retrieval makes connect-time
identity accurate by construction on all three platforms, but it does so by removing the
*question* rather than answering it, and the question does not stay removed. A persistent
connection is what a long-lived shim wants, `system/health` already implies one, and the
Windows named-pipe transport will reintroduce multi-request connections regardless. Choosing
uniformity now would mean paying for the resampling design later anyway, with a shipped contract
constraining it.

So AC 7's explicit per-platform declaration is load-bearing rather than a fallback: `SO_PEERCRED`
cannot serve, `SO_PASSCRED`/`SCM_CREDENTIALS` is the candidate and is still **untested**, and
until it is tested the Linux record must state indeterminate strength rather than inherit
macOS's. An implementation that resamples on macOS and silently reports the connect-time
snapshot on Linux while emitting identical audit fields is the failure mode this criterion
exists to prevent — the fields would agree and the guarantees would not.

## Spec Conflicts — require approval before resolution

Per `AGENTS.md` spec coherence, these are surfaced rather than resolved.

1. **`caller-verification-policy` Req 7.4 and the Agent_Restricted_Profile glossary entry.**
   Both mandate the per-profile `identity_type` as the restriction determinant and state that
   no new field is introduced. Requirement 2 AC 1 makes the credential the decision subject.
   The conflict is real and unresolved. Note that Req 7.4 is currently *unsatisfiable as
   intended* under N:1 for the alias reason in Requirement 2's rationale, so reconciliation is
   owed regardless of this spec's fate. Status of that requirement is `proposal`, and
   enforcement is Increment 2, so nothing shipped depends on it yet.
2. **`scope-down-plugin` Req 1 AC 2** still lacks a base directory for relative
   `boundary_policy` values after `DaemonConfig::profile_data_dir` was deleted. Requirement 2
   AC 2 depends on boundaries being resolvable per profile, so that open question blocks
   Requirement 2's implementation, not merely scope-down's.
3. **`config-set-get-unset` Req 5 AC 1** names `bootstrap` as the mechanism for repointing a
   profile at another credential source, which `bootstrap` cannot do (no `--credential` flag;
   a gap in the current CLI). This spec's Requirement 1 assumes profiles and credentials
   are independently addressable; if that independence is not reachable by any command, the
   API is granular over a relationship users cannot create.
4. ~~**`windows-named-pipe-transport` Req 5 and 6**~~ — **RESOLVED by that spec's owner,
   2026-08-21.** (Cited here as "Req 5 and 6"; they are actually that spec's **Requirement 2**
   AC 5 and AC 6.) Req 2 AC 5 stated "the HTTP layer above the transport MUST be unchanged. The
   Local_Router, route handlers, and response types MUST be shared with the UDS path."
   Requirement 9 AC 1-3 here removes that HTTP layer from the local transport altogether, so AC
   5's *intent* survived — one shared dispatcher, two transports, no duplication — while its
   *terms* did not. AC 6's proposed rename of `uds_router` described "peer identity verified
   below HTTP," and `uds_router` is deleted rather than renamed, making a SHOULD-rename of an
   absent symbol unsatisfiable.

   Both ACs were rewritten in place with the amendment reasoning recorded inline, and that
   spec's `Local_Router` glossary entry became `Local_Dispatcher`, explicitly indifferent to
   which protocol the dispatcher speaks. Neither amendment touches that spec's substance (pipe
   instance lifecycle, no TCP listener, no stale-socket path), all of which this refinement
   leaves intact. Its status was already `proposal` and unimplemented, so no status revert was
   needed and no migration was incurred.

## Dependencies

- **Blocks:** `scope-down-plugin` Layer 2 (no input surface for a scope without Requirement
  4); M:N profile→credential (no manifest, no default-credential designation).
- **Blocked by:** Open Decision 1, which needs the `scope-down-plugin` base-directory
  question settled to be implementable.
- **Interacts with:** `credential-proxy` and `aws-config-file-generation` (projections at the
  edge under Requirement 12 AC 1, both run-time tooling),
  `secrets-source-plugin` (already treats a profile as an aggregate of one credential plus N
  secrets; Requirement 1 AC 5 generalizes the shape it assumes, and Requirement 13 AC 4 depends
  on its `--secret` argument shape).
- **Amendment candidate, not a conflict — `caller-verification-policy`.** Its Req 1.2 requires
  the PID to come from kernel peer credentials but does not say how often. Requirement 14
  answers "every Material-returning request", which that spec should probably absorb, since it
  owns the mechanism and the audit contract. Requirement 14 AC 9 *strengthens* its line-19
  soundness claim rather than contradicting it, so this is an addition for its owner to make,
  not a conflict to resolve. Separately, Requirement 2 AC 6 **is** a real conflict with its
  Req 7.4 — see Spec Conflicts.
- **Shares protocol infrastructure with:** an MCP server (whose envelope types, line framing,
  and domain-code convention this spec adopts in Requirement 8 AC 1) and `plugin-framework` (line-delimited JSON-RPC 2.0 over stdio, with
  its own `src/plugins/protocol.rs`). Requirement 9 AC 1 makes three surfaces speak one
  protocol; whether they share **one** implementation of the envelope and framing, rather than
  three hand-rolled ones, is a design-document question this spec deliberately leaves to
  `design.md`. It is worth asking early — two hand-rolled copies already exist or are
  specified.
