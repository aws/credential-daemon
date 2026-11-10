# Requirements: Credential Projection

**Status:** draft — declaration model; notation for a multi-option type undecided (see
`design.md` → Open decision: notation)
**Feature:** `credential-projection`
**Scope:** the declaration model — the projection vocabulary, each type's address space,
cardinality and derivation rule, and how a declaration is represented at every association level.
How a selection's declarations are *resolved*, and when a resolution is refused, belongs to the
consumer that resolves them — run-time ease-of-use tooling (see Non-Goals). A criterion numbered
here but marked *Not a core requirement* is reserved for that resolver, so numbering stays stable.

## Introduction

A credential is useless to a child process until something makes it reachable. An AWS SDK
reaches one through a profile that names a `credential_process`; a client library reaches one
through an environment variable it was told to read; a container runtime reaches one over an
HTTP endpoint it discovers from a fixed pair of variables. Each of those is a **projection** —
a way a credential becomes reachable — and which one a credential needs is a property of the
consumer, not of the credential.

So a projection is chosen, not deduced. A credential declares the projection it takes by
default, an environment overrides that for the credentials it composes, and an invocation
overrides both. What a credential *can* be projected as is bounded by its type; what it *is*
projected as is a decision someone makes and writes down.

Choice introduces collision. Every projection occupies an **address** in the child — a variable
name, a profile name, a fixed pair of variables — and two credentials cannot occupy one
address. Some projections admit one credential per child and no more, because the mechanism
that discovers them has exactly one slot. An invocation whose projections collide has no
correct behaviour available to it, so it does not run: the resolver refuses, names both sides,
and the caller resolves it by overriding one.

Some address spaces offer a choice and some do not. Where one does, it is chosen the same way a
type is and by the same precedence. "Which variable does my secret arrive in?" is a question about
delivery, not about the secret, so its answer belongs beside the projection rather than beside the
material: a user who wants a different variable for one command says so on that command, and never
re-supplies a secret in order to re-spell a slot. Where nobody has said, the address follows from
the credential's name — so composing two credentials that have never met still produces two
distinct slots.

Where a space does not offer a choice, it is because the type fixes the address: a singleton has
only one, and an AWS profile is named for the credential it projects, which is the name the user
already types everywhere else. The derivation makes the credential's name the handle in both spaces,
so naming a credential for the variable a library reads — `openai-api-key` — is a way to declare
nothing and still land on `OPENAI_API_KEY`.

Not every address is a credential's to take. A consumer delivering credentials occupies some of the
same space itself, pointing the child at what it is being given, and those slots are **reserved**: a
projection resolving onto one is refused like any other collision rather than quietly winning or
quietly losing.

This specification owns the projection vocabulary and where a projection may be declared. How a
declaration is resolved and when a resolution is refused belong to a consumer's resolver. Neither
owns what a consumer does with a resolved projection.

## Terminology

- **Projection** — a way a credential becomes reachable by a child process.
- **Projection type** — the kind of a projection, which fixes its address space and its
  cardinality. `aws-profile`, `env-var`, and `credential-endpoint` are projection types.
- **Primary projection** — the one projection a credential resolves to, which fixes the addresses
  it occupies in its own right. Distinct from a **singleton address** the credential may
  additionally fill by being the default identity: filling one is a consequence of being chosen,
  not a second projection the credential was declared to take.
- **Address** — the slot in a child that a projection occupies.
- **Address space** — the set of addresses a projection type can occupy.
- **Declared address** — an address stated at an association level.
- **Derived address** — the address a projection takes when no level declared one, computed from
  the credential's name by its type's derivation rule.
- **Reserved address** — an address the consumer itself occupies, so no credential may. Declared by
  the consumer as an input to resolution, never inferred by the resolver.
- **Cardinality** — how many credentials one projection type may project in one invocation, either
  `one` or `many`.
- **Selection** — the credentials one invocation of a consumer composes.
- **Default identity** — the credential that occupies a selection's cardinality-`one` addresses:
  the first credential the selection composes that takes the `aws-profile` projection. A selection
  composing no `aws-profile` credential has no default identity.
- **Singleton address** — an address of a cardinality-`one` projection type. The default profile
  and the container discovery variables are the only ones.
- **Association level** — where a projection's type or address is declared: on a credential, on an
  environment, or in an invocation.
- **Resolver** — the component that computes a resolved projection set from a selection.
- **Resolved projection set** — one projection per credential the selection composes.
- **Conflict** — two credentials in a resolved projection set occupying one address, or a
  cardinality-`one` projection type projecting more than one credential.
- **Facility** — a service a consumer provides for a child's lifetime, such as a credentials
  endpoint.

## User Experience

A credential declares nothing and still lands somewhere predictable. Bootstrap names the credential
and the source; the variable follows from the name:

```
$ creds bootstrap --credential openai static-secret
Paste the secret, then press Enter:
••••••••••••          (input is not echoed)
✓ Sealed 'openai' (static-secret). Projected as env-var OPENAI.
```

Naming the credential for the variable a library reads is how a user declares an address without
declaring anything:

```
$ creds bootstrap --credential openai-api-key static-secret --secret-file ./key.txt
✓ Sealed 'openai-api-key' (static-secret). Projected as env-var OPENAI_API_KEY.
```

`--env-var` states it outright where the two cannot agree — a credential called `openai` whose
library insists on `OPENAI_API_KEY`. That is the credential level of the ladder, the lowest of three.

An environment composes credentials and may re-point any of them. A declaration is a projection type,
optionally with the address it takes:

```toml
# config.toml
[env.dev]
credentials = ["sso-admin", "openai", "gh-token"]
projections = { sso-admin = "credential-endpoint", openai = "env-var:OPENAI_API_KEY" }
```

`sso-admin` takes `aws-profile` by default and is re-pointed to the endpoint; `openai`'s variable is
the environment's choice rather than the credential's; `gh-token` declares nothing at either level and
derives `GH_TOKEN`. An `aws-profile` address is never declared — a profile is named for its
credential, so `[profile sso-admin]` follows from the name the user already types.

An invocation is the third level, and the only one that needs no file edited. The invocation
surface, and the refusals a colliding selection produces, belong to the consumer that resolves the
selection.

## Requirements

### Requirement 1: Each projection type declares an address space and a cardinality

**User story:** As a maintainer adding a projection type, I want its collision rule to follow
from what it declares, so that I do not write a new conflict check for each type.

#### Acceptance Criteria

1.1. The system SHALL define a closed set of projection types.

1.2. Each projection type SHALL declare the address space its projections occupy.

1.3. Each projection type SHALL declare a cardinality of `one` or `many`, per invocation.

1.4. The `env-var` type SHALL address a projection by an environment variable name.

1.5. The `aws-profile` type SHALL address a projection by a profile name, which SHALL be the name
     of the credential projected. That address is therefore not declarable at any level.

1.6. The `aws-profile` type SHALL treat the default profile as a second address, of cardinality
     `one`.

1.7. The `credential-endpoint` type SHALL declare cardinality `one`.

1.8. *Not a core requirement.*

1.9. Each address space a projection type occupies SHALL declare whether an address in it is
     declarable. A space SHALL declare it is not where the type fixes the address rather than
     offering it: because the space holds one address (1.6, 1.7), or because the address is
     determined by the credential projected (1.5). `env-var` is the only declarable space this
     specification defines.

1.10. Each declarable address space SHALL declare a derivation rule yielding the address a
      projection takes when no level declared one. The rule SHALL be a function of the credential's
      name alone, so that a credential's derived address does not depend on what else its selection
      composes.

1.11. The `env-var` type's derivation rule SHALL yield a valid environment variable name for every
      credential name the system accepts.

> **Note (1.5, 1.9 — why an AWS profile takes no address):** a profile name is not a slot the user
> chooses; it is the handle they already hold. `--credential X`, `creds get --credential X`, and
> `[profile X]` in the generated config name one thing, and letting a projection re-point the last
> of those would give one credential two names — the one the user types and the one their SDK reads
> — with a lookup between them that nothing in the child performs. A user who wants a differently
> named profile renames the credential, and everything follows. `env-var` cannot take the same
> treatment, because the variable is chosen by the library reading it rather than by the user.

> **Note (1.10 — derivation, not a constant):** a single constant default shared by every
> credential of a type is admissible under 1.10 only in the degenerate case of one credential per
> selection. Two credentials sharing a derived address collide, and if the shared address is
> the *only* address either can take, no invocation override has anything to offer them. A rule
> that varies with the credential's name is what keeps the common case — compose two token
> credentials — resolvable without declaring anything.

> **Note (1.11 — derivation is not injective):** credential names admit characters a variable name
> does not, so any total rule folds some distinct names together (`my-static` and `my.static`
> reaching one variable, say). That is a collision like any other: refused, named, and resolved by
> declaring an address (2.8). It is not a reason to seek an injective
> rule, which would have to mangle the common case to stay injective in the rare one.

### Requirement 2: A projection is declared at one of three levels

**User story:** As a user, I want a credential's usual projection — and the slot it lands in —
recorded once and overridable where it differs, so that I neither repeat myself nor edit
configuration to run one command.

#### Acceptance Criteria

2.1. A credential SHALL be able to declare the projection it takes.

2.2. An environment SHALL be able to declare a projection for a credential it composes.

2.3-2.6. *Not a core requirement.*

2.7. The resolver SHALL accept one spelling of a projection type from every association level.

2.8. A credential, an environment, and an invocation SHALL each be able to declare the address a
     projection occupies, for a projection type whose address is declarable under 1.9.

2.9-2.12. *Not a core requirement.*

2.13. The representation of a declaration SHALL be able to carry a projection's type and its
      address together, at every association level that can declare either. A level able to state a
      type SHALL be able to state an address.

2.14. *Not a core requirement.*

> **Note (2.13 — a ladder configuration cannot spell is not a ladder):** precedence is a property of
> the configuration format as much as of the resolver. A level whose representation holds only a
> projection type cannot participate in the address ladder, however faithfully the resolver walks it:
> an address-bearing value is not a type, so a format expecting a type either rejects it or — worse,
> given 7.5's leniency about unknown spellings — reads it as a type it does not recognise and refuses
> the credential. A user then sees "unrecognised projection type" for a value this specification
> permits. 2.14 keeps those two faults apart for the same reason.

### Requirements 3-6: Resolution, conflict detection, default identity, invocation override

*Not a core requirement.* Resolution belongs to the consumer that resolves a selection.

> **Open conflict (one projection set whichever consumer):** a resolver may bind every consumer of a
> selection to one resolved projection set. `creds get` is a consumer and has no resolver: it
> computes a token's variable through `credential_env::token_variable`
> (`crates/credsd-core/src/credential_env.rs:253`, called from `crates/credsd/src/main.rs:1391`),
> which walks the environment's declared address, the credential's `env_var`, and the derived name,
> with no invocation level, no type check, no reserved set, and no conflict refusal. A resolver and
> `get` agree on the address ladder they share and nothing else. Unresolved: either that guarantee
> narrows to the shared address ladder, or `get` resolves the way a resolver does.

### Requirement 7: A projection type is added without reshaping configuration

**User story:** As a maintainer, I want a new projection type to cost a type and its address
space, so that adding one does not migrate every configuration file.

#### Acceptance Criteria

7.1. The system SHALL admit a new projection type without changing the shape of a configuration
     entry.

7.2. *Not a core requirement.*

7.3. The system SHALL allow a projection type to declare more than one option.

> **Note (Req 7.3 — one option met, two still open):** the interim notation carries a projection
> type and one option, which is `env-var`'s address (`design.md` → Interim notation). One option is
> enough for every type defined here, since the address is the only one any of them takes. This
> criterion is met for a type wanting one option and unmet for a type wanting two — a key=value
> `file` projection, addressed by a path and a key within it, is the nearest such type, and it is
> what decides between notations A, B, and C.

7.4. The system SHALL allow a projection type to declare no options.

7.5. WHEN configuration names a projection type this version does not recognise, THEN the
     resolver SHALL refuse the credential rather than project it by another type.

> **Note (7.5 — two halves):** core's half is that a declaration naming an unrecognised type still
> loads, as `ProjectionType::Unsupported`, so one forward-looking entry cannot make a configuration
> file or a manifest unloadable. The refusal is the resolver's half, owed by whichever consumer
> resolves the selection.

### Requirement 8: A consumer's own addresses are occupied

*Not a core requirement.*

## Non-Goals

- **Not run-time tooling.** Launching a process with credentials, serving an agent harness, and
  SDK compatibility endpoints are run-time ease-of-use tooling, future development built on credsd's
  API. This spec states only what that tooling may rely on: the declaration model it resolves.
- **Resolving a selection.** The resolver — precedence across levels, conflict detection, the
  default identity, invocation overrides, reserved addresses — belongs to the run-time tooling that
  resolves a selection.
- **What a consumer does with a resolved projection.** Generating an AWS configuration file,
  exporting a variable, or standing up an endpoint belongs to the command that does it — run-time
  tooling for a launched process, and `get`'s own rendering for `get`.
- **The `http-proxy` projection's behaviour.** Requirement 7 obliges the model to accommodate a
  projection type that intercepts outbound requests, and `design.md` tests the candidate
  notations against it. Nothing here specifies what such a projection does, which hosts it
  covers, or how a credential opts out of it.
- **Narrowing what a credential can do.** Restriction and scope-down are a separate concern with
  their own spec. A projection changes how a credential is reached, never what it permits.
- **Choosing the notation.** The criteria above bind what a notation must express, not how it
  spells it. `design.md` carries three candidates, and the decision stays open for a type with more
  than one option; the interim notation carries a type and an address and nothing further.
- **A `file` projection.** Requirements 1.9-1.11 and 2.8-2.12 are written so a type addressed by a
  container and a key within it fits the model, and `design.md` records what it would cost. What
  such a projection writes, where, and with what permissions is its own spec — and it is the type
  that settles Requirement 7.3.
