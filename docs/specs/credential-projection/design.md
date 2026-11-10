# Design: Credential Projection

**Status:** draft — declaration model, implemented under an interim notation; the notation for a
multi-option projection type is undecided (see Interim notation, and Open decision: notation)
**Feature:** `credential-projection`
**Requirements:** see `requirements.md` in this directory.
**Scope:** the declaration model. The resolver belongs to the run-time ease-of-use tooling that
resolves a selection (requirements → Non-Goals); a decision numbered here but marked *Not a core
decision* is reserved for it.

## Overview

A projection is declared at three association levels and resolved by a resolver that sits between a
selection and every consumer that delivers credentials to a child. This document owns what is
declared: the closed set of projection types, the address space and cardinality each one declares,
the derivation rule a declarable space falls back to, and the `<type>[:<address>]` representation
that carries a declaration in configuration, on the wire, and on a command line. The resolver that
walks the levels, checks that the result occupies each address once, and hands a consumer a
resolved projection set belongs to that tooling.

A projection's collision rule follows from its declared address space and cardinality, so one
uniqueness check covers every type rather than one check per type — which is why the declarations
here carry that information at all.

## Key Design Decisions

### 1. A projection is configured; a facility is a consequence

*Not a core decision.* The declaration model's share is
`ProjectionType::requires_facility`, which states per type whether a projection needs one.

### 2. Address plus cardinality replaces three collision rules with one

Every projection type declares the space of slots it can occupy and how many credentials may
occupy that space in one child. Conflict is then a single property — the resolved set is
injective over addresses, and no cardinality-`one` type is claimed twice.

| Projection type | Address | Declarable (Req 1.9) | Derived from (Req 1.10) | Cardinality (per invocation) |
|---|---|---|---|---|
| `env-var` | the variable name | yes | the credential's name, folded | many |
| `aws-profile` | the profile name | no — it *is* the credential's name | — | many |
| `aws-profile` (default slot) | the default profile | no — singleton | — | one |
| `credential-endpoint` | the container discovery variables | no — singleton | — | one |

`env-var` is the only declarable space. A space is non-declarable for one of two reasons: it holds a
single address, or the type fixes the address from the credential — which is the `aws-profile` case,
and the only place this model special-cases AWS.

The alternative — a bespoke check per type — was rejected because it puts the cost of a new
projection type in the conflict logic rather than in the type's own declaration, which is
exactly where Requirement 7 says it must not be.

### 3. The endpoint's singleton is per invocation

`credential-endpoint` admits one credential per invocation, because the mechanism that discovers
it is a single pair of variables in the environment that invocation hands its child. It is not a
property of an environment definition: two concurrent invocations over one environment each stand
up their own endpoint and do not conflict with each other. Stating the constraint per environment
would refuse invocations that are correct.

The invocation is the right scope for every cardinality claim, not only this one, because an
invocation is what resolves a projection set. Cardinality is a property of a resolved set.

### 4-6. Default identity; resolution precedes fetch; conflict refusal and invocation override

*Not a core decision.*

### 7. An address is declared beside the projection, never beside the material

The address answers "how does this credential appear in the child?", which is a fact about delivery.
A source's `env_var` key states it at the credential level — Requirement 2.1's only surface — and the
environment and the invocation override it in turn, resolved independently of the type (Req 2.11) so
that changing one is not a way to silently change the other.

Confining it to the credential level would make the address a fact about the *secret* instead, and
that costs three things:

- Renaming a variable would go through `bootstrap`, the only writer of `env_var`, which re-seals the
  secret. A user would re-supply material they were not changing in order to rename a slot.
- An environment could not vary it, so two environments composing one credential could not hand it to
  two consumers that read different variables — which is the whole reason a projection is chosen
  rather than deduced.
- An invocation could not vary it, so an invocation override would not exist for the one type
  that most needs it: a token source admits no second projection to re-point instead.

`aws-profile` is deliberately excluded, and the asymmetry is the point. A variable name is imposed
on the user by whatever library reads it, so the user must be able to state it. A profile name is
not imposed by anything: the credential name is already the handle in `--credential X`, in
`creds get --credential X`, and in the `[profile X]` the generated config writes, and those three
agreeing is worth more than the freedom to disagree. Making it declarable would let one credential
carry two names, the one typed and the one the SDK reads, with nothing in the child to map between
them. Renaming the credential remains the way to rename the profile.

The ladder therefore has exactly one occupant today, `env-var`'s variable name, and the resolver
refuses an address declared for anything else (Req 2.12).

### 8. A derived default, not a shared constant

A type whose address is declarable needs an answer for the credential that declares nothing, and the
answer is a rule over the credential's name rather than a constant. A constant is correct for exactly
one credential per selection and wrong for two: both resolve to one address, a resolver refuses
the collision, and for a token source whose type admits no alternative there is nothing to
re-point — so launching a process with `--credential a --credential b` would be impossible for any
two token credentials, with no fix available at the command line. A default that fails on the second credential
is not a default.

Deriving from the name makes the common case work with nothing declared, which is what a default is
for. `openai` arrives as `OPENAI`, `gh-token` as `GH_TOKEN`. Requirement 1.10 constrains the rule to
the credential's name alone, so a credential's derived address does not move when the selection around
it changes — a rule that numbered collisions away (`OPENAI`, `OPENAI_2`) would make what a child
receives depend on composition order.

The rule, over the names `validate_name` accepts (`[A-Za-z0-9._-]`, 1-64 characters, no leading
`.`):

1. Upper-case ASCII letters; keep digits.
2. Fold `.`, `-`, and `_` to `_`.
3. Prefix `_` when the result starts with a digit, since a variable name may not.

| Credential | Derived variable |
|---|---|
| `openai` | `OPENAI` |
| `gh-token` | `GH_TOKEN` |
| `my.static` | `MY_STATIC` |
| `1password` | `_1PASSWORD` |

Every step is forced by the two name grammars rather than chosen, which is what keeps it
predictable enough for a user to write a child against without consulting the table. The `_` prefix
is the only addition, and only for a name no ordinary credential has.

It also gives the derivation a use beyond "some name, at least". Since the fold is mechanical, a user
who names the credential for the variable their library reads — `openai-api-key` — declares nothing
and still gets `OPENAI_API_KEY`. That makes the credential's name the handle in both address spaces,
which is the same property decision 7 relies on for `aws-profile`: one name, typed once, meaning the
same thing wherever it appears.

The rule is not injective, because credential names admit `.`, `-`, and `_` where a variable name
admits only `_`. `my-static` and `my.static` fold together. That is a collision like any other and
the model already handles it: refused, named, re-pointable. Seeking injectivity would mean mangling
every ordinary name to protect a case a user can fix in one flag.

### 9-10. Declared versus derived collisions; reserved consumer addresses

*Not a core decision.*

### 11. Precedence is spellable, not only resolvable

A declaration is a pair, not a scalar: a projection type and an optional address, at every level that
can declare either (Req 2.13). A level whose representation holds only a type is outside the address
ladder no matter how faithfully the resolver walks it, so the pair is carried in all three places a
declaration lives — the `EnvConfig` map, its wire copy in `ProfileManifest.projection`, and the
`--project` parser. The wire one belongs to `credential-retrieval-api`, whose Req 6 AC 3 is the reason
the manifest carries projection inputs at all.

A scalar type would not merely fail to carry the address; it would mis-carry it. `ProjectionType`
deserializes an unrecognised spelling to `Unsupported`, deliberately, so one forward-looking entry
cannot make a file unloadable — and under that leniency `env-var:OPENAI_API_KEY` is an unrecognised
spelling. The resolver then refuses the credential under 7.5 and reports an unknown projection type
for a value this model permits.

So the leniency is kept and scoped: an unrecognised *type* degrades to `Unsupported` so one entry
cannot fail a file, while a malformed *address* refuses with its own message naming the malformation
(Req 2.14). They are different faults with different fixes, and reporting a bad variable name as an
unknown projection type sends a user looking for the wrong one.

## Interim notation (shipped)

The notation below is the smallest one the requirements admit, and it is not yet one of the three
candidates. A projection is named by its type and carries at most
one option, its address, after a colon:

```toml
# config.toml
[env.dev]
credentials = ["aws-dev", "openai", "github"]
projections = { openai = "env-var:OPENAI_API_KEY", github = "env-var" }
```

```
--project openai=env-var:OPENAI_KEY_ALT      # invocation level, as run-time tooling spells it
```

`github` declares a type and no address, so it takes the derived one, `GITHUB`. `openai` names its
variable because the library reading it insists on `OPENAI_API_KEY`, and the invocation re-points it
for one command without touching either the environment or the sealed secret.

This is Option C's grammar with the indirection removed: the value is a projection *type and its
address* rather than the name of a defined projection, so the common case is legible where it is
written and no `[projection.<name>]` table exists. The address is Option A's third positional field,
borrowed ahead of the decision because an invocation-level address needs it and because a colon is unambiguous
for the one declarable space that exists — a variable name may not contain one.

Both the config map and its wire copy carry the pair, not a bare type; decision 11 is why that is a
requirement (2.13) rather than an implementation detail.

Two known costs of the interim form, both recorded rather than designed away:

- **Requirement 2.11 is met by the model and not by the spelling.** Type and address resolve
  independently, but this notation cannot express an address alone: declaring one at an invocation
  restates the type, so a caller who wants only to re-point a variable must know what type the
  lower level declared. The cost is currently zero, because the only declarable address belongs to
  `env-var` and the only sources that take `env-var` take nothing else — so the type being restated
  is never in doubt. A later type that is both address-bearing and one of several a source admits is
  what makes this bite.
- **A type whose address contains a colon cannot be added under it.** A key=value `file`
  projection addressed by a path would collide with the delimiter on Windows (`C:\run\secrets`)
  before it collided with Requirement 7.3's option count. Adding that type means deciding the
  notation first, not extending this one.

The credential level declares an address but not a type. `env_var` on a source's configuration is
Requirement 2.1's surface for the address, and there is none for the type: the resolver honours a
credential-level type and the manifest carries the field, but nothing writes one, because each
source's configuration would need a `projection` key — eight structs' worth of change for a level
the env and the invocation already cover. Deferred rather than designed away.

The notation is type-agnostic, so it accepts `aws-profile:prod` syntactically; the resolver refuses
it under Requirement 2.12 rather than the parser rejecting it, so the refusal can say *why* a
profile name is not yours to choose instead of reporting a malformed argument.

## Open decision: notation (for a type with more than one option)

Requirements bind what a notation expresses; three candidates spell it differently. Each is
shown for the same case — an environment composing an AWS credential and two API keys, one of
which needs a variable name that differs from its default.

Each is then read against the projection this model must survive but does not specify: an
`http-proxy` projection that injects a stand-in credential into the child and replaces it, on
outbound requests to a bound destination, with the real one.

That projection stresses a notation less than a long option list would, because its moving parts
are mostly not projection options. The stand-in is minted per invocation, as the endpoint's
authenticator already is. The replacement rule is the proxy's own logic. What is left to express
is the **destination binding** — that this credential is the one to substitute on requests to
`api.service.com` — and where that belongs is a modelling question to answer before the notation
matters:

- **If a destination is a property of the credential**, it lives beside the credential's own
  definition, where its variable name already lives, and a projection selector needs to say no
  more than `http-proxy`. Every notation below then handles the proxy equally well, and the
  comparison turns entirely on the simple cases.
- **If a destination is a property of the projection** — one credential proxied to different hosts
  from different environments — then a projection carries a list, and a notation with no room for
  a second named field strains.

The first reading is the more likely one: a credential's destination is a fact about the API it
authenticates to, not about how a particular environment hands it over. Under that reading the
proxy does not discriminate between these notations at all.

### The forcing type is more likely `file` than `http-proxy`

If the proxy does not discriminate, something else has to. A key=value `file` projection — a
credential written into a dotenv-shaped file the child reads — is both the nearer request and the
harder test. It needs two options at once, a path and a key within it, which is Requirement 7.3
directly rather than by analogy. Its path also carries the interim delimiter and Option A's, so it
cannot be spelled in either: `env-var:MY_KEY` extends to `file:/run/secrets/.env:MY_KEY` only until
someone writes `C:\run\secrets`.

It stresses the *model* too, not only the spelling. Several credentials writing into one file is the
intended use, so the address is the pair (path, key), not the path — `check_addresses` stays
injective over the pair, and a per-path check would refuse exactly the case the type exists for.
Read as a generalisation, `env-var` is that shape with the container left implicit: the process
environment is a container with one instance and no name. Whether `Address` grows a
`(container, key)` form or `file` takes its own variant belongs to that spec, and that spec should
be written before this notation is chosen, since `file` is what the notation has to carry.

### Option A — positional triple

A projection is one string: `<credential>:<type>[:<option>]`.

```toml
# config.toml
[env.dev]
credentials = [
  "aws-dev",
  "openai:env-var:OPENAI_API_KEY",
  "github",                          # env-var, name derived from the credential
]
```

```
--project openai:env-var:OPENAI_KEY_ALT      # invocation level
```

An omitted option takes the type's default — for `env-var`, the credential name
upper-cased with separators folded to underscores, so `github` becomes `GITHUB`.

**Costs nothing in schema.** `EnvConfig::credentials` is already `Vec<String>`, so this adds no
configuration shape at all and `--credential` already accepts the same token.

**The proxy costs it nothing where a destination belongs to the credential** — `openai:http-proxy`
says everything a selector needs to. What strains it is any type wanting two options at once: a
third positional field has no name to distinguish it from a fourth, and a value containing a colon
has no escape. Requirement 7.3 obliges more than one option per type, and this notation satisfies
that only by growing a second delimiter.

### Option B — named fields

A projection is a set of named fields, spelled the same in configuration and on the command line.

```toml
# config.toml
[env.dev]
credentials = ["aws-dev", "openai", "github"]

[[env.dev.projection]]
Credential = "openai"
Projection = "env-var"
Name = "OPENAI_API_KEY"
```

```
--project Credential=openai,Projection=env-var,Name=OPENAI_KEY_ALT      # invocation level
```

**The proxy test passes.** `Credential=openai,Projection=http-proxy,Host=api.openai.com` extends
by adding a field, and opting out is `Projection=none` or a `Proxy=false` field on another
type — no delimiter pressure, no ordering rule.

**It is verbose**, and the shorthand's `Key=value,Key=value` grammar needs quoting rules for a
value containing a comma. Familiar from the AWS CLI, which is the vocabulary this project's users
already carry.

### Option C — named reusable projections

A projection is defined once, named, and referenced.

```toml
# config.toml
[projection.openai-key]
type = "env-var"
name = "OPENAI_API_KEY"

[env.dev]
credentials = ["aws-dev", "openai", "github"]
projections = { openai = "openai-key" }
```

```
--project openai=openai-key      # invocation level
```

**The proxy test passes well.** A proxy projection's host list and header are written once under
`[projection.<name>]` and referenced by every environment that wants it, which is the shape a
fleet with one convention and many environments actually needs.

**It indirects the common case.** Naming a projection to say "this key goes in
`OPENAI_API_KEY`" is a level of ceremony the single-option types do not earn, and a reader of
`[env.dev]` cannot see what a credential projects as without following a reference.

### Comparison

| | A: positional | B: named fields | C: named reusable |
|---|---|---|---|
| Configuration schema change | none | new table array | new table + env map |
| Config and CLI same vocabulary | yes | yes | yes |
| Multi-option projection types | needs a second delimiter | native | native |
| Proxy, destination on the credential | fine | fine | fine |
| Proxy, destination on the projection | strains | good | good |
| `file`, addressed by (path, key) | fails — path holds the delimiter | good | good |
| Common case legible in place | yes | yes | no — indirected |
| Terseness on the command line | best | worst | good |
| Values containing the delimiter | unescapable | needs quoting | not applicable |

Read against the proxy alone, the choice rests on the destination question above. Where a
destination is a credential's property, A costs no schema change and no ceremony, and is the
strongest of the three for every projection type now specified. Where a destination is a
projection's property, A needs a second delimiter and the choice narrows to B or C — B keeping the
common case legible where it is written, C buying a reuse that a multi-environment fleet spends
and a single environment pays for.

Read against `file`, A is out regardless of how the destination question lands, because the problem
is the delimiter rather than the option count: a path is unescapable in a colon-delimited triple on
the one platform where paths contain colons. So the live choice is B or C, and the interim notation
is a subset of neither — adopting either means re-spelling `env-var:NAME`, which is the cost of
having borrowed A's field ahead of the decision, and is cheap while only one type uses it.

## Relationship to the existing seam

| Code | Role here |
|---|---|
| `ProjectionType` (`credsd-core`, `projection.rs`) | the projection type |
| `ProjectionDecl` (`credsd-core`, `projection.rs`) | a declaration at one level: a type and an optional address, spelled `<type>[:<address>]` (Req 2.13) |
| `projection::supported` (`credsd-core`, `projection.rs`) | the bound a resolver enforces on what a credential may be projected as |
| `projection::default_projection` (`credsd-core`, `projection.rs`) | the fallback a resolver takes when no level declares a type |
| `ProjectionType::address_declarable` (`credsd-core`, `projection.rs`) | Requirement 1.9 per type |
| `credential_env::derive_env_var` (`credsd-core`, `credential_env.rs`) | the `env-var` derivation rule (Req 1.10, 1.11) |
| `credential_env::token_variable` (`credsd-core`, `credential_env.rs`) | the env, credential, derived address ladder `get` uses; see requirements → Open conflict |
| `EnvConfig::default_credential` (`credsd-core`, `config/mod.rs`) | **not** the default identity: the first credential of any type, answering what `credential/get` means with none named |

Two notions of "default" therefore coexist, and they answer different questions. *Which credential
does an unnamed request mean* is `EnvConfig::default_credential`, and it is indifferent to
projection. *Which credential occupies a singleton address* is the default identity, and it is
`aws-profile`-only by construction. They name the same credential whenever a selection's first
credential takes `aws-profile`, which is why the distinction has not yet had a consequence.

The names do not say this. `EnvConfig::default_credential`'s documentation claims it is "the ambient
identity served on the container endpoint and written as `[default]`", which the `[default]` half
contradicts — a resolver fills that address from the filtered `aws-profile` list, not from this
function. Adopting this specification means splitting the name,
not just the definition.

One term, one meaning: this specification says **projection** where older code said
*materialization form*, and the code carries the same word rather than a synonym, because a synonym
is how the two come to drift.

One collision of the word is worth knowing about: `rpc::Projection` is an unrelated use — the env
settings (region, sdk, cli) a manifest carries so a client can render without reading config.
`projection.rs` says so at the top.

## Correctness properties

- A credential declaring no address has a derived address determined by its name alone —
  unchanged by what else the selection composes.
- Two `env-var` credentials, neither declaring an address, derive distinct addresses whenever their
  names differ outside the characters the derivation folds.
- The derivation is total: every credential name the system accepts derives a valid variable name.
- An `aws-profile` projection's address is the credential's name; no representation can declare
  another.
- Every declaration a level can express as a type, it can express as a type and an address.
- A declaration naming an unrecognised type loads, as `Unsupported`, rather than failing its file.

Properties of a resolved projection set are the resolver's, not this design's.

## Error handling

| Condition | Behaviour |
|---|---|
| Unrecognised projection type in configuration or a manifest | Loads as `ProjectionType::Unsupported`; the resolver refuses the credential |
| Unrecognised projection type on a command line | Refused at the argument (`ProjectionType::from_str`), naming the known types |
| Malformed address for its type's space | Carried as written; the resolver refuses, naming the malformation |
| Derived address is not a valid address in its space | Cannot occur: the derivation rule is total over accepted credential names (Req 1.11) |

Resolver refusals are the resolver's, not this design's.

## File changes

| File | Role |
|---|---|
| `crates/credsd-core/src/projection.rs` | Declaration types: `ProjectionType`, `Address`, `Cardinality`, `ProjectionDecl` and its lenient and strict parses, `supported`, `default_projection`, `address_declarable`, `valid_env_var` |
| `crates/credsd-core/src/credential_env.rs` | The `env-var` derivation rule (`derive_env_var`); the address ladder `get` uses (`token_variable`) |
| `crates/credsd-core/src/config/credentials.rs` | Per-source `env_var` as the credential-level address declaration; `validate_name`, which bounds what the derivation rule must accept |
| `crates/credsd-core/src/config/mod.rs` | `EnvConfig.projections`, a type-and-address pair per credential (Req 2.13); `default_credential`, distinct from the default identity |
| `crates/credsd-core/src/rpc/methods.rs` | Supported projections per source type; `Projection.projections` carries each declaration's type and address — a wire field owned by `credential-retrieval-api` Req 6 AC 3 |

The resolver, the invocation-level `--project` surface, and the reserved set a consumer declares
are not in this repository.

## Alternatives considered

**Inferring a projection from the credential's type.** Rejected: it is what the system does
today, and it makes Requirement 2 unexpressible. A type bounds what a credential *can* be
projected as; only a human knows what the consumer reads.

**One shared default variable for every `env-var` credential.** Rejected: see decision 8. It makes
any two-token selection unresolvable, and unresolvable by anything the command line can say, which
defeats invocation override for the one type that has no second projection to fall back on.

**Numbering a collision away (`OPENAI`, `OPENAI_2`).** Rejected: the address a
credential lands at would depend on the order of the selection composing it, so the same credential
would arrive at a different variable in two different runs. Requirement 1.10
forbids it, and a child cannot be written against it.

**Deriving the address from the credential's *source type* rather than its name.** Rejected: it is
inference from a type, which a configured projection exists to avoid, and it collides for any two
credentials of one source — which is the common case, not the rare one.

**Namespacing every derived address (`CREDSD_OPENAI`).** Rejected, though it would make a collision
with a consumer's variables impossible by construction. Nothing reads `CREDSD_OPENAI`, so every
credential would need a declaration anyway and the derived default would exist only to be
overridden. The point of a default is the case where nothing is declared, and a prefix guarantees
that case is never the useful one. Refusing a reserved-address collision costs one message and keeps
`openai-api-key` → `OPENAI_API_KEY` working.

**Making `aws-profile`'s address declarable for symmetry.** Rejected: symmetry is not a
requirement, and the asymmetry it would remove is load-bearing. A variable name is imposed by the
library that reads it; a profile name is the credential's own handle, shared with `--credential` and
with the generated config. Declaring one would produce two names for one credential and no mapping
between them in the child. `env-var` stays the only declarable address space, which also keeps the
interim notation's delimiter safe — a variable name cannot contain a colon, where a future
address might.

**Folding this model into run-time tooling.** Rejected: `get` and configuration read the same
declarations, and a rule owned by the tooling that launches processes would be reached into by
commands that start no process.

Alternatives for the resolver — write-time conflict detection, last-declaration-wins, promoting an
endpoint declaration to default identity, a denylist of variables, and letting either side of a
reserved-address collision win — are the resolver's to weigh.
