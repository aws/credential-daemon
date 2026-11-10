# Requirements: Static-Secret Credentials

**Status:** accepted — 3.3 defers the projection variable to `credential-projection`; returns to
`complete` once 3.3's credential and environment levels are verified against `creds get`'s shell
formats. Its invocation level is honoured by run-time tooling, not by this repository (see
Non-Goals).
**Feature:** `static-secret-credentials`
**Scope:** A credential source, `static-secret`, that stores an opaque secret the
user supplies — a bearer token, an API key, any pre-issued secret string — and
serves it verbatim. No issuer, no exchange, no unattended renewal.

## Introduction

Every credential source credsd has today either federates to AWS (SSO, IAM-user,
Roles Anywhere, aws-web-identity, aws-login) or obtains a bearer token from an issuer (`jwt`,
`oauth`, `jwt-bearer`). None covers the simplest case: the user already holds a
secret an API accepts — a personal access token, a service API key, a
pre-provisioned bearer token — and wants credsd to hold it and hand it to child
processes like any other credential.

`static-secret` is that source. It is deliberately the smallest provider: the
credential **is** the secret. credsd is the seal, the (optional) expiry, and the
serving, and no more — the same posture as the `jwt` provider, minus the JWT's
parseable `exp` claim.

### Relationship to `aws-iam-user`

`static-secret` resembles `aws-iam-user` only in **how the secret is captured and
stored**: the user supplies it at bootstrap, it is sealed in its own encrypted
file under the credential's data dir, and it never lands in `credentials.toml`.

On the two axes that define a provider's runtime behavior it is the **opposite**
of `aws-iam-user`:

- **No credential exchange.** `aws-iam-user` brokers its long-term key into
  short-lived session credentials via `sts:GetSessionToken`. `static-secret`
  exchanges nothing — the stored secret is what is served.
- **No unattended re-minting.** `aws-iam-user` (without MFA) re-mints unattended.
  `static-secret` has no issuer to re-mint from; its only path to a *new* secret is
  the user supplying one again, so it is **re-auth-only**. Loading the already-sealed
  secret is not re-minting, and does happen unattended — that is how a cache miss is
  served.

Consequently `static-secret` is structurally a member of the `jwt` family
(seal + serve, re-auth-only), not the IAM-user family.

### Terminology

- **Secret** — the opaque string the user supplies (bearer token, API key, …).
  Its internal structure, if any, is not interpreted.
- **Sealed secret file** — the encrypted at-rest artifact holding the secret,
  under the caller's uid-partitioned tree
  (`callers/<uid>/credentials/<name>/static_secret.enc`).
- **Declared expiry** — an optional, user-supplied absolute expiry recorded in
  `credentials.toml`. credsd cannot derive one from an opaque secret.
- **Request binding** — how a consumer places the secret into a request (header
  name, scheme prefix, query parameter). Owned by the consumer, not modeled here.

## User Experience

Bootstrap accepts the secret from stdin (never echoed) or a file — never as a
command-line argument. The desired flow:

Paste interactively (secret read from a hidden prompt):

```
$ creds bootstrap --env prod --credential openai static-secret --env-var OPENAI_API_KEY
Paste the secret, then press Ctrl-D:
••••••••••••••••          (input is not echoed)
✓ Sealed 'openai' (static-secret) in env 'prod'. Projected as env-var OPENAI_API_KEY.
```

From a file, with a known rotation date:

```
$ creds bootstrap --env prod --credential gh static-secret \
    --secret-file ./gh-token.txt --expires-at 2026-12-31T00:00:00Z
✓ Sealed 'gh' (static-secret) in env 'prod'. Projected as env-var GH; expires 2026-12-31.
```

Re-running bootstrap for the same credential replaces the secret (the rotation
path). Thereafter the value is served like any other credential:

```
$ eval "$(creds get --env prod --credential openai --format shell)"
$ printenv OPENAI_API_KEY
sk-...
```

No expiry declared means the credential never expires and reads `active`
indefinitely; a declared expiry that passes surfaces a re-auth prompt to
re-bootstrap, not a silent stale secret.

## Requirements

### Requirement 1: Source definition and selection

**User story:** As a user holding a pre-issued API token, I want to register it as
a credential, so that credsd serves it to my tools like any other credential.

#### Acceptance Criteria

1.1. The system SHALL provide a credential source spelled `type = "static-secret"`
     in `credentials.toml`.

1.2. WHEN a `static-secret` entry is present, THEN the system SHALL resolve it to a
     provider that serves the stored secret as an `AccessToken` credential.

1.3. The source's kind (`served_kind`) SHALL be `AccessToken`, and its
     manifest source discriminant SHALL be `static_secret`.

1.4. The only materialization form for a `static-secret` source SHALL be `EnvVar`;
     it SHALL NOT be projected as an AWS profile or `credential_process` line,
     because the secret is not AWS credential material.

### Requirement 2: Secret capture and storage

**User story:** As a user, I want my secret captured without exposing it, so that it
does not leak into shell history, process listings, or `credentials.toml`.

#### Acceptance Criteria

2.1. WHEN bootstrapping a `static-secret` credential, THEN the system SHALL read
     the secret from a file or from standard input, and SHALL NOT accept it as a
     plain command-line argument.

2.2. The system SHALL seal the secret to `static_secret.enc` (`0600`) under the
     credential's data dir, using the daemon's master key, and SHALL NOT write the
     secret to `credentials.toml`.

2.3. The system SHALL NOT interpret, validate, or parse the secret's contents; any
     non-empty byte string is a valid secret.

2.4. Re-running bootstrap for an existing `static-secret` credential SHALL replace
     the sealed secret. This is the supported way to rotate or replace it.

### Requirement 3: Serving

**User story:** As a child process, I want the stored secret handed to me in the
variable my client library reads, so that I authenticate without knowing credsd is
involved.

#### Acceptance Criteria

3.1. WHEN a `static-secret` credential is requested, THEN the system SHALL return
     `Material::AccessToken { token, token_type }` where `token` is the stored
     secret.

3.2. The served `token_type` SHALL always be `"Bearer"`, matching the daemon's
     existing bearer-token serving. It is not configurable.

3.3. The system SHALL project the secret into the environment variable the
     `credential-projection` resolver resolves for this credential: the `env_var` recorded in config as the credential-level
     declaration, overridable by the environment and by the invocation, and derived
     from the credential's name when no level declares one. The same mechanism serves the `jwt` source; neither
     source defines a default of its own.

> **Note (3.3 — this source defines no default of its own):** the variable is
> `credential-projection`'s to resolve, under its declaration model's Requirements 1.9-1.11
> and 2.8, by whichever consumer resolves the selection. A
> default named here would have to be a constant, since this source knows only its own
> credential — and a constant shared by every `env-var` credential makes a
> selection composing two of them unresolvable, with no second projection type for
> either to re-point to. Deferring also keeps `env_var` a declaration rather than the
> only way to set a variable, so renaming a slot never requires re-sealing a secret
> through `bootstrap`.

3.4. WHEN the sealed secret file is absent, THEN the system SHALL report the
     credential's status as `NoSession` and, on a fetch, surface a re-auth error
     naming the bootstrap command that seals a secret — never a decrypt error and
     never a silently empty credential.

3.5. The `credential/get` (and `credential/get_batch`) response for a
     `static-secret` SHALL be the existing `CredentialResult` shape, with no new
     result or material type:
     - `credential`: the credential's name, echoed.
     - `material`: `{ "type": "access_token", "token": <the secret>,
       "token_type": "Bearer" }`.
     - `expires_at`: the declared absolute expiry (RFC 3339), or `null` when none
       is declared (Requirement 5).
     - `provenance`: `cached_shared` (the secret is served from the shared sealed
       file, not minted per request).

### Requirement 4: Renewal and re-auth

**User story:** As the daemon, I want a static secret loaded on demand but never
re-minted, so that a cache miss still serves the credential while nothing ever
tries to obtain a new secret unattended.

#### Acceptance Criteria

4.1. The `static-secret` provider SHALL be renewable in the sense the provider
     seam uses — its `renewer()` SHALL return a renewer whose renewal **reloads
     the sealed secret and mints nothing** — and SHALL NOT attempt to obtain a new
     secret from any issuer, because none exists. Serving the sealed secret needs
     no human, which is what lets a cache miss be satisfied; producing a
     *different* secret requires one, which is what makes the source re-auth-only.
     This is the same posture as the `jwt` source.

4.1a. The background refresh loop SHALL NOT refresh a `static-secret` credential
     that declares no expiry: a credential with no stated expiry never approaches
     one, so there is nothing to refresh toward.

4.2. WHEN a `static-secret` credential is required after its declared expiry (if
     any) has passed, THEN the system SHALL surface a re-auth requirement pointing
     at re-bootstrap, rather than serving the expired secret or attempting renewal.

### Requirement 5: Optional declared expiry

**User story:** As a user whose API key rotates on a known date, I want to record
that date, so that credsd reports the credential as expiring/expired instead of
serving a key I know is dead.

#### Acceptance Criteria

5.1. A `static-secret` entry MAY record an absolute expiry (`expires_at`,
     RFC 3339). It is optional.

5.2. WHEN no expiry is recorded, THEN the credential SHALL never be considered
     expired, SHALL report status `Active` whenever a sealed secret is present, and
     SHALL carry `expires_at: null` in its `credential/get` response. This relies on
     the `credential-retrieval-api` amendment permitting a null (no-expiry) response
     alongside an absolute one; relative lifetimes remain prohibited.

5.3. WHEN an expiry is recorded, THEN the system SHALL report `Active`, `Expiring`,
     or `Expired` using the same status logic every other credential uses, derived
     from that recorded expiry.

5.4. The recorded expiry SHALL live in `credentials.toml` (it is not secret) and
     SHALL NOT be sealed with the secret.

### Requirement 6: Isolation and coherence

**User story:** As a maintainer, I want `static-secret` to reuse existing wire and
projection machinery, so that it adds a source without adding a parallel path.

#### Acceptance Criteria

6.1. The feature SHALL reuse the existing `Material::AccessToken` wire type and the
     `EnvVar` materialization form; it SHALL NOT introduce a new material variant
     or projection form.

6.2. Adding `static-secret` SHALL NOT change the behavior of any existing source.

6.3. The `static_secret` source discriminant SHALL have a serialize path in
     `CredentialSourceType` (not fall through to `Unsupported`), so a manifest
     reports it faithfully.

6.4. The one wire change this feature makes is `CredentialResult.expires_at`
     becoming nullable (Requirement 5); it is shared by every credential kind but
     changes no other source's behavior, since every other source stamps an
     absolute expiry. See the `credential-retrieval-api` Requirement 4 amendment.

## Non-Goals and Caveats

- **Request binding is out of scope.** credsd stores the secret and projects it as
  an environment variable. How a consumer places it into a request — header name
  (`Authorization` vs `X-Api-Key`), scheme, query parameter — is the consumer's
  contract. The first consumer (Strands Box) brings its own binding definition and
  needs only the value. The served `token_type` is always `Bearer` (the daemon's
  existing behavior) and is not a configurable binding mechanism; a consumer that
  needs a different scheme applies it itself.
- **No credential exchange or scope-down.** A static secret cannot be exchanged for
  a scoped-down or shorter-lived credential. It is served with exactly the
  authority it already carries — with, unlike `aws-iam-user`, no blast-radius
  reduction from brokering.
- **Not run-time tooling.** Launching a process with the secret in its environment is
  run-time ease-of-use tooling, future development built on credsd's API. That tooling is what
  honours 3.3's invocation level; this spec states the declaration it reads.
- **No unattended renewal or rotation.** credsd does not fetch, rotate, or refresh
  the secret. Replacing it is a re-bootstrap, driven by a human.
- **No structural interpretation.** Even if the secret happens to be a JWT, this
  source does not read its `exp`; the `jwt` source exists for that.
