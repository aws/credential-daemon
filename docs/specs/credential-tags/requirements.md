# Requirements: Credential Tags

**Status:** draft
**Feature:** `credential-tags`
**Scope:** User-defined `key=value` labels on a credential, stored in `credentials.toml`,
returned by `credential/list`, and usable as a `credential/list` filter.

## Introduction

A user with many credentials has no way to group them. Names carry some meaning by convention,
but `credential/list` can only filter by environment, and an environment is a composition for
building a process environment, not a grouping for finding things.

Tags fill that gap. A tag is a `key=value` pair the user attaches to a credential, such as
`team=payments` or `stage=prod`. `credential/list` returns each credential's tags and accepts a
tag filter, so a user or a tool can ask for "every credential where `stage=prod`" without
reading `credentials.toml`.

Tags are labels only. They change nothing about how a credential is obtained, renewed, served,
or authorized.

### Terminology

- **Tag** — one `key=value` pair on one credential. A credential has at most one value per key.
- **Tag set** — all of one credential's tags. It may be empty.
- **Tag filter** — a set of conditions on `credential/list`. Each condition names a key, and
  either a value that key must equal or no value, meaning the key must be present.

## User Experience

Tag a credential when creating it, or later:

```
$ creds bootstrap --credential pay-prod --tag team=payments --tag stage=prod aws-idc-sso ...
$ creds tag set --credential pay-dev team=payments stage=dev
$ creds tag unset --credential pay-dev stage
```

List by tag:

```
$ creds list --tag team=payments --tag stage=prod
CREDENTIAL  KIND                 STATUS  TAGS
pay-prod    session_credentials  active  stage=prod team=payments

$ creds list --tag stage
```

The second command lists every credential that has a `stage` tag, whatever its value.

## Requirements

### Requirement 1: Tag shape

**User story:** As a user, I want tags with predictable syntax, so that a tag I write in one
place is matched the same way everywhere.

#### Acceptance Criteria

1.1. A tag key, after folding (1.4), SHALL match `[a-z0-9][a-z0-9._-]{0,62}`: 1 to 63 bytes,
     lowercase ASCII letters, digits, `.`, `_`, and `-`, not starting with `.`, `_`, or `-`.
     Input MAY use ASCII `A` to `Z`; folding maps them into the pattern.

1.2. A tag value SHALL be 0 to 256 bytes of printable ASCII (`0x20` to `0x7E`). An empty value
     is allowed.

1.3. A credential SHALL carry at most 32 tags.

1.4. The daemon SHALL fold every tag key to lowercase, mapping ASCII `A` to `Z` only, at every
     input: `credential/bootstrap` `tags`, `credential/tag` `set` and `unset`, the
     `credential/list` filter, and the load of `credentials.toml`. Keys SHALL be stored and
     returned only in folded form, and compared byte for byte after folding. Values SHALL NOT be
     folded and SHALL be compared byte for byte. No other trimming or normalization is applied.
     Folding happens in the daemon, so a client that skips the CLI gets the same result.

1.5. WHEN a tag violates 1.1, 1.2, or 1.3, THEN the operation that introduced it SHALL fail, and
     the error SHALL name the credential and the offending key. The error SHALL NOT echo a value.

1.6. WHEN two keys in one request, or in one entry at load, fold to the same key (for example
     `Env` and `env`), THEN the operation SHALL fail with the error of 1.5, naming both spellings.
     Folding SHALL NOT pick a winner.

Note: 1.4 depends on 1.1 admitting no character with a case other than ASCII letters. Any change
that relaxes 1.1 MUST revisit 1.4.

### Requirement 2: Storage

**User story:** As a user, I want tags kept with the credential they describe, so that editing
or removing a credential keeps its tags consistent.

#### Acceptance Criteria

2.1. A credential's tags SHALL be stored as an optional `tags` table on its entry in
     `credentials.toml`. An absent table is an empty tag set.

2.2. WHEN `credentials.toml` is loaded and an entry's `tags` table violates Requirement 1, THEN
     the load SHALL fail with the error of 1.5. A tag violation SHALL NOT be skipped or truncated.

2.3. Adding the `tags` key SHALL NOT change how any source type's own fields are parsed. A source
     type that rejects unknown fields SHALL still reject them.

2.4. WHEN a credential is removed (`credential/remove`), THEN its tags SHALL be removed with its
     entry. Clearing a credential's session SHALL NOT change its tags.

2.5. The daemon SHALL remain the sole writer of `credentials.toml` (credential-retrieval-api
     Requirement 15 AC 8). Tags SHALL be written only through the methods in Requirement 3.

### Requirement 3: Setting tags

**User story:** As a user, I want to tag a credential at creation and change its tags later,
so that I do not have to recreate a credential to relabel it.

#### Acceptance Criteria

3.1. `credential/bootstrap` SHALL accept an optional `tags` object of key to string value.

3.2. WHEN `credential/bootstrap` is given `tags`, THEN the credential's tag set SHALL become
     exactly that object. WHEN `tags` is absent, THEN a new credential SHALL have an empty tag
     set, and a re-bootstrapped credential SHALL keep its existing tag set.

3.3. The system SHALL provide a mutation method `credential/tag` with params `credential`, an
     optional `set` object of key to string value, and an optional `unset` array of keys. It
     SHALL apply `set` and then `unset` to the credential's tag set in one write, and SHALL
     return `OkResult` (`{}`).

3.4. `credential/tag` SHALL follow credential-retrieval-api Requirement 15 AC 2 to 5:
     dispatch-enforced exposure, peer-uid storage root, and `validate_name` on `credential`. It is
     Credential-addressed, so an unknown credential or an unauthorized caller SHALL fail as
     `CREDENTIAL_NOT_FOUND` with identical text (credential-retrieval-api Requirement 8 AC 7),
     not `ENVIRONMENT_NOT_FOUND`.

3.5. WHEN a `credential/tag` call names the same key in both `set` and `unset`, or the result
     would violate Requirement 1, THEN the call SHALL fail with `-32602` and SHALL NOT write.
     Unsetting a key the credential does not carry SHALL succeed and change nothing.
     The conflict is `set` against `unset` within one call, not tags against source fields. A key
     in both is almost always a mistake, and the result would depend on an order the user never
     sees, so the call is rejected rather than ordered. Keys conflict after folding (1.4): `Env`
     in `set` and `env` in `unset` conflict.

3.6. The CLI SHALL expose 3.1 as a repeatable `creds bootstrap --tag key=value`, and 3.3 as
     `creds tag set --credential <name> key=value...` and
     `creds tag unset --credential <name> key...`. `--name` SHALL be accepted as an alias of
     `--credential`, as on other commands. Each `set` argument is one `key=value`, split at the
     first `=`, so a value may contain `=`. A `set` argument without `=` SHALL fail. `unset`
     takes bare keys. The shell removes quotes before the CLI sees them, so `foo="multi word"`
     and `"foo=multi word"` arrive as the same argument.

     ```
     $ creds tag set --credential pay-dev team=payments stage=dev
     $ creds tag set --credential pay-dev owner="Pat Lee"
     $ creds tag set --credential pay-dev query=a=b
     $ creds tag unset --credential pay-dev owner query
     ```

     The third sets `query` to `a=b`.

3.7. WHEN one CLI invocation gives the same key twice, THEN the CLI SHALL reject it before
     sending a request, naming the key.

### Requirement 4: Listing and filtering

**User story:** As a user or a tool, I want to see a credential's tags and list only the
credentials that carry given tags, so that I can find a group without reading config files.

#### Acceptance Criteria

4.1. Each `credential/list` row SHALL carry a `tags` object holding the credential's full tag
     set. The field SHALL always be present; an empty tag set is `{}`.

4.2. `credential/list` params SHALL accept an optional `tags` object. Each member is a
     condition: a string value requires the row's tag of that key to equal it; `null` requires
     only that the row carries the key.

4.3. A row SHALL match the filter only when it satisfies every condition. An absent or empty
     `tags` filter SHALL apply no tag filtering.

4.4. A condition on a key that no credential carries SHALL match no row. It SHALL NOT be an
     error.

4.5. The tag filter SHALL combine with the `environment` filter by AND. An `environment` filter
     that fails (credential-retrieval-api Requirement 16 AC 6) SHALL fail the same way whatever
     the tag filter.

4.6. A filter key or value that violates Requirement 1 SHALL fail the request with `-32602`.

4.7. The CLI SHALL expose 4.2 as a repeatable `creds list --tag key=value` for a value
     condition and `creds list --tag key` for a presence condition. Text output SHALL include a
     `TAGS` column showing each row's tags as `key=value` pairs. `--format json` rows SHALL
     include `tags`.

### Requirement 5: Tags are not secrets and not authorization

**User story:** As a security reviewer, I want tags kept out of every security decision, so that
a mislabeled credential cannot widen anyone's access.

#### Acceptance Criteria

5.1. The system SHALL NOT use tags in any authorization, restriction, presence, or credential
     selection decision. A tag filter narrows a listing; it never grants or denies access.

5.2. Tags SHALL be visible to every caller that may list the credential, including run-time
     tooling that exposes `credential/list` to a model (credential-retrieval-api Requirement 13).
     Users SHALL NOT store secrets in tags, and the documentation SHALL say so.

5.3. A consumer that shows tags to a model SHALL treat them as user-supplied data, not as
     instructions.

5.4. No mutation method SHALL accept a tag filter; the tag filter exists only on
     `credential/list`. Each mutation names one credential and keeps its own gate, so a tool
     that lists by tag and then removes each result passes `credential/remove`'s gate on every
     call. Logout is not gated, and neither the daemon nor the CLI SHALL accept a tag on logout.
     A script that loops over `creds list --tag` reaches no credential it could not already
     reach by name, so tags widen no scope.

## Non-Goals

- Tag-based retrieval. `credential/get` addresses one credential by name; tags do not select
  one.
- Tags on environments. A future revision may add them if a need appears.
- Filter operators beyond exact match and presence. A future revision adds prefix and negation
  first, since both are additive to the filter shape; OR may follow later.

## Relationship to Other Specs

- **credential-retrieval-api Requirement 13 AC 4** caps a `credential/list` row at name,
  Credential_Kind, source type, and session status. This spec amends that cap to add `tags`.
  Tags are user-chosen labels with no Material in them and no Material obtainable from them, so
  the cap's purpose (no Material, nothing that becomes Material by accumulation) holds. Per
  Requirement 11 AC 2 the field is additive and needs no version increment; once added it is
  permanent.
- **credential-retrieval-api Requirement 15 AC 1** lists `credential/tag` among the mutation
  methods, and AC 4 lists it among the credential-addressed ones, whose misses fail as
  `CREDENTIAL_NOT_FOUND` (Requirement 3.4).
