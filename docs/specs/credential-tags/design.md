# Design: Credential Tags

**Status:** draft
**Feature:** `credential-tags`
**Requirements:** see `requirements.md` in this directory.

## Overview

Tags are a map from key to value on each `credentials.toml` entry. They are parsed by a thin
wrapper around `CredentialSource`, validated at load, returned on every `credential/list` row,
matched by an optional `credential/list` filter, and written by `credential/bootstrap` and a new
`credential/tag` method. Nothing else reads them.

## Key Design Decisions

1. **A wrapper, not a field on every source.** `CredentialSource` is an internally tagged enum
   with nine configured variants. Adding `tags` to each config struct would repeat one field nine
   times and let a new source forget it. A wrapper holds it once:

   ```rust
   #[derive(Deserialize, Serialize)]
   pub struct CredentialEntry {
       #[serde(default, skip_serializing_if = "Tags::is_empty")]
       pub tags: Tags,
       #[serde(flatten)]
       pub source: CredentialSource,
   }
   ```

   The wrapper consumes `tags` itself; `flatten` passes only the remaining keys to the source.
   So a source struct with `deny_unknown_fields` never sees `tags`, and still rejects a stray key
   (Requirement 2.3). The wrapper itself MUST NOT carry `deny_unknown_fields`: on a struct with a
   `flatten` field, serde reports every flattened key as unknown, and every entry would fail.

2. **Every parse goes through the wrapper.** Parsing an entry straight into `CredentialSource`
   would hand `tags` to the source struct, and the one with `deny_unknown_fields` would reject
   it. `parse_sources` therefore parses `HashMap<String, CredentialEntry>` and maps each entry to
   its source, so existing callers keep `CredentialSources` unchanged. Callers that need tags use
   a sibling that keeps the entries.

3. **A dedicated `credential/tag`, not `config/set`.** `config/set` is environment-addressed and
   always presence-gated, and for a credential that no environment composes it fails as
   `ENVIRONMENT_NOT_FOUND` (credential-retrieval-api Requirement 10, open question on
   environment-addressed configuration). Tags are per-credential labels and not an authorization
   input (Requirement 5.1), so they belong on a Credential-addressed method. A dedicated method
   also gives `set` and `unset` one atomic write.

4. **`BTreeMap` for the tag set.** Ordered keys give a stable `credentials.toml` rewrite, a
   stable JSON row, and deterministic test output. At 32 entries the cost is nothing.

5. **`null` means "key present" in the filter.** The filter is a JSON object, so one condition
   per key falls out of the shape and duplicate keys cannot be expressed on the wire. A string
   value is an equality condition; `null` is a presence condition. This avoids a second filter
   field for presence.

6. **`tags` is always present on a row.** A consumer reads `row.tags` without an existence
   check, and `{}` is unambiguous. The cost is three bytes per untagged row.

7. **Bootstrap without `--tag` keeps the existing set.** Re-bootstrap is the re-authentication
   and rotation path. Losing labels because a user did not repeat them would be a surprise; a
   user who wants to change tags has `creds tag`.

8. **Tag writes go through the existing `credentials.toml` write path.** That path checks the
   file against the bytes read and keeps the drift seal in step with the new text
   (drift-detection). A tag write is an edit to the entry's `tags` table in the same
   `toml_edit` document, so comments and unrelated entries are preserved and drift detection
   sees the change as the daemon's own.

## Data Models

### Config entry (`credentials.toml`)

```toml
[pay-prod]
type = "aws-idc-sso"
start_url = "https://example.awsapps.com/start"
sso_region = "us-east-1"
tags = { team = "payments", stage = "prod" }
```

### `credential/list` params

```json
{ "environment": "dev", "tags": { "team": "payments", "stage": null } }
```

Both fields are optional. `ListParams` keeps `deny_unknown_fields`; it has no `flatten` field.

### `credential/list` row

```json
{
  "credential": "pay-prod",
  "kind": "session_credentials",
  "status": "active",
  "tags": { "stage": "prod", "team": "payments" }
}
```

### `credential/tag` params and result

```json
{ "credential": "pay-dev", "set": { "stage": "dev" }, "unset": ["owner"] }
```

Result: `OkResult` (`{}`).

### `credential/bootstrap` params

Gain an optional `tags` object with the same shape as the config table.

## Components

### 1. `Tags` (`credsd-core`, `config/tags.rs`, new)

A newtype over `BTreeMap<String, String>` whose `Deserialize` folds each key to ASCII lowercase
and then runs the Requirement 1 checks, so an invalid or unfolded tag set cannot be constructed
from config or from a request. Two input keys that fold to one key fail, naming both spellings
(Requirement 1.6). One `validate` function holds the folding, the key pattern, the value range,
and the count limit; the load path, the request path, and the CLI all call it, and the daemon
never relies on the CLI having done it. A `TagFilter` newtype over
`BTreeMap<String, Option<String>>` folds and validates keys and values the same way and provides
`matches(&Tags) -> bool`. The `unset` list of `credential/tag` is folded the same way.

### 2. Credentials file (`config/credentials.rs`)

`CredentialEntry` as above. `parse_sources` goes through it (Decision 2). A load error names the
credential and the key (Requirement 1.5).

### 3. RPC types (`rpc/methods.rs`)

`ListParams.tags: Option<TagFilter>`. `CredentialSummary.tags: Tags`. New
`METHOD_CREDENTIAL_TAG = "credential/tag"` and `TagParams { credential, set, unset }`.
`credential/bootstrap` params gain `tags: Option<Tags>`.

### 4. Dispatch (`credsd-daemon`, `server/dispatch.rs`)

The list handler fills `tags` from the loaded entry and drops rows the filter does not match,
after the environment filter has run. `credential/tag` is added to the UDS-only exposure table
and writes through the existing credentials write path (Decision 8).

### 5. CLI (`credsd`, `main.rs`)

`--tag` on `bootstrap` and `list`, and a `tag` subcommand with `set` and `unset`. Parsing
`key=value` versus `key` and the duplicate-key check happen before the request is sent.
`list` text output gains a `TAGS` column of `key=value` pairs; JSON output includes `tags`.

## Correctness Properties

1. **Filter matches the model.** For any tag set and any filter, `matches` returns true exactly
   when every condition holds under a direct reference implementation.
2. **Empty filter is the identity.** For any rows, an empty filter keeps every row.
3. **Validation is exact.** Every key from the Requirement 1.1 pattern and every value from the
   1.2 range is accepted; any key outside the pattern, any value with a byte outside
   `0x20`-`0x7E` or over 256 bytes, and any set over 32 tags is rejected.
4. **Tags do not disturb sources.** For any valid entry and tag set, the parsed source equals the
   source parsed from the same entry without `tags`, and a stray key is still rejected where it
   was before.
5. **Round trip.** Writing a tag set and loading the file yields the same set.
6. **Set and unset compose.** `credential/tag` with `set` and `unset` yields the old set with
   `set` applied and then `unset` removed.
7. **Folding is total and never merges.** For any input key, the stored key is its ASCII
   lowercase form; values are unchanged; two input keys with one folded form are rejected.

## Testing Strategy

Properties 1 to 7 are `proptest` tests in `credsd-core`, with generators for valid keys and
values and for adversarial ones: mixed case (folded), colliding spellings such as `Env` and
`env`, non-ASCII letters with case (rejected, not folded), leading punctuation, control
characters, 63- and 64-byte keys, 256- and 257-byte values, 32 and 33 tags. Dispatch tests cover
the filter on `credential/list` together with the environment filter, folding on every request
path, and the exposure of `credential/tag`. CLI parse tests cover `--tag` forms and duplicate
keys.

## Spec Coherence

- credential-retrieval-api Requirement 13 AC 4: amended to add `tags` to the row (see
  `requirements.md`, Relationship to Other Specs).
- credential-retrieval-api Requirement 15 AC 1 and AC 4: `credential/tag` is a credential-addressed mutation method.
- drift-detection: tag writes use the daemon's sealed write path; a hand edit to `tags` is
  drift like any other hand edit.
