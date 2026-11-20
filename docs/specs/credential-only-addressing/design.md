# Design: Credential-Only Addressing

**Requirements:** [requirements.md](requirements.md)

## Boundary

The CLI and socket select credentials only. Environment model, projection code, and handler
implementations remain in the codebase for later reuse, but callers cannot reach them.
The dispatcher returns method-not-found for environment methods and environment setting
methods. The OpenRPC document lists only dispatched methods. A dormant method implementation
is not part of the API.

## Credential selector

`Login`, `Get`, and `Remove` each declare one field:

```rust
#[arg(long, visible_alias = "name")]
credential: String,
```

`Bootstrap` declares the same selector as `Option<String>` with
`required_unless_present = "name_prefix"` and `conflicts_with = "name_prefix"`, so clap requires
exactly one of `--credential`/`--name` and `--name-prefix`.

A required `String` makes clap reject a missing selector. clap's `ArgAction::Set` rejects a
second occurrence under either spelling. `Get` and `Remove` do not declare an `env` field.

## Environment selector refusal

`main` scans raw argv before `Cli::parse`, stopping at the first bare `--`. It matches only a
token equal to `--environment` or `--env`, or beginning with `--environment=` or `--env=`.
On a match it prints Requirement 2's message to stderr and returns exit status 2. This gives
the refusal precedence over clap's missing-credential and unknown-subcommand errors, without
putting the withdrawn selector in help or completions. clap's long-argument inference stays
disabled, so `--env-var` is independent.

## Socket refusal

The dispatch exposure table marks the six environment and environment-setting methods
unavailable on every carrier. Their implementations and wire types remain compiled, so a
future spec can reintroduce them without recovering deleted logic. Before calling a handler,
dispatch checks whether `credential/get` or `credential/list` contains an `environment`
member, including `null`. An absent member remains valid. The rejection happens before
loading caller state, and `credential/get` requires a credential name.

The OpenRPC document excludes unavailable methods and environment fields.

Integration tests that require a served environment remain in the test suite but are ignored
while the environment surface is unavailable. Credential-only socket tests cover the active
behavior.

### Unreachable implementations

The withdrawn methods keep their `Method` variants, their `Method::parse` arms, and their
`handle` arms. `exposed()` returns `false` for each one on every carrier, and `dispatch` checks
exposure before it calls `handle`. Every handler is therefore still referenced, so no
`#[allow(dead_code)]` is needed and `cargo clippy -- -D warnings` passes unchanged. The same
holds for the presence `Op` variants those handlers raise.

Because `exposed()` is the only guard, a test walks `Method::all()` and asserts that each
withdrawn method returns `-32601` with the same body as an unknown method. Flipping one of those
`false` values back to `true` fails the test instead of silently re-exposing the method.

### Error codes

`dispatch.rs::not_found` delegates to `credential_not_found`. `bootstrap.rs::not_found` and the
`login_one` miss build `DomainCode::CredentialNotFound`. As a result, `authorized_uid`,
`enumerating_uid`, `authorize_for_bootstrap`, and the misses in `credential/login`,
`credential/remove`, and `credential/bootstrap` all deny as `CREDENTIAL_NOT_FOUND`
(Requirement 4.5). `DomainCode::EnvironmentNotFound` keeps its variant and its wire spelling, so
the code is never reassigned. Only the unreachable environment handlers still construct it.

## Config files

The file-loading boundary rejects `environment` and `environments` top-level tables before
creating caller state. The same check runs before `file/revalidate` seals a snapshot. The
model parser and `EnvConfig` validation remain available to tests and to later designs.
An existing file is not rewritten; its owner must remove the table to restore service.

## CLI commands

- `cmd_get` fetches a named credential with `fetch_credential` or `fetch_role_credential`.
  An interactive re-authentication retries the same named credential. A token's shell
  export uses the name derived from the credential, with no manifest request.
- `cmd_remove` calls `credential/remove` for the named credential.
- `ConfigAction` contains `Path` only. Its environment-specific CLI handlers are absent.
  The underlying config model, keys, client functions, and daemon handlers remain unreachable.
- `creds list` uses credential enumeration without an environment filter. Text and JSON
  output have no environment field.

## Documentation and compatibility

The CLI command reference lists `config path` as the sole `config` subcommand and describes
`get` and `remove` as credential addressed. The API reference and OpenRPC contract list
only dispatched methods. Accepted specs whose criteria or examples name an environment carry an "Applicability"
note that limits those criteria to retained internal code:

| Spec | What the note covers |
|---|---|
| `credential-retrieval-api` | Environment addressing, aggregate retrieval, the manifest, the `config/*` methods, `environment/remove` |
| `presence-gated-operations` | The gates on `config/set`, `config/unset`, and `environment/remove`, and 8.5's deny-by-absence code |
| `static-secret-credentials` | 3.3's environment level and 3.5's `environment/credentials`. Its introduction examples use `--credential` alone. |
| `drift-detection` | 6.1's `config/get` example |
| `client-storage-delegation` | The non-goal that lists `environment/credentials` and `describe` |

## Verification

| Requirement | Test |
|---|---|
| 1 | Parse tests cover both selector spellings, missing selectors, duplicate selectors, and help text on all four commands, and `bootstrap` with `--name-prefix` alone, with both, and with neither. |
| 2 | Parser tests cover both environment spellings and forms, precedence, `--env-var`, and the end-of-options marker. A binary test checks exit 2 and the exact stderr before any connection. |
| 3.1-3.2 | CLI tests verify named get and remove use the credential methods without an environment selector. |
| 3.3 | Each omitted `creds config` subcommand fails as unknown, while `config path` works. |
| 3.4-3.6 | Output and parsing tests cover credential-only listing and no ambient selector. |
| 4.1 | All six environment methods return the same method-not-found response as an unknown method. |
| 4.2 | `credential/get` and `credential/list` reject any `environment` value, including `null`, before caller-state access. |
| 4.3-4.4 | OpenRPC contains no environment surface; credential retrieval tests use only credential restrictions. |
| 4.1 (guard) | Walk `Method::all()`: every withdrawn method returns the unknown-method body. |
| 4.5 | For an unauthorized caller and for an absent credential, `credential/get`, `credential/login`, `credential/remove`, and `credential/bootstrap` all return `CREDENTIAL_NOT_FOUND`. |
| 5 | A config with either environment table spelling is refused on load and revalidation; the file is not rewritten. |
| Token export name | `creds get --format shell` of a token credential exports the name derived from the credential, both for a credential bootstrapped with `--env-var` and for one without. |

## File changes

| File | Change |
|---|---|
| `crates/credsd/src/main.rs` | Credential selector alias and pre-parse refusal; credential-only get/remove; `ConfigAction::Path` only; CLI-only handler and help cleanup. |
| `crates/credsd-daemon/src/server/dispatch.rs` | Withdraw environment methods at the exposure table; retain their implementations. `not_found` is `CREDENTIAL_NOT_FOUND`. |
| `crates/credsd-daemon/src/server/bootstrap.rs` | Use credential-not-found errors for credential bootstrap and login. |
| `crates/credsd-core/src/config/mod.rs`, `crates/credsd-daemon/src/server/integrity.rs` | Reject environment tables at persisted-file load and revalidation boundaries. |
| `docs/api/openrpc.json` | Describe only reachable methods and fields. |
| `docs/reference/commands.md`, `docs/reference/configuration.md` | Document the CLI surface and retained environment config. |
| `docs/specs/credential-only-addressing/*` | Define this credential-only boundary. |
| `docs/specs/{credential-retrieval-api,presence-gated-operations,static-secret-credentials,drift-detection,client-storage-delegation}/requirements.md` | Applicability notes; `static-secret-credentials` examples. |
