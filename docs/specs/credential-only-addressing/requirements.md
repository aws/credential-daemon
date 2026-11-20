# Requirements: Credential-Only Addressing

## Introduction

A caller names a credential with `--credential <NAME>` or `--name <NAME>` on the CLI, or with
the `credential` parameter on the socket. No CLI command or socket method exposes an
environment. A request that still names one fails rather than silently selecting a
different credential.

Environment implementation remains in the codebase for a later decision to reintroduce it.
Its handlers are unreachable through dispatch, and nothing serves an environment.
`config.toml` files containing environment tables are invalid.

## Requirement 1: One credential selector, two spellings

1. `bootstrap`, `login`, `get`, and `remove` SHALL take a credential selector.
   `--credential` is its primary spelling and `--name` is a visible synonym. The two SHALL
   parse to the same value and behave identically.
2. The credential selector SHALL be required on `login`, `get`, and `remove`. `bootstrap` SHALL
   take exactly one of the credential selector or `--name-prefix <PREFIX>`, which names an
   `aws-login` credential after the identity that signs in. An invocation that gives neither,
   or both, SHALL fail as a usage error before the client connects to the daemon.
3. Repeating the selector, under either spelling or both, SHALL fail as a usage error.
4. No other option SHALL be named `--name`.

## Requirement 2: Refuse an environment selector on the CLI

1. WHEN `--environment` or `--env` appears on any `creds` subcommand, with a separate value,
   `=value`, or no value, THEN the CLI SHALL exit with usage-error status 2 and print to stderr:

   `error: --environment is not supported; name a credential with --credential <NAME> (or --name <NAME>)`

   The message SHALL not echo the supplied value.
2. The refusal SHALL happen before the client connects to the daemon, reads a file, or prompts.
   It SHALL take precedence over other usage errors in the invocation.
3. Neither spelling of the environment selector SHALL appear in CLI help or shell completions.
4. Other options whose names start with `env`, such as `--env-var`, SHALL continue to work.
   Option matching SHALL be exact.

## Requirement 3: Credential-only CLI behavior

1. `creds get` SHALL fetch the named credential under its own restrictions. It SHALL not use
   an environment to choose or narrow it.
2. `creds remove` SHALL remove the named credential. It SHALL not remove an environment.
3. `creds config` SHALL expose only `path`. `set`, `get`, and `unset` each require an
   environment and no credential provider consumes their environment settings. `keys` lists
   only those settings. The four omitted subcommands SHALL fail as unknown subcommands.
4. `creds list` SHALL list every credential once, with no environment field or column.
5. CLI help, errors, and remediation hints SHALL not tell the user to name, create, or remove
   an environment.
6. The CLI SHALL not derive a credential from `$AWS_PROFILE` or any other ambient variable.

## Requirement 4: No reachable environment socket surface

1. `environment/credentials`, `environment/describe`, `environment/remove`, `config/set`,
   `config/get`, and `config/unset` SHALL return method-not-found (`-32601`) on every carrier.
2. `credential/get` and `credential/list` SHALL reject an `environment` parameter, including
   `null`, as invalid params (`-32602`) before loading caller state. The error SHALL name the
   parameter without echoing its value. `credential/get` SHALL require `credential`.
3. Results and the OpenRPC document SHALL contain no environment field or method.
4. No served credential or audit outcome SHALL depend on an environment definition.
5. Every dispatched method that names a subject names a credential. Its not-found failure, and
   its deny-by-absence failure for a caller not authorized for it, SHALL be
   `CREDENTIAL_NOT_FOUND`. No dispatched method SHALL emit `ENVIRONMENT_NOT_FOUND`. The code
   stays reserved and SHALL NOT be reassigned to another meaning.

## Requirement 5: Environment tables are invalid

1. A caller `config.toml` containing `[environments]`, `[environments.<name>]`, or the
   unsupported singular `[environment]` SHALL be rejected as invalid configuration. The
   rejection SHALL name the unsupported table without echoing its contents.
2. `file/revalidate` SHALL not seal a file containing such a table.
3. The parser and validation code for `EnvConfig` SHALL remain in the codebase for later use,
   but no served request SHALL read an environment definition.

## Non-Goals

- Deleting the environment model, projection code, or method implementations. They remain
  unreachable for later reuse.
- Rewriting existing `config.toml` files. The caller must remove the unsupported tables;
  the daemon does not silently discard them.
- Moving `region`, `sdk.*`, or `cli.*` onto credentials. Providers retain their own region in
  `credentials.toml`.

## Open Questions

- A future spec may decide whether and how to restore environment operations.
