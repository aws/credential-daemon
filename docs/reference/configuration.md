<!-- maturity-notice -->
> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path. The on-disk layout may change without a migration. Windows is for
> ease of use only: there is no process-tree assessment, and `serve` does not run there yet.
<!-- /maturity-notice -->

# Configuration reference

Source of truth: `crates/credsd-core/src/config/keys.rs` (`ALLOWED_KEYS`),
`crates/credsd-core/src/config/mod.rs` (`DaemonConfig`, `EnvConfig`),
`crates/credsd-core/src/config/credentials.rs` (`CredentialSource`),
`crates/credsd-core/src/config/platform.rs` (paths), and each `std::env::var` call site for
environment variables.

The daemon owns every file below and is their only writer. Change them with
[`creds`](commands.md) (`bootstrap`, `config set`, `remove`), not by hand: under a system
install they belong to the `credsd` account and users cannot read them.

## Files and where they live

### Data directory

| Install shape | Data directory | Socket | Default log file |
|---|---|---|---|
| macOS system install (LaunchDaemon) | `/Library/Application Support/credsd` | `/var/run/credsd/credsd.sock` | `/Library/Logs/credsd/credsd.log` |
| macOS user-scoped install (official signed release) | `~/Library/Application Support/credsd` | `<data dir>/credsd.sock` | `<data dir>/credsd.log` |
| Linux system install | `/var/lib/credsd` | `/run/credsd/credsd.sock` | `/var/log/credsd/credsd.log` |
| Windows (install shapes undecided) | `C:\ProgramData\credsd` | named pipe `\\.\pipe\credsd-<USERNAME>`, not yet served | — |

`CREDSD_DATA_DIR` overrides the data directory and `CREDSD_SOCKET` the socket. The macOS
user-scoped service sets both in its LaunchAgent. `credsd serve` run by hand as a non-root,
non-`credsd` uid uses the platform data directory above and binds a per-user socket:
`~/Library/Application Support/credsd/credsd.sock` on macOS,
`$XDG_DATA_HOME/credsd/credsd.sock` (default `~/.local/share/credsd/credsd.sock`) on Linux.

A client dials `CREDSD_SOCKET` if set, else the per-user socket if one is live, else the
system socket.

### Layout

```
<data dir>/
├── config.toml                 daemon-wide: [log]
├── callers/<uid>/              one per authorized user, mode 0700
│   ├── owner                   username recorded at provisioning
│   ├── config.toml             this user's environments
│   ├── credentials.toml        this user's credential sources (no secrets)
│   └── credentials/<name>/     sealed material for one credential (*.enc)
└── quarantine/                 Linux: sealed files moved aside after a TPM or keyring reset
```

A uid with no `callers/<uid>/` directory cannot use the daemon; the daemon creates it on the
user's first bootstrap. Files are written mode 0600, and credsd warns when it finds one more
permissive. Where the master key lives depends on the storage backend; see
[key security](../key-security.md).

Environment and credential names are 1–64 characters of letters, digits, `.`, `_`, `-`, and
do not start with `.`.

## config.toml

### Environments

An environment is an ordered list of credentials plus the settings handed to a child process.

```toml
[environments.work]
credentials = ["work-sso", "audit"]
identity_type = "human"
region = "us-west-2"

[environments.work.sdk]
retry_mode = "adaptive"
```

| Key | Type | Meaning |
|---|---|---|
| `credentials` | array of names | Credentials composed, in order. The first is the default identity, which `creds get` returns when `--credential` is omitted. Omitted: one credential named after the environment. |
| `credential` | name | Legacy single-credential form. Read, never written. |

Every listed credential must exist in `credentials.toml`, or the file fails to load.

### Identity types

`identity_type` classifies an environment or a credential: `human` (default), `automation`,
`agent`. Privilege ascends `agent` < `automation` < `human`. An environment may compose only
credentials whose type is no more privileged than its own: a `human` environment composes any,
an `automation` environment composes `automation` and `agent`, an `agent` environment composes
only `agent`. An unrecognized value on an environment is treated as `agent` (least-privileged).
An unrecognized value on a credential is treated as more privileged than `human`: only a
`human` environment may compose it; `config.toml` fails to load if any other environment does.
An `agent` environment logs a warning: agent credentials are not yet scoped down and carry the
role's full permissions.

### Settable keys

`creds config set|get|unset <key> --environment <env>` edits these. `creds config keys` lists
them. The Variable and AWS config columns name where a consumer that delivers an environment to a
process — run-time tooling built on the [API](api.md) — places each key: the environment variable
it exports, and the setting it writes to every section of a generated AWS config.

Two keys are restricted, in different ways. `credential` is blocked for read, write, and unset
alike; change a credential with `creds bootstrap`. `identity_type` is readable and settable but
cannot be unset: an absent `identity_type` is read as `human`, the most privileged tier, so
removing it would grant privilege rather than drop it — set it to an explicit
[tier](#identity-types) instead.

| Key | Type | Variable | AWS config | Meaning |
|---|---|---|---|---|
| `region` | string | `AWS_REGION`, `AWS_DEFAULT_REGION` | `region` | Region for the environment. |
| `identity_type` | `human`, `automation`, `agent` | | | [Identity type](#identity-types). |
| `description` | string | | | Free text. Stored; credsd does not act on it. |
| `sdk.endpoint_url` | string | `AWS_ENDPOINT_URL` | `endpoint_url` | Global endpoint URL override. |
| `sdk.use_fips_endpoint` | boolean | `AWS_USE_FIPS_ENDPOINT` | `use_fips_endpoint` | Use FIPS endpoints. |
| `sdk.use_dualstack_endpoint` | boolean | `AWS_USE_DUALSTACK_ENDPOINT` | `use_dualstack_endpoint` | Use dual-stack endpoints. |
| `sdk.ca_bundle` | string | `AWS_CA_BUNDLE` | `ca_bundle` | Path to a CA certificate bundle. |
| `sdk.retry_mode` | `standard`, `adaptive`, `legacy` | `AWS_RETRY_MODE` | `retry_mode` | SDK retry strategy. |
| `sdk.max_attempts` | positive integer | `AWS_MAX_ATTEMPTS` | `max_attempts` | Maximum attempts. |
| `sdk.defaults_mode` | `legacy`, `standard`, `in-region`, `cross-region`, `mobile`, `auto` | `AWS_DEFAULTS_MODE` | `defaults_mode` | SDK defaults mode. |
| `sdk.sts_regional_endpoints` | `regional`, `legacy` | `AWS_STS_REGIONAL_ENDPOINTS` | `sts_regional_endpoints` | STS endpoint resolution. |
| `sdk.s3_us_east_1_regional_endpoint` | `regional`, `legacy` | `AWS_S3_US_EAST_1_REGIONAL_ENDPOINT` | `s3_us_east_1_regional_endpoint` | S3 us-east-1 endpoint resolution. |
| `sdk.disable_request_compression` | boolean | `AWS_DISABLE_REQUEST_COMPRESSION` | `disable_request_compression` | Disable request compression. |
| `sdk.request_min_compression_size_bytes` | positive integer | `AWS_REQUEST_MIN_COMPRESSION_SIZE_BYTES` | `request_min_compression_size_bytes` | Minimum payload size to compress, in bytes. |
| `sdk.ignore_configured_endpoint_urls` | boolean | `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS` | `ignore_configured_endpoint_urls` | Ignore configured endpoint URLs. |
| `sdk.sdk_ua_app_id` | string | `AWS_SDK_UA_APP_ID` | `sdk_ua_app_id` | Application id in the SDK user agent. |
| `sdk.account_id_endpoint_mode` | `preferred`, `disabled`, `required` | `AWS_ACCOUNT_ID_ENDPOINT_MODE` | `account_id_endpoint_mode` | Account-based endpoint routing. |
| `sdk.parameter_validation` | boolean | | `parameter_validation` | Client-side parameter validation. |
| `cli.output` | `json`, `text`, `table`, `yaml`, `yaml-stream` | `AWS_DEFAULT_OUTPUT` | `output` | AWS CLI output format. |
| `cli.pager` | string, may be empty | | | Stored, never projected: `AWS_PAGER` is a command line the CLI executes, so projecting it would let config run code as the caller. |
| `cli.cli_timestamp_format` | `iso8601`, `wire` | | `cli_timestamp_format` | AWS CLI timestamp format. |
| `cli.cli_binary_format` | `base64`, `raw-in-base64-out` | | `cli_binary_format` | AWS CLI binary encoding. |
| `cli.cli_follow_urlparam` | boolean | | `cli_follow_urlparam` | AWS CLI fetches URL parameters. |

Booleans accept `true` or `false` in any case. Strings other than `cli.pager` must be
non-empty.

### Other top-level keys

| Key | File | Meaning |
|---|---|---|
| `[log]` `level` | `<data dir>/config.toml` | `error`, `warn`, `info`, `debug`, `trace`. Daemon only. |
| `[log]` `format` | `<data dir>/config.toml` | `text`, `json`. Daemon only. |
| `[log]` `file` | `<data dir>/config.toml` | Log file path. Daemon only. |
| `[auth]` `agent_binaries` | `callers/<uid>/config.toml` | Binary names that mark a caller as an agent when found in its process ancestry, for the audit record. Non-empty replaces the built-in list. |
| `socket_path` | either | Must be absolute. Neither binary reads it; use `CREDSD_SOCKET`. |

`port`, `transport_mode`, and `storage_backend` are obsolete: credsd logs a warning and ignores
them.

## credentials.toml

One table per credential, keyed by name, tagged by `type`. Secrets are never in this file: each
is sealed under `credentials/<name>/`. Every type also takes `identity_type`
(default `human`). An unknown `type` loads as unsupported rather than failing the file.

```toml
[work-sso]
type = "aws-idc-sso"
start_url = "https://example.awsapps.com/start"
sso_region = "us-east-1"
account_id = "123456789012"
role_name = "Developer"
```

### aws-idc-sso

| Field | Required | Meaning |
|---|---|---|
| `start_url` | yes | SSO start URL. |
| `sso_region` | yes | SSO region. |
| `account_id` | yes | Account. |
| `role_name` | yes | Role. |

Sealed: `sso_token.enc`.

### aws-iam-user

| Field | Required | Meaning |
|---|---|---|
| `region` | yes | Region whose STS endpoint brokers `GetSessionToken`. |
| `duration_seconds` | no | Session duration. |
| `mfa_serial` | no | MFA device ARN. Set: sessions need an MFA code, so renewal needs `creds login`. |

Sealed: `iam_user.enc` (key pair), `iam_session.enc` (session from `creds login`).

### aws-roles-anywhere

| Field | Required | Meaning |
|---|---|---|
| `trust_anchor_arn` | yes | Trust anchor ARN. |
| `profile_arn` | yes | Profile ARN. |
| `role_arn` | yes | Role ARN. |
| `region` | no | Default: from the trust anchor ARN. |
| `duration_seconds` | no | Session duration. |
| `role_session_name` | no | Role session name. |
| `endpoint_url` | no | `CreateSession` endpoint, for non-commercial partitions. |

Sealed: `ra_key.enc` (private key). The certificate and chain are public and stored in
`ra_public.json`.

### aws-web-identity

| Field | Required | Meaning |
|---|---|---|
| `role_arn` | yes | Role for `AssumeRoleWithWebIdentity`. |
| `authorization_endpoint` | no | OAuth authorization endpoint. Set by `bootstrap`. |
| `token_endpoint` | no | OAuth token endpoint. Set by `bootstrap`. |
| `client_id` | no | OAuth client id. Set by `bootstrap`. |
| `scopes` | no | Array of scopes. |
| `region` | yes | STS region. Required; no default. |
| `duration_seconds` | no | Session duration. |
| `role_session_name` | no | Role session name. |
| `callback_port` | no | Fixed loopback callback port. Default: ephemeral. |

Sealed: `oauth_token.enc`.

### aws-login

AWS Sign-In (`aws login`). No role and no STS call: the token endpoint returns credentials.

| Field | Required | Meaning |
|---|---|---|
| `region` | yes | Sign-In region; selects `https://{region}.signin.aws.amazon.com`. Required; no default. The `bootstrap` CLI requires `--region`. |
| `callback_port` | no | Fixed loopback callback port. Default: ephemeral. Not valid with `remote`. |
| `remote` | no | Boolean. Cross-device login: no loopback listener; the authorization code is pasted back. Default `false`. |
| `identity_type` | no | Who the credential is for. Default `human`. |

Sealed: `aws_login_token.enc` (includes the DPoP key).

### jwt

| Field | Required | Meaning |
|---|---|---|
| `env_var` | no | Variable the token is exported as to a child. Default: the credential name, upper-cased, with `.`, `-`, and `_` folded to `_` (`my-token` exports `MY_TOKEN`). |

Sealed: `jwt.enc`. Expiry is the JWT's `exp` claim. No path is stored.

### oauth

OAuth 2.0 client credentials.

| Field | Required | Meaning |
|---|---|---|
| `token_url` | yes | Token endpoint. |
| `client_id` | yes | Client id. |
| `grant` | yes | `client-credentials`. Other values load as unsupported. |
| `scope` | no | Requested scope. |

Sealed: `oauth_client_secret.enc` (`client_secret_basic`) or `oauth_client_key.enc`
(`private_key_jwt`); which one exists selects the method.

### static-secret

| Field | Required | Meaning |
|---|---|---|
| `env_var` | no | Variable the secret is exported as to a child. Default: the credential name, upper-cased, with `.`, `-`, and `_` folded to `_`. |
| `expires_at` | no | RFC 3339 expiry. Omitted: never expires. |
| `secret_source` | no | Where the secret came from. Recorded for diagnostics; never read at runtime. |

Sealed: `static_secret.enc`.

### jwt-bearer

`jwt-bearer` feature only. A build without it parses a stored jwt-bearer credential but skips
it with a warning rather than serving it.

**Experimental: subject to change.** This config shape may change in a later release without
the compatibility guarantees given to default-on features.

| Field | Required | Meaning |
|---|---|---|
| `token_url` | yes | Token endpoint. |
| `client_id` | no | Client id, for IdPs that require one. |
| `scope` | no | Requested scope. |

Sealed: `jwt_assertion.enc`. To rotate the assertion, bootstrap again.

## Environment variables

| Variable | Read by | Effect |
|---|---|---|
| `CREDSD_DATA_DIR` | both | Data directory. Overrides the platform default. Must be absolute: the daemon and `install` refuse to start with a relative value, and the client ignores it with a warning. |
| `CREDSD_CONFIG_DIR` | both | Legacy name for `CREDSD_DATA_DIR`, used when that is unset. `--config-dir` sets it. |
| `CREDSD_SOCKET` | both | Socket the daemon binds and the client dials. Must be absolute; a relative value is ignored with a warning, an empty one is treated as unset. `creds --socket` sets it. |
| `CREDSD_LOG_LEVEL` | both | `error`, `warn`, `info`, `debug`, `trace`. |
| `CREDSD_LOG_FORMAT` | both | `text`, `json`. |
| `CREDSD_LOG_FILE` | both | Append logs to this file, as well as stderr. |
| `CREDSD_SE_PROTECTION` | `credsd`, `secure-enclave` backend | Keychain protection class of the Secure Enclave key: `always` (default), `after-first-unlock`, `when-unlocked`. Other values are an error. |
| `CREDSD_TPM_POLICY` | `credsd`, `tpm` backend | Not supported. The `tpm` backend seals under the `machine` policy only and refuses to start while this is set. |
| `CREDSD_ALLOW_HTTP` | `credsd`, debug builds only | Set to any value: allow `http` OAuth endpoints. Release builds ignore it. |
| `CREDSD_TOKEN` | not read | Not a default. A `jwt` or `static-secret` token is exported under the credential name, upper-cased, unless `env_var` is set. |

Log settings resolve flag, then `[log]` in `<data dir>/config.toml` (daemon only), then the
`CREDSD_LOG_*` variable, then the default (`info`, `text`, no file). `RUST_LOG`, when set,
overrides the level.
