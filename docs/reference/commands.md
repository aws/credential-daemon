<!-- maturity-notice -->
> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path. The on-disk layout may change without a migration. Windows is for
> ease of use only: there is no process-tree assessment, and `serve` does not run there yet.
<!-- /maturity-notice -->

# Command reference

Two binaries. `creds` is the client; it talks to the daemon over its socket. `credsd` is the
daemon and its service installer.

Source of truth: the clap definitions in `crates/credsd/src/main.rs` (`creds`) and
`crates/credsd-daemon/src/main.rs` (`credsd`). A test fails when this page and those
definitions disagree.

Every `creds` command except `config path` and `config keys` needs a running daemon.
On Windows there is no daemon transport yet, so those commands fail with an error.

`--environment` is also accepted as `--env` wherever it appears.

## creds

### creds

Client CLI. Global flags, accepted before or after the subcommand:

| Flag | Value | Meaning |
|---|---|---|
| `--config-dir <PATH>` | path | Sets `CREDSD_CONFIG_DIR` for this invocation. See [configuration](configuration.md#environment-variables). |
| `--quiet`, `-q` | | Log level `error`. Conflicts with `--verbose`. |
| `--verbose`, `-v` | | Log level `debug`. |
| `--log-file <PATH>` | path | Append logs to this file. |
| `--log-format <FORMAT>` | `text`, `json` | Log format. |
| `--socket <PATH>` | absolute path | Daemon socket to dial. Sets `CREDSD_SOCKET` for this invocation. |

### creds bootstrap

Create or re-authenticate a credential, optionally wrapping it in an environment.

```
creds bootstrap [--environment <ENV>] [--credential <NAME>] [<PROVIDER> <PROVIDER-FLAGS>]
```

| Flag | Value | Meaning |
|---|---|---|
| `--environment <ENV>` | name | Environment to create. Alone, it also names the credential (1:1). |
| `--credential <NAME>` | name | Credential to create. Alone, no environment is created. |

At least one of the two is required. With no provider, re-authenticates an existing
credential from its saved configuration, as `creds login` does. Names are 1–64 characters of
letters, digits, `.`, `_`, `-`, and do not start with `.`.

`--identity-type` on a provider sets the credential's [identity type](configuration.md#identity-types):
`human`, `automation`, or `agent`.

### creds bootstrap aws-idc-sso

AWS IAM Identity Center. Runs the device-code flow in a browser.

| Flag | Value | Meaning |
|---|---|---|
| `--start-url <URL>` | URL | Required. SSO start URL. |
| `--sso-region <REGION>` | region | SSO region. Required; no default. |
| `--account-id <ID>` | account id | Account. Omitted: chosen interactively. |
| `--role-name <NAME>` | role | Role. Omitted: chosen interactively. |
| `--identity-type <TYPE>` | identity type | Default `human`. |

```
creds bootstrap --environment work aws-idc-sso --start-url https://example.awsapps.com/start --sso-region us-east-1
```

### creds bootstrap aws-iam-user

Long-term IAM access key, brokered into session credentials with `sts:GetSessionToken`. The
secret access key is read from the terminal with echo disabled, or from piped stdin.

| Flag | Value | Meaning |
|---|---|---|
| `--access-key-id <ID>` | key id | Required. |
| `--region <REGION>` | region | Region whose STS endpoint is called. Required; no default. |
| `--duration-seconds <N>` | integer | Session duration. |
| `--mfa-serial <ARN>` | MFA device ARN | Sessions require an MFA code, so renewal needs `creds login`. |
| `--identity-type <TYPE>` | identity type | Default `human`. |

### creds bootstrap aws-roles-anywhere

IAM Roles Anywhere. Reads the certificate and private key once; the key is sealed, the path is
not kept.

| Flag | Value | Meaning |
|---|---|---|
| `--trust-anchor-arn <ARN>` | ARN | Required. |
| `--profile-arn <ARN>` | ARN | Required. |
| `--role-arn <ARN>` | ARN | Required. |
| `--certificate <PATH>` | PEM file | Required. Leaf certificate. |
| `--private-key <PATH>` | PEM file | Required. Private key. |
| `--cert-chain <PATH>` | PEM file | Intermediate chain. |
| `--region <REGION>` | region | Default: taken from the trust anchor ARN. |
| `--duration-seconds <N>` | integer | Session duration. |
| `--role-session-name <NAME>` | string | Role session name. |
| `--endpoint-url <URL>` | URL | `CreateSession` endpoint. Required for China and GovCloud partitions. |
| `--identity-type <TYPE>` | identity type | Default `human`. |

### creds bootstrap aws-web-identity

OAuth 2.0 authorization code with PKCE, federated to AWS with
`sts:AssumeRoleWithWebIdentity`. The daemon runs the flow; `creds` prints the authorization URL for you to open.

| Flag | Value | Meaning |
|---|---|---|
| `--authorization-endpoint <URL>` | URL | Required. |
| `--token-endpoint <URL>` | URL | Required. |
| `--client-id <ID>` | string | Required. |
| `--role-arn <ARN>` | ARN | Required. Role to assume. |
| `--scope <SCOPE>` | string, repeatable | Default `openid`. STS needs the `id_token` that `openid` yields. |
| `--region <REGION>` | region | STS region. Required; no default. |
| `--duration-seconds <N>` | integer | Session duration. |
| `--role-session-name <NAME>` | string | Role session name. |
| `--identity-type <TYPE>` | identity type | Default `human`. |
| `--callback-port <PORT>` | 1024–65535 | Fixed loopback callback port, for IdPs that require an exact redirect URI. Default: ephemeral. |

### creds bootstrap aws-login

AWS Sign-In login (`aws login`): OAuth 2.0 with PKCE and DPoP. Sign-In returns AWS
session credentials directly, with no `AssumeRoleWithWebIdentity`. The daemon runs the flow;
`creds` prints the authorization URL for you to open. Uses the AWS CLI's client id, so Sign-In may refuse it from another
client.

Two flows, picked by `--remote`:

- Same-device (default). Sign-In redirects to a loopback port the daemon is listening on, so the
  browser must run on this machine.
- Cross-device (`--remote`). No listener is bound. Sign-In redirects to its own confirmation page,
  which shows a code; `creds` prompts for it. Use this when the browser is elsewhere — a host
  reached over SSH, a container, a machine with no desktop.

| Flag | Value | Meaning |
|---|---|---|
| `--region <REGION>` | region | Required. Sign-In region. |
| `--identity-type <TYPE>` | identity type | Default `human`. |
| `--callback-port <PORT>` | 1024–65535 | Fixed loopback callback port. Default: ephemeral. Conflicts with `--remote`. |
| `--remote` | | Cross-device login: prompt for the code Sign-In displays instead of listening for a redirect. Recorded, so `creds login` reuses it. |

### creds bootstrap jwt

A bearer JWT read from a file and served as the credential. Its `exp` claim is the expiry.
To replace it, run the command again with a new file.

| Flag | Value | Meaning |
|---|---|---|
| `--token-file <PATH>` | file | Required. Read once and sealed. |
| `--env-var <NAME>` | variable name | Variable a child process receives the token in. Default: the credential name, upper-cased (`.`, `-`, `_` folded to `_`). |
| `--identity-type <TYPE>` | identity type | Default `human`. |

### creds bootstrap oauth

OAuth 2.0 client credentials. Authenticates with a client secret or an ES256 private key; the
secret or key is sealed.

| Flag | Value | Meaning |
|---|---|---|
| `--token-url <URL>` | HTTPS URL | Required. |
| `--client-id <ID>` | string | Required. |
| `--client-secret` | | Prompt for the client secret (`client_secret_basic`). Conflicts with `--private-key`. |
| `--private-key <PATH>` | PEM file | ES256 key (`private_key_jwt`). Conflicts with `--client-secret`. |
| `--scope <SCOPE>` | string | Requested scope. |
| `--identity-type <TYPE>` | identity type | Default `automation`. |

### creds bootstrap static-secret

A secret you already hold (API key, personal access token), served verbatim. Read from a file
or stdin, never from an argument. To rotate, run the command again.

| Flag | Value | Meaning |
|---|---|---|
| `--secret-file <PATH>` | file or `-` | Source of the secret. Omitted or `-`: stdin, prompted with echo disabled on a terminal. |
| `--env-var <NAME>` | variable name | Variable a child process receives the secret in. Default: the credential name, upper-cased (`.`, `-`, `_` folded to `_`). |
| `--expires-at <TIME>` | RFC 3339 | Expiry. Omitted: never expires. |
| `--identity-type <TYPE>` | identity type | Default `human`. |

```
my-secret-manager read api-key | creds bootstrap --environment api static-secret
```

### creds bootstrap jwt-bearer

OAuth 2.0 JWT bearer grant (RFC 7523). The assertion is read by `creds` and sealed by the
daemon; the daemon never sees the path. Builds with the `jwt-bearer` feature only; absent
from the default build and from `creds --help`.

**Experimental: subject to change.** Its config shape, CLI flags, and error behavior may
change in a later release without the compatibility guarantees given to default-on features.

| Flag | Value | Meaning |
|---|---|---|
| `--token-url <URL>` | HTTPS URL | Required. |
| `--assertion-file <PATH>` | file or `-` | Required. JWT assertion; `-` reads stdin. |
| `--client-id <ID>` | string | Client id, for IdPs that require one. |
| `--scope <SCOPE>` | string | Requested scope. |
| `--identity-type <TYPE>` | identity type | Default `automation`. |

### creds login

Re-authenticate credentials whose unattended renewal has ended (expired SSO session, MFA
session). Runs the interactive flow the source needs and stores the result.

| Flag | Value | Meaning |
|---|---|---|
| `--environment <ENV>` | name | Re-authenticate every credential in the environment. |
| `--credential <NAME>` | name | Re-authenticate one credential. |

One of the two is required.

### creds get

Fetch a credential from the daemon and print it. This is what generated `credential_process`
lines call. On a terminal, a re-authentication demand runs the login flow and retries once.

| Flag | Value | Meaning |
|---|---|---|
| `--environment <ENV>` | name | Alone: the environment's first credential. With `--credential`: the authorization context. |
| `--credential <NAME>` | name | Credential to fetch. Alone, resolves only if an environment has the same name. |
| `--format <FORMAT>` | `credential-process`, `shell`, `fish`, `powershell` | Default: raw JSON. Shell formats export a token credential under a variable derived from `--credential` (upper-cased, with `.`, `-`, and `_` folded to `_`), derived from `--credential`, or from the environment's default credential when `--credential` is omitted. Session credentials export fixed `AWS_*` names. |
| `--agentic` | | Declares an agentic caller. The daemon adds agent treatment in its audit trail; the claim can only add restriction. |

```
creds get --environment work --format credential-process
```

### creds list

List each configured credential once, with its source type (MODE) and session status. A
credential shared by several environments appears once. `--format json` prints a flat array of
`{ "name", "mode", "status" }` objects.

| Flag | Value | Meaning |
|---|---|---|
| `--format <FORMAT>` | `text`, `json` | Default `text`. |

### creds remove

Remove an environment, or a credential and its sealed data. Prompts for confirmation, then
needs approval: Touch ID, or `sudo creds request approve <id>`.

| Flag | Value | Meaning |
|---|---|---|
| `--environment <ENV>` | name | Remove the environment. Its credentials stay. |
| `--credential <NAME>` | name | Remove the credential and its sealed data. Refused while an environment references it. |
| `--force` | | Skip the confirmation prompt. |

One of `--environment`, `--credential` is required. Remove a credential's environments before
the credential itself.

### creds revalidate

Re-seal `config.toml` and `credentials.toml` after editing them by hand. Shows the full contents
of every file that has drifted from its sealed snapshot, then needs approval: Touch ID, or
`sudo creds request approve <id>`. A file that has not drifted is named as unchanged and left
alone. With nothing drifted, it reports so and asks for nothing.

Takes no flags. A snapshot covers its whole file, so revalidation covers every drifted file in
your caller root at once.

### creds config

Read and change an environment's settings in `config.toml`. Keys are listed in
[configuration](configuration.md#configtoml).

### creds config path

Print the path of this user's `config.toml` (`<data dir>/callers/<uid>/config.toml`). Needs
no daemon. Under a system install the file is owned by the `credsd` account and is not
readable by the user; change it with `creds config set`.

### creds config set

Set a key. The value is validated against the key's type.

```
creds config set <KEY> <VALUE> --environment <ENV>
```

| Flag | Value | Meaning |
|---|---|---|
| `--environment <ENV>` | name | Required. |

```
creds config set sdk.retry_mode adaptive --environment work
```

### creds config get

Print a key's value. An unset key prints nothing and exits 1.

```
creds config get <KEY> --environment <ENV>
```

| Flag | Value | Meaning |
|---|---|---|
| `--environment <ENV>` | name | Required. |

### creds config unset

Remove a key, reverting to its default.

```
creds config unset <KEY> --environment <ENV>
```

| Flag | Value | Meaning |
|---|---|---|
| `--environment <ENV>` | name | Required. |

### creds config keys

List the settable keys with type and description. Needs no daemon.

| Flag | Value | Meaning |
|---|---|---|
| `--format <FORMAT>` | `text`, `json` | Default `text`. |

### creds import

Import credentials from an external store. The source is only read.

### creds import aws-profiles

Import static-key profiles from the AWS shared-credentials file. Each profile with
`aws_access_key_id` and `aws_secret_access_key` becomes an `aws-iam-user` credential in a
same-named environment. SSO and `credential_process` profiles are skipped.

| Flag | Value | Meaning |
|---|---|---|
| `--from <PATH>` | file | Default `$AWS_SHARED_CREDENTIALS_FILE`, then `~/.aws/credentials`. |
| `--region <REGION>` | region | Needed for profiles that name no region. Order: the profile's `region` in the credentials file, `--region`, `AWS_REGION`, `AWS_DEFAULT_REGION`, then `region` in the profile's section of `~/.aws/config` (`AWS_CONFIG_FILE`). A profile that resolves none is skipped. |
| `--dry-run` | | List what would be imported; write nothing. |

### creds request

Manage pending presence-gate requests.

### creds request list

List pending requests: yours, or every uid's under `sudo`. No flags.

### creds request approve

Approve a pending request. Run as the request's owner, it signs with your presence key (Touch ID)
if one is enrolled and the request accepts it. Run under `sudo`, it shows who raised the request
and asks for confirmation. Enrollments accept only `sudo`. What is gated, and why:
[presence and sudo approval](../presence.md).

```
creds request approve <ID>
```

### creds request withdraw

Withdraw a pending request. Owner only; nothing is changed.

```
creds request withdraw <ID>
```

**Deprecated alias.** `creds approve` is still accepted for backward compatibility but hidden from help. Use `creds request` instead: `creds approve <id>` → `creds request approve <id>`; `creds approve --list` → `creds request list`; `creds approve --withdraw <id>` → `creds request withdraw <id>`.

### creds presence

Manage the presence key that approves gated operations with Touch ID. macOS builds with the
`secure-enclave` feature only. The key is kept in `~/.credsd/`.

### creds presence enroll

Create a presence key in the Secure Enclave and request its enrollment. The enrollment is a
pending request that only `sudo creds request approve <id>` satisfies. Check that the approval shows the same
fingerprint. An enrolled key is replaced only when its replacement is approved.

| Flag | Value | Meaning |
|---|---|---|
| `--policy <POLICY>` | `biometry`, `presence` | `biometry` (default): Touch ID only, invalidated if fingerprints change. `presence`: Touch ID or the device passcode. |

### creds presence revoke

Revoke this uid's presence key. Gated operations then need `sudo creds request approve <id>`. No flags.

### creds presence status

Show this uid's enrolled presence key, and whether this client holds it. No flags.

## credsd

### credsd

Daemon and service installer. Global flags, accepted before or after the subcommand:

| Flag | Value | Meaning |
|---|---|---|
| `--storage-backend <NAME>` | backend | Where the master key is held: `data-protection-keychain`, `secure-enclave`, `tpm`, `kkrs`, `file`, `dpapi`, `credential-manager`, as compiled into this build (`credsd --version`). Required by `serve` and `init`; optional for `install`. See [key security](../key-security.md). |
| `--config-dir <PATH>` | path | Sets `CREDSD_CONFIG_DIR` for this invocation. |
| `--quiet`, `-q` | | Log level `error`. Conflicts with `--verbose`. |
| `--verbose`, `-v` | | Log level `debug`. |
| `--log-file <PATH>` | path | Append logs to this file. |
| `--log-format <FORMAT>` | `text`, `json` | Log format. |

`credsd install` is the only subcommand that resolves a backend when the flag is absent:
`credsd install --user` resolves `data-protection-keychain`, a macOS `sudo credsd install`
picks `secure-enclave` and never considers the keychain (a LaunchDaemon has no login session
to reach it), and Linux picks `tpm` when the build has the feature and `/dev/tpmrm0` exists.
There is no Windows install yet; when there is, it would resolve `dpapi`. With nothing
hardware-backed available, `install` fails rather than falling back, and a backend must be
named.

`credsd serve` and `credsd init` do not resolve one. Both exit with an error when the flag is
absent; the installed service passes the backend `install` baked into its definition.

### credsd serve

Run the daemon in the foreground on its Unix socket until stopped. Refuses to run as root.
The installed service runs this; running it by hand as your own uid is unsupported.

| Flag | Value | Meaning |
|---|---|---|
| `--insecure-backend` | | Allow the `file` backend, whose key file any process of the daemon's uid can read. |
| `--system` | | Require running as the `credsd` service account. Set by `credsd install`. |

### credsd install

Install the daemon as a service. Without `--user`: a system service running as the `credsd`
account (LaunchDaemon on macOS, systemd unit on Linux). Requires root. `--storage-backend`
and `--log-file` are written into the service definition; the default log file is
`/Library/Logs/credsd/credsd.log` (macOS) or `/var/log/credsd/credsd.log` (Linux). On Linux
with the `tpm` backend, the unit gets `SupplementaryGroups=tss` when the `tss` group exists.
See [install](../install.md).

| Flag | Value | Meaning |
|---|---|---|
| `--user` | | macOS, official signed release only: install a LaunchAgent running as your uid. Refused on Linux, and under `sudo`. Accepts `data-protection-keychain` and nothing else — every other backend is refused, because it is the only keystore a service running as its own caller's uid can hold a key in. Omit `--storage-backend` and it resolves that one. |
| `--skip-security-warning` | | Skip the interactive confirmation `--user` shows. |

```
sudo credsd install
```

### credsd uninstall

Remove the service. Leaves configuration and credentials in place. Requires root without
`--user`.

| Flag | Value | Meaning |
|---|---|---|
| `--user` | | macOS only: remove the user-scoped LaunchAgent. Refused on Linux. |
| `--purge-key` | | Also delete the master encryption key from the keystore named by `--storage-backend`. Asks for a typed `yes` on `/dev/tty`. |

`--purge-key` requires `--storage-backend`: the key worth deleting is usually the one an
install is switching away from, so it is never inferred. The sealed credentials are moved
to `<data-dir>/quarantine` first and cannot be decrypted afterwards — each environment has
to be re-imported with `creds bootstrap --env <env>`. It runs whether or not a service was
installed, so a key left behind by an aborted install can still be removed, and it is
refused while a credsd service is still running.

The keystore has to be one the invoking user can reach. A user install's data protection
keychain item belongs to your login session, so purge it as yourself; a system install's
key belongs to the service account, so purge it under `sudo`.

A system install is the only shape with a backend to switch to, since a user install accepts
`data-protection-keychain` alone:

```bash
# switch a Linux system install from the file backend to the TPM.
# Install a -tpm artifact's binaries first; a build without the feature cannot select tpm.
sudo credsd uninstall --purge-key --storage-backend file
sudo credsd install --storage-backend tpm
```

For a user install, purging is how you discard the keychain key and start over:

```bash
credsd uninstall --user --purge-key --storage-backend data-protection-keychain
credsd install --user
```

### credsd init

Initialize the keystore for the selected storage backend — mint the master encryption key
and store it in the backend. Run once after `credsd install` before starting the daemon.
`credsd init` is idempotent: if the key already exists it loads it without re-minting.
`sudo credsd install` runs this automatically as part of the install flow.

For KKRS (`--storage-backend kkrs`, only in builds with the `kkrs` feature), `credsd serve`
handles first startup directly; `credsd init` is not required and is a no-op. KKRS reboot
recovery also happens automatically in `serve`.

| Flag | Meaning |
|---|---|
| `--storage-backend <b>` | Required. Backend to initialize. |
| `--reset` | Keystore reset after hardware key loss (TPM, Linux only). See below. |

#### credsd init --reset

Recover from a TPM key loss on Linux. First confirms the existing key is actually unreadable
— if the key can still be retrieved, it refuses: the key is intact and no reset is needed.
Then prompts for a typed confirmation on `/dev/tty` (cannot be scripted or pasted),
quarantines the now-unrecoverable blobs, and mints a fresh key.

Use after a TPM reset, PCR 7 policy violation (firmware or Secure Boot change), or other
event that makes the TPM-sealed key unreadable. `serve` will have told you to run this.

All cached credentials require re-authentication afterward. The quarantined blobs are moved
to `<data_dir>/quarantine/` — they were already unrecoverable before reset ran.

`--storage-backend tpm` required. Linux only. This is a keystore reset (key lost, blobs
abandoned), not a rotation (re-encrypt blobs) or rewrap (re-seal same key). If run as root,
the new key files are automatically chowned to the service user.

### credsd status

Report whether the service is installed and running, its binary, and its arguments.

| Flag | Value | Meaning |
|---|---|---|
| `--format <FORMAT>` | `text`, `json` | Default `text`. Any other value prints text. |

## Exit codes

| Code | Binary | Meaning |
|---|---|---|
| 0 | both | Success. |
| 1 | both | Error; the message is on stderr. Also `creds config get` on an unset key, with no output. |
| 2 | both | Usage error from argument parsing. `credsd` also exits 2 when started with no arguments and no terminal (a Finder launch of the macOS app bundle). |

Exit codes may change during the preview.
