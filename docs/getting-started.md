<!-- maturity-notice -->
> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path. The on-disk layout may change without a migration. Windows is for
> ease of use only: there is no process-tree assessment, and `serve` does not run there yet.
<!-- /maturity-notice -->

# Getting started

## Which path is yours

| Platform | Build | Path |
|---|---|---|
| macOS (Apple Silicon) | Official signed release (`credsd-macos-aarch64.pkg`) | [A: user-scoped install](#path-a-macos-official-signed-release) |
| macOS | Built from this repository | [B: system install](#path-b-macos-open-source-build) |
| Linux | Any | [C: system install](#path-c-linux) |

Windows install shapes are not yet decided. [Install](install.md) explains what each shape
protects.

## Path A: macOS, official signed release

Signed and notarized, Apple Silicon only — the installer refuses to run on an Intel Mac.
Download it from [Releases](https://github.com/aws/credential-daemon/releases) and verify
the detached signature against the public key in [`KEYS`](../KEYS):

```bash
base=https://github.com/aws/credential-daemon/releases/latest/download
curl -fLO "$base/credsd-macos-aarch64.pkg"
curl -fLO "$base/credsd-macos-aarch64.pkg.sig"
curl -fsSL https://raw.githubusercontent.com/aws/credential-daemon/main/KEYS | gpg --import
gpg --verify credsd-macos-aarch64.pkg.sig credsd-macos-aarch64.pkg
```

The package carries `Credsd.app` with both binaries inside the bundle, and offers two
destinations:

```bash
# Me only — bundle in ~/Applications, symlinks in ~/.local/bin
installer -pkg credsd-macos-aarch64.pkg -target CurrentUserHomeDirectory

# All users of this Mac — bundle in /Applications, symlinks in /usr/local/bin
sudo installer -pkg credsd-macos-aarch64.pkg -target /
```

The service is user-scoped either way. The installer registers it for the installing
account, or for the console user when the install ran as root, so in a new terminal:

```bash
credsd status
```

A private install also adds `~/.local/bin` to `PATH` in your shell profile when it is not
already there, which is the other reason for the new terminal.

Every other account on a shared install registers its own, once, with `credsd install
--user` — that one does carry a typed security prompt.

## Path B: macOS, open-source build

Needs a Rust toolchain and the Command Line Tools (for the Swift Secure Enclave shim, which the
default feature set builds).

```bash
cargo build --release
sudo install -m 0755 target/release/credsd target/release/creds /usr/local/bin/
sudo credsd install
credsd status
```

## Path C: Linux

Needs a Rust toolchain, `pkg-config`, and the tpm2-tss development libraries, on a host with
`/dev/tpmrm0`.

```bash
cargo build --release --features credsd-core/tpm
sudo install -m 0755 target/release/credsd target/release/creds /usr/local/bin/
sudo credsd install
credsd status
```

## Bootstrap a credential

`creds bootstrap` authenticates once, has the daemon seal the long-lived secret, and verifies
it. `--environment <name>` creates a credential and a same-named env wrapping it. The first
bootstrap from your uid also registers you with the daemon.

**IAM Identity Center (SSO):**

```bash
creds bootstrap --environment work aws-idc-sso \
  --start-url https://myorg.awsapps.com/start \
  --sso-region us-east-1
```

Omit `--account-id` and `--role-name` to choose from the accounts and roles you have.

**IAM user key**, brokered into sessions with `sts:GetSessionToken`:

```bash
creds bootstrap --environment legacy aws-iam-user \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --region us-east-1
```

The secret access key is read with echo disabled, never from an argument; piping it from a
secret manager works. Add `--mfa-serial <arn>` if the account requires MFA.

Confirm with `creds list`. When a session can no longer renew unattended, run
`creds login --environment work`.

## Get credentials into a process

The env is always named on the command line; credsd never infers it from `$AWS_PROFILE`.
`creds get` serves both a tool that reads a `credential_process` line and your own shell:

```bash
# In ~/.aws/config:  credential_process = creds get --environment work --format credential-process
eval "$(creds get --environment work --format shell)"
```

Running a command with credentials delivered for it alone — a generated AWS config, a named
environment variable, or a loopback credential endpoint — is left to run-time tooling built on
the [API](reference/api.md); credsd itself ships `creds get`.

## Next steps

- [Install](install.md) — shapes, paths, upgrade, uninstall
- [Key security](key-security.md) — backends and what they protect
- [Command reference](reference/commands.md)
- [Configuration reference](reference/configuration.md)
- [API reference](reference/api.md)
