<!-- maturity-notice -->
> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path. The on-disk layout may change without a migration. Windows is for
> ease of use only: there is no process-tree assessment, and `serve` does not run there yet.
<!-- /maturity-notice -->

# AWS Credential Daemon (credsd)

AWS Credential Daemon (credsd) is a local background service that vaults, refreshes, and vends
short-term credentials, eliminating plaintext keys and cached session tokens from disk.
Developers and local AI agents get uninterrupted, low-friction access to AWS APIs and external
services, while security teams set permission ceilings per host and maintain clear audit trails.

credsd works with the AWS CLI, AWS SDKs, and existing authentication workflows including IAM
Identity Center (SSO), `aws login`, and IAM Roles Anywhere. Instead of sharing static credential
files or broad session tokens across local tools, the daemon seals long-lived secrets under a
master key in a hardware-backed keystore and vends short-lived credentials from memory.

## Key benefits

- **Developers move fast without token interruptions.** Eliminate expired-session errors and the
  daily re-authentication loop. credsd refreshes short-lived credentials in the background,
  keeping local CLI workflows and coding agents running without anyone managing cache files, and
  prompts for re-authentication only when an underlying session reaches its maximum lifetime.

- **Keep credentials off disk.** Replace plaintext long-term keys and cached session tokens with
  encrypted files sealed under a master key in the Secure Enclave, a TPM 2.0, or the macOS data
  protection keychain, while caching only short-lived credentials in memory. What a process
  receives is a session that expires, never the key that minted it.

- **Works with your existing AWS authentication and audit tools.** Keep the authentication
  methods and observability workflows you rely on. credsd logs the kernel-verified process tree —
  uid, pid, executable path — for every credential request, and uses heuristic matching to tag
  known agent harnesses in local logs. Local process classification is best-effort telemetry. To
  distinguish an AI agent's actions from a developer's in AWS CloudTrail, and to enforce least
  privilege, provision a dedicated credential and IAM role for the agent.

credsd is not a general-purpose secret store: it has no API for applications to store and read
arbitrary values, and everything it holds belongs to one user on one machine. What it does beyond
holding secrets — exchanging credentials, composing environments, projecting each credential into
the form its consumer reads, gating changes on approval, and the planned permission ceiling — is
described in the [overview](docs/overview.md).

## The two binaries

| Binary | Role | Subcommands |
|---|---|---|
| `creds` | Client | `bootstrap`, `login`, `get`, `list`, `remove`, `revalidate`, `config`, `import`, `request`, `presence` |
| `credsd` | Daemon | `serve`, `init`, `install`, `uninstall`, `status` |

## Choose your path

- **Evaluating credsd:** [Overview](docs/overview.md), then [Key security](docs/key-security.md).
- **Setting it up:** [Getting started](docs/getting-started.md).
- **Choosing an install shape:** [Install](docs/install.md).
- **Approving a change:** [Presence and sudo approval](docs/presence.md).
- **Every command and flag:** [Command reference](docs/reference/commands.md).
- **Files, keys, and environment variables:** [Configuration reference](docs/reference/configuration.md).
- **Talking to the socket directly:** [API reference](docs/reference/api.md).
- **Reviewing custody and threat model:** [Key security](docs/key-security.md).

## Platform support

| Platform | Install shape | Storage backend |
|---|---|---|
| macOS, official signed release (`credsd-macos-aarch64.pkg`) | User-scoped (LaunchAgent), `credsd install --user` | `data-protection-keychain` |
| macOS, built from source | System (LaunchDaemon), `sudo credsd install` | `secure-enclave` |
| Linux | System (systemd) | `tpm` |
| Windows | On the roadmap for H1 2027 | — |

Windows is on the roadmap for H1 2027: the storage backends exist in the code, and the service
transport and install shape are still being designed.

See [Install](docs/install.md) for what each shape protects.

## License

Apache-2.0
