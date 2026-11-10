<!-- maturity-notice -->
> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path. The on-disk layout may change without a migration. Windows is for
> ease of use only: there is no process-tree assessment, and `serve` does not run there yet.
<!-- /maturity-notice -->

# credsd

credsd is a local credential daemon for developers and for the agents and tools they run. It
holds long-lived secrets — SSO sessions, IAM user keys, Roles Anywhere private keys, OAuth and
bearer tokens — sealed under a master key in a hardware or OS keystore, and vends short-lived
material to processes on request. The daemon is the only process that opens the keystore;
the client asks it over a Unix socket, the daemon authorizes the caller by kernel-verified
peer uid, and every request is assessed and audited there.

credsd is not a general-purpose secret store like HashiCorp Vault, and not a password manager.
Holding secrets is one part of what it does. It also exchanges them for short-lived
credentials, groups credentials into named environments, delivers each one in the form its
consumer reads, and requires a Touch ID or `sudo` approval before anything changes them.
Everything it holds belongs to one user on one machine. See the [overview](docs/overview.md).

## The two binaries

| Binary | Role | Subcommands |
|---|---|---|
| `creds` | Client | `bootstrap`, `login`, `get`, `list`, `remove`, `config`, `import`, `request`, `presence` |
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
| macOS, official signed release (not yet published) | User-scoped (LaunchAgent), `credsd install --user` | `data-protection-keychain` |
| macOS, built from source | System (LaunchDaemon), `sudo credsd install` | `secure-enclave` |
| Linux | System (systemd) | `tpm` |
| Windows | Not yet decided | — |

See [Install](docs/install.md) for what each shape protects.

## License

Apache-2.0
