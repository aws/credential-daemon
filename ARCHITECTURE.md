# Architecture

What credsd is and what it promises is [docs/overview.md](docs/overview.md). This page is the
contributor's orientation: where the code lives and which document is authoritative for each
part of it.

## Crates

```
crates/
├── credsd-core     shared internals: storage backends, encryption, providers, RPC codec and
│                   the client half of the socket transport, config, projections, presence
│                   types. No server.
├── credsd-daemon   the `credsd` binary: the UDS server, caller assessment, presence
│                   gating, the credential store's background refresh, and `install`.
├── credsd          the `creds` binary: the unprivileged client CLI.
└── credsd-client   the public Rust client library for the socket protocol.
```

Two binaries, and the names do not match their crates: `crates/credsd` builds `creds` and
`crates/credsd-daemon` builds `credsd`. `creds` carries no entitlement and never opens the
keystore; the only key material it holds is the enclave-wrapped presence key in
`~/.credsd/presence-key.json`. It is a client like any other.

Workspace lints in `Cargo.toml` deny `unwrap_used`, `panic`, `indexing_slicing`, and
`arithmetic_side_effects` across every crate. `vendor/` is excluded from the workspace so those
lints do not apply to code we do not own.

## Transport

The daemon serves line-delimited JSON-RPC 2.0 over a Unix domain socket. That socket is the
whole RPC surface — there is no HTTP transport — and it carries no bearer token: the daemon
reads the connecting process's uid from the kernel, so there is no credential to steal. A system
install is socket-activated by launchd or systemd.

The daemon does bind one other listener, and only during a bootstrap or an interactive re-login:
a loopback TCP port for an OAuth authorization-code redirect, opened by an `aws-login` or
`aws-web-identity` flow and closed with it (`providers/oauth/callback.rs`, reached from
`server/bootstrap.rs`). A TCP port has no uid boundary, so what gates the exchange is PKCE and
the `state` parameter rather than the port. The `credential-endpoint` projection in
[docs/overview.md](docs/overview.md) is a third thing again: an address run-time tooling fills,
not a listener the daemon opens.

The contract is [`docs/api/openrpc.json`](docs/api/openrpc.json), described in
[docs/reference/api.md](docs/reference/api.md). Where the guide and the contract disagree, the
contract is correct.

## Request path

`creds` → socket → `server/uds.rs` (accept, peer credentials, resolve the caller) →
`server/dispatch.rs` (authorize, audit) → `credential_store.rs` (warm cache, background refresh) →
`providers/` (exchange the sealed secret for a session) → response.

The daemon is the only way a CLI invocation obtains credentials. There is no
direct-from-provider fallback, because one would reach the same material without the caller
assessment `serve` performs — see the module comment in `credsd-core/src/credential_resolve.rs`.

Changing a credential or configuration is not on this path. Those operations are held as a
pending request and performed only after a Touch ID signature or a `sudo` approval, from the
record the daemon made rather than from anything a client re-sends. See
[docs/presence.md](docs/presence.md) and `docs/specs/presence-gated-operations/`.

## Key custody

Every secret is sealed with AES-256-GCM under one master key, and the storage backend decides
who can open that key. The backends live in `credsd-core/src/storage/`; which one an install
resolves, what each protects, and what an attacker would need are in
[docs/key-security.md](docs/key-security.md) and `docs/design/key-storage-backends.md`.

## Platforms

| Platform | Backends shipped | Service |
|---|---|---|
| macOS, signed release (Apple Silicon) | `data-protection-keychain` | launchd LaunchAgent |
| macOS, built from source | `data-protection-keychain` (compiled, unusable), `secure-enclave`, and `file` with the `file` feature | launchd LaunchDaemon |
| Linux (x86_64, aarch64) | `tpm` with the `tpm` feature, `file` | systemd service + socket |
| Windows | `dpapi`, `credential-manager` — deferred | none |

`data-protection-keychain` compiles on every macOS build — the `cfg` is the target, not a
feature — but only the signed release can open it. The access group
`94KV3E626L.com.amazon.aws.credsd.daemon` is authorized by the release's provisioning profile,
so a build with no Apple signing identity carries no such entitlement and its availability
probe fails. `credsd install --user` then resolves something else and is refused, because the
keychain is the only keystore a service running as its own caller's uid may hold a key in. From
source the usable set is `secure-enclave` and, with the feature, `file`. The signed release is
the inverse: it drops `secure-enclave` so that `sudo credsd install` cannot resolve a backend a
LaunchAgent-only artifact would never reach.

**Windows is deferred.** The storage backends compile behind `#[cfg(target_os = "windows")]`,
but no CI row builds them, so nothing about them is verified. `serve` has no Windows transport
either, which takes every command that reaches the daemon with it. The code stays in the tree.

[docs/install.md](docs/install.md) covers each shape, and
`docs/design/tpm-linux-artifact.md` covers why Linux ships a second `-tpm` artifact per distro
and architecture.

## Where to read next

- [docs/overview.md](docs/overview.md) — what credsd does and what it is not
- [AGENTS.md](AGENTS.md) — build commands, code style, persisted-format rules
- `.agents/rules/` — the minimalism ladder, how to write a spec, platform one-way doors
- `docs/specs/` — requirements and design per feature; the authority for behavior
