# Architecture

## Overview

credsd is a cross-platform daemon that vends short-lived AWS credentials via a
local HTTP endpoint. It holds long-lived secrets (SSO tokens, IAM keys) in
platform-specific secure storage, exchanges them for temporary session
credentials, and serves those credentials to local processes using the ECS
container credentials protocol.

## Module Map

```
src/
├── main.rs              CLI (clap) + subcommand dispatch
├── lib.rs               Public module declarations
├── error.rs             DaemonError enum + Result alias
├── config/
│   ├── mod.rs           DaemonConfig, EnvConfig, serialization
│   └── platform.rs      Platform-specific paths (config dir, data dir)
├── credentials.rs       Credential data model (session creds, expiry)
├── encryption.rs        AES-256-GCM envelope encryption (EncryptionService)
├── storage/
│   ├── mod.rs           SecureStorage trait + backend selection
│   ├── macos.rs         macOS Keychain backend
│   ├── windows.rs       Windows Credential Manager backend (deferred, untested)
│   └── file.rs          Plaintext file fallback (CI, dev)
├── providers/
│   ├── mod.rs           CredentialProvider trait
│   └── sso.rs           AWS SSO (IAM Identity Center) provider
├── credential_store.rs  In-memory cache + background refresh
├── credential_resolve.rs  Fetch creds from daemon or provider directly
├── credential_env.rs    Env var assembly for child processes
├── auth.rs              Bearer token generation + persistence
├── bootstrap.rs         Interactive env setup (SSO device auth flow)
├── get.rs               Output formatting (credential_process, shell, fish)
└── server/
    ├── mod.rs           Axum app setup, AppState
    ├── routes.rs        HTTP handlers (ECS credential endpoint)
    ├── middleware.rs    Bearer token auth middleware
    └── response.rs      Credential JSON response types
```

## Data Flow

```
credsd bootstrap ──► SSO device auth ──► encrypted token on disk
                                            │
credsd serve ──► loads config + token ──► starts HTTP on 127.0.0.1:PORT
                                            │
AWS CLI/SDK ──► GET /credentials ──► bearer auth ──► decrypt token
               (container creds URI)                     │
                                               STS GetRoleCredentials
                                                         │
                                               ◄── session credentials
```

## Platform Support

| Platform | Secure Storage | Service Manager |
|----------|---------------|-----------------|
| macOS (aarch64, x86_64) | Keychain (`security-framework`) | launchd |
| Linux (x86_64, aarch64) | TPM 2.0; `file` only if explicitly requested | systemd |
| Windows (x86_64) | Credential Manager / DPAPI (Win32 API) — deferred | none |

**Windows is deferred.** The storage backends exist as code and are gated behind
`#[cfg(target_os = "windows")]`, but there is no Windows CI row, so the round-trip tests in
`storage/windows.rs` and `storage/dpapi.rs` never execute anywhere; nothing about the backends
is verified. There is no service-manager path either — `install.rs` covers launchd and systemd
only. And `serve` has no Windows transport: a Named Pipe with a user-restricted ACL is the
equivalent boundary to the Unix socket, and it is not implemented, which (given that the daemon
is the only credential source) takes `run`, `get`, `exec`, and `import` with it. The code stays in the
tree for now.

## Key Design Decisions

**ECS container credentials protocol**: The daemon implements the same HTTP
protocol that ECS uses to vend credentials to containers. This means any AWS
SDK works out of the box — just set `AWS_CONTAINER_CREDENTIALS_FULL_URI` and
`AWS_CONTAINER_AUTHORIZATION_TOKEN`.

**Encryption at rest**: SSO tokens are encrypted with AES-256-GCM using a key
stored in platform secure storage. The encryption key never touches disk in
plaintext (on macOS; the Windows backends intend the same but are deferred and
unverified). The `file` backend stores the key as a plaintext file for
environments without OS credential stores.

**Single-binary deployment**: No runtime dependencies beyond the OS. TLS uses
`rustls` (compiled in), not OpenSSL. The release binary is statically linked
where possible.

**The daemon is the only credential source**: `credsd run` and `credsd get` both
require a running `credsd serve`. There is no direct-from-provider mode. The
daemon is where a request is assessed, classified, and audited, so a path around
it would make that record optional — and, once caller verification enforces
rather than observes, would turn a denial into a success.

## Dependencies

Core: tokio, axum, clap, serde, ring, zeroize, tracing
AWS: aws-config, aws-sdk-sso, aws-sdk-ssooidc (all with rustls)
Platform: security-framework (macOS), windows (Windows — deferred, built by no CI row)
