# Design: User Documentation

The documentation set is nine documents. Each has one primary audience, a fixed section
outline, and a named source of truth.

## Document map

| Document | Primary audience | Role |
|---|---|---|
| `README.md` | Evaluator | Orientation and routing |
| `docs/overview.md` | Evaluator, security reviewer | What credsd is and is not, its layers, and how it compares |
| `docs/getting-started.md` | User | Install-to-credentials walkthrough, per install shape |
| `docs/install.md` | Operator | Install shapes and their consequences for key custody |
| `docs/key-security.md` | Security reviewer, operator | Storage backends, custody, threat model, recovery |
| `docs/presence.md` | User, security reviewer | Which operations need approval, how to approve them, and what approval guarantees |
| `docs/reference/commands.md` | User, operator | Every `creds` and `credsd` subcommand and flag |
| `docs/reference/api.md` | Integrator | JSON-RPC methods, shapes, error codes |
| `docs/reference/configuration.md` | Operator | `config.toml`, `credentials.toml`, environment variables, data-directory layout |

## Maturity notice

### Text

> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path.

### Mechanism

The canonical text lives in `README.md` between marker comments:

```
<!-- maturity-notice -->
> **Pre-release preview.** …
<!-- /maturity-notice -->
```

Every other document in the set carries the same block, markers included, as its first content.
A test in the `creds` crate reads `README.md` and each document under `docs/` (excluding
`docs/specs/` and `docs/design/`) relative to `CARGO_MANIFEST_DIR`, extracts the marked block,
and fails when a document has none or its block differs byte-for-byte from the README's
(Requirements 1.4, 1.5). Markers make the check a string comparison and keep the block
invisible in rendered Markdown apart from the notice itself.

## Outlines

### `README.md`

1. Maturity notice
2. What credsd is — one paragraph: what it is, who it is for, the security premise (a daemon
   holds credentials and vends short-lived material; the client never opens the keystore)
   — then one paragraph on what it is not: not a general-purpose secret store, what it does
   beyond holding secrets, linking to `docs/overview.md`
3. The two binaries — `creds` (client) and `credsd` (daemon), with their subcommands
4. Choose your path — one line per audience, linking to the document that serves it
5. Platform support — install shapes per platform, linking to `docs/install.md`
6. License

**Source of truth:** `crates/credsd/src/main.rs` and `crates/credsd-daemon/src/main.rs` for
binary and subcommand names; `docs/install.md` for shapes.

### `docs/overview.md`

1. Maturity notice
2. The premise — why secrets readable by your uid are exposed, and the boundary credsd puts
   between them and your processes, per install shape
3. What credsd does — the five layers in one table (vaulting, credential exchange, environment
   definitions, credential projection, lightweight authorization), then one subsection each
4. What credsd is not — a general-purpose secret store, an authorization system for the
   credentials' issuer, a sandbox, protection from root
5. How it compares — one paragraph per category: general-purpose secret stores, cloud secret
   managers, password managers, AWS credential helpers, OS keystores
6. Next — links to getting started, install, key security, and presence

**Source of truth:** `crates/credsd-core/src/config/credentials.rs` (credential types and what
each exchanges), `crates/credsd-core/src/projection.rs` (projection types and defaults),
`crates/credsd-daemon/src/server/` (authorization), `docs/specs/presence-gated-operations`.

### `docs/getting-started.md`

1. Maturity notice
2. Which path is yours — a short decision: platform, then official signed release or
   open-source build
3. Path A: macOS, official signed release — user-scoped install
4. Path B: macOS, open-source build — system install
5. Path C: Linux — system install
6. Bootstrap a credential — `creds bootstrap`, one SSO and one IAM-user example
7. Get credentials into a process — `creds get`, as a `credential_process` line and
   evaluated into a shell
8. Next steps — links to install, key security, and the reference pages

**Source of truth:** `crates/credsd/src/main.rs` (client commands),
`crates/credsd-daemon/src/install.rs` (install behavior per shape).

### `docs/install.md`

1. Maturity notice
2. Install shapes at a glance — table of shape, platform and build, service manager, account
   the daemon runs as, resolved backend
3. macOS user-scoped install — official signed release only; LaunchAgent; data protection
   keychain under the daemon's access group
4. macOS system install — LaunchDaemon as the `credsd` service account; `secure-enclave`
5. Linux system install — systemd unit and socket as `credsd`; `tpm`, with access through the
   `tss` group
6. Windows — install shapes not yet decided
7. Why a user-scoped install is limited to the signed release (Requirement 6.2)
8. Running the daemon yourself — `credsd serve` as your own uid, and what that gives up
9. Status, upgrade, and uninstall — `credsd status`, re-running `install`, `credsd uninstall`

**Source of truth:** `crates/credsd-daemon/src/install.rs`;
`docs/specs/presence-gated-operations` Requirement 7; `docs/specs/mac-pkg-installation`.

### `docs/key-security.md`

1. Maturity notice
2. Your install, your posture — the shape-to-posture summary, linking to `docs/install.md`
3. Storage backends — one subsection per backend: `data-protection-keychain`,
   `secure-enclave`, `tpm`, `kkrs`, `dpapi`, `credential-manager`, `file`.
   Each states where the master key is held, who can read or replace it, what it does and
   does not protect against, and which builds compile it
4. How a backend is chosen — `--storage-backend` or auto-detect; auto-detect order per
   platform; the error when no hardware-backed backend is found
5. Changing backend — what happens to the existing master key and sealed credentials
6. What an attacker would need — per shape
7. If you lose the machine
8. When credsd refuses to start — causes and remedies
9. What you can tell your security reviewer

**Source of truth:** `crates/credsd-core/src/storage/mod.rs` (`Backend`, `auto_detect`,
`select_backend`), `crates/credsd-core/src/storage/*.rs` (per-backend custody),
`crates/credsd-core/src/encryption.rs` (key initialization).

### `docs/presence.md`

1. Maturity notice
2. Why your uid is not enough — the same-uid process, and why changes differ from reads
3. What needs approval — the built-in gate, by `creds` command
4. How an approval works — pending request, challenge, expiry, discard on a changed base state;
   bootstrap and import approved for one re-send
5. Approving with sudo — what the approver sees, root supplies presence not identity, no
   headless bypass
6. Approving with Touch ID — enrollment and why it needs `sudo`, policies, status and revoke,
   where the key lives
7. Managing pending requests — list and withdraw
8. For other clients — `APPROVAL_REQUIRED` and `APPROVAL_REFUSED`
9. What approval does and does not guarantee

**Source of truth:** `crates/credsd-daemon/src/server/presence.rs` (gate, expiry, verifiers),
`crates/credsd/src/presence.rs` (client prompts and messages),
`docs/specs/presence-gated-operations`.

### `docs/reference/commands.md`

1. Maturity notice
2. `creds` — one section per subcommand: `bootstrap` (with its provider subcommands), `login`,
   `get`, `list`, `remove`, `config` (`path`, `set`, `get`, `unset`, `keys`), `import`,
   `request`, `presence`. Each lists synopsis, flags, and an example
3. `credsd` — `serve`, `init`, `install`, `uninstall`, `status`, and global flags
4. Exit codes

**Source of truth:** the clap definitions in `crates/credsd/src/main.rs` and
`crates/credsd-daemon/src/main.rs`.

**Check (Requirement 3.2):** each command has a `### <path>` section (`### creds`,
`### creds bootstrap aws-sso`), the root section carrying the global flags, and documents its
flags as table rows beginning `` | `--flag ``. A test in each binary crate walks
`Cli::command()` — clap's `CommandFactory`, already available from the derive — and fails when
a command has no section, a long flag is missing from its section, a table row names a flag the
command and root do not define, or a section names no command. The comparison lives in one
test-only module, `crates/credsd/src/command_reference.rs`, which the `credsd` crate includes
by path. No new dependency.

### `docs/reference/api.md`

1. Maturity notice
2. Transport — the Unix socket (and named pipe), socket location order, peer-uid
   authorization
3. Envelope — JSON-RPC 2.0 framing, notifications used by interactive bootstrap
4. Methods — one section per wire method: `credential/get`, `credential/get_batch`,
   `credential/list`, `credential/remove`, `environment/describe`, `environment/bootstrap`,
   `environment/bootstrap/respond`, `environment/login`, `environment/import`,
   `environment/remove`, `config/get`, `config/set`, `config/unset`, `system/health`,
   `request/get`, `request/list`, `request/approve`, `request/withdraw`, `presence/enroll`,
   `presence/revoke`, `presence/status`; which methods are gated, and how approval completes
   them
5. Errors — the application error code and each `data.code`: `ENVIRONMENT_NOT_FOUND`,
   `REAUTH_REQUIRED`, `WRONG_CREDENTIAL_TYPE`, `PROVIDER_UNAVAILABLE`, `INTERNAL`,
   `AUTH_TIMEOUT`, `AUTH_CANCELLED`, `APPROVAL_REQUIRED`, `APPROVAL_REFUSED`,
   `REQUEST_NOT_FOUND`, with the remediation each carries

**Source of truth:** `crates/credsd-core/src/rpc/methods.rs` and
`crates/credsd-core/src/presence.rs` (method names and shapes),
`crates/credsd-core/src/rpc/mod.rs` (`DomainCode`), `docs/specs/credential-retrieval-api`,
`docs/specs/presence-gated-operations`.

### `docs/reference/configuration.md`

1. Maturity notice
2. Files and where they live — `config.toml`, `credentials.toml`, sealed material under
   `credentials/<name>/`, and the data-directory layout for each install shape
3. `config.toml` — environments, credential membership and order, `identity_type`, and every
   `sdk.*` and `cli.*` key with its type and effect
4. `credentials.toml` — one section per source type (`aws-sso`, `aws-iam-user`,
   `aws-roles-anywhere`, `aws-web-identity`, `aws-login`, `jwt`, `oauth`, `static-secret`, `jwt-bearer`) and its
   fields; secrets are never in this file
5. Environment variables — `CREDSD_DATA_DIR`, `CREDSD_CONFIG_DIR`, `CREDSD_SOCKET`,
   `CREDSD_LOG_FILE`, `CREDSD_LOG_FORMAT`, `CREDSD_LOG_LEVEL`, `CREDSD_SE_PROTECTION`,
   `CREDSD_TPM_POLICY`, `CREDSD_TOKEN`, `CREDSD_ALLOW_HTTP`: what each does and which binary
   reads it

**Source of truth:** `crates/credsd-core/src/config/keys.rs` (`ConfigKeyDef` table),
`crates/credsd-core/src/config/credentials.rs` (`CredentialSource`),
`crates/credsd-core/src/config/platform.rs` (paths), and each `std::env::var` call site for
variables.

## Decisions

### 1. Organized by reader and install shape

A feature-organized set puts the commands a reader needs next to commands that do not apply to
their install shape, and the posture a page describes is the posture of whichever shape its
author had in mind. One walkthrough per shape keeps each path's commands and posture
consistent.

### 2. Reference pages are checked, not generated

Generating Markdown from clap would add a dependency and produce pages without examples or
explanation. A completeness check over the clap tree keeps hand-written pages exhaustive at the
cost of one test per binary.

### 3. One canonical maturity notice

A notice paraphrased per document drifts, and a reader who lands on any page — from a search or
a link — sees it first. One text, copied verbatim and checked, changes everywhere at once when
the project's maturity changes.

### 4. `key-security.md` keeps its name

It is already linked from the README and is the page a security reviewer is sent to. Backend
coverage extends it rather than moving to a new page.

## Open questions

- **Maturity notice wording.** The proposed text says interfaces and on-disk formats can change
  without a migration path. Confirm that commitment, and whether the notice should also say
  whether credsd is suitable for production credentials.
- **Exit codes.** Whether exit codes are stable enough to document as part of the command
  reference during the preview.
