# Agent Guidelines

Instructions for AI coding agents working in this repository.

> **Adapting for your agent.** This file is the agent-neutral source of truth for the
> always-on rules; longer, task-scoped guidance lives in `.agents/` (see below).
> Agent-specific entrypoints (`CLAUDE.md`, `.cursorrules`,
> `.github/copilot-instructions.md`, etc.) are gitignored — point yours at this file
> locally. For agents that read a fixed filename, symlink it:
> `ln -s AGENTS.md CLAUDE.md`. Keep any agent-specific rules or skills local until they
> can be extracted into an agent-neutral, committable form.

## Further Guidance

`.agents/` holds guidance too long or too situational for this file:

- **`.agents/rules/`** — standing rules that apply to every change. `minimalism.md`
  is the decision ladder to descend before writing any code; `spec-voice.md` is how to
  write a spec; `platform-one-way-doors.md` is what to look for in a spec or design that
  would be expensive to reverse if another platform is supported later.
- **`.agents/skills/`** — task-scoped procedures invoked on demand:
  `security-review` (pre-PR diff review and whole-system audit) and `audit-specs`
  (requirements-to-code drift). See `.agents/README.md` for wiring them into your
  harness.

Not every skill a maintainer runs is in there — ones that automate a personal workflow or
need account-specific access stay local and uncommitted.

## Build Commands

```bash
cargo fmt              # format code (required before commit)
cargo clippy -- -D warnings   # lint (must pass with zero warnings)
cargo test             # run all tests (must pass)
cargo build            # verify compilation
```

Always run fmt, clippy, and test before committing. The pre-commit hook enforces fmt and clippy; tests run in CI.

## Coverage

Coverage needs two separate pieces, which is why it is not configured in one place:

| Piece | What it is | Comes from |
|---|---|---|
| `llvm-tools-preview` | rustup component (the profdata tooling) | `rust-toolchain.toml` — automatic |
| `cargo-llvm-cov` | a standalone cargo subcommand binary | `cargo install` — one-time, per machine |

It is **not** a Cargo dependency and never appears in `Cargo.toml`. There is no rustup
component for it, so the toolchain file cannot supply it.

```bash
cargo install cargo-llvm-cov --locked   # one-time setup
cargo llvm-cov --summary-only           # per-file table, printed to stdout
cargo llvm-cov --html --open            # annotated source; writes target/llvm-cov/html/
```

To render several views without re-running the suite, instrument once then report:

```bash
cargo llvm-cov --no-report              # run tests, keep the profile data
cargo llvm-cov report --summary-only    # then as many report forms as you like
cargo llvm-cov report --html --open
```

Read the **region** column, not lines: it counts match arms and `?` early-returns
separately, which is where the classification logic lives. Coverage is not a commit
gate — CI runs it on one row and uploads `target/lcov.info` as an artifact.

Every output form lands under `target/`, so nothing needs its own `.gitignore` entry.
`--lcov` is the one form with no default location, so it takes an explicit
`--output-path target/lcov.info`.

Two things coverage will not tell you. Instrumented builds use their own `RUSTFLAGS`
and a separate `target/llvm-cov-target/` build dir, so they do not share artifacts with
`cargo build` — alternating between the two rebuilds each time, which is expected, not
a broken cache. And `tracing` does not evaluate a log macro's field expressions unless
a subscriber is installed, so audit-record fields read as covered while nothing has
checked them; use the `LogCapture` helper in the `server/mod.rs` tests to assert on
emitted records.

## Toolchain

Pinned in `rust-toolchain.toml`. Do not change the channel without discussion. All formatting decisions come from this version's rustfmt — do not override with local config.

`components` includes `llvm-tools-preview` so `cargo llvm-cov` works after a plain
checkout. Removing it breaks coverage for everyone, including CI, which has no
install step of its own.

## Code Style

- No comments unless explaining a non-obvious WHY (hidden constraint, workaround, surprising behavior)
- No TODO/FIXME in code — track in `private/TODO.md` instead
- Error types: use `DaemonError` variants via the `error.rs` enum. No `anyhow`, no `unwrap()` in library code
- Use `thiserror` derives for new error variants
- Secrets/keys: wrap in types that implement `Zeroize + Drop`. Never log secret values.
- Platform-specific code: gate with `#[cfg(target_os = "...")]`, keep in platform-specific modules (e.g., `storage/macos.rs`)
- Test modules: `#[cfg(test)] mod tests { ... }` at the bottom of each file. Use `proptest` for output-format and serialization properties.

## Persisted Formats

A file's format says who writes it. Pick by writer, not by taste:

| Writer | Format | Examples |
|---|---|---|
| A person, by hand or through the CLI | TOML, mutated with `toml_edit` so comments survive | `config.toml`, `credentials.toml` |
| The daemon alone | JSON plaintext sealed with `EncryptionService::seal_to_file`, named `*.enc` | `sso_token.enc`, `iam_user.enc` |
| A key | a `SecureStorage` slot, never a file the daemon formats | master key |
| The daemon alone, and must not be restorable | a `SecureStorage` slot under `data-protection-keychain`; otherwise a sealed `*.enc` outside every caller root, owned by the service account | enrolled-key registry, integrity record |
| The client alone | JSON plaintext, `0600`, in `~/.credsd/` — never the daemon's data dir | `presence-key.json` |

Do not give daemon-only state a TOML file: it reads as an invitation to hand-edit, and for
state like the enrolled-key registry a hand-edit is the attack. Do not add a plaintext
`.json` for daemon state either; if it is worth persisting, seal it — being public is not a
reason to skip sealing. `ra_public.json` (a Roles Anywhere certificate chain) predates this
rule and is the one existing exception.

The client has no master key, so it cannot seal; what it persists must be safe unsealed, like a
key wrapped by the Secure Enclave. Keep it in `~/.credsd/` even when a user-scoped daemon's data
dir is also under `$HOME`: one writer per directory.

## Project Structure

```
src/
├── main.rs              CLI definition (clap) + subcommand dispatch
├── lib.rs               Public module declarations
├── error.rs             DaemonError enum
├── config/              Configuration parsing, platform paths
├── storage/             SecureStorage trait + platform backends
├── providers/           CredentialProvider trait + implementations (SSO, etc.)
├── server/              HTTP server (axum), routes, middleware
├── credential_store.rs  In-memory cache + background refresh
├── credential_env.rs    Credential variable naming + env-var formatting
├── credential_resolve.rs  Credential fetch strategy (daemon vs standalone)
├── credentials.rs       Credential data model
├── encryption.rs        AES-256-GCM envelope encryption
├── auth.rs              Bearer token generation + validation
├── bootstrap.rs         Interactive credential setup (+ convenience 1-cred env)
└── get.rs               Output formatting (credential_process, shell, etc.)
```

## Commit Style

Conventional commits: `type: short description`

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `style`, `chore`, `ci`

Keep the subject line under 72 characters. Body is optional — use it for non-obvious reasoning.

## Spec Coherence

When modifying code that is covered by a spec (`docs/specs/*/`), check whether the behavioral change contradicts any MUST/SHALL criterion in the spec's `requirements.md`. If it does, **stop and surface the conflict to the user before proceeding.** Do not unilaterally modify spec requirements to match your implementation — spec changes require explicit user approval.

Once the user has approved the direction:

1. Update the spec (requirements and/or design) in the same commit as the code change.
2. Write a commit message that explains why the spec changed (not just what).
3. If the spec's status is `complete`, revert it to `accepted` until re-verified.

The only exception to requiring approval is correcting a spec that is provably inconsistent with itself (internal contradiction) or with an upstream constraint the spec failed to account for. Even then, flag the correction for review in the commit message.

To determine if a spec covers your change: check if the files you modified appear in the spec's `design.md` "File changes" table, or if the behavior you're altering is described in the spec's acceptance criteria.

If unsure whether a spec applies, err on the side of checking — reading a spec's requirements takes less time than debugging a silent design drift.

When writing or reviewing a spec or design, also check it for platform one-way doors — choices that would foreclose a future platform or force a rewrite rather than just add per-platform work. See `.agents/rules/platform-one-way-doors.md`.

## What Not To Do

- Do not commit without running `cargo fmt`
- Do not suppress clippy warnings with `#[allow(...)]` without justification
- Do not add dependencies without checking they're necessary and maintained
- Do not use `unsafe` without a safety comment and prior discussion
- Do not write to stdout in library code (only in `main.rs` / command handlers)
- Do not hardcode paths — use `config::platform` for OS-specific directories
