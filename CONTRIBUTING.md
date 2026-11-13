# Contributing to credsd

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold it.

## Developer Certificate of Origin (DCO)

All contributions must include a `Signed-off-by` line in the commit message, certifying the [Developer Certificate of Origin](https://developercertificate.org/):

```
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s` to add this automatically.

## AI-Assisted Contributions

We welcome the use of AI coding tools (Copilot, Claude, coding agents, etc.) as part of your development workflow. The following principles apply:

**Contributor primacy.** You are responsible for everything you submit. If you used AI tools to generate code, you must understand it fully, test it, and be prepared to explain and defend it during review.

**Disclosure.** If AI tools generated a meaningful portion of your contribution (beyond trivial autocomplete or reformatting), note this in the PR description. This helps reviewers calibrate their review.

**DCO applies regardless.** Your `Signed-off-by` certifies that YOU have the right to submit the code and are accountable for it. AI tools cannot certify the Developer Certificate of Origin on your behalf.

**Trivial use is excluded.** Autocomplete, code reformatting, spelling corrections, and similar IDE-level assistance do not require disclosure.

**Maintainers may reject without detailed review** submissions that appear to be untested, bulk-generated AI output, or where the author cannot answer review questions about their own code.

**Commit messages and documentation** must be human-authored or human-verified. If you used an AI tool to draft a commit message, ensure it accurately reflects your understanding of the change.

## Development Setup

Needs `rustup` (the toolchain version comes from `rust-toolchain.toml`). On macOS it also
needs the Xcode Command Line Tools: the default feature set builds a Swift Secure Enclave
shim, so `cargo build` fails without them.

```bash
# Install pre-commit hook (one-time)
ln -sf ../../scripts/pre-commit .git/hooks/pre-commit

# Build and verify
cargo build
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Those four commands are the same ones CI runs on every PR; see
[Pre-commit Hygiene](#pre-commit-hygiene) for the extra rows CI adds for feature-gated code
and dependency changes. Nothing else in this section is needed to build, test, or lint.

To exercise the daemon and the `creds` client end to end, follow
[docs/getting-started.md](docs/getting-started.md) Path B: it installs both binaries, runs
`sudo credsd install`, and checks `credsd status`. Every `creds` command talks to the daemon
over its Unix socket, so without that install step there is nothing to connect to.

`scripts/install.sh` is the shortcut for the build-and-relink half of that loop: it builds
the workspace and symlinks `credsd` onto PATH. On a Mac with no Secure Enclave (a VM, a
pre-T2 Intel) pass `FEATURES=file` — the default build has no usable storage backend there.
The link points into `target/`, so a rebuild lands behind it with no reinstall for
*interactive* use only; the service runs a root-owned copy that `sudo credsd install`
stages, so re-run that to put a new build behind the service.

## Code Style

### Error handling

Use helper constructors on `DaemonError`:

```rust
// Good
DaemonError::config("env 'dev' not found")
DaemonError::provider("SSO session expired")

// Avoid — use helpers instead of direct variant construction
DaemonError::Storage(format!("keychain retrieve failed: {}", e))
```

Error messages: lowercase start, no trailing period, include actionable context.

```rust
// Good
"env '{}' not found. Run 'creds bootstrap' first"
"storage backend '{}' is not compiled into this build; rebuild with `--features {}`"

// Bad
"Env not found."
"Error occurred"
```

For AWS SDK errors, use Display formatting (`{}`), not Debug (`{:?}`). Debug produces multi-page dumps that are unreadable to users. If you need the full error chain for diagnostics, log it at debug level separately.

### Output contract

- **stdout**: data only — credentials, env vars, JSON, table output. Must be parseable/eval-able.
- **stderr**: everything else — tracing logs, progress, confirmations, errors, prompts.

Never mix diagnostic output into stdout. A user running `eval $(creds get --format shell ...)` must get clean evaluable output with no log noise.

### Logging (tracing vs eprintln)

Two channels, two purposes:

| Channel | Use for | Examples |
|---------|---------|----------|
| `tracing::info!/warn!/error!` | Structured operational logs (filterable via `RUST_LOG`) | Daemon lifecycle, credential refresh, backend selection, request handling |
| `eprintln!` | Interactive user-facing messages | Bootstrap prompts, confirmations, progress indicators, selection menus |

Rule of thumb: if the message matters when the daemon runs unattended (as a service), use tracing. If it only matters during interactive CLI use, use eprintln.

### Async and unwrap

- No `.unwrap()` in library code or command handlers. Use `?` or handle the error.
- `.unwrap()` is acceptable in tests and in cases where failure is provably impossible (e.g., serializing a known-good struct).
- No blocking operations (`std::fs::read`, `std::thread::sleep`) inside async functions without `tokio::task::spawn_blocking`.

### Platform-specific code

- Gate with `#[cfg(target_os = "...")]` on module declarations in `mod.rs`.
- Backend implementations are self-contained files — one struct, one `impl SecureStorage`, one `#[cfg(test)]` block.
- Use `cfg!()` (runtime, always compiles) for logic decisions. Use `#[cfg()]` (compile-time) for module inclusion and platform-only code paths.

## Pre-commit Hygiene

Run before every commit:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

All three must pass locally. CI enforces them too — catching issues locally avoids fixup commits cluttering the history.

CI lints more than that, because the default run compiles neither the platform-gated nor the
feature-gated arms. It adds `--features secure-enclave,file` on macOS and
`--features credsd-core/tpm` (needs `libtss2-dev`) and `--features credsd-core/kkrs` on
Linux. If you touched code behind one of those gates, run the matching row locally — the
default run never compiles it.

Dependency changes have one more gate: `THIRD-PARTY-LICENSES.md` must track `Cargo.lock`, and
CI regenerates it and fails on any diff. After changing a dependency, regenerate it in the
same commit:

```bash
cargo install cargo-about --locked --version 0.9.3   # the version CI pins
cargo about generate --all-features --workspace --locked -o THIRD-PARTY-LICENSES.md about.hbs
```

Commit discipline: one meaningful commit per push. If CI fails on something you missed locally, amend the commit and force-push the branch rather than stacking "fix fmt" / "fix clippy" commits.

Note: there is no Windows CI row, so the `#[cfg(target_os = "windows")]` code (`storage/windows.rs`, `storage/dpapi.rs`) is neither built nor tested anywhere — locally or in CI. Windows support is deliberately deferred; the code stays in the tree for now. Do not assume a green build says anything about it.

## Submitting Changes

1. Create a feature branch from `main`
2. Make focused, small changes
3. Run the pre-commit hygiene checks above
4. Commit with `git commit -s` and a clear message describing the why — the sign-off is the DCO certification and is mandatory on every commit
5. Open a PR against `main`

## Spec-Required Changes

Changes to the following require a spec (requirements.md + design.md) before implementation:

- New credential provider type (auth mode)
- Storage backend additions
- API surface changes (new JSON-RPC methods on the Unix socket, response format changes)
- Security model modifications (trust boundaries, threat model)
- Breaking changes to config.toml format

Changes that do NOT require a spec: bug fixes, internal refactors, documentation, dependency updates, CI changes, new output formats on existing commands.

### Spec Format

Specs live in `docs/specs/<feature-name>/`. The path is a convention — any editor, agent, or human can produce the files. No specific tooling is required.

```
docs/specs/my-feature/
├── requirements.md    # What: user stories, acceptance criteria, constraints
├── design.md          # How: technical approach, data flow, API shapes, alternatives considered
└── tasks.md           # Work breakdown: optional scaffolding, written when a spec is accepted
```

### Spec Lifecycle and Status

Status is recorded in `requirements.md` only (the lead artifact). Other files in the spec directory inherit the status of their `requirements.md`. Two notations are equivalent, and both are in use in `docs/specs/`:

```yaml
---
status: accepted
created: 2026-10-04
---
```

```markdown
**Status:** accepted
```

The bold-line form is the more common one, and it usually carries a trailing clause
qualifying what the status means for that spec ("accepted — compiled only with the `kkrs`
feature, which no shipped build enables"). That qualification is worth keeping. Pick one
notation per spec; do not write both.

Valid statuses:

| Status | Meaning |
|--------|---------|
| `draft` | Being written or under discussion. Design may change. Approval means "proceed to implementation". |
| `proposal` | Synonym for `draft`. No spec currently uses it; prefer `draft`. |
| `accepted` | Approved for implementation. |
| `complete` | Implemented as designed. All MUST/SHALL criteria verified in code. |
| `rejected` | Evaluated and declined. Retained for historical context. |

**Transitions:**
- `draft → accepted`: Implementation may begin.
- `accepted → complete`: Verify by tracing each MUST/SHALL criterion in `requirements.md` to code that satisfies it, then change the status. The spec is now an assertion: the code conforms to this design.
- `draft → rejected`: Note a one-line rationale alongside the status. The spec remains in the repo as a record of the decision.
- `accepted → rejected`: Rare (scope cut, abandoned). Change status, add reason.
- `complete → accepted`: If a regression is found or a requirement is unmet, revert to `accepted`.

**Marking a spec complete:**

A spec may only move to `complete` when:
1. Every task in `tasks.md` is marked `[x]`, if the spec has a `tasks.md` (most do not — see below).
2. Every MUST/SHALL criterion in `requirements.md` can be traced to implementation code (a function, a test, a config path) that satisfies it.
3. The code compiles, passes `cargo clippy --all-targets -- -D warnings`, and all tests pass.

This is an auditable assertion. If an agent or contributor is asked to verify spec status, they should read the requirements, trace each criterion to code, and confirm or dispute the `complete` status with evidence.

### Requirements Language (RFC 2119)

Requirements use RFC 2119 keywords (MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY). Write them consistently so that any agent or human reader can produce a conforming implementation without ambiguity:

| Keyword | Meaning | When to use |
|---------|---------|-------------|
| MUST / SHALL | Absolute requirement. Violation is a defect. | Security constraints, data integrity, API contracts |
| MUST NOT / SHALL NOT | Absolute prohibition. | Dangerous operations, security boundaries |
| SHOULD | Recommended. May be omitted with documented justification. | Best practices, performance targets, UX polish |
| SHOULD NOT | Discouraged. May be done with documented justification. | Suboptimal patterns, deprecated paths |
| MAY | Truly optional. No expectation either way. | Extensions, future-proofing, nice-to-haves |

**Writing acceptance criteria:**
- Each criterion is one sentence starting with a keyword.
- The sentence must be testable — a reader can write a pass/fail assertion from it.
- Use "THE system/command/daemon" as subject, not passive voice.
- Conditional criteria use "WHEN ... , THE system MUST ..." or "IF ... , THEN THE system MUST ..."
- Enumerate edge cases explicitly (empty input, missing file, network timeout) — do not leave them implied.

**Example:**
```markdown
1. THE CLI MUST provide a `remove` subcommand that accepts `--environment <name>`.
2. WHEN the named env does not exist, THE command MUST exit with code 1 and print "env '<name>' not found" to stderr.
3. THE command SHOULD prompt for confirmation unless `--force` is provided.
4. THE command MUST NOT delete the storage backend encryption key (shared across envs).
```

### `requirements.md`

- **Introduction**: One or two paragraphs explaining what problem this solves and why it matters. Provide enough context that a reader unfamiliar with the project can understand the motivation.
- **Glossary**: Define domain terms used in the requirements. Each term should be capitalized consistently throughout the document (e.g., `Config_File`, `Env_Data_Dir`).
- **Requirements**: Numbered sections, each with:
  - A user story: "As a [role], I want [capability], so that [benefit]."
  - Acceptance criteria: Numbered list using RFC 2119 keywords. Each criterion is independently verifiable.
- **Non-requirements** (optional): Explicit exclusions with rationale — what this spec deliberately does NOT cover.

### `design.md`

- **Overview**: One paragraph summarizing the technical approach.
- **Architecture**: How the feature fits into the existing system. Diagrams (ASCII) where helpful.
- **Key decisions**: Important choices made, with alternatives considered and why they were rejected.
- **Interface**: Public API/trait surface that other modules will depend on. Include Rust signatures.
- **Data model**: Structs, enums, TOML schema, on-disk formats.
- **Security considerations**: Threat model impact, secret handling, trust boundaries.
- **Dependencies**: New crate additions with justification.
- **File changes**: Table of files modified/created with a brief description of each change.

### `tasks.md`

Optional, and written only when a spec moves from `draft` to `accepted`. Breaks the design into ordered implementation steps, structured for delegation to agents or collaborators. No spec currently in `docs/specs/` keeps one.

**Structure:** Two levels of nesting. Top-level tasks (## headings) are logical units of work — a module, a trait implementation, a CLI command, or a test suite. Subtasks (list items) are concrete actions within that unit.

**Status notation:**
```
- [ ] Not started
- [~] In progress
- [x] Complete
```

**Format:**
```markdown
# Tasks

## Task 1: DPoP Signer Module
**Requirement**: 2 (DPoP Proof-of-Possession)

- [ ] 1.1: Create `src/providers/dpop.rs` with `DpopSigner` struct
- [ ] 1.2: Implement `generate()` — keypair creation + encryption
- [ ] 1.3: Implement `sign()` — decrypt, build JWT, sign, zeroize
- [ ] 1.4: Implement `from_encrypted()` — reconstruct from persisted key
- [ ] 1.5: Test: generate → sign → verify round-trip
- [ ] 1.6: Test: wrong key fails verification

---

## Task 2: OAuth Callback Server
**Requirement**: 1 (Bootstrap)

- [ ] 2.1: Implement `wait_for_callback()` — bind, accept, parse query params
- [ ] 2.2: Respond with HTML success page
- [ ] 2.3: 5-minute timeout with descriptive error
- [ ] 2.4: Test: valid callback returns code + state
- [ ] 2.5: Test: missing params returns error

---

## Dependency Order

Task 1 blocks Task 3 (token exchange needs DPoP signer)
Task 2 is independent
```

**Guidance:**
- Each top-level task should be completable independently (or note its dependency in the dependency section)
- Subtasks should be small enough to verify in isolation (~1 function, ~1 test, ~1 struct)
- Link each top-level task to the requirement(s) it satisfies
- Include a dependency graph at the bottom showing which tasks block others
- Update status as work proceeds; a task is `[x]` only when it compiles, passes tests, and satisfies its linked acceptance criteria

Tasks are execution scaffolding. They may be deleted or gitignored before merging to `main` — the durable record is requirements + design. They may be retained on the feature branch as progress tracking during active work.

---

Submit the spec (requirements + design) as a PR for review before beginning implementation. The spec is updated alongside the implementation if the design evolves.

## Security

For reporting vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the project's license, [Apache-2.0](LICENSE).
