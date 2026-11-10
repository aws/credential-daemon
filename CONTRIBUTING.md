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

```bash
# Install pre-commit hook (one-time)
ln -sf ../../scripts/pre-commit .git/hooks/pre-commit

# Build and verify
cargo build
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

### macOS: code signing for Secure Enclave (one-time)

The Secure Enclave storage backend requires a code-signed binary. `demo/reinstall.sh`
handles signing automatically, but it needs a local self-signed certificate first:

1. Open **Keychain Access.app**
2. Menu: **Keychain Access → Certificate Assistant → Create a Certificate…**
3. **Name**: `credsd-dev`, **Identity Type**: Self Signed Root, **Certificate Type**: Code Signing
4. Click **Create**, then **Done**
5. Trust it for code signing (both user and system level):
     ```bash
     security find-certificate -a -c "credsd-dev" -p > /tmp/credsd-dev.pem
     security add-trusted-cert -p codeSign -k ~/Library/Keychains/login.keychain-db /tmp/credsd-dev.pem
     sudo security add-trusted-cert -d -p codeSign /tmp/credsd-dev.pem
     ```

After that, `demo/reinstall.sh` signs every build automatically. You only need to do this
once per machine.

## Code Style

### Error handling

Use helper constructors on `DaemonError`:

```rust
// Good
DaemonError::config("profile 'dev' not found")
DaemonError::provider("SSO session expired")

// Avoid — use helpers instead of direct variant construction
DaemonError::Storage(format!("keychain retrieve failed: {}", e))
```

Error messages: lowercase start, no trailing period, include actionable context.

```rust
// Good
"profile '{}' not found. Run 'credsd bootstrap' first"
"no daemon running on port {}. Start with 'credsd serve' or omit --attach"

// Bad
"Profile not found."
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
cargo clippy -- -D warnings
cargo test
```

All three must pass locally. CI enforces them too — catching issues locally avoids fixup commits cluttering the history.

Commit discipline: one meaningful commit per push. If CI fails on something you missed locally, amend the commit and force-push the branch rather than stacking "fix fmt" / "fix clippy" commits.

Note: there is no Windows CI row, so the `#[cfg(target_os = "windows")]` code (`storage/windows.rs`, `storage/dpapi.rs`) is neither built nor tested anywhere — locally or in CI. Windows support is deliberately deferred; the code stays in the tree for now. Do not assume a green build says anything about it.

## Submitting Changes

1. Create a feature branch from `develop`
2. Make focused, small changes
3. Run the pre-commit hygiene checks above
4. Commit with a clear message describing the why
5. Open a PR against `develop` (or `main` for releases)

## Spec-Required Changes

Changes to the following require a spec (requirements.md + design.md) before implementation:

- New credential provider type (auth mode)
- Storage backend additions
- API surface changes (new HTTP endpoints, response format changes)
- Security model modifications (trust boundaries, threat model)
- Breaking changes to config.toml format
- Sandbox runtime additions

Changes that do NOT require a spec: bug fixes, internal refactors, documentation, dependency updates, CI changes, new output formats on existing commands.

### Spec Format

Specs live in `.kiro/specs/<feature-name>/`. The path is a convention — any editor, agent, or human can produce the files. No specific tooling is required.

```
.kiro/specs/my-feature/
├── requirements.md    # What: user stories, acceptance criteria, constraints
├── design.md          # How: technical approach, data flow, API shapes, alternatives considered
└── tasks.md           # Work breakdown: generated only when spec reaches "accepted" status
```

### Spec Lifecycle and Status

Status is recorded in YAML front matter of `requirements.md` only (the lead artifact). Other files in the spec directory inherit the status of their `requirements.md`. Valid statuses:

| Status | Meaning | `tasks.md` present? |
|--------|---------|---------------------|
| `proposal` | Under discussion. Design may change. No commitment to implement. | No |
| `accepted` | Approved for implementation. Task list generated. | Yes |
| `complete` | Implemented as designed. All MUST/SHALL criteria verified in code. | Yes (all tasks `[x]`) |
| `rejected` | Evaluated and declined. Retained for historical context. | No |

**Front matter format** (required on `requirements.md`):
```yaml
---
status: proposal
authors: [github-username]
created: YYYY-MM-DD
completed: YYYY-MM-DD    # only present when status is complete
rejected_reason: "..."   # only present when status is rejected
---
```

**Transitions:**
- `proposal → accepted`: Generate `tasks.md`. Change to `status: accepted`. Implementation may begin.
- `accepted → complete`: All tasks in `tasks.md` are `[x]`. Verify by tracing each MUST/SHALL criterion in `requirements.md` to code that satisfies it. Change to `status: complete` and add `completed` date. The spec is now an assertion: the code conforms to this design.
- `proposal → rejected`: Change to `status: rejected`. Add `rejected_reason` field with a one-line rationale. No `tasks.md` is created. The spec remains in the repo as a record of the decision.
- `accepted → rejected`: Rare (scope cut, abandoned). Change status, add reason. `tasks.md` may be deleted or retained for context.
- `complete → accepted`: If a regression is found or a requirement is unmet, revert to `accepted` and reopen the relevant task(s).

**Marking a spec complete:**

A spec may only move to `complete` when:
1. Every task in `tasks.md` is marked `[x]`.
2. Every MUST/SHALL criterion in `requirements.md` can be traced to implementation code (a function, a test, a config path) that satisfies it.
3. The code compiles, passes `cargo clippy -- -D warnings`, and all tests pass.

This is an auditable assertion. If an agent or contributor is asked to verify spec status, they should read the requirements, trace each criterion to code, and confirm or dispute the `complete` status with evidence.

Specs with no front matter are treated as accepted (legacy convention).

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
1. THE CLI MUST provide a `remove` subcommand that accepts `--profile <name>`.
2. WHEN the named profile does not exist, THE command MUST exit with code 1 and print "profile '<name>' not found" to stderr.
3. THE command SHOULD prompt for confirmation unless `--force` is provided.
4. THE command MUST NOT delete the storage backend encryption key (shared across profiles).
```

### `requirements.md`

- **Introduction**: One or two paragraphs explaining what problem this solves and why it matters. Provide enough context that a reader unfamiliar with the project can understand the motivation.
- **Glossary**: Define domain terms used in the requirements. Each term should be capitalized consistently throughout the document (e.g., `Config_File`, `Profile_Data_Dir`).
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

Generated only when a spec moves from `proposal` to `accepted`. Breaks the design into ordered implementation steps, structured for delegation to agents or collaborators.

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

Tasks are execution scaffolding. They may be deleted or gitignored before merging to `main` — the durable record is requirements + design. They may also be retained on `develop` as progress tracking during active work.

---

Submit the spec (requirements + design) as a PR for review before beginning implementation. The spec is updated alongside the implementation if the design evolves.

## Security

For reporting vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the project's license, [Apache-2.0](LICENSE).
