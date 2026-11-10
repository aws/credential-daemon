# Requirements: User Documentation

**Status:** accepted
**Feature:** `user-documentation`
**Scope:** The user-facing documentation set for credsd: which documents exist, who each is
for, what each covers, where each takes its facts from, and the maturity notice every one of
them carries.

## Introduction

credsd is two binaries and a set of install shapes whose security properties differ. `creds`
is the client — `bootstrap`, `get`, `config`, `list`, `remove`, `import`, `login`,
`request`, `presence`. `credsd` is the daemon — `serve`, `init`, `install`, `uninstall`,
`status`.
Which install shape a reader can use, and which storage backend holds their master key, decide
what credsd protects them from. A reader who follows a document written for a different shape
gets a different posture from the one the document describes.

The documentation set is therefore organized by reader and install shape rather than by
feature, and every fact it states about a command, flag, key, variable, method, or backend is
one the code can confirm.

credsd is a pre-release preview, provided in coordination with Strands Box. Every document says
so before it says anything else.

### Terminology

- **Documentation set** — `README.md` and every file under `docs/` other than `docs/specs/`
  and `docs/design/`. Specs and design notes are maintainer material and are not in the set.
- **Maturity notice** — the block that opens every document in the set and states the
  project's release maturity.
- **Source of truth** — the code location a document's facts are drawn from and checked
  against.
- **Install shape** — one of: macOS user-scoped install (official signed release), macOS system
  install (LaunchDaemon), Linux system install. Windows install shapes are undecided.

### Audiences

| Audience | Needs |
|---|---|
| Evaluator | What credsd is, who it is for, its maturity, and its security premise |
| User | Install for their shape, bootstrap a credential, get credentials into a process |
| Operator | Install options, storage backends, configuration, recovery |
| Integrator | The socket API: methods, shapes, errors |
| Security reviewer | Custody, threat model, what each install shape does and does not protect |

## Requirements

### Requirement 1: Every document opens with the maturity notice

**User story:** As an evaluator, I want to know before reading further that credsd is a
pre-release preview and what that means for me, so that I do not adopt it on assumptions it
does not meet.

1.1. Every document in the set SHALL begin with the maturity notice, before its title's first
     paragraph and before any instructions.

1.2. The maturity notice SHALL state that credsd is a pre-release preview, and that it is
     provided in coordination with Strands Box, linked to `https://github.com/strands-agents/box`.

1.3. The maturity notice SHALL state what pre-release means for a reader: which interfaces may
     change between releases, and whether a change carries a migration path.

1.4. The maturity notice SHALL have one canonical text. Every document SHALL carry that text
     verbatim, so that a change to the project's maturity changes every copy together.

1.5. A check SHALL fail when a document in the set lacks the maturity notice or carries a text
     that differs from the canonical one.

### Requirement 2: The README orients and routes

**User story:** As an evaluator, I want one page that tells me what credsd is and where to go
next, so that I can decide whether it applies to me without reading everything.

2.1. The README SHALL state, in one paragraph, what credsd is, who it is for, and its security
     premise.

2.2. The README SHALL name both binaries and state which subcommands belong to each.

2.3. The README SHALL route each audience to the document that serves it, and SHALL NOT repeat
     reference material those documents own.

2.4. The README SHALL state, in one paragraph, that credsd is not a general-purpose secret store,
     name what it does beyond holding secrets, and route to the overview.

### Requirement 3: Reference documentation is complete and cannot drift

**User story:** As an operator or integrator, I want reference pages that list everything the
code accepts, so that a flag, key, or method I find in the code is documented, and one I find in
the documentation exists.

3.1. A command reference SHALL document every `creds` and `credsd` subcommand and every flag.

3.2. A check SHALL fail when the command reference omits a subcommand or flag the CLI
     definitions accept, or documents one they do not.

3.3. An API reference SHALL document every JSON-RPC method the daemon serves by its wire name,
     with its request and response shapes, and every error code a client can receive.

3.4. A configuration reference SHALL document every `config.toml` key, every `credentials.toml`
     source type and its fields, every environment variable credsd reads, and the data-directory
     layout for each install shape.

3.5. Each reference page SHALL name its source of truth in the code.

### Requirement 4: Storage backends are documented by custody

**User story:** As a security reviewer, I want each storage backend described by who can reach
the master key, so that I can judge the posture of a given install without reading the code.

4.1. The backend documentation SHALL cover every backend the daemon accepts:
     `data-protection-keychain`, `secure-enclave`, `tpm`, `kkrs`, `dpapi`,
     `credential-manager`, and `file`, and SHALL state which builds compile each.
     (AMENDED 2026-10-07: `legacy-keychain` removed from every build by `mac-pkg-installation`
     Requirement 7.6, which also makes `file` on macOS a build option; the per-build statement
     is new because the official macOS build no longer accepts every backend.)

4.2. For each backend it SHALL state where the master key is held, which processes can read or
     replace it, and what the backend does and does not protect against.

4.3. It SHALL state the auto-detect order for each platform, the outcome when auto-detect finds
     no hardware-backed backend, and how a backend is selected explicitly.

4.4. It SHALL state what changing the backend of an existing install does to its master key
     and sealed credentials.

### Requirement 5: Getting started follows the reader's install shape

**User story:** As a new user, I want a walkthrough for the install shape I can actually use, so
that the commands I run produce the posture the page describes.

5.1. The getting-started guide SHALL present a path per install shape and SHALL state which
     shape applies to which reader.

5.2. It SHALL use `creds` for client subcommands and `credsd` for daemon subcommands.

5.3. It SHALL take a reader from install to credentials in a child process, and SHALL route to
     the reference documentation rather than restate it.

### Requirement 6: Install options state their consequences

**User story:** As an operator, I want each install option described with what it does to key
custody, so that I choose the shape knowingly.

6.1. The install documentation SHALL describe each install shape, the platforms and builds it
     is available for, and the storage backend it resolves to.

6.2. It SHALL state why a user-scoped install exists only for the official signed macOS
     release: in a user-scoped install the daemon runs as the caller's uid, so only a keystore
     gated on code identity separates them, and an open-source build's signature is
     reproducible by anyone.

6.3. It SHALL state that Windows install shapes are not yet decided.

### Requirement 7: The documentation describes the system as it is

**User story:** As any reader, I want a document to be wrong only when the code is, so that I
can act on what it says.

7.1. A document SHALL NOT name a command, flag, configuration key, environment variable, method,
     error code, or backend that the code does not have.

7.2. A behavior change that alters a documented fact SHALL update the document in the same
     change.

### Requirement 8: The overview places credsd among tools that hold secrets

**User story:** As an evaluator, I want to know what credsd does that a secret store does not, and
what it does not do at all, so that I do not adopt it for a job it was not built for or dismiss it
as a duplicate of a tool I already have.

8.1. An overview SHALL state credsd's security premise and SHALL describe it as five layers:
     vaulting, credential exchange, environment definitions, credential projection, and
     lightweight authorization, each with what it does and where it is configured.

8.2. The overview SHALL state what credsd is not: a general-purpose secret store, an
     authorization system for the credentials' issuer, a sandbox for the processes it serves,
     and protection from root.

8.3. The overview SHALL contrast credsd with each category of tool that holds secrets —
     general-purpose secret stores, cloud secret managers, password managers, AWS credential
     helpers, and OS keystores — naming examples of each. A claim about another tool SHALL be
     limited to a property that defines its category, so that the contrast does not depend on
     that tool's current feature set.

### Requirement 9: Approval is documented by what it guarantees

**User story:** As a user who has just been asked to approve a change, I want to know why, how to
approve it, and what approving does and does not guarantee, so that I approve what I meant to and
recognize a request I did not raise.

9.1. A presence document SHALL list every operation the daemon's built-in gate requires approval
     for, and when, as `presence-gated-operations` Requirement 1.7 defines it, by the `creds`
     command that raises it.

9.2. It SHALL describe both verifiers: privileged approval with `sudo`, available on every
     platform and in every session, and a presence signature with Touch ID, available after
     enrollment on a macOS build with the `secure-enclave` feature. It SHALL state that
     enrollment is approved only by `sudo`, and why.

9.3. It SHALL state what an approval guarantees — that what is performed is what was recorded —
     and what it does not: that the approver saw what was recorded, and any guarantee in an
     insecure posture.

## Non-Goals

- **Maintainer documentation.** Specs, design notes, and contributor guidance are outside the
  set.
- **Deciding Windows install shapes.** The set records that they are undecided.
- **Generated prose.** Checks keep the reference pages complete; the pages are written, not
  rendered from the code.

## Relationship to adjacent specs

**`presence-gated-operations`.** Requirement 7 of that spec defines the install shapes and their
trust boundaries; Requirements 4 and 6 here document them. Its built-in gate, verifiers, and
limits are what Requirement 9 documents.

**`credential-projection`.** Defines the projections the overview names (Requirement 8.1).

**`mac-pkg-installation`.** Defines the signed macOS distribution whose user-scoped install
Requirement 6 describes.

**`tpm-encryption-backend`, `kkrs-encryption-backend`, `secure-enclave-encryption-backend`.**
Define backend behavior and the auto-detect order that Requirement 4 documents.

**`credential-retrieval-api`.** Defines the JSON-RPC methods and error model the API reference
documents.
