---
status: accepted
created: 2026-11-09
---

# Requirements: Error Rendering

## Summary

Every error credsd shows a person names its category once. `DaemonError` owns
the category prefix of each variant. A message built from another error shows a
single prefix, however the call site built it. An error relayed from the daemon
is shown exactly as the daemon worded it.

## Scope

`credsd_core::error::DaemonError` and every place that renders it: the CLI, the
daemon's RPC error responses, and the client library. The shell client imports
`DaemonError` and `Result` from `credsd-core`; the surface it depends on is
defined in Requirement 5.

## Requirements

### Requirement 1: One prefix per rendered error

1.1. A category variant (`Config`, `Storage`, `Encryption`, `Provider`,
     `ReauthRequired`, `Io`, `Json`) SHALL render as `<category>: <message>`.
     Every other `DaemonError` variant SHALL render a fixed phrase over its own
     fields, and no field of any variant SHALL hold another error's rendered
     text:
     - `Unreachable` renders `cannot reach the daemon at <socket>: <cause>.
       <advice>`. Its `cause` field is governed by 4.2: it holds an I/O error, a
       literal, or another error's `detail()`, never another `DaemonError`'s
       rendered text.
     - `EnvNotFound` renders a not-found phrase naming the credential or
       environment and the command that lists them. Its name field holds a name,
       not a message.
     - `ApprovalRequired` and `ApprovalRefused` render their challenge
       description, reason, message, and remediation. Those fields are built by
       the daemon's approval path from request facts, not from another error.
     - `CredentialsExpired` and `RequestNotFound` render a fixed phrase with no
       field.
     - `Remote` is governed by Requirement 2.

1.2. Rendering a `DaemonError` SHALL add at most one category prefix, however
     many errors it was built from. Text a message holds of its own is not a
     prefix rendering added (4.3).

1.3. Each category name SHALL be written once in the source, and every use of
     it SHALL read that one definition.

### Requirement 2: Relayed daemon errors

2.1. `DaemonError::Remote` SHALL render the daemon's message verbatim, with no
     category prefix added.

2.2. Text the daemon sends is rendered by the same `DaemonError` type, so a
     relayed message SHALL carry at most one category prefix added by
     rendering.

2.3. When the daemon relays a `DaemonError` in an RPC error message that the
     client re-categorizes (it builds a `DaemonError` of its own category from
     the message), it SHALL send that error's `detail()`, not its rendered text.
     Other relays, which the client shows as the daemon's text, MAY send the
     rendered text (see Non-goals). A client that builds a
     `DaemonError` from an RPC error message SHALL NOT add a category to text
     that already carries one. For example, an authentication timeout relayed
     as `AUTH_TIMEOUT` and shown by the client as `configuration error: auth
     timed out: <message>` SHALL hold one prefix.

### Requirement 3: Message without its prefix

3.1. `DaemonError::detail()` SHALL return the message with no category prefix
     for every variant, including `ReauthRequired`, `Io`, and `Json`. It is the
     text to use wherever an error's message is embedded in other text that is
     not itself a `DaemonError`, such as an RPC error message or a status cause.

3.2. A relayed `Io`, `Json`, or `ReauthRequired` cause therefore shows without
     its category: for example a status cause reads `no such file or directory`
     rather than `I/O error: no such file or directory`. The outer error's own
     category, if any, is the only one shown.

### Requirement 4: Enforcement by construction

4.1. The one-prefix property SHALL hold by construction in every build,
     release included. No runtime check SHALL be needed to detect a repeated
     prefix.

4.2. A category variant SHALL hold its message apart from its category. An
     error built from another error SHALL take the inner error's `detail()`, or
     hold the inner error as a typed source, and SHALL NOT embed the inner
     error's rendered text. The same holds across the wire: an error built from
     a relayed RPC error message follows 2.3.

4.3. Rendering SHALL NOT rewrite a message. Message text that contains a
     category name followed by `: ` SHALL be shown unchanged.

4.4. A property test SHALL build errors from other errors, with arbitrary
     messages that hold no category name, at arbitrary depth and across every
     category variant, using each construction path call sites use. It SHALL
     assert the rendered text holds exactly one prefix, `detail()` holds none,
     and `Remote` relays the rendered text unchanged. A separate test SHALL show
     a message that does hold a category name is shown unchanged (4.3), and
     another SHALL show an error relayed through an RPC error message (2.3)
     renders one prefix.

### Requirement 5: Public surface

5.1. The public surface the shell client depends on is `DaemonError`, `Result`,
     the `Remote` variant, and the functions `config()`, `provider()`,
     `remote()`, and `detail()`. These names and their signatures are the
     surface this spec defines; a change to them is a breaking change to that
     client.

## Non-goals

- Carrying the category on the wire as a code. A relayed storage or encryption
  error is still shown as its rendered text.
- Localized or structured error messages.
