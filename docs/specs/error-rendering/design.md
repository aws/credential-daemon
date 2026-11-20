---
status: accepted
created: 2026-11-09
---

# Design: Error Rendering

## Shape

`error.rs` declares each category name once. A category variant holds its
message apart from its category and renders `<category>: <message>`. An error
built from another error takes the inner error's `detail()`, so rendering adds
one prefix. `detail()` returns the message with no prefix, and `Remote` shows
its message as sent. Nothing is rewritten at render time.

```
Provider error built from Encryption("decryption failed") with context "no usable key"
  -> "provider error: no usable key: decryption failed"
```

## Decisions

### 1. Structural: build from `detail()`, never from rendered text

Each category variant carries its message as data, separate from its category.
A call site that builds one error from another passes the inner error's
`detail()` (or holds it as a typed source), never its `Display`, so the inner
prefix never enters the outer message. Rendering only prepends the outer
category; it never inspects or rewrites the message, so text that legitimately
contains a category name followed by `: ` (a path, a quoted server reply) is
shown unchanged.

Considered and rejected: stripping category prefixes from the message at render
time. It needs no call-site changes, but it rewrites legitimate message text.

### 2. One list of category names

Every rendering of a category and every test reads the same constant. A new
category is one constant and one list entry; a name cannot drift between the
rendered text and the check on it.

### 3. No runtime prefix check

The invariant holds by construction. A debug-only check that counts prefixes in
constructor input only fires in tests and does not cover tuple literals or
`#[from]` conversions, so the design has none.

### 4. Public names unchanged

The shell client imports `DaemonError` and `Result` and uses `Remote`,
`remote()`, `detail()`, `config()`, and `provider()`. Requirement 5 defines that
surface; variant fields and other variants are not part of it.

## Testing

- Property test: arbitrary messages that hold no category name, nested through
  every category variant up to five deep by the construction paths call sites
  use. Asserts exactly one prefix in the rendered text, none in `detail()`, and
  that `Remote` relays the rendered text unchanged.
- A message holding `provider error: ` of its own is rendered unchanged inside
  its variant's prefix.
- An encryption error wrapped by a provider error renders
  `provider error: no usable key: decryption failed`.
- An error relayed as an RPC error message and rebuilt by the client (for
  example an authentication timeout) renders one prefix.

## File changes

| File | Change |
|---|---|
| `crates/credsd-core/src/error.rs` | Category constants, rendering, `detail()` covering every variant (now including `ReauthRequired`, `Io`, `Json`), tests; debug prefix check removed |
| Call sites that build one error from another | Pass `detail()` instead of the inner error |
| Call sites that relay `detail()` into a status cause (credential store, integrity, revalidate) | No code change; the relayed `Io`, `Json`, and `ReauthRequired` text now shows without its category (Req 3.2) |
| Daemon relays the client re-categorizes (bootstrap's sign-in failures, such as the authentication timeout) | Send `detail()` (Req 2.3) |
| Daemon relays the client shows as is (bootstrap install, config validation on a gated write) | Send the rendered text of a typed `DaemonError`, so it names exactly one category (Req 2.3) |

## Open Questions

1. Should the category travel on the wire as a code, so a relayed error can be
   matched by category instead of by text? It would change the RPC error format.
2. Should `Remote` normalize text from a daemon on an older build that still
   nests prefixes? Pre-launch, so the spec shows the daemon's text verbatim.
