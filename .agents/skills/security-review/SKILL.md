---
name: security-review
description: Security review of credsd code as a Rust/cryptography auditor. Two scales — `diff` mode reviews staged or branch-delta changes before a PR, `audit` mode reviews the whole system. Covers crypto primitives, secret lifecycle/zeroization, IPC and bearer auth, file permissions, unsafe FFI, cross-platform service installation, and supply chain. Use before opening a PR, when asked to security-review a change, or for a whole-system security audit.
capabilities: read files, run shell commands, search file contents, optionally delegate subtasks
---

# Security Review

Review credsd for exploitable security defects. You are a security auditor with deep Rust
and applied-cryptography experience and working knowledge of process management and init
systems on macOS (launchd), Linux (systemd), and Windows (Task Scheduler / SCM).

credsd holds long-lived AWS SSO refresh material and vends short-lived credentials over
local IPC. The threat actors that matter are, in order:

1. **A non-root local user on the same machine** — the primary adversary. Wants to read
   another user's credentials via the socket or log files.
2. **A same-UID unprivileged process** — a browser tab's helper, a malicious `npm`
   postinstall. Already inside the UID boundary, so file modes don't stop it; what stops
   it is that there is nothing extra to steal beyond what the UID already grants.
3. **A malicious or compromised upstream dependency** — the crate graph is in the TCB of a
   credential daemon.
4. **A hostile remote endpoint** — a signin/SSO/OIDC service response, or a redirect to one.

Root on the same machine is **explicitly out of scope** (`SECURITY.md`: "root is trusted at
install time"), as is local DoS. Do not report findings whose precondition is root.

The file-and-line specifics below describe a tree with no HTTP transport: `serve` binds a Unix
domain socket only, and there is no bearer token on it — the daemon takes the caller's uid from
the kernel. One per-operation loopback listener remains, the OAuth authorization-code callback,
bound by an `aws-login` or `aws-web-identity` flow and closed with the flow that opened it. Note
that the *daemon* binds it, not the client. Where a checklist item names a file or
symbol, confirm it still exists before trusting the surrounding claim — a checklist that has
drifted from the code will send you looking for the wrong bug.

**Windows is deferred.** `storage/windows.rs` and `storage/dpapi.rs` are still in the tree and
still worth reading — unreviewed `unsafe` is unreviewed `unsafe`, and the code is not being
deleted today — but no CI row builds them, their round-trip tests execute nowhere, and no
shipped binary contains them. So a defect there is not currently exploitable by anyone, and
should be reported at reduced severity with that reason stated. Do not report the absence of a
Windows transport, Windows ACLs, or Windows service installation as a finding; those are
declared non-goals for now.

## Arguments

Invoked as `security-review [mode] [scope]` (a slash command in harnesses that
support them):

- (no arg) → `diff` mode against the staged index. The default; this is the pre-PR gate.
- `diff` → staged index (`git diff --cached`). Falls back to `main...HEAD` if nothing is
  staged, and says which it used.
- `diff <rev-range>` → e.g. `diff main...HEAD`, `diff HEAD~3`. Review that delta.
- `audit` → whole-system review, every area below.
- `audit <areas>` → comma-separated area keys from the table below, e.g.
  `audit crypto,ipc-auth`. Review only those, and say so in the report.

## Mode: diff

Purpose: catch a security defect in a change **before** it becomes a PR. Bounded by the
diff — do not audit untouched code, but **do** read enough surrounding context to judge
the changed lines (a diff that removes a bounds check looks innocent in isolation).

### Step 1 — Establish the delta

```bash
git status --porcelain
git diff --cached --stat            # staged; if empty, fall back:
git diff main...HEAD --stat
git diff --cached                   # or the chosen range
```

State the range you reviewed and the file count. If the delta is empty, say so and stop —
do not silently escalate to an audit.

### Step 2 — Deterministic pre-flight

These are signal, not verdict. Run what is present; **name every tool that was absent** so
the report never implies coverage it does not have.

```bash
command -v gitleaks cargo-audit                  # detect

gitleaks git --staged --redact --no-banner .      # staged secrets (or --log-opts for a range)
cargo audit --deny warnings                       # only if Cargo.lock is in the delta
```

`gitleaks` reads `.gitleaks.toml`, which allowlists the literal `EXAMPLE` (AWS's published
example key, used in fixtures) and `target/`. A hit that is *not* covered by that allowlist
is a tier-1 blocker. Never print a matched secret's value — report type, file, and length.

If `Cargo.toml` or `Cargo.lock` changed, additionally diff the dependency delta and judge
each new crate against the supply-chain checklist:

```bash
git diff --cached -- Cargo.toml Cargo.lock | grep -E '^\+' | grep -E 'name =|version =' | head -40
cargo tree --duplicates 2>/dev/null | head -30    # new duplicate majors in the TCB
```

### Step 3 — Map changed lines to areas, then review

For each changed file, look up its areas in the **Threat areas** table and apply those
checklists to the changed lines. A file in no area still gets a general Rust-safety pass
(panics on attacker-influenced input, integer casts, `unwrap()` in library code).

### Step 4 — Report

Use the report format below, headed `## Security Review — diff`.

**Failure semantics.** This skill is advisory: it reports, it does not block a commit. The
blocking gates are `scripts/pre-commit` (fmt, clippy, gitleaks, cargo audit) and CI. If you
find a tier-1 finding, lead with it and state plainly that the change should not be pushed
as-is.

## Mode: audit

Purpose: find exploitable defects across the whole system, including in code no recent diff
touched. Work area by area. Prefer reading a whole file over grepping for a pattern —
several of the areas below are about what is *missing*, which grep cannot find.

Before the areas, take the inventory:

```bash
find crates vendor -name '*.rs' | sort
grep -rn "unsafe" --include='*.rs' crates | wc -l
grep -rn "unwrap()\|expect(\|panic!\|\[0\]\|as usize\|as u32\|as i32" --include='*.rs' crates | wc -l
gh api "repos/$(gh repo view --json nameWithOwner -q .nameWithOwner)/code-scanning/alerts?state=open" \
  --jq '.[] | "\(.rule.security_severity_level) \(.rule.id) \(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)"'
```

Open CodeQL alerts are **inputs, not findings** — verify each by reading the code before
reporting it, and drop it if it is a false positive (say that you dropped it and why).

### Threat areas

| Key | Files | What to prove |
|---|---|---|
| `crypto` | `encryption.rs`, future DPoP/PKCE code | primitive choice, nonce discipline, key sizes, signature encoding |
| `secrets` | `credentials.rs`, `credential_store.rs`, `credential_env.rs`, `storage/*`, `config/keys.rs` | every secret-bearing type zeroizes; no secret reaches a log, error string, `Debug`, or serialized artifact |
| `ipc-auth` | `server/{uds,routes,dispatch,classify,revalidate,presence}.rs` — `CallerAuth` and `DenyReason` are defined in `routes.rs`, resolved in `uds.rs` | who can reach the socket, and what proves they are allowed; that the kernel-supplied uid is the only accepted proof and no claim a client sends substitutes for it |
| `fs-perms` | `config/{mod,platform}.rs`, `log.rs`, `server/uds.rs`, `storage/file.rs` | mode is set **before** secret bytes land; TOCTOU; symlink and parent-dir trust |
| `unsafe-ffi` | `server/process_tree.rs`, `storage/{windows,dpapi}.rs` (deferred, unbuilt) | every `unsafe` block's invariant actually holds; buffer sizes, lifetimes, null and error paths |
| `service` | `install.rs` | injection into plist/unit/task XML; write-path trust; privilege at install and at run |
| `exec` | `credential_env.rs`, `get.rs`, `bootstrap.rs`, `install.rs` | argv construction, no shell interpolation, no secret in argv or in a command echoed to a user |
| `net` | `providers/*` | TLS backend, endpoint/redirect validation, SSRF via the OAuth loopback callback, response trust |
| `supply-chain` | `Cargo.toml`, `Cargo.lock` | advisories, duplicate crypto stacks, unmaintained crates, build-script risk |

### `crypto`

- **Primitive and mode.** AES-256-GCM via `aws-lc-rs` is the established choice; `ring` is
  transitive-only (via rustls) and must not come back as a direct dependency. Flag any
  new direct crypto crate (`p256`, `sha2`, `openssl`, `rust-crypto`) — `aws-lc-rs` was
  verified to cover SHA-256, AES-GCM, and P-256 ECDSA including private-key export.
- **Nonce discipline.** `LessSafeKey` + `Nonce::assume_unique_for_key` puts the uniqueness
  burden entirely on the caller. Prove the nonce is 12 fresh CSPRNG bytes per `seal`, never
  derived from a counter that can reset, never reused across a re-encrypt of the same
  plaintext. A repeated (key, nonce) pair under GCM is a **catastrophic** finding — it
  leaks the XOR of plaintexts and enables forgery, not just confidentiality loss.
- **AAD.** `Aad::empty()` today means a ciphertext is not bound to its context: an attacker
  with write access to the store could swap profile A's blob into profile B's slot and it
  would decrypt cleanly. Whether that is exploitable depends on the file modes — reason it
  through rather than reporting it reflexively.
- **ES256 encoding.** If DPoP/JWS signing lands: JOSE requires 64-byte fixed `r‖s`
  (`ECDSA_P256_SHA256_FIXED_SIGNING`), not ASN.1 DER. Both compile and both produce valid
  ECDSA, so only an explicit length assertion catches the wrong one.
- **Comparisons.** Any comparison of a secret, MAC, or token must be constant-time.
  `auth.rs::constant_time_eq` is the house implementation; an early-return `==` on secret
  bytes is a finding.
- **RNG.** Key and nonce material must come from a CSPRNG (`aws_lc_rs::rand::SystemRandom`,
  or `rand::thread_rng` for tokens). `rand::rngs::SmallRng`, `StdRng::seed_from_u64`, or
  any seeded/predictable source for security material is a finding.

### `secrets`

- Every type holding a secret implements `Zeroize` and drops it (`AGENTS.md` requires it).
  Check the **moves**: a `Vec<u8>` cloned into a `String`, pushed into a `serde_json::Value`,
  or returned by value leaves un-zeroized copies the `Drop` impl never sees. `String`
  reallocation on `push_str` leaves the old buffer in the allocator.
- No secret in: `tracing` fields, `DaemonError` messages, `#[derive(Debug)]` on a
  secret-bearing struct, a `Display` impl, an HTTP error body, or a panic message. Note
  that `log.rs` has **no redaction layer** — the only defense is that nothing logs a secret
  in the first place, so any new log line near credential material deserves scrutiny.
- Secrets must not transit argv (world-readable via `ps`) or an inherited environment
  beyond the intended child.

### `ipc-auth`

- **UDS.** `server/uds.rs` sets parent dir `0700` and socket `0600`, and the accept loop
  resolves the kernel-supplied peer uid through `resolve_caller` into a `CallerAuth`.
  Confirm it is consulted on **every** accepted connection and that both failure modes fail
  closed: no peer credential at all (`DenyReason::NoPeerCred`) and a passwd lookup that
  fails (`CallerAuth::Unresolved`). A check that exists but is never invoked, or that
  defaults to authorized, is a live cross-user read. Note the socket `set_permissions` is
  deliberately best-effort
  (`let _ =`), with the parent dir as the real gate; that is sound only if the parent mode
  is enforced (not best-effort) and its own parents are not writable by others.
- **Stale-socket handling.** `check_stale_socket` removes a path that fails to connect.
  Reason about a hostile file at that path (symlink, another user's socket) and about the
  race between the check and `bind`.
- **No token at all.** Nothing on the socket authenticates by secret; `credsd-core/src/auth.rs`
  still carries unused bearer helpers from the removed HTTP transport, so a change that starts
  calling them is reintroducing a credential, not reusing an existing one. Review it as new
  auth.
- **No persistent token.** There is deliberately no token file: `serve` authenticates by
  peer UID, so a bearer token would add a second, weaker credential for the same boundary.
  Treat the reintroduction of an on-disk token as a finding in itself, and if one ever
  lands, check what a previous audit had to check about it — that it is not *read and
  trusted* from a path an attacker can write (whoever writes the file chooses the token),
  that its mode and ownership are validated rather than assumed, and that a short or
  low-entropy existing value is rejected rather than accepted.
- **Optionality is the bug.** A bearer token threaded as `Option<String>` and unwrapped
  with `unwrap_or_default()` yields `""` as the expected value, which then compares equal
  to a request sending exactly `Bearer `. Any auth secret whose type permits an empty or
  absent state is a finding regardless of whether you can reach it today — prefer a
  non-optional type so the state is unrepresentable.
- **OAuth callback listener.** `providers/oauth/callback.rs` binds the one remaining loopback
  TCP listener, for an authorization-code redirect. Two call sites reach it, both
  `begin_interactive_login` — `providers/aws_login.rs` for `aws-login`, and
  `providers/oauth/mod.rs` for `aws-web-identity` (the provider there is
  `AwsWebIdentityProvider`; the `oauth` credential type is the client-credentials grant and
  binds nothing). Both run inside the daemon, from `server/bootstrap.rs`. A TCP
  port has **no UID boundary** — any local user can connect, and with `callback_port` set
  the port is predictable. Confirm the bind address is loopback and never `0.0.0.0`, that
  PKCE and the `state` parameter are what gate the exchange rather than the port, and that
  the listener dies with the flow that opened it.

### `fs-perms`

- **Order matters.** `fs::write` then `set_permissions` leaves a window where the file is
  `0644` with secrets already in it. Flag write-then-chmod on any secret path; the safe
  shape is create-with-mode (`OpenOptions::mode`) or write to a `0600` temp in the same
  dir and rename.
- `config/mod.rs:176` *validates* mode `0o600` on read while several call sites set it
  best-effort (`let _ =`). Reconcile: a best-effort set whose failure is later caught by a
  validating read is fine; one that is never validated is a gap.
- Check parent-directory modes, not just file modes — `0600` inside a `0777` directory is
  still replaceable. Check symlink following on paths derived from config, and that no path
  is hardcoded (`config::platform` owns OS directories).
- Windows has no `0600`. Where `#[cfg(unix)]` guards a permission call, note what would
  protect the same file on Windows (DPAPI-at-rest, ACLs, or nothing) — but since Windows is
  deferred and ships nowhere, an unguarded path there is a design gap to record, not a live
  finding.

### `unsafe-ffi`

18 `unsafe` blocks across three files; `AGENTS.md` requires a safety comment on each. For
every block, state the invariant and whether it holds:

- **`server/process_tree.rs`** (macOS `proc_listpids`/`proc_pidinfo`) — the classic bug is
  trusting the returned size. `buf_size` from a first call can grow before the second, so
  `actual` may exceed the allocation, and `fds.as_ptr().add(offset)` casts to
  `*const ProcFdInfo` at a computed offset: verify `actual_fd_count` is derived from the
  **actual** returned byte count, not the requested one, and that the final element cannot
  read past the buffer. Check `#[repr(C)]` and field layout against the system headers, and
  the alignment of a `Vec<u8>` reinterpreted as a struct. The fixed `[0u8; 648]`
  `sock_info` buffer is a magic size — confirm it matches `socket_fdinfo` and is not
  overrun.
- **`storage/dpapi.rs`** — `from_raw_parts(output_blob.pbData, cbData)` before checking
  `pbData` for null, or on an error path where the API did not populate the blob, is UB.
  `CryptUnprotectData`'s output is zeroed with `write_bytes` before `LocalFree` (good);
  check `CryptProtectData`'s output blob is freed on **every** path including the error
  return, and that plaintext copies are zeroized.
- **`storage/windows.rs`** — the open CodeQL high (`rust/access-invalid-pointer`,
  `windows.rs:72`) is `LocalFree(HLOCAL(output_blob.pbData))`-shaped: verify the null guard
  precedes every dereference on both success and failure paths of `CredReadW`, and that
  `CredFree` is not reachable with a dangling or already-freed pointer. A null guard was
  added here after the alert was raised — determine whether the alert is now stale or still
  live.

### `service`

`install.rs` renders a launchd plist and shells out to `launchctl`, and covers the Linux systemd
(system) path — apply the same checks to both. Windows Task Scheduler / SCM is deferred with no
owner, so its absence is not a finding.
`serve` takes no flags of its own, so everything baked into `ProgramArguments` is a global
flag; a rendered definition `serve` would reject fails at login, where nobody is watching.

- **Injection.** `render_plist` interpolates `label`, the binary path, and each arg into
  XML through `xml_escape`. The real check is that the escape set matches the
  **interpolation context**: element content (`<string>V</string>`) requires `&` and `<`
  only, so today's `& < >` set is correct there; an attribute value would additionally
  require `"` and `'`. Flag a value interpolated into an attribute with the
  content-only escape, and flag any interpolated value that bypasses `xml_escape` —
  one unescaped `format!` is a plist injection, and a plist controls what runs at login.
  `parse_program_arguments` does ad-hoc string parsing of a plist — treat its input as
  untrusted and check it cannot be steered.
- **Write-path trust.** The plist lands in `~/Library/LaunchAgents`. Confirm the target and
  its parent are not attacker-writable, that an existing plist is not blindly trusted on
  reinstall, and that the binary path recorded is absolute and canonicalized — a relative
  or symlinked path is a persistence hijack.
- **Privilege.** A LaunchAgent runs as the user (correct here — a credential daemon must
  not be a root LaunchDaemon). Flag any move toward `/Library/LaunchDaemons`, a
  system-wide systemd unit, or a `SYSTEM`-context scheduled task, since it would place
  user credentials in a root-owned process and change the whole threat model.
- **Subprocess.** `Command::new("launchctl")` with `.arg()` — no shell, good. Verify no
  code path builds a command string for `sh -c`, and that `PATH` is not attacker-influenced
  for the bare `launchctl` lookup.

### `exec`

`mcp/tools/launch_command.rs` builds an argv from MCP tool input — attacker-adjacent input
if an MCP client is compromised. Verify: `command` stays a `Vec<String>` passed as separate
argv entries (never joined into a shell string), `profile` is validated against known
profiles rather than interpolated into a path, and `--` separates credsd flags from the
target argv so a leading-dash element cannot be absorbed as a credsd flag. Confirm no
credential value lands in the returned `command` array or in `env_overrides` — the harness
is supposed to inject via the environment, not echo secrets back.

### `net`

- TLS must resolve through `default-https-client` (aws-lc-rs). The `rustls` feature on
  `aws-sdk-sso`/`ssooidc` pins rustls 0.21 + rustls-webpki 0.101.7 and reintroduces
  GHSA-82j2-j2ch-gfr8. It was removed deliberately. Flag its return.
- Check that OIDC/SSO endpoints and any redirect target come from validated config, not
  from a server response; that `state`/PKCE values are compared constant-time where they
  authenticate; and that no response field is trusted into a filesystem path.
- SSRF: the proxy is loopback-only by design — verify nothing lets a request choose an
  upstream host.

### `supply-chain`

- `cargo audit --deny warnings`, then reason about what it cannot see: unmaintained crates,
  a crate with a `build.rs` that runs arbitrary code at build time, and duplicate stacks
  (`ring` **and** `aws-lc-rs` are both compiled today via rustls — audit surface, not a
  correctness bug, and the pull is upstream's, not ours).
- Any new dependency in the crypto or IPC path is a TCB expansion; per
  `.agents/rules/minimalism.md` it must justify itself against std and
  already-present crates.

## Report format

Bar for reporting: **a concrete failure scenario** — specific inputs or state leading to a
specific wrong outcome. If you cannot name who does what and what they get, it is not a
finding. Do not report style, do not report "consider hardening," do not pad the list.
An empty findings table is a valid and useful result.

Severity: **CRITICAL** — remote or cross-user credential disclosure, auth bypass, key/nonce
reuse, memory-safety with attacker-controlled data. **HIGH** — local cross-user escalation,
secret written to a world-readable or persistent location, persistence hijack. **MEDIUM** —
requires an unlikely precondition or discloses metadata only. **LOW** — a defense-in-depth
gap you can tie to a real (if narrow) scenario.

Confidence: **CONFIRMED** (traced through the code, precondition verified reachable) or
**PLAUSIBLE** (the shape is wrong but you could not confirm reachability — say what would
confirm it).

```
## Security Review — {diff | audit}

**Scope:** <rev-range and file count | areas audited>
**Tools:** gitleaks <ver> (clean|N hits) · cargo-audit (not installed) · CodeQL (N open)
**Verdict:** N findings (n CRITICAL, n HIGH, ...) — or: no findings

### Findings
| # | Sev | Conf | Area | file:line | Finding | Failure scenario |
|---|-----|------|------|-----------|---------|------------------|

### Detail
#### 1. HIGH/CONFIRMED — <one-line claim> (`file.rs:NN`)
<the defect, the exact scenario, and a fix sketch — 3-6 lines, no lecture>

### Checked and sound
- `encryption.rs` — AES-256-GCM, 12-byte nonce per seal from `SystemRandom`, key zeroized on drop
- <one line per non-trivial area cleared; this is the coverage claim, keep it honest>

### Not covered
- <every area skipped, every tool absent, every claim you could not verify>
```

`Not covered` is mandatory and must be specific. "cargo-audit not installed — no
known-CVE coverage this run" is the kind of gap that must never be implicit.

## Constraints

- **Read-only.** Never fix, never commit, never change a repo or GitHub setting. Report and
  recommend; remediation is the user's call. (Reading via `gh api` is fine; no `-X PATCH`.)
- **Never print a secret value.** Type, location, and length only — the project's own
  no-secret-logging rule applies to the report.
- Do not report findings whose precondition is root on the same machine, or local DoS —
  both are out of scope per `SECURITY.md`.
- Do not report a CodeQL or gitleaks hit without verifying it in the code first. A scanner
  hit relayed unverified is not a finding.
- Distinguish CONFIRMED from PLAUSIBLE honestly. Inflating confidence is worse than
  reporting fewer findings.
- If a finding contradicts a MUST/SHALL criterion in a `docs/specs/*/requirements.md`,
  surface the conflict; do not propose editing the spec (see `AGENTS.md` Spec Coherence).
- For a large `audit`, you may delegate one area per subagent to parallelize if your
  harness supports it, but verify each returned finding yourself before reporting it —
  delegated findings arrive unverified.
