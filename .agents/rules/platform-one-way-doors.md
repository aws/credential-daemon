---
name: platform-one-way-doors
description: Find the irreversible platform assumptions in a spec or design before they harden
---

# Platform One-Way Doors

credsd ships on macOS and Linux. Windows support is deliberately deferred: the Credential
Manager and DPAPI backends in `crates/credsd-core/src/storage/{windows,dpapi}.rs` still
exist behind `#[cfg(target_os = "windows")]`, but no CI row builds that target — the matrix
in `.github/workflows/build.yml` is macOS and Linux only — so they are unverified code. The
wider Windows work is parked.

The deferral is a decision, not an oversight, and it is cheap to hold. What is not cheap is
a design that assumed the deferral was permanent. When writing or reviewing a spec or a
design, look for that assumption. The question is not "does this compile on Windows" — it
is "what gets torn out if it lands".

## One-way vs two-way

- **Two-way door** — per-platform work behind a seam that already exists: another module
  beside `storage/macos.rs`, another arm on `storage::Backend`. Costs effort, forecloses
  nothing. Do not surface it.
- **One-way door** — the option is gone, or the seam has to move: a trait contract that
  names a POSIX primitive, a wire format carrying a uid, an invariant only one kernel can
  enforce. Surface it at design time.

## Where they hide here

- **Transport and IPC** — Unix domain sockets and `SO_PEERCRED` peer identity
  (`credsd-daemon/src/server/uds.rs`, `server/routes.rs`). A named pipe authenticates a SID
  against a security descriptor, not a uid against `peer_cred()`: a different identity
  model, not a different API.
- **Paths and permissions** — mode bits *as* the access boundary (`(0o700, 0o600)` for a
  non-system socket, `(0o755, 0o666)` for the system one), plus symlinks and path shape.
  Windows has no mode bits; the equivalent is an ACL, and "world-connectable, uid is the
  gate" does not translate.
- **Process identity and ancestry** — `server/process_tree.rs` walks parents to classify a
  caller. Ancestry is not equally cheap, stable, or reliable on every platform.
- **Service management** — launchd/systemd verbs, unit and plist rendering, socket
  activation, and the system-vs-user domain split (`credsd-daemon/src/install.rs`).
- **Secure storage** — Keychain, DPAPI, TPM, and kernel keyring differ in kind, not degree:
  what the secret is bound to, what survives a reboot, and whether the plaintext may leave
  the boundary at all. A `SecureStorage` contract that quietly assumes one of those
  semantics is a one-way door even though the trait looks portable.

## When you find one

1. Name it in the spec — a "Platform considerations" note, or in the Non-Goals section if
   the spec has one.
2. State whether it is accepted deliberately, and on what reasoning.
3. Record what reversing it would cost: which contract or module gets rewritten.

Do not silently design around it — an abstraction hedging against a platform nobody has
committed to is worse than a documented constraint. Do not block the work either. Name the
door, say which way it swings, and keep going.
