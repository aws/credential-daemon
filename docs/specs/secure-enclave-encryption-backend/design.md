# Design: Secure Enclave Encryption-Key Backend

**Status:** draft (spec phase — approval means "proceed to implementation")
**Feature:** `secure-enclave-encryption-backend`

## Overview

`Backend::SecureEnclave` seals the master key with envelope encryption where the wrapping key
is hardware-resident. A P-256 key-agreement key pair lives in the Secure Enclave; the master
key is encrypted to its public half with ECIES and written to disk; the enclave key itself is
persisted as its opaque `dataRepresentation`. Recovering the master key requires the same
machine's enclave, which is what makes the data directory useless when copied.

The enclave is reached through CryptoKit rather than through keychain APIs. CryptoKit's
`SecureEnclave` types are Swift-only — `CryptoKit.framework` ships a `.swiftmodule` and no
`Headers/` — so the backend links a small Swift shim exporting a C ABI, compiled by a build
script behind an off-by-default feature.

The storage logic and the enclave are separated by the `SeSeam` trait, mirroring the TPM
backend's structure. Everything that can be wrong about file layout, permissions,
get-or-create, and recovery is therefore exercised on every platform in the build matrix,
against a substitute seam, with no enclave present.

## Key Design Decisions

### 1. CryptoKit, not `SecItem`

The `SecItem` route to the Secure Enclave goes through the data protection keychain, which is
available only to code running in a user context. A system install runs as a shell-less
service account with no login session, so that route is structurally unavailable to it — no
entitlement, certificate, or packaging changes that. CryptoKit reaches the enclave with no
keychain, no entitlement, no provisioning profile, and no code signing, which makes it the
route a system daemon can take, and makes the backend available to unsigned builds from
source.

The cost is that CryptoKit's enclave types have no C interface, which is the entire reason the
crate carries a build script. See `docs/design/key-storage-backends.md` for the platform record
behind this decision.

### 2. The envelope construction

Wrapping generates an ephemeral P-256 key pair in software, performs ECDH against the enclave
key's public half, derives an AES-256 key with HKDF-SHA256 using the ephemeral public key as
the shared info, and seals the master key with AES-GCM. The output is the ephemeral public key
in uncompressed X9.63 form followed by the AES-GCM sealed box.

The ephemeral key is software-generated deliberately: only the *recipient* key needs to be
hardware-bound, and minting a second enclave key per wrap would buy nothing. Unwrapping
reverses this with the ECDH half performed inside the enclave, so the plaintext is recoverable
only on the machine whose enclave issued the key blob. AES-GCM authentication means a modified
sealed file fails to open rather than yielding altered plaintext.

The ephemeral public key is fixed-width, which is what lets unwrap split the two parts without
a length prefix.

### 3. One enclave key per key id

Each key id owns its own enclave key rather than sharing one per machine. This keeps deletion
total — there is no shared key to orphan, and no way for deleting one id to strand another —
at the cost of one extra hardware key generation per id, of which there is one.

It also satisfies per-home isolation without an instance namespace: both artifacts live inside
the home, so two homes mint distinct enclave keys as a consequence of the layout rather than of
a naming scheme. This is the `storage-backend-per-home` Requirement 5.3 case, not the 5.1 case
— the backend's secret does not live outside the home.

### 4. The key blob is a capability, not a secret

An enclave-wrapped key blob is not bound to the identity of the code that created it. A process
with a different signing identity, or no signature at all, can rehydrate the blob and ask the
enclave to unwrap with it. Hardware binding therefore buys non-exfiltratability off the device
and **no local access control at all**.

The consequence is that confidentiality of the blob is the entire local boundary: a `0600` file
in a `0700` directory, owned by the account the daemon runs as. This is the same posture as the
TPM backend, for the same reason — a secure element answers "which machine" and has no opinion
on "which principal" — and it is why the modes and the service account are security controls
rather than hygiene.

It is also why the documentation states the guarantee narrowly. "The key cannot be used on
another machine" is true. "The key cannot be stolen" is not: the files are copyable, they are
merely inert elsewhere. "Only credsd can use it" is not: the boundary is the account and the
file mode.

### 5. The protection class is a parameter, defaulting to no session dependency

Which accessibility class the enclave will honour for a given process is the one behaviour of
this backend that depends on the runtime context rather than on the code. A class that becomes
available after first unlock is unavailable to a daemon that must unwrap before any user has
logged in; the class with no session dependency is deprecated. Making the class a parameter
rather than a constant means that constraint is expressed in configuration, and a change in
platform behaviour is answered by a configuration change.

The default is the class with no session dependency, because a boot-start system daemon is the
case the backend exists to serve. The resolved value appears in startup diagnostics so the
posture of a running daemon is observable rather than inferred.

No access-control flags are requested. User presence and biometric confirmation are reachable
only from a user login context and cannot be moved between security contexts, so requiring them
would make a daemon key strictly unusable rather than better protected. Key agreement does not
need the flag that gates signing.

### 6. `SeSeam` separates logic from hardware

```
trait SeSeam {
    fn generate(&self, protection: Protection) -> Result<Vec<u8>>;
    fn wrap(&self, key_blob: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, key_blob: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}
```

`SecureEnclaveStorage<S: SeSeam>` holds the directory, the seam, and the protection class. With
the feature enabled the seam is the Swift-linked implementation; without it, a seam whose every
operation reports why it cannot proceed, so a build lacking the enclave path never appears to
succeed at sealing. Tests use a substitute seam that masks its input, so an assertion that the
sealed file does not contain the plaintext is a statement about the storage layer rather than a
property of the substitute.

### 7. The Swift boundary owns no memory

Swift never allocates for Rust. Each shim function takes a caller-owned output buffer and its
capacity, writes the required length unconditionally — including when the buffer is too small,
so a caller can size a retry — and copies bytes only when they fit. Nothing crosses the boundary
that either side must free, so the `unsafe` blocks on the Rust side have no ownership rule to
get wrong, and every call site has the same shape.

Status codes are negative so they can never be confused with a length, and each maps to a
distinct operator-facing explanation: no enclave on this machine, buffer too small, access
control could not be built, generation failed, the stored key could not be rehydrated, key
agreement failed, seal failed, open failed, invalid input.

The archive links statically, but the Swift runtime stays a system dylib: `-static` applies to
the shim's own code only. That keeps the binary self-contained without embedding a runtime that
ships with the OS.

### 8. Key blob files are validated at open time, not at path-check time

The ownership and mode of the key blob file are security controls (Requirement 2.3), not hygiene.
Checking them at path-resolution time and then opening the file separately leaves a TOCTOU window:
a symlink swap or a permission change between check and open defeats the check.

The implementation opens the file with `O_NOFOLLOW` first, rejects a symlink at that path before
any bytes are read, and validates the owner uid and mode through the open file descriptor's
`fstat`. The check and the read are on the same inode with no window between them.

A key blob that fails either check is refused as a tamper or adoption attempt rather than
corrected or regenerated. This keeps the enforcement symmetric with the creation invariant:
the file was created with `O_CREAT | O_EXCL | O_NOFOLLOW` at mode `0600`, and every subsequent
read asserts those conditions still hold.

`retrieve` is intentionally routed through `key_blob` for the same reason: a direct `read` of
the key path would bypass the O_NOFOLLOW and uid/mode checks, which are only useful if every
read path goes through them.

### 10. Absence and unrecoverability are separate answers

Retrieval answers one of three ways. No sealed master key present is *absence*, which the
key-initialization path treats as a first run. A sealed master key present with no key blob
beside it is *unrecoverable*, reported as such, because reporting absence there would invite the
caller to mint a fresh master key and strand every credential the old one sealed. An enclave
refusal is a third answer, carrying the two explanations an operator can act on.

Nothing in this backend regenerates the master key. The choice to regenerate belongs to the
key-initialization path, which can only make it correctly if absence and damage arrive as
different answers.

### 11. Availability is a capability probe

`is_available()` answers "can *this process* use the enclave", not "does this Mac have one".
Without the feature compiled in it is false, so auto-detection can never select a backend whose
seal would fail. With the feature, it asks the shim, which asks the enclave. An explicit
selection that fails this probe is refused with an error separating "this build cannot reach an
enclave" from "this machine has no enclave", because the remedies differ.

### 12. Custody is a separate axis from the key model

This backend defines the key model — wrap to an enclave key, persist ciphertext — and one
custody choice for the key blob: a file inside the home. The same key model admits other custody
for the blob, which is what a user install can use to add a reader gate the filesystem cannot
provide. Those are separate backends sharing this one's crypto, layout, and recovery behaviour,
and they inherit the properties below unchanged except for who can read the blob.

Keeping the axes separate is what makes "no configuration of credsd stores the master key" a
property of the product rather than of one backend.

## Correctness properties

- The master key never reaches disk, a log, or an error value in plaintext.
- A sealed master key opened on a machine other than the issuing one fails; it does not yield
  wrong plaintext.
- A modified sealed master key fails to open.
- Deleting a key id removes both artifacts, leaving no state that would make a later store
  ambiguous.
- Storing twice under one key id reuses the existing enclave key and replaces only the sealed
  master key.
- Absence, unrecoverability, and enclave refusal are three distinguishable outcomes.
- A build without the enclave feature never reports the backend available and never silently
  substitutes another.
- Both artifacts are `0600` inside a `0700` directory at every point after creation.
- A key blob file opened at read time is validated against the expected uid and mode through the open fd's `fstat`; a file owned by a different uid or with a mode wider than `0600` is refused.
- A symlink at the key blob path is refused at open time via `O_NOFOLLOW`; the read never follows it.

## Error handling

| Condition | Behaviour |
|---|---|
| No sealed master key | Absence reported; key-initialization treats it as a first run |
| Sealed master key, no key blob | Unrecoverable, named as such, with the path that is missing |
| Enclave refuses to unwrap | Error naming the two actionable causes: different machine, or unsatisfiable protection class |
| Enclave absent, backend named explicitly | Refusal distinguishing build-lacks-feature from machine-lacks-enclave |
| Shim output buffer too small | Error stating the required length; never a truncated value |
| Feature enabled, non-macOS target | Build fails naming the target |
| Feature enabled, no Swift toolchain or SDK | Build fails naming what is missing |

## File changes

| File | Role |
|---|---|
| `crates/credsd-core/src/storage/secure_enclave.rs` | Backend, `SeSeam`, protection class, Swift binding, tests |
| `crates/credsd-core/swift/SecureEnclaveShim.swift` | Enclave access behind a C ABI |
| `crates/credsd-core/build.rs` | Compiles and links the shim under the feature |
| `crates/credsd-core/src/storage/mod.rs` | `Backend::SecureEnclave`, parse/name, availability probe, selection, construction |
| `crates/credsd-core/Cargo.toml` | The `secure-enclave` feature |
| `crates/credsd/Cargo.toml`, `crates/credsd-daemon/Cargo.toml` | Feature passthrough |
| `docs/key-security.md` | User-facing statement of the guarantee, in the narrow form Requirement 8 requires |
| `docs/design/key-storage-backends.md` | The platform record this design rests on |

## Alternatives considered and rejected

**The enclave through the keychain.** Creating the enclave key as a keychain item scoped by an
access group would add a reader gate, but the data protection keychain is unavailable to code
outside a user context, so the result is structurally limited to a user install. It cannot serve
the system install this backend exists for, and it makes hardware-backed storage conditional on
a paid signing identity, which forecloses it for builds from source.

**Storing the master key in a keychain item instead of wrapping it.** A keychain item marked
non-migratable is also device-bound, so against an attacker who copies the artifact the two are
comparable. They differ in what a bypass yields: a keychain item hands over the master key,
portable and usable off-device thereafter, while the envelope hands over the ability to ask one
machine's enclave to unwrap. The envelope also makes an omitted non-migratable attribute
non-fatal, and keeps one key model across every custody choice.

**An ephemeral enclave key.** An enclave key that is not persisted cannot unwrap anything after
a restart, which makes the master key unrecoverable by design. Persistence of the key blob is
load-bearing, and the one-key-per-id layout is what provides it.

**Presence or biometric protection.** Rejected rather than deferred; see Decision 5.

**A per-caller key hierarchy.** Deriving a distinct key per caller uid would narrow the blast
radius of a service-account compromise. It does not close it, applies equally to every backend,
and belongs above the key store rather than inside this backend.
