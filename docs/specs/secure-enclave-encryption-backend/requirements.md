# Requirements: Secure Enclave Encryption-Key Backend

**Status:** draft (spec phase — approval means "proceed to implementation")
**Feature:** `secure-enclave-encryption-backend`

## Introduction

The `secure-enclave` backend protects the master key on macOS by wrapping it to a P-256 key
pair resident in the Secure Enclave. It is the macOS backend available to a system install:
the daemon runs as the shell-less `credsd` service account, which has no login session and
therefore no keychain, and the Secure Enclave is reachable through CryptoKit without a
keychain, an entitlement, a provisioning profile, or code signing.

The backend never stores the master key. It stores two artifacts: an opaque representation of
the enclave key, and the master key encrypted to that enclave key. Neither is secret-bearing
on its own and neither is usable on another machine.

The platform evidence behind these choices — why the keychain routes are unavailable to a
daemon, what Apple has and has not committed to, and what an enclave-wrapped blob does and
does not bind to — is recorded in `docs/design/key-storage-backends.md`.

## Terminology

- **Master key** — the single AES-256 key that seals every credential under a home, kept
  in the slot `daemon-encryption-key.<ns>`, where `<ns>` is the home's instance namespace (`storage-backend-per-home` Requirement 5.1).
- **Enclave key** — a P-256 key-agreement key pair generated inside the Secure Enclave. The
  private half never leaves the enclave and cannot be read by any software, including the
  operating system.
- **Key blob** — the enclave key's `dataRepresentation`: an opaque, machine-bound handle that
  only the issuing machine's enclave can rehydrate. Not the private key, and not a secret on
  its own.
- **Sealed master key** — the master key encrypted to the enclave key's public half.
- **Envelope** — the pairing of the two: the master key is wrapped rather than stored.
- **Seam** — the trait boundary between the backend's storage logic and the enclave itself,
  so the logic is exercised without enclave hardware.
- **Protection class** — the keychain accessibility class the enclave key is created under,
  which determines when the enclave will perform operations with it.
- **Instance namespace (`ns`)** — the per-home discriminator defined by
  `docs/specs/storage-backend-per-home/`.

## Requirements

### Requirement 1: The master key is wrapped, never stored

**As** an operator, **I want** the master key to exist on disk only as ciphertext, **so that**
copying the data directory yields nothing usable.

1.1. The system SHALL encrypt the master key to the enclave key and persist only the
     resulting ciphertext.

1.2. The system SHALL NOT write the master key, or any value from which the master key can be
     derived without the enclave, to any file, log, environment variable, or error message.

1.3. Plaintext master key bytes SHALL exist only in process memory for the duration of a
     single wrap or unwrap, and SHALL be zeroized when that use ends.

1.4. The wrap SHALL be authenticated, so that a modified sealed master key fails to open
     rather than yielding altered plaintext.

### Requirement 2: Two artifacts, both private, inside the home

**As** an operator, **I want** the on-disk footprint to be explicit and least-privileged,
**so that** the access boundary is auditable.

2.1. The system SHALL persist the key blob and the sealed master key as separate files under
     the home, in a directory dedicated to this backend.

2.2. Both files SHALL be created with mode `0600`, in a directory with mode `0700`, owned by
     the account the daemon runs as.

2.3. The file modes and the owning account SHALL be treated as security controls: any change
     widening who can read the backend's directory is a change to the system's security
     posture.

2.4. Because the key blob's confidentiality is the entire local access boundary (Requirement
     8), the system SHALL NOT rely on code identity, signing state, or process ancestry to
     restrict use of the enclave key.

2.5. WHEN the key blob file is present, the system SHALL validate the file's owning uid and
     mode at read time, before using its contents, and SHALL refuse to use a file whose owner
     is not the current process's uid or whose mode is wider than `0600`. A file that passes
     neither condition SHALL be treated as a tamper or adoption attempt, not as a recoverable
     state.

2.6. The system SHALL open the key blob file with `O_NOFOLLOW` so that a symlink planted at
     the key blob path cannot redirect the read to an attacker-chosen file. A path that
     resolves as a symlink SHALL be treated as a tamper or adoption attempt.

### Requirement 3: A missing key and an unrecoverable key are different outcomes

**As** an operator, **I want** a first run distinguished from a damaged state, **because**
confusing them destroys credentials.

3.1. WHEN no sealed master key is present, THEN retrieval SHALL report absence, so the
     key-initialization path treats it as a first run.

3.2. WHEN a sealed master key is present but its key blob is absent, THEN retrieval SHALL
     report the state as unrecoverable and SHALL NOT report absence.

3.3. WHEN the enclave declines to unwrap, THEN the error SHALL name the two explanations an
     operator can act on: a key blob issued by a different machine, or a protection class the
     running process cannot satisfy.

3.4. The system SHALL NOT regenerate the master key in response to any condition in 3.2 or
     3.3.

### Requirement 4: Availability is a capability probe, not a hardware probe

**As** an operator, **I want** backend selection to reflect what this process can actually
do, **so that** a selected backend never fails at first use.

4.1. The system SHALL report the backend available only when the running binary can reach an
     enclave — the enclave-linked code is compiled in, the host has an enclave, and the
     enclave responds.

4.2. A build without the enclave-linked code SHALL report the backend unavailable.

4.3. Auto-detection SHALL NOT select this backend when 4.1 does not hold.

4.4. WHEN the backend is named explicitly but 4.1 does not hold, THEN the system SHALL refuse
     with an error distinguishing "this build cannot reach an enclave" from "this machine has
     no enclave", and SHALL NOT substitute another backend.

4.5. On macOS, auto-detection SHALL select `data-protection-keychain` when it is available,
     else this backend when 4.1 holds, and otherwise SHALL fail with a configuration error. It
     SHALL NOT select `file`, which is used only when named with `--storage-backend`.
     (AMENDED 2026-10-07: previously excluded `legacy-keychain`, which `mac-pkg-installation`
     Requirement 7.6 removes from every build. `file` takes its place as the one macOS backend
     auto-detection must never fall to; it exists on macOS only in a build that opts in.)

### Requirement 5: The protection class is explicit and suits a daemon

**As** an operator running a boot-start daemon, **I want** the enclave key usable when the
daemon runs, **because** a class tied to a user session makes the key unusable.

5.1. The enclave key SHALL be created under a protection class with no dependency on a login
     session.

5.2. The protection class SHALL be configurable, and its value SHALL be recorded in the
     daemon's startup diagnostics.

5.3. The system SHALL NOT request user presence, biometric, or passcode confirmation for
     enclave operations.

5.4. WHEN the enclave declines an operation because the protection class cannot be satisfied,
     THEN the error SHALL say so distinctly from a wrong-machine failure.

### Requirement 6: The storage logic is exercised without enclave hardware

**As** a contributor on any platform, **I want** the backend's logic under test, **so that**
correctness does not depend on a Mac being present.

6.1. The enclave operations SHALL sit behind a seam, and the backend's file layout,
     permissions, get-or-create, and recovery behavior SHALL be tested against a substitute
     implementation of that seam.

6.2. The tests in 6.1 SHALL run on every platform in the build matrix and SHALL NOT require
     the enclave-linked code to be compiled.

6.3. A test exercising real enclave hardware SHALL exist, SHALL be excluded from default test
     runs, and SHALL assert that neither persisted artifact contains the master key.

### Requirement 7: One home's key material is isolated from another's

**As** a developer running more than one home, **I want** each home's key material distinct,
**because** shared key material makes filesystem isolation a fiction.

7.1. Both artifacts SHALL live inside the home, satisfying
     `storage-backend-per-home` Requirement 5.3 without an instance namespace.

7.2. The system SHALL NOT use any machine-global, home-independent handle or identifier for
     the enclave key.

7.3. Each home SHALL hold its own enclave key, so that destroying one home's artifacts
     leaves another home's ability to unwrap intact.

### Requirement 8: The blob is a capability, and the system says so

**As** a security reviewer, **I want** the backend's actual guarantee stated, **so that** it
is not credited with protection it does not provide.

8.1. The system's documentation SHALL state that hardware binding means the key cannot be
     used on another machine, and SHALL NOT claim the key cannot be copied.

8.2. The system's documentation SHALL state that any process able to read the key blob can
     ask the enclave to unwrap with it, and SHALL NOT claim the enclave restricts use to
     credsd or to signed code.

8.3. The system SHALL NOT present hardware binding as a property verifiable by a remote
     service.

### Requirement 9: Building the enclave path is on by default on macOS and fails loudly

**As** a contributor building credsd on a Mac, **I want** a default build to produce a daemon I
can actually install, **so that** the supported path needs no feature flag to find.

9.1. The enclave-linked code SHALL be behind a build feature that is in the default set. A
     default build for a macOS target SHALL invoke a Swift toolchain; a default build for any
     other target SHALL NOT.
     (AMENDED 2026-10-27: previously off by default, so that a contributor without a Swift
     toolchain paid nothing. That traded the wrong way: a source build has no Apple signing
     identity, so the enclave is the only hardware-backed keystore it can reach, and
     `mac-pkg-installation` Requirement 7.2 confines a user-scoped install to the data
     protection keychain. A default build was therefore a daemon that could install nothing on
     macOS, while the toolchain in question ships with the Command Line Tools. The cost moves
     to the one build that does not need it — see 9.4.)

9.2. WHEN the feature is enabled for a non-macOS target, THEN the build SHALL skip the
     enclave-linked code and succeed, producing a binary without the backend.
     (AMENDED 2026-10-27: previously a hard error naming the target, so that a build which
     asked for hardware-backed storage could not silently lack it. A default feature cannot
     error on the targets it is not for; the guarantee it protected is kept by Requirement 4.2
     — a build without the enclave-linked code reports the backend unavailable — and by the
     backend never being compiled off macOS, so there is nothing to select and nothing to fall
     back to.)

9.3. WHEN the feature is enabled for a macOS target and the toolchain or SDK is unavailable,
     THEN the build SHALL fail with an error identifying which is missing.

9.4. The official signed release SHALL be built without this feature, so the released daemon
     compiles the data protection keychain alone. The released client SHALL keep it, since it
     is what signs a presence challenge with Touch ID.
     (ADDED 2026-10-27: the release's supported path is a user-scoped install, and a
     LaunchDaemon can never reach the keychain that install depends on. An enclave compiled
     into the released daemon would make `sudo credsd install` resolve a backend and look
     supported, which is the hole 7.6 of `mac-pkg-installation` closes by subtraction.)

## Non-Goals

- **Device binding and remote attestation.** The Secure Enclave offers no equivalent to
  `TPM2_Certify`, so hardware residency cannot be proven to a remote verifier from an
  unenrolled daemon. This backend's guarantee is local and self-verifying: a wrong machine
  fails to unwrap.
- **Keychain custody of the key blob.** Storing the blob in the legacy or data protection
  keychain, which adds a reader gate in a user install, is a separate backend with its own
  spec. This spec covers the in-home file custody that a system install requires.
- **Hardware without an enclave.** Macs with no Secure Enclave have no envelope available and
  fall to an explicitly selected backend.
- **User presence and biometrics.** Excluded by Requirement 5.3, not deferred: presence
  confirmation is unavailable to a daemon and would make the key unusable rather than better
  protected.
- **Windows.** No enclave analogue is in scope; see Platform considerations.

## Platform considerations

**The backend is macOS-only by nature, behind a seam that already exists.** It is another arm
on `storage::Backend` and another module beside `storage/macos.rs` — a two-way door. Adding a
platform costs a module, not a redesign.

**One-way door, accepted: the guarantee depends on an undocumented Apple path.** Reaching the
enclave without a keychain is not documented by Apple and carries no compatibility promise. If
it stops working, the master key becomes unrecoverable and **every credential sealed under it is
lost** — the bytes remain on disk but nothing can decrypt them again, which is data loss
whatever the file count says. The recovery is a full re-bootstrap, and its cost is not uniform:
a credential whose seed is re-derivable from an issuer (SSO, OAuth, aws-web-identity, aws-login) costs one
re-authentication, while a secret the user supplied by hand (`static-secret`, a long-term IAM
key) is gone and must be reissued at its provider. That cost is accepted — hardware-bound key
material is a deliberate project goal, and a key that cannot leave the machine cannot be
recovered off it either — but it is the cost, not zero.

What Requirements 3.3 and 3.4 buy here is not preservation, it is **visibility**: the daemon
refuses and says which of two causes applies, rather than silently minting a fresh master key
and continuing to serve a subset of credentials while the rest fail without explanation. The
artifacts stay in place because a loud failure with its evidence intact is worth more than a
tidy one. Reversing the dependency costs this backend, not the `SecureStorage` contract.

**One-way door, accepted: the protection class with no session dependency is deprecated.** A
class Apple has deprecated is the only one a boot-start daemon can rely on. If it is withdrawn,
a daemon that must unwrap before any login loses this backend; a daemon whose first use follows
a login does not. The loss is the same shape as above wherever it bites — an unrecoverable
master key and a re-bootstrap — so Requirement 5.2 keeps the class configurable, which makes the
fallback a configuration change rather than a code change *and* lets an operator move off the
class before it is withdrawn rather than after.

**Not a door: mode bits as the access boundary.** Requirement 2.2 uses POSIX modes, which do
not translate to Windows ACLs — but this backend does not exist on Windows, so nothing is
foreclosed. The equivalent statement for a future platform is that the store protecting the
blob is the boundary, whatever that store is.
