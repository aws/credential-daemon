# Requirements: KKRS Encryption-Key Backend

**Status:** accepted — compiled only with the `kkrs` Cargo feature, which no shipped build
enables (Requirement 6)
**Feature:** `kkrs-encryption-backend`
**Scope:** Linux only. Stores the daemon's AES-256 master key in the kernel
keyring (Kernel Key Retention Service), with reboot detection and recovery.

## Introduction

credsd protects every at-rest secret with a single AES-256-GCM master key. That
key is held by a `SecureStorage` backend: macOS Keychain, Windows DPAPI, or (on
Linux today) a `0600` file. This feature adds a Linux backend that keeps the
master key in the **kernel user keyring** instead of on disk.

The defining property is intentional: kernel keyring keys are **wiped on
reboot**. A KKRS-backed daemon therefore forgets every cached secret across a
reboot, forcing re-authentication. This is a security posture (no long-lived
key on disk), not a bug — but it produces a "reboot surprise" if handled
naively (the daemon would silently mint a new key and every previously sealed
file would fail to decrypt). The bulk of this spec is about detecting the
reboot and turning that surprise into a clear, actionable signal.

Because of the reboot surprise, KKRS is **opt-in only**. It is never chosen by
auto-detection. **Nor is `file`:** as of the `tpm-encryption-backend` feature,
Linux auto-detect returns `tpm` when a usable TPM is present and otherwise
**errors, requiring an explicit backend choice** — it never silently falls back
to `file` or `kkrs`. See "Backend precedence" below.

### Terminology

- **Master key** — the 32-byte AES-256 key in the slot `daemon-encryption-key.<ns>`, where `<ns>` is the home's instance namespace (`storage-backend-per-home` Requirement 5.1).
- **Sealed file** — any at-rest artifact encrypted with the master key. The
  daemon seals every provider type symmetrically under the caller's
  uid-partitioned tree, `callers/<uid>/credentials/<name>/*.enc` (`sso_token.enc`,
  `iam_user.enc`, `oauth_token.enc`, `dpop_key.enc`, `jwt.enc`). (The legacy
  global `credentials/<name>/*.enc` tree is the no-daemon standalone CLI's only.)
- **Boot identity** — a value that uniquely identifies the current boot session
  (primarily `/proc/sys/kernel/random/boot_id`).
- **Sentinel** — a small on-disk file recording the boot identity present when
  the master key was created; survives reboot.

## Requirements

### Requirement 1: Backend availability and selection

**User story:** As a Linux user who wants no long-lived key material on disk, I
want to opt into a kernel-keyring backend, so that my master key exists only in
kernel memory and is gone after a reboot.

#### Acceptance Criteria

1.1. WHEN built with the `kkrs` Cargo feature, the system SHALL provide a storage
     backend named `kkrs` on Linux that stores the master key in the kernel user
     keyring. Without the feature the backend is not compiled (Requirement 6).

1.2. WHEN the user selects `kkrs` explicitly with `--storage-backend kkrs`,
     THEN the system SHALL use the KKRS backend. No environment variable or
     configuration key SHALL select a backend.

1.3. The KKRS backend SHALL NOT be returned by auto-detection under any
     condition. On Linux, auto-detection SHALL return `tpm` when a usable TPM is
     present and otherwise SHALL return a configuration error requiring an
     explicit backend choice; it SHALL NOT silently select `kkrs` or `file`.
     *(Superseded default: earlier drafts had auto-detect fall back to `file`.
     The `tpm-encryption-backend` feature removed that silent fallback so that
     no software-only backend is ever chosen without the operator's explicit
     acknowledgement of its weaker guarantees.)*

1.4. WHEN `kkrs` is selected on a non-Linux platform, THEN the system SHALL
     return a configuration error naming the platform mismatch and SHALL NOT
     fall back to another backend.

1.5. On Linux, auto-detect SHALL resolve only to `tpm` (usable TPM present) or,
     failing that, to a configuration error. `file` and `kkrs` are reachable
     **only** by explicit selection and SHALL NEVER be an auto-detect fallback,
     because each carries a materially different guarantee (`file`: cross-user
     protection via `0600` perms but **no device binding**; `kkrs`: key in
     kernel memory but **wiped on reboot**) and a silent fallback would be a
     silent security/stability posture change. See "Backend precedence" below.

1.6. The `kkrs` backend SHALL report `backend_name()` as `"kkrs"`.

#### Backend precedence (Linux) — normative

`file` and `kkrs` are **explicit opt-in only** and SHALL NEVER be selected as an
auto-detect fallback when a probe fails, because each carries a materially
different security/stability guarantee:

| Backend | Selected by | Guarantee | Distinct failure/limitation |
|---|---|---|---|
| `tpm` | auto-detect (device present) **or** explicit | machine-bound, no cleartext key on disk | unseal fails on TPM clear or replacement |
| `file` | **explicit only** | cross-user protection via `0600` perms | **no device binding** — disk theft yields the key |
| `kkrs` | **explicit only** | key in kernel memory, never on disk | **wiped on reboot** — all cached credentials lost |

Auto-detect returns `tpm` iff a usable TPM is present; otherwise it returns a
configuration error telling the user to pick a backend explicitly. This mirrors
the normative precedence in the `tpm-encryption-backend` spec.

### Requirement 2: Key storage semantics

**User story:** As the daemon, I want keyring reads and writes to behave like the
other backends within a boot session, so that restarts and SSH reconnects keep
working without re-authentication.

#### Acceptance Criteria

2.1. WHEN storing the master key, the system SHALL add a key of type `"user"` to
     the kernel **user keyring** with description `com.amazon.aws.credsd:<key_id>`.

2.2. *For any* `key_id` and key bytes, storing and then retrieving with the same
     `key_id` SHALL return byte-identical bytes (within one boot session).

2.3. Master keys stored via KKRS SHALL remain retrievable across daemon process
     restarts and across SSH disconnect/reconnect for the same UID, as long as
     the machine has not rebooted.

2.4. Master keys stored via KKRS SHALL NOT survive a reboot (the kernel clears
     the user keyring).

2.5. WHEN retrieving a `key_id` that is not present, THEN the system SHALL return
     `DaemonError::Storage`.

2.6. Deleting a key SHALL remove it from the keyring and SHALL be idempotent
     (deleting an absent key is not an error).

2.7. `exists(key_id)` SHALL return `true` if and only if the key is present in
     the user keyring for the current UID.

### Requirement 3: Reboot detection and signaling

**User story:** As a user whose machine rebooted, I want credsd to tell me my
cached credentials are gone and that I must re-authenticate, so that I am not
confronted with confusing decryption failures.

#### Acceptance Criteria

3.1. WHEN the KKRS backend creates (generates and stores) a master key, THEN the
     system SHALL persist a sentinel recording the current boot identity.

3.2. WHEN, at startup with the KKRS backend, the master key is ABSENT from the
     keyring AND a sentinel exists recording a boot identity DIFFERENT from the
     current one, THEN the system SHALL classify the situation as a reboot.

3.3. WHEN a reboot is classified, THEN the system SHALL emit a single clear,
     user-actionable message indicating that cached credentials were cleared by
     a reboot and re-authentication is required (`DaemonError::ReauthRequired`
     semantics), rather than silently minting a new key and deferring the
     failure to later decrypt attempts.

3.4. WHEN a reboot is classified, THEN the system SHALL move the stale sealed
     credential artifacts that the newly generated key cannot decrypt into a
     pruned quarantine directory (rather than deleting them, since they are
     permanently undecryptable after key loss). This covers both the
     uid-partitioned daemon blobs `callers/<uid>/credentials/<name>/*.enc` of
     every provisioned caller AND the legacy global `credentials/<name>/*.enc`
     blobs — the daemon-wide master key protects them all — so that credential
     status reports "no session" rather than "corrupt"/"decrypt failed".

3.5. WHEN the master key is ABSENT AND no sentinel exists AND no other compiled
     backend holds the encryption key, THEN the system SHALL treat this as
     first-run: generate the key and write the sentinel, with no warning.
     WHEN another compiled backend already holds the key, the system SHALL refuse
     with a cross-backend conflict error (see `storage-backend-per-home` spec,
     Req 3) rather than minting a new key.

3.6. WHEN the master key is ABSENT AND the sentinel records the SAME boot
     identity (the key vanished within the current boot — manual `keyctl clear`,
     keyring GC, or quota eviction), THEN the system SHALL apply the same
     recovery as a reboot (signal + purge + regenerate) and SHALL note that no
     reboot was detected.

3.7. The boot identity SHALL be read from `/proc/sys/kernel/random/boot_id`.
     WHEN that source is unavailable, THEN the system SHALL fall back to the
     kernel boot time from `/proc/stat` (`btime`), comparing it against the
     sentinel's recorded boot time.

3.8. The reboot-detection and recovery logic SHALL apply ONLY when the active
     backend is `kkrs`; no other backend's key-init path is affected.

### Requirement 4: Isolation from other backends

**User story:** As a maintainer, I want the KKRS feature to leave existing
backends untouched, so that adding it cannot regress macOS/Windows/file users.

#### Acceptance Criteria

4.1. Selecting `keychain`, `dpapi`, `credential-manager`, `tpm`, or `file` SHALL
     behave exactly as before this feature.

4.2. The sentinel file and reboot-recovery path SHALL never be created or
     consulted for non-KKRS backends.

4.3. The "encryption key protected by filesystem permissions only" warning SHALL
     continue to fire for the `file` backend on Linux and SHALL NOT fire for
     `kkrs`.

### Requirement 5: Security

**User story:** As a security reviewer, I want the KKRS backend to keep secrets
out of logs and off disk, so that the backend does not weaken the daemon's
posture.

#### Acceptance Criteria

5.1. The master key SHALL exist only in kernel keyring memory and process memory
     while KKRS is active; it SHALL NOT be written to disk by this backend.

5.2. The sentinel file SHALL be created `0600` under the `0700` data directory
     and SHALL contain no secret material (the boot identity is not sensitive).

5.3. Key bytes SHALL NOT be logged at any level.

5.4. Keyring key permissions SHALL restrict access to the possessor and owning
     UID (the keyutils default), so other users cannot read the key.

### Requirement 6: Build gating

**User story:** As a release owner, I want the KKRS backend kept out of shipped
builds until its known weaknesses are fixed, so that no install can select it,
while the code stays compiled and tested for the day it ships.

#### Acceptance Criteria

6.1. The KKRS backend, its reboot recovery, and its `linux-keyutils` dependency
     SHALL be compiled only when the `kkrs` Cargo feature is enabled. No
     binary's default feature set and no release build SHALL enable it.

6.2. WHEN `kkrs` is selected in a build without the feature, THEN the system
     SHALL return a configuration error stating that the backend is not
     compiled into this build and naming the `kkrs` feature. It SHALL NOT
     report `kkrs` as an unknown backend and SHALL NOT fall back to another
     backend.

6.3. A build without the feature SHALL NOT list `kkrs` among the valid
     backends in any error message, and SHALL NOT consider it when checking
     whether another backend already holds the master key.

6.4. CI SHALL lint and test the crate with the `kkrs` feature enabled on Linux,
     so that the gated code keeps compiling and its tests keep passing.

6.5. The `kkrs` feature SHALL NOT be enabled in a shipped build until each of
     the following holds, verified on a build with the feature:
     - a master key that is absent in serve (open-only) mode is refused, not
       regenerated; regeneration happens only in an explicit init or reset;
     - a key found in the keyring is adopted only if the daemon can show it
       created that key, so a key another process planted under the same
       description is refused;
     - the daemon's user keyring is not linked into an inherited session
       keyring, so other processes in that session cannot read the key;
     - `exists()` distinguishes "absent" from "present but not readable", so a
       permission failure cannot trigger recovery;
     - selecting `kkrs` requires the same insecure-backend acknowledgment as
       `file`, or a recorded decision that it should not;
     - a missing or corrupt sentinel cannot classify an existing sealed tree as
       a first run.

## Non-Goals and Caveats

- **TPM 2.0 backend** is out of scope here; it is a separate feature
  (`tpm-encryption-backend`) and is the **only** backend auto-detect selects on
  Linux. `file` and `kkrs` are explicit opt-in only and are never an auto-detect
  fallback (see "Backend precedence" above).
- **Long-term IAM material is not spared.** Reboot recovery (3.4) quarantines
  *all* sealed artifacts, including imported IAM long-term keys — not just SSO
  refresh tokens. KKRS is therefore best suited to SSO / short-lived setups; users who
  rely on imported long-term keys will have to re-import them after every
  reboot. This tradeoff is inherent to "wiped on reboot" and is the reason KKRS
  is opt-in.
- **Cross-UID sharing** is not supported; keys are scoped to the daemon's UID.
