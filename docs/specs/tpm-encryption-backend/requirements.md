# Requirements: TPM 2.0 Encryption-Key Backend

**Status:** accepted
**Feature:** `tpm-encryption-backend`
**Scope:** Linux only. Stores the daemon's AES-256 master key sealed to a
TPM 2.0 device, so the key never exists in cleartext on disk and is bound to the
physical machine.

## Introduction

credsd protects every at-rest secret with a single AES-256-GCM master key held
by a `SecureStorage` backend: macOS Keychain, Windows DPAPI, or (on Linux today)
a `0600` file. This feature adds a Linux backend, `TpmStorage`, that **seals**
the master key to a TPM 2.0 device. The sealed blob lives on disk; the plaintext
key exists only in TPM and process memory, and only after a successful
**unseal**.

The `Backend::Tpm` enum variant and a `/dev/tpmrm0` probe already exist;
`create_storage(Tpm)` currently returns "TPM backend not yet implemented". This
feature implements it.

### What the TPM does and does not provide

A TPM has **no notion of OS users** and **cannot attest the identity of the
calling binary**. Its only "who can call me" control is filesystem permissions
on the device node (`/dev/tpmrm0`, typically `root:tss 0660`). Consequently:

- The TPM provides **at-rest confidentiality and machine binding**: an attacker
  who steals the disk, or copies the sealed blob to another machine, cannot
  recover the key.
- The TPM does **not** provide access control between users on the running
  machine. Authorization — deciding *who may request derived credentials* —
  remains entirely the daemon's job, enforced at the credsd service UID via
  socket permissions and bearer-token auth. The sealed key sits behind that
  boundary; requesting users never touch the TPM or the key.

This separation is the reason credsd runs as a dedicated service user under
`systemd`: the process/UID boundary is the access-control mechanism, and the TPM
is the at-rest mechanism. The two roles must not be conflated.

### Terminology

- **Master key** — the 32-byte AES-256 key in the slot `daemon-encryption-key.<ns>`, where `<ns>` is the home's instance namespace (`storage-backend-per-home` Requirement 5.1).
- **Sealed blob** — the TPM-encrypted form of the master key (the sealed object's
  public + private portions), persisted on disk.
- **SRK** — Storage Root Key: a primary key deterministically derived under the
  TPM's owner hierarchy seed; the parent under which the master key is sealed.
- **Sealing policy** — the TPM policy that must be satisfied to unseal. The
  supported policy is `machine`: empty, so the seal is machine-bound only.
- **PCR 7** — the platform configuration register holding UEFI **Secure Boot
  policy** state (Secure Boot on/off and the PK/KEK/db/dbx key databases). A
  candidate future policy; not supported (3.6).

## Requirements

### Requirement 1: Backend availability and selection

**User story:** As a Linux user with a TPM, I want the daemon to protect its
master key with hardware so that the key never sits in cleartext on disk and
cannot be exfiltrated to another machine.

#### Acceptance Criteria

1.1. The system SHALL provide a storage backend named `tpm` on Linux that seals
     the master key to a TPM 2.0 device via the resource-managed interface
     (`/dev/tpmrm0`).

1.2. WHEN the user selects `tpm` explicitly with `--storage-backend tpm`, THEN
     the system SHALL use the TPM backend. No environment variable or configuration
     key SHALL select a backend.

1.3. Auto-detection on Linux SHALL return `tpm` WHEN and ONLY WHEN a usable
     TPM 2.0 device is present. WHEN no usable TPM is present, auto-detection
     SHALL return a configuration error instructing the user to explicitly
     select a backend; it SHALL NOT silently fall back to `file` or `kkrs`.
     *(See "Backend precedence" below and the matching note in the KKRS spec.)*

1.4. WHEN `tpm` is selected (explicitly or by auto-detect) but the device is
     unusable — no device node, device open fails, or the TPM rejects the
     required commands — THEN the system SHALL return an error naming the
     failure and SHALL NOT fall back to another backend.

1.5. WHEN `tpm` is selected on a non-Linux platform, THEN the system SHALL
     return a configuration error naming the platform mismatch.

1.6. The `tpm` backend SHALL report `backend_name()` as `"tpm"`.

### Requirement 2: Seal / unseal semantics

**User story:** As the daemon, I want sealing and unsealing to behave like the
other backends' store/retrieve so that restarts and reboots keep working without
re-authentication (as long as the sealing policy still holds).

#### Acceptance Criteria

2.1. WHEN storing the master key, the system SHALL seal the plaintext key bytes
     to the TPM under the SRK and SHALL persist the resulting sealed blob to
     `<data_dir>/tpm/<key_id>.sealed` with `0600` permissions under the `0700`
     data directory.

2.2. *For any* `key_id` and key bytes, storing and then retrieving with the same
     `key_id` — with the sealing policy still satisfied — SHALL return
     byte-identical bytes.

2.3. Sealed master keys SHALL remain retrievable across daemon process restarts,
     SSH disconnect/reconnect, **and reboots**, as long as the same TPM is
     present and the sealing policy is still satisfied. *(This is the primary
     posture difference from `kkrs`, whose key is wiped on reboot.)*

2.4. The plaintext master key SHALL NOT be written to disk by this backend at any
     point; only the sealed blob is persisted. **(Validates 5.1.)**

2.5. WHEN retrieving a `key_id` whose sealed blob is absent, THEN the system
     SHALL return `DaemonError::Storage`.

2.6. WHEN retrieving a `key_id` whose sealed blob is present but **unseal fails**
     (policy no longer satisfied, TPM cleared/replaced, or blob unloadable), THEN
     the system SHALL return an error distinguishable from "absent" so the
     key-init path can apply reboot-style recovery (Requirement 3).

2.7. Deleting a key SHALL remove the sealed blob (and any sidecar metadata) and
     SHALL be idempotent (deleting an absent key is not an error).

2.8. `exists(key_id)` SHALL return `true` if and only if the sealed blob is
     present on disk. *(It does not attempt an unseal; presence-of-blob and
     unsealability are distinct — see 2.6.)*

### Requirement 3: Sealing policy and unseal-failure recovery

**User story:** As a user whose TPM state changed (firmware update, Secure Boot
change, TPM clear), I want credsd to tell me my cached credentials are gone and
that I must re-authenticate, rather than confront me with decryption failures.

#### Acceptance Criteria

3.1. The system SHALL seal under the **`machine`** policy: under the SRK with an
     **empty** policy, so unseal succeeds on the same TPM regardless of boot
     state. The policy SHALL be recorded in a `0600` sidecar
     (`<data_dir>/tpm/<key_id>.meta`) alongside the sealed blob, for diagnostics
     and drift detection. The sidecar SHALL contain no secret material.

3.2. WHEN sealing, the system SHALL persist the policy identifier, so that a
     blob sealed under a different policy is recognized as such rather than
     unsealed as if it were machine-bound.

3.3. WHEN an unseal fails (2.6), THEN the system SHALL refuse to start and SHALL
     emit a single clear, operator-actionable error message naming the likely cause
     (cleared or replaced TPM; a blob sealed under a policy the build does not
     support; inaccessible device node) and the explicit recovery command
     (`credsd init --reset --storage-backend tpm`). The system SHALL NOT automatically
     re-seal a new key — recovery is always an explicit operator step so that
     credential loss is never silent.

3.4. WHEN the operator runs `credsd init --reset --storage-backend tpm`, THEN the system
     SHALL move the stale sealed credential artifacts that the old key can no longer
     decrypt — under both the daemon tree `<data_dir>/callers/*/credentials/*/` and
     the legacy standalone tree `<data_dir>/credentials/*/` — into a pruned
     quarantine directory (rather than deleting them, since they are permanently
     undecryptable after the TPM reset), so credential status reports "no session"
     rather than "corrupt"/"decrypt failed", then generate and seal a fresh master
     key and rewrite the sidecar.

3.5. WHEN no sealed blob exists (first run) AND no other compiled backend holds
     the encryption key, THEN the system SHALL generate the key, seal it, write
     the blob and sidecar, with no warning.
     WHEN another compiled backend already holds the key, the system SHALL refuse
     with a cross-backend conflict error (see `storage-backend-per-home` spec,
     Req 3) rather than minting a new key.

3.6. The sealing policy SHALL NOT be selectable. The system SHALL NOT read the
     policy from the environment: WHEN `CREDSD_TPM_POLICY` is set, THEN the
     system SHALL refuse to start the `tpm` backend with an error naming the
     variable, rather than ignore it, because an operator who set it expects a
     binding the key does not have.

3.7. WHEN a sidecar names a policy other than `machine`, THEN retrieve SHALL fail,
     the blob SHALL count as present-but-unsealable (2.6), and recovery SHALL follow
     3.3. The system SHALL NOT unseal it under `machine` or any other policy.

3.8. The design SHALL document the exact conditions that break unsealing under
     `machine`, and under `pcr7` as the candidate further policy (see design
     "PCR 7 vs. machine-bound").

### Requirement 4: Isolation from other backends

**User story:** As a maintainer, I want the TPM feature to leave existing
backends untouched.

#### Acceptance Criteria

4.1. Selecting `keychain`, `dpapi`, `credential-manager`, `kkrs`, or `file` SHALL
     behave exactly as before this feature (subject to the precedence change in
     1.3, which applies to auto-detect only, not to explicit selection).

4.2. The TPM sealed blob, sidecar, and unseal-failure recovery path SHALL never
     be created or consulted for non-TPM backends.

4.3. The "encryption key protected by filesystem permissions only" warning SHALL
     continue to fire for the `file` backend on Linux and SHALL NOT fire for
     `tpm`.

### Requirement 5: Security

**User story:** As a security reviewer, I want the TPM backend to keep secrets
off disk and out of logs.

#### Acceptance Criteria

5.1. The master key SHALL exist in cleartext only in TPM memory and process
     memory; only the sealed blob is persisted. Plaintext key bytes held in
     process memory SHALL be zeroized on drop (existing `Zeroize` convention).

5.2. The sealed blob and sidecar SHALL be created `0600` under the `0700` data
     directory.

5.3. Key bytes SHALL NOT be logged at any level. Sealed-blob bytes and TPM
     handles SHALL NOT be logged.

5.4. The backend SHALL rely on the OS to restrict `/dev/tpmrm0` access
     (device-node permissions / `tss` group) as the only "who can use the TPM"
     control; it SHALL document that any process at the credsd service UID (or
     root, or in the `tss` group) can drive the TPM, which is why credsd runs as
     a dedicated, minimal-surface service user.

## Backend precedence (Linux) — normative

The backend is chosen by `--storage-backend` or, when that flag is absent, by
auto-detect. No environment variable or configuration key selects it: any
process running as the daemon's uid can set those, so a backend chosen that way
would be a downgrade the operator never made.

Auto-detect (`--storage-backend` absent) resolves as follows. `file` and `kkrs` are **explicit opt-in only** and are **never**
selected as a fallback when a probe fails, because each carries a materially
different security/stability guarantee and a silent fallback would be a silent
posture change:

| Backend | Selected by | Guarantee | Distinct failure/limitation |
|---|---|---|---|
| `tpm` | auto-detect (device present) **or** explicit | machine-bound, no cleartext key on disk | unseal fails on TPM clear or replacement |
| `file` | **explicit only** | cross-user protection via `0600` perms | **no device binding** — disk theft yields the key |
| `kkrs` | **explicit only**, in builds with the `kkrs` feature (no shipped build has it) | key in kernel memory, never on disk | **wiped on reboot** — all cached credentials lost |

- Auto-detect returns `tpm` iff a usable TPM is present; otherwise it returns a
  configuration error telling the user to pick a backend explicitly (1.3).
- Explicitly selecting `tpm` on a machine without a usable TPM is an error, not a
  fallback (1.4).

## Non-Goals and Caveats

- **Per-user or per-binary TPM access control** is out of scope and not
  achievable at the TPM layer; the UID boundary is the access-control mechanism.
- **Measured-boot attestation of the kernel/initramfs** (PCR 4/8/9, IMA) is out
  of scope.
- **Secure Boot binding (`pcr7`)** is deferred until the policy-session path is
  validated on a real TPM. When it is offered it SHALL be chosen explicitly at
  key initialization, with an operation that re-wraps an existing key under the
  new policy, and never through the environment or another implicit path. It
  binds only to Secure Boot *policy*, not to the measured kernel; it would
  detect Secure-Boot tampering, not a signed-but-malicious kernel.
- **TPM auth values / password-protected sealing** are out of scope for v1: the
  secret would need to live on disk readable by credsd, reintroducing the
  `file`-backend exposure as the weakest link. Machine binding + the UID
  boundary is the v1 posture. Revisit only with a concrete threat that the UID
  boundary does not already cover.
- **NVRAM-resident keys** (as opposed to on-disk sealed blobs) are out of scope.
