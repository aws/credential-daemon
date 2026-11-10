# Key Storage Backends — Design Record

Why each encryption-key storage backend has the posture it has, what the platforms allow,
and what is still unsettled. **Audience: maintainers and security reviewers.**

For the user-facing statement of what protects a given install, see
[`docs/key-security.md`](../key-security.md). That document describes the target state in
plain terms and makes no claims this one does not support. This one carries the evidence,
the defects, and the open questions; keep them here rather than there.

## Scope

This document is about **the master key** — the single AES-256 key, stored per home under the
slot `daemon-encryption-key.<ns>` (`<ns>` is the home's instance namespace), that `EncryptionService` uses to seal every credential
at rest. It covers where that key lives, what protects it, and what an attacker needs
in order to use it.

It is not about the credentials themselves (see `docs/specs/credential-retrieval-api/`),
nor about who may *ask* the daemon for a credential. That is a separate boundary which
happens to matter here, because on some platforms it is the *only* boundary.

It is also not about **device binding** — proving to a remote service that a key is
hardware-resident. That is a different property with different mechanisms; see
"Hardware binding is not attested residency" below for why the two must not be conflated.

## Reading this document

Backend posture is split into **current state** and **target state**, because they differ
materially on macOS and the difference is the point. Current state describes what a build
of `main` does today, including defects. Target state describes where the design is going
and is not yet true. The platform constraint section between them is neither — it is a
property of macOS that both states must live with.

## The three properties

Every backend is a different point in the same three-dimensional space. Keeping the axes
separate is what makes the platform tradeoffs legible — most confusion about "is this
secure" comes from collapsing them.

**Hardware binding.** The key cannot be extracted from the machine. A copy of the disk,
or of the daemon's data directory, does not yield a usable key. Enforced by a secure
element (Secure Enclave, TPM) that performs the unwrap and never emits the wrapping key.

**Cross-user reach.** The key is usable by a process running as one uid on behalf of
callers running as *other* uids. A daemon serving every local user needs this; a per-user
agent does not.

**Identity-based authorization.** The key store itself decides *which* principal may
unwrap, and refuses the others. Distinct from hardware binding: a secure element can
guarantee "only on this machine" while having no opinion whatsoever about "only for this
user".

A backend with hardware binding but no identity-based authorization protects against a
stolen disk and not at all against a local attacker who reaches the right uid. That
distinction is the subject of most of this document.

### Hardware binding is not attested residency

"Hardware binding" above means exactly one thing: **the key cannot be used on another
machine.** It does not mean a remote party can verify that. Those are separate properties,
and only the first is achievable here.

A TPM can produce the second: `TPM2_Certify` has one key certify another object's name and
attributes, signed by an attestation key chaining to a manufacturer-issued EK certificate,
so a remote verifier learns that a specific public key's private half is resident in a
genuine TPM. **The Secure Enclave has no analogue.** There is no `SecKeyCertify`; no
CryptoKit `SecureEnclave` API emits an attestation; and `kSecAttrTokenIDSecureEnclave` is a
local attribute the OS asserts to itself, not a portable claim. Apple provides attested
residency only through App Attest (App ID plus entitlement) and MDM Managed Device
Attestation (enrollment plus ACME) — neither reachable from an unenrolled daemon.

The consequence for design: an SE or TPM backend lets *credsd* be certain the key is
machine-bound, because a wrong machine simply fails to unwrap — the enclave is the verifier
and a failed unwrap is the proof. It does not let *AWS*, or any other remote party, be
certain of anything. Any future device-binding work should treat this as a hard constraint
and distinguish three claims that get conflated:

| | Claim | Verifier | Needs |
|---|---|---|---|
| A | The key cannot be used on another machine | the device itself, by construction | SE or TPM — **this document's subject** |
| B | The peer holds the key the service enrolled | the remote service, against its own record | a persistent key and a service that checks a signature |
| C | The key demonstrably lives in genuine hardware | the remote service, against a root CA | App Attest or MDM; no self-rooted option exists |

A alone means copied files are useless. B alone means a copied *key* still authenticates
from anywhere. A+B is what "stolen credentials are useless off the device" actually
requires, and it needs no Apple gate. C is the only tier that is verified rather than
trusted, and on macOS it is narrow and enterprise-dependent.

---

# Current state

## At a glance

| Backend | Platform | Key at rest | Hardware binding | Who can unwrap | Identity authz | Status on `main` |
|---|---|---|---|---|---|---|
| `keychain` | macOS | wrapped in a login keychain | no | the owning login account, keychain unlocked | keychain ACL, account-scoped | shipped; auto-detected unconditionally (defect) |
| `tpm` | Linux | sealed blob on disk (`0600`) | **yes** (TPM 2.0) | anyone who can open `/dev/tpmrm0` | **none** | shipped; device seam built into the `-tpm` Linux artifacts only |
| `dpapi` | Windows | DPAPI blob on disk | no | the service account, on this machine | Windows account scope | shipped; auto-detected |
| `credential-manager` | Windows | Credential Manager vault | no | the service account, interactive logon | Windows account scope | shipped; explicit only |
| `file` | all | **plaintext** key file (`0600`) | no | the owning uid, and root | filesystem permissions | shipped; explicit only |
| `kkrs` | Linux | kernel keyring, never on disk | no | the owning uid (keyutils default) | kernel keyring, uid-scoped | on `main` behind the `kkrs` feature; in no published build |
| `secure-enclave` | macOS | ECIES blob on disk, SE-wrapped | **yes** (SE) | anyone who can read the blob | **none** | prototyped only; the prototype takes a different (Path A) design |

`file` and `kkrs` are reachable only by explicit selection. Auto-detect never falls back
to them: each carries a materially different guarantee, and a silent fallback would be a
silent posture change. On Linux, auto-detect resolves to `tpm` or to a configuration
error — never to a weaker backend.

## The shared architecture

The posture of any backend is only meaningful against the rest of the system, which is
identical on every platform.

**One master key, envelope encryption.** The master key is generated once and handed to
`SecureStorage`. Credentials are sealed individually with AES-256-GCM under that key and
written to `callers/<uid>/credentials/<name>/`. Plaintext key bytes exist only in secure-
element or process memory and are zeroized on drop.

**One daemon, many callers.** A system install runs as a dedicated, shell-less service
account (`credsd`, `UserShell=/usr/bin/false`, `NFSHomeDirectory=/var/empty`). Every
OS-level protection on the master key is therefore scoped to *that account* — not to the
calling user. Separation between callers is enforced by the daemon in software, above the
key store.

**Authorization is the peer uid, not the key store.** The socket is deliberately
world-connectable (`SockPathMode`/`SocketMode` `0666`): one daemon serves many client uids
and no OS group enumerates them, so a restrictive mode would deny every ordinary uid
rather than the wrong ones. A connection is not a grant. The sole gate is deny-by-absence
on `callers/<uid>/owner`, keyed to the kernel-reported peer uid from `SO_PEERCRED`, with
the recorded username re-checked against `getpwuid(uid)` to catch uid reuse.

This is the load-bearing consequence: **an attacker who reaches the `credsd` uid has the
master key on every platform**, because the key store's own access control is scoped no
more finely than that account. Hardware binding raises the cost of *offline* attacks. It
does nothing about that one.

## macOS

`KeychainStorage` stores the master key as a generic password — service
`aws.identity.credsd`, account `daemon-encryption-key.<ns>` — through
`security_framework::passwords`, which issues `SecItemAdd`/`SecItemCopyMatching` against
the **legacy, file-based keychain**. There is no Secure Enclave involvement and no
hardware binding: the key is wrapped by a key derived from the owning account's password,
in a file on disk.

**This is a consequence of signing, not a free choice of API.** The data protection
keychain — and therefore the Secure Enclave *as reached through the keychain* — is gated
behind a `keychain-access-groups` entitlement, which requires a provisioning profile issued
against a real team identity. An unsigned or ad-hoc-signed build cannot hold that
entitlement, so the legacy keychain is the only store it can reach. (A second route to the
Secure Enclave exists that bypasses the keychain and its entitlement entirely; see "The
macOS constraint", Path C.) The gate is observable in the Path A prototype: every SE key
there is created
with `kSecAttrAccessGroup=aws.identity.credsd`, and `SecKeyCreateRandomKey` returns
`errSecMissingEntitlement` for ad-hoc or unsigned binaries; the `spikes/sep-probe` bundle
that does work carries an embedded provisioning profile granting
`keychain-access-groups: [4VU7CJK5G7.aws.identity.credsd]` under team ID `4VU7CJK5G7`.
Reaching the data protection keychain for a *generic password* item is the same documented
entitlement gate, though only the SE key path has been measured here.

### Defect: unconditional keychain selection

`auto_detect()` returns `Ok(Backend::Keychain)` on macOS unconditionally — it does not
consider the install shape, the signing state of the binary, or whether a usable keychain
exists. This is a bug, not a design. It is wrong in the common case: the default install
is a `/Library/LaunchDaemons` plist running as `credsd`, an account with no home directory
and therefore no login keychain and no unlock event.

What keeps it from becoming a silent failure is the probe. `create_storage` exercises the
backend with a real store/delete round-trip before returning it, and on failure emits a
configuration error steering the operator to a user-scoped install or to `file`. A
Keychain probe failure returns `Err` rather than silently degrading to `FileStorage`. The
result is a correct refusal arrived at by accident: the selection is wrong, and a separate
mechanism catches it.

Whether the Keychain backend can work at all under a LaunchDaemon is **not established** —
testing has been inconclusive.

### Residual posture

- The key is wrapped, not hardware-bound. Disk theft plus the account password yields it;
  FileVault is the control that makes that combination hard, and FileVault is a whole-disk
  property the daemon does not own.
- Keychain ACLs bind the item to the owning account, not to the credsd binary. Any process
  running as that account can read it.
- `kSecAttrAccessible*` protection classes are meaningless in a daemon context: there is
  no unlock event for them to gate on.

## Linux

`TpmStorage` seals the master key to a TPM 2.0 device. Only the sealed blob and a
non-secret policy sidecar are persisted, `0600` inside a `0700` data directory; the
plaintext exists only in TPM and process memory. The sidecar records the policy the blob
was sealed under — a present blob with an unreadable sidecar, or one recording a policy
the build does not support, is treated as unsealable and routed to recovery rather than
guessed at.

The one policy is `machine` (empty policy), which unseals on the same TPM regardless of
boot state, and it is not configurable. Binding to PCR 7, the UEFI Secure Boot policy, is
deferred until it is validated on real hardware, and would be chosen at key
initialization with an explicit re-wrap; see the
[TPM backend spec](../specs/tpm-encryption-backend/design.md).

All TPM logic — policy, sidecar, recovery, backend wiring — is compiled and unit-tested on
`main`. The `tss-esapi` device seam is behind the `tpm` feature, because it links the system
`tpm2-tss` C libraries and a binary carrying it does not start on a host without them. The
feature is therefore off in a default build and on in the `-tpm` Linux release artifacts,
one per AL2023 and Ubuntu architecture (AL2 has no variant); see
[`tpm-linux-artifact.md`](tpm-linux-artifact.md). Without the feature, seal and unseal
return a clear "requires the `tpm` feature" error. Note that `Backend::Tpm.is_available()`
probes only for the existence of `/dev/tpmrm0` and not for the feature, so on a default
build on TPM-equipped hardware auto-detect selects `tpm` and the failure surfaces at first
store rather than at selection.

### Hardware binding: yes

This is the one backend in the set that genuinely has it. The blob is useless on any other
machine, and a stolen disk yields nothing. Unseal failure is a real operational mode — TPM
clear or replacement — so the key-init path regenerates
and then purges the sealed credential artifacts the new key can no longer decrypt.

### The authorization gap

**A TPM has no notion of OS identity.** Sealing proves *which machine*; it says nothing
about *which principal*. The backend relies on device-node permissions on `/dev/tpmrm0`
(the `tss` group) as the only "who may use the TPM" control, which means any process
running as the credsd service uid — or as root, or in the `tss` group — can drive the
unseal. Per-user or per-binary TPM access control is not achievable at the TPM layer and
is explicitly out of scope.

TPM auth values would close part of this, and are deliberately excluded: the auth secret
would have to live on disk readable by credsd, reintroducing the `file` backend's exposure
as the weakest link in the chain. Binding plus the uid boundary is the accepted posture;
the auth-value question is reopened only against a concrete threat the uid boundary does
not already cover.

### Which is why the uid boundary is the security boundary

The real access-control mechanism for the master key on Linux is **the POSIX uid**, and
the TPM is a disk-theft and machine-cloning control layered on top of it. This is why the
daemon runs as a dedicated, minimal-surface service account rather than as root or as the
invoking user, and why the surface reachable at that uid — the socket, the config parser,
the credential store — is where hardening effort belongs.

| Threat | TPM binding | uid boundary |
|---|---|---|
| Stolen disk / backup image | **blocks** | no help |
| Blob copied to another machine | **blocks** | no help |
| Local user reads the key file | no help — nothing useful on disk | **blocks** |
| Local attacker executing as the credsd uid | no help — can drive the TPM | **is the boundary** |
| Root on the live machine | no help | no help |
| Malicious signed kernel | no help | no help |

Hardware binding without identity-based authorization, plus identity-based authorization
without hardware binding, does not compose into both. The TPM makes the key non-portable;
the uid makes it non-shared. Neither covers the other's gap, and the uncovered
intersection — a local attacker who achieves execution as the service account on the live
machine — is the residual risk the architecture accepts.

## Windows

`dpapi` is the default. The master key is protected with `CryptProtectData` under a
compiled-in secondary entropy constant and written as a blob under the data directory. The
scope is the **service account on this machine**: `CRYPTPROTECT_LOCAL_MACHINE` is not set,
so the blob is bound to the credsd account's DPAPI master key, itself derived from that
account's credentials. No hardware binding. The entropy constant ships in the binary and
is not a secret; it provides domain separation, not protection.

`credential-manager` stores the key in the Windows Credential Manager vault and requires
an **interactive logon session** — the same session-availability constraint that shapes
the macOS story, surfacing on a different platform. It is explicit-only, probed before
use, and selecting it without an interactive session is a configuration error with
remediation text rather than a fallback. A key already in the vault migrates forward to
DPAPI on first DPAPI use.

## The `file` backend

The master key is written as **plaintext** to a `0600` file in a `0700` directory. It has
cross-user protection from filesystem permissions and no device binding whatsoever: disk
theft yields the key directly, and root reads it trivially. It exists as an explicit,
documented escape hatch for environments where no hardware-backed option is reachable —
never as a fallback, and the CLI names the tradeoff at the point of selection
(`--insecure-backend`).

---

# The macOS constraint

This section is a property of the platform. It holds in both the current and the target
state, and it is why the target state is shaped the way it is.

**The assertion, and its verdict.** Hardware binding and cross-user access are mutually
exclusive on macOS **when the hardware key is reached through the keychain** — which is
the only documented route. They are not exclusive in the hardware itself. The exclusivity
is a property of the keychain, not of the Secure Enclave.

There are consequently three paths, not two.

| | Path A — SE via keychain | Path B — legacy keychain or file | Path C — SE via CryptoKit |
|---|---|---|---|
| Hardware binding | yes | no | **yes** |
| Cross-user reach | no | **yes** | **yes** |
| Keychain involved | data protection keychain | file-based keychain | **none** |
| Requires | login session, signed bundle identity, `keychain-access-groups` profile | a `LaunchDaemon` and a service account | nothing — no entitlement, no signing, no bundle |
| Runs as | `LaunchAgent` in the user's GUI session | root `LaunchDaemon` | root `LaunchDaemon` |
| Apple's position | documented, supported | documented, supported | **undocumented; explicitly not blessed** |
| Key material | in the keychain | wrapped file / plaintext file | SE-wrapped blob wherever you put it |

### Path A and B: the exclusivity is documented and firm

TN3137 *On Mac keychain APIs and implementations* states it normatively: "Programs that
run outside of a user context, like a `launchd` daemon, must target the file-based
keychain. The data protection keychain is only available to programs running in a user
context, like an app or an app extension." Protecting a key with the Secure Enclave is
listed among the features that *require* the data protection keychain. The callout that
forecloses every packaging workaround: "regardless of the packaging, the data protection
keychain is only available in that context."

Asked directly whether a device-wide SE-backed identity shared across all OS users is
possible, Apple DTS answered "No." The clinching structural evidence is that Apple built
the cross-user data protection keychain concept and shipped it on **tvOS only** —
`kSecUseUserIndependentKeychain` is `API_AVAILABLE(tvos(16.0))` and
`API_UNAVAILABLE(macos, ios, watchos, macCatalyst)` in the macOS SDK header. The concept
exists; macOS does not have it.

Two independently sufficient blockers gate Path A, and they are not equal:

1. **The caller's session context.** Decisive, and unfixable by packaging. There is no
   system-context data protection keychain for the system to select — a structural
   absence, not a permission check. The same signed binary with a correct embedded
   provisioning profile succeeds under `sudo` and fails under `launchctl load`, which
   proves the axis is the session and not the uid.
2. **The `keychain-access-groups` entitlement.** Real, and *solvable* — a standalone
   executable has nowhere to embed a provisioning profile, but Apple documents an
   app-like wrapper for exactly this. Solving it changes nothing, because blocker 1 still
   applies. That is the actual point.

Root is not a blocker. macOS carries execution context above the POSIX uid, and there is
no supported way for a daemon to impersonate a user's security context.

### Path C: the Secure Enclave without the keychain

CryptoKit's `SecureEnclave.P256` types reach the Secure Enclave directly, with no
keychain, no entitlement, no access group, no provisioning profile, and no code signing.
The key is persisted as an opaque `dataRepresentation` blob that the process stores
wherever it likes. This dissolves the conflict: a root daemon holds an SE-wrapped blob in
a root-owned file and serves many uids over its own IPC. **That is exactly credsd's
shape.**

Apple's position on it is genuinely unsettled, and the record is contradictory within two
months from the same engineer. In September 2025 DTS answered a question describing this
precise architecture with "Using the SE from a `launchd` daemon is not supported. Please
don't go down this path." In November 2025 the same engineer wrote that CryptoKit "changed
that calculus", that "the old answer of 'No, because of the data protection keychain
constraint' is no longer valid", that he had bench-tested it — "AFAICT this does actually
work" — and then: "Is it supported? And I don't have an official answer to that. I can't
see any obvious flaws in the approach, but without documentation you're essentially
trading in implementation details."

There is a plausible mechanism for the reversal, and it is observable locally.
`com.apple.ctkd.token-client` — the Mach service that brokers SE access — was diagnosed in
2023 as reachable only from an *agent*, and therefore not from a daemon. On macOS 26.6.2 it
is published by `/System/Library/LaunchDaemons/com.apple.ctkd.plist` in the **system**
bootstrap domain, running `ctkd -st` as `_ctkd`, loaded. The prohibition appears to have
lapsed because a Mach service became reachable in the global namespace, not because a
policy changed.

### The finding that matters most for design

**An SE-wrapped blob is not bound to the creating code's identity.** Apple DTS initially
said it was, then retracted after reproducing a developer's test: a second process can use
the key for signing and decryption *even when signed with a different Team ID, or unsigned
entirely*. Hardware binding buys non-exfiltratability off the device. It buys **no local
access control at all**.

Therefore, under Path C, confidentiality of the blob is the entire access boundary — a
root-owned `0600` file. Which is the same posture as the Linux TPM backend, for the same
reason.

### The general rule

Stated as two clauses, one per platform, the constraint looks like two different facts. It
is one:

- **macOS, via the keychain:** hardware binding and cross-user access are *mutually
  exclusive*.
- **macOS via CryptoKit, and Linux via TPM:** cross-user access protection is *required,
  even with hardware-bound keys*.

Both follow from hardware binding and identity-based authorization being orthogonal axes.
A secure element answers "which machine" and has no opinion on "which principal". macOS
makes the two exclusive only by routing the hardware path through a per-user keychain;
remove the keychain and macOS converges on the Linux model exactly — hardware binding for
device binding, filesystem permissions and the service uid for authorization, neither
substituting for the other.

### No prior art either way for the daemon case

An exhaustive search across roughly twenty products found **no third-party root
`LaunchDaemon` that performs the SE key operation itself.** Every attributable product
does it in a user context, and the negative results are informative:

| Product | Shape | Where the SE op happens |
|---|---|---|
| Kolide / 1Password Device Trust | daemon-only install | a spawned **per-console-user** process; the root daemon is its HTTP client |
| Secretive | `SMAppService` login item | the login-item GUI agent |
| GoDaddy `hardware-enclave` | LaunchAgent | the per-user agent, via **CryptoKit**; requires a GUI session |
| Teleport | ships a root daemon, deliberately keeps Touch ID out of it | the user-invoked `tsh` |
| Okta Verify, Microsoft Entra SSO | app extensions | **Apple's** `AppSSOAgent`, not the vendor |
| CrowdStrike Falcon, Google/NPS Santa, Tailscale (OSS) | daemons / sysexts | **no SE usage at all** |

Kolide is the case study, because they started where credsd is and conceded. Their own
repository records it: "When launcher runs as a daemon instead, as it does normally, it is
unable to access the secure enclave"; `launchctl asuser` "does not fix secure enclave
access … we then run into `errSecMissingEntitlement`"; and the shipped code comments "we
can not perform any secure enclave operations without a console user logged in, so we keep
trying until we have one." They moved the operation to a user agent and listed it under
*Cons*. Their stated reason for dismissing CryptoKit — that it falls back to the Security
framework — is contradicted by three later sources and should not be inherited.

Note also that Apple's own `mdmclient` is a root daemon doing SE-backed attestation, using
private entitlements no third party can obtain. "Apple's daemon does it, so ours can" is
unsound.

---

# Target state

## One key model, three custody choices

The three macOS backends are not three architectures. **All of them wrap the master key to
an SE-resident P-256 key via ECIES and persist only ciphertext; none stores the AES key
itself.** What varies between them is custody of the enclave key's opaque
`dataRepresentation` blob — and therefore who can read it.

| Backend | `.sekey` custody | Reader gate | Install shape | Signing |
|---|---|---|---|---|
| `secure-enclave` | `0600` file | file mode + the `credsd` service account | system **or** user | irrelevant |
| `keychain` | legacy keychain | per-item ACL, prompt-mediated | user only | irrelevant |
| `keychain-dp` | data protection keychain | access group, entitlement-enforced | user only | **required** |

The `keychain` row is a record, not a live option: `legacy-keychain` was removed from every
build on 2026-10-07 (`mac-pkg-installation` Requirement 7.6). It was reachable only from a
user-scoped install, which already refused it, and its items are plantable by the uid.

Three consequences worth holding onto:

**The invariant is uniform.** No configuration of credsd on SE-capable hardware stores the
AES-256 master key. A bypass of any backend's reader gate yields a *use-oracle* — the
ability to ask that machine's enclave to unwrap, while you retain read access, on that
machine — not a portable secret. Compare a design that puts the AES key in a keychain item:
there, a bypass hands over the key itself, exfiltratable and usable off-device forever. The
envelope makes every backend fail soft.

**Signing is load-bearing for exactly one backend.** For `keychain-dp` the
`keychain-access-groups` entitlement *is* the access group, so the signature is the security
control. For `secure-enclave` signing buys nothing security-relevant — Path C needs no
entitlement, and the blob carries no code identity — so it is a distribution choice only.
That is what makes `secure-enclave` the open-source-viable hardware-backed option.

**Custody fixes the install shape.** Both keychains need a login session, so selecting
keychain custody and selecting the user install are the same decision. File custody is the
only universal one. A boot-start system daemon can only have file custody.

The sealed master key (`.sealed`) stays a `0600` file in every case: it is
AES-GCM-authenticated ciphertext and inert without the unwrap. Protect the capability, not
the ciphertext.

### Selection

Selection is driven by what the running binary can actually reach, determined by probe
rather than assumed.

| # | Install shape | Build | Backend | Hardware binding | Cross-user | Same-uid gate |
|---|---|---|---|---|---|---|
| 1 | user install | signed, entitled | `keychain-dp` | **yes** | no | **yes** |
| 2 | user install | OSS / unsigned | `keychain` | **yes** | no | weak (ACL prompt) |
| 3 | system install | either | `secure-enclave` | **yes** | **yes** | n/a — service account |
| 4 | system install, no enclave | either | `file` (explicit) | no | **yes** | n/a — service account |

Rows 1 and 2 differ only in reader gate, because the entitlement is what buys the
access-group scoping. Row 3 reaches the enclave by Path C, which needs no entitlement, so
signing does not appear in it.

### Row 4: the SE-less fallback is a posture, not a concession

On Macs with no Secure Enclave (2017 and earlier), and on Linux with no TPM, the envelope
does not exist and the key must be stored. Within the system install `file` is the only
option — both keychains are user-install-only — so the real question is whether the system
install is still the right shape when there is no hardware. It is:

| Threat | system install + `file` | user install + keychain (key at rest) |
|---|---|---|
| A live process running as the user | **blocked** — key owned by `credsd` | weak: ACL is prompt-mediated, users click through |
| Offline disk or backup theft | plaintext key exposed **unless FDE** | key encrypted (password-derived; no SEP on this hardware) |
| Root | lost | lost |

The keychain option's at-rest advantage is largely redundant with FileVault, which is on by
default across a managed fleet. The system install's uid separation is redundant with
nothing. So the trade is a mostly-covered weakness for an uncovered strength: **the service
account's uid boundary substitutes for the absent hardware boundary.**

Two obligations follow. FileVault becomes load-bearing rather than incidental, so it should
be a checked precondition (`fdesetup status`) and not an assumption — refuse or warn loudly
and record it, rather than leaving a reviewer to take it on faith. And the install cost (root
installer, LaunchDaemon, service account) stops being ergonomics and becomes the security
control, which is the documented reason not to later "simplify" this into an agent.

Row 3 is hardware-backed because Path C works from a system daemon. Measured on macOS 26.6.2
(Apple M3 Pro): a `/Library/LaunchDaemons` job running as the shell-less `credsd` service
account generates an enclave key, wraps the master key, and — across a `launchctl
bootout`/`bootstrap` cycle — unwraps it and serves `creds get` from credentials sealed before
the restart. Generate, wrap and unwrap therefore all work with no login keychain and no
entitlement. The fallback chain below it stays probe-driven: `keychain` where an enclave is
unreachable, `file` only as an explicit last resort.

One condition is unverified: every observation so far was made from a logged-in session, so
none of it speaks to the pre-login case. See Open questions.

The `secure-enclave` backend wraps the AES-256 master key with a P-256 key pair resident
in the Secure Enclave, via ECIES (X963/SHA-256/AES-GCM), and persists only the ciphertext
blob. The private key never leaves SE hardware, so neither root access nor a memory dump
recovers it.

### What this target state still depends on

**Pre-login behaviour, for row 3 only.** A daemon that must unseal before any user logs in
depends on the `Always` protection class, which is deprecated and untested here. If it turns
out not to work, row 3 still holds for machines where a login precedes first daemon use, but
a boot-start daemon on an unattended machine falls back to `keychain` or `file`.

**Whether to depend on an undocumented path at all.** Path C is not blessed by Apple, so row
3's hardware binding rests on behaviour that could change in a point release with no
deprecation warning. That is a posture decision, not a technical one — the technical question
is now answered.

**Whether `keychain-dp` earns its cost.** Under the custody model it is not "the signed,
therefore stronger, backend" — it is a targeted mitigation for one threat: a hostile process
running as the user, in the user install. It is the only mechanism on macOS that provides
that boundary, and it should be justified by naming the threat (a malicious dependency
postinstall, a compromised agent harness, an editor extension) rather than by appeal to
signing. Against that threat it is worth the entitlement, the bundle, and the Developer ID.
Absent that threat, it pays a paid-identity dependency and a login-session constraint for a
boundary the system install already gets from the kernel.

It also introduces a risk the file custody does not have: **it couples data availability to
code-signing state.** A `0600` file survives an expired provisioning profile; a keychain item
behind an AMFI-killed process does not, and an unreachable blob means an unrecoverable master
key and a forced re-bootstrap. The blast radius is bounded (machine loss already costs a
re-bootstrap, and SSO seeds are re-derivable), but it is a dependency of *data* on *signing
validity*, which is a different class of risk from the one being bought. That is the reason
the system install keeps the plain file even after `keychain-dp` ships — not because the file
is more secure, but because it is unconditionally readable.

Note the corollary for the Path A prototype as currently written: because it takes Path A, it is
structurally limited to a user install. It cannot serve row 3 regardless of how it is
completed, and under the custody model its SE-key-in-the-keychain design is superseded by
"SE envelope, keychain custody of the blob."

## Linux

The current posture is the target posture: `tpm` for hardware binding, the service uid as
the authorization boundary, `file` and `kkrs` as explicit-only alternatives. The feature and
its device seam reach customers in the `-tpm` artifacts, so the auto-detected backend is one
that works — on a host that took that download. On a default build, auto-detect still selects
`tpm` from the device node alone and fails at first store; that gap is below, not a packaging
question.

## Gaps to close

- **The `--insecure-backend` refusal message is wrong for a system install.** It reads "the
  file backend stores the encryption key as a plain file readable by your uid — any process
  you run can exfiltrate sealed credentials", which is false under a dedicated service
  account: the file is not readable by the invoking user, and no process they run can read
  it. Its remediation is wrong twice over — it recommends "Keychain on macOS", which is not
  hardware-backed in this implementation, and on SE-less hardware there is no hardware-backed
  option at all, so it advises a fix that does not exist on the machine that triggered the
  error. Make it posture-aware: for row 4 the residual risk to name is plaintext at rest and
  therefore FileVault, not a same-uid threat the posture already eliminates. As written it
  trains operators to pass the flag reflexively on the one configuration where its stated
  justification does not apply.
- **No FileVault precondition check.** Row 4's argument rests on full-disk encryption. Probe
  `fdesetup status` and refuse or warn rather than assuming.
- **`auto_detect()` on macOS ignores install shape and signing state.** It must probe for
  the Secure Enclave, then a usable keychain, then fall through — instead of returning
  `Keychain` unconditionally and relying on a downstream probe to refuse.
- **The Secure Enclave backend is incomplete.** It is not shipped and
  its behavior is not yet validated end to end; a passing in-process test does not
  demonstrate that the key is usable by the shape of process that needs it.
- **Keychain-under-LaunchDaemon is unproven.** Row 3 cannot be specified until this is
  settled either way.
- **`Backend::Tpm.is_available()` does not reflect the `tpm` feature**, so auto-detect can
  select a backend whose seal will fail.
- **Per-home namespacing** of the keychain / Secure Enclave item must land alongside these
  (see `docs/specs/storage-backend-per-home/`) so two homes on one machine cannot collide.
- **The keychain backend does not pin `kSecUseDataProtectionKeychain: false`.**
  `security_framework::passwords` omits the key entirely and relies on the documented
  default. On macOS 14.5+ `SecItemAdd` has been reported to target the data protection
  keychain by default, contrary to TN3137. If that holds, the current backend may be
  landing items in a keychain no daemon can read — which would be a candidate explanation
  for the inconclusive daemon testing. Pass the flag explicitly rather than inheriting a
  default that has already drifted once.
- **Settle whether CryptoKit SE keys work pre-login from a root LaunchDaemon.** Roughly
  fifty lines of Swift, one plist, and a reboot with no login. Two traps make casual
  testing invalid: the CryptoKit default protection class is
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, which fails pre-login with
  `errSecInteractionNotAllowed` (-25308) and needs `kSecAttrAccessibleAlways` — itself
  `API_DEPRECATED(macos(10.9, 10.14))`; and *any* login invalidates the test, including
  SSH. A valid test is a daemon that creates the key at boot and logs the result, inspected
  after logging in later.
- **Use `privateKeyUsage` only, with no presence flags.** `LAContext` is user-context-only
  and cannot be moved between security contexts, so adding a user-presence requirement to a
  daemon key makes it strictly worse. Biometrics are opt-in additional protection, not a
  prerequisite for SE key use.

---

# Residual risk

Common to every backend, because it lives above the key store:

- Execution as the credsd service account yields the master key.
- Root on the live machine yields the master key.
- Caller separation is enforced by the daemon in software, not by the key store.

Backend-specific:

| Backend | Principal residual risk |
|---|---|
| `secure-enclave` | read access to the blob on the live machine — there is no code-identity check (see "The finding that matters most for design") |
| `tpm` | local execution as the service uid, or in `tss`; unseal loss on TPM clear |
| `keychain` | no hardware binding; disk plus account password; availability under a daemon unproven |
| `dpapi` | no hardware binding; blob plus account credentials |
| `credential-manager` | no hardware binding; requires an interactive session |
| `file` | key recoverable from a disk image with no further secret |

# Open questions

- **Whether CryptoKit SE keys work *pre-login* from a root LaunchDaemon.** The
  post-login case is settled — generate, wrap and unwrap all work from a system daemon as a
  shell-less service account (see Target state, row 3). The remaining question is a daemon
  that must unseal before any user has logged in, which depends on the deprecated `Always`
  protection class. Untested in every public source, including the ones advocating the
  approach. Settled by one reboot with no login; any login, SSH included, invalidates the
  test.
- **Whether credsd should depend on an undocumented path.** Path C works, is shipped by at
  least one third party, and is documented as the only option by two OSS projects — and
  Apple has said both "please don't go down this path" and "AFAICT this does actually work"
  within two months, with "I don't have an official answer" on support. TN3137 has not been
  revised since 2022 and does not mention the CryptoKit route at all. This is a risk
  appetite decision.
- **Whether CryptoKit is genuinely hardware-bound or silently falls back.** No public test
  settles it. `SecureEnclave.P256` has no software fallback path and Apple describes
  `dataRepresentation` as wrapped so only the issuing SE can use it, but DTS never answered
  the question when it was asked directly.
- **Whether `keychain` is usable from a LaunchDaemon**, which row 3 depends on if Path C is
  rejected. The `kSecUseDataProtectionKeychain` default drift above is the first thing to
  rule out.
- **Whether an `SMAppService` privileged helper or an Endpoint Security system extension
  changes the answer.** No Apple statement either way; system extensions sit on the *daemon*
  side of the data-protection-keychain line, so inference is that they do not help.
- **`/Library/Keychains/system-keychain-2.db`** exists on macOS 26.6.2, root-only, with
  `-shm`/`-wal` siblings — the naming convention of a data protection keychain at system
  scope. Undocumented. Worth watching, given Apple DTS stating that "the eventual goal is to
  allow daemons to use the data protection keychain."
- **TPM auth values on Linux** remain out of scope pending a concrete threat the uid
  boundary does not cover. The open question is whether such a threat exists in the
  deployment environments credsd targets.
- **A per-caller key hierarchy** — deriving a distinct key per caller uid rather than
  sealing every caller's credentials under one master key — would narrow the blast radius
  of a service-account compromise. It does not close it, and it is not currently modelled.
