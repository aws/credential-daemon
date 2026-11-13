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

Backend posture is split into **current state** and **target state**. Most of the target
state has landed, so the split now reads as reasoning rather than as a plan: current state
describes what a build of `main` does today, and target state describes the custody model
and why each row is the row it is. Where the two disagree, current state is what ships and
"Gaps to close" names the difference — the one open disagreement is which material the data
protection keychain holds. The platform constraint section between them is neither — it is a
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
| `data-protection-keychain` | macOS | item in the data protection keychain | **yes** (SE-protected keychain hierarchy) | the entitled signed binary, in a login session | `keychain-access-groups` entitlement — **per-binary**, not per-account | shipped; the only backend a user-scoped install may hold a key in |
| `tpm` | Linux | sealed blob on disk (`0600`) | **yes** (TPM 2.0) | anyone who can open `/dev/tpmrm0` | **none** | shipped; device seam built into the `-tpm` Linux artifacts only |
| `dpapi` | Windows | DPAPI blob on disk | no | the service account, on this machine | Windows account scope | compiled on Windows, built by no CI row; what resolution *would* pick, except that no Windows install exists |
| `credential-manager` | Windows | Credential Manager vault | no | the service account, interactive logon | Windows account scope | compiled on Windows, built by no CI row; explicit only |
| `file` | all | **plaintext** key file (`0600`) | no | the owning uid, and root | filesystem permissions | shipped; explicit only |
| `kkrs` | Linux | kernel keyring, never on disk | no | the owning uid (keyutils default) | kernel keyring, uid-scoped | on `main` behind the `kkrs` feature; in no published build |
| `secure-enclave` | macOS | ECIES blob + enclave key blob on disk (`0600`) | **yes** (SE) | anyone who can read the blobs *from the launchd context that minted them* | **none** beyond file mode | shipped from source behind the `secure-enclave` feature; absent from the signed release; the hardware round-trip test is `#[ignore]`d, so CI proves nothing about the enclave itself |

`file` and `kkrs` are reachable only by explicit selection. Resolution never falls back
to them: each carries a materially different guarantee, and a silent fallback would be a
silent posture change. On Linux, resolution gives `tpm` or a configuration error — never a
weaker backend.

Resolution happens at `credsd install` and nowhere else. `credsd serve` and `credsd init`
both require `--storage-backend` and refuse to run without it, so an install fixes the
backend once and bakes it into the service definition; the daemon never re-resolves one
between installs. Nothing mints a key implicitly either — see
[`docs/key-security.md`](../key-security.md), "Changing backend".

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

This is the load-bearing consequence: **an attacker who reaches the account the daemon runs
as has the master key**, because most key stores' own access control is scoped no more finely
than that account. Hardware binding raises the cost of *offline* attacks. It does nothing
about that one.

One backend is the exception, and it is the reason the user-scoped shape exists at all:
`data-protection-keychain` scopes the item to an entitlement, so reaching the account is
necessary but not sufficient — see "macOS" below.

## macOS

Two backends, and which one a build can reach is decided by its signature.

`DataProtectionKeychainStorage` stores the master key as a generic password — service
`com.amazon.aws.credsd` (`storage::SERVICE_NAME`), account `daemon-encryption-key.<ns>` —
through `security_framework::passwords` with `kSecUseDataProtectionKeychain = true` and **no**
explicit `kSecAttrAccessGroup`, so the item lands in the daemon's default access group: the
single entry of its `keychain-access-groups` entitlement,
`94KV3E626L.com.amazon.aws.credsd.daemon` (`packaging/credsd.entitlements`). The enclave
protects that keychain's key hierarchy, so a keychain file copied off the disk does not yield
the key on another machine. How much further that binding goes is not pinned and not measured
here: the backend sets no `kSecAttrAccessible*`, so the item takes Apple's default protection
class, and whether a backup or a migration assistant can carry it to another Mac is untested —
see "Gaps to close". The legacy, file-based keychain is not used by any
backend; `legacy-keychain` was removed from every build on 2026-10-07
(`mac-pkg-installation` Requirement 7.6).

**The entitlement is the access control, which makes signing load-bearing.** A
`keychain-access-groups` entitlement requires a provisioning profile issued against a real
team identity, so only the signed release carries it. `creds` deliberately does not
(`presence-gated-operations` Requirement 7.5), which is what keeps a binary the caller runs
outside the boundary. A from-source build has no signing identity, holds no entitlement, and
cannot reach the item at all — not a weaker version of the same custody, no custody. It uses
`secure-enclave` instead, which reaches the enclave by Path C and needs no entitlement; see
"The macOS constraint".

`SecureEnclaveStorage` wraps the master key to an SE-resident P-256 key and persists only
ciphertext: `<data_dir>/secure-enclave/<key_id>.sekey` holds the enclave key's opaque
`dataRepresentation` and `<key_id>.sealed` the ECIES-wrapped master key, both `0600` in a
`0700` directory. The enclave is reached through CryptoKit rather than `SecItem`, because the
`SecItem` route goes back through the data protection keychain. The key binds to the launchd
context that minted it and not merely to the uid — a key minted outside launchd fails to
unwrap inside the service with `key agreement failed (-6)` — which is why a system install
mints through a one-shot LaunchDaemon (`com.amazon.aws.credsd.mint`) rather than in the
installing process.

### Selection, and why a LaunchDaemon never gets the keychain

Selection is a probe, not an assumption, and it happens once per install. Resolution without
`--storage-backend` is reached only from `credsd install`:

- `credsd install --user` resolves `data-protection-keychain` when the probe succeeds. Any
  other resolved backend is refused outright, because the keychain is the only keystore a
  service running as its own caller's uid may hold a key in — `secure-enclave`'s `0600` key
  file is open to every other process running as that same login uid.
- `sudo credsd install` pins `secure-enclave` and never considers the keychain. This is now
  settled rather than inconclusive: the data protection keychain needs a login session and a
  LaunchDaemon has none, so `reachable_by_system_service` excludes it and an explicit
  `--storage-backend data-protection-keychain` on a system install is refused.

The probe is a real store/delete round-trip. `create_storage` exercises the backend before
returning it, and on failure returns a configuration error naming the entitlement
(`94KV3E626L.com.amazon.aws.credsd.daemon`) and pointing at `secure-enclave`. It never
degrades silently to `FileStorage`.

### Residual posture

- `data-protection-keychain` is device-bound to the extent the gap below records, and the gate
  is the entitlement rather than the
  account. A process running as the same uid without the signature cannot read the item,
  which is what makes the user-scoped install viable at all. What remains is root, and any
  binary Apple would issue the same entitlement to — which is why the release also runs under
  the hardened runtime with no `get-task-allow`, so the signed daemon cannot be attached to or
  injected into. See [`SECURITY.md`](../../SECURITY.md).
- `secure-enclave` is device-bound but has no identity gate. Within a system install the
  `credsd` service account owns the blobs and file mode is the whole boundary; within a user
  install it would be no boundary at all, hence the refusal above.
- This is the one place the "reach the account, get the key" rule from *The shared
  architecture* is narrower than on other platforms. For `secure-enclave` it holds exactly:
  the account is the whole gate. For `data-protection-keychain` it does not — the account is
  necessary and not sufficient, because the item is also scoped to the entitlement, so the
  attacker needs code carrying the daemon's signature as well.

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
return a clear "requires the `tpm` feature" error, but nothing gets that far:
`Backend::Tpm.is_available()` requires the feature as well as `/dev/tpmrm0`, so a default
build on TPM-equipped hardware never selects `tpm`. The failure surfaces at selection —
`credsd install` errors with "no hardware-backed storage available", and an explicit
`--storage-backend tpm` errors with "not compiled into this build" — rather than at first
store.

### Hardware binding: yes

This is the one backend in the set that genuinely has it. The blob is useless on any other
machine, and a stolen disk yields nothing. Unseal failure is a real operational mode — TPM
clear or replacement — and it stops startup rather than recovering on its own, so that
nothing destroys a credential the next boot might have opened. The operator runs `credsd
init --reset --storage-backend tpm`, which quarantines the undecryptable blobs and mints a
fresh key; see Requirement 3.3 and 3.4 of the
[TPM backend spec](../specs/tpm-encryption-backend/requirements.md).

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

The three macOS backends are not three architectures. The custody model that organizes them
is one envelope — the master key wrapped to an SE-resident P-256 key via ECIES, only the
ciphertext persisted — with three choices of where the enclave key's opaque
`dataRepresentation` blob lives, and therefore of who can read it.

| Backend | Custody of the material on disk | Reader gate | Install shape | Signing |
|---|---|---|---|---|
| `secure-enclave` | the `.sekey` blob, a `0600` file | file mode + the `credsd` service account | system only — a user install is refused | irrelevant |
| `keychain` | the `.sekey` blob, in the legacy keychain | per-item ACL, prompt-mediated | user only | irrelevant |
| `data-protection-keychain` | the master key itself, as a keychain item | access group, entitlement-enforced | user only | **required** |

The `keychain` row is a record, not a live option: `legacy-keychain` was removed from every
build on 2026-10-07 (`mac-pkg-installation` Requirement 7.6). It was reachable only from a
user-scoped install, which already refused it, and its items are plantable by the uid.

The `data-protection-keychain` row is the one place the envelope is not what ships. The
backend hands the raw master key to the keychain and the keychain's own SE-protected key
hierarchy supplies the hardware binding, so the item is device-bound without credsd wrapping
anything; moving it to `.sekey` custody is an open gap, not a property of the current build.

Three consequences worth holding onto:

**The envelope is what makes a reader-gate bypass fail soft.** Where it is in place —
`secure-enclave` — a bypass yields a *use-oracle*: the ability to ask that machine's enclave
to unwrap, while you retain read access, on that machine. Not a portable secret. Under
`data-protection-keychain` custody a bypass hands over the AES key itself, and only its
device binding keeps it from being usable off the machine; that is the gap above, stated as
what it costs.

**Signing is load-bearing for exactly one backend.** For `data-protection-keychain` the
`keychain-access-groups` entitlement *is* the access group, so the signature is the security
control. For `secure-enclave` signing buys nothing security-relevant — Path C needs no
entitlement, and the blob carries no code identity — so it is a distribution choice only.
That is what makes `secure-enclave` the open-source-viable hardware-backed option.

**Custody fixes the install shape.** Both keychains need a login session, so selecting
keychain custody and selecting the user install are the same decision. File custody is the only
one a boot-start system daemon can have, and the only one a user install refuses: a `0600` file
is no boundary against the uid the service itself runs as.

Wherever the envelope is in place, the sealed master key (`.sealed`) stays a `0600` file: it is
AES-GCM-authenticated ciphertext and inert without the unwrap. Protect the capability, not
the ciphertext. `data-protection-keychain` has no such file — the key is the keychain item.

### Selection

Selection is driven by what the running binary can actually reach, determined by probe
rather than assumed.

| # | Install shape | Build | Backend | Hardware binding | Cross-user | Same-uid gate |
|---|---|---|---|---|---|---|
| 1 | user install | signed, entitled | `data-protection-keychain` | **yes** | no | **yes** |
| 2 | ~~user install~~ | ~~OSS / unsigned~~ | ~~`keychain`~~ | — | — | **removed** |
| 3 | system install | either | `secure-enclave` | **yes** | **yes** | n/a — service account |
| 4 | system install, no enclave | either | `file` (explicit) | no | **yes** | n/a — service account |

Row 2 went with `legacy-keychain`. An unsigned build now has no user install at all: the
entitlement is what buys the access-group scoping, so without it row 1's reader gate cannot
be approximated, and a user install resolving anything other than `data-protection-keychain`
is refused rather than downgraded. An OSS build takes row 3 or row 4. Row 3 reaches the
enclave by Path C, which needs no entitlement, so signing does not appear in it.

### Row 4: the SE-less fallback is a posture, not a concession

On Macs with no Secure Enclave (2017 and earlier), and on Linux with no TPM, the envelope
does not exist and the key must be stored. Within the system install `file` is the only
option — the keychain is user-install-only — so the real question is whether the system
install is still the right shape when there is no hardware. It is. The second column is the
alternative as it stood when this was decided, kept because it is the comparison the decision
rests on; `legacy-keychain`'s removal has since taken it off the table outright:

| Threat | system install + `file` | user install + keychain (key at rest, no longer offered) |
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
a boot-start daemon on an unattended machine has only `file` left — row 4.

**Whether to depend on an undocumented path at all.** Path C is not blessed by Apple, so row
3's hardware binding rests on behaviour that could change in a point release with no
deprecation warning. That is a posture decision, not a technical one — the technical question
is now answered.

**Whether `data-protection-keychain` earns its cost.** Under the custody model it is not
"the signed, therefore stronger, backend" — it is a targeted mitigation for one threat: a
hostile process running as the user, in the user install. It is the only mechanism on macOS
that provides that boundary, and it should be justified by naming the threat (a malicious
dependency postinstall, a compromised agent harness, an editor extension) rather than by
appeal to signing. Against that threat it is worth the entitlement, the bundle, and the Developer ID.
Absent that threat, it pays a paid-identity dependency and a login-session constraint for a
boundary the system install already gets from the kernel.

It also introduces a risk the file custody does not have: **it couples data availability to
code-signing state.** A `0600` file survives an expired provisioning profile; a keychain item
behind an AMFI-killed process does not, and an unreachable blob means an unrecoverable master
key and a forced re-bootstrap. The blast radius is bounded (machine loss already costs a
re-bootstrap, and SSO seeds are re-derivable), but it is a dependency of *data* on *signing
validity*, which is a different class of risk from the one being bought. That is the reason
the system install keeps the plain file alongside `data-protection-keychain` — not because
the file is more secure, but because it is unconditionally readable.

Note the corollary for the Path A prototype as currently written: because it takes Path A, it is
structurally limited to a user install. It cannot serve row 3 regardless of how it is
completed, and under the custody model its SE-key-in-the-keychain design is superseded by
"SE envelope, keychain custody of the blob."

## Linux

The current posture is the target posture: `tpm` for hardware binding, the service uid as
the authorization boundary, `file` and `kkrs` as explicit-only alternatives. The feature and
its device seam reach customers in the `-tpm` artifacts, so the backend an install resolves
is one that works — on a host that took that download. A default build never resolves `tpm`,
because `Backend::Tpm.is_available()` requires the feature as well as the device node, so a
host with `/dev/tpmrm0` and a featureless binary gets a selection-time error rather than a
seal that fails later.

## Gaps to close

- **`data-protection-keychain` holds the master key, not the envelope.**
  `DataProtectionKeychainStorage` stores the AES-256 key as the keychain item itself, where
  the custody model asks for the `.sekey` blob there and the master key wrapped to an
  SE-resident key. The item is device-bound either way, so the posture difference is what a
  reader-gate bypass yields: the key, rather than the use-oracle the envelope leaves. Closing
  it means minting through the enclave on the user-install path too, which has no mint
  LaunchDaemon to borrow.
- **The `--insecure-backend` refusal message is posture-blind.** It reads "the file backend
  stores the encryption key as a plain file readable by your uid — any process you run can
  exfiltrate sealed credentials", which is false under a dedicated service account: the file
  is owned by `credsd`, and no process the invoking user runs can read it. Its remediation is
  also wrong on the hardware that triggers it — it names the data protection keychain and the
  Secure Enclave, and a Mac with no enclave has neither. Make it posture-aware: for row 4 the
  residual risk to name is plaintext at rest and therefore FileVault, not a same-uid threat
  the posture already eliminates. As written it trains operators to pass the flag reflexively
  on the one configuration where its stated justification does not apply.
- **No FileVault precondition check.** Row 4's argument rests on full-disk encryption. Probe
  `fdesetup status` and refuse or warn rather than assuming. Nothing in the tree reads it
  today.
- **The keychain item's protection class is left to Apple's default.**
  `DataProtectionKeychainStorage` sets service, account, and
  `kSecUseDataProtectionKeychain` and nothing else — no `kSecAttrAccessible*`, no
  `kSecAttrSynchronizable` — so how far the device binding goes is inherited rather than
  asserted. A copied keychain file does not yield the key, but whether a backup or a migration
  assistant can carry the item to another Mac is untested. Pin
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and the claim becomes the code's rather than
  the platform's. This is the same "inheriting a default that has already drifted once" risk
  the Closed entry below records for `kSecUseDataProtectionKeychain`.
- **No automated run touches an enclave.** The backend ships from source and its
  launchd-context behavior has been observed by hand — that is where `key agreement failed
  (-6)` and the mint LaunchDaemon come from — but `hardware_round_trip` is `#[ignore]`d
  because the CI runners are virtualized and expose no enclave. Every green macOS row proves
  the logic against a fake seam and nothing about the hardware.
- **The protection class we depend on is deprecated.** `Protection::Always` is the default
  because it is the only class with no login dependency, and a boot-start daemon has no
  login; CryptoKit's own default,
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, fails pre-login with
  `errSecInteractionNotAllowed` (-25308). But `kSecAttrAccessibleAlways` is
  `API_DEPRECATED(macos(10.9, 10.14))`, so the system install rests on an API Apple has
  already marked for removal, and there is no non-deprecated replacement for the pre-login
  case. Whether it even works pre-login is the first item under "Open questions".

### Closed

Recorded so they are not reopened, with where each landed:

- **macOS selection ignoring install shape and signing.** `resolve_install_backend` pins the
  enclave for a system install and `auto_detect` probes the keychain before it; neither
  returns a backend unconditionally.
- **Keychain-under-LaunchDaemon.** Settled as impossible, not inconclusive:
  `reachable_by_system_service` excludes the data protection keychain, and a system install
  naming it is refused.
- **`Backend::Tpm.is_available()` not reflecting the `tpm` feature.** It now requires
  `Backend::COMPILED` to contain `Tpm` as well as the device node.
- **Per-home namespacing.** The key slot is `daemon-encryption-key.<ns>` via
  `instance_namespace(home)`, with a proptest on it (`docs/specs/storage-backend-per-home/`).
- **`kSecUseDataProtectionKeychain` left to the default.** Pinned explicitly — to `true`, via
  `PasswordOptions::use_protected_keychain`, the data protection keychain now being the
  intended target rather than the one to avoid.
- **Presence flags on the master key.** `ACCESS_FLAGS` is `0`: no flags at all. Not even
  `privateKeyUsage`, which gates signing and is irrelevant to a key-agreement key. User
  presence on a daemon key would need `LAContext`, which cannot cross security contexts.
  Presence is a separate mechanism on a separate client-held key
  (`docs/specs/presence-gated-operations/`).

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
| `data-protection-keychain` | local execution as the login uid **with the daemon's code signature**; root; unreachable from a system daemon by design |
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
