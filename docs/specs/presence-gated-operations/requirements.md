---
status: accepted
created: 2026-10-04
---

# Requirements: Presence-Gated Operations

## Summary

Some daemon operations should not complete on the strength of the caller's uid alone. A process
running as the owner of a credential can issue any JSON-RPC call the socket accepts, so an
operation the daemon performs because the uid is provisioned is an operation every process running
as that uid can perform — whether or not the owner meant it to.

The daemon's built-in gate (Requirement 1.7) decides which operations need more than a uid. This
spec defines what verified presence is and how it is obtained: the
daemon records the operation as pending, returns a challenge over it, and performs it only when a
verifier the requesting uid cannot produce unaided satisfies that challenge. There are two
verifiers — a signature by an enrolled presence key, and an approval from a privileged session —
and one lifecycle that both share.

The gate is the mechanism, not the list. Which operations are gated is the built-in list in
Requirement 1.7, and specs that introduce a gated operation — `drift-detection`'s revalidation among them — state its subject and
description in terms this spec defines.

## Threat model

The adversary is a process running under the same OS uid as the owner of the operation's subject.
It cannot forge `SO_PEERCRED`, read the daemon's keys, or defeat isolation between users. It can
issue any JSON-RPC call the socket accepts, read and write every file in that uid's caller root,
read the memory of every other process running as that uid, and choose what that uid's terminal
displays — including the words of any prompt a client running as that uid draws.

The path this spec closes is the **unapproved mutation**: the process calls a daemon operation —
`config/set` is the cheapest — and the daemon performs it because the uid is provisioned. That is
not a privilege-boundary failure in the OS sense. It is an authority failure in credsd's sense: the
owner of the credential did not agree to what the operation did.

The goal is that no gated operation completes without something the adversary cannot supply: a
finger on the platform authenticator, or someone becoming root.

What the adversary cannot write depends on the install shape (Requirement 7). In a system install
the daemon runs as a service account, and the adversary's uid is not that account. In a
user-scoped install the daemon runs as the adversary's uid, and the boundary is the daemon's code
signature instead — which is why Linux has no user-scoped install, and macOS has one only as the
official release build. An open-source build run as the caller has no boundary at all; this spec's
guarantees do not hold there, and the user is told so (Requirement 7.8).

## Terminology

- **Evidence** — a fact the daemon derives from its own state and supplies to policy: verified
  presence, caller uid, and whatever a consuming spec adds.
- **Gate** — the evidence-collection step that precedes a decision. The gate collects; policy
  decides.
- **Subject record** — a record a gated operation would write. A record that does not yet exist is
  a subject in its absent state.
- **Base state** — a digest of a subject record's contents as they were when the operation was
  requested.
- **Pending operation** — the daemon's in-memory record of a gated operation: what it would do, to
  which subject records, from which base state, and for which caller. A gated operation is
  performed from its pending operation, never from arguments re-supplied by a client, except one
  performed by re-send (Requirement 2.8).
- **Challenge** — what the daemon returns when a gate is salvageable: the identifier of a pending
  operation, a digest of its canonical form, and a description. A challenge confers nothing; it is
  what a verifier proves presence against.
- **Verifier** — a way of satisfying a challenge. There are two: a presence signature and a
  privileged approval.
- **Presence key** — a non-exportable signing key, held by the user's platform authenticator, whose
  every use requires the user's biometric or device-owner check. On macOS, a Secure Enclave key
  with a user-presence access control.
- **Presence signature** — a signature by an enrolled presence key over a challenge's digest.
- **Privileged approval** — satisfaction of a challenge over a connection whose kernel-reported
  uid is 0: `sudo creds request approve <id>`.
- **Enrollment** — the gated operation that registers a presence key's public half with the daemon,
  for the uid that raised it.
- **Enrolled-key registry** — the daemon's record of every enrolled presence key, at most one per
  uid. It is state the daemon alone writes, not a record anyone edits, and is persisted only
  sealed (Requirement 5.10).
- **Client-owned storage** — `~/.credsd/`, the directory the user's own client writes. It holds
  the presence key's private half, wrapped so that only this device's authenticator can use it,
  and it is separate from daemon-owned storage in every posture (Requirement 5.12).
- **Login identity** — the uid a process's login session was opened for, as the kernel records it
  and preserves across `sudo`: the audit login uid on Linux, the audit user id of the audit session
  on macOS.
- **Official release build** — a build signed by credsd's release identity, whose signature no
  third party can reproduce. Every other build — open source rebuilt by anyone, or a development
  build — is an **open-source build** here.
- **Secure posture** — a way of running the daemon in which daemon-owned storage is out of every
  caller uid's reach (Requirement 7.1–7.3). There are two: a **system install**, the daemon run by
  the service manager as a service account — a LaunchDaemon on macOS from any build, a system unit
  on Linux — and an **official user-scoped install**, the official release build run as the
  caller's uid by a per-user LaunchAgent on macOS.
- **Insecure posture** — any other way of running the daemon: as the caller's uid without the
  storage Requirement 7.3 requires. A LaunchAgent installed from an open-source build is one, and
  so is `credsd serve` run by the caller. Only an open-source build may run in one (Requirement
  7.8).

## User Experience

What a user sees — Touch ID approval on macOS, `sudo` approval elsewhere, and enrolling a presence
key — is in `ux.md`.

## Requirements

### Requirement 1: The gate collects evidence; the built-in gate decides

**User story:** As a security reviewer, I want the facts the decision rests on to come from the
daemon and the decision to come from a fixed list, so that no caller and no configuration can
relax which operations need presence.

#### Acceptance Criteria

1.1. The gate SHALL collect evidence and SHALL NOT itself permit or deny. The decision SHALL be
     made by the built-in gate of Requirement 1.7. An operation it lists, attempted without
     verified presence, SHALL be a salvageable denial.

1.2. Every evidence value SHALL be derived by the daemon from its own state. No client-supplied
     field SHALL set any evidence value, and there SHALL be no request parameter asserting that a
     gate was already satisfied.

1.3. The request context SHALL carry `presence_verified`, true only for an evaluation that
     performs a pending operation whose challenge a verifier satisfied, and `proof_verified`, true
     only when a submitted proof satisfies the challenge it names.

1.4. Approving a challenge and enrolling a presence key SHALL each be a distinct operation, so
     that each is gated and audited separately from the operations it approves.

1.5. The built-in gate SHALL refuse approval without a verified proof and SHALL refuse
     enrollment without verified presence. Neither SHALL be removable by configuration.

1.6. The gate SHALL observe that presence was verified and SHALL NOT observe which verifier
     verified it. Which verifier a user can reach is a property of their platform and session, and a
     rule
     that varied by verifier would make the weaker one a target. A restriction to privileged
     approval (Requirement 3.6) is a property of the operation's challenge, not of the gate, so
     that nothing above the gate can relax it.

1.7. The built-in gate SHALL require verified presence for every operation that changes a
     caller's existing configuration or sealed material, and for enrollment:

     | Operation | Gated when |
     |---|---|
     | `config/set` | always |
     | `config/unset` | the key is set, and the key is not one Requirement 1.8 refuses to unset |
     | `environment/bootstrap` | the credential exists, or the environment exists without it |
     | `environment/import` | any profile would bind into an existing environment, or replace sealed material its credential left behind |
     | `credential/remove` | always |
     | `environment/remove` | always |
     | `presence/enroll` | always |

     The built-in gate SHALL be fixed in the daemon and SHALL NOT be configurable. An operation that
     would change nothing — a first bootstrap, an unset of a key that is not set — SHALL NOT be
     gated by it, because there is nothing for an approver to agree to.

1.8. A configuration key whose absence is read as a more privileged value than some value it can
     hold SHALL NOT be unsettable: the daemon SHALL refuse `config/unset` of such a key outright,
     without raising a challenge, because no approval would make the resulting escalation safe to
     grant. `identity_type` is such a key: an absent `identity_type` reads as `Human`, the most
     privileged tier.

### Requirement 2: A salvageable denial becomes a pending operation and a challenge

**User story:** As a user, I want a denied operation that I can approve to wait for my approval
rather than fail, and to be performed exactly as it was asked, so that approving it later cannot
approve something else.

#### Acceptance Criteria

2.1. WHEN an evaluation denies an operation, and the denial would be reversed by verified presence,
     THEN the daemon SHALL record a pending operation and SHALL return a challenge naming it, as
     the error Requirement 8.1 defines. The daemon SHALL NOT hold the originating connection open
     awaiting the challenge's satisfaction.

2.2. A pending operation SHALL record the operation and its arguments — or, for an operation
     Requirement 2.8 governs, a digest of them — each subject record with its base state, and
     the requesting caller's kernel-reported uid, pid, and executable.

2.3. A subject record's base state SHALL change whenever any of its contents that the operation's
     outcome depends on changes. It SHALL NOT be a value that an edit can leave unchanged — an
     a sealed snapshot is such a value, because a hand-edit leaves it unchanged. Absence SHALL be a
     base state, distinct from every present one.

2.4. A challenge SHALL carry the pending operation's identifier and a digest of the pending
     operation's canonical form. Satisfying a challenge SHALL authorize exactly the operation its
     digest names: the daemon SHALL perform the pending operation as recorded, and SHALL NOT accept
     the operation's arguments again from a client — except for an operation Requirement 2.8
     governs.

2.5. A pending operation SHALL be satisfiable at most once, and SHALL expire. Satisfaction, expiry,
     and withdrawal SHALL each discard it, and a discarded pending operation SHALL NOT be
     approvable. Its owner SHALL be able to withdraw it on uid alone.

2.6. BEFORE performing a satisfied operation, the daemon SHALL confirm that each subject record is
     still in the base state recorded under Requirement 2.2. WHEN any is not, THEN the daemon SHALL
     discard the pending operation unperformed, because the approval was given against a state
     that no longer exists. A subject record that cannot be read SHALL be treated as not in its
     base state.

2.7. A pending operation SHALL be enumerable by its owner, and every pending operation SHALL be
     enumerable by a privileged approver, so that an approval workflow does not depend on the
     requester having captured an identifier from a transcript.

2.8. An operation whose arguments carry secret material, or whose performance runs an
     interactive flow on the requesting connection, SHALL be performed by re-send rather than from
     its pending operation. Its pending operation SHALL record a digest of its arguments in place
     of the arguments, and satisfying its challenge SHALL perform nothing: it SHALL grant one
     authorization, bound to the requesting uid, that digest, and the base state recorded under
     Requirement 2.2, expiring within minutes. The daemon SHALL perform the operation only for a
     request whose arguments' digest and subjects' base state equal those of an unexpired
     authorization, and SHALL consume the authorization in doing so. The digest SHALL be computed
     over the daemon's own serialization of the arguments as it parsed them, SHALL cover every
     argument except a per-attempt request identifier, and SHALL be prefixed with the operation's
     name, so that an authorization for one operation cannot be spent on another.
     `environment/bootstrap` and `environment/import` are performed by re-send.

### Requirement 3: A challenge is satisfied by a presence signature or a privileged approval

**User story:** As a user on a Mac or on a remote Linux host, I want one approval workflow whose
guarantee does not depend on the hardware in front of me, so that the gate is enforceable
everywhere rather than waived where it is inconvenient.

#### Acceptance Criteria

3.1. A challenge SHALL be satisfiable by either of two verifiers: a presence signature
     (Requirement 5) or a privileged approval. Except for a privileged-only operation
     (Requirement 3.6), either verifier SHALL satisfy any challenge, so that which one a client
     reaches for confers no advantage.

3.2. A presence signature SHALL be a signature over the challenge's digest, under a fixed
     domain-separation prefix, by the presence key enrolled for the uid that the pending operation
     records.

3.3. A privileged approval SHALL be submitted over a connection whose kernel-reported uid is 0. It
     SHALL contribute verified presence and nothing else. The operation SHALL be performed for the
     uid the pending operation records and against that uid's caller root, and the approving
     connection SHALL NOT require a caller root of its own.

3.4. Neither verifier SHALL be satisfiable by anything the requesting uid can produce unaided.
     Possession of a challenge — its identifier or its digest — SHALL NOT be sufficient to satisfy
     it. A process that can raise a challenge and satisfy it alone has not been gated.

3.5. WHEN no interactive session is available, or no presence key is enrolled, THEN privileged
     approval SHALL remain available and SHALL be the only way the operation is performed. There
     SHALL NOT be a headless bypass, because an escape hatch conditioned on "no session available"
     is a condition a background process can arrange.

3.6. An operation whose approval would establish the authority that later approvals or
     verifications rest on SHALL be privileged-only: its challenge SHALL be satisfiable by
     privileged approval alone, and a presence signature SHALL NOT satisfy it. The restriction
     SHALL be fixed by the operation, recorded in its pending operation, and SHALL NOT be settable
     by a client or by policy. Enrollment (Requirement 5.2) and `drift-detection`'s regeneration are
     privileged-only.

### Requirement 4: A challenge describes what it approves, and the description is not the guarantee

**User story:** As the person approving, I want to be told what I am approving, without the system
pretending that what I was told is what I approved.

#### Acceptance Criteria

4.1. A challenge SHALL carry a description of the operation and its subject, and a client that
     solicits a verifier SHALL present it to whoever satisfies the challenge. For a mutation it
     SHALL name the value being written; for an enrollment it SHALL name the key's fingerprint and
     the uid it would be enrolled for; a spec that introduces a gated operation SHALL state its
     description. Approval SHALL NOT be solicited without it, because a prompt that names nothing
     trains its recipient to clear it.

4.2. The description SHALL NOT be the gate's guarantee, and the system SHALL NOT claim that what
     was approved is what the approver saw. Under a presence signature the prompt is drawn by a
     client running as the requesting uid; under a privileged approval it reaches the approver
     through their shell. The guarantee is Requirement 2.4: what is performed is what the digest
     names.

### Requirement 5: A presence key is enrolled only by privileged approval

**User story:** As the owner of a credential on a Mac, I want to approve gated operations with
Touch ID rather than `sudo`, without that convenience letting any process running as me approve
on my behalf.

#### Acceptance Criteria

5.1. Enrollment SHALL be a gated operation that registers the public half of a presence key for
     the uid that raised it. That uid SHALL be the requesting connection's kernel-reported uid, as
     recorded in the pending operation. Enrollment SHALL NOT accept a uid as a parameter.

5.2. Enrollment SHALL be privileged-only (Requirement 3.6). A presence
     signature — including one by a key already enrolled for the uid — SHALL NOT satisfy it. The
     daemon cannot verify where a presence key's private half is held, so the decision to trust a
     key is the root of the presence signature's authority, and SHALL come from outside the uid.

5.3. A presence key SHALL be generated by a client running as the enrolling uid, in that uid's
     session, as non-exportable, and with an access control that requires user presence for every
     use. The daemon SHALL NOT claim to have verified these properties, and SHALL report an enrolled
     key as enrolled rather than as hardware-attested.

5.4. An enrolled public key SHALL be held in daemon-owned storage (Requirement 7). In a secure
     posture that is storage the enrolling uid cannot write. It SHALL NOT be held in the uid's
     caller root.

5.5. The enrolling client SHALL display the key's fingerprint, and the enrollment's description
     (Requirement 4.1) SHALL carry the same fingerprint, so that an approver can match the key
     being approved to the key that was created.

5.6. WHEN an enrollment is raised for a uid that already has one pending, THEN the daemon SHALL
     discard both, and SHALL tell the requester that another was pending, naming the pid and
     executable that raised it.

5.7. A uid SHALL have at most one enrolled presence key. Enrolling a key for a uid that has one
     SHALL replace it when the enrollment is approved, and not before.

5.8. Revocation of an enrolled presence key SHALL require only its owner's uid. Revocation can
     only remove a verifier, and privileged approval remains available afterward.

5.9. Absence of an enrolled presence key SHALL NOT prevent any gated operation. It SHALL leave
     privileged approval as the only verifier.

5.10. The enrolled-key registry SHALL be encrypted at rest, with authenticated encryption under the
      daemon's encryption master key, in every posture and whatever holds it — a file or a
      keychain item. It SHALL NOT be persisted in plaintext.

5.11. WHEN the enrolled-key registry fails to decrypt or authenticate, THEN the daemon SHALL trust no
      key from it, SHALL report the failure through the audit path, and SHALL treat the uid as
      having no enrolled key (5.9). It SHALL NOT discard or overwrite the registry, so that the
      failure stays diagnosable.

5.12. The client SHALL hold a presence key's wrapped private half in client-owned storage,
      `~/.credsd/`, and SHALL create that directory `0700` and refuse it when another uid owns it.
      Client-owned storage SHALL NOT be located inside daemon-owned storage, or derived from the
      daemon's data directory, in any posture. The daemon SHALL NOT read or write it.

5.13. WHEN a challenge names an enrolled key, THEN the client SHALL sign only with the key whose
      public half has that fingerprint. WHEN it holds no such key, THEN it SHALL NOT prompt the
      user, and SHALL present privileged approval instead.

5.14. Enrolling a replacement presence key SHALL NOT remove the key it replaces from client-owned
      storage before the replacement is the enrolled key (5.7).

### Requirement 6: The decision record is auditable

**User story:** As someone reconstructing an incident, I want to know what was asked, what the
daemon knew, why it was gated, who approved, and what happened, without needing the original
request.

#### Acceptance Criteria

6.1. Every gate evaluation SHALL emit exactly one audit record, whatever the outcome. Expiry,
     withdrawal, and discard on a changed base state are outcomes.

6.2. An audit record SHALL carry the operation requested, the subject records, the evidence
     collected and each value, the decision, and the resulting outcome.

6.3. An audit record for a satisfied gate SHALL carry the verifier. For a presence signature it
     SHALL carry the fingerprint of the key that signed. For a privileged approval it SHALL carry
     the approving uid and, where the kernel keeps one for the approving process, its login
     identity. Login identity SHALL be read from the kernel and never from a client-supplied field
     or environment variable such as `SUDO_UID`, and SHALL NOT be evidence for the gate.

6.4. An audit record SHALL NOT carry credential material.

6.5. An audit record SHALL be emitted through the daemon's existing audit path, so that this
     spec's records are subject to the same handling as every other.

6.6. An audit record SHALL be sufficient, on its own, to answer what was asked, what evidence
     existed, why it was gated, and what happened.

### Requirement 7: Daemon-owned storage is owned by something the caller is not

**User story:** As the owner of a credential, I want the daemon's record of my enrolled key to be
out of reach of every process running as me in every supported install, and to be told plainly
when I have chosen one where it is not, so that enrolling a key never becomes something malware
can do by writing a file without my knowing.

#### Acceptance Criteria

7.1. A system install SHALL run the daemon as a service account that is not any caller's uid.
     Daemon-owned storage in a system install SHALL be storage that the service account owns and
     no caller uid can write.

7.2. credsd SHALL support exactly the two secure postures. On macOS: a LaunchDaemon, from any
     build, and a per-user LaunchAgent from the official release build, as
     `mac-pkg-installation` delivers it. On Linux: system units only. `credsd install --user`
     SHALL refuse on Linux, withdrawing the `systemd --user` unit earlier versions installed.

7.3. In an official user-scoped install, the daemon's storage backend SHALL be `data-protection-keychain`,
     and daemon-owned storage SHALL be that backend's keychain, in an access group that only the
     daemon's signed binary is entitled to. An enrolled presence key SHALL be held there as a
     keychain item, not in a file. The `secure-enclave` backend's file custody
     (`secure-enclave-encryption-backend` Requirement 2) is daemon-owned only in a system
     install, where the service account owns the files, and SHALL NOT serve an official
     user-scoped install.

7.4. In an official user-scoped install, the daemon SHALL run under the hardened runtime, and SHALL NOT carry
     any entitlement that lets another process running as the same uid inject code into it or read
     its memory — among them `get-task-allow`, `disable-library-validation`, and
     `allow-dyld-environment-variables`.

7.5. In an official user-scoped install, the access-group entitlement SHALL be carried by the daemon alone.
     The client SHALL NOT carry it, so that a binary a caller runs is never inside the boundary.

7.6. WHEN an official release build runs as the caller's uid and its selected backend is not
     `data-protection-keychain`, or it cannot reach that backend's keychain under
     Requirement 7.3, THEN it SHALL refuse to start. It SHALL NOT fall back to a file, because
     a file the daemon writes as the caller's uid is storage the caller can write. An official
     release build SHALL NOT run in an insecure posture.

7.7. A revoked or replaced presence key SHALL NOT be restorable by replacing daemon-owned storage
     with an earlier copy of itself. A caller who cannot write daemon-owned storage cannot restore
     it; this criterion forbids any secure posture in which daemon-owned storage is a file the
     caller can replace, even one the daemon authenticates. Encryption (5.10) does not satisfy
     it, because an earlier copy of the registry decrypts as validly as the current one.

7.8. An open-source build MAY run in an insecure posture. WHEN it does, THEN the system SHALL
     warn the user that daemon-owned storage is writable by the caller's uid, and that the
     master key, enrolled presence keys, and integrity bindings are therefore within reach of
     every process running as that uid. The warning SHALL be given:

     - at install, by `credsd install --user`, which SHALL NOT proceed until the user
       acknowledges it interactively, from the terminal rather than from standard input;
     - every time the daemon starts in that posture, as a warning-level log record, whether it
       was started by a LaunchAgent or by `credsd serve`.

     The warning SHALL name the secure posture available to that build: `sudo credsd install`,
     a LaunchDaemon on macOS or a system unit on Linux.

### Requirement 8: Every gate outcome a client can receive is classifiable

**User story:** As the author of a client that is not `creds` — a library consumer that cannot
draw a Touch ID prompt and will not run `sudo` — I want "this needs approval" and "this approval
was refused" to be distinct, machine-readable outcomes, so that I can tell my user what happened
and what to run, and never mistake an unperformed operation for a performed one.

#### Acceptance Criteria

8.1. A challenge SHALL be returned as a JSON-RPC error with the application code and the domain
     code `APPROVAL_REQUIRED`, never as a successful result. Its error data SHALL carry the
     challenge (Requirement 2.4: identifier, digest, description, expiry, the verifiers it
     accepts) and a `remediation` string naming the command that approves it. A client that does
     not recognise the code SHALL therefore observe a failure, not a performed operation.

8.2. WHEN `request/approve` does not satisfy a challenge, THEN the daemon SHALL return the domain
     code `APPROVAL_REFUSED`, with error data carrying a `reason` and a `remediation`. The reason
     SHALL be one of: `not_satisfied` (no proof, and the connection is not privileged),
     `signature_invalid`, `no_presence_key`, `privileged_only` (Requirement 3.6), or
     `base_state_changed` (Requirement 2.6). A refusal SHALL NOT be reported as invalid
     parameters.

8.3. A refusal other than `base_state_changed` SHALL leave the pending operation pending, so that
     the other verifier remains available. A `base_state_changed` refusal discards it.

8.4. A request for a pending operation that does not exist, has been discarded, or belongs to
     another uid on a non-privileged connection SHALL return the domain code
     `REQUEST_NOT_FOUND`, and the three SHALL be indistinguishable on the wire, so that a caller
     cannot learn whether another uid has a pending operation.

8.5. Every gate error SHALL be issued only to a caller authorized for its subject. A caller
     denied by absence SHALL continue to receive `ENVIRONMENT_NOT_FOUND`, so that a challenge
     never confirms that a subject exists to a caller who could not see it.

8.6. Remediation SHALL be supplied by the daemon in the error data. A client SHALL present it
     rather than compose its own, so that remediation text cannot drift from what the daemon will
     accept.

8.7. The client library SHALL expose `APPROVAL_REQUIRED` as its own error, carrying the challenge
     and remediation, and SHALL NOT itself solicit a verifier. Soliciting a presence signature or
     directing a user to `sudo` is the calling application's decision, not the library's.

## Non-Goals

- **A configurable policy layer.** Gating operations beyond the built-in list (Requirement 1.7),
  through a policy engine above the gate, is future work. This spec enumerates only the list.
- **The platform authenticator.** Which primitive holds a presence key and enforces its
  user-presence check — the Secure Enclave on macOS, and whatever a later platform supplies —
  belongs to that platform's backend. This spec states what a presence key must be
  (Requirement 5.3), how it is enrolled, and how its signatures are verified.
- **Attesting a presence key.** The daemon trusts an enrolled key because a privileged approval
  accepted it, not because it verified the key's custody. Remote attestation of a key's hardware
  binding is not available on macOS and is not attempted.
- **A trustworthy prompt.** Neither verifier can make the words an approver sees trustworthy, and
  this spec does not try (Requirement 4.2).

## Relationship to adjacent specs

**`credential-retrieval-api`.** Owns the JSON-RPC error model this spec extends: the
application code, `data.code` as the single classifier, deny-by-absence as
`ENVIRONMENT_NOT_FOUND`, and `REAUTH_REQUIRED`'s payload-carried remediation, which
Requirement 8 follows for the gate's three codes.

**`drift-detection` (accepted).** A consumer. Its revalidation is a gated operation whose
description is the diff and current contents of the files it would seal. It supplies the base
state of a load-bearing file — a digest of the file's canonical form — under Requirement 2.3.

**`sudo` as a verifier.** An earlier proposal held that verified presence must not mean a `sudo`
invocation. This spec does not adopt that constraint: Requirement 3.1 makes privileged approval
one of the two verifiers, because a gate that cannot be satisfied on a machine without a
biometric sensor is a gate that gets disabled. The property that constraint was protecting — that
a same-uid process cannot satisfy the gate on its own — is preserved by Requirements 3.3, 3.4, and 5.2: a same-uid process is not uid 0 and cannot become it
without the credential that makes `sudo` a presence signal, and it cannot enroll a presence key of
its own without that same credential.

## Platform considerations

**Not a one-way door: the two verifiers.** Privileged approval depends only on the operating
system authenticating a privileged invocation, which every target platform can do; on Windows the
privileged connection is an elevated administrator token rather than uid 0. A presence signature is
an optimization available where a platform authenticator can hold a non-exportable, presence-gated
signing key. A platform that gains one gains the presence signature by implementing key generation
and signing in the client, with no change to the challenge, the policy, the evidence, or the audit
record, because Requirement 1.6 keeps the verifier out of the decision.

**One-way door, accepted: install shape follows the trust boundary.** Linux installs only system
units. Windows' install shapes are not yet decided, and Requirement 7 is the test a user-scoped
Windows install would have to pass. macOS runs as a system install (a LaunchDaemon) for every build,
or as a user-scoped install for the official release build only (Requirement 7.2). An open-source
build may also run in an insecure posture, under a warning (Requirement 7.8); that is a permitted
choice, not a supported posture, and nothing in this spec's guarantees extends to it. The rule is that a user-scoped
install exists only where a platform keystore can separate the daemon from other processes running
as the same uid by code identity, and only for a build whose code identity a third party cannot
reproduce. An open-source build can be rebuilt and re-signed by anyone, so its signature is not a
boundary, and the uid of a service account is the only one left. A platform that later wants a
user-scoped install must supply both halves — a keystore gated on code identity, and a signed
build — and Requirement 7 states what each must do. Reversing the rule, to allow a user-scoped
install without them, would make every enrolled key writable by the uid it gates.

**Not a one-way door: login identity.** Its source is per platform — the audit login uid on Linux,
the audit session's audit user id on macOS — and a platform without one records its absence.
Because Requirement 6.3 keeps login identity out of policy, a platform that cannot supply it loses
an audit field, not a decision.
