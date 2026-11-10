# Design: Presence-Gated Operations

## Shape

Three mechanisms, each small, composing into one property:

1. **A pending operation per salvageable denial** — the daemon records what it would do, to which
   subject records, from which base state, for which caller, and holds it in memory.
2. **A challenge over it, satisfied by one of two verifiers** — a presence signature over the
   challenge's digest, or a privileged approval naming it.
3. **An enrolled-key registry** — one presence key per uid, written only by privileged approval.

The property: no gated operation completes on the requesting uid alone, and an approval performs
exactly the operation it named, once, against the state it was approved for.

Presence is evidence, and what decides is the built-in gate fixed in the daemon (Decision 11). A
configurable policy layer above it is future work. Evidence collection itself decides nothing, which is what keeps this spec to a pending-operation store, a signature check, and an
enrolled-key registry.

## Decisions

### 1. The gate is a two-pass evaluation, completed once

The gate evaluates twice: deny, ask whether the deny would flip with `presence_verified = true`,
and if so obtain presence. This spec defines what
"obtain presence" means, and defines it once for every gated operation. A consuming spec contributes
an operation, a description, and — where its records have one — a base state; it does not contribute
a lifecycle.

The floor this spec adds, as two rules of the built-in gate:

- **Enrollment** (`presence/enroll`) is refused without verified presence (Requirement 5). That
  only privileged approval satisfies it is a property of its challenge (Decision 6).
- **Approval** (`request/approve`) is refused without a verified proof (Requirements 3.1–3.4): a
  presence signature over the challenge's digest, or a uid-0 connection.

`proof_verified` is derived by the daemon, like every other evidence value, and says only that the
submitted proof satisfies the named challenge. It does not say which verifier produced it. Both
rules are part of the built-in gate (Decision 11), so no configuration can lift them.

### 2. One challenge, two verifiers, and policy sees neither

Every salvageable deny produces the same thing: a pending operation and a challenge over it. What
varies is only the proof that satisfies the challenge.

| | Presence signature | Privileged approval |
|---|---|---|
| Available where | a presence key is enrolled and a session can prompt | everywhere |
| Who produces it | the requesting client, in the user's session | a separate `sudo` invocation |
| What authenticates it | the platform authenticator's user-presence check | the OS, via uid 0 |
| Bound to the operation by | a signature over the challenge's digest | the identifier, resolved daemon-side |
| Typical round trip | within one CLI invocation | across two |

Splitting at the proof rather than at the request's lifetime is what makes the two verifiers
interchangeable. The pending operation, its expiry, its base-state check (Requirement 2.6), its
description, and its audit record are the same code whichever verifier arrives. A platform that
gains an authenticator adds a verifier; it does not add a mode with its own lifecycle.

Either verifier satisfies any challenge (Requirement 3.1), so the client chooses which to attempt
and the choice confers nothing. The CLI tries a presence signature when it has a key and a session,
and prints `sudo creds request approve <id>` otherwise. A rule that the daemon picks the verifier would
protect against a client steering toward the weaker one; when both are accepted for every
challenge, there is no steering to protect against.

Policy observes `presence_verified` and nothing else (Requirement 1.6). Exposing the verifier would
invite policies that trust one more than the other, and the weaker of two trusted paths is the one
an attacker uses.

### 3. Pending operations live in memory, and are not a queue

The pending-operation store is in-daemon memory, keyed by a random identifier, bounded by expiry.
It holds every gated operation, whichever verifier will satisfy it.

Persisting it would reintroduce the problem `drift-detection` exists to fix: a pending operation
written to disk is a new record, readable and writable by the same uid the threat model names, and
it would need its own sealed snapshot to be trustworthy — which is the recursion. Keeping it in
memory means a daemon restart discards every pending operation, which is the correct fail-closed
behaviour: nothing was written, and the caller retries.

Identifiers are random and unguessable, but Requirement 3.4 does not depend on that. The identifier
names a pending operation; it does not authorize one. Approval is authorized by a verified proof, so
leaking an identifier discloses only that an approval is outstanding.

The pending operation, not the client, is the source of the operation's arguments (Requirement
2.4). A proof is checked against what the daemon recorded, and the daemon performs what it recorded.
A design in which the client re-sends the operation alongside its proof would need the daemon to
compare the two, and every field that comparison missed would be a field an attacker could change
between approval and performance.

Two operations cannot be performed from a record, and are performed by re-send instead
(Requirement 2.8). `environment/bootstrap` runs an interactive provider flow — a device code, an
account and role selection — that streams to the requesting connection and cannot be replayed
from memory, and both it and `environment/import` carry long-term secrets that should not wait in
a pending operation for its lifetime. For these, approval grants a one-use authorization and the
client re-sends.

The objection above is to a field-by-field comparison, and re-send here makes none. The daemon
hashes its own serialization of the arguments as it parsed them, so the digest covers every field
the operation can act on by construction — an added field changes the digest, and a field the
parser drops cannot influence the operation. A re-send is accepted only when that digest, the
subjects' base state, and the uid all equal an unexpired authorization's, which is the same
guarantee a recorded operation gives: what is performed is what was approved.

### 4. The base state is the record's contents, not anything the daemon wrote about them

The base-state check (Requirement 2.6) exists so that an approval given against one state of a
record is not performed against another. It is only as strong as the base state's sensitivity to
change: a value that some edit leaves unchanged is a value that lets that edit through.

So the base state is a digest of the file's contents — for a load-bearing file, of its
canonical form, as `drift-detection` defines it. It is never a value the daemon stored alongside
the file. A sealed snapshot is the obvious candidate and the wrong one: it changes when the
daemon writes and not when anyone else does, so it is blind to exactly the writes the threat model
names. A record that does not exist has its own base state, so an operation that would create a
record is discarded if something else creates it first.

### 5. Who comes from the request; presence comes from the approval

A connection from `sudo creds request approve <id>` is uid 0. The kernel reports nothing else about it, and
`sudo` does not tell the socket who invoked it. Any design that needs the approving connection to
say whose operation it is approving has nothing reliable to ask.

So the approving connection is never asked. A pending operation records its subject — the requesting
connection's kernel-reported uid, pid, and executable — when it is raised (Requirement 2.2), and the
operation is performed for that uid against that uid's caller root (Requirement 3.3). A privileged
approval names a pending operation and contributes one fact: someone here could become root. It
cannot change the subject, because the subject is not a parameter of the approval.

This also settles where uid 0 is served. A uid-0 connection is not resolved to a caller root of
its own for `request/approve` and `request/list`; it is an approver, not a caller.

The cost is the approver's identity. "uid 0 approved" is a weak line in an incident record, so the
audit record adds the approving process's login identity where the kernel keeps one — the audit
login uid from `/proc/<pid>/loginuid` on Linux, the audit user id from the peer's audit token on
macOS. Both are set when a login session opens, survive `sudo`, and cannot be changed by an
unprivileged process. `SUDO_UID` is not used: it is an environment variable, which makes it a claim
made by the client, and Requirement 1.2 admits no client claims as evidence. Login identity stays
out of policy (Requirement 6.3), because it is absent for processes no login started and adds
nothing a decision needs that uid 0 does not already prove.

### 6. Enrollment is the trust root, so only `sudo` can satisfy it

The daemon receives a public key and can verify signatures under it. It cannot verify that the
private half is non-exportable, held by an authenticator, or gated on user presence. Outside
Apple's managed-device attestation, macOS offers no attestation of a Secure Enclave key that the
daemon could check. Everything a presence signature proves therefore rests on the decision to
enroll the key.

That decision must come from outside the uid (Requirement 5.2). If a presence signature could
satisfy an enrollment, a same-uid process could enroll a software key of its own the first time no
key existed — and, once one did, persuade the user to touch the sensor once and enroll a second key
that needs no touch at all. Restricting enrollment to privileged approval makes `sudo` the root and
Touch ID a cheaper credential delegated from it.

The restriction is a property of the enrollment challenge, not a policy rule. A policy rule would
need policy to observe the verifier, which Decision 2 refuses, and it would put the trust root in
the one layer of the system that is designed to be configured. A challenge that accepts only one
kind of proof cannot be configured into accepting another.

Enrollment is the first operation of this kind, not the only one (Requirement 3.6). Any operation
whose approval establishes what later approvals or verifications rest on gets the same restriction,
for the same reason: a presence signature is authority delegated from `sudo`, and delegated
authority should not be able to re-root itself. Enrollment is the first; any future operation
that re-roots trust of the same weight would be the second.

The key is generated by the client, as the enrolling uid, in that uid's session (Requirement 5.3).
The daemon cannot do it: a key the user's Touch ID unlocks has to be created where the user's
session is, and `sudo creds presence enroll` would create it in root's. Enrollment therefore takes
the same two-step shape as any other privileged approval — the user raises it, root ratifies it —
and Decision 5 is what makes that shape carry the right uid.

The enrolled public key is held in daemon-owned storage (Requirement 5.4), not in the caller root.
In the caller root it would be a record the adversary can write: deleting it only forces `sudo`,
but restoring a revoked key's old entry would re-enable it, and a sealed snapshot cannot tell an
old valid entry from a current one.

### 7. The digest is the guarantee; the prompt is a courtesy

A presence signature is produced by the requesting client, so the words on the Touch ID prompt are
chosen by a process running as the requesting uid — the adversary's uid. A privileged approval's
description reaches the approver through their shell, which the same adversary can alias. Neither
verifier can make the description trustworthy, and Requirement 4.2 forbids claiming otherwise.

What both verifiers can do is bind the proof to the operation. A presence signature covers the
challenge's digest, and the daemon performs the pending operation that digest names; a privileged
approval names the pending operation directly, resolved daemon-side. The adversary can lie about
what an approval is for. It cannot make an approval for one operation perform another, and it
cannot produce an approval without a finger on the sensor or someone becoming root.

The signed message is domain-separated so a presence key's signature cannot be lifted into any
other protocol:

```
"credsd-presence-v1" 0x00 <challenge-id> 0x00 SHA-256(<pending-operation canonical form>)
```

### 8. Daemon-owned means owned by an identity the caller does not have

Requirement 5.4 needs storage the enrolling uid cannot write, and a uid can write everything its
own processes can. So "daemon-owned" has to name an identity other than the caller's, and the two
secure postures supply different ones (Requirement 7):

| Posture | Daemon runs as | Daemon-owned storage | The caller is kept out by |
|---|---|---|---|
| System install (Linux system unit; macOS LaunchDaemon, any build) | a service account | a directory the service account owns, under any backend — on macOS, `secure-enclave` or `file` | the uid |
| Official user-scoped install (macOS LaunchAgent, official release build only) | the caller's uid | the `data-protection-keychain` backend's keychain, daemon's access group | the code signature |
| Insecure (open-source build as the caller's uid: a LaunchAgent, or `credsd serve`) | the caller's uid | files the caller can write | nothing — the user is warned (Requirement 7.8) |

The `secure-enclave` backend keeps its key blob and sealed master key as `0600` files
(`secure-enclave-encryption-backend` Requirement 2). Those files are daemon-owned when a service
account owns them, which is why that backend serves a system install and no other. A user-scoped
install selects `data-protection-keychain` instead (Requirement 7.3), so "never a file" holds
without carving an exception for the enclave blob.

In every posture the enrolled-key registry is sealed under the encryption master key (Requirement
5.10), with the same AEAD envelope as every other sealed artifact. The public keys are not secret,
but the registry says which uids can approve without `sudo`, by which key, and who approved each
enrollment, and nothing at rest needs to be readable outside the daemon. Sealing also makes a
tampered registry fail closed (Requirement 5.11) in the postures where custody alone would not
catch it. It is not the rollback defence: an earlier sealed registry decrypts as validly as the
current one, which is why custody, not encryption, carries Requirement 7.7. The cost is that the
registry is tied
to the master key, so a master-key regeneration loses every enrolled key and each uid re-enrolls
under privileged approval — the same recovery as an unreadable credential.

In a system install the registry can be a file, `<data_dir>/presence/enrolled.enc`, because the
caller cannot write the directory it sits in — and so cannot delete, edit, or restore it.

In an official user-scoped install every file the daemon can write, the caller can write too. Sealing
a file would stop edits but not restores: an old, validly authenticated registry that still lists
a revoked key re-enables it (Requirement 7.7), and no MAC can tell an old valid registry from the
current one. A keychain item has no earlier copy for the caller to put back, because the caller
cannot write the item at all. An official user-scoped install serves one uid, so the registry holds
one entry, and one item holds the sealed registry.

That item is one per home. A file custody sits inside the home and dies with it; a keychain item
outlives the home, so the item's name carries the home's instance namespace
(`storage-backend-per-home` Requirements 5.1-5.3): `presence-enrolled.<ns>`. Custody is the access
group, which an item's name neither supplies nor weakens, so scoping the name costs the custody
property nothing. Without it a second home on the machine is born holding the approval authority
a different home enrolled, which nobody there approved.

The daemon picks the custody from its storage backend, not from a posture it would have to infer:
under `data-protection-keychain` the registry is the home's `presence-enrolled` slot, and under
every other backend it is the file. Requirement 7.3 makes that backend the only one an official
user-scoped install runs on, so the two rules agree wherever the custody matters. Either way the
bytes are the same sealed envelope.

The keychain's access group is enforced against the `keychain-access-groups` entitlement, so in an
official user-scoped install the signature is the security boundary, and the rest of Requirement 7 follows
from taking that seriously:

- **Hardened runtime, and no entitlement that weakens it** (Requirement 7.4). Without it, a process
  running as the same uid can inject a library into the daemon or attach to it, and then write the
  item as the daemon — or read the pending operations out of its memory.
- **The client is outside the boundary** (Requirement 7.5). The client is a binary the caller runs
  with arguments the caller chooses. If it carried the entitlement, the boundary would include
  every code path in it.
- **No fallback for the official build** (Requirement 7.6). An official build running as the
  caller that cannot reach the keychain item — a missing entitlement, or a backend other than
  `data-protection-keychain` — has no daemon-owned storage. Writing a file instead would quietly
  turn the posture the user chose for its protection into one without it.
- **Only the official build** (Requirement 7.2). A signature is a boundary only when an attacker
  cannot produce it. Anyone can rebuild open-source credsd and sign it with an access group of
  their choosing, so for those builds the service account is the only identity the caller lacks.

An open-source build running as the caller has no boundary to offer, so it is not a supported
posture — but it is a legitimate one to choose, for development or where `sudo` is unavailable. It
runs, and it says so (Requirement 7.8): an acknowledged warning at install, because that is where
the choice is made, and a warning-level record at every start, because a LaunchAgent outlives the
terminal that installed it and `credsd serve` has no install step at all. Refusing to run would
push those users to patch the check out, which is the same posture with no warning. The warning
names the secure alternative rather than only the risk.

The same reasoning governs `drift-detection`'s integrity record. It is held under the same
custody, chosen from the backend the same way, because it too is a record whose earlier copy, put
back, would undo an approved change. The custody of both is verified under `drift-detection`
Requirement 10.8.

### 9. A challenge is an error, and every refusal has a code

The gate's outcomes reach clients that are not `creds`: library consumers that cannot draw a
prompt, will not run `sudo`, and classify failures by `data.code` alone, as
`credential-retrieval-api` defines it. Each outcome is shaped for that reader.

**A challenge is an error** (Requirement 8.1). An operation that has not been performed is a
failure from the caller's point of view, whatever happens next. Returned as a successful result,
a challenge is indistinguishable from completion to any client that predates it: a mutation
whose result type carries no fields deserializes `{"challenge": …}` as success and reports a
write that did not happen. As an error, an unrecognised challenge fails closed — every existing
client maps an unknown domain code to a generic failure carrying the daemon's message — and the
invariant that an `RpcError` means the daemon answered stays whole.

**The codes follow the precedent already in the API.** The domain codes are
`ENVIRONMENT_NOT_FOUND`, `REAUTH_REQUIRED`, `WRONG_CREDENTIAL_TYPE`, `PROVIDER_UNAVAILABLE`,
`INTERNAL`, `AUTH_TIMEOUT`, and `AUTH_CANCELLED`. `REAUTH_REQUIRED` is the one shaped like a
challenge: a refusal a human can resolve, carrying the subject and a `remediation` string in its
data. `APPROVAL_REQUIRED` takes the same `<what is missing>_REQUIRED` form and the same payload
convention. None of the existing codes fits — `REAUTH_REQUIRED` would send a client into a login
flow that cannot satisfy an approval — and the envelope's `-32602` is what the gate must stop
returning, because it tells a client its parameters were wrong when they were not.

**Three codes, because codes are permanent.** `credential-retrieval-api` makes domain codes
additive-only, so each name coined here is coined for good. The set is the smallest that gives
each outcome a distinct next action:

| Code | The caller's next action |
|---|---|
| `APPROVAL_REQUIRED` | have the operation approved; `remediation` says how |
| `APPROVAL_REFUSED` | depends on `reason` — retry the other verifier, enroll a key, or raise again |
| `REQUEST_NOT_FOUND` | raise the operation again |

Reasons are a field, not codes, so that a reason can be added without coining a permanent name,
and so a client that knows only `APPROVAL_REFUSED` can still act on the daemon's remediation.

**Refusal keeps the request alive** (Requirement 8.3), except when the base state changed. A
signature that fails, or an approval from an unprivileged connection, says nothing about whether
the other verifier will succeed. Discarding on refusal would let any same-uid process cancel an
owner's pending operation by submitting a bad proof for it. A changed base state is different:
nothing can satisfy that approval any more.

**Not-found stays uninformative** (Requirement 8.4). Expired, withdrawn, discarded, and another
uid's request all read the same, so a request identifier is never an oracle for another user's
activity. The owner loses the distinction between "expired" and "discarded"; the audit record
keeps it (Requirement 6.1), and the remedy — raise it again — is the same either way.

**Deny-by-absence takes precedence** (Requirement 8.5). The gate runs only after a caller has
been authorized for its subject; a caller who has not receives `ENVIRONMENT_NOT_FOUND` exactly as
before, so `APPROVAL_REQUIRED` can never be used to discover that an environment exists.

**The library reports; the application decides** (Requirement 8.7). `credsd-client` surfaces
`APPROVAL_REQUIRED` as an error variant carrying the challenge and remediation, and does not
attempt a signature or print instructions. A synchronous consumer can then refuse with the
daemon's own remediation, and `creds` — the one client that can prompt — layers Touch ID and
`sudo` handling on top.

### 10. The client's key lives in `~/.credsd/`, in a JSON wrapper

The Secure Enclave returns a presence key's private half as an opaque `dataRepresentation` that
only this device's enclave can use, and only with the user present. The client keeps it in
client-owned storage, `~/.credsd/` (Requirement 5.12), never in the daemon's data directory.

**Location.** Separating storage by writer is what keeps "daemon-owned" from blurring. In a
user-scoped install the daemon's data directory is `~/Library/Application Support/credsd`, and
its LaunchAgent sets `CREDSD_DATA_DIR` to it, which shells started from the same session can
inherit. A client that resolved its own files from that variable or that directory would write
into the daemon's storage. So the client's directory is a fixed path under `$HOME` with no
override shared with the daemon. In a user-scoped install the two directories have the same
owner, so this separation does not keep the caller out of anything. The keychain access group
does that (Decision 8). What the separation guarantees is that each directory has one writer, and
that nothing of the client's is ever mistaken for daemon state.

**Format.** The file is a small JSON wrapper rather than the bare enclave bytes:

- **Requirement 5.13 needs the public key without the enclave.** The client checks a challenge's
  fingerprint against its key before prompting. Getting the public key from the enclave would
  mean using the key, which prompts. So the wrapper stores the public key, and the client derives
  the fingerprint from it rather than storing a second field that could disagree with it.
- **Requirement 5.14 needs two keys told apart.** A replacement waits in
  `presence-key.pending.json` until a challenge names its fingerprint, and then replaces
  `presence-key.json`. A replacement that is never approved never displaces the enrolled key.
- **A version field** lets a later shape, such as another authenticator's key, be refused by name
  rather than handed to the enclave as bytes it cannot parse.

It is not sealed. The client has no master key (`client-storage-delegation`), and sealing bytes
that only this enclave can use, with the user present, protects nothing more. A backup restored
to another Mac carries a key that no enclave there can use, and that the daemon there has not
enrolled. No challenge names it, so the client does not prompt (Requirement 5.13), and the user
enrolls on that Mac.

### 11. The built-in gate is a floor, fixed in the daemon

Requirement 1.7 lists the operations that need verified presence whatever policy says: every
operation that changes a caller's existing configuration or sealed material, and enrollment. It is
code, not configuration, because the list is the security property — an operation that could be
removed from it by editing a file is an operation same-uid code could remove from it.

A policy layer, if one is added later, composes with it rather than replacing it: it may gate
further operations and may not ungate these, the same as the approval and enrollment rules in
Decision 1. The daemon is fully gated without one, so adding one can only add restrictions.

The floor excludes operations that change nothing — a first bootstrap, which writes over nothing,
and an unset of a key that is not set. A prompt for those would ask the approver to agree to
nothing, which teaches them to stop reading prompts. The consequence is accepted and stated: a
same-uid process can create a new environment or credential without approval. It cannot redirect
an existing one, and a name it claims first is visible when the owner later bootstraps that name,
because that bootstrap is then gated as a replacement.

## Rejected alternatives

**Returning a challenge as a successful result.** A client that does not know about challenges
reads it as a performed operation. Decision 9.

**Returning refusals as invalid parameters.** Tells a client its request was malformed when it was
well-formed and unauthorized, and leaves classification to parsing English. Decision 9.

**One domain code per refusal reason.** Each code is permanent, and a client branching on five
codes to reach one remediation string gains nothing from the split. Decision 9.

**Discarding a pending operation on a refused approval.** Lets a same-uid process cancel the
owner's request by submitting a bad proof. Decision 9.


**A sealed enrolled-key file as the custody in an official user-scoped install.** Sealing stops
edits. It does not stop restoring an older sealed file, which re-enables a revoked key. The registry
is sealed in every posture (Requirement 5.10), but in this posture it also needs custody the caller
cannot write. Decision 8.

**Treating an open-source build's user-scoped install as a secure posture.** The signature that
would separate the daemon from the caller is one anyone can produce. It is permitted as an insecure
posture under a warning instead. Decision 8.

**Refusing to run an open-source build as the caller.** Closes the insecure posture outright. Leaves
development and sudo-less machines with a patched-out check and no warning. Decision 8.

**The bare enclave bytes as the client's key file.** Leaves the client unable to tell which key a
challenge names without prompting, and a replacement key with nowhere to wait. Decision 10.

**The client's key in the daemon's data directory.** In a user-scoped install the two directories
would be one, and a client file would sit among daemon state. Decision 10.


**A bearer token the requester redeems (`change_id`).** Lets the requester carry proof from an
approval step. Makes possession of a value sufficient to pass the gate, which Requirement 3.4
rejects: the same-uid adversary that raised the request can read the requester's memory and files.
A challenge is not this. Its identifier and digest are public to the requester by design, and
satisfying it takes a signature only the authenticator can produce or a connection only root can
open.

**A daemon-drawn, synchronous prompt.** The daemon holds the request and raises the Touch ID prompt
itself, so the prompt's words are not the client's. It is the stronger property where it is
available, and it is not available where it matters: a daemon running outside the user's GUI
session — a LaunchDaemon, a system service, any Linux install — has no session to draw in. It also
gives the two verifiers different lifecycles, a held request and a pending one, which is two
implementations of the gate. Decision 7 states what is given up instead.

**Using a file's sealed snapshot as its base state.** Already in the companion file, and cheap to
compare. Unchanged by every write that does not go through the daemon. Decision 4.

**Running enrollment under `sudo`.** `sudo creds presence enroll` would generate the key in root's
context, where the user's prompts cannot reach it, and present uid 0 over the socket, enrolling the
key for root. Decision 5 and Decision 6.

**Taking the approver's identity from `SUDO_UID`.** Set by `sudo`, but read from the client's
environment, so it reaches the daemon as a claim. Requirement 1.2. The kernel's login identity
serves the same audit purpose without being client-supplied. Decision 5.

**Trust on first use for presence keys.** Accept the first key a uid enrolls without approval. The
first enrollment is exactly the one a same-uid process can race, and the user would never know it
lost. Requirement 5.2.

**Letting an enrolled key approve enrolling another.** Saves a `sudo` on key replacement. Lets one
touch of the sensor — for a prompt whose words the adversary chose — enroll a key that needs no
touch thereafter. Decision 6.

**Letting policy see the verifier.** Would allow "Touch ID for endpoint changes, sudo for everything
else". Also creates a weakest-path target and makes a policy's meaning depend on the hardware it
runs on. Decision 2.

**A headless bypass.** An operation permitted because no session exists is an operation a background
process can reach by ensuring none does. Requirement 3.5.

## Data shapes

A pending operation (Requirement 2.2), as held in daemon memory — never on disk (Decision 3):

| Field | Source |
|---|---|
| `id` | random, 128 bits |
| `operation`, `arguments` | the request that was denied salvageably |
| `subjects` | each record it would write, with its base state at request time (Decision 4) |
| `owner_uid`, `owner_pid`, `owner_executable` | the requesting connection, kernel-reported |
| `accepts` | `any`, or `privileged` for a privileged-only operation (Decision 6), fixed by the operation |
| `created`, `expires` | daemon clock |
| `digest` | SHA-256 of the canonical form of every field above except `digest` |

The challenge returned to the client is `{id, digest, description, expires}`. A presence signature
is over the message in Decision 7. It travels as an error (Decision 9):

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "error": {
    "code": -32000,
    "message": "approval required: set sdk.endpoint_url on environment 'work'",
    "data": {
      "code": "APPROVAL_REQUIRED",
      "challenge": {
        "id": "req-5d1e07",
        "digest": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "description": "set sdk.endpoint_url on environment 'work'",
        "expires_in_secs": 900,
        "accepts": "any"
      },
      "remediation": "approve with Touch ID, or run: sudo creds request approve req-5d1e07"
    }
  }
}
```

A refused approval:

```json
"data": {
  "code": "APPROVAL_REFUSED",
  "reason": "not_satisfied",
  "remediation": "no presence key is enrolled for uid 1000 and this connection is not privileged; run: sudo creds request approve req-7f3a91"
}
```

An enrolled presence key (Requirement 5.4), one entry of the enrolled-key registry, in
daemon-owned storage — `<data_dir>/presence/enrolled.enc` in a system install, or the
`presence-enrolled` slot of the `data-protection-keychain` backend in an official user-scoped
install (Decision 8). Either way the stored bytes are the registry, serialized as JSON and sealed
under the master key (Requirement 5.10), never these fields in plaintext. It is JSON rather than
TOML because it is daemon-written state, not a hand-edited record (`AGENTS.md`, Persisted
formats):

| Field | Meaning |
|---|---|
| `uid` | the uid it satisfies challenges for |
| `public_key` | ECDSA P-256, SEC1 uncompressed |
| `fingerprint` | `SHA256:` + base64 of the SHA-256 of the public key |
| `enrolled_at`, `approved_by_uid`, `approved_by_login_uid` | from the approving connection |

A client's presence key (Requirement 5.12), in client-owned storage as
`~/.credsd/presence-key.json`, or `~/.credsd/presence-key.pending.json` while a replacement awaits
approval (Decision 10). JSON, `0600`, not sealed:

| Field | Meaning |
|---|---|
| `version` | `1`; any other value is refused, not passed to the enclave |
| `policy` | `biometry` or `presence`, the access control it was created with |
| `public_key` | hex ECDSA P-256, SEC1 uncompressed; the fingerprint is derived from it |
| `key` | hex of the enclave's `dataRepresentation` |
| `created_at` | RFC 3339 |

The audit record (Requirement 6.2), as emitted through the existing audit path. Consuming specs add
evidence fields — `drift-detection` adds `record_drifted`:

| Field | Source |
|---|---|
| `operation` | the gated operation |
| `subjects` | the records evaluated |
| `evidence.presence_verified` | the gate |
| `evidence.proof_verified` | the verifier, for `request/approve` |
| `evidence.is_root` | `SO_PEERCRED` uid |
| `evidence.caller_uid`, `caller_pid`, `caller_executable` | the caller assessment (`SO_PEERCRED` and process lookup) |
| `decision` | `Allow` / `Deny` |
| `pending_operation` | the identifier, where a challenge was raised |
| `verifier` | `presence_signature` / `privileged_approval` / `none` |
| `presence_key` | the fingerprint, presence signature only |
| `approver_uid`, `approver_login_uid` | privileged approval only; the second from the kernel, where kept |
| `outcome` | what the daemon did |

## Evaluation order

```
built-in gate (operation, subjects, evidence)
        │
    evaluate ──► Allow ──► perform
        │
        └──► Deny ──► salvageable with presence_verified = true?
                          │
                    no ───┴─── yes
                     │          │
              hard deny    record pending operation ──► return challenge {id, digest}
              + audit                                          │
                                       ┌───────────────────────┴───────────────────┐
                           presence signature over digest            sudo creds request approve <id>
                           (client, Touch ID)                        (uid-0 connection)
                                       └───────────────────────┬───────────────────┘
                                                               │
                                         request/approve ──► proof_verified?
                                                               │
                                         subjects still in their base state?
                                                               │
                                         re-evaluate with presence_verified = true
                                                               │
                                         perform the pending operation, discard
```

Every terminal state in that diagram — hard deny, expiry, withdrawal, base-state change, perform —
emits exactly one audit record.

## Correctness properties

1. **The gate cannot be satisfied by the adversary.** A same-uid process has neither a presence
   key's user-presence check nor uid 0, possession of a challenge confers nothing, and it cannot
   enroll a key of its own (Req 3.4, 5.2).
2. **An approval authorizes exactly one operation.** A proof binds to a digest, the daemon performs
   what the digest names, once, against the state it was approved for (Req 2.4, 2.5, 2.6).
3. **The base state sees every edit.** It is a digest of contents, so no write — the daemon's or
   anyone else's — leaves it unchanged (Req 2.3).
4. **The approver cannot change the subject.** The subject is fixed when the request is raised, by
   the kernel, and is not a parameter of approval (Req 3.3, 5.1).
5. **No client input reaches the decision.** Every evidence value is daemon-derived (Req 1.2).
6. **The floor is not liftable.** The approval and enrollment rules are part of the built-in gate,
   which no configuration can change (Req 1.5).

## Error handling

| Condition | Behaviour | Criterion |
|---|---|---|
| Salvageable denial | `APPROVAL_REQUIRED`, carrying the challenge and remediation | 2.1, 8.1 |
| Presence prompt cancelled or failed | pending operation kept for privileged approval or explicit withdrawal; subject unchanged | 2.5 |
| No presence key, or no session | challenge printed for privileged approval; not a bypass | 3.5 |
| Signature invalid, or by a key not enrolled for the owner | `proof_verified = false`; `APPROVAL_REFUSED`, `signature_invalid` or `no_presence_key`; still pending | 3.2, 8.2, 8.3 |
| Presence signature submitted for a privileged-only operation | `APPROVAL_REFUSED`, `privileged_only`; still pending | 3.6, 5.2, 8.2 |
| Approval without a proof and without uid 0 | `APPROVAL_REFUSED`, `not_satisfied`; still pending | 3.4, 8.2 |
| Subject not in its base state at approval | `APPROVAL_REFUSED`, `base_state_changed`; pending operation discarded unperformed | 2.6, 8.2 |
| Subject record unreadable at approval, or at the commit of a bootstrap re-send that spent its approval | `APPROVAL_REFUSED`, `base_state_changed`; discarded unperformed, with an audit record giving the error kind | 2.6 |
| Pending operation expired, satisfied, withdrawn, or another uid's | `REQUEST_NOT_FOUND`, indistinguishably | 2.5, 8.4 |
| Second enrollment raised while one is pending | both discarded; requester told of the other | 5.6 |
| `presence enroll` raised from uid 0 | refused; enrollment is for the requesting uid | 5.1 |
| Daemon restart with pending operations | discarded | Decision 3 |
| Enrolled-key registry fails to decrypt or authenticate | no key trusted; error-level audit record naming the custody; registry left in place, and enrollment and revocation refused until an operator moves it aside | 5.11 |
| Client holds no key with the challenge's fingerprint | no prompt; challenge printed for privileged approval | 5.13 |
| Client key file of an unknown `version` | treated as absent; never passed to the enclave | Decision 10 |

## File changes

| File | Role |
|---|---|
| `crates/credsd-daemon/src/authorization.rs` | Schema: `request/approve`, `presence/enroll`, `presence_verified`, `proof_verified`; the built-in rules |
| `crates/credsd-daemon/src/server/pending.rs` | New. Pending-operation store, digest, expiry, base-state check, proof resolution |
| `crates/credsd-daemon/src/server/presence.rs` | New. Enrolled-key registry sealed under the master key at `presence/enrolled.enc`, signature verification, enrollment; storage per posture |
| `crates/credsd-core/src/storage/` | Data protection keychain item for the enrolled key, official user-scoped installs |
| `crates/credsd-daemon/src/main.rs` | Official build: refuse to start as the caller without daemon-owned storage. Open-source build: warn on every start in an insecure posture |
| `crates/credsd-daemon/src/install.rs` | Insecure-posture warning and interactive acknowledgment for an open-source build's `install --user` |
| Signing and entitlements for the official macOS build | Hardened runtime; access-group entitlement on the daemon only |
| `crates/credsd-daemon/src/server/uds.rs` | Serve uid 0 as an approver without a caller root; sample login identity |
| `crates/credsd-daemon/src/server/dispatch.rs` | Route salvageable denials into the pending-operation store; the built-in gate for `config/set`, `config/unset`, and both removals; one approval flow for every operation (base-state recheck, then perform or authorize) |
| `crates/credsd-daemon/src/server/bootstrap.rs` | The built-in gate for `environment/bootstrap` and `environment/import`: overwrite detection, the arguments digest, and spending a re-send authorization (Requirement 2.8) |
| `crates/credsd-core/src/rpc/methods.rs` | `request/approve`, `request/list`, `request/withdraw`, `presence/enroll`, `presence/revoke` |
| `crates/credsd-core/src/rpc/mod.rs` | `DomainCode::{ApprovalRequired, ApprovalRefused, RequestNotFound}`; constructors carrying challenge, reason, and remediation |
| `crates/credsd-core/src/rpc/uds.rs` | Map the three codes in `error_to_daemon` |
| `crates/credsd-client/src/lib.rs` | `ClientError::ApprovalRequired { challenge, remediation }` and `ApprovalRefused { reason, remediation }`; no prompting |
| `crates/credsd-core/src/presence/` | New. Client-side presence-key generation and signing; macOS backend over the Secure Enclave |
| `crates/credsd/src/main.rs` | `creds request`, `creds presence enroll\|revoke` |
| `crates/credsd/src/presence.rs` | Client key file in `~/.credsd/`; sign only with the key a challenge names; promote a replacement once enrolled |
| `crates/credsd-core/src/config/platform.rs` | `client_dir()`: `~/.credsd/`, `0700`, owned by the running uid |

## Open decisions

**A machine where nobody can become root.** Without `sudo`, privileged approval is unreachable, and
on Linux there is no presence key either — so no gated operation can complete, and a hand-edit
under `drift-detection` is unrecoverable without re-bootstrapping. On macOS the same user cannot
enroll a key, because enrollment needs root. That may be the correct posture — a machine where
nobody can prove presence is a machine where nothing should be ratified — but it should be a
decision rather than a discovery.

**Recovering an unreadable registry held in a keychain slot.** Requirement 5.11 leaves an
unreadable registry in place and refuses to write over it, and an operator recovers a file by
moving it aside. The `presence-enrolled` slot is reachable only by the daemon's signed binary, so
no operator command reaches it today. That needs a privileged-only daemon operation that clears
the slot, or an argument that a slot whose envelope fails to authenticate cannot arise without a
master-key loss that already forces re-enrollment.

**Locating the daemon under `sudo`.** `sudo creds request approve <id>` runs with root's environment, and for a
user-scoped install the socket is found from the invoking user's home. The approving client needs a
way to reach the right daemon that does not trust an environment variable for anything beyond
finding the socket.

**Whether a Linux presence key exists.** A FIDO2 authenticator, or a TPM key behind a PIN policy,
could serve as a Linux presence key under Requirement 5 unchanged. Whether either is worth
supporting, and whether a TPM PIN is a presence signal or only a second factor, is open.

**Windows install shapes.** Requirement 7.2 settles Linux and macOS. Whether Windows has a
user-scoped install depends on whether it can supply a keystore gated on code identity and a build
whose signature a third party cannot reproduce; DPAPI under the user's own profile is readable by
every process running as that user, and is not one.

**Prompt text on macOS.** The Touch ID prompt's reason string is supplied by the signing process
(Decision 7). Whether the CLI should show the daemon's description verbatim, or a fixed string
that points at the terminal, is a usability question with no security difference.
