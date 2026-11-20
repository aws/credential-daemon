---
status: draft
created: 2026-11-09
---

# Design: aws-login identity

## Decision 1: where the Signed_In_Identity comes from

`sts:GetCallerIdentity`, called with the new credentials before anything is persisted. STS
authenticates the credentials and returns the assumed-role (or user) ARN, which carries partition,
account, resource type, name, and session. No token signature needs verifying. The call uses the AWS
SDK's own endpoint resolution for the credential's region, so every partition works. It is an
outbound STS request like any other, so it goes through the HTTP client `outbound-network`
defines for STS (`net::sdk_http_client()`, Requirement 1.2b), not the SDK default. A failure
fails the sign-in with nothing saved. The `idToken` `sub` is kept for reference only.

Considered and rejected: trusting the `idToken` claims, with or without signature verification.
Verification needs Sign-In's keys per partition; trusting it unverified relies on parsing alone.

The AWS CLI does neither. `aws login` reads the `sub` claim out of the `idToken` unverified
(`awscli/customizations/login/utils.py`) and stores it as the profile's `login_session`, then
compares that string on the next login to decide whether to prompt. So credsd's identity is a
different and stronger fact than the CLI's: STS-authenticated rather than parsed from a token, and a
Principal rather than a session. There is nothing to reuse, and the two values are not
interchangeable.

## Decision 1a: equality on the Principal

The session name changes on every sign-in, so equality uses the Principal: partition, account,
resource type, and the role or user name. The resource type is part of it — one account can hold a
role and an IAM user of the same name, and they are different principals with different permissions.
The same Principal is saved ungated; a different one, or no record, is gated.

## Decision 2: storage

`identity.enc` in the credential's sealed directory, sealed with the path-bound AAD every sealed file
uses. Like the token and key, it is first sealed in the bootstrap's staging directory, under the
staging path, and install rebinds every staged `.enc` to its final path's AAD before the directory
is renamed into place (`sealed-file-path-binding` 1.1). What opens afterwards is therefore bound to
the credential's real path; a record left bound to the staging path would fail to open and read as
no record, which gates (Requirement 5.2) rather than matching. It is not part of `credentials.toml`, so a hand edit cannot change it, and it is not part of
the drift snapshot (it is daemon-written sealed state, like the token). `credential/logout` keeps it;
`credential/remove` deletes it. Requirement 5.3 records what path binding does not cover.

## Decision 3: gate change

`presence-gated-operations` 1.7 gates `credential/bootstrap` "when the credential exists". This spec
narrows that row rather than removing it: an `aws-login` bootstrap under the same provider source is
ungated **only** when the signed-in Principal is the one on record. A different Principal, no
record, a record that will not open, a tier change, and any other provider source all stay gated.

The narrowing is sound because a re-sign-in as the recorded Principal replaces one session with
another from the same account and role, which is the same thing `credential/login` does ungated.
Whoever signs in is no longer a question the caller answers — the daemon reads it from STS — so the
exemption does not rest on anything the caller asserts, which `presence-gated-operations` 1.2
forbids.

Considered and rejected: asking the client to confirm a changed identity instead of gating it. The
client is the caller, so a hostile process running as the user answers its own prompt and re-points
the credential at an attacker's account with no presence check — exactly the actor the gate exists
for. The prompt would have read as a control while being a courtesy.

## Decision 3a: where the decision is taken

At commit, under the per-caller write lock, not at entry. Two reasons:

- The identity is not known at entry. The sign-in has to run first, and with `name_prefix` the
  credential's *name* is not known either.
- Reading the record at entry and writing at commit is a race: a concurrent same-source bootstrap
  could change the record in between. One decision, inside the lock that performs the write, closes
  it (Requirement 2.6).

The entry check still runs for every other provider and for a different provider source, so a
sign-in that cannot be committed is still refused before the user is sent to a browser where
possible.

**This makes the identity decision an after-the-fact one, and that is worth saying plainly.** The
sign-in is performed unconditionally: by the time credsd knows who signed in, the user has really
authenticated at Sign-In and a real session exists in memory. What the gate decides is only whether
it may be *persisted*. Two consequences follow. A refused change wastes a sign-in, so the error says
so and tells the user to approve and sign in again — the second sign-in a re-run asks for is
expected, not a bug. And the unsaved session is dropped with the staging directory rather than
revoked at the issuer, so it remains valid at AWS until it expires on its own; credsd never handed
it to anything, but it is not a revocation. Revoking a refused sign-in would need a Sign-In logout
call and is not in scope here.

## Decision 3b: binding an approval to the Principal

An approval for an identity change is spendable only for the change the challenge named: from the
Principal on record to the Principal that signed in. The params digest the authorization covers is

```
SHA-256("aws-login-identity\0" || params_digest || recorded || signed_in)
```

where `signed_in` is the length-prefixed partition, account, resource type, and name, and
`recorded` is a one-byte tag — `0` for no readable record, `1` followed by the same four
length-prefixed fields for a record. The session is excluded, because the re-run's sign-in gets a
new one, and every field is length-prefixed so no two different pairs can concatenate to the same
bytes.

Without the signed-in half, an approval shown "move to account A" could be spent by a re-run that
signs in as account B: the re-send carries the same request params either way, and the identity is
not a request param. Without the recorded half, an approval shown "X → A" could be spent after the
record became Y — by another approved change, or by a same-uid caller deleting `identity.enc` or
restoring an archived one (Requirement 5.3) — moving the credential off a Principal the approver
was never shown. Both halves are read under the write lock that installs (Requirement 2.6), so the
pair the digest names is the pair the install acts on. Binding them keeps
`presence-gated-operations`' property that an approval authorizes exactly what the approver was
shown.

It also makes the `name_prefix` form approvable at all. The credential's name is derived from the
Principal (Requirement 4.2), so a re-run that signs in as the approved Principal derives the same
name *and* the same bound digest, and spends the approval. Had the name kept the session, every
re-run would have addressed a different credential and no approval could ever be spent.

## Decision 3c: `credential/login` refuses rather than challenges

`login` persists a sign-in only as the recorded Principal; anything else fails with nothing saved
and names the gated bootstrap. It raises no challenge of its own because it has no respond method
(`credential-retrieval-api` defines `credential/bootstrap/respond` with no login equivalent) and no
approval re-send path, so a challenge would have nowhere to be answered and every change would dead
-end. Re-pointing a credential at another account is a replace, and replaces go through bootstrap.

## Flow

1. Sign-in completes; tokens and DPoP key are held in memory.
2. Call `sts:GetCallerIdentity` with the new credentials; derive the Signed_In_Identity. On failure,
   discard and fail.
3. If `name_prefix`: build and normalize the name from the Principal (Requirement 4.2).
4. Seal the material into the staging directory, including `identity.enc`, under the staging
   path's AAD. Nothing is in place yet.
5. Take the write lock. Read the Identity_Record at the credential's real path.
6. No credential: install, return.
7. Same provider source and same Principal: install, return (no challenge).
8. Otherwise: spend an approval bound to the recorded and signed-in Principals (Decision 3b), or
   raise a challenge naming both and return `APPROVAL_REQUIRED`. The staging directory is dropped,
   so nothing is kept.
9. On install, rebind each staged `.enc` to its final path, then rename the directory into place.

## API versus presentation

The daemon returns `{ credential, identity }` from `credential/bootstrap` and nothing else about
presentation; the identity carries `arn`, `partition`, `account`, `kind`, `name`, `session`, and an
optional `sub`. A challenge's `description` is the daemon's own wording, as for every other gated
operation, because the approver may be at a different terminal than the caller. How `creds` or any
other client renders either is the client's business, and two clients may word them differently.

There is no `identity_changed` progress message: an identity change is an `APPROVAL_REQUIRED`
error, which every client already handles, rather than a step a client must learn to answer.

## Interaction with `credential/logout`

`credential/logout` deletes tokens and key but keeps `identity.enc`, so the next sign-in compares
against the identity that was signed out (Requirement 1.4). A kept record means a re-sign-in as the
same Principal is ungated, which is the point: signing back in after a sign-out is not a replace.

## Decision 4: what makes a provider source "the same"

The region and the `identity_type`, as Requirement 2.1 states normatively. `callback_port` and
`remote` are how *this machine* reaches Sign-In, not where the credential comes from, so they do
not make a different source. The `identity_type` *is* the credential's tier, so a tier change is a
different source, because it changes what the credential is allowed to compose, and the gate is
what discloses that.

## Migration

No existing `aws-login` credential has an Identity_Record. For `credential/bootstrap` that changes
nothing: replacing an existing credential is gated today, and a credential with no record stays
gated, so an old credential behaves exactly as it does on `main`. The new cost is on
`credential/login`, which today re-authenticates an `aws-login` credential ungated and, under
Requirement 3.6, refuses one with no record. Each existing credential therefore needs one approved
bootstrap to record who signs in, and after that `login` is ungated again for that Principal.

Two ways to avoid that cost were considered and rejected:

- Trust-on-first-use: record whoever signs in next when there is no record. In a user-scoped install
  the daemon's data directory is owned by the caller's own uid, so a same-uid process can delete
  `identity.enc` and then sign in as an account it controls; "no record" has to gate rather than to
  trust (Requirement 2.4).
- Let `login` skip the check when there is no record. That is no worse than `main` for a credential
  nobody has touched, but the same deletion turns the check off for any credential, so it would hold
  only until an attacker chose to remove it.

## Open questions

1. Foreign creator (gap 6): a credential another tool created under the same provider source is
   reachable ungated by a re-sign-in as its recorded Principal. When gap 6 lands, a foreign creator
   should gate even that, with `data.name` and `data.creator` on APPROVAL_REQUIRED.
2. Name length: `name_prefix` capped at 32 so the 55-character cut keeps some of the identity. With
   the session dropped from the name, `login.{account}-role-{role}` fits inside the cut for most
   realistic role names, so the hash suffix should be uncommon.
3. Returning what was written from every provider's bootstrap, not just `aws-login`, so a client can
   render a credential without a second call. Raised in review; it needs a result shape per provider
   and a decision about which fields map onto a generated `~/.aws/config` profile, so it is its own
   spec rather than a widening of this one.
