---
status: draft
created: 2026-11-09
---

# Requirements: aws-login identity

**Depends on:** `credential-retrieval-api` (credential-addressed `credential/bootstrap` and
`credential/login`), `presence-gated-operations` (Requirement 1.7, amended here).

## Introduction

credsd does not know who signed in to an `aws-login` credential. A bootstrap over an existing
credential therefore needs approval even when the same person signs in again, and
`credential/login` re-authenticates without checking who signed in, so a credential can quietly
move to a different AWS account. The AWS CLI also cannot name a credential after the identity that
signed in, because the name must be chosen before sign-in.

This spec records the signed-in identity with each `aws-login` credential, lets the *same* identity
sign in again without approval, keeps a change of identity gated, and lets bootstrap name the
credential from the identity.

## What the identity record buys, and what it does not

The record narrows the gate; it does not replace it. A re-sign-in as the Principal already on
record changes only which session a credential holds, which is what makes it safe to run ungated —
the same reasoning `credential-retrieval-api` uses for leaving `credential/login` ungated. A
sign-in as a *different* Principal is a different thing: the credential would hand out another
account's authority to every consumer that reads it, so it stays a gated replace.

This boundary is deliberate, and it is where an earlier draft of this spec was wrong. Asking the
client to confirm a changed identity cannot stand in for the gate: the client *is* the caller, so a
process running as the user would answer its own prompt, which is precisely the actor
`presence-gated-operations` exists to stop (its Requirement 1.2 forbids a request parameter that
asserts a gate was already satisfied). A confirmation is a courtesy to a cooperating client; only
presence is a control.

## Glossary

- **Signed_In_Identity**: the identity a completed Sign-In authorized — partition, account,
  resource type, name, and session — from the ARN `sts:GetCallerIdentity` returns for the new
  credentials (Decision 1).
- **Principal**: a Signed_In_Identity without the session: partition, account, resource type
  (`role`, `user`, or `root`), and the name Requirement 1.1 parses from the ARN. The session changes
  on every sign-in; the Principal does not.
- **Identity_Record**: the Signed_In_Identity credsd keeps for a credential.
- **Name_Prefix**: a prefix the caller gives in place of a credential name; credsd derives the full
  name from the Signed_In_Identity.

## Requirement 1: Record who signed in

1.1. WHEN an `aws-login` sign-in completes, THEN the system SHALL call `sts:GetCallerIdentity` with
     the new credentials, before any token or key is persisted, and derive the Signed_In_Identity
     from the returned ARN. The `idToken` `sub`, when present, MAY be recorded for reference; it
     SHALL NOT decide equality. The ARN SHALL be parsed as follows, and in every form the account
     SHALL be exactly 12 decimal digits and the partition non-empty:

     | Returned ARN | Resource type | Name | Session |
     |---|---|---|---|
     | `arn:{partition}:sts::{account}:assumed-role/{role}/{session}` | `role` | `{role}` | `{session}` |
     | `arn:{partition}:iam::{account}:user/{path/}{user}` | `user` | `{path/}{user}`, path included | none |
     | `arn:{partition}:iam::{account}:root` | `root` | empty | none |

     STS drops a role's path from an assumed-role ARN, so a role's path is not part of its
     Principal. A user's path is, exactly as the ARN gives it: a user moved to another path signs
     in as a different Principal once, and that sign-in is gated. An assumed-role ARN whose role or
     session is empty, or whose session contains `/`, does not parse.
1.2. WHEN `sts:GetCallerIdentity` fails or returns an ARN the system cannot parse — including a
     `federated-user` ARN or any form not in Requirement 1.1's table — THEN the sign-in SHALL fail
     and nothing SHALL be persisted.
1.3. The system SHALL keep the Identity_Record sealed, in daemon-owned storage, bound to the
     credential's path like other sealed files. A caller SHALL NOT be able to write a record the
     daemon did not seal, or alter one it did. This does not stop a caller that shares the
     daemon's data-directory owner from deleting the record or restoring an archived copy of it;
     Requirements 5.2 and 5.3 state what that buys.
1.4. The Identity_Record SHALL survive a sign-out that keeps the credential's entry (gap 5,
     `credential/logout`), so the next sign-in compares against it.
1.5. The `credential/bootstrap` result for `aws-login` SHALL include the credential name and the
     Signed_In_Identity. It SHALL NOT include any token. How a client renders that is the client's
     own: this spec fixes the API's fields and nothing about their presentation.

## Requirement 2: The same Principal signs in again without approval

2.1. A sign-in is under the **same provider source** WHEN the existing credential is an `aws-login`
     source and the bootstrap names the same `region` and names or keeps the same `identity_type`.
     These are the only settings compared: `callback_port` and `remote` SHALL NOT take part
     (design, Decision 4).
     A credential's tier is its `identity_type`, so a tier change is a different provider source
     and the gate still discloses it. A different provider source — another source type, another
     region, or an `identity_type` the bootstrap names and the credential does not hold — stays a
     gated replace (`presence-gated-operations` 1.7). A bootstrap that omits `identity_type` keeps
     the credential's own, so it names no other one.
2.2. WHEN `credential/bootstrap` completes a sign-in for an existing `aws-login` credential under
     the same provider source AND the Signed_In_Identity's Principal equals the Identity_Record's
     Principal, THEN the system SHALL replace the credential's tokens and key without a presence
     challenge, and SHALL record the new session.
2.3. Principal equality SHALL compare the partition, account, resource type, and the role or user
     name exactly. No partial or case-folded match, and a role SHALL NOT equal an IAM user of the
     same name. The session SHALL NOT take part.
2.4. The ungated replace in 2.2 SHALL apply only to an `aws-login` credential whose Identity_Record
     has the same Principal. Every other case is gated: a different Principal, an existing
     credential with no Identity_Record, and a record that will not open (Requirement 5.2).
2.5. The same-provider-source decision SHALL read the `credentials.toml` bytes the write check
     verified, not the file again.
2.6. The decision SHALL be taken under the per-caller write lock that performs the write, against
     the Identity_Record as it stands there, so neither can change between the decision and the
     write.

## Requirement 3: A change of identity is gated

3.1. WHEN the Signed_In_Identity's Principal differs from the Identity_Record's, OR the credential
     exists with no readable Identity_Record, THEN the system SHALL NOT persist the sign-in, and
     SHALL return `APPROVAL_REQUIRED` with a challenge.
3.2. The challenge's description SHALL name the Principal on record (or that there is none) and the
     Principal that signed in, so an approver sees which account and role the credential would move
     to. It SHALL NOT carry any token.
3.3. The approval SHALL authorize exactly the change it was shown: the params digest it covers
     SHALL include both the Principal on record (or that there is none) and the signed-in
     Principal. A re-run that signs in as a different Principal, or that finds a different
     Principal on record than the challenge named, finds no approval to spend and is challenged
     afresh. The session SHALL NOT take part, because the re-run's sign-in gets a new one.
3.4. WHEN the credential does not exist, THEN the system SHALL create it without a challenge.
3.5. A refused or unapproved change SHALL leave the stored credential, its sealed material, and its
     Identity_Record exactly as they were.
3.6. `credential/login` SHALL persist a sign-in only when its Principal equals the
     Identity_Record's, and then SHALL record the new session, as 2.2 does. Any other outcome
     SHALL fail as `IDENTITY_MISMATCH` with nothing saved, and the message SHALL name the gated
     `credential/bootstrap` as the way to change who a credential signs in as. The code is its
     own, not `AUTH_CANCELLED`, because the sign-in completed and was refused. `login`
     raises no challenge of its own: it has no respond method and no approval re-send, and
     re-pointing a credential at another account is a replace rather than a re-authentication.

## Requirement 4: Name the credential from the identity

4.1. `credential/bootstrap` for `aws-login` SHALL accept exactly one of `credential` (a full name)
     or `name_prefix`. A request with both or neither SHALL fail as invalid params.
4.2. WHEN `name_prefix` is given, THEN after sign-in the system SHALL build the name from
     `name_prefix` and the **Principal** — not the session — normalize it with Requirement 4.3, and
     proceed as if that name had been given (Requirements 2 and 3 apply to it). The name before
     normalization SHALL be:

     | Resource type | Name |
     |---|---|
     | `role` | `{name_prefix}{account}-role-{role}` |
     | `user` | `{name_prefix}{account}-user-{user}`, where `{user}` is the last path segment |
     | `root` | `{name_prefix}{account}-root` |

     The resource type is in the name so that a role and an IAM user of the same name in one
     account address different credentials, as they are different Principals (2.3). A user's
     path is left out because IAM user names are unique within an account whatever their path.
     The partition is left out to keep the name short; were two partitions ever to yield the same
     name, the second sign-in would address the first's credential and be gated by 2.3, never
     merged into it. Excluding the
     session is what makes a repeat sign-in as the same Principal address the same credential,
     rather than leaving another one behind on every sign-in. This departs from the AWS CLI's
     `login_session` naming, which is a per-session profile and not a credential credsd re-seals.
4.3. Normalization SHALL be deterministic: a name that already passes credential-name validation is
     used as is; otherwise each disallowed character becomes `-`, the result is cut to 55
     characters, and `-` plus the first 8 lowercase hex digits of the SHA-256 of the name before
     cleanup is appended.
4.4. The result SHALL include the final credential name.
4.5. `name_prefix` SHALL itself pass credential-name validation and SHALL be at most 32 characters.

## Requirement 5: Protect the identity from editing

5.1. A caller editing `credentials.toml` or any file in its folder SHALL NOT be able to make a
     different identity read as the stored one. Requirement 1.3 (sealed under the master key,
     path-bound) satisfies this: a caller cannot forge or alter a record it cannot seal.
5.2. An unreadable or undecryptable Identity_Record SHALL be treated as no Identity_Record, which
     Requirement 2.4 gates. It SHALL NEVER read as a match.
5.3. Path binding does not cover replay of an archived `(path, ciphertext)` pair
     (`sealed-file-path-binding` 3.1), so a same-uid caller can restore an earlier authentic
     Identity_Record at the same path. What that buys is bounded by Requirement 3: the restored
     record names a Principal that was genuinely recorded before, and signing in as it requires
     controlling that account. Deleting the record does not help either, because absence gates
     (2.4). Naming the record in the caller's integrity record, so a rollback reads as drift
     (`drift-detection` 10.3), is the stronger fix and is left to that spec.

## Non-Goals

- Recording which tool created a credential (gap 6). A credential another tool created under the
  same provider source is reachable ungated by a re-sign-in as its recorded Principal, which needs
  that account's own authority; changing the Principal stays gated either way.
- Identity for providers other than `aws-login` (SSO is separate work).
- Deciding how a client presents an identity or a challenge. The API carries the fields; `creds`
  and any other client word them as they see fit.
- Returning what was written from every other provider's bootstrap. Requirement 1.5 covers
  `aws-login` only; doing it for all of them needs a result shape per provider and a decision about
  which fields belong in a generated `~/.aws/config` profile (design, Open question 3).
