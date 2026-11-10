# User Experience: Presence-Gated Operations

Companion to `requirements.md` and `design.md`. This document shows what a user sees. The
requirements say what must hold; the design says why and how.

## The shape of every approval

A gated operation always works the same way:

1. The client asks for the operation.
2. The daemon records it as a pending operation and returns a challenge: an id, a digest, and a
   description.
3. Something proves presence against the challenge — a Touch ID signature, or `sudo creds request approve <id>`.
4. The daemon performs the operation it recorded.

```
client                               daemon
──────                               ──────
config/set ───────────────────────►  deny, salvageable with presence
                                     record pending operation
           ◄───────────────────────  challenge {id, digest, description}

then one of:
  presence signature   ───────────►  request/approve {id, signature over digest}
  privileged approval  ───────────►  request/approve {id}       from a uid-0 connection

                                     verify proof, re-evaluate, perform, audit
```

Only step 3 depends on the platform. The flows below use `config set`; any gated operation —
`drift-detection`'s revalidation among them — looks the same with a different description.

## Flow A — macOS, with Touch ID

```
$ creds config set sdk.endpoint_url https://vpce-0abc.execute-api.us-west-2.vpce.amazonaws.com --env work

This change redirects every AWS API call made under environment 'work'.

  sdk.endpoint_url
    to: https://vpce-0abc.execute-api.us-west-2.vpce.amazonaws.com

  [Touch ID: "Approve: set sdk.endpoint_url on environment 'work'"]

✓ set sdk.endpoint_url on environment 'work'
```

- One command, one prompt. The CLI receives the challenge, has the Secure Enclave sign its digest,
  and submits the signature.
- The signature covers the digest, so it approves this operation and no other.
- The CLI draws the prompt, so a process running as the same user can draw one with different
  words. It cannot get a signature without a finger on the sensor.

Cancelling the prompt changes nothing, and the request stays pending, so `sudo` remains an option:

```
  [Touch ID: cancelled]

Touch ID was not completed: cancelled.

Pending request req-5d1e07 (expires in 15m).
Approve from a privileged session:

  sudo creds request approve req-5d1e07

Or withdraw it: creds request withdraw req-5d1e07
```

- The write happens only after an approval succeeds, so a cancelled prompt leaves the record as it
  was.
- The request is not withdrawn automatically. Withdrawing is the requesting client's choice, so it
  protects nothing: a hostile requester would simply not withdraw. The protection is that approval
  needs a finger or root. Keeping the request pending gives the `sudo` path to a user who cancelled
  because Touch ID was out of reach.
- The message says why the prompt failed — cancelled, locked out, Touch ID unavailable, or not
  recognised — so the user knows whether retrying will help.

A Mac with no enrolled key, or an SSH session into one, gets Flow B, plus a pointer to Flow C:

```
Approval required. Raised pending request req-5d1e07 (expires in 15m).
Approve from a privileged session:

  sudo creds request approve req-5d1e07

To approve with Touch ID instead, enroll a presence key: creds presence enroll
```

## Flow B — Linux, or no presence key

```
$ creds config set sdk.ca_bundle /tmp/corp-bundle.pem --env work

Approval required: this change substitutes the CA trust store for environment 'work'.

Raised pending request req-7f3a91 (expires in 15m).
Approve from a privileged session:

  sudo creds request approve req-7f3a91
```

The command exits. The request waits in the daemon until it is approved or expires.

Knowing the id is not enough:

```
$ creds request approve req-7f3a91
error: req-7f3a91 needs a presence signature or a privileged approval
       no presence key is enrolled for uid 1000, and this session is not privileged
```

With `sudo`, the approver sees the request before approving it:

```
$ sudo creds request approve req-7f3a91

Request req-7f3a91 — config set on environment 'work'
Raised by uid 1000 (alice), pid 48122, /usr/local/bin/creds, at 2026-09-30T18:22:04Z

  sdk.ca_bundle
    to: /tmp/corp-bundle.pem

A CA bundle under /tmp is writable by any process running as uid 1000.

Approve? [y/N] y

✓ set sdk.ca_bundle on environment 'work' for uid 1000
```

- The approving connection is uid 0. The write still lands in uid 1000's records, because the
  request recorded uid 1000 when it was raised. Root supplies presence, not identity.
- The audit record names the approver as uid 0, with login identity uid 1000 taken from the
  kernel.
- If the environment changes before approval — by the daemon or by an editor — the request is
  discarded instead of performed.

Lost an id? List them. Owners see their own; root sees everyone's:

```
$ creds request list
ID          OPERATION                          RAISED BY  EXPIRES IN
req-7f3a91  config set on environment 'work'   uid 1000   12m
```

## Flow C — enrolling a presence key

The daemon cannot tell whether a public key's private half is in the Secure Enclave or in a file
a script can read. If the user's uid could enroll keys, malware running as that user could enroll
its own and approve everything. So enrollment needs `sudo`, and a Touch ID signature cannot
approve it.

Running the whole thing under `sudo` does not work:

```
$ sudo creds presence enroll
error: a presence key is enrolled for the uid that raises the request, and this connection is uid 0
       run 'creds presence enroll' without sudo; approval is a separate, privileged step
```

Under `sudo`, the key would be created in root's context, and the daemon would see uid 0 and
enroll it for root. So enrollment takes two steps: the user creates the key and raises the
request, and root approves it.

```
$ creds presence enroll

Created a presence key in the Secure Enclave.
  fingerprint  SHA256:Qm4rT0bJ8vW2kq9sE1uXn5yZaL3cF7dH6gP0iR2oX2c
  use requires Touch ID or the device passcode

Enrollment needs a privileged approval:

  sudo creds request approve req-9b20d4

Check that the approval shows the same fingerprint.
```

```
$ sudo creds request approve req-9b20d4

Request req-9b20d4 — enroll presence key for uid 501 (alice)
Raised by uid 501 (alice), pid 48911, /usr/local/bin/creds, at 2026-10-02T17:03:11Z

  key          ecdsa-p256
  fingerprint  SHA256:Qm4rT0bJ8vW2kq9sE1uXn5yZaL3cF7dH6gP0iR2oX2c

Once enrolled, a signature by this key satisfies any gated operation for uid 501.
The daemon cannot verify where this key is held. Approve only a key you have just created.

Approve? [y/N] y

✓ presence key SHA256:Qm4r…oX2c enrolled for uid 501
```

- The uid comes from the request, so root cannot enroll the key for anyone else.
- The approver's identity comes from the kernel's login record, never from `SUDO_UID`.

A second enrollment raised while one is pending cancels both:

```
$ creds presence enroll
error: another enrollment was pending for uid 501 — req-a71c3e, raised by pid 51002 (/tmp/.x/creds)
       both were discarded; if you did not start the other one, something running as you did
```

Revoking needs no `sudo`, because it can only take a verifier away:

```
$ creds presence revoke
✓ presence key SHA256:Qm4r…oX2c revoked for uid 501
  gated operations now require: sudo creds request approve <id>
```

### Limits

- Both fingerprints reach the user through their own shell, and same-uid malware can change what
  the shell shows.
- If an attacker controls the shell of a user who can run `sudo`, aliasing `sudo` already gets them
  root. Enrollment does not defend against that. It guarantees only that no process running as the
  user can enroll a key unless someone becomes root.
