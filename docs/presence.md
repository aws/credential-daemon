<!-- maturity-notice -->
> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path. The on-disk layout may change without a migration. Windows is for
> ease of use only: there is no process-tree assessment, and `serve` does not run there yet.
<!-- /maturity-notice -->

# Presence and sudo approval

Some operations change what your credentials are or where they send traffic. credsd does not
perform them on the strength of your uid alone. It holds each one as a pending request until
someone approves it with a Touch ID signature or with `sudo`.

## Why your uid is not enough

The daemon knows which uid is calling, and nothing else. Every process running as you, whether
an editor plugin, a dependency's install script, or an agent, connects as that same uid and can
send any request you can.

For reading credentials, that is the bargain: a process you run as yourself is a process you
chose to give your credentials to. Changing them is different. A process that could silently
point `sdk.endpoint_url` at a server it controls, swap a CA bundle, or replace an SSO credential
with its own would redirect every later request you make. So the daemon requires something such
a process cannot produce by itself: a finger on the sensor, or someone becoming root.

## What needs approval

The list is fixed in the daemon. No configuration adds to it or removes from it.

| Command | Needs approval when |
|---|---|
| `creds config set` | always |
| `creds config unset` | the key is set |
| `creds bootstrap` | it would replace an existing credential, or repoint an existing environment |
| `creds import` | a profile would bind into an existing environment, or replace sealed material left behind |
| `creds remove --credential` | always |
| `creds remove --environment` | always |
| `creds presence enroll` | always, and only `sudo` can approve it |

An operation that changes nothing needs no approval, so a first bootstrap, a first import, and
an unset of a key that is not set all go straight through. Reading credentials (`creds get`,
`creds list`) is never gated.

## How an approval works

1. You run the command. The daemon records exactly what it would do and to which records, then
   answers with a challenge: a request id, a digest of the recorded operation, and a description.
2. The challenge is satisfied in one of two ways: a Touch ID signature over the digest, or
   `sudo creds request approve <id>`.
3. The daemon performs the operation it recorded, not one re-sent by a client.

A pending request expires after 15 minutes. It can be approved once. If what it would change has
changed in the meantime, by credsd or by hand, the daemon discards it unperformed, because the
approval was given against a state that no longer exists.

On a Mac with an enrolled presence key, the command asks for Touch ID and finishes in one step.
Anywhere else it stops and tells you how to approve it:

```
$ creds config set sdk.ca_bundle /etc/ssl/corp-bundle.pem --environment work
Approval required: set sdk.ca_bundle = /etc/ssl/corp-bundle.pem on environment 'work'

Pending request <id> (expires in 15m).
Approve from a privileged session:

  sudo creds request approve <id>

Or withdraw it: creds request withdraw <id>

error: configuration error: not applied yet: it takes effect when request <id> is approved
```

Nothing has been written at this point. Approving performs the change; letting the request expire
or withdrawing it leaves everything as it was.

### Bootstrap and import

`creds bootstrap` and `creds import` carry secrets, and a bootstrap may run an interactive
sign-in, so the daemon does not hold their arguments in a pending request. Approving one grants
a single use of those exact arguments, valid for 5 minutes. With Touch ID the command retries
on its own. After `sudo creds request approve <id>`, run the same command again. A command with different
arguments needs its own approval.

## Approving with sudo

`sudo` works on every platform and needs no setup. Run it from any terminal where you can become
root:

```
$ sudo creds request approve <id>

Request <id> — set sdk.ca_bundle = /etc/ssl/corp-bundle.pem on environment 'work'
Raised by uid 501 (alice), pid 48122, /usr/local/bin/creds, at 2026-09-30T18:22:04Z
  digest <digest>

Approve? [y/N] y
✓ <outcome>  [<verifier>]
```

Read the request before you approve it: what it changes, which uid and executable raised it, and
when. A request you did not just start is a request something else started.

Root supplies presence, not identity. The operation is performed for the uid that raised it,
against that uid's records, and root cannot redirect it to anyone else. The daemon's audit record
names the approver as uid 0, along with the login identity the kernel recorded for the session
that ran `sudo`, never a value taken from an environment variable such as `SUDO_UID`.

`sudo` is always available. A request that Touch ID could approve can also be approved with
`sudo`, and a cancelled or failed Touch ID prompt leaves the request pending for it. There is no
headless bypass: a session with no sensor, an SSH session, or a script gets the `sudo` path and
nothing else.

## Approving with Touch ID

On macOS, a presence key lets you approve with Touch ID instead of `sudo`. The key is created in
the Secure Enclave and cannot leave it, and every use needs Touch ID. This needs a build with
the `secure-enclave` feature, which the official macOS release has.

### Enroll

Enrolling takes two steps, and the second needs `sudo`.

```
$ creds presence enroll
Created a presence key in the Secure Enclave.
  fingerprint  SHA256:<fingerprint>
  use requires Touch ID (invalidated if fingerprints change)
  key file     ~/.credsd/presence-key.pending.json

Pending request <id> (expires in 15m).
Approve from a privileged session:

  sudo creds request approve <id>

Or withdraw it: creds request withdraw <id>

Check that the approval shows the same fingerprint.
```

```
$ sudo creds request approve <id>

Request <id> — enroll presence key SHA256:<fingerprint> for uid 501
Raised by uid 501 (alice), pid 48911, /usr/local/bin/creds, at 2026-10-02T17:03:11Z
  digest <digest>

Once enrolled, a signature by this key satisfies any gated operation for uid 501.
The daemon cannot verify where this key is held. Approve only a key you have just created.

Approve? [y/N] y
```

Approve only when the fingerprint matches the one `creds presence enroll` printed.

**Why enrollment needs `sudo`.** The daemon receives only the public half of a key. It cannot tell
whether the private half is in the Secure Enclave or in a file a script wrote. If your uid could
enroll keys by itself, a process running as you could enroll its own key and then approve
everything. So a Touch ID signature, even one from a key you already enrolled, cannot approve an
enrollment.

Run `creds presence enroll` without `sudo`. Under `sudo` the key would be created in root's
context, so the daemon refuses it.

`--policy` chooses what each use requires:

| Policy | Each use requires |
|---|---|
| `biometry` (default) | Touch ID. Enrolling or removing a fingerprint invalidates the key. |
| `presence` | Touch ID or the device passcode. |

A uid has at most one presence key. Enrolling another replaces it when the new enrollment is
approved, and not before. If a second enrollment is raised while one is pending, the daemon
discards both and names the process that raised the other one.

### Status and revoke

```
creds presence status    # this uid's enrolled key, and whether this client holds it
creds presence revoke    # remove it; approvals fall back to sudo
```

Revoking needs no approval: it can only take a way of approving away, and `sudo` remains.

### Where the key lives

The client holds the key's wrapped private half in `~/.credsd/`, which only your uid can read and
only this Mac's Secure Enclave can use. The daemon holds the enrolled public halves in its own
storage, sealed under its master key, where your uid cannot write them. Neither side reads the
other's copy.

## Managing pending requests

```
creds request list           # your pending requests
sudo creds request list      # every uid's
creds request withdraw <id>  # discard one of yours; nothing is changed
```

A request you did not raise is worth investigating before it expires: `sudo creds request approve <id>`
shows which process raised it, and you can answer `N`.

## For other clients

A client other than `creds` receives a challenge as a JSON-RPC error with the domain code
`APPROVAL_REQUIRED`, never as a success. The error carries the request id, the digest, the
description, the expiry, which approvals it accepts, and a `remediation` string naming the
command that approves it. A client that does not recognize the code sees a failure, not a change
that did not happen. A refused approval is `APPROVAL_REFUSED`, with a `reason`.

## What approval does and does not guarantee

**Guaranteed:** what is performed is exactly what was recorded when the request was raised. A
signature or an approval covers that one operation's digest and nothing else, and a request
whose records changed is discarded rather than performed.

**Not guaranteed:** that what you saw is what you approved. The Touch ID prompt is drawn by a
client running as your uid, and `sudo creds request approve <id>` prints through your shell. A process running
as you can change either one's wording. It still cannot approve without your finger or root.

**Not covered:**

- Someone who can already become root, or who controls the shell of a user who runs `sudo`.
  Aliasing `sudo` in that shell is root already.
- A daemon run as your own uid from an open-source build. There, the daemon's storage, including
  the enrolled-key registry, is writable by every process running as you, so none of this holds.
  Use a system install (`sudo credsd install`) instead; see [install](install.md).

See the [command reference](reference/commands.md#creds-approve) for every flag.
