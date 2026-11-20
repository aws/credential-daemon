<!-- maturity-notice -->
> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path. The on-disk layout may change without a migration. Windows is for
> ease of use only: there is no process-tree assessment, and `serve` does not run there yet.
<!-- /maturity-notice -->

# Socket API reference

The daemon serves line-delimited JSON-RPC 2.0 over a Unix domain socket. `creds` and the
`credsd-client` Rust crate are clients of this API; any other client needs only a socket, a
line reader, and a JSON parser.

**Source of truth:** `crates/credsd-core/src/rpc/methods.rs` and
`crates/credsd-core/src/presence.rs` (method names and shapes),
`crates/credsd-core/src/rpc/mod.rs` (envelope, `DomainCode`),
`crates/credsd-daemon/src/server/dispatch.rs`, `server/bootstrap.rs`, `server/presence.rs`, and
`server/uds.rs` (what is served), `docs/specs/credential-retrieval-api/`,
`docs/specs/presence-gated-operations/`.

**Machine-readable contract:** [`docs/api/openrpc.json`](../api/openrpc.json), an OpenRPC
document covering every method, its params, results and errors, and which carrier exposes it
(spec: `docs/specs/api-contract/`). Where this guide and the contract disagree on a shape, the
contract is correct.

## Transport

### Socket paths

| Socket | macOS | Linux |
|---|---|---|
| System install | `/var/run/credsd/credsd.sock` | `/run/credsd/credsd.sock` |
| User socket: macOS user-scoped install, or `credsd serve` as a non-root uid other than `credsd` | `~/Library/Application Support/credsd/credsd.sock` | `$XDG_DATA_HOME/credsd/credsd.sock`, else `~/.local/share/credsd/credsd.sock` |

A system install is socket-activated: init binds the system socket and the daemon adopts it.
`credsd serve` binds `CREDSD_SOCKET` if set, else the path above for its uid. The system socket
is connectable by every local uid; any other socket the daemon binds is mode `0600` in a `0700`
directory.

A client dials the first of:

1. `--socket <path>` or `CREDSD_SOCKET` (absolute paths only; a relative or blank value is ignored)
2. the user socket, if a socket file exists there
3. the system socket

Windows has no transport yet: `credsd serve` refuses to start ("named pipe transport pending").

### Authorization

The daemon reads the peer uid from the kernel. A caller is authorized when
`<data dir>/callers/<uid>/owner` exists and contains the username that uid resolves to now. An
absent `owner` file is a denial (deny-by-absence); a mismatched name is a denial (uid reuse); a
failed lookup fails closed. There is no bearer token on the socket.

An unauthorized caller gets the same error as a missing subject: `CREDENTIAL_NOT_FOUND` for a
request addressed to a credential. The audit log records the
real reason. Exceptions:

- `system/health` requires no authorization.
- `credential/bootstrap` and `credential/import` provision `callers/<uid>/owner` for a uid
  that has never been provisioned, then proceed.

Every method acts only on the caller's own `callers/<uid>/` tree. See
[configuration](configuration.md) for the data directory per install shape.

## Envelope

One compact JSON object per line, terminated by `\n`. A line may be at most 1 MiB.

| Member | Request | Response |
|---|---|---|
| `jsonrpc` | `"2.0"` | `"2.0"` |
| `id` | number or string, required | echoed; `null` when the request could not be read |
| `method` | string | — |
| `params` | object, optional (absent reads as `{}`); arrays are refused | — |
| `result` / `error` | — | exactly one |

`error` is `{code, message, data?}`. A JSON-RPC batch (top-level array) is refused with
`-32602`. A request the daemon cannot decode gets an error response and the connection
closes. Requests on one connection are answered in order, except that `credential/bootstrap`
and `credential/login` run concurrently with later requests on the same connection.

Credential name fields accept letters, digits, `.`, `_`, and `-`, at most 64
characters, not starting with `.`. A violation is `-32602`; the message states the rule and
never echoes the value. Methods marked *strict* below reject unknown params members with
`-32602`; the others ignore them.

### Interactive flows

`credential/bootstrap` and `credential/login` stream progress before their response. The
daemon sends `notifications/progress` notifications (no `id`); `params.type` selects the step:

| `type` | Fields | Client action |
|---|---|---|
| `device_code` | `verification_uri`, `user_code` | Show them; the daemon polls for up to 5 minutes |
| `authorize_url` | `url` | Open it; the IdP redirects to the daemon's loopback listener |
| `authorize_code` | `url` | Open it anywhere; respond with the code the IdP's confirmation page shows. No listener is bound, so this step has no out-of-band answer. Do not log the response — it carries an authorization code |
| `select_account` | `accounts`: `[{id, name, email}]` | Respond with an account `id` |
| `select_role` | `roles`: `[string]` | Respond with a role name |
| `mfa_required` | `serial` | Respond with the MFA code |

A client responds with a notification, not a request:

```
{"jsonrpc":"2.0","method":"credential/bootstrap/respond","params":{"selection":"123456789012"}}
```

The daemon waits 300 seconds for a selection (`AUTH_TIMEOUT`). Closing the connection cancels
the flow (`AUTH_CANCELLED`). One bootstrap or login may be in flight per connection; a second
gets `PROVIDER_UNAVAILABLE`. A client reads lines until one carries its request `id`.

## Methods

Wire values: `kind` is `session_credentials` or `access_token`. `status` is one of `active`,
`expiring`, `expired`, `sign_in_required`, `no_session`, `corrupt`, `unreadable`, `decrypt_failed`, `unknown`.
`source` is one of `aws_idc_sso`, `aws_iam_user`, `aws_roles_anywhere`, `aws_web_identity`, `aws_login`, `jwt`,
`oauth`, `jwt_bearer`, `static_secret`, `unsupported`. Each value set may grow.

Every method that takes `request_id` treats it as an opaque correlation string.

**Approval.** `credential/remove`, `credential/bootstrap` (when it would replace a credential, except an
`aws-login` sign-in over an `aws-login` credential of the same region and identity type that signs
in as the principal already recorded for it, or a repeat `aws-idc-sso` bootstrap that changes no
stored setting), `credential/import` (when it would replace sealed material a removed credential
left behind), and `file/revalidate` (when a file has drifted, a file has been deleted, or the
integrity record will not open) are gated. A gated call is not performed: it fails with
`APPROVAL_REQUIRED`, whose `data.challenge` names a pending request, and the operation happens
when [`request/approve`](#requestapprove) satisfies it. [`presence/enroll`](#presenceenroll) is
gated too, but returns its challenge in a successful result, since raising the request is all
it does. For `credential/bootstrap` and `credential/import`, approval performs nothing; it lets
the identical call be re-sent once within 5 minutes. See [presence and sudo
approval](../presence.md).

**Drift and custody.** Before a credential is served, and before anything is written to
`config.toml` or `credentials.toml`, the daemon checks both files against their sealed snapshots
and checks custody of the integrity record. So `credential/get`, `credential/bootstrap`,
`credential/login`, `credential/import`, `credential/remove`, `credential/logout` and
`credential/tag` can each fail with `CONFIG_DRIFTED`, `INTEGRITY_UNVERIFIABLE` or
`CUSTODY_BROKEN` before doing anything else. `request/approve` and `presence/revoke` check custody
alone, and can fail with `CUSTODY_BROKEN`. The per-method `Errors:` lines below name only what is
specific to the method.

### `credential/get`

Material for one credential. *Strict.*

| Param | Type | |
|---|---|---|
| `credential` | string | required; the credential to serve |
| `account_id` | string | optional, twelve digits, with `role_name`; `aws-idc-sso` only. The account to mint for in place of the credential's stored one |
| `role_name` | string | optional, with `account_id`; `aws-idc-sso` only. The role to mint for in place of the stored one |
| `scope` | any JSON | optional; accepted, not yet applied |
| `claim` | `"agentic"` | optional; the caller asserts it is an agent. Unrecognized values are ignored |
| `request_id` | string | optional |

`credential` is required. Every miss is `CREDENTIAL_NOT_FOUND` with one message. An
`environment` parameter, including `null`, is invalid params.

| Result | Type | |
|---|---|---|
| `credential` | string | the credential served |
| `material` | object | tagged on `type`; see below |
| `expires_at` | RFC 3339 string or `null` | `null` means no stated expiry; always present |
| `provenance` | `"cached_shared"` \| `"minted_for_request"` | always `cached_shared` today |

| `material.type` | Fields |
|---|---|
| `session_credentials` | `access_key_id`, `secret_access_key`, `session_token` |
| `access_token` | `token`, `token_type` (always `"Bearer"` today) |

```
→ {"jsonrpc":"2.0","id":1,"method":"credential/get","params":{"credential":"dev"}}
← {"jsonrpc":"2.0","id":1,"result":{"credential":"dev","material":{"type":"session_credentials","access_key_id":"ASIA…","secret_access_key":"…","session_token":"…"},"expires_at":"2026-10-05T18:00:00Z","provenance":"cached_shared"}}
```

For an `aws-idc-sso` credential, `account_id` and `role_name` select another account and role
from the credential's one sign-in. Name both or neither; one alone is `-32602`, and a pair on any
other source is `ROLE_SELECTION_UNSUPPORTED`. Without them the credential's stored account and role
are served. A pair is served only if it is the stored one or in the credential's allowed list, set by
`creds bootstrap aws-idc-sso --allow-role` and changed only by a re-bootstrap, which needs presence
approval; any other pair is `ROLE_NOT_ALLOWED`. A listed role the user does not hold fails as
`PROVIDER_UNAVAILABLE`.

```
→ {"jsonrpc":"2.0","id":1,"method":"credential/get","params":{"credential":"sso.acme","account_id":"111111111111","role_name":"ReadOnly"}}
```

Errors: `-32602`, `CREDENTIAL_NOT_FOUND`, `REAUTH_REQUIRED`,
`PROVIDER_UNAVAILABLE`, `CONFIG_INVALID`, `INTERNAL`.

### `credential/list`

What credentials exist, with no material. *Strict.*

Params: `tags` (optional), `request_id` (optional). An `environment` parameter, including
`null`, is invalid. `tags` is a filter object: a string value requires the credential's tag of
that key to equal it, `null` requires only that the key is present, and a credential must satisfy
every condition. Keys fold to lowercase as in [`credential/tag`](#credentialtag).

Result: `credentials`, an array of `{credential, kind, source, status, tags}`, one entry per
credential. `source` is the credential's source type. `tags` is the credential's full tag set, `{}`
when it has none.

Errors: `-32602`, `CREDENTIAL_NOT_FOUND` (unauthorized), `CONFIG_INVALID`.

### `credential/remove`

Delete a credential's sealed material and its `credentials.toml` entry.

Params: `credential` (required).

Result: `{}`.

Errors: `APPROVAL_REQUIRED` (gated; see [Approval](#methods));
`CREDENTIAL_NOT_FOUND` (unauthorized, or nothing to remove); `-32602` (bad name); `INTERNAL`.

### `credential/logout`

Sign a credential out. Deletes its sealed session (refresh token, signing key, cached
credentials) and keeps its `credentials.toml` entry. Afterwards `credential/get` returns
`REAUTH_REQUIRED` until [`credential/login`](#credentiallogin) signs in again. Not gated, so a
sign-out works in a script without approval. For `aws_idc_sso` it first calls the SSO `Logout`
API, so the access token stops working at SSO too. An expired access token is first refreshed,
when a refresh token is sealed with it, and `Logout` is sent with the refreshed one, which is
never stored. The refresh and `Logout` share one 30-second bound. If either fails, the local session is still
deleted and the logout still succeeds, reporting `"provider": "failed"` with the start URL to sign
out at and when the access token expires. The SSO session may last longer than the token.

An error may leave the logout partly done. Retrying the same logout is safe and finishes it.

Applies to `aws_login`, `aws_idc_sso`, and `aws_web_identity` credentials. Any other source holds
material a sign-in does not restore, so the call is refused; use `credential/remove` instead.
Logging out of a credential with no session succeeds and deletes nothing.

Params: `credential` (required).

Result: `signed_out`, false only when there was no session, and `provider`, what happened at the
identity provider:

| `provider` | Meaning |
|---|---|
| `ended` | SSO accepted `Logout`, ending the sign-in at SSO too. |
| `token_rejected` | SSO refused the access token or the refresh before it as invalid or expired. No sealed token works at SSO, but the access-portal session may still be live. |
| `local_only` | An `aws_login` or `aws_web_identity` sign-in, which has no session at an identity provider to end, or an `aws_idc_sso` credential with no sealed token left. |
| `failed` | SSO refused the refresh or `Logout` for another reason or did not answer within 30 seconds, or the sealed token could not be read. The session may stay live at SSO until it expires. Adds `start_url` (the SSO start URL, where the user can sign out of the SSO session) and, when the token was readable, `access_token_expires_at` (the expiry of the newest access token SSO issued, the sealed one or one refreshed for the logout; the SSO session may last longer). |
| `none` | There was no session. Nothing was deleted or sent; `signed_out` is false. |

Errors: `CREDENTIAL_NOT_FOUND` (unauthorized, or no such credential); `-32602` (bad name);
`LOGOUT_UNSUPPORTED_SOURCE` (a source with no sign-in); `CONFIG_DRIFTED`; `INTERNAL` (another write held the caller's lock too
long, or the logout did not finish in time, and nothing was deleted; or a local deletion failed,
which may have deleted part of the session; retry either way). Every other error deletes nothing.

The CLI equivalent is `creds logout --credential <name>`.

### `credential/tag`

Set and unset a credential's tags in one write. Ungated: tags are labels and carry no authority.
Keys not named keep their values, and a key in `set` that already exists takes the new value;
`credential/bootstrap` with `tags` instead replaces the whole set.

Params: `credential` (required), `set` (optional object of key to string value, applied first),
`unset` (optional array of keys). A key is 1-63 bytes matching `[a-z0-9][a-z0-9._-]*` once ASCII
`A-Z` are folded to lowercase; the daemon folds every key it is given, here, in
`credential/bootstrap`, in the `credential/list` filter, and on load of `credentials.toml`. Two
spellings of one key in a request fail naming both. A value is at most 256 bytes of printable
ASCII and is never folded. A credential has at most 32 tags. Do not put secrets in tags: every
caller that may list the credential sees them.

Result: `{}`.

Errors: `-32602` (bad name, a key in both `set` and `unset`, or a result that breaks the rules
above; nothing is written); `CREDENTIAL_NOT_FOUND` (unknown or unauthorized); `CONFIG_INVALID`
(another entry in `credentials.toml` breaks the rules); `INTERNAL`.

### `credential/bootstrap`

Create or replace a credential. Creates only the credential: no environment is created or
changed. Streams [progress](#interactive-flows).

| Param | Type | |
|---|---|---|
| `credential` | string | required unless `name_prefix` is given |
| `name_prefix` | string | `aws_login` only, at most 32 characters; exactly one of this and `credential` |
| `provider` | object | required; tagged on `type`, below |
| `tags` | object | optional; key to string value. Given, the tags become exactly this; omitted, a replaced credential keeps its tags |
| `request_id` | string | optional |

An `aws_login` bootstrap returns `{credential, identity}`: the final credential name and who
signed in (`arn`, `partition`, `account`, `kind`, `name`, `session`), as `sts:GetCallerIdentity`
reported it for the new credentials. With `name_prefix`, the name is the prefix plus
`<account>-role-<role>`, `<account>-user-<user>` (without the user's path), or `<account>-root`,
normalized as below. The kind is part of the name, so a role and a user of the same name get
different credentials; the session is not, so signing in again as the same principal addresses the
same credential. A sign-in whose identity STS cannot confirm
saves nothing. Every other provider returns `{}`.

Replacing an existing `aws_login` credential is ungated only when the region, the identity type,
and the signed-in principal (partition, account, kind, and role or user name) all match what is
recorded. Signing in as a different principal returns `APPROVAL_REQUIRED`, and the challenge names
both; the approval is bound to the recorded and signed-in principals it was shown, so an approved
re-run that signs in as a third one, or finds a different one recorded, is challenged again. A
credential with no readable recorded identity is gated too.

Bootstrapping an existing `aws-idc-sso` credential is ungated when `start_url`, `sso_region`,
`identity_type`, `account_id`, `role_name`, and `allowed_roles` all match what is stored: that is
a re-authentication, and only the sign-in is replaced. Omitted fields keep the stored values, and
no `select_account` or `select_role` prompt runs, so a sign-in needs no client selection. An
`allowed_roles` of `[]` is not the same as an absent one: it clears the allowed list, which is a
change. Any other value returns `APPROVAL_REQUIRED`, and the challenge names each changed field
with its old and new value, plus the stored account, role, and allowed pairs it keeps when
`start_url` or `sso_region` changes. Whether the credential still holds a session makes no
difference — an expired one, or one `credential/logout` ended, is the same credential.

Every provider accepts `identity_type`: `"human"`, `"automation"`, or `"agent"`, written onto the
credential. Absent keeps the credential's existing value (`human` for a new one).

| `provider.type` | Required | Optional |
|---|---|---|
| `aws_idc_sso` | `start_url`, `sso_region` | `account_id` and `role_name` (both or neither), `allowed_roles` (array of `{account_id, role_name}`) |
| `aws_iam_user` | `access_key_id`, `secret_access_key`, `region` | `duration_seconds`, `mfa_serial` |
| `aws_roles_anywhere` | `trust_anchor_arn`, `profile_arn`, `role_arn`, `cert_der`, `key_der`, `key_tag` | `chain_der` (array), `region`, `duration_seconds`, `role_session_name`, `endpoint_url` |
| `aws_web_identity` | `authorization_endpoint`, `token_endpoint`, `client_id`, `role_arn`, `region` | `scopes` (default `["openid"]`), `duration_seconds`, `role_session_name`, `callback_port` |
| `aws_login` | `region` | `callback_port`, `remote` |
| `jwt` | `jwt` | `env_var` |
| `oauth` | `token_url`, `client_id`, and `client_secret` or `private_key_pem` | `scope` |
| `jwt_bearer` | `token_url`, `assertion` | `client_id`, `scope` |
| `static_secret` | `secret` | `env_var`, `expires_at` (RFC 3339), `secret_source` |

Notes:

- `aws_idc_sso` takes `account_id` and `role_name` both or neither; one without the other is
  `-32602`, refused before any sign-in. It prompts with `select_account` and `select_role` unless
  both are given, or the credential already exists and keeps its stored pair; a single account or
  role is chosen without a prompt.
- `aws_roles_anywhere`: `cert_der`, `key_der`, and `chain_der` are base64 DER; `key_tag` is
  `PKCS8`, `RSA`, or `EC`.
- `aws_web_identity` and `jwt_bearer` endpoints must be `https://` with no userinfo. `scopes` always
  gains `openid`. After sealing, `aws_web_identity` federates once; failure there returns an error
  even though the credential was saved.
- `aws_login`: `region` is the Sign-In region. `callback_port` and `remote` are mutually exclusive —
  a remote login binds no loopback listener and the user carries the authorization code back by
  hand. Sending both is `PROVIDER_UNAVAILABLE`, not `-32602`: the provider refuses the pair, and
  `callback_port` is checked as a param only for its range. The client id is one of Sign-In's two
  fixed devtools clients, picked by `remote`, and it fixes the redirect shape with it — so there is
  no `client_id` knob.
- `env_var` is stored with token credentials for a future child-process projection.
- `jwt_bearer` needs a build with the `jwt-bearer` cargo feature, which no published build enables:
  it is off by default in every crate that declares it and no job in `.github/workflows/` turns it
  on. A default daemon refuses to bootstrap one with `PROVIDER_UNAVAILABLE`. `source` still reports
  `jwt_bearer` for a credential a feature build stored, but a default daemon cannot serve it — the
  store logs a warning and registers no provider for it.

Result: `{}`.

Errors: `APPROVAL_REQUIRED` (gated; see [Approval](#methods)); `-32602` (bad params, unknown
`provider.type`, empty secret, bad `identity_type`, `callback_port` out of range, undecodable
DER); `CREDENTIAL_NOT_FOUND` (unauthorized); `AUTH_TIMEOUT`; `AUTH_CANCELLED`;
`PROVIDER_UNAVAILABLE` (flow already in flight, no accounts or roles, seal or federation
failure, provider feature not compiled into this build); `REAUTH_REQUIRED` (`aws_web_identity`
saved but cannot federate; no `remediation`); `INTERNAL`.

### `credential/bootstrap/respond`

A client-to-daemon notification, sent without `id`, carrying `params.selection` (string) into
the in-flight bootstrap or login on the same connection. It has no response. Sent with an `id`,
it is `-32601`.

### `credential/login`

Re-authenticate one saved credential. Streams [progress](#interactive-flows).

Params: `credential` (required), `request_id`.

A login re-authenticates the credential as it stands; it changes no stored setting. To change
one, bootstrap the credential with the new values, which is gated (see
[`credential/bootstrap`](#credentialbootstrap)).

| Source (`credentials.toml` type) | Behavior |
|---|---|
| `aws-idc-sso` | Renews unattended if it can, else `device_code` |
| `aws-iam-user` with `mfa_serial` | `mfa_required` |
| `aws-web-identity` | `authorize_url` |
| `aws-login` | `authorize_url`, or `authorize_code` when the credential is `remote` (Sign-In re-login). Saved only when it signs in as the principal recorded for the credential; any other one is `IDENTITY_MISMATCH` with nothing saved, naming the gated `credential/bootstrap` as the way to change it |
| `jwt`, `static-secret` | `PROVIDER_UNAVAILABLE` naming the reseal command |
| others | No-op |

Result: `{}`.

Errors: `CREDENTIAL_NOT_FOUND` (unauthorized, or unknown credential; one message), `-32602`,
`AUTH_TIMEOUT`, `AUTH_CANCELLED`, `IDENTITY_MISMATCH` (an `aws-login` sign-in as another
principal, or one whose credential has no readable recorded identity), `PROVIDER_UNAVAILABLE`,
`INTERNAL`.

### `credential/import`

Seal one static IAM key pair as an `aws-iam-user` credential. Creates only the credential, no
environment. A client importing several profiles makes one call per profile. Not streamed.

| Param | Type | |
|---|---|---|
| `credential` | string | the credential to create |
| `access_key_id` | string | required |
| `secret_access_key` | string | required |
| `region` | string | required |
| `identity_type` | string | optional |
| `dry_run` | bool | default `false`; decides and writes nothing |

Result: `{credential, status, reason?}` with `status` one of `imported`, `skipped`,
`would_import`, `would_skip`. An invalid or existing name is a skip with a `reason`, not an
error.

Errors: `APPROVAL_REQUIRED` (gated; see [Approval](#methods)); `-32602` (empty
`secret_access_key`, bad `identity_type`), `CREDENTIAL_NOT_FOUND` (unauthorized), `INTERNAL`.

### `system/health`

Protocol handshake. Takes no params and needs no authorization.

| Result | Type | |
|---|---|---|
| `protocol` | integer | the wire revision, currently `1`; the only field to branch on |
| `version` | string | daemon version, informational |

Additive changes (a new kind, code, or field) do not change `protocol`.

### `request/get`, `request/list`

Show pending requests. The owner sees its own; a connection whose uid is 0 sees every uid's.

| Method | Params | Result |
|---|---|---|
| `request/get` | `id` | a pending request |
| `request/list` | none | array of pending requests, oldest first |

A pending request is `{challenge, owner_uid, owner_pid, owner_executable, raised_at}`.
`owner_pid` and `owner_executable` are `null` when the kernel did not report them; `raised_at`
is RFC 3339. `challenge` is:

| Field | Type | |
|---|---|---|
| `id` | string | the request id, `req-` and 12 hex digits; names the request and authorizes nothing |
| `digest` | string | hex SHA-256 of the recorded operation |
| `description` | string | what the request would do, for display |
| `expires_in_secs` | integer | seconds until it expires; a request lasts 15 minutes |
| `accepts` | string | `any` (a presence signature or privileged approval) or `privileged` (privileged approval only) |
| `presence_key` | string or `null` | fingerprint of the owner's enrolled presence key |

Errors: `REQUEST_NOT_FOUND` (`request/get`); `CREDENTIAL_NOT_FOUND` (unauthorized).

### `request/approve`

Satisfy a pending request and perform it.

Params: `id` (required); `signature` (hex DER ECDSA P-256), for a presence signature. Omit
`signature` on a privileged approval, which is a connection whose uid is 0 and needs no
`callers/<uid>/` of its own.

A presence signature is over the bytes `credsd-presence-v1`, `0x00`, the request id, `0x00`,
and the 32 raw bytes of the digest, by the presence key enrolled for the request's owner.

Result: `{outcome, verifier}`. `outcome` describes what was done; `verifier` is
`presence_signature` or `privileged_approval`.

The operation is performed as recorded, for the uid that raised it. If any record it would change
has been modified since, it is discarded unperformed (`APPROVAL_REFUSED`, reason
`base_state_changed`).

Errors: `APPROVAL_REFUSED`; `REQUEST_NOT_FOUND`; `-32602` (`signature` is not hex);
`CREDENTIAL_NOT_FOUND` (unauthorized, on a connection whose uid is not 0).

### `request/withdraw`

Discard one of the caller's pending requests. Nothing is changed. Owner only; uid 0 cannot
withdraw another uid's request.

Params: `id` (required).

Result: `{}`.

Errors: `REQUEST_NOT_FOUND`; `CREDENTIAL_NOT_FOUND` (unauthorized).

### `presence/enroll`

Raise an enrollment of a presence key for the calling uid. Gated: the result's challenge accepts
privileged approval only, and the key is enrolled when it is approved. Refused on a connection
whose uid is 0.

Params: `public_key` (required), hex SEC1 uncompressed P-256 point (65 bytes).

Result: `{challenge, fingerprint}`. `fingerprint` is `SHA256:` and the unpadded base64 SHA-256 of
the public key.

Errors: `-32602` (uid 0, a malformed key, or another enrollment was pending for this uid, in
which case both are discarded and the message names the process that raised the other);
`CREDENTIAL_NOT_FOUND` (unauthorized).

### `presence/revoke`

Remove the calling uid's enrolled presence key. Not gated.

Params: none.

Result: `{revoked}`, the removed key's fingerprint.

Errors: `-32602` (no key enrolled); `INTERNAL` (the enrolled-key registry did not open or could
not be written); `CREDENTIAL_NOT_FOUND` (unauthorized).

### `presence/status`

Show the calling uid's enrolled presence key.

Params: none.

| Result | Type | |
|---|---|---|
| `uid` | integer | the caller |
| `presence_key` | string or `null` | fingerprint of the enrolled key |
| `enrolled_at` | string or `null` | RFC 3339 |
| `approved_by_uid` | integer or `null` | uid of the approving connection |
| `approved_by_login_uid` | integer or `null` | login identity of the approver's session, from the kernel |

Errors: `CREDENTIAL_NOT_FOUND` (unauthorized).

### `file/revalidate`

Reseal hand-edited config files after review. Takes no selector: a snapshot covers its whole
file, so every drifted file is shown and resealed together. Every load-bearing file that is
present must parse before any of this is reached, whatever the trigger was; one that does not is
corrected or restored first.

Params: none.

Result: `{}`.

Errors: `APPROVAL_REQUIRED` (gated; the operation happens on approval, see
[Approval](#methods)); `CONFIG_DRIFTED` (a load-bearing file that is present does not parse, so
it has no canonical form and there is nothing a snapshot could ratify; raised before drift is
classified, so it does not mean that file drifted); `CUSTODY_BROKEN` (custody of the integrity
record or the enrolled-key registry is broken); `CREDENTIAL_NOT_FOUND` (unauthorized); `-32602`
(any field in `params`: the method takes none); `INTERNAL` (reading either file, hashing the base
state, or a file that is not UTF-8).

## Errors

| `error.code` | Meaning |
|---|---|
| `-32700` | Not JSON, or line over 1 MiB |
| `-32600` | JSON but not a valid request (missing or `null` `id`, array `params`) |
| `-32601` | Unknown method |
| `-32602` | Bad params, or a JSON-RPC batch |
| `-32603` | Internal envelope failure |
| `-32000` | Domain failure; read `data.code` |

Numeric codes describe the message. Every domain failure is `-32000` with `data.code`:

| `data.code` | Meaning | Remediation |
|---|---|---|
| `CREDENTIAL_NOT_FOUND` | A credential request missed: no such credential, or the caller is not authorized. One message for every cause, indistinguishable by design | Bootstrap the credential |
| `REAUTH_REQUIRED` | No valid session | From `credential/get`: `data.credential` and `data.remediation`, the command `creds login --credential <name>` |
| `WRONG_CREDENTIAL_TYPE` | Material of a kind the projection cannot use. Reserved: no method sends it today, and a client that recognizes it keeps working against a daemon that starts to | Use a credential of the right kind |
| `ROLE_NOT_ALLOWED` | `credential/get` named an account and role that is neither the credential's stored pair nor in its allowed list | Re-bootstrap the credential with `--allow-role` for that pair |
| `ROLE_SELECTION_UNSUPPORTED` | `credential/get` named an account and role for a credential whose source is not `aws-idc-sso` | Drop `account_id` and `role_name`, or address an `aws-idc-sso` credential |
| `PROVIDER_UNAVAILABLE` | Upstream or provider failure, or a flow already in flight | Retry; the message says what failed |
| `INTERNAL` | Daemon-side failure (config, storage, encryption, I/O) | See the daemon log |
| `AUTH_TIMEOUT` | Sign-in or selection not completed in time | Run the flow again |
| `AUTH_CANCELLED` | The client closed the connection during a flow | Run the flow again |
| `IDENTITY_MISMATCH` | `credential/login` for an `aws-login` credential signed in as a principal other than the one it records, or the credential has no readable recorded identity. Nothing was saved | `creds bootstrap --credential <name>` with its `aws-login` provider, which asks for approval |
| `APPROVAL_REQUIRED` | The operation is gated and was not performed. `data.challenge` is the pending request's challenge, as in [`request/get`](#requestget-requestlist) | `data.remediation`, e.g. `sudo creds request approve <id>` |
| `APPROVAL_REFUSED` | `request/approve` did not satisfy the request. `data.reason` is `not_satisfied` (no signature, and the connection is not uid 0), `signature_invalid`, `no_presence_key`, `privileged_only`, or `base_state_changed`. Every reason but `base_state_changed` leaves the request pending | `data.remediation` |
| `REQUEST_NOT_FOUND` | No such pending request, one that expired or was discarded, or another uid's on a connection whose uid is not 0. Indistinguishable by design | Re-run the original command |
| `CONFIG_DRIFTED` | The caller's `config.toml` or `credentials.toml` no longer matches its sealed snapshot. Credential operations are blocked, as is every write to either file; the message names the credential or the file | Read the contents, then `creds revalidate` |
| `CONFIG_INVALID` | `config.toml` or `credentials.toml` parses but does not validate, for example a tag key that breaks the rules. The message names the credential and key, never a value. Nothing is served or listed | Fix the file, then `creds revalidate` |
| `INTEGRITY_UNVERIFIABLE` | The caller's integrity record will not open, so neither file can be checked | `creds revalidate`; its approval shows both files in full and replaces the record |
| `CUSTODY_BROKEN` | Ownership or modes on the integrity record or the enrolled-key registry are wrong. Nothing they govern is served, written, or approved | None. An operator restores ownership and modes and restarts the daemon; a client that retries or re-prompts loops |
| `LOGOUT_UNSUPPORTED_SOURCE` | `credential/logout` named a credential whose source has no sign-in to log out of. Nothing was deleted | `credential/remove` (`creds remove --credential <name>`) |

A client should treat an unrecognized `data.code` as a failure.
