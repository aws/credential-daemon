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

An unauthorized caller gets `ENVIRONMENT_NOT_FOUND`, the same error as a missing environment.
The audit log records the real reason. Exceptions:

- `system/health` requires no authorization.
- `environment/bootstrap` and `environment/import` provision `callers/<uid>/owner` for a uid
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
closes. Requests on one connection are answered in order, except that `environment/bootstrap`
and `environment/login` run concurrently with later requests on the same connection.

Name fields (`environment`, `credential`) accept letters, digits, `.`, `_`, and `-`, at most 64
characters, not starting with `.`. A violation is `-32602`; the message states the rule and
never echoes the value. Methods marked *strict* below reject unknown params members with
`-32602`; the others ignore them.

### Interactive flows

`environment/bootstrap` and `environment/login` stream progress before their response. The
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
{"jsonrpc":"2.0","method":"environment/bootstrap/respond","params":{"selection":"123456789012"}}
```

The daemon waits 300 seconds for a selection (`AUTH_TIMEOUT`). Closing the connection cancels
the flow (`AUTH_CANCELLED`). One bootstrap or login may be in flight per connection; a second
gets `PROVIDER_UNAVAILABLE`. A client reads lines until one carries its request `id`.

## Methods

Wire values: `kind` is `session_credentials` or `access_token`. `status` is one of `active`,
`expiring`, `expired`, `sign_in_required`, `no_session`, `corrupt`, `unreadable`, `decrypt_failed`, `unknown`.
`source` is one of `aws_idc_sso`, `aws_iam_user`, `aws_roles_anywhere`, `aws_web_identity`, `jwt`, `oauth`,
`jwt_bearer`, `static_secret`, `unsupported`. Each value set may grow.

Every method that takes `request_id` treats it as an opaque correlation string.

**Approval.** `config/set`, `config/unset` (when the key is set), `credential/remove`,
`environment/remove`, `environment/bootstrap` (when it would replace a credential or repoint an
environment), `environment/import` (when a profile would bind into an existing environment, or
replace sealed material left behind) are gated. A gated call is not performed: it fails with
`APPROVAL_REQUIRED`, whose `data.challenge` names a pending request, and the operation happens
when [`request/approve`](#requestapprove) satisfies it. [`presence/enroll`](#presenceenroll) is
gated too, but returns its challenge in a successful result, since raising the request is all
it does. For
`environment/bootstrap` and `environment/import`, approval performs nothing; it lets the
identical call be re-sent once within 5 minutes. See [presence and sudo
approval](../presence.md).

### `credential/get`

Material for one credential. *Strict.*

| Param | Type | |
|---|---|---|
| `environment` | string | required |
| `credential` | string | optional; absent means the environment's default credential |
| `scope` | any JSON | optional; accepted, not yet applied |
| `claim` | `"agentic"` | optional; the caller asserts it is an agent. Unrecognized values are ignored |
| `request_id` | string | optional |

A `credential` the environment does not reference fails as `ENVIRONMENT_NOT_FOUND`.

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
→ {"jsonrpc":"2.0","id":1,"method":"credential/get","params":{"environment":"dev"}}
← {"jsonrpc":"2.0","id":1,"result":{"credential":"dev","material":{"type":"session_credentials","access_key_id":"ASIA…","secret_access_key":"…","session_token":"…"},"expires_at":"2026-10-05T18:00:00Z","provenance":"cached_shared"}}
```

Errors: `-32602`, `ENVIRONMENT_NOT_FOUND`, `REAUTH_REQUIRED`, `PROVIDER_UNAVAILABLE`,
`INTERNAL`.

### `credential/get_batch`

Every credential the environment references, all or none. The caller names the environment,
never the members. *Strict.*

Params: `environment` (required), `scope`, `claim`, `request_id`, as for `credential/get`.

Result: `credentials`, an array of `credential/get` results. Any member's failure returns that
one error and no material.

Errors: as `credential/get`.

### `credential/list`

What credentials exist, with no material. *Strict.*

Params: `environment` (optional filter; an unknown name yields an empty list), `request_id`.

Result: `credentials`, an array of `{environment, credential, kind, status}`. `kind` is the
kind the credential serves.

Errors: `-32602`, `ENVIRONMENT_NOT_FOUND` (unauthorized).

### `environment/describe`

One environment's manifest: its credentials and the inputs a client needs to build a child
environment. No material. *Strict.*

Params: `environment` (required), `request_id`.

| Result | Type | |
|---|---|---|
| `environment` | string | |
| `credentials` | array | `{credential, kind, source, env_var?, status, default}` |
| `projection` | object | `region?`, `sdk?`, `cli?` — the environment's `sdk.*` and `cli.*` settings, keyed as in `config.toml` |

`env_var` is present only for a token credential that names a variable other than the default.
`default` is always present. A credential with no `credentials.toml` entry reports `source:
"unsupported"`. `identity_type` is never returned.

Errors: `-32602`, `ENVIRONMENT_NOT_FOUND`.

### `credential/remove`

Delete a credential's sealed material and its `credentials.toml` entry.

Params: `credential` (required).

Result: `{}`.

Errors: `APPROVAL_REQUIRED` (gated; see [Approval](#methods)); `ENVIRONMENT_NOT_FOUND`
(unauthorized, or nothing to remove); `-32602` (bad name, or an environment still references the
credential — the message lists them); `INTERNAL`.

### `environment/remove`

Delete an environment from `config.toml`. Its credentials stay.

Params: `environment` (required).

Result: `{}`.

Errors: `APPROVAL_REQUIRED` (gated; see [Approval](#methods)); `ENVIRONMENT_NOT_FOUND`
(unauthorized, or no such environment), `-32602`, `INTERNAL`.

### `environment/bootstrap`

Create or replace a credential and add it to an environment, creating the environment if
needed. Streams [progress](#interactive-flows).

| Param | Type | |
|---|---|---|
| `environment` | string | required |
| `credential` | string | optional; defaults to `environment` |
| `provider` | object | required; tagged on `type`, below |
| `request_id` | string | optional |

Every provider accepts `identity_type`: `"human"`, `"automation"`, or `"agent"`. Absent keeps the
environment's existing value (`human` for a new one).

| `provider.type` | Required | Optional |
|---|---|---|
| `aws_idc_sso` | `start_url`, `sso_region` | `account_id`, `role_name` |
| `aws_iam_user` | `access_key_id`, `secret_access_key`, `region` | `duration_seconds`, `mfa_serial` |
| `aws_roles_anywhere` | `trust_anchor_arn`, `profile_arn`, `role_arn`, `cert_der`, `key_der`, `key_tag` | `chain_der` (array), `region`, `duration_seconds`, `role_session_name`, `endpoint_url` |
| `aws_web_identity` | `authorization_endpoint`, `token_endpoint`, `client_id`, `role_arn`, `region` | `scopes` (default `["openid"]`), `duration_seconds`, `role_session_name`, `callback_port` |
| `jwt` | `jwt` | `env_var` |
| `oauth` | `token_url`, `client_id`, and `client_secret` or `private_key_pem` | `scope` |
| `jwt_bearer` | `token_url`, `assertion` | `client_id`, `scope` |
| `static_secret` | `secret` | `env_var`, `expires_at` (RFC 3339), `secret_source` |

Notes:

- `aws_idc_sso` prompts with `select_account` and `select_role` unless both `account_id` and
  `role_name` are given; a single account or role is chosen without a prompt.
- `aws_roles_anywhere`: `cert_der`, `key_der`, and `chain_der` are base64 DER; `key_tag` is
  `PKCS8`, `RSA`, or `EC`.
- `aws_web_identity` and `jwt_bearer` endpoints must be `https://` with no userinfo. `scopes` always
  gains `openid`. After sealing, `aws_web_identity` federates once; failure there returns an error
  even though the credential was saved.
- `jwt_bearer` needs a build with the `jwt-bearer` feature, which no published build enables, and
  is experimental; a default daemon rejects it here, though `source` still reports it for a
  credential stored by a feature build.
- `env_var` defaults to the credential name, upper-cased (`.`, `-`, `_` folded to `_`; a leading digit gets a `_` prefix).

Result: `{}`.

Errors: `APPROVAL_REQUIRED` (gated; see [Approval](#methods)); `-32602` (bad params, unknown
`provider.type`, empty secret, bad `identity_type`, `callback_port` out of range, undecodable
DER); `ENVIRONMENT_NOT_FOUND` (unauthorized); `AUTH_TIMEOUT`; `AUTH_CANCELLED`;
`PROVIDER_UNAVAILABLE` (flow already in flight, no accounts or roles, seal or federation
failure); `REAUTH_REQUIRED` (`aws_web_identity` saved but cannot federate; no `remediation`);
`INTERNAL`.

### `environment/bootstrap/respond`

A client-to-daemon notification, sent without `id`, carrying `params.selection` (string) into
the in-flight bootstrap or login on the same connection. It has no response. Sent with an `id`,
it is `-32601`.

### `environment/login`

Re-authenticate saved credentials. Streams [progress](#interactive-flows).

Params: `environment` (required), `credential` (optional; logs in only that credential),
`request_id`. Without `credential`, every credential the environment references is processed.

| Source (`credentials.toml` type) | Behavior |
|---|---|
| `aws-idc-sso` | Renews unattended if it can, else `device_code` |
| `aws-iam-user` with `mfa_serial` | `mfa_required` |
| `aws-web-identity` | `authorize_url` |
| `aws-login` | `authorize_url`, or `authorize_code` when the credential is `remote` (Sign-In re-login) |
| `jwt`, `static-secret` | Skipped; named with `credential`, `PROVIDER_UNAVAILABLE` naming the reseal command |
| others | No-op |

Result: `{}`.

Errors: `ENVIRONMENT_NOT_FOUND` (unauthorized, unknown environment or credential), `-32602`,
`AUTH_TIMEOUT`, `AUTH_CANCELLED`, `PROVIDER_UNAVAILABLE`, `INTERNAL`.

### `environment/import`

Seal a batch of static IAM key pairs, each as an `aws-iam-user` credential with a same-named
environment. Not streamed.

| Param | Type | |
|---|---|---|
| `profiles` | array | `{name, access_key_id, secret_access_key, region, identity_type?}` |
| `dry_run` | bool | default `false`; decides and writes nothing |

Result: `outcomes`, an array of `{name, status, reason?}` with `status` one of `imported`,
`skipped`, `would_import`, `would_skip`. An invalid or existing name is a per-profile skip with
a `reason`, never a batch failure.

Errors: `APPROVAL_REQUIRED` (gated; see [Approval](#methods)); `-32602` (empty
`secret_access_key`, bad `identity_type`; the whole batch is refused before any write),
`ENVIRONMENT_NOT_FOUND` (unauthorized), `INTERNAL`.

### `config/get`, `config/set`, `config/unset`

Read, write, or remove one `config.toml` key of an environment. Keys are those listed in
[configuration](configuration.md).

| Method | Params | Result |
|---|---|---|
| `config/get` | `environment`, `key` | `{value}`: string, or `null` when unset |
| `config/set` | `environment`, `key`, `value` (string, validated against the key's type) | `{}` |
| `config/unset` | `environment`, `key` | `{}` |

Errors: `APPROVAL_REQUIRED` (gated; see [Approval](#methods)); `ENVIRONMENT_NOT_FOUND`
(unauthorized, or no such environment); `-32602` (bad name, unknown key, invalid value, or the
protected key `credential`); `INTERNAL`.

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

Errors: `REQUEST_NOT_FOUND` (`request/get`); `ENVIRONMENT_NOT_FOUND` (unauthorized).

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
`ENVIRONMENT_NOT_FOUND` (unauthorized, on a connection whose uid is not 0).

### `request/withdraw`

Discard one of the caller's pending requests. Nothing is changed. Owner only; uid 0 cannot
withdraw another uid's request.

Params: `id` (required).

Result: `{}`.

Errors: `REQUEST_NOT_FOUND`; `ENVIRONMENT_NOT_FOUND` (unauthorized).

### `presence/enroll`

Raise an enrollment of a presence key for the calling uid. Gated: the result's challenge accepts
privileged approval only, and the key is enrolled when it is approved. Refused on a connection
whose uid is 0.

Params: `public_key` (required), hex SEC1 uncompressed P-256 point (65 bytes).

Result: `{challenge, fingerprint}`. `fingerprint` is `SHA256:` and the unpadded base64 SHA-256 of
the public key.

Errors: `-32602` (uid 0, a malformed key, or another enrollment was pending for this uid, in
which case both are discarded and the message names the process that raised the other);
`ENVIRONMENT_NOT_FOUND` (unauthorized).

### `presence/revoke`

Remove the calling uid's enrolled presence key. Not gated.

Params: none.

Result: `{revoked}`, the removed key's fingerprint.

Errors: `-32602` (no key enrolled); `INTERNAL` (the enrolled-key registry did not open or could
not be written); `ENVIRONMENT_NOT_FOUND` (unauthorized).

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

Errors: `ENVIRONMENT_NOT_FOUND` (unauthorized).

### `file/revalidate`

Reseal hand-edited config files after review. Takes no selector: a snapshot covers its whole
file, so every drifted file is shown and resealed together.

Params: none.

Result: `{}`.

Errors: `APPROVAL_REQUIRED` (gated; the operation happens on approval, see [Approval](#methods)).

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
| `ENVIRONMENT_NOT_FOUND` | No such environment or credential, a credential the environment does not reference, or the caller is not authorized. Indistinguishable by design | Bootstrap the environment |
| `REAUTH_REQUIRED` | No valid session | From `credential/get` and `credential/get_batch`, `data.environment` and `data.remediation`, currently the string `credsd login --environment <env>`; the client command is `creds login` |
| `WRONG_CREDENTIAL_TYPE` | Material of a kind the projection cannot use. No socket method returns it today; the ephemeral container-credentials proxy does, for an access token | Use a credential of the right kind |
| `PROVIDER_UNAVAILABLE` | Upstream or provider failure, or a flow already in flight | Retry; the message says what failed |
| `INTERNAL` | Daemon-side failure (config, storage, encryption, I/O) | See the daemon log |
| `AUTH_TIMEOUT` | Sign-in or selection not completed in time | Run the flow again |
| `AUTH_CANCELLED` | The client closed the connection during a flow | Run the flow again |
| `APPROVAL_REQUIRED` | The operation is gated and was not performed. `data.challenge` is the pending request's challenge, as in [`request/get`](#requestget-requestlist) | `data.remediation`, e.g. `sudo creds request approve <id>` |
| `APPROVAL_REFUSED` | `request/approve` did not satisfy the request. `data.reason` is `not_satisfied` (no signature, and the connection is not uid 0), `signature_invalid`, `no_presence_key`, `privileged_only`, or `base_state_changed`. Every reason but `base_state_changed` leaves the request pending | `data.remediation` |
| `REQUEST_NOT_FOUND` | No such pending request, one that expired or was discarded, or another uid's on a connection whose uid is not 0. Indistinguishable by design | Re-run the original command |

A client should treat an unrecognized `data.code` as a failure.
