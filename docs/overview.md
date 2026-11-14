<!-- maturity-notice -->
> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path. The on-disk layout may change without a migration. Windows is for
> ease of use only: there is no process-tree assessment, and `serve` does not run there yet.
<!-- /maturity-notice -->

# Overview

AWS Credential Daemon (credsd) is a local credential manager. It holds the long-lived secrets a
developer works with, exchanges them for the short-lived credentials a task actually needs, and
delivers those to the one process that asked, in the form that process expects to find them. It
is built for a developer's own machine and for the agents and tools that developer runs there.

Securing local credentials should not require you to learn new commands or rewrite application
code, so credsd answers where the AWS CLI and SDKs already look.

- **If you are a developer,** you keep the sign-in and command-line workflow you already use.
  credsd refreshes sessions for you and hands each tool the credential it expects to find.
- **If you are responsible for a fleet,** the long-lived material behind those sessions moves
  into a keystore that the processes running as your developers cannot open, and every request
  for a credential is assessed and audited on the host.

## The problem

Developers authenticate to AWS from laptops, build servers, and virtual machines. The AWS CLI
and SDKs have historically kept long-lived access keys, sign-in sessions, and session caches in
plaintext files under `~/.aws/`.

Operating-system file permissions keep other users of a shared machine out of those files. They
do not distinguish between programs running as the same developer. Every local script,
third-party dependency, and AI coding assistant running under your account can read every
credential file on your disk.

Two shifts made that model untenable:

- **Local AI coding agents.** An agent reads files and runs commands chosen at run time rather
  than following a fixed code path. Content it was never meant to trust — a repository issue, a
  pull request title, a web page — can induce it to read and disclose the credentials sitting
  in `~/.aws/`.
- **Longer sign-in sessions.** As organizations adopt extended AWS sign-in sessions of up to 90
  days to cut daily re-authentication, one copied session file becomes months of access from
  any machine.

## The boundary credsd adds

credsd moves those secrets behind a boundary your user account does not cross:

- **A separate trust domain.** In a system install the daemon runs as its own service account.
  Your processes cannot read its files or its memory. In the macOS user-scoped install, which
  only the official signed release supports, the daemon runs as you, and the keychain gates its
  storage on the daemon's code signature instead. See [install](install.md).
- **One process opens the keystore.** The daemon seals every secret under a master key held by
  a hardware or OS keystore and is the only process that opens it. `creds`, the client, never
  does. See [key security](key-security.md).
- **Short-lived material out, long-lived material stays in.** A caller receives a session that
  expires, not the key that minted it.
- **Changes need more than your uid.** Changing an existing configuration or credential needs a
  Touch ID signature or a `sudo` approval, so a process running as you cannot quietly do it. See
  [presence and sudo approval](presence.md).

## When to use credsd

**Safely empower local AI coding agents.** Run autonomous coding assistants and local scripts
alongside your normal developer environment without leaving readable credentials on disk or
handing an agent unrestricted access. Give the agent's environment its own IAM role, or pair
credsd with a sandbox such as [Strands Box](https://github.com/strands-agents/box) when the agent
should not hold a credential at all.

**Eliminate plaintext credential files on developer workstations.** Protect laptops from local
credential harvesting by sealing session material under a hardware-backed key. Applications and
CLI commands fetch short-lived credentials from the local daemon over a Unix domain socket rather
than reading credential files or a cache. Because the AWS SDKs resolve ambient environment
variables and plaintext files before they consult `credential_process`, importing and removing
what is already on the host is part of installing.

**Unify custody across AWS and third-party credentials.** Hold the OAuth tokens, bearer JWTs and
static API keys your tools use alongside their AWS credentials, establishing a single local
security boundary across every service a machine authenticates to rather than maintaining
separate solutions per provider.

## What credsd does

Holding a secret is one of five things credsd does. The other four decide what a process
receives and how it receives it.

| Layer | What it does | Where it is configured |
|---|---|---|
| Vaulting | Seals long-lived secrets at rest under a master key in a hardware or OS keystore. | Chosen at install: [key security](key-security.md) |
| Credential exchange | Trades a held secret for a short-lived credential from its issuer, and refreshes it before it expires. | `credentials.toml`, through `creds bootstrap` |
| Environment definitions | Names a set of credentials and the settings that go with them, so a task asks for `work` rather than for each piece. | `config.toml`, through `creds config` |
| Credential projection | Delivers each credential in the form its consumer reads: an AWS profile, an environment variable, or a credential endpoint. | The credential type's default, or a declaration in `config.toml` or `credentials.toml` |
| Lightweight authorization | Decides who may ask: kernel-verified caller identity, per-user isolation, identity-type rules, and approval for changes. | Fixed in the daemon; not configurable |

### Vaulting

Every secret is sealed with AES-256-GCM under one master key. The storage backend holds that key
in the Secure Enclave, a TPM 2.0, or the macOS data protection keychain, depending on the
install. Secrets never appear in `credentials.toml`, and there is no command that exports them or
the master key.

### Credential exchange

Most credential types store a secret whose only purpose is to be exchanged:

| Type | Holds | Exchanges it for |
|---|---|---|
| `aws-idc-sso` | An IAM Identity Center session | Role credentials for one account and role |
| `aws-iam-user` | An access key pair | A session token, with MFA if configured |
| `aws-roles-anywhere` | An X.509 private key | A Roles Anywhere session |
| `aws-web-identity` | An OAuth 2.0 sign-in | Role credentials through `AssumeRoleWithWebIdentity` |
| `aws-login` | An AWS Sign-In session (`aws login`) | Raw AWS credentials from the Sign-In token endpoint, rotated on each refresh |
| `oauth` | A client secret or signing key | An OAuth 2.0 access token (client credentials) |
| `jwt-bearer` | A signed assertion | An access token (JWT bearer grant) |
| `jwt`, `static-secret` | A token or secret | Nothing: delivered as stored, until it expires |

The daemon caches the short-lived result and refreshes it in the background, so a long-running
task keeps working without holding anything long-lived. The last row is the plain vaulting case,
and it is the exception. Field-level detail is in the
[configuration reference](reference/configuration.md#credentialstoml).

### Environment definitions

An environment is an ordered list of credentials plus settings: region, endpoint overrides, CA
bundle, retry behavior, CLI output. The first credential is the default identity; the rest stay
addressable by name. A consumer asks for `work` and receives all of it: `creds get --environment
work` returns the default identity, and `--credential` names any other.

### Credential projection

Consumers find credentials in different places. The AWS SDKs read a profile's
`credential_process`; a client library reads a named environment variable; a container-style
consumer discovers an HTTP endpoint. Each of these is a projection, and every credential is
delivered through one:

- **`aws-profile`.** An AWS config section whose `credential_process` calls `creds get`. The
  config holds no secrets.
- **`env-var`.** A token or secret under the variable its consumer reads. `creds get --format
  shell` prints it for `eval`.
- **`credential-endpoint`.** A loopback endpoint behind a bearer token, for consumers that only
  discover credentials that way.

Each credential type has a default projection, and configuration can declare another. credsd
defines the projections and serves `creds get`; delivering a whole environment into one child
process — a generated config, exported variables, a resident endpoint — is left to run-time
tooling built on the [API](reference/api.md).

### Lightweight authorization

The daemon decides who may ask without a policy language:

- **Caller identity comes from the kernel.** The daemon reads the connecting process's uid from
  the socket. The socket takes no bearer token, so there is none to steal.
- **Users are isolated.** Each uid has its own environments and credentials, and a request sees
  only its own. A request about something you do not own is indistinguishable from one about
  something that does not exist.
- **Identity types bound composition.** An environment or credential is `human`, `automation`,
  or `agent`. An environment may compose only credentials no more privileged than itself.
- **Agents are recorded.** On macOS and Linux the daemon inspects the caller's process ancestry
  and records in its audit log when an agent harness is among its ancestors. `--agentic` declares
  this explicitly.
- **Changes need approval.** The daemon gates a fixed set of operations: changing configuration,
  overwriting or removing a credential, and enrolling a Touch ID key. See
  [presence and sudo approval](presence.md).

Every request is audited, with the reason for any denial recorded in the daemon's log rather
than returned to the caller.

## What credsd is not

**Not a general-purpose secret store.** credsd seals secrets so that it can exchange and deliver
them. It has no API for applications to store and read arbitrary values, no secret paths or
versioning, no lease management, and no sharing between users or machines. Every secret it holds
belongs to one user on one machine, and its master key cannot be exported or backed up.

**Not an authorization system for your cloud.** What an AWS credential can do is decided by the
IAM role or policy behind it. credsd chooses which credential a process receives; it does not
narrow what that credential permits. `agent` credentials are not yet scoped down and carry their
role's full permissions.

> **Planned: a scope-down ceiling.** An environment will be able to carry a ceiling that credsd
> applies as an inline policy at issuance, through `sts:GetScopedCredentials`, so the session
> AWS returns is already narrower than the role behind it. Because AWS applies the limit when
> the credential is minted rather than the daemon enforcing it locally, the limit travels with
> the credential and nothing holding that session can widen it. This is in development and no
> release carries it yet; the paragraph above describes current behavior.

**Not a sandbox.** A process that receives a credential can use it however it likes, and so can
anything that process passes it to. credsd limits what is handed out and records who asked; it
does not contain what happens next.

**Not protection from root.** Root on the live machine, or code running as the daemon's own
account, is inside the boundary. So is anything running as you, if you run the daemon as you
from an open-source build: that configuration is permitted, but it is not a secure posture,
and nothing on this page holds for it. See [install](install.md).

## How it compares

Several kinds of tool hold secrets. credsd overlaps each of them in part and is a replacement for
none of them.

**General-purpose secret stores** such as HashiCorp Vault and OpenBao are networked services that
many clients and teams share, with their own authentication methods, policy language, and
secret engines. credsd serves the processes of one machine over a local socket and is not
reachable from the network. It
fills the gap such a store leaves on a developer's laptop: the long-lived credential used to
authenticate to the store is itself something credsd can hold.

**Cloud secret managers** such as AWS Secrets Manager hold application secrets for workloads
running in the cloud and authorize access through cloud IAM. credsd sits before them: it is how
a developer's process gets the AWS credential that lets it call one.

**Password managers** such as 1Password and Bitwarden hold secrets for people, sync them across
devices, and share them within teams. Some can inject secrets into a command's environment.
credsd holds machine credentials rather than passwords, never syncs or shares, and exchanges
most of what it holds rather than handing it over as stored.

**AWS credential helpers** such as aws-vault and Granted are the closest neighbors: they also
keep long-lived AWS credentials out of plaintext files and exchange them for sessions. They run
as your user and reach the OS keystore with your user's permissions. credsd places a separate
daemon between your processes and the keystore, gates changes on approval, and handles non-AWS
credentials and projections through the same model.

**OS keystores** such as the macOS keychain, the Secure Enclave, and a TPM 2.0 are what credsd
builds on. They hold its master key; credsd supplies everything above that.

## Next

- [Getting started](getting-started.md): install, bootstrap a credential, run a command.
- [Install](install.md): which install shape you can use, and what each protects.
- [Key security](key-security.md): storage backends, custody, and threat model.
- [Presence and sudo approval](presence.md): what is gated and how to approve it.
