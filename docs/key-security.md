<!-- maturity-notice -->
> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path. The on-disk layout may change without a migration. Windows is for
> ease of use only: there is no process-tree assessment, and `serve` does not run there yet.
<!-- /maturity-notice -->

# Key Security

credsd seals every credential with AES-256-GCM under one random 32-byte *master key* per data
directory. Every backend names the key's slot `daemon-encryption-key.<home>`, where `<home>` is
the 8-byte hex instance namespace of that directory, so two homes on one machine never share a
key. The storage backend decides where that key lives, so it decides who can reach your
credentials.
Only the daemon opens the backend; `creds` never does.

There is no command to export, back up, or migrate the master key.

## Your install, your posture

| Install shape | Daemon runs as | Backend | Master key bound to this machine |
|---|---|---|---|
| macOS user-scoped, official signed release | you | `data-protection-keychain` | yes |
| macOS system install | `credsd` service account | `secure-enclave` | yes |
| Linux system install | `credsd` service account | `tpm` | yes |
| Any host without the hardware | `credsd` service account | `file`, named explicitly (macOS: a build with the `file` feature) | no |

Install shapes and how to choose one: [install.md](install.md).

The hardware paths are compile-time features. `secure-enclave` is on by default and needs a
Swift toolchain, which the macOS Command Line Tools provide; `tpm` is off by default and links
the system tpm2-tss libraries. A build without them cannot use the hardware. On macOS `file` is
a feature too, off by default, for Macs without a Secure Enclave (virtual machines, Intel Macs
without a T2 chip); Linux and Windows always include it.

The official macOS release is built without `secure-enclave` and without `file`, so it accepts
`data-protection-keychain` alone. That is deliberate: the release installs a user-scoped
service, whose keystore is that keychain, and a daemon with no login session can never reach
it — so a release that carried the enclave would make `sudo credsd install` look like a
supported path. `credsd --version` lists the backends a binary was built with.

`credsd status` reports the backend baked into the service definition, and `--format json` adds
the data directory and socket beside it. Neither probes a keystore. The daemon logs
`encryption key loaded` with the backend name at startup; the `file` backend logs a warning
instead.

## Storage backends

Paths below are relative to the daemon's data directory; see
[configuration.md](reference/configuration.md) for where that is per install shape.

### `data-protection-keychain` (macOS)

- **Held:** a generic-password item in the data protection keychain, in the access group
  `94KV3E626L.com.amazon.aws.credsd.daemon`.
- **Can read or replace it:** only a binary carrying that access-group entitlement, running as
  you. Only the signed release daemon carries it; `creds` does not. Needs a login session, so
  it serves a user-scoped install only.
- **Protects against:** a copied disk or keychain database; other processes running as you,
  including unsigned rebuilds of credsd.
- **Does not protect against:** root on the live machine; code that gets execution inside the
  signed daemon.

### `secure-enclave` (macOS)

- **Held:** `secure-enclave/daemon-encryption-key.<home>.sekey`, an opaque handle to a P-256 key
  inside the Secure Enclave, and `secure-enclave/daemon-encryption-key.<home>.sealed`, the master key
  encrypted to it. Both `0600` in a `0700` directory. The master key never reaches disk
  unwrapped.
- **Can read or replace it:** any process that can read `.sekey` on this Mac *and* runs in the
  launchd context the key was minted in can ask the enclave to unwrap. The enclave does not
  check code identity, but it does bind the key to that context: a key minted outside launchd
  fails to unwrap in the service, which is why the system install mints through a one-shot
  LaunchDaemon. File permissions and the owning account are the local boundary you administer.
- **Protects against:** a copied disk or data directory; the files are useless on another Mac.
- **Does not protect against:** anything running as the daemon's account, or root.
- **Caveats:** reaching the enclave from a `launchd` daemon without a keychain is not a path
  Apple documents or commits to. The enclave key's protection class defaults to `always`,
  the only class with no login dependency, which Apple has deprecated. Set
  `CREDSD_SE_PROTECTION` (`always`, `after-first-unlock`, `when-unlocked`) in the daemon's
  environment to change it; it applies only when a new enclave key is created, and
  `credsd install` does not set it. Unwrap before any user has logged in is untested.

### `tpm` (Linux)

- **Held:** `tpm/daemon-encryption-key.<home>.sealed`, the master key sealed to the TPM 2.0 storage
  root key, and `tpm/daemon-encryption-key.<home>.meta`, a non-secret record of the sealing policy.
  Both `0600` in a `0700` directory. The plaintext key exists only in the TPM and in process
  memory.
- **Can read or replace it:** any process that can read the blob and open `/dev/tpmrm0`. The
  TPM has no notion of OS users or calling binary. In a system install that is the `credsd`
  account (through the `tss` group) and root.
- **Protects against:** a copied disk, backup, or blob.
- **Does not protect against:** execution as the `credsd` account, or root, or a change to
  the boot chain: the key unseals on this TPM in any boot state.
- **Policy:** `machine`, the only sealing policy; it is not configurable. The daemon refuses
  to start the `tpm` backend while `CREDSD_TPM_POLICY` is set, and refuses a key whose
  sidecar records any other policy, which `credsd init --reset --storage-backend tpm`
  recovers from.
- **Needs its own download:** the `-tpm` artifacts — `al2023-x64-tpm`, `al2023-aarch64-tpm`,
  `ubuntu-x64-tpm`, `ubuntu-aarch64-tpm` — are the only builds carrying the `tpm` feature.
  They need the tpm2-tss runtime on the host (`tpm2-tss` on AL2023, `libtss2-dev` on Ubuntu)
  and do not start without it, which is why they are separate downloads. There is no AL2
  variant. Any other artifact falls back as described under
  [how a backend is chosen](#how-a-backend-is-chosen).

### `kkrs` (Linux, with the `kkrs` feature)

- **Held:** the kernel user keyring of the daemon's uid, as
  `com.amazon.aws.credsd:daemon-encryption-key.<home>`. Never on disk. A `kkrs.sentinel`
  file records the boot it was created in.
- **Can read or replace it:** processes running as the daemon's uid, and root.
- **Protects against:** a copied disk; there is no key on it.
- **Does not protect against:** anything running as the daemon's uid, or root.
- **Cost:** the kernel clears the keyring on reboot. Every boot then starts with a new master
  key, and every sealed credential, including hand-entered IAM keys, is quarantined and must be
  bootstrapped again. Never auto-detected.
- Absent from every published build. Build with `cargo build --features kkrs`; naming it in a
  build without the feature fails with ``not compiled into this build; rebuild with
  `--features kkrs` ``.

### `dpapi` (Windows)

- **Held:** `dpapi\daemon-encryption-key.<home>.dpapi`, the master key encrypted with
  `CryptProtectData` under the daemon account's DPAPI user key, with a fixed entropy value
  compiled into the binary.
- **Can read or replace it:** any process running as that Windows account.
- **Protects against:** other accounts and a copied disk without the account's credentials.
- **Does not protect against:** code running as the account; a disk plus the account's
  credentials. No hardware binding.
- When `dpapi` starts with no key of its own and a `credential-manager` key exists, it moves
  that key into DPAPI and deletes the original.

### `credential-manager` (Windows)

- **Held:** a generic credential `credsd/daemon-encryption-key.<home>` in Windows Credential Manager,
  persisted per machine, or only for the logon session where the session does not allow that.
- **Can read or replace it:** any process running as that Windows account.
- **Protects against:** other accounts.
- **Does not protect against:** code running as the account. No hardware binding. A
  session-persisted key is lost at logoff.
- Needs an interactive logon session; without one, selecting it is an error. Never
  auto-detected.

`credsd serve` does not run on Windows yet (no named-pipe transport), so neither Windows
backend is in use today. Windows install shapes are undecided.

### `file` (Linux and Windows; macOS with the `file` feature)

- **Held:** `keys/daemon-encryption-key.<home>.key`, the master key in plaintext, `0600` in a `0700`
  directory.
- **Can read or replace it:** the daemon's account and root.
- **Protects against:** other local accounts, while the system is running.
- **Does not protect against:** anyone who obtains the disk or a backup. Use full-disk
  encryption (FileVault, LUKS) with this backend.
- Never auto-detected. `credsd serve` refuses it without `--insecure-backend`; a user-scoped
  install refuses it outright. Absent from the official macOS release; on macOS, build with
  `cargo build --features secure-enclave,file` (or `FEATURES=file scripts/install.sh`).

## How a backend is chosen

`--storage-backend <name>` (a global `credsd` flag) names a backend. `credsd install
--storage-backend <name>` bakes it into the service definition, and adds `--insecure-backend`
when the name is `file`. Without the flag the daemon auto-detects at every start:

| Platform | Auto-detect |
|---|---|
| macOS | `data-protection-keychain` if this binary can write to it, else `secure-enclave` if this binary can reach an enclave, else an error |
| Linux | `tpm` if this build has the `tpm` feature and `/dev/tpmrm0` exists, else an error |
| Windows | `dpapi` |

Auto-detect never picks `kkrs`, `file`, or `credential-manager`. When it
errors, the daemon does not start; name a backend explicitly to proceed, for example:

```bash
credsd --storage-backend file serve --insecure-backend
```

A named backend that is unavailable is an error, never a substitution. A build without the
`tpm` feature never selects `tpm`, even on a host with `/dev/tpmrm0`: auto-detect errors, and
naming it explicitly fails with ``not compiled into this build; rebuild with `--features tpm` ``.
Sealed credentials from an earlier `tpm` install are left in place.

## Upgrading from a build with a shared key slot

Earlier builds kept the master key under the slot `daemon-encryption-key`, with no
`.<home>` suffix, so every data directory under one account read the same key. This build
opens only the per-home slot, and `serve` does not create a missing key: after an in-place
upgrade the daemon exits with `no encryption key found` until a new key is minted. Re-run
`sudo credsd install` for a system install, or `credsd install --user` for a user-scoped
one (the macOS `.pkg` does this for you), or run `credsd init --storage-backend <name>`.
`kkrs` is the one backend that mints a new key on start. Credentials sealed under the old
key then read as `decrypt failed`; re-seal them as in step 4 of
[Changing backend](#changing-backend).

The old key is not removed, and `credsd purge` does not remove it either: purge deletes only
the current home's slot. To delete it by hand, remove the item with no suffix:

- `data-protection-keychain`: the generic password with service `com.amazon.aws.credsd` and
  account `daemon-encryption-key`, in Keychain Access or with `security delete-generic-password`.
- `secure-enclave`: `secure-enclave/daemon-encryption-key.sekey` and
  `secure-enclave/daemon-encryption-key.sealed` in the data directory.
- `tpm`: `tpm/daemon-encryption-key.sealed` and `tpm/daemon-encryption-key.meta`.
- `kkrs`: the user-keyring key `com.amazon.aws.credsd:daemon-encryption-key`, with `keyctl`.
- `dpapi`: `dpapi\daemon-encryption-key.dpapi`.
- `credential-manager`: the generic credential `credsd/daemon-encryption-key`.
- `file`: `keys/daemon-encryption-key.key`.

## Changing backend

The backend is not recorded anywhere; the daemon resolves it at each start. When the resolved
backend holds no master key:

1. The daemon creates a new random master key in that backend.
2. The old key stays in the old backend. Nothing migrates or deletes it, except the Windows
   `credential-manager` to `dpapi` move above.
3. Sealed credentials stay on disk, encrypted under the old key. `creds list` shows them as
   `decrypt failed`, and requests for them fail.
4. `creds login --env <env>` re-authenticates issuer-backed sources (SSO, OAuth, AWS login).
   Secrets you entered yourself, such as IAM access keys or static secrets, need
   `creds bootstrap` again with the secret in hand. Either one re-seals under the new key.

Switching back to the old backend makes credentials readable again, if they were not
re-sealed in between.

Auto-detect can change the backend without any setting changing. On macOS, a daemon that
loses access to the data protection keychain falls through to `secure-enclave`, and a new key
is created. Pass `--storage-backend` explicitly to make that a startup error instead.

The two keychain backends and `credential-manager` treat a key credsd cannot read as missing,
and store a new key under the same name.

## What an attacker would need

Every shape exposes one path regardless of backend: code running as you can ask the daemon for
your credentials over the socket, as `creds` does. The table covers the master key and every
sealed credential at once.

| Attacker has | macOS user-scoped (signed) | macOS or Linux system install | `file` backend |
|---|---|---|---|
| A copy of the disk or data directory | nothing | nothing | the key, unless the disk is encrypted |
| Another local account | nothing | nothing | nothing |
| Code running as you | requests over the socket only | requests over the socket only | requests over the socket only |
| Code running as the daemon's account | same as the row above: the daemon runs as you | the key | the key |
| Root on the live machine | the key | the key | the key |

Under `credsd serve` run as your own uid, the daemon's account is you, so code running as you
reaches the key on every backend except `data-protection-keychain`. See
[install.md](install.md).

## If you lose the machine

The master key cannot leave the machine, so neither can your sealed credentials. You start
over after:

- a new or replaced machine, or a disk restored onto different hardware;
- a macOS erase-and-reinstall;
- a TPM clear;
- a reboot, on `kkrs`.

Issuer-backed sources cost one re-authentication. Long-term IAM keys and static secrets you
entered by hand are gone unless you keep them elsewhere; otherwise rotate them at the
provider.

On `tpm` and `kkrs`, the daemon recovers by itself. It logs that re-authentication is
required, moves every sealed credential to `quarantine/<timestamp>/` (it keeps the newest
three), and creates a new key. Credentials then show `no session`.

`secure-enclave` and `file` refuse to start when the key is present but unusable, and leave the
files in place. For the keychain backends and `credential-manager`, see
[Changing backend](#changing-backend).

## When credsd refuses to start

| Message contains | Cause | Remedy |
|---|---|---|
| `no hardware-backed storage available` | Linux auto-detect found no `/dev/tpmrm0`, or the build lacks the `tpm` feature | Use a `-tpm` artifact on a host with a TPM; otherwise name `file` explicitly and enable full-disk encryption |
| `no hardware-backed storage available (no entitled data protection keychain, no reachable Secure Enclave)` | macOS auto-detect found neither | On a Mac without an enclave, a system install with a `file`-feature build and `--storage-backend file` |
| `the file backend stores the encryption key as a plain file` | `file` without `--insecure-backend` | Add `--insecure-backend`, or use a hardware backend |
| `storage backend '…' is not compiled into this build` | The build lacks the feature for that backend: `secure-enclave` or `file` on macOS, `tpm` or `kkrs` on Linux | Use a build with the feature the message names (on Linux, a `-tpm` artifact) |
| `storage backend 'secure-enclave' is unavailable` | The Mac has no enclave | On a system install, a `file`-feature build and `--storage-backend file` |
| `could not unwrap key` | Enclave files from another Mac, or a protection class this process cannot meet | Restore the right `CREDSD_SE_PROTECTION`, or move `secure-enclave/` aside to start with a new key |
| `has no enclave key` | `.sealed` present, `.sekey` missing | The key is unrecoverable; move `secure-enclave/` aside to start with a new key |
| `data-protection-keychain requires the daemon's keychain-access-groups entitlement` | Not the signed release daemon | Use the signed release, or a system install |

After moving `secure-enclave/` aside, credentials show `decrypt failed` until re-bootstrapped.

## What you can tell your security reviewer

Check the daemon's startup log first: the claims depend on the backend actually in use.

**System install with `secure-enclave` or `tpm`, or user-scoped install with
`data-protection-keychain`:**

- The credential encryption key is bound to this machine's hardware and is useless on another
  machine.
- No process running as the developer can read the key. In a system install it belongs to the
  `credsd` service account; in a user-scoped install, only the signed daemon can read it.
- On macOS system installs, the binding uses a Secure Enclave path Apple does not document
  for daemons. It is observed to work, not supported.

**`file` backend:** the key is a file readable only by the service account, protected at
rest by full-disk encryption only.

Claims that are not true:

| Claim | Why not |
|---|---|
| The key cannot be stolen | The files can be copied. They are useless elsewhere. |
| Only credsd can use the key | For `secure-enclave` and `tpm`, any code running as the daemon's account can. |
| Code running as the developer cannot get credentials | It can ask the daemon over the socket. |
| Credentials are protected from root | Not on any backend. |
| AWS verifies the credentials came from this hardware | Hardware binding is local. credsd proves nothing to a remote service. |
| This build is hardware-backed | Only if built with `secure-enclave` or `tpm` and the log names that backend. |
