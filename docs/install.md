<!-- maturity-notice -->
> **Pre-release preview.** credsd is provided as a pre-release preview in coordination with
> [Strands Box](https://github.com/strands-agents/box). Commands, configuration, the socket
> API, and on-disk formats can change between releases, and a change does not necessarily come
> with a migration path. The on-disk layout may change without a migration. Windows is for
> ease of use only: there is no process-tree assessment, and `serve` does not run there yet.
<!-- /maturity-notice -->

# Install

## Install shapes at a glance

| Artifact and platform | Command | Service manager | Daemon runs as | Backend |
|---|---|---|---|---|
| macOS, official signed release (not yet published) | `credsd install --user` | launchd LaunchAgent | your uid | `data-protection-keychain` |
| macOS, built from source | `sudo credsd install` | launchd LaunchDaemon | `credsd` | `secure-enclave` |
| Linux | `sudo credsd install` | systemd unit + socket | `credsd` | `tpm` |
| Windows | not yet decided | — | — | — |

On macOS the artifact decides the command, and each artifact supports one. The signed release
installs a user-scoped service only: its keystore is the data protection keychain, which is
reachable only from a login session, so only a LaunchAgent can use it — and the release build
omits the Secure Enclave backend entirely, so `sudo credsd install` from it has no backend to
resolve and refuses. A build from source installs a system service only: it has no Apple
signing identity, so it can never reach that keychain, which leaves the enclave, whose key
lives outside any user's keybag and belongs to a service account. `credsd install --user` from
a source build is refused for the same reason, and `sudo credsd install --user` is refused
because a user-scoped service must run as the account that uses it. The two signed-release
destinations below differ only in where the bundle lands and which `bin` directory gets the
symlinks.

`credsd install` resolves the backend and bakes it into the service definition, so the daemon
never re-detects one between installs. A macOS system install resolves `secure-enclave` without
probing: the daemon runs with no login session, which is the one thing the data protection
keychain needs. Resolution fails closed — with no hardware-backed backend install errors rather
than falling back — and a reinstall that would change the baked backend is refused, because
credentials sealed under the old key cannot be opened under a new one.
See [Key security](key-security.md) for each backend's custody and for selecting one
explicitly.

Both system installs are socket-activated: init binds the socket and starts the daemon on
first connect. One daemon serves every local uid. The socket is world-connectable (mode
`0666`); a connection authorizes nothing by itself. A uid is served only once it is
provisioned, which its first `creds bootstrap` does.

## macOS user-scoped install

Official signed release only, which is not yet published. The release is a `.pkg` carrying `Credsd.app`, with the daemon
at `Contents/MacOS/credsd` and the client at `Contents/Resources/creds`.

| Installer destination | Bundle | Symlinks |
|---|---|---|
| Me only (`installer -pkg credsd.pkg -target CurrentUserHomeDirectory`) | `~/Applications/Credsd.app` | `~/.local/bin/{credsd,creds}` |

A private install appends a block marked `# Added by credsd` to `~/.zprofile` or
`~/.bash_profile` when `~/.local/bin` is not already on `PATH`.

The `.pkg` registers the service for the account that installed it. If that step did not run,
register it by hand in a new terminal:

```bash
credsd install --user
```

It prints a security warning and reads `yes` from `/dev/tty`; `--skip-security-warning`
skips the prompt for scripted use. It refuses under `sudo`, because the service must run as the
account that uses it; when the resolved backend is anything but `data-protection-keychain`,
which is what a build from source resolves; and when any ancestor of the daemon's path is
writable by another user (root-owned, `admin`-writable directories such as `/Applications`
excepted).

| Item | Path |
|---|---|
| Service definition | `~/Library/LaunchAgents/com.amazon.aws.credsd.daemon.plist` |
| Daemon binary | the in-bundle path, e.g. `~/Applications/Credsd.app/Contents/MacOS/credsd` |
| Data directory | `~/Library/Application Support/credsd` |
| Socket | `~/Library/Application Support/credsd/credsd.sock` (mode `0600`) |
| Log | `~/Library/Application Support/credsd/credsd.log` |

The master key is a data protection keychain item in an access group only the daemon's
signed binary is entitled to. The daemon must run from inside the bundle: the bundle's
signature and provisioning profile authorize that entitlement, and a copy outside it loses
it. The client carries no entitlement.

## macOS system install

For builds from source. The `secure-enclave` feature is on by default, so a plain build
produces a daemon that can run this service; it needs a Swift toolchain, which the Command Line
Tools provide. The signed release is built without it and refuses this install.

```bash
cargo build --release
sudo install -m 0755 target/release/credsd target/release/creds /usr/local/bin/
sudo credsd install
```

`install` creates the `credsd` service account (a free id in 200–499, shell
`/usr/bin/false`) if absent, chowns the data directory to it, mints the master key, writes the
LaunchDaemon, and loads it.

The enclave key is minted by a one-shot LaunchDaemon that install bootstraps, waits for and
removes, rather than by `install` itself. The enclave binds a key to the launchd context that
created it, so a key minted by `credsd install` — as root, or as the service account under
`sudo -u` — fails to unwrap in the service with `key agreement failed (-6)`. For the same
reason `sudo credsd init --storage-backend secure-enclave` refuses to mint one and points back
here. A reinstall keeps the existing key and skips the mint.

| Item | Path |
|---|---|
| Service definition | `/Library/LaunchDaemons/com.amazon.aws.credsd.daemon.plist` |
| Data directory | `/Library/Application Support/credsd` |
| Socket | `/var/run/credsd/credsd.sock` |
| Log | `/Library/Logs/credsd/credsd.log` |

The master key is wrapped by a Secure Enclave key; the wrapped blob is readable only by the
`credsd` account.

On a Mac without a Secure Enclave (a virtual machine, an Intel Mac without a T2 chip), build
with the `file` feature instead and name the backend. The master key is then a plain file
readable by the `credsd` account and root, so use FileVault:

```bash
cargo build --release --features file
sudo install -m 0755 target/release/credsd target/release/creds /usr/local/bin/
sudo credsd install --storage-backend file
```

## Linux system install

Build with the `tpm` feature, which links the system tpm2-tss libraries (headers and
`pkg-config` needed at build time). Without it the `tpm` backend is selected when
`/dev/tpmrm0` exists and then fails every seal.

```bash
cargo build --release --features credsd-core/tpm
sudo install -m 0755 target/release/credsd target/release/creds /usr/local/bin/
sudo credsd install
```

`install` creates the `credsd` system user (`useradd --system`, shell `/usr/sbin/nologin`)
if absent, chowns the data directory to it and restricts it to 0700, writes `credsd.service`
and `credsd.socket`, and runs `systemctl enable --now credsd.socket`. The service unit declares
`RuntimeDirectory=`, `StateDirectory=` and `LogsDirectory=` for the paths below, so systemd
keeps their ownership and mode. When the backend resolves to `tpm` and a `tss` group exists,
the unit gets `SupplementaryGroups=tss` so the service account can open `/dev/tpmrm0`.

| Item | Path |
|---|---|
| Units | `/etc/systemd/system/credsd.service`, `/etc/systemd/system/credsd.socket` |
| Data directory | `/var/lib/credsd` |
| Socket | `/run/credsd/credsd.sock` |
| Log | `/var/log/credsd/credsd.log` |

`credsd install --user` and `credsd uninstall --user` are refused on Linux.

### Choices common to both system installs

- **Binary location.** The service runs as `credsd`, so its binary must be replaceable only by
  root. If the binary you invoke is not (a build tree, `~/.cargo/bin`), `install` stages a
  root-owned copy (`/usr/local/libexec/credsd/credsd` on Linux, `/opt/credsd/credsd` on macOS),
  bakes that in, and warns. Rebuilding then does not update the service; re-run
  `sudo credsd install`.
- **Backend.** `sudo credsd install --storage-backend <name>` bakes the backend into the
  service arguments. Naming `file` also bakes `--insecure-backend`.
- **Log file.** `--log-file <path>` bakes a log path. `install` refuses a log directory that
  exists and is not owned by `credsd`.

## Windows

Install shapes are not yet decided. `serve` has no Windows transport, so `get` and every other
command that reaches the daemon fail there.

## Why user-scoped is signed-release only

In a user-scoped install the daemon runs as your uid, so any process you run can read the
daemon's files, signal it, or replace what it reads. The only boundary left between the daemon
and those processes is a keystore that gates on code identity: the data protection keychain,
whose item only a binary carrying the authorizing signature and entitlement can read. An
open-source build's signature is reproducible by anyone, so for that build the gate admits
anyone. A system install puts the boundary in the OS account instead, which works for any
build.

## Running the daemon yourself

`credsd serve` runs the daemon in the foreground as your own uid. This is an unsupported,
deliberate mode for development. It refuses to run as root, binds the socket under your user
data directory (where `creds` finds it), and needs a data directory you can write:

```bash
CREDSD_DATA_DIR="$HOME/.local/share/credsd" credsd serve                    # Linux
CREDSD_DATA_DIR="$HOME/Library/Application Support/credsd" credsd serve     # macOS
```

What it gives up: the master key and every sealed credential sit under your uid, so any
process you run can read or replace them. The `file` backend is refused unless you pass
`--insecure-backend`.

## Status, upgrade, and uninstall

```bash
credsd status                 # installed, running, binary path, baked arguments
credsd status --format json
```

On macOS, `status` reports the user-scoped install if one exists, otherwise the system
install.

**Upgrade.** Re-run the install command: `sudo credsd install`, or install a newer `.pkg`,
which re-registers the service itself. Each rewrites the service definition and restarts
the daemon.

**Uninstall.**

```bash
sudo credsd uninstall         # system install; also removes the staged copy
credsd uninstall --user       # macOS user-scoped install
```

Uninstall removes the service definition and leaves configuration and credentials in place.
To remove your credentials too, run `creds remove --environment <name>` for each environment,
then `creds remove --credential <name>` for each credential. Each removal needs approval.
