# Design: macOS `.pkg` Installation

**Status:** draft (implemented on this branch — approval means "accept this behavior")
**Feature:** `mac-pkg-installation`
**Requirements:** see `requirements.md` in this directory.

## Overview

The distribution `.pkg` is a product archive wrapping one component package. The
component carries one thing, the `Credsd.app` bundle, declared at the *relative*
install location `Applications`. A relative location is what lets one payload serve two
destinations: the installer resolves it against the target volume for `LocalSystem` and
against the invoking customer's home for `CurrentUserHomeDirectory`. The
distribution script enables exactly those two destinations, so `-target` is the whole of
the placement decision.

The post-install script does two things: establish `PATH` access, then register the
user-scoped service by running `credsd install --user`. Which mechanism each uses follows
from whether the script holds root, which follows from the destination. A private install
is already the account the service belongs to; a root install hands the registration to
the console user's session.

```
                       pkg responsibility        customer responsibility
                 ┌──────────────────────────┐  ┌─────────────────────────┐
  installer ───▶ │ place payload            │  │ creds bootstrap         │
                 │ establish PATH access    │  └─────────────────────────┘
                 │ credsd install --user    │
                 └──────────────────────────┘
```

## Key Design Decisions

### 1. The installer registers the service for one account

The service is user-scoped by construction: its LaunchAgent, socket, data directory and
keychain item all belong to a single uid. So the installer can register it for the account
in front of the machine and for no one else. A shared install serves every account on the
Mac, and account number two still runs the command once itself.

Two steps of `install_user` need that account's live login session, which root cannot
stand in for: `launchctl load` needs its `gui/<uid>` domain, and minting the master key
needs its unlocked Data Protection keybag — the same absence that makes the system scope
unable to reach that keychain at all (Requirement 7's matrix). A root-run script therefore
re-enters the session rather than dropping privileges:

```sh
launchctl asuser "$console_uid" sudo -H -u "$console_user" -- \
    "$DAEMON" install --user --skip-security-warning
```

`asuser` supplies the domain and the session; `-H` supplies the home directory the data
dir and socket path are derived from. `sudo -u` alone gives the uid and neither of the
other two.

Three cases this cannot cover, and does not try to:

| Case | Behavior |
|---|---|
| No console user (login window, `sudo installer` over ssh) | No session exists to register into. Files are placed, the install succeeds (Req 4.7), and the command is reported. |
| A setup or system account owns the console (`_mbsetupuser` during Automated Device Enrollment, `root`, `loginwindow`) | Treated as no console user, by name rather than by uid. The account is not a customer and in the enrollment case does not outlive Setup Assistant, so registering there would strand the agent and the key. |
| Other accounts on a shared install | Per-uid by construction; Req 4.6 records why one shared `/Library/LaunchAgents` plist cannot substitute. Each runs the command once. |
| Fast user switching | The console user is the active one. The others are the row above. |

The cost is accepted deliberately. The script resolves the console user and executes as
another account, and a root install writes into one customer's home directory. In exchange,
an ordinary double-click install leaves a running service rather than an instruction.

The consent prompt is the other cost. `confirm_typed_yes` reads `/dev/tty` precisely so a
script cannot answer it, and an installd-run script has no terminal, so registration passes
`--skip-security-warning`. The warning's content moves to the final installer pane, which
states the posture the customer now has. This is a real reduction in the consent surface: a
pane that is read after the fact in place of a typed `yes` before the act.

### 2. Relative install location, not one component package per destination

A component package may declare an absolute install location, which would need two
components and a choice in the distribution script to select between them. The
relative location collapses that to one component and moves the choice to
`-target`, where `installer` already expects a destination. The `credsd/` level
below `Applications` keeps the `bin` directory out of the top-level apps folder.

### 3. Bundle relocation is refused explicitly

An inferred bundle component defaults to relocatable. A relocatable component makes
the installer look the bundle's `CFBundleIdentifier` up in the bundle database and
install over whatever copy it finds, in place of the declared location. Because the
`PATH` references are derived from the install destination, a relocated bundle is
written to one path and referenced at another — and only on machines carrying an
earlier copy, which is the population a first-install test does not cover.

There is no command-line flag for this. It takes a component property list supplied
to the package builder, setting `BundleIsRelocatable` false alongside a strict
identifier and a root-relative bundle path.

### 4. The bundle's mode is part of the payload

The package builder records each directory's mode into the bill of materials, and the
installer applies it. A bundle written with default-private permissions lands `0700`
and root-owned under a shared install: present and unreachable, because the other
accounts the design expects to run `credsd install --user` cannot traverse into it.

A private install masks this completely, because there the bundle belongs to the
installing customer, who may enter their own private directory. The failure therefore
appears only in the shared install, and only when something tries to execute the
daemon.

The payload *root* is a separate matter and deliberately not relied on. It maps to
`Applications`, which exists on every macOS install, and the installer applies a
recorded mode only to a directory it creates — verified by installing a probe over an
existing `0700` directory and observing the mode unchanged. So the root's recorded
mode never lands, and the check asserts the bundle's own mode instead.

### 5. Both executables live inside the bundle, and nothing in it is a `PATH` entry

The daemon is at `Contents/MacOS/credsd` and the client at `Contents/Resources/creds`.
That is where macOS software of this shape keeps its executables, and where a
`/usr/local/bin` or `~/.local/bin` symlink conventionally resolves to.

The bundle holds no `bin` directory arranged for the shell to find. Such a directory — the
client plus a relative symlink to the daemon — would let a private install put one entry on
`PATH` and expose both commands. It is rejected because it makes the two install shapes use
different mechanisms for the same job: symlinks into a `bin` directory one way, a `PATH`
entry pointing inside the bundle the other. Decision 6 uses the same mechanism for both.

Keeping both executables in the bundle also simplifies signing: the client is signed with
its own identifier and the bundle's signature then seals it, so one notarization subject
covers everything rather than two independent artifacts.

That makes signing order significant. The client must be signed before the bundle, because
signing the bundle computes the seal over its contents. Sign them the other way round and
`codesign --verify --deep --strict` fails, which Gatekeeper enforces after notarization.
Signing the bundle's *main* executable is not a separate step — it is what signing the
bundle does.

The daemon is never copied out. A copy outside the bundle carries no provisioning profile,
so it cannot reach the Data Protection keychain, and `credsd status` would disagree with the
service definition about which file is the daemon.

### 6. One `PATH` mechanism, two directories

Both install shapes do the same thing: create one symlink per command in a `bin` directory
that is on `PATH`, pointing at the executables inside the bundle. Only the directory differs
— `/usr/local/bin` when the install holds root, `~/.local/bin` when it does not, because
`/usr/local/bin` is `root:wheel 0755` and Requirement 1.5 keeps a private install
unprivileged.

Both are the established choices. System-wide installers symlink into `/usr/local/bin`;
per-user installers symlink into `~/.local/bin`, which is what comparable software does for
a CLI that lives inside an application bundle.

`~/.local/bin` is not on the default `PATH`, which is five root-owned directories, so a
private install may still need to add it. That is a smaller and more durable edit than the
alternative: the block names `~/.local/bin` rather than a path inside the bundle, so moving
or reinstalling the bundle leaves it valid, and a customer who already has the directory on
`PATH` needs no edit at all.

Detection of "already on `PATH`" is best effort and deliberately so. `PATH` can be set by a
file the installer cannot find — a shell startup file that sources another one, for instance
— and the only way to know for certain would be to run the customer's login shell and read
its environment, which means sourcing arbitrary user configuration as part of an install. A
redundant `PATH` entry is harmless; doing that is not.

`/etc/paths.d` is rejected. It applies only through `path_helper` at login, so it misses
non-login contexts, and it is not the mechanism this class of software uses.

Three properties keep the mechanism from doing harm:

- **Not fatal** (for PATH access). The bundle is placed and usable before `PATH` access is
  attempted, so a failure reports what was skipped and still succeeds. Bundle integrity
  failure is the one exception: linking a suspect bundle into `PATH` is worse than a failed
  install, so verification failure exits non-zero (Req 5.12).
- **Does not clobber foreign entries.** An entry of that name not already pointing into a
  credsd install is left alone. Replacing it would silently take over a name another product
  owns.
- **Reports shadowing.** An entry earlier in `PATH` wins, and a customer who prepends a
  development build in their shell startup file will keep resolving it. Reporting the
  shadowing path is cheaper than a support conversation, and matches what
  `scripts/install.sh` already does.

### 7. An installed bundle must satisfy the install arm's ancestor check

Choosing `/Applications` creates an obligation: the install Requirement 4.1 performs,
and the command 4.9 names for every other account, both have to accept the path the
installer chose.

A per-user LaunchAgent names an absolute binary path and macOS runs it at every
login, so an account able to replace that binary obtains code execution as the
agent's owner. The check walks the daemon path's ancestors and rejects anything
other-writable or owned by neither root nor the serving account. `/Applications` is
`root:admin` mode `0775`, so every shared install is rejected, and `/Applications`
is not a directory credsd may re-permission.

The exception admits a root-owned, non-other-writable ancestor whose group is
`admin`, gated to macOS. It is calibrated against what already occupies that
directory. A third-party application that registers a login item commonly presents
a bundle that is itself group-writable and owned by the account that installed it:

```
775 <installing account>:admin  /Applications/Example.app/Contents/MacOS
775 <installing account>:admin  /Applications/Example.app
775 root:admin                  /Applications
755 root:wheel                  /
```

A `.pkg`-installed credsd bundle is `root:wheel 0755`, so the only group-writable
ancestor on its path is the system directory:

```
755 root:wheel  /Applications/Credsd.app/Contents/MacOS
755 root:wheel  /Applications/Credsd.app
775 root:admin  /Applications
755 root:wheel  /
```

The exception therefore admits a group-writable *directory* and not a group-writable
bundle, and credsd stays tighter in `/Applications` than its neighbours already
rely on.

What the relaxation costs, stated once: on a machine with two or more admin
accounts, an admin can rename `/Applications/Credsd.app` aside and substitute a bundle,
and the served account's agent runs it at next login. That account could already
replace any other application in the directory and obtain the same execution when
the customer next launches one, and could already `sudo` with its own password. The
exception narrows the gap from "when the customer opens something" to "at login",
not from impossible to possible. The master key is unaffected: a binary running as
the customer can read their keychain whether or not a plist names it, so this is a
persistence vector.

`admin` alone is sufficient. `wheel` is not admitted, because the root-owned
`wheel` directories on either install path are not group-writable and already pass.

The `/usr/local/bin` symlink does not provide an escape. If the service definition
named `/usr/local/bin/credsd`, every ancestor would pass — but
`resolve_binary_path_canonical` canonicalizes, and it must, because the signature
and entitlement attach to the bundle path. The definition names the bundle, so the
check sees `/Applications`.

Alternatives considered and rejected:

- **Verify the code signature in place of the mode.** Application identity is what
  the Data Protection keychain gates on, so this is the stronger control on macOS.
  Rejected as the *primary* control because it forecloses Linux, which has no
  signature to verify and would be left with no guard, and because it introduces a
  verification path and an acceptable-identity policy to avoid adjusting one
  predicate.
- **Install the bundle somewhere root-only.** Satisfies the unmodified rule and
  places an application bundle where customers do not look for applications.
- **Drop the shared install.** Satisfies every rule by deleting the case, and
  removes the choice Requirement 1 provides.

## Platform considerations

Per `.agents/rules/platform-one-way-doors.md`.

**The mode-bit check.** Decision 7 is an instance of "mode bits as the access
boundary". It broadens one predicate behind a `#[cfg(target_os = "macos")]`; the
Linux arm keeps the unmodified rule. Reversing it costs one expression and its unit
tests, so it is a two-way door and is taken without hedging.

**The one-way door nearby, not taken.** Replacing the mode check with signature
verification as the primary control would be one-way: Linux has no equivalent, so
the seam would have to move rather than gain another arm, and the install contract
would acquire a notion of verified code identity only one platform can satisfy.

**`SMAppService`.** Apple's mechanism for an application to register its own login
item, from a plist inside its own signed bundle. It is the eventual destination for
Requirement 4: the installer's `credsd install --user` becomes the application
registering itself, and the service definition stops being a file in the customer's
home — which would retire the console-user resolution and the session re-entry with it. That would retire the ancestor check on macOS entirely, because
the definition would live inside the signed bundle and identity would come from the
signature rather than from directory modes. It is deliberately out of scope here: it
is macOS-only, requires the signed bundle to exist first, and does not block
anything this feature delivers. Adopting it later adds an arm; it does not move a
seam.

**Windows.** This feature is macOS-only and adds no contract a future Windows
install path would inherit. A `.pkg` has no Windows analogue, and the mode-bit
predicate is already `#[cfg]`-gated away from that target.

## Architecture

```
credsd.pkg  (product archive)
├── Distribution                     destinations: LocalSystem, CurrentUserHomeDirectory
│                                    conclusion pane stating the posture + bootstrap
└── credsd-component.pkg
    ├── PackageInfo                  install-location="Applications"
    │                                no <relocate> element
    ├── Bom                          Credsd.app mode 0755
    ├── Payload                      Credsd.app/ (MacOS/credsd + Resources/creds)
    └── Scripts/postinstall          PATH access, then credsd install --user
```

```
sudo installer -target /                    installer -target CurrentUserHomeDirectory
        │                                              │
        ▼                                              ▼
bundle → /Applications/Credsd.app           bundle → ~/Applications/Credsd.app
        │  (root:wheel 0755)                          │  (customer-owned)
        ▼                                              ▼
postinstall as uid 0                         postinstall as the invoking customer
        │                                              │
        ▼                                              ▼
/usr/local/bin/{creds,credsd}                ~/.local/bin/{creds,credsd}
        │                                              │
        ▼                                              ▼
launchctl asuser <console_uid>               credsd install --user
  sudo -H -u <console_user>                    (already the right account)
  credsd install --user
        │                                              │
        └──────────────────┬───────────────────────────┘
                           ▼
        ~/Library/LaunchAgents/com.amazon.aws.credsd.daemon.plist
        ProgramArguments[0] = <destination>/Credsd.app/Contents/MacOS/credsd
```

With no console user the left branch stops after the symlinks and reports the command.

## Components and Interfaces

### 1. Build script (`packaging/build-dist-pkg.sh`)

Assembles the staging tree including the `bin/credsd` symlink, sets the staging
root's mode, emits the component property list, builds the component package with
the relative install location, writes the distribution script with the license and
conclusion panes, builds the product archive, and runs the Requirement 8 checks. Accepts
pre-signed inputs, so the signing step owns the signature and packaging owns the
structure.

### 2. Post-install script (`packaging/dist-scripts/postinstall`)

Reads the install destination, verifies the bundle, establishes `PATH` access —
symlinks when running as root, a marked startup-file block otherwise — and then
registers the user-scoped service. Reports a skipped mechanism or a shadowing entry
without failing; bundle verification is the one fatal step (5.12). Requirement 8.6
asserts the registration is present in the built package and that no shared
`/Library/LaunchAgents` plist is written.

### 3. Install arm (`crates/credsd-daemon/src/install.rs`)

Invoked by the installer, and by any further account on a shared machine. Writes the
per-user LaunchAgent and carries the ancestor trust check from Decision 7. The install
destination is invisible to it: it sees only the daemon path it resolved, which is why one
arm serves both install shapes and every account on a shared machine. Its root refusal
(Req 7.7) is what forces the installer's session re-entry rather than a plain `sudo -u`.

### 4. Distribution script (generated)

Declares the two destinations, disables the arbitrary-volume one, pins host
architectures to `arm64` (1.7), requires scripts to run, and carries the conclusion pane stating the
user-scoped posture, naming `creds bootstrap`, and naming `credsd install --user` for
the other accounts on a shared install.

## Correctness Properties

1. The bundle's installed path is a function of `-target` alone. No previously
   installed bundle changes it.
2. Both commands resolve by name in a login shell started after the install, or the
   install reported why not.
3. No launchd service definition exists anywhere as a result of an install.
4. An install succeeds with no account logged in at the screen.
5. A `PATH` entry the installer created points into the install destination; an
   entry it did not create is untouched.
6. Uninstalling removes every `PATH` entry the install added, and each is
   discoverable by inspection.
7. The ancestor check rejects every other-writable ancestor, and every ancestor
   owned by a third account, at both destinations and on both platforms.
8. The service definition names the in-bundle daemon path, not a `PATH` symlink,
   whichever account created it.
9. No install writes a service definition outside one account's own
   `~/Library/LaunchAgents`.

## Error Handling

| Condition | Behavior |
|---|---|
| `/usr/local/bin` absent on a shared install | Create it, then symlink. |
| `PATH` mechanism cannot be completed | Report what was skipped and the direct path. Install still succeeds (5.7). |
| A `/usr/local/bin` entry of that name points outside a credsd install | Leave it, report it. Do not replace (5.9). |
| A command of that name resolves earlier in `PATH` | Report the shadowing path (5.8). |
| No account logged in at the screen | Not an error. The installer places files, skips registration, and names the command (4.7). |
| Registration fails for any other reason | Report it and the command to re-run. Install still succeeds (5.9). |
| Daemon path has an other-writable ancestor | `credsd install --user` fails, naming the path. Not reachable from a `.pkg`-installed location. |
| Resolved backend is `file` for a user install | `credsd install --user` fails, naming the guarantee it does not provide. |

Bundle integrity failure is the exception: if verification fails, the installer exits
non-zero (Req 5.12) rather than linking a suspect bundle. All other failures — PATH
access, symlink creation, shell-rc update — are non-fatal once the payload is placed.

## Testing Strategy

### Build-time, on the artifact (Requirement 8)

Expand the built product archive and assert: the payload contains both binaries and
the `bin/credsd` symlink; the component carries no relocate element; the bill of
materials records the bundle at `0755`; both install destinations are enabled;
the scripts register the user-scoped service and re-enter the console user's session
to do it, and reference neither `/Library/LaunchAgents` nor
`/Library/LaunchDaemons`; the packaged daemon's `--version` reports exactly
`data-protection-keychain` as its storage backends (8.8); and the host architectures the
distribution script declares are read back from the expanded package and compared against
`lipo -archs` of the two packaged binaries (8.10). `build.yml`
asserts the same `--version` line on the CI binary the signed bundle is built from, before upload.

### Install-time, per UX shape

For UX-3 and UX-4: assert the bundle's resulting path, that both commands resolve in
a freshly started login shell, that the console user's
`~/Library/LaunchAgents/com.amazon.aws.credsd.daemon.plist` exists and names the
in-bundle daemon, and that nothing appeared under `/Library/LaunchAgents` or
`/Library/LaunchDaemons`. UX-4 runs without root. Repeat UX-3 with no console user and
assert the install succeeds with no agent written.

The root path's keychain mint is the step that cannot be inferred from the launchd
result: `launchctl asuser` is documented to supply the bootstrap domain, and its supplying
a usable Data Protection keybag is an empirical claim about a signed bundle on real
hardware. The standalone signed probe is what settles it, and it must be settled before
this ships.

### Unit, in the install arm

The ancestor check is a pure function of path metadata, tested against constructed
trees:

| Case | Expected |
|---|---|
| other-writable ancestor | rejected |
| ancestor owned by a third account | rejected |
| root-owned, `admin`-group-writable ancestor | accepted on macOS |
| root-owned, `admin`-group-writable *and* other-writable | rejected |
| root-owned, group-writable by a group other than `admin` | rejected |
| the same accepted case, on Linux | rejected |

### Shell-level, on the post-install script

`packaging/postinstall-check.sh` runs the real script against a fake bundle in a throwaway
`HOME` and asserts the non-root branch: the daemon is invoked as
`install --user --skip-security-warning`, both symlinks point into the bundle, appending
twice leaves one `PATH` block, a reinstall re-registers, and a registration that exits
non-zero is reported without failing the install (4.8). The root branch is out of its
reach — `launchctl asuser` needs root and a console user — and is covered by the
install-time shapes above.

A throwaway `HOME` is not sufficient isolation. `ensure_path_entry` resolves the startup
file from the *invoking account's* directory-service record, which no environment
variable redirects, so the harness puts a fake `dscl` first on `PATH` and pins the answer
per scenario. Without it the result follows whoever ran it: a zsh login shell writes
`.zprofile` and passes, a bash one writes `.bash_profile`, and fish or tcsh write nothing
at all. Pinning it also makes the three outcomes assertable rather than incidental — zsh,
bash, and an unsupported shell that must report and write no file.

### Not covered by test

The Data Protection keychain path, which needs a signed bundle with an embedded
provisioning profile and a login session. An install test asserts placement and
`PATH` resolution, not the posture from Requirement 7.

## File changes

| File | Change |
|---|---|
| `packaging/assemble-app.sh` | Build `Credsd.app` with the daemon at `Contents/MacOS/credsd`, the client at `Contents/Resources/creds`, and `LICENSE`, `NOTICE` and `THIRD-PARTY-LICENSES.md` beside the client, read from the repository root above the script (2.8). |
| `packaging/Credsd.app.Info.plist.in` | `CFBundleName` is the bundle name, not the executable name. |
| `packaging/build-dist-pkg.sh` | Payload is the bundle alone at install location `Applications`; component property list marking it non-relocatable; bundle mode; distribution script with both install destinations, the license pane taken from the staged bundle's own `LICENSE` (2.9) and the conclusion pane; the artifact checks. |
| `packaging/dist-scripts/postinstall` | `PATH` access — two symlinks into `/usr/local/bin` as root or `~/.local/bin` otherwise, plus a marked startup-file block when `~/.local/bin` is not already on `PATH` — then `credsd install --user --skip-security-warning`, run directly when not root and through `launchctl asuser <console_uid> sudo -H -u <console_user>` when root. Skipped with a note when there is no console user. Non-fatal throughout except bundle verification. |
| `packaging/postinstall-check.sh` | New. Runs the post-install script against a fake bundle in a throwaway `HOME` and asserts the non-root branch. |
| `crates/credsd-core/src/storage/` | `legacy-keychain` removed. `file` compiled on macOS only under the `file` feature. `Backend::COMPILED` lists what the binary was built with (7.6). |
| `crates/credsd-daemon/src/main.rs` | `credsd --version` prints the `storage backends:` line the artifact checks read (8.8). |
| `.github/workflows/build.yml`, `scripts/install.sh` | The macOS release build passes `--no-default-features` for the daemon alone, so the published daemon drops `secure-enclave` while the client keeps it; CI tests `secure-enclave,file` without building either into the release binary, and asserts the release binary's backend line. |
| `crates/credsd-daemon/src/install.rs` | Ancestor trust check accepts a root-owned, non-other-writable, `admin`-group-writable ancestor on macOS only; unit tests for each row of the table above. |
