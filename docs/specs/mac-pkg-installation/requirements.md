# Requirements: macOS `.pkg` Installation

**Status:** draft (implemented on this branch — approval means "accept this behavior")
**Feature:** `mac-pkg-installation`
**Scope:** macOS only. The distribution `.pkg` and nothing it delegates: where it
places the application bundle and client binary, how it makes both commands
reachable from a new terminal, and the boundary between that and starting the
service.

## Introduction

credsd reaches macOS customers as a signed distribution `.pkg` carrying an
application bundle, `Credsd.app`, with the client binary `creds` inside it. The daemon
executes from inside the bundle, because its code signature and embedded
provisioning profile are what authorize the `keychain-access-groups` entitlement,
and that entitlement is how the Data Protection keychain gates key access on
application identity rather than on uid alone. A daemon copied out of its bundle
cannot reach that keychain.

The `.pkg` has three responsibilities and no others:

1. Place the bundle and the client in a location the customer chose.
2. Make `credsd` and `creds` reachable from a terminal opened after the install.
3. Register the user-scoped launchd service for the account installing.

The third is bounded by what a user-scoped service is. Its LaunchAgent, socket, data
directory and keychain item belong to one uid, so an install registers it for one
account — the one in front of the machine — and for no one else. On a shared install,
every further account runs `credsd install --user` once itself. With no account logged
in, there is no session to register into, and the install places files only.

Registering for the console user from a root-run script means re-entering that
account's login session rather than merely assuming its uid, because two steps need the
session itself: `launchctl load` needs the `gui/<uid>` domain, and minting the master key
needs an unlocked Data Protection keybag. That is the same absence that makes a system
install unable to reach that keychain at all (Requirement 7).

Two costs are accepted rather than avoided. The installer resolves the console user and
executes as another account, so what an install changed can no longer be read off the
script without following a `launchctl asuser` hand-off. And the interactive security
prompt that `credsd install --user` normally carries cannot be answered by a script, so
registration suppresses it and the final installer pane states the posture instead.

Credentials still require `creds bootstrap`, an interactive SSO login no installer can
perform, so a terminal session remains necessary before credsd is usable. What the
install removes is the step before that one.

### Terminology

- **Install destination** — an installer-declared root that a payload's relative install
  location resolves against. `LocalSystem` resolves against the target volume;
  `CurrentUserHomeDirectory` resolves against the invoking customer's home.
- **Shared install** — an install into the `LocalSystem` destination. The bundle and the
  `PATH` entries are visible to every account.
- **Private install** — an install into the `CurrentUserHomeDirectory` destination. The
  bundle and the `PATH` entry belong to one account.
- **PATH access** — a symlink in a `bin` directory on `PATH`, pointing at an executable
  inside the bundle. A private install may also add its `bin` directory to `PATH` through a
  marked block in a shell startup file.
- **Domain** — reserved here for the launchd sense: `system/<label>` and
  `gui/<uid>/<label>`. Apple uses the word for both concepts — the Distribution element is
  `<domains>` and the flag is `installer -dominfo` — so this spec says *install destination*
  for the installer one, and *domain* only for launchd.
- **Relocation** — the installer behavior of redirecting a bundle payload to
  wherever an existing bundle with the same `CFBundleIdentifier` resides, in place
  of the declared install location.

## User Experience

Every interaction a customer has with this feature.

`PATH` access works the same way in both install shapes: one symlink per command, in a single
`bin` directory, pointing into the installed bundle. Only the directory differs —
`/usr/local/bin` for a shared install, `~/.local/bin` for a private one, because the latter
holds no root and every directory on the default `PATH` is root-owned. `~/.local/bin` is not
on the default `PATH`, so a private install also adds it when it is missing. Requirement 5 is
normative; UX-1 and UX-2 below show each case.

### UX-1. Graphical install, shared

The customer double-clicks `credsd.pkg`. Installer.app presents a **License** pane
carrying the Apache-2.0 text, which the customer agrees to. Because two destinations
are enabled, it then presents a **Destination Select** pane offering "Install for all
users of this computer" and "Install for me only". The customer picks the former
and is asked for an administrator password.

Installed:

```
/Applications/Credsd.app                                readable by every account
/Applications/Credsd.app/Contents/MacOS/credsd          the daemon
/Applications/Credsd.app/Contents/Resources/creds       the client
/Applications/Credsd.app/Contents/Resources/LICENSE     the project license
/Applications/Credsd.app/Contents/Resources/NOTICE      the attribution notice
/Applications/Credsd.app/Contents/Resources/THIRD-PARTY-LICENSES.md
/usr/local/bin/credsd -> …/Credsd.app/Contents/MacOS/credsd
/usr/local/bin/creds  -> …/Credsd.app/Contents/Resources/creds
```

The service is registered and running for the installing account. A final pane states
that, states the user-scoped posture it has, and names `creds bootstrap` as the
remaining step.

### UX-2. Graphical install, private

Same double-click, "Install for me only". No administrator password is requested.

```
~/Applications/Credsd.app
~/.local/bin/credsd -> ~/Applications/Credsd.app/Contents/MacOS/credsd
~/.local/bin/creds  -> ~/Applications/Credsd.app/Contents/Resources/creds
```

Same two symlinks as the shared install, in the per-user directory. `~/.local/bin` is not on
the default `PATH`, so when it is missing the install also appends a marked, idempotent block:

```sh
# Added by credsd
export PATH="$HOME/.local/bin:$PATH"
```

The block names the `bin` directory rather than a path inside the bundle, so moving or
reinstalling `Credsd.app` leaves it valid.

### UX-3. Command-line install, shared

```console
$ sudo installer -pkg credsd.pkg -target /
installer: Package name is credsd
installer: Installing at base path /
installer: The install was successful.
```

### UX-4. Command-line install, private

No `sudo`:

```console
$ installer -pkg credsd.pkg -target CurrentUserHomeDirectory
installer: Package name is credsd
installer: Installing at base path /Users/alice
installer: The install was successful.
```

`-target` is required. There is no default and no fallback; omitting it is a usage
error, not a private install.

### UX-5. After the install

The service is already registered and running for the installing account. In a terminal
opened after the install, both commands resolve by name, and the one remaining step is
the credential setup:

```console
$ creds bootstrap
```

WHEN no account was logged in at the screen, the install placed files and registered
nothing. `/var/log/install.log` carries the line, and the account that wants the service
runs UX-7.

### UX-6. Verifying

```console
$ credsd status
installed: true
running:   true
binary:    /Applications/Credsd.app/Contents/MacOS/credsd
args:      --log-file /Users/alice/Library/Application Support/credsd/credsd.log serve
```

`binary:` names the path inside the bundle, not the symlink it was invoked through,
because the service definition must name the signed bundle for the entitlement to
apply.

### UX-7. A second account on a shared install

Bob logs into the same Mac, where Alice ran UX-1 or UX-3. The bundle and the
symlinks are already in place and already on his `PATH`, but the service Alice's
install registered is hers: its agent, socket, data directory and key are all under
her uid. Bob registers his own, once, with no administrator password and no second
install:

```console
$ credsd install --user
<user-install security warning>
Type 'yes' to continue: yes
credsd user service installed. It will start on login.
```

He gets the typed confirmation Alice did not, because he has a terminal.

### UX-8. Finding and removing what the install added

```console
$ ls -l /usr/local/bin/{creds,credsd}                  # shared install
$ ls -l ~/.local/bin/{creds,credsd}                    # private install
$ grep -n 'Added by credsd' ~/.zprofile                # private install, if PATH was added
```

A shared install's additions are two symlinks. A private install's addition is one
marked block. Both are removable by hand, and both are what an uninstall removes.

### UX-9. When a command does not resolve

A command already on `PATH` ahead of the install's entry wins. The install reports
this rather than leaving the customer to discover it:

```
!  PATH resolves creds to /Users/alice/dev/credsd/target/release/creds,
!  which shadows /usr/local/bin/creds
```

### Requirement-to-UX map

| UX | Requirements exercised |
|---|---|
| UX-1, UX-3 | 1, 2, 3, 4, 5, 6, 7 |
| UX-2, UX-4 | 1, 2, 3, 4, 5, 6, 7 |
| UX-5, UX-7 | 4, 6, 7 |
| UX-6 | 6 |
| UX-8 | 5 |
| UX-9 | 5 |

## Requirements

### Requirement 1: Install destinations and bundle location

**User story:** As a macOS customer, I want to choose whether credsd is installed
for everyone on the machine or only for me, so that the install matches whether the
machine is shared.

#### Acceptance Criteria

1.1. The `.pkg` SHALL enable exactly two install destinations: `LocalSystem` and
     `CurrentUserHomeDirectory`.

1.2. The `.pkg` SHALL NOT enable an arbitrary-volume destination. An `Applications`
     directory on a volume that is neither a system root nor a home directory names
     no meaningful location.

1.3. WHEN installed with `installer -pkg credsd.pkg -target /` THEN the system
     SHALL place the bundle at `/Applications/Credsd.app`.

1.4. WHEN installed with
     `installer -pkg credsd.pkg -target CurrentUserHomeDirectory` THEN the system
     SHALL place the bundle at `~/Applications/Credsd.app`.

1.5. A private install SHALL NOT require root.

1.6. The declared install location SHALL be relative, so that one payload serves
     both destinations without a separate component package for each.

1.7. The `.pkg` SHALL pin its host architectures to exactly those the binaries it
     carries were built for, which for the released artifact is `arm64` alone. A host
     the installer accepts but the binaries do not target installs cleanly and then
     cannot execute them, which reaches the customer as a successful install whose
     service never runs.
     (ADDED 2026-11-10, with 8.10: the declaration was `arm64,x86_64` while both
     binaries were arm64-only.)

### Requirement 2: Payload layout and reachability

**User story:** As a customer of a shared install, I want the daemon the installer
placed to be executable by my account, so that I can register and run the service.

#### Acceptance Criteria

2.1. The payload SHALL be the application bundle alone. Both executables live inside
     it: the daemon at `Contents/MacOS/credsd`, the client at
     `Contents/Resources/creds`.

2.2. The bundle SHALL NOT contain a directory whose purpose is to be placed on
     `PATH`. `PATH` access is by symlink into a directory already on it
     (Requirement 5), so the bundle holds executables and nothing arranged for the
     shell's benefit.

2.3. Rationale for 2.1 and 2.2, normative: an application's own executables belong
     inside its bundle, which is where macOS software of this shape puts them and
     where a `/usr/local/bin` or `~/.local/bin` symlink conventionally resolves to.
     Putting a `bin` directory inside the bundle for the shell to find would make the
     two install shapes use different mechanisms for the same job.

2.4. The payload SHALL NOT copy either executable into a directory on the default
     `PATH`. `PATH` access is by reference (Requirement 5), so a single installed
     copy remains the only copy and an uninstall cannot leave a stale binary behind.

2.5. The bundle directory SHALL be traversable and readable by all local accounts
     (mode `0755`).

2.6. Rationale for 2.5, normative: a shared install writes the bundle as
     `root`-owned. A root-owned bundle excluding other accounts is unreachable by
     the accounts Requirement 4 expects to run `credsd install --user`, so the
     daemon cannot be executed even though it is present. A private install does not
     exhibit this, because there the bundle belongs to the installing customer.

2.7. The payload root maps to the `Applications` directory, which exists on every
     macOS install, so the recorded root mode SHALL NOT be relied on: the installer
     applies it only to a directory it creates. 2.5 constrains the bundle's own mode
     for that reason.

2.8. The bundle SHALL carry `LICENSE`, `NOTICE` and `THIRD-PARTY-LICENSES.md` in
     `Contents/Resources`, read from the same commit as the binaries beside them.
     Apache-2.0 §4 requires a redistributed copy to carry the license and the
     `NOTICE` file, and the dependencies' licenses require their text and copyright
     notices to travel with the binaries — so the files have to be inside the one
     thing the installer places, not alongside the download.
     (ADDED 2026-11-09, with 8.9.)

2.9. The `.pkg` SHALL present the `LICENSE` text on the installer's license pane,
     from the copy 2.8 places in the bundle rather than from a second source.
     (ADDED 2026-11-09.)

### Requirement 3: The declared install location is authoritative

**User story:** As a customer who has installed credsd before, I want a reinstall to
land where the installer says it will, so that the `PATH` entries and the bundle do
not disagree about where the commands are.

#### Acceptance Criteria

3.1. The application bundle SHALL be marked non-relocatable.

3.2. The system SHALL place the bundle at the declared install location
     irrespective of the location of any previously installed bundle carrying the
     same `CFBundleIdentifier`.

3.3. Rationale for 3.1, normative: the `PATH` references in Requirement 5 are
     derived from the install destination. A relocated bundle is therefore written
     to one path and referenced at another, and the symlink or startup-file entry
     points at a path holding no binary.

### Requirement 4: The installer places files and registers one account's service

**User story:** As a customer, I want the install to leave credsd running for my
account, so that the only thing left to do is the credential setup no installer could
have performed for me.

(AMENDED 2026-10-30: 4.1–4.4 and 4.8–4.9 previously bounded the installer to placing
files, with registration left to the customer in a terminal. All `.pkg` installs are
now confined to the user-scoped install — the released daemon compiles only the backend
that scope can use (7.6) — so the command the conclusion pane named was the only one
available, and the install performs it. The consent cost this gives up is stated in 4.10
rather than elided.)

#### Acceptance Criteria

4.1. A `.pkg` install SHALL place the payload (Requirement 2), establish `PATH`
     access (Requirement 5), register the user-scoped service for exactly one account
     (4.3), and SHALL make no other change to the system.

4.2. A `.pkg` install SHALL NOT write a launchd service definition anywhere other than
     the `~/Library/LaunchAgents` of the single account named in 4.3.

4.3. The account a `.pkg` install registers the service for SHALL be the account
     running the install when that is not root, and the console user otherwise. A `.pkg`
     install SHALL NOT register the service for more than one account, SHALL NOT
     register it for an account with no active login session, and SHALL NOT register it
     for a system or setup account that owns the console without being a customer —
     `root`, `loginwindow`, and `_mbsetupuser`.
     (ADDED 2026-10-30: `_mbsetupuser` owns `/dev/console` for the whole of Setup
     Assistant, which is the window Automated Device Enrollment installs in, so the
     uid-0 test alone admitted it. Registering there puts the agent and the master key
     in an account that is about to stop existing, and the customer created afterwards
     gets nothing.)

4.4. WHEN the install is running as root THEN registration SHALL execute inside the
     console user's login session, not merely under its uid, and SHALL supply that
     account's home directory to the invocation.

4.5. A `.pkg` install SHALL NOT copy the daemon out of its bundle.

4.6. A `.pkg` install SHALL NOT write a plist to `/Library/LaunchAgents`. That location
     serves software an administrator installs once for every login session, and its use
     would mean one registration configuring every account — which the user-scoped posture
     in 4.1 rules out. It is also not expressible for this service: a single shared plist
     holds one literal socket path, so every account's daemon would be directed at the same
     socket. On macOS 13 and later `SMAppService` supersedes the location entirely. Managed
     fleet deployment is unspecified, and is where this would be revisited.

4.7. A `.pkg` install SHALL succeed with no account logged in at the screen, so
     that an unattended or pre-login deployment places files rather than failing. In that
     case registration is skipped, and 5.9 governs the report.

4.8. Registration failure SHALL NOT be fatal. WHEN registration is skipped or fails
     THEN the install SHALL report the reason and name `credsd install --user`, and SHALL
     still report success, because the bundle is placed and both commands are on `PATH`.

4.9. The installer SHALL state, in a pane shown at the end of a successful install,
     that the service is running, that its posture is user-scoped with secrets in the
     installing account's home, that `creds bootstrap` remains, and that any other account
     on a shared install registers its own service with `credsd install --user`.

4.10. Rationale for 4.1 and 4.9, normative: `credsd install --user` carries an
      interactive security warning read from `/dev/tty`, written that way so a script
      cannot answer it. An installer-run script has no terminal, so registering from the
      installer requires suppressing that prompt. This is a real reduction in the consent
      surface — a pane read after the fact in place of a typed `yes` before the act — and
      is accepted because the `.pkg` offers no other install scope (7.6), so the posture
      the prompt warns about is the only posture this artifact can produce. The pane in
      4.9 SHALL therefore carry the substance of the warning and not only the outcome.
      Any future `.pkg` offering a second scope reinstates the prompt.

4.11. Rationale for 4.3 and 4.4, normative: a user-scoped service is per-uid in every
      component — agent, socket, data directory, keychain item — so there is no "register
      for everyone". Two of the steps need the target account's session rather than its
      uid: `launchctl load` resolves against `gui/<uid>`, and the master-key mint needs an
      unlocked Data Protection keybag. Assuming the uid alone (`sudo -u`) satisfies
      neither, and is the failure that reads as a successful install.

### Requirement 5: PATH access

**User story:** As a customer, I want `credsd` and `creds` to work by name in the
next terminal I open, so that using credsd does not mean typing a path into a
bundle.

#### Acceptance Criteria

5.1. After a successful install, both `credsd` and `creds` SHALL resolve by name in
     a login shell started afterwards.

5.2. The system SHALL establish `PATH` access by creating one symlink per command in
     a single `bin` directory, pointing at the executables inside the installed
     bundle. This is the only mechanism, in both install shapes.

5.3. The `bin` directory SHALL be `/usr/local/bin` for a shared install and
     `~/.local/bin` for a private install, created if absent.

5.4. Rationale for 5.3, normative: `/usr/local/bin` is on the default `PATH` and
     root-owned, and Requirement 1.5 forbids a private install from requiring root.
     `~/.local/bin` is the conventional per-user equivalent, and is where comparable
     software symlinks a CLI that lives inside an application bundle.

5.5. `/usr/local/bin` is on the default `PATH`; `~/.local/bin` is not. WHEN a private
     install's `bin` directory is absent from `PATH` THEN the system SHALL add it by
     appending a marked block to the invoking customer's shell startup file. The
     block SHALL name the `bin` directory and not a path inside the bundle, so it
     survives the bundle being moved or reinstalled elsewhere.

5.6. The block in 5.5 SHALL carry a fixed marker comment identifying credsd as its
     author, SHALL be idempotent across repeated installs, and SHALL be removable
     without disturbing the rest of the file.

5.7. The system SHALL NOT append the block in 5.5 when the `bin` directory is
     already on `PATH` or a shell startup file already adds it. Detection is best
     effort: `PATH` may be set by a file the installer cannot find, in which case a
     redundant but harmless entry results.

5.8. Every change SHALL be reversible, and what was added SHALL be discoverable by
     inspection (UX-8).

5.9. Establishing `PATH` access SHALL NOT be fatal when it fails for infrastructure
     reasons (cannot create the `bin` directory, cannot write the shell RC file, a
     conflicting entry already exists). WHEN such a failure occurs THEN the install
     SHALL report what was skipped and the path to invoke directly, and SHALL still
     report success, because the bundle is placed and usable.

5.12. Bundle integrity failure is not a PATH infrastructure failure and is not
      covered by 5.9. WHEN bundle verification fails THEN the installer SHALL exit
      non-zero and report the failure, because linking a suspect bundle into `PATH`
      is worse than not linking at all — the user expects a working install, not a
      silent partial one.

5.10. WHEN a command of the same name already resolves ahead of the install's entry
      THEN the system SHALL report the shadowing path (UX-9).

5.11. The system SHALL NOT replace an entry of the same name that does not already
      point into a credsd install location.

### Requirement 6: An installed bundle is usable by `credsd install --user`

**User story:** As a customer who installed for all users, I want the registration the
installer performs — and the same command run later by another account — to work, so
that the location the installer chose is not one the daemon refuses.

#### Acceptance Criteria

6.1. A bundle placed by this installer, at either destination, SHALL be an acceptable
     daemon path to `credsd install --user`, both as the installer invokes it (4.1) and
     as any other account that can read it invokes it later.

6.2. Before writing a per-user service definition, the system SHALL verify every
     ancestor of the daemon path, and SHALL reject an ancestor that is
     other-writable or owned by neither root nor the account served.

6.3. On macOS the system SHALL accept a root-owned ancestor that is group-writable
     by group `admin` and is not other-writable.

6.4. The exception in 6.3 SHALL be gated to macOS. On Linux every group-writable
     ancestor SHALL remain rejected, because `admin` names no group there and the
     platform offers no equivalent.

6.5. The exception in 6.3 SHALL admit a group-writable *directory* only. A
     group-writable ancestor that is not a directory SHALL be rejected, including
     one owned by root: a binary any member of the group may overwrite in place is
     the case the check exists to refuse.

6.6. Rationale for 6.3, normative: `/Applications` is `root:admin` mode `0775`, it
     is the location macOS treats as standard for applications, and it is not a
     directory credsd may re-permission. A rule forbidding all group-write rejects
     every shared install while rejecting nothing an attacker needs, because an
     account able to write `/Applications` can already replace any other
     application there and obtain code execution when the customer next launches
     one. The exception narrows the gap from "possible" to "automatic at login",
     not from "impossible" to "possible".

6.7. credsd's installed bundle SHALL remain tighter than the surrounding directory
     permits. A `.pkg`-installed bundle is `root:wheel 0755`, so the accepted
     group-writable ancestor is the system directory alone.

### Requirement 7: Posture of the service the customer registers

**User story:** As a security reviewer, I want to know what posture the documented
next step produces, so that the installer's recommendation is not a recommendation
to run something unprotected.

#### Acceptance Criteria

7.1. The install the installer performs in 4.1, and the command it names in 4.9, SHALL
     both be the user-scoped install, and its posture SHALL be read from the user rows of
     the matrix below.

7.2. A user-scoped install SHALL resolve only to the `data-protection-keychain` backend,
     the one user row of the matrix below that gates same-uid access.
     (AMENDED 2026-10-05: previously forbade only `file`. `presence-gated-operations`
     Requirements 7.2, 7.3 and 7.6 now confine a user-scoped install to the official signed
     build and that backend, because every other user row leaves daemon-owned storage writable
     by the customer's own uid. The other user rows below record why each is refused.)

7.3. A user-scoped install SHALL NOT resolve a backend by silent fallback. WHEN no
     backend meeting 7.2 is available THEN the system SHALL fail with the reason.

7.4. A user-scoped install SHALL record the resolved backend and its posture in the
     install log.

#### Posture matrix — normative

| Scope | Backend | Same-uid access to the master key |
|---|---|---|
| system | `file` | Gated: the key is owned by the service account, not the requesting customer. Absent from the official build (7.6). |
| system | `secure-enclave` | Gated by file ownership on the wrapped blob. Hardware binding prevents use on another machine; it does not bind the blob to the calling code's identity. |
| system | `data-protection-keychain` | Unavailable: same absent login session. |
| user | `file` | Ungated: the key is a file readable by the customer's own uid. Refused (7.2). Absent from the official build (7.6). |
| user | `secure-enclave` | Ungated: any process as that uid may request an unwrap. Refused (7.2). |
| user | `data-protection-keychain` | Gated by application identity: only a binary carrying the authorizing signature and entitlement may read the item. |

7.5. The bundle exists to make the final row reachable. A change that stops the
     daemon executing from inside the signed bundle forfeits that row and SHALL be
     treated as a posture regression. This is why the service definition names the
     in-bundle path and not the `/usr/local/bin` symlink (UX-6).

7.6. The official release build SHALL compile exactly one storage backend into the daemon,
     `data-protection-keychain`, which is the keystore of the one install scope this artifact
     supports. The `file` backend SHALL be compiled on macOS only into a build that opts in to
     it, which exists for Macs without a Secure Enclave (virtual machines, Intel Macs without
     a T2 chip). The `legacy-keychain` backend SHALL NOT exist in any build.
     (ADDED 2026-10-07: `legacy-keychain` items are readable and replaceable by any process
     running as the uid, which is how a pre-planted master key is adopted; it was reachable
     only from a user-scoped install, which 7.2 already refuses, so it is removed rather than
     gated. `file` leaves the official build so that neither scope has a software-only
     backend to fall to. Linux keeps `file` unconditionally, having no guarantee of
     hardware-backed storage.)
     (AMENDED 2026-10-27: `secure-enclave` leaves the released daemon too. It was there for a
     system install from this artifact, which is not a supported path and cannot be made one:
     the daemon a system install runs has no login session, so it can never reach the keychain
     this bundle's provisioning profile exists to authorize. While the enclave was compiled
     in, `sudo credsd install` from the released artifact resolved a backend and installed a
     LaunchDaemon — observed on a real machine. Subtracting the backend makes that invocation
     refuse on its own, with no runtime artifact detection to maintain. A system service is
     what a build from source installs; see `secure-enclave-encryption-backend` Requirement
     9.4. The released *client* keeps the feature, which is what signs a presence challenge
     with Touch ID.)

7.7. A user-scoped install SHALL be refused when this process is root, naming the account the
     service runs as. Under `sudo` the resolved home is root's, so the service definition would
     land in a home directory no one logs into.
     (ADDED 2026-10-27: `sudo credsd install --user` was accepted — the user-scoped branch
     returned before the root check that follows it — and wrote a LaunchAgent into
     `/var/root/Library/LaunchAgents`.)

### Requirement 8: Verifiable properties of the built artifact

**User story:** As a release engineer, I want the packaging invariants checked when
the `.pkg` is built, so that a regression is caught before a customer installs it.

#### Acceptance Criteria

8.1. The build SHALL fail when the payload does not contain the bundle with the daemon
     at `Contents/MacOS/credsd` and the client at `Contents/Resources/creds`.

8.2. The build SHALL fail when the bundle contains a `Contents/Resources/bin`
     directory, which would mean Requirement 2.2 had been reverted.

8.3. The build SHALL fail when the built package marks the bundle relocatable.

8.4. The build SHALL fail when the bundle directory is not mode `0755` (2.5).

8.5. The build SHALL fail when either destination named in 1.1 is absent from the
     built package's enabled destinations.

8.6. The build SHALL fail when the package's scripts do not register the user-scoped
     service, do not enter the console user's session to do it, or reference
     `/Library/LaunchAgents` or `/Library/LaunchDaemons`.
     (AMENDED 2026-10-30, with Requirement 4: the check previously asserted the absence
     of `launchctl`, `credsd install` and `/dev/console`. Those are now how 4.3 and 4.4
     are satisfied, so the check asserts their presence and keeps only the one location
     constraint 4.6 still forbids.)

8.7. Each check in 8.1–8.6 and 8.8–8.10 SHALL read the built package rather than the inputs
     that produced it, so that a tool ignoring its configuration is still caught.

8.8. The build SHALL fail when the packaged daemon does not report exactly the backends
     7.6 names for the official build.
     (ADDED 2026-10-07, with 7.6.)

8.9. The build SHALL fail when the payload is missing any of the three files 2.8 names,
     and when the built package declares no license pane or carries no text for it.
     A signed bundle supplied to the build already assembled is checked the same way,
     so one built before 2.8 cannot be packaged.
     (ADDED 2026-11-09, with 2.8 and 2.9.)

8.10. The build SHALL fail when the host architectures the package declares are not
      exactly those of the packaged binaries (1.7), or when the two binaries do not
      agree with each other. The declaration is checked against the binaries rather
      than against a literal, so widening it for a universal build needs no new check.
      (ADDED 2026-11-10, with 1.7.)

## Dependencies

The only user-scope row in Requirement 7's matrix that gates same-uid access is
`data-protection-keychain`, the Data Protection keychain. That backend is specified separately;
this feature does not define it and defines no behavior conditional on its
internals.

Signing and notarization of the `.pkg` and the bundle are a separate concern. An
unsigned bundle carries no provisioning profile and cannot satisfy the
`data-protection-keychain` row regardless of which backend is selected.

This spec covers the official release build. A `credsd install --user` from an
open-source build is the insecure posture of `presence-gated-operations`
Requirement 7.8 — permitted under an acknowledged warning, and outside every row of
Requirement 7's matrix that this installer is allowed to produce.

## Out of scope

- Registering the service from inside `Credsd.app` via `SMAppService`, which would
  make the application rather than the customer the registering party. See the
  design's platform considerations.
- Migration from a service definition installed under a previous label.
- Uninstall sequencing. Requirement 5.6 constrains what uninstall must be able to
  remove; the order and the command are specified elsewhere.
- First-run credential bootstrap beyond naming it as a required step.
- Linux and Windows packaging.
