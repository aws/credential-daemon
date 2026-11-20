# TPM-Enabled Linux Artifact — Design Record

Why the TPM backend ships as its own Linux artifact rather than as the default build, what
the system library floor costs, and which properties the release gates assert.
**Audience: maintainers and release engineers.**

For what the TPM backend protects and what it does not, see
[`docs/design/key-storage-backends.md`](key-storage-backends.md). That document owns the
security posture; this one owns the build and release shape.

## Scope

How a `credsd` binary that can reach a TPM 2.0 device gets built, named, tested and
published, and how the default Linux binaries stay runnable on hosts with no tpm2-tss
installation.

Out of scope: the seal and unseal protocol, the policy model, and recovery — all in
`docs/specs/tpm-encryption-backend/`. Also out of scope: the install-time grant of
`/dev/tpmrm0` access, which `crates/credsd-daemon/src/install.rs` already renders as
`SupplementaryGroups=tss` on the systemd unit.

## The constraint

`credsd-core`'s `tpm` feature pulls `tss-esapi` 7.7.0, which sits on `tss-esapi-sys` 0.6.0.
That build script probes four system libraries through pkg-config — `tss2-sys`,
`tss2-esys`, `tss2-tctildr`, `tss2-mu` — each at version 2.4.6 or later, and panics if any
is absent. At run time `tctildr` additionally dlopens a TCTI module
(`libtss2-tcti-device`) when a context opens.

So the feature is not a compile-time switch with a graceful runtime fallback. A binary
built with it does not start on a host without tpm2-tss, which is what makes a separate
artifact the only shape that serves both populations from one release.

The sys crate carries pregenerated bindings for `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `arm-unknown-linux-gnueabi` and `x86_64-unknown-darwin`, and
reaches for bindgen only under its `generate-bindings` feature. Both shipped Linux
architectures therefore build with no libclang and no header generation; only the
pkg-config `.pc` files and the shared libraries have to be present. `tss-esapi` 7.7.0 is
pinned in `Cargo.lock`, so every build stays `--locked`.

That last property is what makes a manylinux2014 build possible at all. The image has no
working package manager — `vault.centos.org` serves 403 for CentOS 7 — so
`scripts/manylinux-toolchain.sh` builds tpm2-tss 4.0.2 from a checksummed tarball into
`/opt/tss` purely to satisfy the pkg-config probe and the link. None of it is shipped: the
binary's `DT_NEEDED` names the four `libtss2` sonames and the host supplies them, which the
`assert build-host independence` step checks by refusing any `RUNPATH`.

Every input to that build is pinned by content, not by name: the two tarballs by `sha256sum
-c`, which aborts the script, and the manylinux2014 images by digest rather than their
floating `latest` tag. A `-tpm` row fetches and compiles its own tpm2-tss on every run, so
without those pins the bytes the daemon links against could change under a build that looks
identical.

4.0.2 is the version AL2023 packages, so the link-time ABI is the one the pregenerated
bindings were generated against. Dropping to the crate's 2.4.6 floor would widen the set of
hosts whose tpm2-tss can satisfy the link, but it would put those fixed bindings two major
versions from the headers they came from — a struct-layout mismatch, which fails at run time
rather than at link time. Do not lower the pin without enabling `generate-bindings`.

Building tpm2-tss ourselves also needs OpenSSL, and 1.1.1w rather than 3.x: OpenSSL 3's
`Configure` requires the `IPC::Cmd` perl module, which the image lacks and yum cannot
supply. It clears tpm2-tss's `libcrypto >= 1.1.0` floor and, like tpm2-tss itself, is
never linked into a shipped binary — so its EOL status is a build-image reporting matter,
not an exposure.

## Shape

A TPM-enabled build is a **platform**, not a differently named binary. Every artifact path
in the release system is keyed by a platform segment — `builds/<commit>/<platform>/`,
`develop/<platform>/`, `tested/<commit>/<platform>/`, one integration lane per platform —
so a new platform needs no change to the key layout.

A TPM platform is an existing platform name with a `-tpm` suffix: `linux-x64-tpm` and
`linux-aarch64-tpm`. Each carries the same `{creds, credsd}` pair as every other
platform: a `credsd` linked against tpm2-tss, and a `creds` that is not.

`.github/workflows/release.yml` needs no knowledge of any of this. It derives the platform
from the artifact directory name, loops the two binaries by name, and builds the manifest
by `jq -s … platforms: add` over whatever digest blobs the matrix produced. The
manifest-versus-prefix cross-check compares two sorted lists, with no platform list of its
own.

## Decisions

### 1. A platform segment, not a binary named `credsd-tpm`

Naming the binary carries the capability into a namespace that is not keyed by it.
`release.yml`'s upload loop iterates the fixed pair `creds credsd` under a platform
directory, and the integration harness derives the client key as the daemon key's sibling
under the same prefix. A third binary name breaks both. A fifth platform breaks neither.

### 2. The suffix marks the TPM build, not the absence of one

The default Linux artifacts keep their names. Inverting it — shipping the TPM build as
`linux-x64` and a `-notpm` variant beside it — makes the obvious download the one that
fails to start on any host without tpm2-tss, and silently reassigns the meaning of a
platform name that existing consumers already pull.

### 3. The daemon and the client are built in separate cargo invocations

`crates/credsd/Cargo.toml` depends on `credsd-core` directly, so a single workspace build
with the feature enabled resolves one `credsd-core` for every member and hands the client
the tpm-enabled rlib. Two invocations give the two binaries two feature resolutions:

```
cargo build --release --locked -p credsd-daemon --features tpm
cargo build --release --locked -p creds
```

The second invocation rebuilds `credsd-core` without `tpm` and leaves
`target/release/credsd` in place, so both binaries survive in one `target/release`. The
cost is compiling `credsd-core` and its dependents twice on these rows.

For the client this has to resolve `credsd-core` to the same feature set the base row's
workspace build does, or the published `-tpm/creds` stops being the same bytes as
`<platform>/creds` — which the integration lane asserts before promoting, since it runs
only one of the two. That is why `credsd-core` declares no `default` feature: a library's
`default` is active when the library is in the build selection and absent when it is
reached only through dependents that set `default-features = false`, and the two sets are
different `-C metadata` inputs even when they activate identical code.

Whether a unified build would in fact leave `libtss2` in the client's `DT_NEEDED` depends
on `--as-needed` and on unused-object elimination, and may vary by toolchain and distro.
The separate invocations make the question moot; decision 7 makes the answer observable
either way.

### 4. One portable pair per architecture, not one pair per distro

**Superseded the per-distro set.** This decision previously read "every distro and
architecture the default matrix ships, except AL2", and the matrix carried `al2023-x64`,
`al2023-aarch64`, `ubuntu-x64`, `ubuntu-aarch64` and a `-tpm` sibling for each. It now
carries `linux-x64`, `linux-aarch64` and their two `-tpm` siblings, and nothing
else on Linux at all.

The per-distro set existed because a binary's glibc floor is whatever its build host
happens to supply. Building on manylinux2014 sets that floor at 2.17 deliberately, which is
below every distro the old rows targeted — below AL2's 2.26, and far below the 2.34 an
AL2023 build linked. One binary therefore reaches every host the eight artifacts reached.

The old rationale for mirroring was that "a platform name means the same thing with and
without the suffix, and the `tpm` feature gets compiled under both toolchains rather than
one." The first half still holds: `linux-aarch64-tpm` sits beside `linux-aarch64`.
The second half is the cost of this change and is accepted — the `tpm` feature is now
compiled under one toolchain, against a pinned tpm2-tss 4.0.2 built from source rather than
against two distro packages. What the distro packages were really covering was runtime
ABI compatibility, and the integration lanes still cover that: each lane installs its own
distro's tpm2-tss and loads our binary against it.

Every shipped platform has an integration lane, because a platform without one cannot be
released at all. Promotion reads `tested/<commit>/<platform>/` for every platform in its
list, and only a lane's graduation step writes that prefix — so an ungated platform either
aborts the release or is left out of the list and never reaches a customer. The artifact set
and the lane set are one decision. The lanes live in the separate distribution repository,
which has since settled the naming as `linux-*`: each lane names the artifact platform it
verifies, and the four distro-flavoured names are kept beside it as aliases for the
duration of the cutover, so a commit under either naming runs its lanes. Two lanes now
gate each portable platform, which is why graduation requires a witness per lane rather
than the presence of the binaries. See "Implementation order".

The AL2 rows are gone too. They never published an artifact; they existed to prove the
glibc 2.26 floor, and the portable rows now prove a stricter one at 2.17 on every build.
What goes with them is old-toolchain coverage — AL2 built under gcc 7.3.1 and a cmake3
symlink, where manylinux2014 supplies gcc 10.2.1 and a current cmake — so nothing in CI
now compiles the tree under a pre-2020 compiler. Accepted: no shipped artifact was built
that way, and the floor those rows guarded is now asserted rather than inferred.

Linux is therefore five rows down to four, and every one of them ships.

### 5. `matrix.bootstrap` runs inside the container; `matrix.host_bootstrap` runs on the runner

Every Linux row is now an `image` row — the job runs on the runner and invokes docker
itself — because manylinux2014 is glibc 2.17 and the runner forces its JS actions onto a
Node that needs 2.28. `matrix.bootstrap` is therefore always executed inside that docker
invocation, as root, with no `sudo`, and `matrix.container` is gone along with the
job-level `container:` key and the toolchain step that keyed on it.

That leaves a gap the per-distro rows did not have. The assertion steps run on the runner,
against the binary docker left in `target/release`, and a tpm-linked `credsd` will not
start without libtss2 present there. `matrix.host_bootstrap` fills exactly that: it installs
`libtss2-dev` on the runner for the two `-tpm` rows, and nothing else uses it.

### 6. The feature is compiled and linted on every pull request

`.github/workflows/ci.yml`'s lint job is matrixed over host families precisely because a
single-target lint run cannot see gated code, and it already carries a
`clippy (secure-enclave)` step for the feature-gated version of that blind spot. The `tpm`
feature gets the same treatment on the Linux row:

```
cargo clippy --all-targets --features credsd-core/tpm -- -D warnings
```

`credsd-core/tpm` rather than a bare `tpm`: at the workspace root with `--all-targets`, a
bare feature name fails against members that do not define it.

The TPM build rows additionally run `cargo test --locked -p credsd-core --features tpm`.
That reaches the feature-gated unit tests; it does not reach a TPM. The seal-and-unseal
round trip in `crates/credsd-core/src/storage/tpm.rs` returns early with a message when no
device is reachable, which is what keeps it safe on hardware-free runners and is also the
seam a software TPM plugs into — `EsapiSeam::open` consults
`TctiNameConf::from_environment_variable()` before falling back to
`device:/dev/tpmrm0`.

### 7. Linkage is asserted on every row, not reasoned about

Every Linux row reads its own `ldd` output, on pull requests as well as on `main`:

- a `*-tpm` row fails unless `credsd` names `libtss2-esys`
- every other Linux row fails if `credsd` names any `libtss2`
- every Linux row fails if `creds` names any `libtss2`

This is the whole claim the separate artifact exists to make, and it is one `ldd` away from
being checkable, so nothing about it is left to inference. The assertion runs on the
machine that produced the binary, beside the existing digest recording.

### 8. The portable floor is asserted the same way

A row carrying `matrix.glibc_floor` additionally fails unless both binaries stay at or below
that floor and neither carries a `RUNPATH`. Both halves fail builds that otherwise look
green, which is why neither is left to the build image's reputation:

- A symbol picked up from a newer toolchain does not fail the build or the tests. It fails
  on the oldest host a customer has, which no CI row is.
- A `RUNPATH` left behind by `/opt/tss` or `/opt/ossl` sends the loader to a build-machine
  path. On a host where that path is creatable, that is somewhere to plant a library the
  daemon will load.

Only non-weak symbols count toward the floor. Rust std references `statx`, `copy_file_range`,
`getrandom`, `gettid` and `pidfd_spawnp` weakly and falls back to a syscall when the host
lacks them, so a weak reference above the floor is not a floor — reading it as one would
make every portable build fail its own assertion.

## Verifiable properties

1. A push to `main` uploads `builds/<commit>/<platform>/{creds,credsd}` for every TPM
   platform, and the manifest names them with no change to its schema.
2. On a host with `/dev/tpmrm0` and the tpm2-tss runtime, a `*-tpm` `credsd` reports the
   `tpm` backend as available.
3. The default Linux `credsd` links no tpm2-tss library, and neither does any `creds`.
4. A pull request that breaks `cfg(feature = "tpm")` code fails lint, not a later release.

## File changes

| File | Role |
|---|---|
| `crates/credsd-daemon/Cargo.toml` | `tpm` passthrough to `credsd-core/tpm`, beside `secure-enclave` |
| `crates/credsd-core/src/storage/tpm.rs` | The `esapi` module compiles and passes clippy against tss-esapi 7.x |
| `.github/workflows/ci.yml` | `clippy (tpm)` on the Linux lint row, with `libtss2-dev` installed; `test (kkrs)` moved here from `build.yml` |
| `.github/workflows/build.yml` | Four `linux-*` rows replacing the eight per-distro ones; `host_bootstrap`; tpm branch in the `image` step; `ldd` linkage and glibc-floor assertions |
| `scripts/manylinux-toolchain.sh` | Builds OpenSSL 1.1.1w and tpm2-tss 4.0.2 from checksummed tarballs inside the container, for the `-tpm` rows |
| `docs/key-security.md` | The `tpm` feature ships in a named Linux artifact; `credsd status` remains the only thing that settles a given install |
| `docs/design/key-storage-backends.md` | The backend table's `tpm` row reflects a shipped device seam |

`release.yml` and `tagged-release.yml` are unchanged: `release.yml` derives its platform set
from the artifact directory names, so renaming the Linux platforms needs no edit there.

`test (kkrs)` moved because every Linux build row now runs in a container, and the backend's
tests make keyring syscalls a container's seccomp profile can refuse. `ci.yml`'s Linux lint
row is the only bare Linux runner left in CI.

## Platform considerations

Encoding a storage capability in the platform segment is a **two-way door for a third
platform and a one-way door for a second axis.** Another operating system is just another
segment. A second orthogonal build dimension — a FIPS variant, a `-notpm` build, a
differently linked TLS stack — multiplies against this one instead of composing with it,
and the first such pair is where the segment scheme has to become structured rather than
suffixed. Reversing it means rewriting the key layout in both repositories, every
EventBridge matcher, and the promotion platform list.

One naming hazard follows from the same choice. Windows reaches a TPM through CNG and
DPAPI, not through tpm2-tss, so a future `windows-x64-tpm` segment would name a different
mechanism with the same word. If Windows support lands, its TPM-backed storage is a
property of the default Windows artifact, and the `-tpm` suffix stays a statement about
linking tpm2-tss.

Accepted deliberately: the suffix is the smallest thing that works for one extra axis, and
a structured scheme invented before a second axis exists would be an abstraction hedging
against a build nobody has committed to.

## Dependencies

The `tpm` passthrough on `credsd-daemon`, and the reporting of `tpm` as unavailable when
the feature is absent, are prerequisites tracked separately. So is install documentation
for the runtime requirement — the tpm2-tss package and `tss` group membership. The
integration lanes and the promotion platform list live in a separate distribution
repository, which is not public.

## Implementation order

Execution plan rather than durable record; it describes the sequence, not the system.

1. **Compile-verify `esapi`.** Done, and it needed no code changes. The module in
   `crates/credsd-core/src/storage/tpm.rs` compiles and lints clean against tss-esapi 7.7.0
   under the pinned toolchain, and `cargo test -p credsd-core --features tpm` passes 459
   tests. Reproduce it without a GitHub runner:

   ```bash
   finch run --rm -v "$PWD":/w -w /w public.ecr.aws/amazonlinux/amazonlinux:2023 sh -euc '
     dnf install -y --quiet tar gzip git gcc cmake perl pkgconf-pkg-config tpm2-tss-devel
     curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
       | sh -s -- -y --profile minimal --no-modify-path --default-toolchain none
     . "$HOME/.cargo/env"
     cargo clippy -p credsd-core --all-targets --features tpm -- -D warnings
     cargo test --locked -p credsd-core --features tpm
   '
   ```

   `cmake` and `perl` are for `aws-lc-sys`, `pkgconf-pkg-config` for the four pkg-config
   probes. AL2023 resolves all four tss2 libraries at 4.0.2.

   Seal and unseal are verified too, against swtpm 0.7.3 on Ubuntu 24.04 rather than
   AL2023, whose repositories carry no `swtpm` package. The `machine` policy round-trips
   through the real `EsapiSeam`. Use the `swtpm` TCTI, not `mssim` — swtpm's `--ctrl`
   channel speaks its own protocol, so mssim fails in `simulator_setup()`; the recipe is on
   `esapi_seal_unseal_round_trip`. That socket TCTI now reaches only that test: the daemon
   opens `/dev/tpmrm0` alone, so running it against swtpm takes `swtpm chardev --vtpm-proxy`
   on a host with no TPM. Ubuntu's `libtss2-dev` also supplies all four `.pc`
   files at 4.0.1, so the Ubuntu rows' build script resolves.

   Two limits on what that establishes. It ran on aarch64, so it exercised
   `tss-esapi-sys`'s `aarch64-unknown-linux-gnu` pregenerated bindings and not the x86_64
   set — the `linux-x64-tpm` row settles that. And machine binding depends on a real
   TPM's seed, so a simulator cannot assert it at all.

2. **Passthrough plus `ci.yml`.** Smallest useful commit, and it installs the compile gate
   that keeps step 1 from rotting.

3. **`build.yml`, per-distro rows.** Done: one `*-tpm` row per distro and arch, the
   `container` predicate, the split build, and the `ldd` assertions.

4. **`build.yml`, portable rows.** Done: `scripts/manylinux-toolchain.sh`, the four
   `linux-*` rows, `host_bootstrap`, the glibc-floor assertion, and the removal of the
   eight per-distro rows and the two AL2 rows. Linux is now four rows, all of them shipped.
   The rows published as `manylinux-*` when they first landed and were renamed once the
   distribution repository settled the name; the toolchain script keeps the `manylinux`
   name because it is named after the build image, not the artifact.

   Verified on aarch64 before landing — the full suite passes from a manylinux2014 build on
   manylinux2014, AL2023 and Ubuntu 24.04 for both variants, and both `-tpm` integration
   lanes pass against real NitroTPM hardware with the daemon reporting `storage backends:
   tpm, file`. x86_64 was verified in CI rather than locally: both x86_64 rows build and
   test green, and the floor assertion reports 2.16 there — lower than aarch64's 2.17
   because x86_64 glibc symbol versions begin at 2.2.5 while aarch64's begin at 2.17.
   Runtime TPM verification on x86_64 hardware is still outstanding; both integration lanes
   run so far were aarch64.

5. **Integration lanes and the promotion list**, in the separate distribution repository.
   Settled there as `linux-*`, which is the name this matrix now publishes. Each lane
   names the artifact platform it verifies rather than deriving it from the lane's own
   name, and the four distro-flavoured names are accepted beside it for the duration of
   the cutover, so a commit under either naming fires its lanes and graduates.

   The four Linux lanes are instance-backed and distro-flavoured on purpose — each launches
   its own NitroTPM AMI — so the mapping is not one-to-one. One portable platform is gated
   by two lanes, which is a change to promotion's list and not just a rename: presence of
   the binaries under `tested/<commit>/<platform>/` no longer proves which lane wrote them,
   so a passing lane also writes a witness object and the release gate requires one per
   expected lane.

   One condition outside this naming remains, in that repository's workflow inputs rather
   than in the lanes: `release.yml` resolves its upload prefix from the repository name, so
   while this repository is not the one that check names, its builds land under
   `staging-builds/` — a prefix no lane or promotion step reads — and reach no lane
   regardless of platform naming.

6. **Docs**, once the artifacts exist and the names are settled. Done for the artifact
   names in the same commit as the rename; `docs/install.md` describes the Linux artifact
   generically and needed no edit.
