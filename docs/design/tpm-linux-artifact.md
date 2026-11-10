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

## Shape

A TPM-enabled build is a **platform**, not a differently named binary. Every artifact path
in the release system is keyed by a platform segment — `builds/<commit>/<platform>/`,
`develop/<platform>/`, `tested/<commit>/<platform>/`, one integration lane per platform —
so a new platform needs no change to the key layout.

A TPM platform is an existing platform name with a `-tpm` suffix: `al2023-x64-tpm`,
`al2023-aarch64-tpm`, `ubuntu-x64-tpm`, `ubuntu-aarch64-tpm`. Each carries the same
`{creds, credsd}` pair as every other platform: a `credsd` linked against tpm2-tss, and a
`creds` that is not.

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
`al2023-x64` and a `-notpm` variant beside it — makes the obvious download the one that
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

### 4. Every distro and architecture the default matrix ships, except AL2

Ubuntu 24.04 ships tpm2-tss 4.0.1 as `libtss2-dev`, and AL2023 ships 4.0.2 as
`tpm2-tss-devel`. Both clear the 2.4.6 floor with room, on both architectures, so the TPM
rows mirror the default rows and the platform names stay predictable: a customer who pulls
`al2023-aarch64` finds `al2023-aarch64-tpm` beside it.

Every shipped platform has an integration lane, because a platform without one cannot be
released at all. Promotion reads `tested/<commit>/<platform>/` for every platform in its
list, and only a lane's graduation step writes that prefix — so an ungated platform either
aborts the release or is left out of the list and never reaches a customer. The artifact set
and the lane set are one decision.

AL2 is not in the set. Its `tpm2-tss` is 1.3.0, below the floor. A conforming build exists
there under the separate `tpm2-tss3` and `tpm2-tss3-devel` package names at 3.1.1, so an AL2
variant is possible — but AL2 rows build inside a docker invocation the job makes itself,
because the runner's JS actions need a glibc AL2 does not have, so the bootstrap and the
package names would both have to be threaded through that inner shell. AL2 also has no
integration lane to gate the result. The combination is not worth a platform nobody has
asked for; AL2's reason to exist in the matrix is proving the glibc 2.26 floor, which the
default rows already do.

A smaller set is defensible and was weighed: an AL2023 build links glibc 2.34 and therefore
runs on an Ubuntu 24.04 host, so the AL2023 pair alone reaches every host the full set
reaches, and the Ubuntu rows add build-toolchain coverage rather than host coverage. Mirroring
the default matrix wins on two counts — a platform name means the same thing with and without
the suffix, and the `tpm` feature gets compiled under both toolchains rather than one.

### 5. `matrix.bootstrap` means "run these commands" and nothing else

A bootstrap string and a bare container image are independent facts. The toolchain
install predicates on `matrix.container`, so a row on a GitHub-hosted runner can carry a
bootstrap — `sudo apt-get install -y -qq libtss2-dev` — without the job also installing
rustup over the runner's preinstalled toolchain. Container rows run as root and need no
`sudo`; runner rows do.

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
| `.github/workflows/ci.yml` | `clippy (tpm)` on the Linux lint row, with `libtss2-dev` installed |
| `.github/workflows/build.yml` | One `*-tpm` matrix row per TPM platform; toolchain install keyed on `container`; split build/test for TPM rows; `ldd` linkage assertion |
| `docs/key-security.md` | The `tpm` feature ships in a named Linux artifact; `credsd status` remains the only thing that settles a given install |
| `docs/design/key-storage-backends.md` | The backend table's `tpm` row reflects a shipped device seam |

`release.yml` and `tagged-release.yml` are unchanged.

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
   set — the `al2023-x64-tpm` row settles that. And machine binding depends on a real
   TPM's seed, so a simulator cannot assert it at all.

2. **Passthrough plus `ci.yml`.** Smallest useful commit, and it installs the compile gate
   that keeps step 1 from rotting.

3. **`build.yml`.** The `container` predicate change first, on its own, since it is
   behaviour-preserving today and the matrix rows depend on it. Then the rows, the split
   build, and the `ldd` assertions.

4. **Docs**, once the artifacts exist and the names are settled.
