# Vendored `rolesanywhere-core`

This directory holds a vendored copy of the Rust IAM Roles Anywhere credential-helper core,
licensed Apache-2.0 — the same licence as credsd itself. See the repository root `LICENSE`.

It is a **pre-release copy**. The upstream project is not yet published, so there is no
crates.io version or public repository to depend on. It is kept here as a plain path
dependency of `crates/credsd` and `crates/credsd-core` precisely so it can be swapped for
the published crate without touching call sites, and the root `Cargo.toml` excludes it from
the workspace so credsd's `-D warnings` lint profile does not apply to code credsd does not
own.

Only `crates/core` is vendored. Upstream also carries `cli`, `ffi`, and language bindings;
credsd uses none of them, so they are deliberately absent. Comments throughout the source
cite the public Go credential helper (`signer.go`, `credentials.go`, `serve.go`) by filename
— that is the reference the Rust implementation was written against, not code it copies.

## Changes from upstream

- The test fixtures in `tst/certs/` were pruned to the set this crate's own tests read, and
  the test CA hierarchy was regenerated with neutral subjects. `tst/certs/README.md` has the
  generation recipe.

## Caveats

- No CI job builds, tests, or lints this directory, and `crates/core/Cargo.lock` is separate
  from the root lockfile, so it can drift unchecked. Run `cargo test` inside
  `vendor/rolesanywhere/crates/core` after changing anything here; the root `cargo test`
  does not reach it.
- Because it is a path dependency rather than a registry crate, `cargo about` does not list
  it in `THIRD-PARTY-LICENSES.md`. Its licence is recorded here and in root `NOTICE`.
