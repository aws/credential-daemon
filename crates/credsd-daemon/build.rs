//! Bundle identity for the `credsd` binary.
//!
//! A bare Mach-O has nowhere to carry an Info.plist but its own `__TEXT,__info_plist` section,
//! and `codesign` reads `CFBundleIdentifier` from there rather than synthesizing one from the
//! file name. `credsd` ships as a plain file under `platform::SERVICE_BINARY_DIR`, not in an
//! .app bundle, so that section is the only place a signed binary can state its identity.
//!
//! This renders `packaging/Info.plist.in` — substituting the three at-delimited tokens
//! `@IDENTIFIER@`, `@EXECUTABLE@` and `@VERSION@` — and asks `ld` to `-sectcreate` the result
//! into the executable. The template carries no comment of its own because the whole file is
//! embedded verbatim into every signed binary.
//!
//! Not a service definition: `credsd install` still renders the LaunchDaemon plist from the
//! running binary at install time (see `install.rs`).
//!
//! Near-identical to `crates/credsd/build.rs`. Two copies of ~25 lines beat a shared build
//! dependency; a *third* bin crate is the point to extract this rather than copy it again.

use std::{env, error::Error, fs, path::PathBuf};

/// Relative to the package root, which is a build script's working directory.
const TEMPLATE: &str = "../../packaging/Info.plist.in";

/// The daemon's bundle identity. Independent of `credsd_core::storage::SERVICE_NAME` (the
/// Keychain / kernel-keyring credential-store key): the bundle ID and the credential-store key
/// are separate namespaces. A build script cannot depend on the crate it builds, so this is a literal that the
/// `embedded_plist_identity` test pins by reading the plist actually embedded in the binary.
const IDENTIFIER: &str = "com.amazon.aws.credsd.daemon";

/// Both the `[[bin]]` name and the plist's `CFBundleExecutable`. Cargo hard-errors on a
/// `rustc-link-arg-bin` naming no bin target, so a rename cannot silently drop the section; the
/// test against `CARGO_BIN_NAME` covers the other half — that the embedded plist still names the
/// binary it is embedded in.
const EXECUTABLE: &str = "credsd";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed={TEMPLATE}");

    let rendered = PathBuf::from(env::var("OUT_DIR")?).join("Info.plist");
    fs::write(
        &rendered,
        fs::read_to_string(TEMPLATE)?
            .replace("@IDENTIFIER@", IDENTIFIER)
            .replace("@EXECUTABLE@", EXECUTABLE)
            .replace("@VERSION@", &env::var("CARGO_PKG_VERSION")?),
    )?;

    // `-bin=` rather than a blanket link-arg: only Mach-O has the section, and test binaries
    // neither need it nor should be relinked for it.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // Absolute path — the linker's working directory is the workspace root, not this crate.
        println!(
            "cargo::rustc-link-arg-bin={EXECUTABLE}=-Wl,-sectcreate,__TEXT,__info_plist,{}",
            rendered.display()
        );
    }

    Ok(())
}
