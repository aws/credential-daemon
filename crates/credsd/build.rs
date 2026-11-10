//! Bundle identity for the `creds` binary — the same job `crates/credsd-daemon/build.rs` does
//! for the daemon, which carries the full rationale.
//!
//! Renders `packaging/Info.plist.in` (substituting `@IDENTIFIER@`, `@EXECUTABLE@` and
//! `@VERSION@`) and asks `ld` to `-sectcreate` the result into the executable's
//! `__TEXT,__info_plist` section, so a signed `creds` states its own identity instead of
//! letting `codesign` synthesize one from the file name.

use std::{env, error::Error, fs, path::PathBuf};

/// Relative to the package root, which is a build script's working directory.
const TEMPLATE: &str = "../../packaging/Info.plist.in";

const IDENTIFIER: &str = "com.amazon.aws.credsd.client";

/// Both the `[[bin]]` name and the plist's `CFBundleExecutable`. Cargo hard-errors on a
/// `rustc-link-arg-bin` naming no bin target, so a rename cannot silently drop the section; the
/// `CARGO_BIN_NAME` test in `main.rs` covers the other half — that the embedded plist still names
/// the binary it is embedded in.
const EXECUTABLE: &str = "creds";

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
