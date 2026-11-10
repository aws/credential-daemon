//! Compiles and links the Swift Secure Enclave shim for the `secure-enclave` feature.
//!
//! CryptoKit's `SecureEnclave` types have no C interface — the framework in the SDK carries a
//! `.swiftmodule` and no `Headers/` — so reaching the enclave from Rust requires compiling
//! Swift. `swift/SecureEnclaveShim.swift` exports a C ABI via `@_cdecl`; this script builds it
//! into a static archive and tells rustc how to link it.
//!
//! Unlike the two bin-crate build scripts (which embed an Info.plist unconditionally on macOS),
//! everything here is gated on the feature and on the target: off macOS the script returns
//! early, so the Linux and Windows rows of the build matrix never see this code path.
//!
//! `-static` applies to *our* Swift code only: the Swift runtime stays a dylib in
//! `/usr/lib/swift`, which has shipped as part of macOS since 10.14.4. That is what keeps credsd
//! a single self-contained binary — `-static-stdlib` would bloat it and is unnecessary.

use std::{env, error::Error, path::PathBuf, process::Command};

/// Relative to the package root, which is a build script's working directory.
const SHIM: &str = "swift/SecureEnclaveShim.swift";

/// Swift module name. Only visible in mangled symbols; the `@_cdecl` exports are unmangled.
const MODULE: &str = "CredsdSE";

/// Deployment floor for the shim. CryptoKit's Secure Enclave types predate this by years; the
/// constraint is only that it not exceed what credsd itself targets.
const MACOS_MIN: &str = "13.0";

fn main() -> Result<(), Box<dyn Error>> {
    if env::var_os("CARGO_FEATURE_SECURE_ENCLAVE").is_none() {
        return Ok(());
    }

    // A no-op off macOS rather than an error, because the feature is on by default: the enclave
    // is the only hardware-backed keystore a self-built macOS daemon has, so a plain
    // `cargo build` has to produce one that can use it. That makes the feature inert on every
    // other target instead of unasked-for — `Backend::COMPILED` gates the variant on
    // `all(target_os = "macos", feature = "secure-enclave")` and the module itself is
    // `cfg(target_os = "macos")`, so nothing off macOS can reach the shim this would have built.
    if env::var("CARGO_CFG_TARGET_OS")? != "macos" {
        return Ok(());
    }

    println!("cargo::rerun-if-changed={SHIM}");

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let archive = out_dir.join("libcredsd_se.a");
    let sdk = sdk_path()?;

    // `aarch64` is Rust's name for what Apple's toolchain calls `arm64`. Cargo builds one
    // target per invocation, so a single-arch archive is correct here — no `lipo` step.
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")?;
    let arch = if target_arch == "aarch64" {
        "arm64"
    } else {
        target_arch.as_str()
    };

    let status = Command::new("xcrun")
        .args(["--sdk", "macosx", "swiftc"])
        .args(["-emit-library", "-static", "-parse-as-library", "-O"])
        .args(["-module-name", MODULE])
        .args(["-target", &format!("{arch}-apple-macos{MACOS_MIN}")])
        .args(["-sdk", &sdk])
        .arg("-o")
        .arg(&archive)
        .arg(SHIM)
        .status()?;

    if !status.success() {
        return Err(format!("swiftc failed to build {SHIM} ({status})").into());
    }

    println!("cargo::rustc-link-search=native={}", out_dir.display());
    println!("cargo::rustc-link-lib=static=credsd_se");

    // Frameworks the shim itself calls into.
    println!("cargo::rustc-link-lib=framework=CryptoKit");
    println!("cargo::rustc-link-lib=framework=Foundation");
    println!("cargo::rustc-link-lib=framework=LocalAuthentication");
    println!("cargo::rustc-link-lib=framework=Security");

    // The Swift runtime, for link-time resolution only. The SDK's stubs record absolute install
    // names under `/usr/lib/swift`, so the resulting binary needs no `@rpath` entry and no
    // `-rpath` flag — verified with `otool -L`, which shows every `libswift*.dylib` bound to an
    // absolute path. Those libraries are part of macOS from 10.14.4 on, so nothing ships with
    // credsd to satisfy them.
    println!("cargo::rustc-link-search=native={sdk}/usr/lib/swift");

    Ok(())
}

/// `$SDKROOT` first: the `--sdk macosx` below ignores it, while rustc's link step honours it.
fn sdk_path() -> Result<String, Box<dyn Error>> {
    println!("cargo::rerun-if-env-changed=SDKROOT");
    if let Some(sdk) = env::var_os("SDKROOT").filter(|v| !v.is_empty()) {
        return Ok(sdk.to_string_lossy().into_owned());
    }
    let out = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()?;
    if !out.status.success() {
        return Err("xcrun could not locate the macOS SDK (is Xcode or the CLT installed?)".into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}
