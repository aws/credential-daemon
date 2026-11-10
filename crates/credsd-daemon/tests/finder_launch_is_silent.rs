//! Launching `Credsd.app` from Finder runs `Contents/MacOS/credsd` with no arguments and no
//! terminal. The bundle carries the daemon's entitlement; it is not meant to be launched, so
//! that invocation must produce nothing rather than usage text sent nowhere.

use std::process::{Command, Stdio};

const CREDSD: &str = env!("CARGO_BIN_EXE_credsd");

#[test]
fn no_arguments_and_no_terminal_produces_no_output() {
    let out = Command::new(CREDSD)
        .stdin(Stdio::null())
        .output()
        .expect("run credsd");

    assert_eq!(out.status.code(), Some(2), "should exit 2");
    assert!(
        out.stderr.is_empty(),
        "stderr should be empty, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "stdout should be empty, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The guard is narrow: anything with an argument behaves normally, terminal or not.
#[test]
fn an_argument_still_produces_output() {
    let out = Command::new(CREDSD)
        .arg("--help")
        .stdin(Stdio::null())
        .output()
        .expect("run credsd --help");

    assert_eq!(out.status.code(), Some(0));
    assert!(!out.stdout.is_empty(), "--help should print to stdout");
}
