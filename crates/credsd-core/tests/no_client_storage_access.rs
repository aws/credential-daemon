//! Regression guard for the client-storage-delegation feature (requirements.md Req 1.1):
//! client code must not touch the platform `SecureStorage` backend. After the change the only
//! non-test references to these symbols live in `credsd-daemon` (the sole storage opener) and in
//! `credsd-core`'s own `storage/` + `encryption.rs` modules.
//!
//! Enforced as a source scan rather than a type check because "does not call" is not something
//! the compiler can assert — a re-introduced `init_encryption_with_backend` in the client would
//! compile fine. `credsd-daemon` is deliberately out of scope (it is allowed to open storage).
//!
//! Two symbol sets, because `EncryptionService` is scoped differently:
//! - The **client binary crates** (`credsd`, `credsd-client`) must not even name
//!   `EncryptionService` — accepting a pre-built one from a caller and decrypting with it would
//!   reach sealed material without ever calling `init_encryption`/`create_storage`, bypassing the
//!   narrower guard.
//! - `credsd-core` is the shared library: `EncryptionService` is a legitimate type there, used by
//!   the daemon-consumed providers, `credential_status`, and bootstrap helpers. Only the
//!   keystore-opening symbols are forbidden in it, and only outside `storage/` + `encryption.rs`.

use std::path::Path;

/// Keystore-opening symbols. Forbidden everywhere this test scans.
const STORAGE_SYMBOLS: [&str; 3] = ["init_encryption", "create_storage", "SecureStorage"];

/// The encryption service type. Forbidden in the client crates only (see module docs).
const CLIENT_ONLY_SYMBOLS: [&str; 1] = ["EncryptionService"];

#[test]
fn no_client_side_storage_access() {
    // CARGO_MANIFEST_DIR is crates/credsd-core; its parent is the workspace `crates/` dir.
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .to_path_buf();

    // Each root scans for its own symbol set. The client crates get the stricter set; credsd-core
    // gets only the keystore-opening symbols, since it is the library that defines the rest. The
    // `storage/` + `encryption.rs` exclusions apply to credsd-core ONLY — a client-side file by
    // either name must still be scanned, or a re-introduced client storage access there would slip
    // the guard. `core_exclusions` carries that per-root.
    let client: Vec<&str> = STORAGE_SYMBOLS
        .iter()
        .chain(CLIENT_ONLY_SYMBOLS.iter())
        .copied()
        .collect();
    // (root, symbols, core_exclusions)
    let scan_roots: [(std::path::PathBuf, &[&str], bool); 3] = [
        (crates_dir.join("credsd/src"), &client, false),
        (crates_dir.join("credsd-client/src"), &client, false),
        (crates_dir.join("credsd-core/src"), &STORAGE_SYMBOLS, true),
    ];

    let mut violations = Vec::new();
    for (root, symbols, core_exclusions) in scan_roots {
        // Fail loudly on a missing root: a silent skip would switch the guard off on a directory
        // rename/move and still report green — the one failure mode a regression guard must avoid.
        assert!(
            root.is_dir(),
            "scan root {} does not exist or is not a directory — the guard would silently pass; \
             fix the path",
            root.display()
        );
        collect_violations(&root, symbols, core_exclusions, &mut violations);
    }

    assert!(
        violations.is_empty(),
        "client code must not access storage; found:\n{}",
        violations.join("\n")
    );
}

fn collect_violations(
    dir: &Path,
    symbols: &[&str],
    core_exclusions: bool,
    violations: &mut Vec<String>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        // A crate without the expected src layout is not a failure of this property.
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // credsd-core's own `storage/` is where these symbols are defined and used; the client
            // crates have no such exemption, so a client `storage/` dir is scanned.
            if core_exclusions && path.file_name().is_some_and(|n| n == "storage") {
                continue;
            }
            collect_violations(&path, symbols, core_exclusions, violations);
            continue;
        }
        if !is_scannable(&path, core_exclusions) {
            continue;
        }
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        for symbol in symbols {
            if content.contains(symbol) {
                violations.push(format!("{}: {symbol}", path.display()));
            }
        }
    }
}

/// `.rs` files. In credsd-core (`core_exclusions`), `encryption.rs` is skipped — it legitimately
/// defines the encryption service and its `init_encryption*` constructors. The client crates get
/// no such exemption: a client file named `encryption.rs` is scanned like any other.
fn is_scannable(path: &Path, core_exclusions: bool) -> bool {
    if path.extension().is_none_or(|e| e != "rs") {
        return false;
    }
    !(core_exclusions && path.file_name().is_some_and(|n| n == "encryption.rs"))
}
