//! Integration tests for the sign-request-pipeline.
//!
//! These tests are gated behind the `integration-tests` feature and are intended
//! to run against a real or pre-prod IAM Roles Anywhere endpoint.
//!
//! # Required Environment Variables
//!
//! For `generate_credentials` round-trip tests:
//! - `ROLESANYWHERE_CERT_PATH` — Path to the client X.509 certificate PEM file
//! - `ROLESANYWHERE_KEY_PATH` — Path to the private key PEM file
//! - `ROLESANYWHERE_TRUST_ANCHOR_ARN` — Trust anchor ARN
//! - `ROLESANYWHERE_PROFILE_ARN` — Profile ARN
//! - `ROLESANYWHERE_ROLE_ARN` — Role ARN
//! - `ROLESANYWHERE_REGION` (optional) — AWS region; defaults to region derived from ARN
//!
//! For differential serial number tests:
//! - No environment variables required; uses test certificates at `tst/certs/`
//!
//! # Running
//!
//! ```bash
//! # Run integration tests (requires env vars for endpoint tests):
//! cargo test --features integration-tests --test integration
//!
//! # Run only the differential serial number test (no env vars needed):
//! cargo test --features integration-tests --test integration differential
//! ```
#![cfg(feature = "integration-tests")]

use rolesanywhere_core::pipeline::{SignRequestInput, generate_credentials};
use rolesanywhere_core::serial::extract_serial_number;

use std::env;
use std::process::Command;

/// Test certificate fixtures shared by the serial-number tests, as (label, path)
/// pairs relative to the crate root. See `tst/certs/`.
const TEST_CERTS: [(&str, &str); 3] = [
    ("RSA-2048", "../../tst/certs/rsa-2048-cert.pem"),
    ("EC-P256", "../../tst/certs/ec-p256-cert.pem"),
    ("Large-Serial", "../../tst/certs/large-serial-cert.pem"),
];

/// Helper to read all required environment variables for the round-trip test.
/// Returns None if any required variable is missing.
fn get_rolesanywhere_env() -> Option<SignRequestInput> {
    let cert_path = env::var("ROLESANYWHERE_CERT_PATH").ok()?;
    let key_path = env::var("ROLESANYWHERE_KEY_PATH").ok()?;
    let trust_anchor_arn = env::var("ROLESANYWHERE_TRUST_ANCHOR_ARN").ok()?;
    let profile_arn = env::var("ROLESANYWHERE_PROFILE_ARN").ok()?;
    let role_arn = env::var("ROLESANYWHERE_ROLE_ARN").ok()?;
    let region = env::var("ROLESANYWHERE_REGION").unwrap_or_default();
    let endpoint_url = env::var("ROLESANYWHERE_ENDPOINT_URL").ok();

    Some(SignRequestInput {
        cert_path,
        key_path,
        region,
        trust_anchor_arn,
        profile_arn,
        role_arn,
        session_duration: None,
        role_session_name: None,
        cert_chain_path: None,
        endpoint_url,
    })
}

/// Full round-trip test: calls `generate_credentials` against a real endpoint
/// and verifies that valid AWS credentials are returned.
#[test]
fn test_generate_credentials_round_trip() {
    let input = match get_rolesanywhere_env() {
        Some(input) => input,
        None => {
            eprintln!(
                "Skipping test_generate_credentials_round_trip: \
                 required environment variables not set. Set ROLESANYWHERE_CERT_PATH, \
                 ROLESANYWHERE_KEY_PATH, ROLESANYWHERE_TRUST_ANCHOR_ARN, \
                 ROLESANYWHERE_PROFILE_ARN, and ROLESANYWHERE_ROLE_ARN."
            );
            return;
        }
    };

    let result = generate_credentials(&input);

    match result {
        Ok(output) => {
            // Version must be 1 per credential_process spec
            assert_eq!(output.version, 1, "Version should be 1");

            // AccessKeyId should start with "ASIA" (temporary credentials)
            assert!(
                output.access_key_id.starts_with("ASIA"),
                "AccessKeyId should start with 'ASIA' for temporary credentials, got: {}",
                output.access_key_id
            );

            // SecretAccessKey should be non-empty
            assert!(
                !output.secret_access_key.is_empty(),
                "SecretAccessKey should not be empty"
            );

            // SessionToken should be non-empty
            assert!(
                !output.session_token.is_empty(),
                "SessionToken should not be empty"
            );

            // Expiration should be a valid ISO 8601 timestamp
            assert!(
                !output.expiration.is_empty(),
                "Expiration should not be empty"
            );
            assert!(
                output.expiration.contains('T') && output.expiration.contains('Z'),
                "Expiration should be an ISO 8601 timestamp, got: {}",
                output.expiration
            );
        }
        Err(e) => {
            panic!("generate_credentials failed: {}", e);
        }
    }
}

/// Cross-check serial extraction against `openssl x509`: extract each test cert's
/// serial with Rust's `extract_serial_number` and compare to openssl's serial.
///
/// What this actually measures (and what it does NOT):
/// - The reference is `openssl x509 -serial` (hex) converted to decimal via an
///   UNSIGNED `BigUint` — NOT the Go binary. It confirms the magnitude matches a
///   second independent implementation.
/// - All three fixtures have POSITIVE serials, where signed and unsigned decoding are
///   identical, so this test cannot catch a negative-serial sign bug. The signed-vs-
///   unsigned parity (the part that matches Go's signed `big.Int.String()`) is covered
///   by `serial::tests::test_extract_serial_number_negative_cert_is_signed` instead.
#[test]
fn test_differential_serial_number_extraction() {
    for (label, cert_path) in &TEST_CERTS {
        // Committed fixture: a read failure is a test-environment bug, so fail loudly
        // rather than silently skipping into a false green.
        let cert_pem = std::fs::read(cert_path)
            .unwrap_or_else(|e| panic!("cannot read {} fixture {}: {}", label, cert_path, e));

        let pem_parsed = pem::parse(&cert_pem).unwrap_or_else(|e| {
            panic!("Failed to parse PEM for {}: {}", label, e);
        });
        let cert_der = pem_parsed.contents();

        let rust_serial = extract_serial_number(cert_der).unwrap_or_else(|e| {
            panic!("Rust extract_serial_number failed for {}: {}", label, e);
        });

        // Reference serial from `openssl x509` (hex), converted to decimal. For these
        // positive serials this equals Go's big.Int.String(); see the fn docstring for
        // why this is an unsigned-magnitude cross-check, not a Go-binary differential.
        let reference_serial = extract_serial_via_openssl(cert_path);

        match reference_serial {
            Some(serial) => {
                assert_eq!(
                    rust_serial, serial,
                    "Serial number mismatch for {} certificate.\n\
                     Rust: {}\n\
                     Reference (openssl→decimal): {}",
                    label, rust_serial, serial
                );
                eprintln!("[PASS] {} serial number matches: {}", label, rust_serial);
            }
            None => {
                // If openssl is not available, just verify Rust output is valid decimal
                eprintln!(
                    "Skipping openssl comparison for {} (openssl not available). \
                     Rust serial: {}",
                    label, rust_serial
                );
                assert!(
                    !rust_serial.is_empty() && rust_serial.chars().all(|c| c.is_ascii_digit()),
                    "Rust serial should be a valid decimal string for {}, got: {}",
                    label,
                    rust_serial
                );
            }
        }
    }
}

/// Extract the serial number from a certificate file using `openssl x509`,
/// then convert the hex output (an unsigned magnitude) to a decimal string.
///
/// Returns `None` if openssl is not available or the command fails.
fn extract_serial_via_openssl(cert_path: &str) -> Option<String> {
    let output = Command::new("openssl")
        .args(["x509", "-in", cert_path, "-serial", "-noout"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // openssl outputs: "serial=HEXVALUE\n"
    let hex_str = stdout.trim().strip_prefix("serial=")?;

    // Convert the unsigned hex magnitude to a decimal string.
    hex_to_decimal(hex_str)
}

/// Convert a hex string to a decimal string using simple big-integer arithmetic.
/// Uses num-bigint which is already a dependency of the crate.
fn hex_to_decimal(hex: &str) -> Option<String> {
    // Remove any leading "0x" prefix and whitespace
    let clean_hex = hex
        .trim()
        .strip_prefix("0x")
        .or_else(|| hex.trim().strip_prefix("0X"))
        .unwrap_or(hex.trim());

    // Parse hex to BigUint
    let value = num_bigint::BigUint::parse_bytes(clean_hex.as_bytes(), 16)?;
    Some(value.to_string())
}

// (Removed test_serial_number_extraction_deterministic: extract_serial_number is a
// pure, stateless function, so a call-it-3x-and-compare check cannot fail. The real
// serial correctness is pinned by the known-answer tests in serial.rs.)
