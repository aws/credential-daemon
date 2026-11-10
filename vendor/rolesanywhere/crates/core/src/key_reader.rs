//! Reading certificates and private keys from PEM files.
//!
//! This mirrors the Go reference (`signer.go`): we read PEM files into DER bytes
//! and base64-encode the certificate for the `X-Amz-X509` header. This module
//! does no cryptography itself — it only turns files into the raw bytes that the
//! signer and parser modules consume.

use crate::pem_tags;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::fs;
use zeroize::Zeroizing;

/// Read a PEM file and return the DER bytes of the first `CERTIFICATE` block.
///
/// In the Go code this is `parseDERFromPEM` in `signer.go`. The DER bytes are the
/// raw binary certificate, which we need both to read the serial number and to
/// base64-encode into the `X-Amz-X509` header.
pub fn read_certificate_der(cert_path: &str) -> Result<Vec<u8>, String> {
    // Read the whole file off disk into memory.
    let file_contents =
        fs::read(cert_path).map_err(|e| format!("Failed to read certificate file: {}", e))?;

    // A PEM file can hold several blocks; parse them all so we can pick the cert.
    let pem_blocks =
        pem::parse_many(&file_contents).map_err(|e| format!("Failed to parse PEM data: {}", e))?;

    // Return the first CERTIFICATE block's contents (its DER bytes).
    for block in pem_blocks {
        if block.tag() == pem_tags::CERTIFICATE {
            return Ok(block.contents().to_vec());
        }
    }

    Err("No CERTIFICATE block found in PEM file".to_string())
}

/// Read an intermediate-certificate chain PEM and return every `CERTIFICATE`
/// block's DER, in file order. A `None` path yields an empty chain.
///
/// This is the one shared implementation of the `--intermediates` loader that
/// every identity kind uses to populate the `X-Amz-X509-Chain` header
/// identically: the file-path pipeline, PKCS#11, and the OS cert-store backends
/// (macOS Keychain / Windows CNG). It differs from `read_certificate_der` only
/// in returning ALL certificate blocks rather than the first — same `pem`
/// crate, same `CERTIFICATE`-tag filter. Backends map the `String` error into
/// their own error type.
pub fn read_certificate_chain_der(chain_path: Option<&str>) -> Result<Vec<Vec<u8>>, String> {
    let Some(path) = chain_path else {
        return Ok(Vec::new());
    };
    let file_contents =
        fs::read(path).map_err(|e| format!("Failed to read certificate chain file: {}", e))?;
    let pem_blocks = pem::parse_many(&file_contents)
        .map_err(|e| format!("Failed to parse certificate chain PEM: {}", e))?;
    // Reject a PEM block that is not a CERTIFICATE rather than silently dropping
    // it: a `--intermediates` file that accidentally points at a private key (or
    // any non-cert PEM) is an operator mistake we should surface loudly, not turn
    // into an empty chain. A file with NO PEM blocks at all (empty, or raw DER)
    // still yields an empty chain, matching the "no chain given" case.
    let mut chain = Vec::with_capacity(pem_blocks.len());
    for block in &pem_blocks {
        if block.tag() != pem_tags::CERTIFICATE {
            return Err(format!(
                "certificate chain PEM contains a non-CERTIFICATE block ({}); \
                 --intermediates must contain only CERTIFICATE blocks",
                block.tag()
            ));
        }
        chain.push(block.contents().to_vec());
    }
    Ok(chain)
}

/// Base64-encode certificate DER bytes for the `X-Amz-X509` header.
pub fn certificate_to_base64(der_bytes: &[u8]) -> String {
    BASE64.encode(der_bytes)
}

/// Read a PEM file and return the DER bytes of the first private-key block,
/// along with the block's tag (so the caller knows which format the bytes are in).
///
/// Supports the three formats the Go tool supports:
///   - `PRIVATE KEY`     (PKCS#8 — modern; can hold either RSA or EC)
///   - `RSA PRIVATE KEY` (PKCS#1 — legacy RSA-only)
///   - `EC PRIVATE KEY`  (SEC1   — legacy EC-only)
///
/// The returned DER is wrapped in `Zeroizing`, and the whole-file buffer read
/// from disk is too, so the plaintext-key bytes in the two buffers we own are
/// scrubbed on drop rather than lingering in freed heap. This is defense-in-depth
/// for a long-running host (e.g. the FFI embedded in a JVM), where freed copies
/// can otherwise sit in the reused heap pool across many signings; it is a no-op
/// benefit for the short-lived CLI. Note the bounds — this covers only the two
/// buffers we own directly. It does NOT touch: the OS page cache of the on-disk PEM,
/// swap, or core dumps; the *parsed* key inside aws-lc-rs (already scrubbed by AWS-LC
/// on drop); or the intermediate DER copy the `pem` crate decodes into and frees
/// without zeroizing (that copy is outside our control — a residual, accepted gap).
/// `Zeroizing<Vec<u8>>` derefs to `&[u8]`, so callers are unchanged.
pub fn read_private_key_der(key_path: &str) -> Result<(Zeroizing<Vec<u8>>, String), String> {
    // Read into a Zeroizing buffer: this whole-file copy contains the plaintext key.
    let file_contents =
        Zeroizing::new(fs::read(key_path).map_err(|e| format!("Failed to read key file: {}", e))?);

    let pem_blocks =
        pem::parse_many(&file_contents).map_err(|e| format!("Failed to parse PEM data: {}", e))?;

    // Return the first block whose tag is one of the private-key formats we accept.
    for block in pem_blocks {
        let tag = block.tag().to_string();
        match tag.as_str() {
            pem_tags::PKCS8_PRIVATE_KEY | pem_tags::RSA_PRIVATE_KEY | pem_tags::EC_PRIVATE_KEY => {
                return Ok((Zeroizing::new(block.contents().to_vec()), tag));
            }
            _ => continue,
        }
    }
    Err("No private key block found in PEM file".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_certificate_der() {
        let der = read_certificate_der("../../tst/certs/rsa-2048-cert.pem");
        assert!(der.is_ok(), "Should parse the test certificate");
        let der_bytes = der.unwrap();
        // DER-encoded certificates are always non-trivial in size.
        assert!(
            der_bytes.len() > 100,
            "Certificate DER should be substantial"
        );
    }

    #[test]
    fn test_certificate_to_base64() {
        let der = read_certificate_der("../../tst/certs/rsa-2048-cert.pem").unwrap();
        let b64 = certificate_to_base64(&der);
        // Base64 output should be non-empty and contain only valid base64 characters.
        assert!(!b64.is_empty());
        assert!(
            b64.chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        );
    }

    #[test]
    fn test_read_private_key_der() {
        let result = read_private_key_der("../../tst/certs/rsa-2048-key.pem");
        assert!(result.is_ok(), "Should parse the test private key");
        let (der_bytes, tag) = result.unwrap();
        assert!(der_bytes.len() > 100, "Key DER should be substantial");
        // openssl generates PKCS#8 by default with -nodes.
        assert!(
            tag == pem_tags::PKCS8_PRIVATE_KEY || tag == pem_tags::RSA_PRIVATE_KEY,
            "Expected PKCS#8 or PKCS#1 format, got: {}",
            tag
        );
    }

    #[test]
    fn test_read_private_key_der_returns_zeroizing_wrapper() {
        // The DER is returned in a Zeroizing<Vec<u8>> so the plaintext-key buffer is
        // scrubbed on drop. Bind it to the exact type to lock the contract: if someone
        // reverts the return to a bare Vec<u8>, this stops compiling. Zeroizing derefs
        // to the slice, so downstream `&[u8]` callers are unaffected (see the signing
        // parity test in rsa_signer.rs).
        let (der, _tag): (zeroize::Zeroizing<Vec<u8>>, String) =
            read_private_key_der("../../tst/certs/rsa-2048-key.pem").unwrap();
        // Deref still exposes the bytes exactly as before.
        assert!(der.len() > 100);
    }

    #[test]
    fn test_read_certificate_file_not_found() {
        let result = read_certificate_der("nonexistent.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_read_certificate_chain_none_is_empty() {
        // No `--intermediates` supplied → empty chain, not an error.
        assert!(read_certificate_chain_der(None).unwrap().is_empty());
    }

    #[test]
    fn test_read_certificate_chain_collects_all_blocks() {
        // ratest-chain.pem holds two CERTIFICATE blocks (see pipeline.rs) — the
        // loader must return BOTH, in order, unlike read_certificate_der which
        // returns only the first.
        let chain = read_certificate_chain_der(Some("../../tst/certs/ratest-chain.pem")).unwrap();
        assert_eq!(chain.len(), 2, "ratest-chain.pem should yield two certs");
        assert!(chain.iter().all(|d| d.len() > 100));
    }

    #[test]
    fn test_read_certificate_chain_missing_file_is_error() {
        assert!(read_certificate_chain_der(Some("nonexistent-chain.pem")).is_err());
    }

    #[test]
    fn test_read_certificate_chain_rejects_non_certificate_block() {
        // Pointing --intermediates at a private-key PEM (a common operator
        // mistake) must error loudly, not silently yield an empty chain.
        let err = read_certificate_chain_der(Some("../../tst/certs/rsa-2048-key.pem"))
            .expect_err("a key PEM must be rejected as a chain");
        assert!(err.contains("non-CERTIFICATE"), "got: {err}");
    }

    #[test]
    fn test_read_private_key_file_not_found() {
        let result = read_private_key_der("nonexistent.pem");
        assert!(result.is_err());
    }
}
