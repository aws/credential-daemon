//! Deciding which signing algorithm to use, and dispatching to the right signer.
//!
//! The private key tells us the algorithm:
//!
//! - `RSA PRIVATE KEY` (PKCS#1) -> always RSA
//! - `EC PRIVATE KEY` (SEC1) -> always ECDSA
//! - `PRIVATE KEY` (PKCS#8) -> could be either, so we read the algorithm OID
//!   stored inside the key to find out.

use crate::ecdsa_signer::sign_with_ecdsa;
use crate::pem_tags;
use crate::rsa_signer::sign_with_rsa;
use crate::types::SigningAlgorithm;
use der::Decode;
use pkcs8::PrivateKeyInfo;

/// Object identifier (OID) for RSA keys: `1.2.840.113549.1.1.1` (rsaEncryption).
/// Public so `cert_data` reads the same constant off the cert's SPKI.
pub const RSA_OID: &str = "1.2.840.113549.1.1.1";

/// Object identifier (OID) for EC keys: `1.2.840.10045.2.1` (id-ecPublicKey).
/// Public so `cert_data` reads the same constant off the cert's SPKI.
pub const EC_OID: &str = "1.2.840.10045.2.1";

/// Decide the signing algorithm from the PEM tag and key bytes.
///
/// For PKCS#8 keys (`PRIVATE KEY`) the tag alone is not enough, so we parse the
/// key's `PrivateKeyInfo` and read its algorithm OID. We use the `pkcs8` crate
/// for this instead of hand-writing an ASN.1 parser — it is simpler to read and
/// already handles malformed input safely.
pub fn detect_algorithm(pem_tag: &str, key_der: &[u8]) -> Result<SigningAlgorithm, String> {
    match pem_tag {
        pem_tags::RSA_PRIVATE_KEY => Ok(SigningAlgorithm::RsaSha256),
        pem_tags::EC_PRIVATE_KEY => Ok(SigningAlgorithm::EcdsaSha256),
        pem_tags::PKCS8_PRIVATE_KEY => detect_pkcs8_algorithm(key_der),
        _ => Err(format!("Unsupported private key PEM tag: {}", pem_tag)),
    }
}

/// Read the algorithm OID out of a PKCS#8 key to tell RSA and EC apart.
fn detect_pkcs8_algorithm(key_der: &[u8]) -> Result<SigningAlgorithm, String> {
    // PrivateKeyInfo is the PKCS#8 structure: { version, algorithm, privateKey }.
    // The `algorithm.oid` field is what we need.
    let info = PrivateKeyInfo::from_der(key_der)
        .map_err(|e| format!("Failed to parse PKCS#8 private key: {}", e))?;

    // Compare the OID (as a dotted string) against the two we support.
    let oid = info.algorithm.oid.to_string();
    if oid == RSA_OID {
        Ok(SigningAlgorithm::RsaSha256)
    } else if oid == EC_OID {
        Ok(SigningAlgorithm::EcdsaSha256)
    } else {
        Err(format!("Unsupported PKCS#8 algorithm OID: {}", oid))
    }
}

/// Send the signing work to the correct implementation for the chosen algorithm.
///
/// NOTE: this dispatcher (and the `rsa_signer`/`ecdsa_signer` it calls) is currently
/// reached only by unit tests. Both live signing flows — the credential pipeline and the
/// `sign-string` command — sign through `signer.rs` (`FileSystemSigner::sign`, which calls
/// aws-lc-rs directly), so this is a parallel implementation kept for its known-answer
/// tests. Safe to consolidate onto `FileSystemSigner` once confirmed. (Only
/// `detect_algorithm` above is on the live path — it is called from `identity.rs`.)
pub fn sign_string(
    key_der: &[u8],
    key_format: &str,
    algorithm: &SigningAlgorithm,
    string_to_sign: &str,
) -> Result<String, String> {
    match algorithm {
        SigningAlgorithm::RsaSha256 => sign_with_rsa(key_der, key_format, string_to_sign),
        SigningAlgorithm::EcdsaSha256 => sign_with_ecdsa(key_der, key_format, string_to_sign),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_reader::read_private_key_der;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

    #[test]
    fn test_detect_rsa_private_key_tag() {
        let result = detect_algorithm(pem_tags::RSA_PRIVATE_KEY, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "AWS4-X509-RSA-SHA256");
    }

    #[test]
    fn test_detect_ec_private_key_tag() {
        let result = detect_algorithm(pem_tags::EC_PRIVATE_KEY, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "AWS4-X509-ECDSA-SHA256");
    }

    #[test]
    fn test_detect_unsupported_tag() {
        let result = detect_algorithm("DSA PRIVATE KEY", &[]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Unsupported private key PEM tag")
        );
    }

    #[test]
    fn test_detect_pkcs8_rsa_key() {
        // Load a real RSA key in PKCS#8 format from the test fixtures. The fixture is
        // committed, so a read failure or a format change is a real test-environment
        // bug — assert it loudly. (An `if let Ok` / `if tag == ...` guard would let the
        // test pass having checked nothing if the fixture were missing or regenerated.)
        let (key_der, tag) = read_private_key_der("../../tst/certs/rsa-2048-key.pem")
            .expect("read rsa-2048-key.pem fixture");
        assert_eq!(
            tag,
            pem_tags::PKCS8_PRIVATE_KEY,
            "rsa-2048-key.pem fixture must be PKCS#8 (\"PRIVATE KEY\")"
        );
        let algo = detect_algorithm(pem_tags::PKCS8_PRIVATE_KEY, &key_der);
        assert!(algo.is_ok(), "Should detect RSA from PKCS#8: {:?}", algo);
        assert_eq!(algo.unwrap().as_str(), "AWS4-X509-RSA-SHA256");
    }

    #[test]
    fn test_detect_pkcs8_ec_key() {
        // Generate an EC P-256 key in PKCS#8 format in-memory.
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();

        let algo = detect_algorithm(pem_tags::PKCS8_PRIVATE_KEY, pkcs8.as_ref());
        assert!(algo.is_ok(), "Should detect EC from PKCS#8: {:?}", algo);
        assert_eq!(algo.unwrap().as_str(), "AWS4-X509-ECDSA-SHA256");
    }

    #[test]
    fn test_detect_pkcs8_invalid_bytes() {
        let invalid = vec![0x30, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];
        let result = detect_algorithm(pem_tags::PKCS8_PRIVATE_KEY, &invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_string_dispatches_to_rsa() {
        // Committed fixture; see test_detect_pkcs8_rsa_key for why we .expect() here.
        let (key_der, tag) = read_private_key_der("../../tst/certs/rsa-2048-key.pem")
            .expect("read rsa-2048-key.pem fixture");
        let string_to_sign = "test-string-to-sign";
        let result = sign_string(&key_der, &tag, &SigningAlgorithm::RsaSha256, string_to_sign);
        assert!(result.is_ok(), "RSA signing should succeed: {:?}", result);
        let sig = result.unwrap();
        // RSA-2048 produces 256 bytes = 512 hex chars.
        assert_eq!(sig.len(), 512);
    }

    #[test]
    fn test_sign_string_dispatches_to_ecdsa() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();

        let string_to_sign = "test-string-to-sign";
        let result = sign_string(
            pkcs8.as_ref(),
            pem_tags::PKCS8_PRIVATE_KEY,
            &SigningAlgorithm::EcdsaSha256,
            string_to_sign,
        );
        assert!(result.is_ok(), "ECDSA signing should succeed: {:?}", result);
        let sig = result.unwrap();
        assert!(!sig.is_empty());
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
