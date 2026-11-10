//! ECDSA P-256 signing, using aws-lc-rs.
//!
//! This matches Go's `ecdsa.SignASN1` path in `file_system_signer.go`: we sign
//! the SigV4 "string to sign" with SHA-256 and produce an ASN.1/DER-encoded
//! signature (`SEQUENCE { r INTEGER, s INTEGER }`), then hex-encode it.
//!
//! NOTE: reached only by unit tests. The live EC crypto is `signer.rs`
//! (`FileSystemSigner`); this module is a parallel path — see `algorithm::sign_string`.

use crate::pem_tags;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

/// Sign the SigV4 "string to sign" with an EC P-256 private key.
///
/// `key_der`    — the raw DER bytes of the key.
/// `key_format` — the PEM tag: `EC PRIVATE KEY` (SEC1) or `PRIVATE KEY` (PKCS#8).
/// Returns the signature as a lowercase hex string.
///
/// Note: ECDSA produces a fresh random value on every signature, so signing the
/// same input twice gives different bytes. That is expected and matches Go, which
/// also uses a randomized nonce. We therefore never assert byte-equality for ECDSA;
/// we verify the signature is valid instead.
pub fn sign_with_ecdsa(
    key_der: &[u8],
    key_format: &str,
    string_to_sign: &str,
) -> Result<String, String> {
    // `ECDSA_P256_SHA256_ASN1_SIGNING` selects: P-256 curve, SHA-256 digest,
    // ASN.1/DER signature encoding — exactly what AWS expects and what Go emits.
    let algorithm = &ECDSA_P256_SHA256_ASN1_SIGNING;

    // Load the key. The two PEM formats need two different constructors:
    //   - PKCS#8 ("PRIVATE KEY")    -> EcdsaKeyPair::from_pkcs8
    //   - SEC1   ("EC PRIVATE KEY") -> EcdsaKeyPair::from_private_key_der
    let key_pair = match key_format {
        pem_tags::PKCS8_PRIVATE_KEY => EcdsaKeyPair::from_pkcs8(algorithm, key_der)
            .map_err(|e| format!("Failed to parse PKCS#8 EC key: {}", e))?,
        pem_tags::EC_PRIVATE_KEY => EcdsaKeyPair::from_private_key_der(algorithm, key_der)
            .map_err(|e| format!("Failed to parse SEC1 EC key: {}", e))?,
        _ => return Err(format!("Unsupported key format for ECDSA: {}", key_format)),
    };

    // ECDSA needs secure random bytes to generate the per-signature nonce.
    let rng = SystemRandom::new();

    // Sign: hashes `string_to_sign` with SHA-256 and returns the DER signature bytes.
    let signature = key_pair
        .sign(&rng, string_to_sign.as_bytes())
        .map_err(|e| format!("ECDSA signing failed: {}", e))?;

    // Hex-encode the DER signature, matching Go's hex.EncodeToString.
    Ok(hex::encode(signature.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, KeyPair, UnparsedPublicKey};

    /// Generate a fresh P-256 key in PKCS#8 DER, returning (pkcs8_der).
    /// Used so the tests don't depend on a key file existing on disk.
    fn generate_pkcs8_key() -> Vec<u8> {
        let rng = SystemRandom::new();
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("key generation should succeed")
            .as_ref()
            .to_vec()
    }

    #[test]
    fn test_sign_with_ecdsa_pkcs8() {
        let pkcs8_der = generate_pkcs8_key();

        let string_to_sign = "AWS4-X509-ECDSA-SHA256\n20240115T123000Z\n20240115/us-east-1/rolesanywhere/aws4_request\nabcdef1234567890";

        let result = sign_with_ecdsa(&pkcs8_der, pem_tags::PKCS8_PRIVATE_KEY, string_to_sign);
        assert!(result.is_ok(), "Signing with PKCS#8 key should succeed");

        let signature_hex = result.unwrap();
        // ECDSA DER signature is variable length but always non-empty.
        assert!(!signature_hex.is_empty(), "Signature should not be empty");
        // Should be valid lowercase hex.
        assert!(
            signature_hex.chars().all(|c| c.is_ascii_hexdigit()),
            "Signature should be valid hex"
        );
        assert_eq!(
            signature_hex,
            signature_hex.to_lowercase(),
            "Signature should be lowercase hex"
        );
    }

    #[test]
    fn test_sign_with_ecdsa_invalid_key_bytes() {
        let invalid_der = vec![0x30, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];
        let result = sign_with_ecdsa(&invalid_der, pem_tags::EC_PRIVATE_KEY, "test");
        assert!(result.is_err(), "Invalid key bytes should produce an error");
        let err = result.unwrap_err();
        assert!(
            err.contains("Failed to parse SEC1 EC key"),
            "Error should describe the parse failure, got: {}",
            err
        );
    }

    #[test]
    fn test_sign_with_ecdsa_invalid_pkcs8_bytes() {
        let invalid_der = vec![0x30, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];
        let result = sign_with_ecdsa(&invalid_der, pem_tags::PKCS8_PRIVATE_KEY, "test");
        assert!(
            result.is_err(),
            "Invalid PKCS#8 bytes should produce an error"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("Failed to parse PKCS#8 EC key"),
            "Error should describe the parse failure, got: {}",
            err
        );
    }

    #[test]
    fn test_sign_with_ecdsa_unsupported_format() {
        let result = sign_with_ecdsa(&[0x00], pem_tags::RSA_PRIVATE_KEY, "test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("Unsupported key format for ECDSA"),
            "Error should indicate unsupported format, got: {}",
            err
        );
    }

    /// Verify the signature actually validates against the matching public key.
    /// This is the right correctness check for ECDSA (we can't compare bytes
    /// because the signature is randomized).
    #[test]
    fn test_sign_with_ecdsa_signature_verifies() {
        let rng = SystemRandom::new();

        // Generate a key pair and keep both the PKCS#8 bytes and the public key.
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();

        let message = "test message for verification";
        let signature_hex =
            sign_with_ecdsa(pkcs8.as_ref(), pem_tags::PKCS8_PRIVATE_KEY, message).unwrap();
        let signature_bytes = hex::decode(&signature_hex).unwrap();

        // Verify with the public key using the matching ASN.1 verification algorithm.
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key_bytes);
        assert!(
            public_key
                .verify(message.as_bytes(), &signature_bytes)
                .is_ok(),
            "Signature should verify against the corresponding public key"
        );
    }

    /// ECDSA-1: ECDSA uses a fresh random nonce per signature, so signing the SAME
    /// message twice must yield DIFFERENT bytes — and both must still verify. This
    /// guards against a catastrophic regression to a fixed/deterministic nonce (which
    /// leaks the private key) that the single-signature verify test above would not
    /// catch. Uses the committed EC fixture.
    #[test]
    fn test_sign_with_ecdsa_is_randomized() {
        use crate::key_reader::read_private_key_der;
        let (key_der, key_format) =
            read_private_key_der("../../tst/certs/ec-p256-key.pem").expect("read ec fixture");

        let message = "AWS4-X509-ECDSA-SHA256\n20240115T123000Z\nscope\nhash";
        let sig1 = sign_with_ecdsa(&key_der, &key_format, message).unwrap();
        let sig2 = sign_with_ecdsa(&key_der, &key_format, message).unwrap();
        assert_ne!(
            sig1, sig2,
            "ECDSA must use a random nonce: identical input must NOT produce identical bytes"
        );
    }
}
