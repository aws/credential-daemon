//! RSA signing, using aws-lc-rs.
//!
//! This matches Go's RSA path in `file_system_signer.go`
//! (`rsa.SignPKCS1v15(rand, key, crypto.SHA256, sha256(stringToSign))`): we sign
//! the SigV4 "string to sign" with PKCS#1 v1.5 padding over SHA-256, then
//! hex-encode the result. It is the RSA counterpart of `ecdsa_signer.rs`.
//!
//! NOTE: reached only by unit tests. The live RSA crypto is `signer.rs`
//! (`FileSystemSigner`); this module is a parallel path — see `algorithm::sign_string`.

use crate::pem_tags;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeyPair as RsaKeyPair;
use aws_lc_rs::signature::RSA_PKCS1_SHA256;

/// Sign the SigV4 "string to sign" with an RSA private key.
///
/// `key_der`    — the raw DER bytes of the key.
/// `key_format` — the PEM tag: `PRIVATE KEY` (PKCS#8) or `RSA PRIVATE KEY` (PKCS#1).
/// Returns the signature as a lowercase hex string.
///
/// aws-lc-rs hashes the message with SHA-256 internally and applies PKCS#1 v1.5
/// padding, producing byte-for-byte identical output to the Go reference.
pub fn sign_with_rsa(
    key_der: &[u8],
    key_format: &str,
    string_to_sign: &str,
) -> Result<String, String> {
    // Load the key. The two PEM formats need two different constructors:
    //   - PKCS#8 ("PRIVATE KEY")     -> RsaKeyPair::from_pkcs8
    //   - PKCS#1 ("RSA PRIVATE KEY") -> RsaKeyPair::from_der
    let key_pair = match key_format {
        pem_tags::PKCS8_PRIVATE_KEY => RsaKeyPair::from_pkcs8(key_der)
            .map_err(|e| format!("Failed to parse PKCS#8 RSA key: {}", e))?,
        pem_tags::RSA_PRIVATE_KEY => RsaKeyPair::from_der(key_der)
            .map_err(|e| format!("Failed to parse PKCS#1 RSA key: {}", e))?,
        _ => return Err(format!("Unsupported key format for RSA: {}", key_format)),
    };

    // The RSA signature is always the same size as the key's modulus
    // (256 bytes for an RSA-2048 key), so we allocate a buffer of that length.
    let mut signature = vec![0u8; key_pair.public_modulus_len()];

    // aws-lc-rs needs a random source even though PKCS#1 v1.5 RSA is deterministic;
    // the output does not depend on the random bytes for this scheme.
    let rng = SystemRandom::new();

    // Sign: hashes `string_to_sign` with SHA-256 and writes the signature into `signature`.
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &rng,
            string_to_sign.as_bytes(),
            &mut signature,
        )
        .map_err(|e| format!("RSA signing failed: {}", e))?;

    // Hex-encode the raw signature bytes, matching Go's hex.EncodeToString.
    Ok(hex::encode(signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_reader::read_private_key_der;

    /// RSA PKCS#1 v1.5 is DETERMINISTIC: signing the same input twice yields the same
    /// bytes (unlike ECDSA, which is randomized — see ecdsa_signer.rs). The known-answer
    /// test below covers success/length/correctness, so this test only documents the
    /// determinism property explicitly.
    #[test]
    fn test_sign_with_rsa_is_deterministic() {
        let (key_der, key_format) =
            read_private_key_der("../../tst/certs/rsa-2048-key.pem").unwrap();

        let string_to_sign = "AWS4-X509-RSA-SHA256\n20240115T123000Z\n20240115/us-east-1/rolesanywhere/aws4_request\nabcdef1234567890";

        let signature1 = sign_with_rsa(&key_der, &key_format, string_to_sign).unwrap();
        let signature2 = sign_with_rsa(&key_der, &key_format, string_to_sign).unwrap();
        assert_eq!(
            signature1, signature2,
            "RSA signing should be deterministic"
        );
    }

    /// Known-answer test: lock the RSA signature to a fixed value that we verified
    /// is byte-for-byte identical to `openssl dgst -sha256 -sign` (the same output
    /// Go's rsa.SignPKCS1v15 produces). If the hash-then-sign layering ever breaks,
    /// this test catches it — unlike a length/determinism check.
    #[test]
    fn test_sign_with_rsa_known_answer() {
        // key_der is a Zeroizing<Vec<u8>> (key_reader scrubs the plaintext key on drop);
        // it deref-coerces to &[u8] here, so the signer sees identical bytes.
        let (key_der, key_format) =
            read_private_key_der("../../tst/certs/rsa-2048-key.pem").unwrap();

        let string_to_sign = "AWS4-X509-RSA-SHA256\n20240115T123000Z\n20240115/us-east-1/rolesanywhere/aws4_request\nabcdef1234567890";

        let signature = sign_with_rsa(&key_der, &key_format, string_to_sign).unwrap();

        let expected = "ab90de979923163232b28e6b95be6e3d8b5625182e144123c01f1f16754dd4ab31aa51409b601bb76032020b04ad514ab3122c4cd0e53f285178fad2c61aea6bbed9be34f908b5e53244ea97846e34ebafd4fa0f504b5605dac5a0d025bc42b1c68cdc31a08d05f1039d89b6b9aa2fe2670b8da44f5ac7ce7b0ff125b8fc522c7f6ec212e2984b284e29159cd67577defc649de53a0c41f752f5197fe5288d25ee47ddcab3098b5ebe86fca544ed1b181d8270ac6f9bbe3ac8a155bfbd0792a616b65cf07bc08fb73341cb4de3b721703d6cc1254b385d5b38b73ef9d318004ff47bb818ea7664ce2d9c12698a922ea99bf463189b787d081fdbc21a639f19b7";
        assert_eq!(
            signature, expected,
            "RSA signature must match the openssl/Go reference vector"
        );
    }
}
