//! A `Signer` abstraction over a key store. File-based today. Additional
//! implementations (PKCS#11, TPM, cert-store) plug in behind this trait.
//! Consumed by the `sign-string` CLI command AND, via `identity::FileSystemIdentity`,
//! by the `pipeline::generate_credentials` credential path — both signing paths now
//! go through this one `FileSystemSigner`, so they cannot drift.

use crate::key_reader::read_private_key_der;
use crate::pem_tags;
use crate::types::SigningAlgorithm;

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeyPair as RsaKeyPair;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256,
};

/// A source of signatures backed by some key store.
pub trait Signer {
    /// The signing algorithm implied by the key type (RSA vs ECDSA).
    fn algorithm(&self) -> &SigningAlgorithm;

    /// The public key marshalled EXACTLY as Go marshals it for the sign-string
    /// fixed test string: EC = uncompressed SEC1 point `0x04||X||Y`
    /// (== Go elliptic.Marshal); RSA = PKCS#1 `RSAPublicKey` DER
    /// (== Go x509.MarshalPKCS1PublicKey).
    fn public_key_marshalled(&self) -> Result<Vec<u8>, String>;

    /// Sign `string_to_sign`, returning the raw signature bytes (not hex).
    /// aws-lc-rs hashes the message internally with SHA-256.
    fn sign(&self, string_to_sign: &[u8]) -> Result<Vec<u8>, String>;
}

/// The two file-key algorithms this signer supports.
enum KeyMaterial {
    Rsa(RsaKeyPair),
    Ecdsa(EcdsaKeyPair),
}

/// A `Signer` backed by a private key file on disk.
pub struct FileSystemSigner {
    material: KeyMaterial,
    algorithm: SigningAlgorithm,
}

impl FileSystemSigner {
    /// Load a private key from a PEM file. Reuses `key_reader` for PEM->DER and
    /// the PEM tag (plus a PKCS#8 OID probe) to pick RSA vs EC.
    pub fn from_key_file(key_path: &str) -> Result<Self, String> {
        let (key_der, tag) = read_private_key_der(key_path)?;
        Self::from_der(&key_der, &tag)
    }

    /// Build a signer from already-read key DER bytes and its PEM tag. This is the
    /// tag-dispatch half of `from_key_file`, split out so a caller that has already
    /// read the DER (e.g. `identity::FileSystemIdentity`) can reuse the exact same
    /// RSA/EC selection — and thus produce byte-identical error text — without
    /// re-reading the file.
    pub fn from_der(key_der: &[u8], tag: &str) -> Result<Self, String> {
        match tag {
            pem_tags::RSA_PRIVATE_KEY => Self::rsa_from_der(key_der, false),
            pem_tags::EC_PRIVATE_KEY => Self::ec_from_der(key_der, false),
            pem_tags::PKCS8_PRIVATE_KEY => {
                // PKCS#8 can hold either RSA or EC; try RSA, then EC. If both
                // fail, surface both causes so the message doesn't blame the
                // wrong algorithm for a corrupt key.
                match Self::rsa_from_der(key_der, true) {
                    Ok(s) => Ok(s),
                    Err(rsa_err) => Self::ec_from_der(key_der, true).map_err(|ec_err| {
                        format!(
                            "Failed to parse PKCS#8 key as RSA ({}) or EC ({})",
                            rsa_err, ec_err
                        )
                    }),
                }
            }
            other => Err(format!("Unsupported private key PEM tag: {}", other)),
        }
    }

    fn rsa_from_der(der: &[u8], pkcs8: bool) -> Result<Self, String> {
        let kp = if pkcs8 {
            RsaKeyPair::from_pkcs8(der)
                .map_err(|e| format!("Failed to parse PKCS#8 RSA key: {}", e))?
        } else {
            RsaKeyPair::from_der(der)
                .map_err(|e| format!("Failed to parse PKCS#1 RSA key: {}", e))?
        };
        Ok(Self {
            material: KeyMaterial::Rsa(kp),
            algorithm: SigningAlgorithm::RsaSha256,
        })
    }

    fn ec_from_der(der: &[u8], pkcs8: bool) -> Result<Self, String> {
        let kp = if pkcs8 {
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der)
                .map_err(|e| format!("Failed to parse PKCS#8 EC key: {}", e))?
        } else {
            EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_ASN1_SIGNING, der)
                .map_err(|e| format!("Failed to parse SEC1 EC key: {}", e))?
        };
        Ok(Self {
            material: KeyMaterial::Ecdsa(kp),
            algorithm: SigningAlgorithm::EcdsaSha256,
        })
    }
}

impl Signer for FileSystemSigner {
    fn algorithm(&self) -> &SigningAlgorithm {
        &self.algorithm
    }

    fn public_key_marshalled(&self) -> Result<Vec<u8>, String> {
        // CRITICAL: use `.as_ref()` (RSA -> PKCS#1 DER; EC -> uncompressed point).
        // Do NOT use `.as_der()` on the RSA public key — that emits SPKI (wrong target).
        match &self.material {
            KeyMaterial::Rsa(kp) => Ok(kp.public_key().as_ref().to_vec()),
            KeyMaterial::Ecdsa(kp) => Ok(kp.public_key().as_ref().to_vec()),
        }
    }

    fn sign(&self, string_to_sign: &[u8]) -> Result<Vec<u8>, String> {
        let rng = SystemRandom::new();
        match &self.material {
            KeyMaterial::Rsa(kp) => {
                let mut sig = vec![0u8; kp.public_modulus_len()];
                kp.sign(&RSA_PKCS1_SHA256, &rng, string_to_sign, &mut sig)
                    .map_err(|e| format!("RSA signing failed: {}", e))?;
                Ok(sig)
            }
            KeyMaterial::Ecdsa(kp) => {
                let sig = kp
                    .sign(&rng, string_to_sign)
                    .map_err(|e| format!("ECDSA signing failed: {}", e))?;
                Ok(sig.as_ref().to_vec())
            }
        }
    }
}

/// Build the EXACT fixed string Go's `sign-string` signs:
///   "AWS Roles Anywhere Credential Helper Signing Test"
///   + "1"                                       (ASCII digit 0x31, the version)
///   + SHA256("IAM RA" || public_key_marshalled())   (raw 32 bytes, not hex)
pub fn build_sign_string_payload(signer: &dyn Signer) -> Result<Vec<u8>, String> {
    const PREFIX: &str = "AWS Roles Anywhere Credential Helper Signing Test";
    const VERSION: &str = "1"; // the fixed test-string version, as an ASCII digit
    const IAM_RA: &[u8] = b"IAM RA";

    let pubkey = signer.public_key_marshalled()?;

    // SHA256("IAM RA" || pubkey)
    let mut suffix_input = Vec::with_capacity(IAM_RA.len() + pubkey.len());
    suffix_input.extend_from_slice(IAM_RA);
    suffix_input.extend_from_slice(&pubkey);
    let digest_suffix = digest::digest(&digest::SHA256, &suffix_input);

    let mut payload =
        Vec::with_capacity(PREFIX.len() + VERSION.len() + digest_suffix.as_ref().len());
    payload.extend_from_slice(PREFIX.as_bytes());
    payload.extend_from_slice(VERSION.as_bytes());
    payload.extend_from_slice(digest_suffix.as_ref());
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    // KAT captured from openssl/Go on the committed fixtures.
    const EC_PUB_HEX: &str = "04905ca327a8431182978fc060fd808a6da6a5b55c62965f55e2a66f886cd82e7d1753e1b68026df113cd3106d090a7ed1359b438587e8cfc3ae3d673c54a98c4e";
    const RSA_PUB_PREFIX: &str = "3082010a0282010100abfafc29"; // PKCS#1 RSAPublicKey DER start
    const RSA_PUB_SUFFIX: &str = "0203010001"; // ...publicExponent 65537

    #[test]
    fn ec_public_key_is_uncompressed_point() {
        let s = FileSystemSigner::from_key_file("../../tst/certs/ec-p256-key.pem").unwrap();
        let pk = s.public_key_marshalled().unwrap();
        assert_eq!(
            hex::encode(&pk),
            EC_PUB_HEX,
            "EC pubkey must be 0x04||X||Y == Go elliptic.Marshal"
        );
        assert_eq!(pk.len(), 65, "P-256 uncompressed point is 65 bytes");
    }

    #[test]
    fn rsa_public_key_is_pkcs1_der() {
        let s = FileSystemSigner::from_key_file("../../tst/certs/rsa-2048-key.pem").unwrap();
        let pk = s.public_key_marshalled().unwrap();
        let h = hex::encode(&pk);
        assert!(
            h.starts_with(RSA_PUB_PREFIX),
            "RSA pubkey must be PKCS#1 DER (not SPKI), got {}",
            &h[..h.len().min(40)]
        );
        assert!(
            h.ends_with(RSA_PUB_SUFFIX),
            "RSA pubkey must end with publicExponent 65537"
        );
        assert_eq!(
            pk.len(),
            270,
            "RSA-2048 PKCS#1 RSAPublicKey DER is 270 bytes"
        );
    }

    #[test]
    fn algorithm_detected_from_key() {
        let rsa = FileSystemSigner::from_key_file("../../tst/certs/rsa-2048-key.pem").unwrap();
        assert_eq!(rsa.algorithm().as_str(), "AWS4-X509-RSA-SHA256");
        let ec = FileSystemSigner::from_key_file("../../tst/certs/ec-p256-key.pem").unwrap();
        assert_eq!(ec.algorithm().as_str(), "AWS4-X509-ECDSA-SHA256");
    }

    #[test]
    fn from_der_matches_from_key_file() {
        // from_key_file is read-then-from_der. Prove the split preserves behavior —
        // building from already-read (der, tag) selects the same algorithm as reading the file.
        // This is the seam identity::FileSystemIdentity reuses to keep error parity.
        use crate::key_reader::read_private_key_der;
        for path in [
            "../../tst/certs/rsa-2048-key.pem",
            "../../tst/certs/ec-p256-key.pem",
        ] {
            let (der, tag) = read_private_key_der(path).unwrap();
            let via_der = FileSystemSigner::from_der(&der, &tag).unwrap();
            let via_file = FileSystemSigner::from_key_file(path).unwrap();
            assert_eq!(
                via_der.algorithm().as_str(),
                via_file.algorithm().as_str(),
                "from_der and from_key_file must select the same algorithm for {path}"
            );
        }
    }

    #[test]
    fn from_der_unsupported_tag_errors_like_file_path() {
        // The tag-dispatch default arm still produces the exact "Unsupported private key
        // PEM tag" message on the from_der path (the error text FileSystemIdentity relies on).
        // Match rather than unwrap_err() because FileSystemSigner is not Debug.
        match FileSystemSigner::from_der(b"anything", "DSA PRIVATE KEY") {
            Ok(_) => panic!("unsupported tag must error"),
            Err(err) => assert!(
                err.contains("Unsupported private key PEM tag"),
                "got: {err}"
            ),
        }
    }

    #[test]
    fn rsa_sign_is_deterministic_and_256_bytes() {
        let s = FileSystemSigner::from_key_file("../../tst/certs/rsa-2048-key.pem").unwrap();
        let a = s.sign(b"hello").unwrap();
        let b = s.sign(b"hello").unwrap();
        assert_eq!(a, b, "RSA PKCS#1 v1.5 is deterministic");
        assert_eq!(a.len(), 256, "RSA-2048 raw signature is 256 bytes");
    }

    #[test]
    fn malformed_key_file_errors() {
        // A malformed key must error cleanly (not panic, not mis-dispatch).
        let result = FileSystemSigner::from_key_file("../../tst/certs/malformed.pem");
        assert!(result.is_err(), "malformed key must produce an error");
    }

    #[test]
    fn p384_key_rejected_cleanly() {
        // aws-lc-rs's EcdsaKeyPair is pinned to P-256 (ECDSA_P256_SHA256_ASN1_SIGNING),
        // so a valid P-384 key fails to load (non-panic Err). Go ACCEPTS and signs P-384,
        // so this is an intentional, documented divergence: we support P-256 EC signing only.
        let result = FileSystemSigner::from_key_file("../../tst/certs/p384-key-pkcs8.pem");
        assert!(
            result.is_err(),
            "P-384 key must be rejected by the P-256-only signer"
        );
    }

    #[test]
    fn encrypted_pkcs8_key_rejected() {
        // Encrypted PKCS#8 ("ENCRYPTED PRIVATE KEY") is a tag key_reader does not
        // recognize, so it errors "No private key block found" (a feature gap vs Go's
        // --pkcs8-password: we do not support decrypting password-protected keys). Lock
        // the clean reject. The message is admittedly misleading for an encrypted key.
        let result = FileSystemSigner::from_key_file("../../tst/certs/enc-rsa-key.pem");
        assert!(
            result.is_err(),
            "encrypted PKCS#8 key must be rejected (no decryption support)"
        );
    }

    #[test]
    fn rsa_1024_key_rejected_below_minimum() {
        // aws-lc-rs enforces a 2048-bit RSA minimum, so a 1024-bit key fails to load. Go
        // has NO minimum and signs it — an intentional, documented divergence, and
        // arguably a security improvement (we refuse weak keys).
        let result = FileSystemSigner::from_key_file("../../tst/certs/rsa-1024-key.pem");
        assert!(
            result.is_err(),
            "RSA-1024 key must be rejected (aws-lc-rs 2048-bit minimum)"
        );
    }

    // Full preimage = "AWS Roles Anywhere Credential Helper Signing Test" + "1"
    //   + SHA256("IAM RA" || public_key_marshalled()).  Captured from the Go binary.
    const EC_PREIMAGE_HEX: &str = "41575320526f6c657320416e7977686572652043726564656e7469616c2048656c706572205369676e696e672054657374313b5358c6d943c7222df68ae1f2898453e3c0eeffeb24b8e8490689e075a11833";
    const RSA_PREIMAGE_HEX: &str = "41575320526f6c657320416e7977686572652043726564656e7469616c2048656c706572205369676e696e67205465737431f93e05142471d9a193844f7a4271d83f266b812862a38bb127783f2246a6c86f";

    #[test]
    fn ec_sign_string_payload_matches_go() {
        let s = FileSystemSigner::from_key_file("../../tst/certs/ec-p256-key.pem").unwrap();
        let payload = build_sign_string_payload(&s).unwrap();
        assert_eq!(hex::encode(&payload), EC_PREIMAGE_HEX);
        assert_eq!(
            payload.len(),
            82,
            "49-byte prefix + 1-byte '1' + 32-byte SHA256"
        );
    }

    #[test]
    fn rsa_sign_string_payload_matches_go() {
        let s = FileSystemSigner::from_key_file("../../tst/certs/rsa-2048-key.pem").unwrap();
        let payload = build_sign_string_payload(&s).unwrap();
        assert_eq!(hex::encode(&payload), RSA_PREIMAGE_HEX);
        assert_eq!(payload.len(), 82);
    }

    #[test]
    fn version_byte_is_ascii_one_not_0x01() {
        let s = FileSystemSigner::from_key_file("../../tst/certs/rsa-2048-key.pem").unwrap();
        let payload = build_sign_string_payload(&s).unwrap();
        // The version byte sits immediately after the fixed prefix; it must be
        // ASCII '1' (0x31), NOT the binary byte 0x01.
        let prefix_len = "AWS Roles Anywhere Credential Helper Signing Test".len();
        assert_eq!(
            payload[prefix_len], 0x31,
            "version must be ASCII '1', not byte 0x01"
        );
    }

    // End-to-end signature KAT: signing the RSA preimage reproduces Go sign-string
    // (deterministic PKCS#1 v1.5). Verified == openssl on the committed fixture.
    const RSA_SIGN_STRING_HEX: &str = "7d6445d8505f8117a1bf0e5ed408ac9f9499031a4b0306cd2b49d12424d0993d956bea117e73f09dd840a38c26c5196cd572752f3f14b407f4faba19d07ecd2a1df0e0951818dfa640d91d7d53060287b1975fdfdfab73bdcc1606cbeea89c1fcc834d62a87c3601f7561565245b59f80195656545c2cefb0672f691269e3c3f47453118d62b55e13274e5a8202a2f141f6f82d1e2b45da427ae88d3a5a9c05e4b29f1da1e4b4f5173d7fbcb8755497eefa1188f20077ec359783edfaddb24aa189423b5dc059e94a8b385b9446f729326332bb5a24511c8072d36b2a0b9af7959518677052026a849c2789e9d4628cfb3ebe5d530d3700e47c1131dfa5839cc";

    #[test]
    fn rsa_sign_string_signature_matches_go() {
        let s = FileSystemSigner::from_key_file("../../tst/certs/rsa-2048-key.pem").unwrap();
        let payload = build_sign_string_payload(&s).unwrap();
        let sig = s.sign(&payload).unwrap();
        assert_eq!(
            hex::encode(&sig),
            RSA_SIGN_STRING_HEX,
            "RSA sign-string output must match the Go binary byte-for-byte"
        );
    }

    /// The differential `signing` fuzz target signs through `algorithm::sign_string`
    /// (a test-only crypto copy — see the NOTE in algorithm.rs), but production signs
    /// through `FileSystemSigner::sign` (this file). RSA PKCS#1 v1.5 is deterministic,
    /// so proving the two paths produce IDENTICAL bytes for the same string-to-sign
    /// transfers the fuzzer's Go byte-equality proof onto the code production actually
    /// runs. It is also the guard that lets `rsa_signer.rs`/`ecdsa_signer.rs` be deleted
    /// later without losing coverage.
    ///
    /// RSA only: ECDSA is randomized, so dead-vs-live byte-equality is impossible. The
    /// live ECDSA path is covered by `ec_sign_string_signature_verifies` above; closing
    /// the live-ECDSA-vs-Go gap requires repointing the fuzzer itself at this signer.
    #[test]
    fn algorithm_sign_string_matches_filesystemsigner_rsa_bytes() {
        use crate::algorithm::sign_string;
        use crate::key_reader::read_private_key_der;
        use crate::types::SigningAlgorithm;

        // A fixed string-to-sign; the property under test is byte-equality of the two
        // signing paths, so the exact content only needs to be stable.
        let sts = "AWS4-X509-RSA-SHA256\n20240115T123000Z\n\
                   20240115/us-east-1/rolesanywhere/aws4_request\n\
                   2ccabf6a9fb9684cb23878e5ed948ba0e04f2f190aed150f29acd360734aa944";

        let (key_der, tag) = read_private_key_der("../../tst/certs/rsa-2048-key.pem")
            .expect("read rsa-2048-key.pem fixture");

        // Dead path (what the fuzzer exercises): returns lowercase hex.
        let via_dead = sign_string(&key_der, &tag, &SigningAlgorithm::RsaSha256, sts)
            .expect("algorithm::sign_string RSA");

        // Live path (what production runs): returns raw bytes -> hex to compare.
        let signer =
            FileSystemSigner::from_der(&key_der, &tag).expect("FileSystemSigner from RSA DER");
        let via_live = hex::encode(
            signer
                .sign(sts.as_bytes())
                .expect("FileSystemSigner::sign RSA"),
        );

        assert_eq!(
            via_dead, via_live,
            "RSA sign-string bytes must be identical on the fuzzed (algorithm::sign_string) \
             and live (FileSystemSigner::sign) paths, so the differential fuzzer's Go \
             byte-equality proof transfers to the code production actually runs"
        );
    }

    /// End-to-end EC sign-string correctness. ECDSA is randomized (random nonce per
    /// signature), so byte-equality is impossible — unlike the RSA KAT above. The
    /// correct check is sign -> verify: sign the REAL sign-string preimage through
    /// FileSystemSigner, then verify the signature under the EC public key. Without
    /// this, the EC branch of `sign()` is never exercised for correctness (the EC
    /// preimage test above only checks the bytes fed INTO the signer).
    ///
    /// Uses the VERIFICATION algorithm `ECDSA_P256_SHA256_ASN1` (not the `_SIGNING`
    /// constant): the signer emits ASN.1/DER, both ends hash the message internally,
    /// and `public_key_marshalled()` returns the uncompressed SEC1 point that
    /// `UnparsedPublicKey` expects for this algorithm.
    #[test]
    fn ec_sign_string_signature_verifies() {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

        let signer = FileSystemSigner::from_key_file("../../tst/certs/ec-p256-key.pem").unwrap();
        let payload = build_sign_string_payload(&signer).unwrap();
        let signature = signer.sign(&payload).unwrap();

        let public_key_bytes = signer.public_key_marshalled().unwrap();
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key_bytes);
        assert!(
            public_key.verify(&payload, &signature).is_ok(),
            "EC sign-string signature must verify against the EC public key"
        );
    }

    /// Negative control for the verify test above: a signature must NOT validate
    /// against a different message. This proves `verify` is discriminating, so the
    /// positive assertion isn't vacuously true.
    #[test]
    fn ec_verify_fails_on_tampered_message() {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

        let signer = FileSystemSigner::from_key_file("../../tst/certs/ec-p256-key.pem").unwrap();
        let payload = build_sign_string_payload(&signer).unwrap();
        let signature = signer.sign(&payload).unwrap();
        let public_key_bytes = signer.public_key_marshalled().unwrap();

        let mut tampered = payload.clone();
        tampered[0] ^= 0x01; // flip one bit of the verified message
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key_bytes);
        assert!(
            public_key.verify(&tampered, &signature).is_err(),
            "verify must reject a signature over a different message"
        );
    }
}
