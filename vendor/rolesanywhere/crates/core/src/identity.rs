//! `CredentialIdentity` — the seam between "what key/cert do we sign with" and the
//! signing pipeline. The pipeline consumes `&dyn CredentialIdentity` instead of reading
//! cert/key file paths directly, so future key backends (PKCS#11, TPM, OS key stores)
//! can plug in behind this trait without touching `pipeline.rs`.
//!
//! `FileSystemIdentity` is the file-path backend — it reproduces exactly what the
//! pipeline does today (read cert, read key, detect algorithm, load the signer), so the
//! CLI/FFI path-based entry points behave byte-for-byte identically.

use crate::key_reader::read_certificate_der;
use crate::pipeline::PipelineError;
use crate::signer::{FileSystemSigner, Signer};
use crate::types::SigningAlgorithm;

/// A source of "a certificate (+ optional chain) and the ability to sign the SigV4
/// string-to-sign." This is exactly what `pipeline::sign_request` needs — nothing more:
///   - `certificate_der` feeds both the serial number and the `X-Amz-X509` header,
///   - `certificate_chain_der` feeds the `X-Amz-X509-Chain` header (empty = no chain),
///   - `signing_algorithm` picks the Authorization algorithm string,
///   - `sign` produces the raw signature bytes (the pipeline hex-encodes them).
///
/// No `Send + Sync` bound today — nothing consumes it yet (YAGNI). Add it when a
/// cross-thread consumer (e.g. a caching provider) needs to share an identity across threads.
pub trait CredentialIdentity {
    /// The leaf certificate DER (serial + `X-Amz-X509`).
    fn certificate_der(&self) -> &[u8];

    /// Intermediate certificate DERs, in order, for `X-Amz-X509-Chain`. Each element is
    /// one certificate's DER; the pipeline base64-encodes and comma-joins them. Default
    /// is "no chain."
    fn certificate_chain_der(&self) -> &[Vec<u8>] {
        &[]
    }

    /// The algorithm implied by the key type (RSA vs ECDSA).
    fn signing_algorithm(&self) -> &SigningAlgorithm;

    /// Sign `string_to_sign`, returning raw signature bytes (same contract as
    /// `Signer::sign`: aws-lc-rs hashes the message with SHA-256 internally).
    fn sign(&self, string_to_sign: &[u8]) -> Result<Vec<u8>, String>;
}

/// A `CredentialIdentity` backed by cert/key files on disk — the behavior the pipeline
/// has today, now behind the trait. Holds a ready `FileSystemSigner` (built eagerly in
/// `from_paths`) plus the leaf cert DER and any intermediate chain DERs.
pub struct FileSystemIdentity {
    signer: FileSystemSigner,
    cert_der: Vec<u8>,
    chain_der: Vec<Vec<u8>>,
}

impl FileSystemIdentity {
    /// Build an identity from cert/key/chain file paths. The read order and error
    /// variants are fixed so the CLI/FFI error text is stable:
    ///   1. read the certificate  -> `CertificateError`
    ///   2. read the private key   -> `PrivateKeyError`
    ///   3. detect the algorithm   -> `UnsupportedKeyType`   (unsupported key *type*)
    ///   4. construct the signer   -> `SigningError`         (recognized type, unusable key)
    ///   5. read + split the chain -> `CertificateError`
    ///
    /// Step 3 vs 4 are two distinct bad-key failure sites: an
    /// unsupported *type* (e.g. ed25519) fails detection; a weak/unusable *key* of a
    /// recognized type (e.g. RSA-1024 below the 2048 minimum, or P-384 on the P-256-only
    /// signer) passes detection but fails aws-lc-rs construction. `from_paths` builds the
    /// signer eagerly, so a construction failure surfaces at load time rather than at sign
    /// time — a timing shift no `generate_credentials`/CLI/FFI caller can observe (they do
    /// load+sign in one call).
    pub fn from_paths(
        cert_path: &str,
        key_path: &str,
        cert_chain_path: Option<&str>,
    ) -> Result<Self, PipelineError> {
        // 1. Certificate.
        let cert_der =
            read_certificate_der(cert_path).map_err(|reason| PipelineError::CertificateError {
                path: cert_path.to_string(),
                reason,
            })?;

        // 2. Private key DER + PEM tag. `key_der` is Zeroizing<Vec<u8>>;
        //    it derefs to &[u8] for the calls below and scrubs itself on drop.
        let (key_der, key_format) =
            crate::key_reader::read_private_key_der(key_path).map_err(|reason| {
                PipelineError::PrivateKeyError {
                    path: key_path.to_string(),
                    reason,
                }
            })?;

        // 3. Detect the algorithm from the key TYPE -> UnsupportedKeyType for
        //    an unsupported type. (See fn doc for the type-vs-unusable-key split.)
        let algorithm = crate::algorithm::detect_algorithm(&key_format, &key_der)
            .map_err(|detail| PipelineError::UnsupportedKeyType { detail })?;

        // 4. Construct the signer from the already-read DER via FileSystemSigner::from_der. A
        //    recognized-but-unusable key fails HERE — mapped to SigningError (not
        //    UnsupportedKeyType). (See fn doc for the type-vs-unusable-key split.)
        //    algorithm.as_str() gives the algorithm string used in the error.
        let signer = FileSystemSigner::from_der(&key_der, &key_format).map_err(|reason| {
            PipelineError::SigningError {
                algorithm: algorithm.as_str().to_string(),
                reason,
            }
        })?;

        // 5. Optional certificate chain (mirrors the pipeline's cert-chain header block). Read the file,
        //    parse all PEM blocks, keep only CERTIFICATE blocks' DER. The base64/join and the
        //    non-empty guard stay in the pipeline; here we only supply the DER list.
        let chain_der = match cert_chain_path {
            Some(chain_path) => {
                let chain_contents =
                    std::fs::read(chain_path).map_err(|e| PipelineError::CertificateError {
                        path: chain_path.to_string(),
                        reason: format!("Failed to read certificate chain file: {}", e),
                    })?;
                let pem_blocks = pem::parse_many(&chain_contents).map_err(|e| {
                    PipelineError::CertificateError {
                        path: chain_path.to_string(),
                        reason: format!("Failed to parse certificate chain PEM: {}", e),
                    }
                })?;
                pem_blocks
                    .iter()
                    .filter(|block| block.tag() == crate::pem_tags::CERTIFICATE)
                    .map(|block| block.contents().to_vec())
                    .collect()
            }
            None => Vec::new(),
        };

        Ok(Self {
            signer,
            cert_der,
            chain_der,
        })
    }
}

impl CredentialIdentity for FileSystemIdentity {
    fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }

    fn certificate_chain_der(&self) -> &[Vec<u8>] {
        &self.chain_der
    }

    fn signing_algorithm(&self) -> &SigningAlgorithm {
        self.signer.algorithm()
    }

    fn sign(&self, string_to_sign: &[u8]) -> Result<Vec<u8>, String> {
        self.signer.sign(string_to_sign)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serial::extract_serial_number;

    // Helper: unwrap a from_paths Ok without requiring FileSystemIdentity: Debug
    // (it holds a FileSystemSigner, which deliberately isn't Debug — key material).
    fn expect_ok(r: Result<FileSystemIdentity, PipelineError>, what: &str) -> FileSystemIdentity {
        match r {
            Ok(id) => id,
            Err(e) => panic!("{what}: expected Ok, got error: {e}"),
        }
    }

    #[test]
    fn from_paths_rsa_selects_rsa_and_exposes_usable_cert() {
        let id = expect_ok(
            FileSystemIdentity::from_paths(
                "../../tst/certs/rsa-2048-cert.pem",
                "../../tst/certs/rsa-2048-key.pem",
                None,
            ),
            "rsa identity",
        );
        assert_eq!(id.signing_algorithm().as_str(), "AWS4-X509-RSA-SHA256");
        // certificate_der() must be the real leaf cert — its serial extracts cleanly.
        assert!(extract_serial_number(id.certificate_der()).is_ok());
        assert!(
            id.certificate_chain_der().is_empty(),
            "no chain path -> empty"
        );
    }

    #[test]
    fn from_paths_ec_selects_ecdsa() {
        let id = expect_ok(
            FileSystemIdentity::from_paths(
                "../../tst/certs/ec-p256-cert.pem",
                "../../tst/certs/ec-p256-key.pem",
                None,
            ),
            "ec identity",
        );
        assert_eq!(id.signing_algorithm().as_str(), "AWS4-X509-ECDSA-SHA256");
    }

    // Helper: assert from_paths errored with the expected variant, without needing
    // FileSystemIdentity: Debug on the Ok arm.
    fn expect_err(r: Result<FileSystemIdentity, PipelineError>) -> PipelineError {
        match r {
            Ok(_) => panic!("expected an error, got Ok"),
            Err(e) => e,
        }
    }

    #[test]
    fn from_paths_missing_cert_is_certificate_error() {
        let err = expect_err(FileSystemIdentity::from_paths(
            "/nonexistent/cert.pem",
            "../../tst/certs/rsa-2048-key.pem",
            None,
        ));
        match err {
            PipelineError::CertificateError { path, .. } => {
                assert_eq!(path, "/nonexistent/cert.pem")
            }
            other => panic!("expected CertificateError, got {:?}", other),
        }
    }

    #[test]
    fn from_paths_missing_key_is_private_key_error() {
        // Valid cert, missing key -> the failure must be PrivateKeyError, not CertificateError,
        // proving the cert->key ordering matches the pipeline.
        let err = expect_err(FileSystemIdentity::from_paths(
            "../../tst/certs/rsa-2048-cert.pem",
            "/nonexistent/key.pem",
            None,
        ));
        match err {
            PipelineError::PrivateKeyError { path, .. } => {
                assert_eq!(path, "/nonexistent/key.pem")
            }
            other => panic!("expected PrivateKeyError, got {:?}", other),
        }
    }

    #[test]
    fn from_paths_unsupported_key_type_is_unsupported_key_type() {
        // ed25519 is a recognized PEM tag (PKCS#8) but an unsupported ALGORITHM: detect_algorithm
        // rejects the OID -> UnsupportedKeyType (NOT SigningError). This is the step-6 failure site.
        let err = expect_err(FileSystemIdentity::from_paths(
            "../../tst/certs/ed25519-cert.pem",
            "../../tst/certs/ed25519-key.pem",
            None,
        ));
        match err {
            PipelineError::UnsupportedKeyType { .. } => {}
            other => panic!("expected UnsupportedKeyType for ed25519, got {:?}", other),
        }
    }

    #[test]
    fn from_paths_weak_rsa_key_is_signing_error_not_unsupported() {
        // RSA-1024 is a RECOGNIZED type (detect_algorithm passes) but aws-lc-rs rejects it
        // (2048-bit minimum) at construction -> SigningError (the step-4 failure site).
        // This is the case that must NOT collapse into UnsupportedKeyType.
        let err = expect_err(FileSystemIdentity::from_paths(
            "../../tst/certs/rsa-2048-cert.pem", // any valid cert; the KEY is what fails
            "../../tst/certs/rsa-1024-key.pem",
            None,
        ));
        match err {
            PipelineError::SigningError { algorithm, .. } => {
                assert_eq!(algorithm, "AWS4-X509-RSA-SHA256")
            }
            other => panic!("expected SigningError for RSA-1024, got {:?}", other),
        }
    }

    #[test]
    fn from_paths_chain_collects_certificate_blocks() {
        // A chain PEM yields one chain_der entry per CERTIFICATE block. Compare against an
        // independent count of CERTIFICATE blocks in the same fixture.
        let chain_path = "../../tst/certs/ratest-ca-cert.pem";
        let id = expect_ok(
            FileSystemIdentity::from_paths(
                "../../tst/certs/rsa-2048-cert.pem",
                "../../tst/certs/rsa-2048-key.pem",
                Some(chain_path),
            ),
            "identity with chain",
        );
        let expected = pem::parse_many(std::fs::read(chain_path).unwrap())
            .unwrap()
            .iter()
            .filter(|b| b.tag() == crate::pem_tags::CERTIFICATE)
            .count();
        assert_eq!(id.certificate_chain_der().len(), expected);
        assert!(
            expected > 0,
            "fixture should have at least one CERTIFICATE block"
        );
    }

    #[test]
    fn from_paths_bad_chain_path_is_certificate_error() {
        // Error-parity guard: an unreadable chain path must yield CertificateError, the
        // same variant the pipeline produces for a bad chain file — guards that moving
        // the chain read into from_paths didn't shift the error class.
        let err = expect_err(FileSystemIdentity::from_paths(
            "../../tst/certs/rsa-2048-cert.pem",
            "../../tst/certs/rsa-2048-key.pem",
            Some("/nonexistent/chain.pem"),
        ));
        match err {
            PipelineError::CertificateError { path, .. } => {
                assert_eq!(path, "/nonexistent/chain.pem")
            }
            other => panic!(
                "expected CertificateError for bad chain path, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn from_paths_chain_file_with_no_certificate_blocks_is_empty() {
        // A key-only PEM has zero CERTIFICATE blocks -> empty chain_der (and no error). Mirrors
        // the pipeline's non-empty guard: no chain header gets emitted downstream.
        let id = expect_ok(
            FileSystemIdentity::from_paths(
                "../../tst/certs/rsa-2048-cert.pem",
                "../../tst/certs/rsa-2048-key.pem",
                Some("../../tst/certs/rsa-2048-key.pem"), // no CERTIFICATE blocks
            ),
            "identity with cert-less chain file",
        );
        assert!(id.certificate_chain_der().is_empty());
    }
}
