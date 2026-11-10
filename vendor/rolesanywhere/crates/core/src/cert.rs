//! Certificate SubjectPublicKeyInfo helpers shared by the device-backed
//! backends — derive the signing algorithm and extract the wire-form public
//! key from a leaf certificate's DER.
//!
//! Every backend that signs with an OS/hardware key still needs to know, from
//! the certificate, (a) which `SigningAlgorithm` to use and (b) the public-key
//! bytes in the form aws-lc-rs's verifier expects. The certificate's SPKI is
//! authoritative for both — it is the public key AWS verifies the signature
//! against, and its algorithm parameters carry the EC named curve so an
//! unsupported curve is rejected precisely (matching how the Go reference tool
//! picks the algorithm from `cert.PublicKey.(type)`).
//!
//! This lives in `core` because the PKCS#11, macOS Keychain, and TPM backends
//! all need the identical logic. It is pure format parsing (x509-cert / der),
//! not crypto — no signing happens here.

use crate::types::SigningAlgorithm;
use x509_cert::der::Decode;
use x509_cert::spki::ObjectIdentifier;

// Public-key algorithm OIDs from the cert's SubjectPublicKeyInfo. RSA and
// id-ecPublicKey are the two key types these backends sign with; P-256 is the
// one supported EC curve.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// Derive the signing algorithm from a certificate's public key.
///
/// The cert's SubjectPublicKeyInfo — not any device key attribute — is
/// authoritative: it is the public key AWS verifies against, it is unambiguous
/// on mixed-key-type devices, and it carries the EC named curve so an
/// unsupported curve (e.g. P-384) is rejected with a precise error rather than
/// a misleading key-cert mismatch. The `Err` is a stable kebab-case kind slug
/// (`cert-parse-failed` / `unsupported-curve` / `unsupported-key-type`) plus a
/// detail, joined `kind: detail` — callers can match on the prefix or wrap it.
pub fn signing_algorithm_from_cert(cert_der: &[u8]) -> Result<SigningAlgorithm, String> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| format!("cert-parse-failed: x509 parse: {e}"))?;
    let alg = cert.tbs_certificate.subject_public_key_info.algorithm;
    let curve_oid = alg
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    signing_algorithm_from_oids(alg.oid, curve_oid)
}

/// Pure OID → algorithm decision, split out so the curve-support policy is
/// unit-testable without a live P-384 fixture.
fn signing_algorithm_from_oids(
    key_oid: ObjectIdentifier,
    curve_oid: Option<ObjectIdentifier>,
) -> Result<SigningAlgorithm, String> {
    if key_oid == OID_RSA_ENCRYPTION {
        Ok(SigningAlgorithm::RsaSha256)
    } else if key_oid == OID_EC_PUBLIC_KEY {
        match curve_oid {
            Some(c) if c == OID_P256 => Ok(SigningAlgorithm::EcdsaSha256),
            Some(c) => Err(format!(
                "unsupported-curve: EC curve {c} is not supported (only P-256)"
            )),
            None => Err("unsupported-curve: EC key has no named-curve parameter".to_string()),
        }
    } else {
        Err(format!(
            "unsupported-key-type: certificate public-key OID {key_oid} is not RSA or EC"
        ))
    }
}

/// Extract a certificate's SubjectPublicKeyInfo bit-string body in the wire
/// form aws-lc-rs's `UnparsedPublicKey` expects: for RSA, the PKCS#1
/// `RSAPublicKey` DER; for ECDSA P-256, the uncompressed SEC1 point
/// (`0x04||X||Y`). This is exactly what `Signer::public_key_marshalled` must
/// return, so a backend caches this once at build time.
pub fn public_key_wire_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| format!("cert-parse-failed: x509 parse: {e}"))?;
    let spki = cert.tbs_certificate.subject_public_key_info;
    let bit_string = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| {
            "cert-parse-failed: SPKI subject_public_key bit-string is unaligned".to_owned()
        })?
        .to_vec();
    Ok(bit_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_from_oids_maps_rsa_p256_and_rejects_others() {
        assert!(matches!(
            signing_algorithm_from_oids(OID_RSA_ENCRYPTION, None),
            Ok(SigningAlgorithm::RsaSha256)
        ));
        assert!(matches!(
            signing_algorithm_from_oids(OID_EC_PUBLIC_KEY, Some(OID_P256)),
            Ok(SigningAlgorithm::EcdsaSha256)
        ));
        // P-384 (1.3.132.0.34) → unsupported-curve.
        let p384 = ObjectIdentifier::new_unwrap("1.3.132.0.34");
        let err = signing_algorithm_from_oids(OID_EC_PUBLIC_KEY, Some(p384)).unwrap_err();
        assert!(err.starts_with("unsupported-curve"), "got: {err}");
        // EC without a curve param → unsupported-curve (fail closed).
        let err2 = signing_algorithm_from_oids(OID_EC_PUBLIC_KEY, None).unwrap_err();
        assert!(err2.starts_with("unsupported-curve"), "got: {err2}");
        // Ed25519 (1.3.101.112) → unsupported-key-type.
        let ed = ObjectIdentifier::new_unwrap("1.3.101.112");
        let err3 = signing_algorithm_from_oids(ed, None).unwrap_err();
        assert!(err3.starts_with("unsupported-key-type"), "got: {err3}");
    }

    #[test]
    fn reads_algorithm_and_pubkey_from_real_certs() {
        // Reuse the existing test fixtures — the same ones cert_data.rs uses.
        // Load via `fixture_der` (panics on a missing fixture) rather than a
        // silent `.ok()` skip, so a broken test environment fails loudly
        // instead of passing with zero assertions.
        let rsa = fixture_der("rsa-2048-cert.pem");
        assert!(matches!(
            signing_algorithm_from_cert(&rsa),
            Ok(SigningAlgorithm::RsaSha256)
        ));
        assert!(!public_key_wire_from_cert(&rsa).unwrap().is_empty());

        let ec = fixture_der("ec-p256-cert.pem");
        assert!(matches!(
            signing_algorithm_from_cert(&ec),
            Ok(SigningAlgorithm::EcdsaSha256)
        ));
        // P-256 uncompressed SEC1 point is 65 bytes, 0x04-prefixed.
        let wire = public_key_wire_from_cert(&ec).unwrap();
        assert_eq!(wire.len(), 65);
        assert_eq!(wire[0], 0x04);
    }

    #[test]
    fn rejects_garbage_der() {
        assert!(signing_algorithm_from_cert(&[0xff, 0x00, 0x01]).is_err());
        assert!(public_key_wire_from_cert(&[]).is_err());
    }

    // Helper: load a fixture cert's DER, panicking if the fixture is absent —
    // a MISSING fixture is a test failure, not a silent skip.
    fn fixture_der(name: &str) -> Vec<u8> {
        let path = format!("../../tst/certs/{name}");
        let pem_bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        pem::parse(&pem_bytes).unwrap().into_contents()
    }

    #[test]
    fn real_p384_cert_is_unsupported_curve() {
        // The end-to-end reject path on a REAL P-384 cert (not a synthetic OID):
        // DER → SPKI → curve OID 1.3.132.0.34 → unsupported-curve.
        let der = fixture_der("p384-cert.pem");
        let err = signing_algorithm_from_cert(&der).expect_err("P-384 must reject");
        assert!(err.starts_with("unsupported-curve"), "got: {err}");
        // The pubkey extractor still succeeds (it doesn't judge the curve) —
        // proving the rejection is a policy decision, not a parse failure.
        assert!(public_key_wire_from_cert(&der).is_ok());
    }

    #[test]
    fn real_ed25519_cert_is_unsupported_key_type() {
        // Ed25519 (OID 1.3.101.112) is neither RSA nor id-ecPublicKey.
        let der = fixture_der("ed25519-cert.pem");
        let err = signing_algorithm_from_cert(&der).expect_err("Ed25519 must reject");
        assert!(err.starts_with("unsupported-key-type"), "got: {err}");
    }

    // ------------------------- property tests -------------------------
    // Robustness/soundness sweep: the cert parsers take UNTRUSTED DER (a leaf
    // cert supplied by the operator / device). They must NEVER panic on
    // malformed input and must return a clean typed error instead. Parsers are
    // exactly where hand-checked examples miss edge cases, so fuzz the input.

    use proptest::prelude::*;

    proptest! {
        /// PROP-cert-parser-soundness: neither `signing_algorithm_from_cert`
        /// nor `public_key_wire_from_cert` may panic on arbitrary bytes — a
        /// malformed cert is a clean `Err`, never a crash. (Random bytes are
        /// almost never a valid cert, so this drives the error paths; it proves
        /// the x509/der decode layer is used soundly, no unwraps on input.)
        #[test]
        fn prop_cert_parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            // The only contract is "does not panic". Ok or Err are both fine.
            let _ = signing_algorithm_from_cert(&bytes);
            let _ = public_key_wire_from_cert(&bytes);
        }

        /// PROP-cert-parser-der-prefixed: bias toward inputs that START like a
        /// certificate (DER SEQUENCE tag 0x30 + a length), so the fuzzer gets
        /// deeper into the x509 structure decode than uniform random bytes
        /// usually reach — still must never panic.
        #[test]
        fn prop_cert_parsers_survive_der_shaped_input(
            len_byte in any::<u8>(),
            body in prop::collection::vec(any::<u8>(), 0..300),
        ) {
            let mut input = vec![0x30, len_byte];
            input.extend_from_slice(&body);
            let _ = signing_algorithm_from_cert(&input);
            let _ = public_key_wire_from_cert(&input);
        }
    }
}
