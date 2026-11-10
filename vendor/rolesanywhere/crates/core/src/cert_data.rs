//! `read-certificate-data` support: read a certificate file and report the
//! diagnostic fields the Go reference returns from ReadCertificateData. No
//! private key is required — only the certificate.

use crate::algorithm::{EC_OID, RSA_OID};
use crate::key_reader::{certificate_to_base64, read_certificate_der};
use crate::serial::extract_serial_number;

use der::Decode;
use x509_cert::Certificate;

/// Mirror of the Go reference's CertificateData. Field order and camelCase JSON
/// tags match Go exactly: keyType, certificateData, serialNumber, supportedAlgorithms.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateData {
    pub key_type: String,
    pub certificate_data: String,
    pub serial_number: String,
    pub supported_algorithms: Vec<String>,
}

/// Build CertificateData from a certificate PEM file.
///
/// keyType is "RSA" or "EC" (matched on the SPKI OID via the shared `RSA_OID`/`EC_OID`
/// constants). For any other public-key algorithm we return a clean error — RSA and EC
/// only, a deliberate divergence from the Go reference's keyType="" fallthrough.
pub fn read_certificate_data(cert_path: &str) -> Result<CertificateData, String> {
    let cert_der = read_certificate_der(cert_path)?;

    let cert = Certificate::from_der(&cert_der)
        .map_err(|e| format!("Failed to parse X.509 certificate DER: {}", e))?;
    let oid = cert
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
        .to_string();

    let key_type = if oid == RSA_OID {
        "RSA"
    } else if oid == EC_OID {
        "EC"
    } else {
        return Err(format!("Unsupported certificate key type (OID {})", oid));
    };

    let supported_algorithms = vec![
        format!("{}SHA256", key_type),
        format!("{}SHA384", key_type),
        format!("{}SHA512", key_type),
    ];

    Ok(CertificateData {
        key_type: key_type.to_string(),
        certificate_data: certificate_to_base64(&cert_der),
        serial_number: extract_serial_number(&cert_der)?,
        supported_algorithms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_cert_data_matches_go() {
        let d = read_certificate_data("../../tst/certs/rsa-2048-cert.pem").unwrap();
        assert_eq!(d.key_type, "RSA");
        assert_eq!(
            d.serial_number,
            "232055119021298063684997990844156026909666465608"
        );
        assert_eq!(
            d.supported_algorithms,
            vec!["RSASHA256", "RSASHA384", "RSASHA512"]
        );
        // certificateData is base64 StdEncoding of the cert DER; Go starts it "MIIC/zCC".
        assert!(
            d.certificate_data.starts_with("MIIC/zCC"),
            "got {}",
            &d.certificate_data[..16]
        );
    }

    #[test]
    fn ec_cert_data_matches_go() {
        let d = read_certificate_data("../../tst/certs/ec-p256-cert.pem").unwrap();
        assert_eq!(d.key_type, "EC");
        assert_eq!(
            d.serial_number,
            "368643213350383568190418459348706308510752521473"
        );
        assert_eq!(
            d.supported_algorithms,
            vec!["ECSHA256", "ECSHA384", "ECSHA512"]
        );
        assert!(
            d.certificate_data.starts_with("MIIBvDCC"),
            "got {}",
            &d.certificate_data[..16]
        );
    }

    #[test]
    fn cert_data_json_shape_matches_go() {
        // Exact JSON byte shape (key order + camelCase) that Go fmt.Print emits.
        let d = read_certificate_data("../../tst/certs/ec-p256-cert.pem").unwrap();
        let json = serde_json::to_string(&d).unwrap();
        assert!(
            json.starts_with(r#"{"keyType":"EC","certificateData":""#),
            "json = {}",
            json
        );
        assert!(
            json.contains(r#""serialNumber":"368643213350383568190418459348706308510752521473""#),
            "json = {}",
            json
        );
        assert!(
            json.ends_with(r#""supportedAlgorithms":["ECSHA256","ECSHA384","ECSHA512"]}"#),
            "json = {}",
            json
        );
    }

    #[test]
    fn p384_cert_data_is_curve_agnostic() {
        // read-certificate-data only reads the SPKI OID (id-ecPublicKey), so it
        // accepts a P-384 cert as keyType "EC" — INDEPENDENT of the P-256-only signer
        // that rejects a P-384 KEY (signer.rs::p384_key_rejected_cleanly). This locks
        // that intentional asymmetry. Output was verified byte-identical to the Go binary
        // on this fixture.
        let d = read_certificate_data("../../tst/certs/p384-cert.pem").unwrap();
        assert_eq!(d.key_type, "EC");
        assert_eq!(
            d.supported_algorithms,
            vec!["ECSHA256", "ECSHA384", "ECSHA512"]
        );
        assert!(
            d.serial_number
                .chars()
                .all(|c| c.is_ascii_digit() || c == '-')
        );
    }

    #[test]
    fn malformed_pem_errors() {
        // A malformed PEM fails at the PEM-parsing stage — must error, not panic.
        let r = read_certificate_data("../../tst/certs/malformed.pem");
        assert!(r.is_err(), "malformed PEM must error");
    }

    #[test]
    fn unsupported_key_type_errors() {
        // An Ed25519 cert is neither RSA nor EC, so it must hit the unsupported-OID
        // branch and return a clean error — a deliberate divergence from Go's
        // keyType="" fallthrough. This is the real test of that branch:
        // the cert parses fine; only the key-type check rejects it.
        let r = read_certificate_data("../../tst/certs/ed25519-cert.pem");
        let msg = match r {
            Ok(_) => panic!("Ed25519 cert must be rejected as unsupported key type"),
            Err(e) => e,
        };
        assert!(
            msg.contains("Unsupported certificate key type"),
            "error must come from the key-type branch, got: {}",
            msg
        );
    }
}
