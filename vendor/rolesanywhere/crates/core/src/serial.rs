//! Reading the serial number out of an X.509 certificate.
//!
//! The serial number becomes the `Credential=<serial>/...` part of the
//! Authorization header, so it must be formatted exactly like the Go reference.
//! Go uses `cert.SerialNumber.String()`, where `SerialNumber` is a *signed*
//! big integer (`big.Int`). We therefore decode the serial as a SIGNED value too,
//! so certificates with a negative serial produce the same string in both tools.
//!
//! Known divergence: `x509-cert` caps serial decoding at 20 octets (RFC 5280 §4.1.2.2
//! requires serials to fit in 20 bytes), so a non-conforming, oversized serial errors
//! here where Go's `big.Int` (which has no size cap) would still parse it. Real CA-issued
//! certs are within the limit, so this is not reachable in practice.

use der::Decode;
use num_bigint::BigInt;
use x509_cert::Certificate;

/// Parse a DER-encoded X.509 certificate and return its serial number as a
/// decimal string, matching Go's `big.Int.String()`.
pub fn extract_serial_number(cert_der: &[u8]) -> Result<String, String> {
    // Parse the certificate structure.
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| format!("Failed to parse X.509 certificate DER: {}", e))?;

    // `as_bytes()` gives the serial's canonical two's-complement value bytes (the
    // same bytes the DER INTEGER carries, with the sign/pad byte preserved). We
    // interpret them as a SIGNED big-endian integer, exactly like Go's `big.Int`,
    // so `to_string()` produces the same decimal form — including a leading '-'
    // for a negative serial.
    let serial = BigInt::from_signed_bytes_be(cert.tbs_certificate.serial_number.as_bytes());
    Ok(serial.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: read a cert PEM fixture and return its DER bytes.
    fn cert_der(path: &str) -> Vec<u8> {
        let pem_bytes = std::fs::read(path).expect("read cert fixture");
        pem::parse(&pem_bytes)
            .expect("parse PEM")
            .contents()
            .to_vec()
    }

    #[test]
    fn test_extract_serial_number_rsa_cert() {
        let der = cert_der("../../tst/certs/rsa-2048-cert.pem");
        let serial = extract_serial_number(&der).expect("extract serial");
        // Positive serial -> all digits, no leading '-'.
        assert!(!serial.is_empty());
        assert!(serial.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_extract_serial_number_ec_cert() {
        let der = cert_der("../../tst/certs/ec-p256-cert.pem");
        let serial = extract_serial_number(&der).expect("extract serial");
        assert!(!serial.is_empty());
        assert!(serial.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_extract_serial_number_large_serial() {
        let der = cert_der("../../tst/certs/large-serial-cert.pem");
        let serial = extract_serial_number(&der).expect("extract serial");
        assert!(serial.chars().all(|c| c.is_ascii_digit()));
        // A large serial should have many digits.
        assert!(
            serial.len() > 10,
            "Large serial should be long, got: {}",
            serial
        );
    }

    /// Known-answer test: lock the serial decimal strings to the exact values Go's
    /// big.Int.String() produces (verified separately). These are positive serials.
    #[test]
    fn test_serial_known_answers() {
        let cases = [
            (
                "../../tst/certs/rsa-2048-cert.pem",
                "232055119021298063684997990844156026909666465608",
            ),
            (
                "../../tst/certs/large-serial-cert.pem",
                "24197857200151252728969465429440056815",
            ),
        ];
        for (path, expected) in cases {
            let der = cert_der(path);
            let serial = extract_serial_number(&der).expect("extract serial");
            assert_eq!(serial, expected, "serial mismatch for {}", path);
        }
    }

    /// The three byte patterns that distinguish SIGNED from unsigned decoding, checked
    /// through the SAME `der::asn1::Int::as_bytes()` that `extract_serial_number` reads
    /// off a real certificate's `SerialNumber` (so this pins the exact value-byte contract
    /// the function relies on):
    ///   - `02 01 FF` is INTEGER -1: the high bit makes it negative, so the signed decode
    ///     must print "-1" where an unsigned decode would print "255".
    ///   - `02 01 00` is INTEGER 0 -> "0".
    ///   - `02 02 00 80` is INTEGER 128: DER prepends a 0x00 pad byte so the 0x80 high bit
    ///     does NOT make it negative, so the signed decode must read +128, not -128.
    #[test]
    fn signed_decode_boundaries_negative_zero_and_padded_positive() {
        // The high-MSB-positive (0x00-pad) case is not covered by any cert fixture, so it
        // is pinned here directly.
        let cases = [
            (&[0x02u8, 0x01, 0xFF][..], "-1"),
            (&[0x02u8, 0x01, 0x00][..], "0"),
            (&[0x02u8, 0x02, 0x00, 0x80][..], "128"),
        ];
        for (der_int, expected) in cases {
            let int = der::asn1::Int::from_der(der_int).expect("decode DER INTEGER");
            let n = BigInt::from_signed_bytes_be(int.as_bytes());
            assert_eq!(n.to_string(), expected, "signed decode of {:02x?}", der_int);
        }
    }

    #[test]
    fn test_extract_serial_number_invalid_der() {
        let result = extract_serial_number(b"not a valid certificate");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Failed to parse X.509 certificate DER")
        );
    }

    #[test]
    fn test_extract_serial_number_empty_input() {
        assert!(extract_serial_number(&[]).is_err());
    }

    /// End-to-end known-answer test for the SIGNED-serial parity fix, through the real
    /// `Certificate::from_der` path (not just the synthetic TLV in the test above).
    ///
    /// `negative-serial-cert.pem` has a serial whose first byte is 0xF0 (high bit set),
    /// which is NEGATIVE as a two's-complement integer. An unsigned decoder would print
    /// the large positive value 1370157784997721485815954530671515330927436759211; Go's
    /// signed `big.Int.String()` (and our `BigInt`) print the negative value below.
    /// This locks the behavior on a genuine certificate, which is what the module
    /// docstring promises but no other test proves end-to-end.
    ///
    /// The expected value was VERIFIED against the Go reference binary:
    ///   GODEBUG=x509negativeserial=1 go run . read-certificate-data --certificate <this>
    /// emits serialNumber = the exact string below.
    ///
    /// Two caveats this fixture is documenting:
    /// 1. openssl/cryptography refuse to emit a negative serial (they pad it to
    ///    positive), so this DER was hand-edited. That invalidates the cert's SIGNATURE
    ///    — use it ONLY for serial extraction, never for signing/verification tests.
    /// 2. Go 1.23+ REJECTS negative serials by default ("could not parse certificate");
    ///    it only parses this cert with the GODEBUG override above. Our parser accepts
    ///    them unconditionally — a known leniency divergence (real CAs never issue
    ///    negative serials; RFC 5280 §4.1.2.2 requires positive). We still decode
    ///    SIGNED so that IF a negative serial ever reaches us, our output matches Go's.
    #[test]
    fn test_extract_serial_number_negative_cert_is_signed() {
        let der = cert_der("../../tst/certs/negative-serial-cert.pem");
        let serial = extract_serial_number(&der).expect("extract serial");
        assert_eq!(
            serial, "-91343852333181432387730302044767688728495783765",
            "negative serial must decode as a signed value (leading '-'), matching Go's big.Int"
        );
    }
}
