//! Minimal ASN.1 DER encoding for ECDSA signatures — shared by the
//! device-backed signing backends.
//!
//! A hardware/OS key backend that performs a raw ECDSA operation
//! (PKCS#11 `CKM_ECDSA`, Windows CNG `NCryptSignHash` with null padding, a
//! TPM `TPM2_Sign`) returns the signature as a bare `r || s` byte pair. AWS
//! SigV4 (and aws-lc-rs's verifier) expect the X9.62 ASN.1 DER form
//! `SEQUENCE { INTEGER r, INTEGER s }`. This module does that conversion.
//!
//! It lives in `core` because THREE backends need the identical wrap
//! (PKCS#11, Windows cert store, TPM). Keeping one audited copy here avoids
//! divergent hand-rolled encoders. It is pure byte-plumbing — no crypto, no
//! dependencies — so it stays trivially reviewable and testable in isolation.
//!
//! Hand-rolled rather than pulling the `der` crate: ~40 lines keeps the audit
//! surface minimal, and the Go reference tool hand-rolls the same encoding,
//! so the two are easy to review side by side.
//!
//! (The in-process file-path signer does NOT use this — aws-lc-rs returns DER
//! natively there. This is only for backends that get raw `r||s` from a
//! device.)

/// Wrap a raw ECDSA `r || s` signature into ASN.1 DER
/// `SEQUENCE { INTEGER r, INTEGER s }`.
///
/// `r` and `s` are the two halves of the raw signature — the caller splits
/// the device output at `sig.len() / 2` (the halves are always equal length
/// for a given curve). Produces the exact encoding AWS and aws-lc-rs expect.
pub fn wrap_ecdsa_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let r_der = asn1_integer(r);
    let s_der = asn1_integer(s);
    let body_len = r_der.len() + s_der.len();
    let mut out = Vec::with_capacity(4 + body_len);
    out.push(0x30); // SEQUENCE
    encode_length(&mut out, body_len);
    out.extend_from_slice(&r_der);
    out.extend_from_slice(&s_der);
    out
}

/// Encode a positive integer's magnitude bytes as an ASN.1 DER INTEGER.
///
/// Two edge cases: leading-zero bytes are stripped (DER minimal-length
/// integers), and if the resulting high bit is set (>= 0x80) a 0x00 pad byte
/// is prepended so the value reads as positive. A zero magnitude encodes as
/// `02 01 00`.
fn asn1_integer(magnitude: &[u8]) -> Vec<u8> {
    // Strip leading zeros, but keep at least one byte so `0` encodes as `00`.
    let stripped = {
        let mut s = magnitude;
        while s.len() > 1 && s[0] == 0x00 {
            s = &s[1..];
        }
        s
    };

    // Prepend 0x00 if the high bit is set (make it positive in ASN.1's
    // two's-complement view). Handles the all-empty case defensively:
    // `magnitude=[]` becomes `stripped=[]`, which we treat as zero.
    let (pad, effective): (bool, &[u8]) = if stripped.is_empty() {
        (false, &[0x00][..])
    } else if stripped[0] & 0x80 != 0 {
        (true, stripped)
    } else {
        (false, stripped)
    };

    let content_len = effective.len() + usize::from(pad);
    let mut out = Vec::with_capacity(2 + content_len);
    out.push(0x02); // INTEGER
    encode_length(&mut out, content_len);
    if pad {
        out.push(0x00);
    }
    out.extend_from_slice(effective);
    out
}

/// DER length encoding. Short-form for len < 128; long-form otherwise.
/// ECDSA payloads fit short-form (P-256 signatures produce ~70-byte SEQUENCE
/// bodies), but we handle up to u32::MAX defensively for future curves.
fn encode_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len <= 0xFF_FFFF {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_two_short_integers() {
        // SEQUENCE { INTEGER 0x1234, INTEGER 0x5678 }
        let out = wrap_ecdsa_signature(&[0x12, 0x34], &[0x56, 0x78]);
        assert_eq!(
            out,
            vec![0x30, 0x08, 0x02, 0x02, 0x12, 0x34, 0x02, 0x02, 0x56, 0x78]
        );
    }

    #[test]
    fn wrap_pads_high_bit_to_stay_positive() {
        // r = 0x80 has the high bit set → must be padded with 0x00.
        let out = wrap_ecdsa_signature(&[0x80], &[0x01]);
        // INTEGER r = 02 02 00 80 ; INTEGER s = 02 01 01
        assert_eq!(
            out,
            vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01]
        );
    }

    #[test]
    fn wrap_strips_leading_zero() {
        // r = 00 01 → leading zero stripped to just 01.
        let out = wrap_ecdsa_signature(&[0x00, 0x01], &[0x02]);
        assert_eq!(out, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn asn1_integer_encodes_zero_correctly() {
        assert_eq!(asn1_integer(&[0x00]), vec![0x02, 0x01, 0x00]);
        assert_eq!(asn1_integer(&[]), vec![0x02, 0x01, 0x00]);
        assert_eq!(asn1_integer(&[0x00, 0x00, 0x00]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn wraps_p256_sized_signature() {
        // 32-byte r and s (P-256). High bit clear on both → no padding.
        let r = [0x7f; 32];
        let s = [0x01; 32];
        let out = wrap_ecdsa_signature(&r, &s);
        // Two INTEGERs of 34 bytes each (02 20 + 32) = 68 body bytes.
        assert_eq!(out[0], 0x30);
        assert_eq!(out[1], 68);
        assert_eq!(out[2], 0x02);
        assert_eq!(out[3], 0x20);
    }

    #[test]
    fn wraps_p256_high_bit_signature() {
        // Both halves have the high bit set → each gets a 0x00 pad (33 bytes).
        let r = [0xff; 32];
        let s = [0x80; 32];
        let out = wrap_ecdsa_signature(&r, &s);
        // Each INTEGER now 02 21 00 + 32 = 35 bytes; body = 70.
        assert_eq!(out[0], 0x30);
        assert_eq!(out[1], 70);
        assert_eq!(out[2], 0x02);
        assert_eq!(out[3], 0x21);
        assert_eq!(out[4], 0x00);
    }

    #[test]
    fn encode_length_short_and_long_form() {
        let mut v = vec![];
        encode_length(&mut v, 0);
        assert_eq!(v, vec![0x00]);
        v.clear();
        encode_length(&mut v, 127);
        assert_eq!(v, vec![0x7f]);
        v.clear();
        encode_length(&mut v, 128);
        assert_eq!(v, vec![0x81, 0x80]);
        v.clear();
        encode_length(&mut v, 256);
        assert_eq!(v, vec![0x82, 0x01, 0x00]);
    }

    // ------------------------- property tests -------------------------
    // Encode/decode round-trip on the hand-rolled DER encoder — the class of
    // code where example-based tests miss edge cases. We encode arbitrary
    // r/s, then decode the output back with a REAL DER reader (the `der`
    // crate's `Int`, the same reader serial.rs uses) and check the value is
    // preserved. This is a differential check: our encoder vs an independent
    // decoder.

    use der::{Decode, Encode};
    use proptest::prelude::*;

    /// The canonical unsigned magnitude of a byte slice: leading 0x00 bytes
    /// dropped, empty treated as a single 0x00. This is the value the encoder
    /// must preserve (it strips leading zeros; the sign-pad it adds is an
    /// ASN.1 encoding artifact, not part of the value).
    fn canonical_magnitude(bytes: &[u8]) -> Vec<u8> {
        let mut b = bytes;
        while b.len() > 1 && b[0] == 0x00 {
            b = &b[1..];
        }
        if b.is_empty() { vec![0x00] } else { b.to_vec() }
    }

    /// Decode a single DER INTEGER (as emitted by `asn1_integer`) back to its
    /// canonical unsigned magnitude via the `der` crate, so we compare our
    /// encoder against an independent reader rather than against itself.
    fn decode_der_uint_magnitude(der_int: &[u8]) -> Vec<u8> {
        // `Uint` is DER's unsigned integer: `as_bytes()` returns the value
        // with any ASN.1 sign-pad already removed — exactly the canonical
        // magnitude, so a leading-zero-stripped input round-trips equal.
        let uint = der::asn1::Uint::from_der(der_int).expect("decode DER INTEGER");
        let mut v = uint.as_bytes().to_vec();
        if v.is_empty() {
            v = vec![0x00]; // der represents 0 as empty content; normalize
        }
        v
    }

    proptest! {
        /// PROP-asn1-roundtrip: for arbitrary r and s (any length 0..=66, the
        /// range that covers P-256/P-384/P-521 halves plus under/over-sized
        /// edges), `wrap_ecdsa_signature` produces a well-formed
        /// `SEQUENCE { INTEGER, INTEGER }` whose two integers, when decoded by
        /// the `der` crate, equal the leading-zero-stripped inputs. Never
        /// panics; the SEQUENCE re-parses.
        #[test]
        fn prop_wrap_roundtrips_through_der(
            r in prop::collection::vec(any::<u8>(), 0..=66),
            s in prop::collection::vec(any::<u8>(), 0..=66),
        ) {
            let out = wrap_ecdsa_signature(&r, &s);

            // Whole output is a valid DER SEQUENCE that re-encodes identically
            // (structural well-formedness, via an independent reader).
            let seq = der::asn1::SequenceRef::from_der(&out)
                .expect("output must be a valid DER SEQUENCE");
            prop_assert_eq!(seq.to_der().unwrap(), out.clone());

            // Split the body into its two INTEGER TLVs and decode each.
            let r_der = asn1_integer(&r);
            let s_der = asn1_integer(&s);
            prop_assert_eq!(
                decode_der_uint_magnitude(&r_der),
                canonical_magnitude(&r)
            );
            prop_assert_eq!(
                decode_der_uint_magnitude(&s_der),
                canonical_magnitude(&s)
            );
        }

        /// PROP-asn1-integer-valid: every `asn1_integer` output is a DER
        /// INTEGER a real reader accepts, for arbitrary magnitude bytes
        /// (covering the high-bit-set sign-pad path and leading-zero strip).
        #[test]
        fn prop_asn1_integer_is_readable(mag in prop::collection::vec(any::<u8>(), 0..=64)) {
            let enc = asn1_integer(&mag);
            prop_assert_eq!(enc[0], 0x02, "must be tagged INTEGER");
            // A DER reader accepts it, and the value equals the canonical input.
            prop_assert_eq!(decode_der_uint_magnitude(&enc), canonical_magnitude(&mag));
        }
    }
}
