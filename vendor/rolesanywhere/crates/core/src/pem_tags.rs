//! PEM block tag names, defined in one place.
//!
//! A PEM file looks like `-----BEGIN <TAG>-----` ... `-----END <TAG>-----`.
//! The `<TAG>` tells us what the block contains and, for keys, which format the
//! DER bytes are in. These strings appear in several modules (key reading,
//! algorithm detection, signing), so we name them here once to avoid typos and
//! to make the supported formats easy to see at a glance.

/// An X.509 certificate.
pub const CERTIFICATE: &str = "CERTIFICATE";

/// A PKCS#8 private key. This is the modern, algorithm-agnostic format:
/// the key bytes start with an AlgorithmIdentifier that says whether the key
/// is RSA or EC, so we have to look inside to know how to sign with it.
pub const PKCS8_PRIVATE_KEY: &str = "PRIVATE KEY";

/// A PKCS#1 private key. This format is RSA-only (legacy), so the tag alone
/// tells us the algorithm is RSA.
pub const RSA_PRIVATE_KEY: &str = "RSA PRIVATE KEY";

/// A SEC1 private key. This format is EC-only (legacy), so the tag alone
/// tells us the algorithm is ECDSA.
pub const EC_PRIVATE_KEY: &str = "EC PRIVATE KEY";
