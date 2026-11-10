//! Shared data types for signing: the signing-algorithm enum and the
//! `SignerParams` bundle used to build the string-to-sign and Authorization
//! header. `DateTime<Utc>` is used because SigV4 requires UTC timestamps in a
//! specific format (no local-timezone complications).

use chrono::{DateTime, Utc};

/// The signing algorithm identifier — determines the Authorization header prefix
/// and the algorithm line of the string-to-sign. It must match what AWS expects
/// exactly, or signature validation fails.
///
/// Which variant is used depends on the private key type:
///   - RSA key             -> `RsaSha256`
///   - EC (Elliptic Curve) -> `EcdsaSha256`
// `Clone` so the pipeline can take an owned copy of the algorithm from a
// `CredentialIdentity` (which lends it by reference) to build `SignerParams`.
#[derive(Debug, Clone)]
pub enum SigningAlgorithm {
    RsaSha256,   // "AWS4-X509-RSA-SHA256"
    EcdsaSha256, // "AWS4-X509-ECDSA-SHA256"
}

impl SigningAlgorithm {
    /// Return the exact protocol string. Must match what AWS expects character
    /// for character, otherwise signature validation will fail.
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningAlgorithm::RsaSha256 => "AWS4-X509-RSA-SHA256",
            SigningAlgorithm::EcdsaSha256 => "AWS4-X509-ECDSA-SHA256",
        }
    }
}

/// Everything needed to construct the string-to-sign and the Authorization
/// header. Set once per signing operation and reused across the steps.
pub struct SignerParams {
    /// The exact moment the request is being signed. Used to generate both the
    /// timestamp and the short date for the credential scope.
    pub datetime: DateTime<Utc>,

    /// The AWS region the request targets (e.g. `us-east-1`). Derived from the
    /// trust anchor ARN unless an explicit region is supplied.
    pub region: String,

    /// The AWS service name — always `rolesanywhere` for this tool. Part of the
    /// credential scope AWS uses to route the request.
    pub service: String,

    /// Which algorithm this signing operation uses, determined by the private
    /// key type the caller provides.
    pub algorithm: SigningAlgorithm,
}

impl SignerParams {
    /// Format the datetime in the exact form SigV4 requires, used for both the
    /// `X-Amz-Date` header and the string-to-sign.
    pub fn formatted_datetime(&self) -> String {
        // %Y 4-digit year, %m 2-digit month, ... trailing Z meaning UTC.
        self.datetime.format("%Y%m%dT%H%M%SZ").to_string()
    }

    /// Format just the date portion as `20240115`. Used in the credential scope.
    pub fn formatted_date(&self) -> String {
        self.datetime.format("%Y%m%d").to_string()
    }

    /// Build the credential scope string. The scope ties the signature to a
    /// specific date, region, and service; if any of these don't match what AWS
    /// expects, the signature is rejected.
    pub fn scope(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.formatted_date(),
            self.region,
            self.service
        )
    }
}
