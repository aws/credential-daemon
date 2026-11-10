//! Presence gate (`presence-gated-operations`).
//!
//! Shared by both ends: the wire shapes of challenges and pending operations, the exact
//! message a presence key signs, and verification. The enclave half (key generation and
//! signing) runs only in the client, under the `secure-enclave` feature.

use serde::{Deserialize, Serialize};

pub const METHOD_REQUEST_APPROVE: &str = "request/approve";
pub const METHOD_REQUEST_GET: &str = "request/get";
pub const METHOD_REQUEST_LIST: &str = "request/list";
pub const METHOD_REQUEST_WITHDRAW: &str = "request/withdraw";
pub const METHOD_PRESENCE_ENROLL: &str = "presence/enroll";
pub const METHOD_PRESENCE_REVOKE: &str = "presence/revoke";
pub const METHOD_PRESENCE_STATUS: &str = "presence/status";

/// Domain separation for the signed message, so a presence signature cannot be lifted into any
/// other protocol (design Decision 13).
const DOMAIN: &[u8] = b"credsd-presence-v1";

/// Which proofs a pending operation accepts. An enrollment accepts only a privileged approval
/// (Requirement 11.2), because the key it would trust cannot vouch for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Accepts {
    Any,
    Privileged,
}

/// Why `request/approve` did not satisfy a challenge (`presence-gated-operations` Requirement
/// 8.2). Every reason but [`BaseStateChanged`](Self::BaseStateChanged) leaves the request pending,
/// so the other verifier stays available (Requirement 8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// No proof was submitted, and the connection is not privileged.
    NotSatisfied,
    SignatureInvalid,
    NoPresenceKey,
    /// The request accepts privileged approval only (Requirement 3.6).
    PrivilegedOnly,
    /// A subject record moved since the request; it was discarded unperformed (Requirement 2.6).
    BaseStateChanged,
    /// A reason not recognised by this version.
    #[serde(other)]
    Unknown,
}

/// Returned in place of performing a gated operation (Requirement 7.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: String,
    /// Hex SHA-256 of the pending operation's canonical form.
    pub digest: String,
    pub description: String,
    pub expires_in_secs: u64,
    pub accepts: Accepts,
    /// Fingerprint of the presence key enrolled for the owner, if any — tells the client whether
    /// a Touch ID signature is worth attempting.
    pub presence_key: Option<String>,
}

/// A pending operation as shown to its owner or an approver (Requirements 7.10, 7.13).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSummary {
    pub challenge: Challenge,
    pub owner_uid: u32,
    pub owner_pid: Option<i32>,
    pub owner_executable: Option<String>,
    pub raised_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdParams {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveParams {
    pub id: String,
    /// Hex DER ECDSA signature over [`signed_message`]. Absent for a privileged approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveResult {
    pub outcome: String,
    pub verifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollParams {
    /// Hex X9.63 (SEC1 uncompressed) P-256 public key.
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResult {
    pub challenge: Challenge,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    pub uid: u32,
    pub presence_key: Option<String>,
    pub enrolled_at: Option<String>,
    pub approved_by_uid: Option<u32>,
    pub approved_by_login_uid: Option<u32>,
}

/// The exact bytes a presence key signs for a challenge.
pub fn signed_message(id: &str, digest: &[u8]) -> Vec<u8> {
    [DOMAIN, b"\0", id.as_bytes(), b"\0", digest].concat()
}

pub fn verify(public_key: &[u8], message: &[u8], der_signature: &[u8]) -> bool {
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, der_signature)
        .is_ok()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// `SHA256:<base64>` of the public key, ssh-style.
pub fn fingerprint(public_key: &[u8]) -> String {
    use base64::Engine;
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha256(public_key))
    )
}

/// A random pending-operation identifier. It names a request; it authorizes nothing
/// (design Decision 9).
pub fn new_request_id() -> String {
    let id: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(12)
        .collect();
    format!("req-{id}")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// Client-side presence keys in the Secure Enclave, via the Swift shim.
#[cfg(all(target_os = "macos", feature = "secure-enclave"))]
pub mod enclave {
    use crate::error::{DaemonError, Result};

    const PRIVATE_KEY_USAGE: u32 = 1 << 30;
    const USER_PRESENCE: u32 = 1 << 0;
    const BIOMETRY_CURRENT_SET: u32 = 1 << 3;
    const BUFFER: usize = 4096;

    extern "C" {
        fn credsd_presence_generate(
            flags: u32,
            out: *mut u8,
            cap: usize,
            len: *mut usize,
            pub_out: *mut u8,
            pub_cap: usize,
            pub_len: *mut usize,
        ) -> i32;
        fn credsd_presence_sign(
            key_blob: *const u8,
            key_blob_len: usize,
            message: *const u8,
            message_len: usize,
            reason: *const std::ffi::c_char,
            out: *mut u8,
            cap: usize,
            len: *mut usize,
        ) -> i32;
    }

    /// `biometry` → Touch ID only, invalidated if the enrolled fingerprints change;
    /// `presence` → Touch ID or the device passcode.
    pub fn flags_for(policy: &str) -> Option<u32> {
        match policy {
            "biometry" => Some(PRIVATE_KEY_USAGE | BIOMETRY_CURRENT_SET),
            "presence" => Some(PRIVATE_KEY_USAGE | USER_PRESENCE),
            _ => None,
        }
    }

    /// Returns `(dataRepresentation, X9.63 public key)`.
    pub fn generate(flags: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut blob = vec![0u8; BUFFER];
        let mut public = vec![0u8; 65];
        let (mut blob_len, mut pub_len) = (0usize, 0usize);
        // SAFETY: both output buffers are live and exactly the capacities passed; the shim writes
        // at most that many bytes, always writes the lengths, and retains no pointer past return.
        let rc = unsafe {
            credsd_presence_generate(
                flags,
                blob.as_mut_ptr(),
                blob.len(),
                &mut blob_len,
                public.as_mut_ptr(),
                public.len(),
                &mut pub_len,
            )
        };
        if rc != 0 || blob_len > BUFFER || pub_len != 65 {
            return Err(DaemonError::Storage(format!(
                "presence key generation failed ({rc})"
            )));
        }
        blob.truncate(blob_len);
        Ok((blob, public))
    }

    /// Blocks on the Touch ID prompt. An error means the user cancelled or failed it, or the blob
    /// is not this machine's.
    pub fn sign(blob: &[u8], message: &[u8], reason: &str) -> Result<Vec<u8>> {
        let reason = std::ffi::CString::new(reason.replace('\0', " "))
            .map_err(|e| DaemonError::config(e.to_string()))?;
        let mut out = vec![0u8; 256];
        let mut len = 0usize;
        // SAFETY: input slices and the C string are borrowed for the call and copied by the shim;
        // `out` is a live buffer of the capacity passed, and `len` a live usize.
        let rc = unsafe {
            credsd_presence_sign(
                blob.as_ptr(),
                blob.len(),
                message.as_ptr(),
                message.len(),
                reason.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
            )
        };
        let detail = || {
            let n = len.min(out.len());
            String::from_utf8_lossy(out.get(..n).unwrap_or_default()).into_owned()
        };
        let reason = match rc {
            0 if len <= out.len() => {
                out.truncate(len);
                return Ok(out);
            }
            -5 => "the presence key could not be loaded (not this machine's enclave)".to_owned(),
            -11 => "cancelled".to_owned(),
            -12 => "Touch ID is locked out after too many attempts".to_owned(),
            -13 => "Touch ID is not available (lid closed, or no fingerprint enrolled)".to_owned(),
            -14 => "the fingerprint was not recognised".to_owned(),
            -10 => format!("signing failed: {}", detail()),
            other => format!("signing failed ({other})"),
        };
        Err(DaemonError::config(reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&b)).unwrap(), b);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn signed_message_is_domain_separated() {
        let m = signed_message("req-1", &[7u8; 32]);
        assert!(m.starts_with(b"credsd-presence-v1\0req-1\0"));
        assert_eq!(m.len(), 18 + 1 + 5 + 1 + 32);
    }
}
