//! Bearer token generation and validation for the ephemeral per-invocation proxy.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::{DaemonError, Result};

/// Generate a one-time bearer token that is not written to disk.
pub fn generate_ephemeral_token() -> Result<String> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes)
        .map_err(|_| DaemonError::Encryption("failed to generate bearer token".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Constant-time comparison of an Authorization header value against the expected token.
pub fn validate_bearer(header_value: &str, expected: &str) -> bool {
    let token = header_value.strip_prefix("Bearer ").unwrap_or(header_value);
    constant_time_eq(token.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_bearer_with_prefix() {
        assert!(validate_bearer("Bearer abc123", "abc123"));
    }

    #[test]
    fn validate_bearer_without_prefix() {
        assert!(validate_bearer("abc123", "abc123"));
    }

    #[test]
    fn validate_bearer_rejects_wrong_token() {
        assert!(!validate_bearer("Bearer wrong", "correct"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
