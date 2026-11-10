//! PKCE (RFC 7636) helpers for the OAuth authorization-code flow.
//!
//! A fresh high-entropy `code_verifier` is generated per login; its S256
//! `code_challenge` goes in the authorization request, and the verifier is sent
//! only on the token exchange. This binds the redeemed code to this client even
//! if the authorization response leaks.

use aws_lc_rs::{digest, rand};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{DaemonError, Result};

/// A PKCE verifier/challenge pair for one authorization-code flow.
///
/// `ZeroizeOnDrop` because the verifier is the secret half: whoever holds it can redeem the
/// authorization code. It lives across an await in `PendingLogin` for up to 5 minutes, which is
/// exactly the window worth scrubbing. Matches `CachedOAuthToken` and `DpopSigner` in this module.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pkce {
    /// Secret sent on the token exchange. 43 chars of base64url (32 random bytes).
    pub verifier: String,
    /// `S256(verifier)`, base64url-nopad — sent in the authorization request.
    pub challenge: String,
}

impl Pkce {
    /// Generate a fresh pair. The verifier is 32 random bytes base64url-encoded
    /// (43 chars — within RFC 7636's 43–128 range); the challenge is its SHA-256.
    pub fn generate() -> Result<Self> {
        let bytes: [u8; 32] = rand::generate(&rand::SystemRandom::new())
            .map_err(|_| DaemonError::provider("PKCE: RNG failure"))?
            .expose();
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let digest = digest::digest(&digest::SHA256, verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest.as_ref());
        Ok(Self {
            verifier,
            challenge,
        })
    }
}

/// A random URL-safe token (state / jti). `n` bytes of entropy, base64url-nopad.
pub fn random_token(n: usize) -> Result<String> {
    // aws-lc-rs `generate` is const-generic over the length; call the common sizes.
    let rng = rand::SystemRandom::new();
    let bytes: Vec<u8> = match n {
        16 => rand::generate::<[u8; 16]>(&rng)
            .map_err(|_| DaemonError::provider("RNG failure"))?
            .expose()
            .to_vec(),
        _ => rand::generate::<[u8; 32]>(&rng)
            .map_err(|_| DaemonError::provider("RNG failure"))?
            .expose()
            .to_vec(),
    };
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_sha256_of_verifier() {
        let p = Pkce::generate().unwrap();
        // Recompute independently: challenge == base64url(SHA256(verifier)).
        let expected =
            URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, p.verifier.as_bytes()));
        assert_eq!(p.challenge, expected);
        // 32 bytes → 43 base64url chars, no padding.
        assert_eq!(p.verifier.len(), 43);
        assert!(!p.challenge.contains('='));
    }

    #[test]
    fn verifiers_are_unique() {
        let a = Pkce::generate().unwrap();
        let b = Pkce::generate().unwrap();
        assert_ne!(a.verifier, b.verifier);
    }

    #[test]
    fn random_token_is_urlsafe_and_unique() {
        let a = random_token(32).unwrap();
        let b = random_token(32).unwrap();
        assert_ne!(a, b);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }
}
