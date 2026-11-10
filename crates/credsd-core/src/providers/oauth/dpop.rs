//! DPoP (RFC 9449) proof signer — sender-constrains the OAuth token credsd obtains.
//!
//! credsd is the client of the IdP's token endpoint, so it mints the per-request
//! DPoP proof itself (in-process). The proof is a compact ES256 JWS over
//! `{jti, htm, htu, iat, ath?, nonce?}` with the public JWK in the header; the
//! authorization server binds the issued token to this key. The private key is an
//! ES256 (P-256) keypair, sealed at rest via [`EncryptionService`] and decrypted
//! only to sign. Only used credsd↔IdP; the child never handles DPoP.
//!
//! The JWS is hand-rolled (base64url + serde_json + aws-lc-rs) — no JOSE crate —
//! and uses aws-lc-rs's FIXED (`r‖s`, 64-byte) ECDSA signatures, which is exactly
//! the JOSE ES256 encoding.

use std::path::Path;

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use zeroize::Zeroizing;

use super::pkce::random_token;
use crate::encryption::EncryptionService;
use crate::error::{DaemonError, Result};

/// Encrypted file (under the credential's data dir) holding the sealed PKCS#8 key.
const KEY_FILE: &str = "dpop_key.enc";

pub struct DpopSigner {
    /// PKCS#8 DER of the ES256 private key. `Zeroizing` scrubs it on drop; it is the
    /// only in-memory copy of the key material.
    pkcs8: Zeroizing<Vec<u8>>,
    /// Uncompressed SEC1 public point `0x04 || X(32) || Y(32)` (65 bytes).
    public_point: Vec<u8>,
}

impl DpopSigner {
    /// Generate a fresh ES256 keypair **without** writing it to disk.
    ///
    /// Sealing is [`seal`](Self::seal), deliberately separate. A login binds its token to the key
    /// it advertised, so writing the key before the token exists means an abandoned login — Ctrl-C,
    /// no browser, the 300s timeout — leaves `dpop_key.enc` holding key B while `oauth_token.enc`
    /// still holds a refresh token bound to key A. That mismatch is invisible until the token
    /// nears expiry, because only the refresh path signs with the key.
    pub fn generate_unsealed() -> Result<Self> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| DaemonError::provider("DPoP: keypair generation failed"))?;
        Self::from_pkcs8(Zeroizing::new(doc.as_ref().to_vec()))
    }

    /// Seal the private key to `dpop_key.enc`.
    ///
    /// Call this only once the token bound to this key is about to be persisted, and as close to
    /// that write as possible: the two files must agree, and nothing here can make them atomic.
    pub fn seal(&self, encryption: &EncryptionService, data_dir: &Path) -> Result<()> {
        encryption.seal_to_file(&data_dir.join(KEY_FILE), &self.pkcs8)
    }

    /// Reconstruct the signer from the sealed key on disk.
    pub fn from_encrypted(encryption: &EncryptionService, data_dir: &Path) -> Result<Self> {
        let pkcs8 = encryption
            .open_from_file(&data_dir.join(KEY_FILE))
            .map_err(|e| DaemonError::provider(format!("DPoP: no usable key: {}", e.detail())))?;
        Self::from_pkcs8(pkcs8)
    }

    fn from_pkcs8(pkcs8: Zeroizing<Vec<u8>>) -> Result<Self> {
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
            .map_err(|_| DaemonError::provider("DPoP: malformed private key"))?;
        Ok(Self {
            pkcs8,
            public_point: kp.public_key().as_ref().to_vec(),
        })
    }

    fn coords(&self) -> Result<(String, String)> {
        // Uncompressed SEC1 point: 0x04 (1) || X (32) || Y (32) = 65 bytes. Destructured by
        // slice pattern, so the length check and the coordinate split are one statement and
        // cannot disagree about where X ends.
        let [0x04, x @ ..] = self.public_point.as_slice() else {
            return Err(DaemonError::provider(
                "DPoP: unexpected public key encoding",
            ));
        };
        let (x, y) = x
            .split_at_checked(32)
            .filter(|(_, y)| y.len() == 32)
            .ok_or_else(|| DaemonError::provider("DPoP: unexpected public key encoding"))?;
        Ok((URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y)))
    }

    /// RFC 7638 JWK thumbprint (`jkt`) of the public key — base64url(SHA-256 of the
    /// canonical JWK: members lexicographically ordered, no whitespace). The
    /// authorization request advertises this so the AS binds the token to the key.
    pub fn jkt(&self) -> Result<String> {
        let (x, y) = self.coords()?;
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, x, y);
        Ok(URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, canonical.as_bytes()).as_ref()))
    }

    /// Build and sign a DPoP proof JWT for one request. `htm`/`htu` bind it to the
    /// HTTP method + URI; `nonce` echoes a server `DPoP-Nonce`; `ath` is the base64url
    /// SHA-256 of the access token (only when presenting a token to a resource).
    pub fn sign(
        &self,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
        ath: Option<&str>,
    ) -> Result<String> {
        let (x, y) = self.coords()?;
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {"crv": "P-256", "kty": "EC", "x": x, "y": y},
        });
        let mut claims = serde_json::Map::new();
        claims.insert("jti".into(), random_token(16)?.into());
        claims.insert("htm".into(), htm.into());
        // RFC 9449 §4.2: `htu` is the request URI with query and fragment removed. Servers that
        // normalize both sides accept the raw form, which is why sending it works against some
        // IdPs and not others.
        claims.insert("htu".into(), htu_claim(htu).into());
        claims.insert("iat".into(), Utc::now().timestamp().into());
        if let Some(ath) = ath {
            claims.insert("ath".into(), ath.into());
        }
        if let Some(nonce) = nonce {
            claims.insert("nonce".into(), nonce.into());
        }

        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::Value::Object(claims))?),
        );

        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.pkcs8)
            .map_err(|_| DaemonError::provider("DPoP: malformed private key"))?;
        let sig = kp
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .map_err(|_| DaemonError::provider("DPoP: signing failed"))?;
        // FIXED signing yields the 64-byte r‖s that JOSE ES256 requires — emit as-is.
        Ok(format!(
            "{}.{}",
            signing_input,
            URL_SAFE_NO_PAD.encode(sig.as_ref())
        ))
    }
}

/// Parse a PEM-encoded ES256 private key into PKCS#8 DER for sealing.
///
/// Accepts PKCS#8 PEM (`BEGIN PRIVATE KEY`) only. SEC1/ECPrivateKey PEM
/// (`BEGIN EC PRIVATE KEY`) is not supported — convert first with
/// `openssl pkcs8 -topk8 -nocrypt`. Validation confirms the key is
/// well-formed ES256 before it touches disk.
pub fn pkcs8_from_pem(pem: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    // Strip the PEM wrapper and decode base64.
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| DaemonError::Config(format!("private key PEM: base64 decode failed: {e}")))?;
    let pkcs8 = zeroize::Zeroizing::new(der);
    // Validate by trying to construct the key pair; rejects wrong curve, bad encoding, etc.
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
        .map_err(|_| DaemonError::Config("private key PEM: not a valid ES256 (P-256) PKCS#8 key — use openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256".into()))?;
    Ok(pkcs8)
}

/// The `htu` claim for a request URI: scheme, authority and path, with query and fragment
/// removed (RFC 9449 §4.2). Split rather than parsed — a URL crate is not warranted for
/// "truncate at the first `?` or `#`", and the input is already an absolute URL by then.
fn htu_claim(uri: &str) -> &str {
    let end = uri.find(['?', '#']).unwrap_or(uri.len());
    uri.get(..end).unwrap_or(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_key;
    use aws_lc_rs::signature;
    use tempfile::tempdir;

    fn signer() -> (DpopSigner, tempfile::TempDir) {
        // No `EncryptionService` here: `generate_unsealed` touches no disk, so a signer that is
        // only exercised in memory needs neither a key nor a directory to seal into.
        (DpopSigner::generate_unsealed().unwrap(), tempdir().unwrap())
    }

    /// A proof this signer produces verifies under its own public key.
    /// The coordinate split is a slice pattern now, so a point of the wrong length or the wrong
    /// Generating a key must not touch disk. An abandoned login would otherwise leave
    /// `dpop_key.enc` bound to a token that was never written, and the mismatch only surfaces at
    /// the next refresh — long after the user could connect it to anything they did.
    /// RFC 9449 §4.2 requires query and fragment stripped from `htu`. A verifier that does not
    /// normalize both sides rejects the proof otherwise, which reads as an IdP-specific failure.
    #[test]
    fn htu_strips_query_and_fragment() {
        for (input, want) in [
            ("https://idp.example/token", "https://idp.example/token"),
            ("https://idp.example/token?x=1", "https://idp.example/token"),
            (
                "https://idp.example/token#frag",
                "https://idp.example/token",
            ),
            (
                "https://idp.example/token?x=1#f",
                "https://idp.example/token",
            ),
            ("https://idp.example/", "https://idp.example/"),
        ] {
            assert_eq!(htu_claim(input), want, "input {input}");
        }
    }

    #[test]
    fn generating_a_key_does_not_write_it() {
        let enc = EncryptionService::new(generate_key().unwrap()).unwrap();
        let dir = tempdir().unwrap();
        let key_file = dir.path().join(KEY_FILE);

        let first = DpopSigner::generate_unsealed().unwrap();
        first.seal(&enc, dir.path()).unwrap();
        let sealed_jkt = first.jkt().unwrap();

        // A second flow that is started and abandoned must leave the sealed key untouched.
        let abandoned = DpopSigner::generate_unsealed().unwrap();
        assert_ne!(abandoned.jkt().unwrap(), sealed_jkt, "keys should differ");
        assert_eq!(
            DpopSigner::from_encrypted(&enc, dir.path())
                .unwrap()
                .jkt()
                .unwrap(),
            sealed_jkt,
            "an abandoned login rotated the key out from under the stored token"
        );
        assert!(key_file.exists());
    }

    /// leading tag must be refused rather than silently yielding short coordinates.
    #[test]
    fn coords_refuse_a_malformed_point() {
        let signer = DpopSigner::generate_unsealed().unwrap();

        // The real key round-trips to two 32-byte coordinates.
        let (x, y) = signer.coords().expect("well-formed point");
        assert_eq!(URL_SAFE_NO_PAD.decode(&x).unwrap().len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.decode(&y).unwrap().len(), 32);

        for bad in [
            vec![],         // empty
            vec![0x04],     // tag only
            vec![0x04; 64], // one byte short
            vec![0x04; 66], // one byte long
            {
                let mut compressed = vec![0x02]; // compressed-point tag, not uncompressed
                compressed.extend(std::iter::repeat_n(0u8, 64));
                compressed
            },
        ] {
            let mut broken = DpopSigner::generate_unsealed().unwrap();
            broken.public_point = bad.clone();
            assert!(
                broken.coords().is_err(),
                "a {}-byte point starting {:?} must be refused",
                bad.len(),
                bad.first()
            );
        }
    }

    #[test]
    fn generate_sign_verify_round_trip() {
        let (s, _d) = signer();
        let proof = s.sign("POST", "https://idp/token", None, None).unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let pubkey =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &s.public_point);
        pubkey
            .verify(signing_input.as_bytes(), &sig)
            .expect("valid proof verifies");

        // Header carries typ/alg/jwk; claims carry the bound request.
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://idp/token");
    }

    /// A proof from one key must not verify under a different key.
    #[test]
    fn wrong_key_fails_verification() {
        let (a, _da) = signer();
        let (b, _db) = signer();
        let proof = a.sign("POST", "https://idp/token", None, None).unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let wrong =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &b.public_point);
        assert!(wrong.verify(signing_input.as_bytes(), &sig).is_err());
    }

    /// The signer survives a seal → reopen round-trip and still signs verifiably.
    #[test]
    fn from_encrypted_round_trips() {
        let dir = tempdir().unwrap();
        let enc = EncryptionService::new(generate_key().unwrap()).unwrap();
        let jkt = {
            let s = DpopSigner::generate_unsealed().unwrap();
            // `generate_unsealed` no longer writes: seal explicitly so `from_encrypted` has
            // something to reopen. That separation is the point of the split.
            s.seal(&enc, dir.path()).unwrap();
            s.jkt().unwrap()
        };
        let reopened = DpopSigner::from_encrypted(&enc, dir.path()).unwrap();
        // Same key → same thumbprint.
        assert_eq!(reopened.jkt().unwrap(), jkt);
    }
}
