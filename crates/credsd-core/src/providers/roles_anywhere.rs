//! IAM Roles Anywhere provider: signs a `CreateSession` request with an X.509 certificate +
//! private key and exchanges it for short-lived AWS credentials.
//!
//! The private key is **encrypted at rest**, the same protection SSO/IAM-user secrets get:
//! `bootstrap` ingests the PEMs and seals the key into `ra_key.enc` via [`EncryptionService`]
//! (hardware-bound whenever the storage backend is keychain/credential-manager/tpm); the public
//! certificate + chain sit beside it in `ra_public.json`. Nothing plaintext-secret lands on disk
//! or in `credentials.toml`. At renew, the key is decrypted **in memory on the blocking thread**,
//! wrapped in a [`Zeroizing`] buffer, and fed to an in-memory [`CredentialIdentity`] — the
//! vendored `rolesanywhere_core` crate's seam for a non-file key source, so no crate edit is
//! needed. The signing + HTTP pipeline is the crate's blocking `generate_credentials_with_identity`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use rolesanywhere_core::identity::CredentialIdentity;
use rolesanywhere_core::pipeline::{
    generate_credentials_with_identity, CredentialProcessOutput, SignRequestInput,
};
use rolesanywhere_core::signer::{FileSystemSigner, Signer};
use rolesanywhere_core::types::SigningAlgorithm;
use serde::{Deserialize, Serialize};
use x509_cert::der::Decode;
use zeroize::{Zeroize, Zeroizing};

use crate::config::RolesAnywhereConfig;
use crate::credentials::Credentials;
use crate::encryption::EncryptionService;
use crate::error::{DaemonError, Result};
use crate::providers::{CredentialProvider, Renewed, Renewer};

/// Sealed private-key blob (inside `ra_key.enc`): the key DER (base64) plus its PEM tag, which
/// tells the signer whether the DER is PKCS#8/PKCS#1/SEC1. Encrypted at rest by `EncryptionService`.
#[derive(Serialize, Deserialize)]
struct SealedKey {
    key_der_b64: String,
    tag: String,
}

/// Public certificate material (`ra_public.json`): the leaf cert DER and any intermediate-chain
/// DERs, base64-encoded. Not secret — stored 0600 for tidiness, not confidentiality.
#[derive(Serialize, Deserialize)]
struct PublicMaterial {
    cert_der_b64: String,
    chain_der_b64: Vec<String>,
}

/// The sealed private key.
const KEY_FILE: &str = "ra_key.enc";
/// The (public) certificate + chain.
const PUBLIC_FILE: &str = "ra_public.json";

/// Seal an ingested key + persist its public certificate material under `data_dir`. Called by
/// bootstrap; the provider reads both back at renew. Mirrors `iam_user::persist_key_pair`
/// — the on-disk format lives here, in one place.
pub fn persist_ingested(
    encryption: &EncryptionService,
    data_dir: &Path,
    key_der: &[u8],
    key_tag: &str,
    cert_der: &[u8],
    chain_der: &[Vec<u8>],
) -> Result<()> {
    // Refuse a certificate outside its own validity window before anything is sealed: AWS would
    // reject it at CreateSession, but this names the cause at bootstrap, not at the first `get`.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| DaemonError::provider(format!("system clock before 1970: {e}")))?;
    check_expiry(cert_not_after(cert_der)?, now)?;

    // The serialized buffer holds the base64 of the private key until `seal_to_file` encrypts it,
    // so scrub it on drop.
    let sealed = Zeroizing::new(serde_json::to_vec(&SealedKey {
        key_der_b64: BASE64.encode(key_der),
        tag: key_tag.to_string(),
    })?);
    encryption.seal_to_file(&data_dir.join(KEY_FILE), &sealed)?;

    let public = serde_json::to_vec(&PublicMaterial {
        cert_der_b64: BASE64.encode(cert_der),
        chain_der_b64: chain_der.iter().map(|c| BASE64.encode(c)).collect(),
    })?;
    write_public_material(&data_dir.join(PUBLIC_FILE), &public)
}

fn write_public_material(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// A [`CredentialIdentity`] backed by an in-memory decrypted key — the vendored crate's seam for
/// a non-file key source. Built on the blocking thread from the sealed key + public material; the
/// decrypted DER lives only as long as `load_identity`'s `Zeroizing` buffer.
struct EncryptedKeyIdentity {
    signer: FileSystemSigner,
    cert_der: Vec<u8>,
    chain_der: Vec<Vec<u8>>,
}

impl CredentialIdentity for EncryptedKeyIdentity {
    fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }
    fn certificate_chain_der(&self) -> &[Vec<u8>] {
        &self.chain_der
    }
    fn signing_algorithm(&self) -> &SigningAlgorithm {
        self.signer.algorithm()
    }
    fn sign(&self, string_to_sign: &[u8]) -> std::result::Result<Vec<u8>, String> {
        self.signer.sign(string_to_sign)
    }
}

/// Decrypt the sealed key and load the public material into an in-memory identity. Runs on the
/// blocking thread. Errors are `String` so the caller can prefix them with the credential name;
/// the decrypted key never leaves this function except inside the returned signer.
fn load_identity(
    encryption: &EncryptionService,
    key_file: &Path,
    public_file: &Path,
) -> std::result::Result<EncryptedKeyIdentity, String> {
    let plaintext = encryption
        .open_from_file(key_file)
        .map_err(|e| e.detail())?;
    let mut sealed: SealedKey =
        serde_json::from_slice(&plaintext).map_err(|e| format!("sealed key malformed: {e}"))?;
    let key_der = Zeroizing::new(
        BASE64
            .decode(sealed.key_der_b64.as_bytes())
            .map_err(|e| format!("private key base64 decode failed: {e}"))?,
    );
    // The base64 of the key is a plaintext-secret copy; scrub it now that the DER is decoded.
    sealed.key_der_b64.zeroize();
    let signer = FileSystemSigner::from_der(&key_der, &sealed.tag)?;

    let pub_bytes = std::fs::read(public_file).map_err(|e| format!("read public material: {e}"))?;
    let public: PublicMaterial = serde_json::from_slice(&pub_bytes)
        .map_err(|e| format!("public material malformed: {e}"))?;
    let cert_der = BASE64
        .decode(public.cert_der_b64.as_bytes())
        .map_err(|e| format!("certificate base64 decode failed: {e}"))?;
    let mut chain_der = Vec::with_capacity(public.chain_der_b64.len());
    for c in &public.chain_der_b64 {
        chain_der.push(
            BASE64
                .decode(c.as_bytes())
                .map_err(|e| format!("chain base64 decode failed: {e}"))?,
        );
    }

    Ok(EncryptedKeyIdentity {
        signer,
        cert_der,
        chain_der,
    })
}

pub struct RolesAnywhereProvider {
    credential_name: String,
    config: RolesAnywhereConfig,
    encryption: Arc<EncryptionService>,
    data_dir: PathBuf,
}

impl RolesAnywhereProvider {
    pub fn new(
        credential_name: String,
        config: RolesAnywhereConfig,
        encryption: Arc<EncryptionService>,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            credential_name,
            config,
            encryption,
            data_dir,
        }
    }

    fn sign_input(&self) -> SignRequestInput {
        SignRequestInput {
            // The identity path supplies cert/key/chain; these path fields are ignored.
            cert_path: String::new(),
            key_path: String::new(),
            cert_chain_path: None,
            // The crate treats an empty region as "derive from the trust anchor ARN".
            region: self.config.region.clone().unwrap_or_default(),
            trust_anchor_arn: self.config.trust_anchor_arn.clone(),
            profile_arn: self.config.profile_arn.clone(),
            role_arn: self.config.role_arn.clone(),
            session_duration: self.config.duration_seconds,
            role_session_name: self.config.role_session_name.clone(),
            endpoint_url: self.config.endpoint_url.clone(),
        }
    }

    /// Decrypt the key, sign, and call CreateSession. The crate's pipeline is synchronous
    /// (blocking reqwest + crypto) and the decrypted key must not cross threads, so both the
    /// decrypt and the sign run on a blocking thread; the key is zeroized when it returns.
    pub async fn mint(&self) -> Result<Credentials> {
        let input = self.sign_input();
        let encryption = self.encryption.clone();
        let key_file = self.data_dir.join(KEY_FILE);
        let public_file = self.data_dir.join(PUBLIC_FILE);

        let out = tokio::task::spawn_blocking(
            move || -> std::result::Result<CredentialProcessOutput, String> {
                let identity = load_identity(&encryption, &key_file, &public_file)?;
                generate_credentials_with_identity(&input, &identity).map_err(|e| e.to_string())
            },
        )
        .await
        .map_err(|e| {
            DaemonError::provider(format!(
                "roles-anywhere '{}': signing task failed: {e}",
                self.credential_name
            ))
        })?
        .map_err(|e| {
            DaemonError::provider(format!("roles-anywhere '{}': {e}", self.credential_name))
        })?;

        let expires_at = DateTime::parse_from_rfc3339(&out.expiration)
            .map_err(|e| {
                DaemonError::provider(format!(
                    "roles-anywhere '{}': unparseable expiration '{}': {e}",
                    self.credential_name, out.expiration
                ))
            })?
            .with_timezone(&Utc);

        Ok(Credentials::session(
            out.access_key_id,
            out.secret_access_key,
            out.session_token,
            expires_at,
        ))
    }
}

impl CredentialProvider for RolesAnywhereProvider {
    // The sealed key re-signs a fresh CreateSession with no human, so this source always renews
    // unattended, with no interactive fallback.
    fn renewer(&self) -> Option<&dyn Renewer> {
        Some(self)
    }

    fn mode_name(&self) -> &'static str {
        "aws-roles-anywhere"
    }
}

#[async_trait]
impl Renewer for RolesAnywhereProvider {
    async fn renew(&self) -> Result<Renewed> {
        self.mint().await.map(Renewed::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_key;
    use tempfile::tempdir;

    fn service() -> Arc<EncryptionService> {
        Arc::new(EncryptionService::new(generate_key().unwrap()).unwrap())
    }

    fn config() -> RolesAnywhereConfig {
        RolesAnywhereConfig {
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/ta".into(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:111111111111:profile/p".into(),
            role_arn: "arn:aws:iam::111111111111:role/r".into(),
            region: None,
            duration_seconds: None,
            role_session_name: None,
            endpoint_url: None,
            identity_type: Default::default(),
        }
    }

    // The vendored crate ships PEM fixtures; read one into (der, tag) + cert DER via the crate's
    // own readers, exactly as bootstrap will. The fixtures live in the repo-root `vendor/` tree;
    // anchor to this crate's manifest dir so the path resolves regardless of `cargo test`'s CWD.
    fn rsa_fixture() -> (Zeroizing<Vec<u8>>, String, Vec<u8>) {
        let certs = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/rolesanywhere/tst/certs"
        );
        let key_path = format!("{certs}/rsa-2048-key.pem");
        let cert_path = format!("{certs}/rsa-2048-cert.pem");
        let (key_der, tag) =
            rolesanywhere_core::key_reader::read_private_key_der(key_path.as_str())
                .expect("read rsa key fixture");
        let cert_der = rolesanywhere_core::key_reader::read_certificate_der(cert_path.as_str())
            .expect("read rsa cert fixture");
        (key_der, tag, cert_der)
    }

    /// Seal an ingested key, then load it back into an in-memory identity — the encrypt→decrypt→
    /// from-DER round trip the provider runs at renew. Proves the sealed blob is usable and the
    /// signer is built from the decrypted key (RSA fixture → RSA algorithm).
    #[test]
    fn persist_then_load_builds_the_identity_from_the_decrypted_key() {
        let enc = service();
        let dir = tempdir().unwrap();
        let (key_der, tag, cert_der) = rsa_fixture();
        persist_ingested(&enc, dir.path(), &key_der, &tag, &cert_der, &[]).unwrap();

        let identity = load_identity(
            &enc,
            &dir.path().join(KEY_FILE),
            &dir.path().join(PUBLIC_FILE),
        )
        .expect("identity loads from sealed key + public material");
        assert_eq!(
            identity.signing_algorithm().as_str(),
            "AWS4-X509-RSA-SHA256"
        );
        assert_eq!(identity.certificate_der(), cert_der.as_slice());
        assert!(identity.certificate_chain_der().is_empty());
    }

    /// A missing `ra_key.enc` (nothing bootstrapped) surfaces as a provider error naming the
    /// credential — never a panic — so the store maps it to `Unavailable`, not a bare miss.
    #[tokio::test]
    async fn renew_without_a_sealed_key_errors_and_names_the_credential() {
        let dir = tempdir().unwrap();
        let err = RolesAnywhereProvider::new(
            "work".into(),
            config(),
            service(),
            dir.path().to_path_buf(),
        )
        .renew()
        .await
        .expect_err("missing sealed key must error")
        .to_string();
        assert!(
            err.contains("roles-anywhere 'work'"),
            "error should name the credential, got: {err}"
        );
    }

    /// A key sealed under one keystore key cannot be opened with another (keystore rotated / wrong
    /// backend): the decrypt failure surfaces as a named provider error, not a panic.
    #[tokio::test]
    async fn renew_with_an_undecryptable_key_errors() {
        let dir = tempdir().unwrap();
        let (key_der, tag, cert_der) = rsa_fixture();
        persist_ingested(&service(), dir.path(), &key_der, &tag, &cert_der, &[]).unwrap();

        // A different EncryptionService (different key) cannot decrypt the sealed blob.
        let err = RolesAnywhereProvider::new(
            "work".into(),
            config(),
            service(),
            dir.path().to_path_buf(),
        )
        .renew()
        .await
        .expect_err("wrong keystore key must error")
        .to_string();
        assert!(err.contains("roles-anywhere 'work'"), "got: {err}");
    }
}

/// The certificate's `notAfter` as a duration since the Unix epoch.
fn cert_not_after(cert_der: &[u8]) -> Result<Duration> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| DaemonError::provider(format!("certificate: cert-parse-failed: {e}")))?;
    Ok(cert.tbs_certificate.validity.not_after.to_unix_duration())
}

/// Refuse `now` at or past `not_after`. Only the end of the window is checked: a start bound would
/// turn local clock skew into a refusal that AWS itself would not make. Pure so the boundary is
/// testable at any instant; the caller supplies the clock.
fn check_expiry(not_after: Duration, now: Duration) -> Result<()> {
    if now >= not_after {
        let at = DateTime::<Utc>::from_timestamp(not_after.as_secs() as i64, 0)
            .map_or_else(|| "an unrepresentable time".to_owned(), |t| t.to_rfc3339());
        return Err(DaemonError::provider(format!(
            "certificate expired at {at}; issue a new certificate and bootstrap again"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod validity_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Refused exactly when `now` is at or past `not_after`, across the whole i64 seconds range.
        #[test]
        fn refuses_exactly_at_or_after_not_after(
            not_after in 0u64..=i64::MAX as u64,
            now in 0u64..=i64::MAX as u64,
        ) {
            let accepted = check_expiry(Duration::from_secs(not_after), Duration::from_secs(now)).is_ok();
            prop_assert_eq!(accepted, now < not_after);
        }
    }

    #[test]
    fn the_last_instant_before_not_after_is_accepted_and_not_after_is_refused() {
        let end = Duration::from_secs(2_000);
        assert!(check_expiry(end, Duration::from_secs(1_999)).is_ok());
        let err = check_expiry(end, end).unwrap_err().to_string();
        assert!(err.contains("expired"), "{err}");
    }
}
