//! TPM 2.0 sealing backend (`Backend::Tpm`), Linux only.
//!
//! Seals the AES-256 master key to a TPM 2.0 device. The sealed blob and a
//! non-secret policy sidecar live on disk under `<data_dir>/tpm/`; the plaintext
//! key exists only in TPM and process memory. See
//! `docs/specs/tpm-encryption-backend/`.
//!
//! ## Layering
//!
//! All *logic* here — policy, sidecar, store/retrieve/delete, and the
//! recovery/purge helpers — is generic over the [`TpmSeam`] trait and is
//! compiled and unit-tested without any TPM hardware or the `tpm` feature (via
//! `FakeSeam` in tests). The real device glue, [`esapi::EsapiSeam`], is behind
//! the off-by-default `tpm` cargo feature because it links the system
//! `tpm2-tss` C libraries and needs an actual TPM 2.0 device.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{DaemonError, Result};
use crate::storage::SecureStorage;

/// The one sealing policy this build writes and unseals: an empty policy under the SRK, so the
/// blob unseals on the same TPM regardless of boot state. The sidecar records it so a future
/// policy can be told apart from this one, and so a blob sealed under a policy this build does
/// not support is refused rather than unsealed under the wrong one.
const MACHINE_POLICY: &str = "machine";

/// Non-secret sidecar written next to each sealed blob.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SealMeta {
    pub(crate) policy: String,
    /// RFC-3339 timestamp of key creation, diagnostics only.
    pub(crate) created_at: String,
}

/// The minimal set of TPM operations the backend needs, isolated so the storage
/// logic can be tested with a fake and the real `tss-esapi` glue stays in one
/// place. `seal` returns the opaque sealed blob to persist; `unseal` recovers
/// the plaintext.
pub(crate) trait TpmSeam: Send + Sync {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>>;
}

/// A `SecureStorage` that seals values to a TPM via a [`TpmSeam`].
pub(crate) struct TpmStorage<S: TpmSeam> {
    dir: PathBuf,
    seam: S,
}

impl<S: TpmSeam> TpmStorage<S> {
    fn new_in(dir: PathBuf, seam: S) -> Self {
        Self { dir, seam }
    }

    fn blob_path(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{}.sealed", key_id))
    }

    fn meta_path(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{}.meta", key_id))
    }
}

/// Marker substrings so the key-init path can tell "no blob yet" (first run)
/// from "blob present but will not unseal" (reboot/TPM-reset recovery). The
/// caller keys recovery off `exists()` being true, so these are for humans.
const ABSENT_MARKER: &str = "no sealed key present";

impl<S: TpmSeam> SecureStorage for TpmStorage<S> {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        // The TPM does not authorize the unseal, so these modes are what keep the blob from
        // other local users. A filesystem that refuses them has to fail the store, not pass it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let blob = self.seam.seal(data)?;

        let meta = SealMeta {
            policy: MACHINE_POLICY.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        write_0600(&self.blob_path(key_id), &blob)?;
        write_0600(&self.meta_path(key_id), &serde_json::to_vec(&meta)?)?;
        Ok(())
    }

    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        let blob_path = self.blob_path(key_id);
        match std::fs::symlink_metadata(&blob_path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(DaemonError::Storage(format!(
                    "{ABSENT_MARKER} for '{key_id}'"
                )));
            }
            Err(e) => {
                return Err(DaemonError::Storage(format!(
                    "cannot stat sealed key '{}': {e}",
                    blob_path.display()
                )));
            }
        }
        let blob = std::fs::read(&blob_path)?;

        // A present blob with a missing/corrupt sidecar is treated as unsealable
        // (fail safe to recovery) rather than guessing a policy.
        let meta_bytes = std::fs::read(self.meta_path(key_id)).map_err(|e| {
            DaemonError::Storage(format!(
                "sealed key '{key_id}' has no readable policy sidecar: {e}"
            ))
        })?;
        let meta: SealMeta = serde_json::from_slice(&meta_bytes).map_err(|e| {
            DaemonError::Storage(format!("policy sidecar for '{key_id}' is malformed: {e}"))
        })?;

        if meta.policy != MACHINE_POLICY {
            return Err(DaemonError::Storage(format!(
                "sealed key '{key_id}' was sealed under the '{}' policy, which this build \
                 does not support",
                meta.policy
            )));
        }

        self.seam.unseal(&blob).map_err(|e| {
            DaemonError::Storage(format!(
                "could not unseal key '{key_id}' (TPM cleared or replaced): {e}"
            ))
        })
    }

    fn delete(&self, key_id: &str) -> Result<()> {
        for path in [self.blob_path(key_id), self.meta_path(key_id)] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(DaemonError::Storage(format!(
                        "cannot delete '{}': {e}",
                        path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    fn exists(&self, key_id: &str) -> Result<bool> {
        let path = self.blob_path(key_id);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(DaemonError::Storage(format!(
                "cannot stat sealed key '{}': {e}",
                path.display()
            ))),
        }
    }

    fn backend_name(&self) -> &'static str {
        "tpm"
    }
}

/// Written through a temporary file that is 0600 from creation and renamed into place, so the
/// bytes are never readable at the umask's mode, and a crash mid-write cannot truncate a blob the
/// next start would then treat as a lost key.
fn write_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Construct the production TPM storage: blobs
/// under `<data_dir>/tpm`, and the real device seam when built with the `tpm`
/// feature. Without the feature the seam is [`UnsupportedSeam`], whose seal /
/// unseal return a clear "requires the tpm feature" error — so the logic is
/// always compiled (and tested) while the C-linked device glue stays optional.
pub(crate) fn production_storage() -> Result<Box<dyn SecureStorage>> {
    // An operator who set this expected a PCR binding; starting without one would leave them
    // believing the key is sealed to Secure Boot state when it is not.
    if std::env::var_os("CREDSD_TPM_POLICY").is_some() {
        return Err(DaemonError::config(
            "CREDSD_TPM_POLICY is not supported: the tpm backend seals under the machine \
             policy only. Unset it to start.",
        ));
    }
    let dir = crate::config::platform::data_dir().join("tpm");

    #[cfg(feature = "tpm")]
    {
        let seam = esapi::EsapiSeam::open()?;
        Ok(Box::new(TpmStorage::new_in(dir, seam)))
    }
    #[cfg(not(feature = "tpm"))]
    {
        Ok(Box::new(TpmStorage::new_in(dir, UnsupportedSeam)))
    }
}

/// Seam used when credsd is built without the `tpm` feature: it cannot reach a
/// TPM, so every seal/unseal is a clear configuration error rather than a panic
/// or a silent fallback to a weaker backend.
#[cfg(not(feature = "tpm"))]
struct UnsupportedSeam;

#[cfg(not(feature = "tpm"))]
impl TpmSeam for UnsupportedSeam {
    fn seal(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(DaemonError::config(
            "tpm backend requires building credsd with the `tpm` feature",
        ))
    }
    fn unseal(&self, _blob: &[u8]) -> Result<Vec<u8>> {
        Err(DaemonError::config(
            "tpm backend requires building credsd with the `tpm` feature",
        ))
    }
}

#[cfg(feature = "tpm")]
mod esapi {
    //! Real `tss-esapi` seal/unseal.
    //!
    //! The `machine` policy round-trips against swtpm (see
    //! `esapi_seal_unseal_round_trip`); no CI row provides a TPM, so nothing here is
    //! exercised by a default run. Binding to a real TPM's seed remains unvalidated —
    //! confirm it on a TPM 2.0 host before relying on it. The command sequence is:
    //!
    //! seal:   CreatePrimary(Owner -> SRK) -> Create(keyedhash, sensitive=data)
    //!         -> persist (out_public, out_private) as the blob.
    //! unseal: CreatePrimary(Owner -> SRK) -> Load(blob) -> Unseal.
    use super::TpmSeam;
    use crate::error::{DaemonError, Result};
    use std::str::FromStr;

    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        handles::KeyHandle,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            key_bits::RsaKeyBits,
            resource_handles::Hierarchy,
        },
        structures::{
            CreatePrimaryKeyResult, Digest, KeyedHashScheme, Private, Public, PublicBuilder,
            PublicKeyRsa, PublicKeyedHashParameters, PublicRsaParametersBuilder, RsaExponent,
            RsaScheme, SensitiveData, SymmetricDefinitionObject,
        },
        traits::{Marshall, UnMarshall},
        Context, TctiNameConf,
    };

    fn map_err<E: std::fmt::Display>(ctx: &str) -> impl Fn(E) -> DaemonError + '_ {
        move |e| DaemonError::Storage(format!("tpm {ctx}: {e}"))
    }

    /// The kernel resource manager, always, outside this crate's tests. An environment TCTI
    /// (`TPM2TOOLS_TCTI`/`TCTI`/`TEST_TCTI`) can name a socket, and a socket TCTI is
    /// unauthenticated: whoever binds the port would be the TPM. Tests honor it so the swtpm
    /// round trip can run without a kernel device.
    pub(super) fn tcti(honor_env: bool) -> Result<TctiNameConf> {
        match honor_env.then(TctiNameConf::from_environment_variable) {
            Some(Ok(t)) => Ok(t),
            _ => TctiNameConf::from_str("device:/dev/tpmrm0").map_err(map_err("tcti config")),
        }
    }

    fn context() -> Result<Context> {
        Context::new(tcti(cfg!(test))?).map_err(map_err("open device"))
    }

    /// SRK: a restricted RSA-2048 decryption (storage) primary under the Owner
    /// hierarchy, with no auth policy so it is usable as a parent without a
    /// policy session. Deterministic from the owner seed, so the same TPM
    /// re-derives the same parent on every process start (this is what binds the
    /// sealed blob to the machine). Template mirrors tss-esapi's own EK RSA-2048
    /// storage profile, minus the EK auth policy.
    fn create_srk(ctx: &mut Context) -> Result<CreatePrimaryKeyResult> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_restricted(true)
            .with_decrypt(true)
            .with_sign_encrypt(false)
            .build()
            .map_err(map_err("srk attrs"))?;

        let rsa_params = PublicRsaParametersBuilder::new()
            .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
            .with_scheme(RsaScheme::Null)
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_exponent(RsaExponent::default())
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(true)
            .build()
            .map_err(map_err("srk rsa params"))?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .map_err(map_err("srk public"))?;

        ctx.execute_with_nullauth_session(|c| {
            c.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .map_err(map_err("create primary"))
    }

    pub(crate) struct EsapiSeam;

    impl EsapiSeam {
        pub(crate) fn open() -> Result<Self> {
            // Verify the device answers before committing to this backend so an
            // unusable TPM is a hard error, not a silent fallback (spec Req 1.4).
            let mut ctx = context()?;
            let srk = create_srk(&mut ctx)?;
            ctx.flush_context(srk.key_handle.into()).ok();
            Ok(EsapiSeam)
        }
    }

    impl TpmSeam for EsapiSeam {
        fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            let mut ctx = context()?;
            let srk = create_srk(&mut ctx)?;

            let attrs = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_user_with_auth(true)
                .with_no_da(true)
                .build()
                .map_err(map_err("object attrs"))?;

            let public = PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::KeyedHash)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(attrs)
                .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
                .with_keyed_hash_unique_identifier(Digest::default())
                .build()
                .map_err(map_err("build public"))?;

            let sensitive =
                SensitiveData::try_from(plaintext.to_vec()).map_err(map_err("sensitive data"))?;

            let created = ctx
                .execute_with_nullauth_session(|c| {
                    c.create(srk.key_handle, public, None, Some(sensitive), None, None)
                })
                .map_err(map_err("create sealed object"))?;

            ctx.flush_context(srk.key_handle.into()).ok();

            // Blob = length-prefixed (public || private) so unseal can split it.
            let public_bytes: Vec<u8> = created
                .out_public
                .marshall()
                .map_err(map_err("marshall public"))?;
            let private_bytes: &[u8] = created.out_private.value();
            let plen = u32::try_from(public_bytes.len())
                .map_err(|_| DaemonError::Storage("tpm: sealed public too large".into()))?;
            let mut blob = Vec::new();
            blob.extend_from_slice(&plen.to_le_bytes());
            blob.extend_from_slice(&public_bytes);
            blob.extend_from_slice(private_bytes);
            Ok(blob)
        }

        fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>> {
            let truncated = || DaemonError::Storage("tpm: truncated sealed blob".into());
            let len_bytes: [u8; 4] = blob
                .get(..4)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(truncated)?;
            let plen = u32::from_le_bytes(len_bytes) as usize;
            let rest = blob.get(4..).ok_or_else(truncated)?;
            let public_bytes = rest.get(..plen).ok_or_else(truncated)?;
            let private_bytes = rest.get(plen..).ok_or_else(truncated)?;
            let public = Public::unmarshall(public_bytes).map_err(map_err("unmarshall public"))?;
            let private = Private::try_from(private_bytes.to_vec()).map_err(map_err("private"))?;

            let mut ctx = context()?;
            let srk = create_srk(&mut ctx)?;

            let object: KeyHandle = ctx
                .execute_with_nullauth_session(|c| c.load(srk.key_handle, private, public))
                .map_err(map_err("load sealed object"))?;

            let out = ctx
                .execute_with_nullauth_session(|c| c.unseal(object.into()))
                .map_err(map_err("unseal"))?;

            ctx.flush_context(object.into()).ok();
            Ok(out.value().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Reversible non-identity transform so a "sealed" blob differs from the
    /// plaintext (lets us assert no-cleartext-on-disk) and can be flipped to
    /// simulate a policy/TPM change that makes unseal fail.
    #[derive(Clone, Default)]
    struct FakeSeam {
        broken: Arc<AtomicBool>,
    }

    impl FakeSeam {
        fn break_unseal(&self) {
            self.broken.store(true, Ordering::SeqCst);
        }
    }

    impl TpmSeam for FakeSeam {
        fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            Ok(plaintext.iter().map(|b| b ^ 0x5A).collect())
        }
        fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>> {
            if self.broken.load(Ordering::SeqCst) {
                return Err(DaemonError::Storage("simulated policy mismatch".into()));
            }
            Ok(blob.iter().map(|b| b ^ 0x5A).collect())
        }
    }

    fn storage(dir: &Path) -> TpmStorage<FakeSeam> {
        TpmStorage::new_in(dir.to_path_buf(), FakeSeam::default())
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        let key = b"encryption-key-bytes-here-32byte";
        s.store("daemon-encryption-key", key).unwrap();
        assert!(s.exists("daemon-encryption-key").unwrap());
        assert_eq!(s.retrieve("daemon-encryption-key").unwrap(), key);
    }

    #[test]
    fn absent_and_unsealable_are_distinguishable() {
        let dir = tempfile::tempdir().unwrap();
        let seam = FakeSeam::default();
        let s = TpmStorage::new_in(dir.path().to_path_buf(), seam.clone());

        // Absent: no blob, exists() false, retrieve() errors with the absent marker.
        assert!(!s.exists("k").unwrap());
        let absent = s.retrieve("k").unwrap_err().to_string();
        assert!(absent.contains(ABSENT_MARKER), "unexpected: {absent}");

        // Unsealable: blob present (exists() true) but the seam refuses to unseal.
        s.store("k", b"0123456789abcdef0123456789abcdef").unwrap();
        seam.break_unseal();
        assert!(s.exists("k").unwrap());
        let unsealable = s.retrieve("k").unwrap_err().to_string();
        assert!(
            !unsealable.contains(ABSENT_MARKER),
            "should not be absent: {unsealable}"
        );
        assert!(
            unsealable.contains("could not unseal"),
            "unexpected: {unsealable}"
        );
    }

    #[test]
    fn no_cleartext_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        let key = b"0123456789abcdef0123456789abcdef";
        s.store("k", key).unwrap();
        let blob = std::fs::read(dir.path().join("k.sealed")).unwrap();
        assert_ne!(blob, key, "sealed blob must not equal the plaintext key");
    }

    #[test]
    fn delete_is_idempotent_and_removes_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        s.delete("missing").unwrap(); // idempotent
        s.store("k", b"0123456789abcdef0123456789abcdef").unwrap();
        assert!(dir.path().join("k.meta").exists());
        s.delete("k").unwrap();
        assert!(!s.exists("k").unwrap());
        assert!(!dir.path().join("k.meta").exists());
    }

    #[test]
    fn sidecar_records_policy_and_holds_no_secret() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"SECRETKEYSECRETKEYSECRETKEY32byt";
        storage(dir.path()).store("k", key).unwrap();
        let meta_bytes = std::fs::read(dir.path().join("k.meta")).unwrap();
        let meta: SealMeta = serde_json::from_slice(&meta_bytes).unwrap();
        assert_eq!(meta.policy, "machine");
        // The sidecar must not leak key bytes.
        assert!(!meta_bytes.windows(key.len()).any(|w| w == key));
    }

    /// Earlier builds also wrote a `pcr_selection` field; a machine-policy sidecar carrying it
    /// still unseals.
    #[test]
    fn a_sidecar_from_an_earlier_build_still_unseals() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        let key = b"0123456789abcdef0123456789abcdef";
        s.store("k", key).unwrap();
        std::fs::write(
            dir.path().join("k.meta"),
            br#"{"policy":"machine","pcr_selection":null,"created_at":"2026-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(s.retrieve("k").unwrap(), key);
    }

    /// A blob sealed under `pcr7` by an earlier build is refused, not unsealed as if it were
    /// machine-bound: a retired policy is a recovery case, never a silent downgrade.
    #[test]
    fn a_sidecar_naming_an_unsupported_policy_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(dir.path());
        s.store("k", b"0123456789abcdef0123456789abcdef").unwrap();
        std::fs::write(
            dir.path().join("k.meta"),
            br#"{"policy":"pcr7","pcr_selection":[7],"created_at":"2026-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        let err = s.retrieve("k").unwrap_err().to_string();
        assert!(err.contains("'pcr7' policy"), "unexpected: {err}");
        assert!(
            s.exists("k").unwrap(),
            "must reach recovery, not first-run mint"
        );
    }

    /// Nothing else reads this variable, so setting it here cannot disturb a parallel test.
    #[test]
    fn the_environment_cannot_choose_a_policy() {
        std::env::set_var("CREDSD_TPM_POLICY", "pcr7");
        let result = production_storage();
        std::env::remove_var("CREDSD_TPM_POLICY");
        let err = result.err().expect("must refuse").to_string();
        assert!(err.contains("CREDSD_TPM_POLICY"), "unexpected: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn blob_and_sidecar_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        storage(dir.path())
            .store("k", b"0123456789abcdef0123456789abcdef")
            .unwrap();
        for name in ["k.sealed", "k.meta"] {
            let mode = std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name} must be 0600, got {mode:o}");
        }
    }

    /// An earlier version wrote the blob at the umask's mode and left the directory as created, so
    /// a re-seal over that tree has to narrow both rather than inherit them.
    #[cfg(unix)]
    #[test]
    fn a_reseal_narrows_a_tree_left_wider_by_an_earlier_version() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let tpm = dir.path().join("tpm");
        std::fs::create_dir(&tpm).unwrap();
        std::fs::set_permissions(&tpm, std::fs::Permissions::from_mode(0o755)).unwrap();
        for name in ["k.sealed", "k.meta"] {
            std::fs::write(tpm.join(name), b"old").unwrap();
            std::fs::set_permissions(tpm.join(name), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }

        storage(&tpm)
            .store("k", b"0123456789abcdef0123456789abcdef")
            .unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&tpm), 0o700);
        for name in ["k.sealed", "k.meta"] {
            assert_eq!(mode(&tpm.join(name)), 0o600, "{name}");
        }
    }

    proptest::proptest! {
        /// Property: for any key_id and key bytes, store→retrieve round-trips
        /// byte-for-byte and the sealed blob on disk never equals the plaintext
        /// (spec Properties 1 and 3).
        #[test]
        fn store_retrieve_round_trip(
            key_id in "[a-z0-9-]{1,40}",
            key in proptest::collection::vec(proptest::num::u8::ANY, 1..64),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let s = storage(dir.path());
            s.store(&key_id, &key).unwrap();
            proptest::prop_assert!(s.exists(&key_id).unwrap());
            proptest::prop_assert_eq!(s.retrieve(&key_id).unwrap(), key.clone());
            let blob = std::fs::read(dir.path().join(format!("{key_id}.sealed"))).unwrap();
            proptest::prop_assert_ne!(blob, key);
        }
    }

    /// Real seal→unseal against an actual TPM 2.0 (a device, or a simulator
    /// reached via `TPM2TOOLS_TCTI`). Skips — does not fail — when no TPM is
    /// reachable, so it is safe in CI without hardware. Exercises the `EsapiSeam`
    /// glue the fake seam cannot cover.
    ///
    /// Against swtpm, use the `swtpm` TCTI, not `mssim`: swtpm's `--ctrl` channel
    /// speaks its own control protocol, so the mssim TCTI fails in
    /// `simulator_setup()` sending `MS_SIM_NV_ON`.
    ///
    /// ```text
    /// swtpm socket --tpm2 --tpmstate dir=/ts \
    ///   --server type=tcp,port=2321,bindaddr=127.0.0.1 \
    ///   --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 \
    ///   --flags not-need-init,startup-clear &
    /// TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321" \
    ///   cargo test -p credsd-core --features tpm esapi_seal_unseal_round_trip
    /// ```
    ///
    /// Only this crate's tests honor that variable. The daemon opens `/dev/tpmrm0` and
    /// nothing else; to run it against swtpm, expose swtpm as that node with
    /// `swtpm chardev --vtpm-proxy` (kernel module `tpm_vtpm_proxy`) on a host with no TPM.
    #[cfg(feature = "tpm")]
    #[test]
    fn esapi_seal_unseal_round_trip() {
        let _env = TCTI_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let seam = match super::esapi::EsapiSeam::open() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping esapi test: no reachable TPM ({e})");
                return;
            }
        };
        let key = b"0123456789abcdef0123456789abcdef";
        let blob = seam.seal(key).expect("seal");
        assert_ne!(
            blob.as_slice(),
            key.as_slice(),
            "blob must not be plaintext"
        );
        let out = seam.unseal(&blob).expect("unseal");
        assert_eq!(out.as_slice(), key.as_slice(), "round-trip mismatch");
    }

    /// Serializes the cases that read or set `TPM2TOOLS_TCTI`, so a swtpm round trip never
    /// sees the dummy value set below.
    #[cfg(feature = "tpm")]
    static TCTI_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A socket TCTI in the environment does not move a non-test build off the device: the
    /// socket is unauthenticated, so honoring it would let whoever binds the port be the TPM.
    #[cfg(feature = "tpm")]
    #[test]
    fn tcti_ignores_the_environment_outside_tests() {
        let _env = TCTI_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os("TPM2TOOLS_TCTI");
        std::env::set_var("TPM2TOOLS_TCTI", "swtpm:host=127.0.0.1,port=2321");
        let pinned = super::esapi::tcti(false);
        let honored = super::esapi::tcti(true);
        match prev {
            Some(v) => std::env::set_var("TPM2TOOLS_TCTI", v),
            None => std::env::remove_var("TPM2TOOLS_TCTI"),
        }
        assert!(matches!(pinned, Ok(tss_esapi::TctiNameConf::Device(_))));
        assert!(matches!(honored, Ok(tss_esapi::TctiNameConf::Swtpm(_))));
    }
}
