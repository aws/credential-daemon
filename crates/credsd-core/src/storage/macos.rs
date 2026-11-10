use crate::error::{DaemonError, Result};
use crate::storage::{SecureStorage, SERVICE_NAME};
use security_framework::passwords::{
    delete_generic_password_options, generic_password, set_generic_password_options,
    PasswordOptions,
};

/// macOS Data Protection Keychain backend.
///
/// Items stored with `kSecUseDataProtectionKeychain = true` and no explicit
/// `kSecAttrAccessGroup`, so they land in the daemon's default access group: the one entry
/// of its `keychain-access-groups` entitlement, `94KV3E626L.com.amazon.aws.credsd.daemon`
/// (`packaging/credsd.entitlements`). Only the signed daemon carries it; `creds` is
/// unentitled. The SE protects the keychain's encryption key hierarchy — device-bound,
/// cannot be decrypted on another machine even if the file is copied.
#[derive(Default)]
pub struct DataProtectionKeychainStorage;

impl DataProtectionKeychainStorage {
    pub fn new() -> Self {
        Self
    }

    fn opts(key_id: &str) -> PasswordOptions {
        let mut o = PasswordOptions::new_generic_password(SERVICE_NAME, key_id);
        o.use_protected_keychain();
        o
    }
}

impl SecureStorage for DataProtectionKeychainStorage {
    fn is_available(&self) -> bool {
        let probe = "__credsd_dp_probe__";
        let ok = set_generic_password_options(b"probe", Self::opts(probe)).is_ok();
        if ok {
            let _ = delete_generic_password_options(Self::opts(probe));
        }
        ok
    }

    fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
        let _ = delete_generic_password_options(Self::opts(key_id));
        set_generic_password_options(data, Self::opts(key_id))
            .map_err(|e| DaemonError::Storage(format!("dp-keychain store failed: {e}")))
    }

    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        generic_password(Self::opts(key_id))
            .map_err(|e| DaemonError::Storage(format!("dp-keychain retrieve failed: {e}")))
    }

    fn delete(&self, key_id: &str) -> Result<()> {
        delete_generic_password_options(Self::opts(key_id))
            .map_err(|e| DaemonError::Storage(format!("dp-keychain delete failed: {e}")))
    }

    fn exists(&self, key_id: &str) -> Result<bool> {
        match generic_password(Self::opts(key_id)) {
            Ok(_) => Ok(true),
            Err(e) if e.code() == -25300 => Ok(false), // errSecItemNotFound
            Err(e) => Err(DaemonError::Storage(format!(
                "dp-keychain exists check failed for '{key_id}': {e}"
            ))),
        }
    }

    fn backend_name(&self) -> &'static str {
        "data-protection-keychain"
    }
}
