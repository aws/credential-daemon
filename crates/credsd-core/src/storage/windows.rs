use crate::error::{DaemonError, Result};
use crate::storage::SecureStorage;
use windows::core::HSTRING;
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST,
    CRED_PERSIST_LOCAL_MACHINE, CRED_PERSIST_SESSION, CRED_TYPE_GENERIC,
};

const TARGET_PREFIX: &str = "credsd/";

#[derive(Default)]
pub struct CredentialManagerStorage;

impl CredentialManagerStorage {
    pub fn new() -> Self {
        Self
    }

    fn target_name(key_id: &str) -> HSTRING {
        HSTRING::from(format!("{}{}", TARGET_PREFIX, key_id))
    }

    fn try_store(
        target: &HSTRING,
        data: &[u8],
        persist: CRED_PERSIST,
    ) -> std::result::Result<(), windows::core::Error> {
        let cred = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: windows::core::PWSTR(target.as_ptr() as *mut u16),
            CredentialBlobSize: data.len() as u32,
            CredentialBlob: data.as_ptr() as *mut u8,
            Persist: persist,
            ..Default::default()
        };

        unsafe { CredWriteW(&cred, 0) }
    }
}

impl SecureStorage for CredentialManagerStorage {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
        let target = Self::target_name(key_id);

        // Try LOCAL_MACHINE first (persists across reboots), fall back to SESSION
        // if the logon session doesn't support it (e.g., SSM, service accounts)
        if Self::try_store(&target, data, CRED_PERSIST_LOCAL_MACHINE).is_ok() {
            return Ok(());
        }

        Self::try_store(&target, data, CRED_PERSIST_SESSION)
            .map_err(|e| DaemonError::Storage(format!("CredWrite failed: {}", e)))?;

        Ok(())
    }

    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        let target = Self::target_name(key_id);
        let mut cred_ptr = std::ptr::null_mut();

        unsafe {
            CredReadW(&target, CRED_TYPE_GENERIC, None, &mut cred_ptr)
                .map_err(|e| DaemonError::Storage(format!("CredRead failed: {}", e)))?;

            if cred_ptr.is_null() {
                return Err(DaemonError::Storage(
                    "CredRead returned success with a null credential pointer".to_string(),
                ));
            }

            let cred = &*cred_ptr;
            let blob =
                std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize)
                    .to_vec();

            CredFree(cred_ptr as *const std::ffi::c_void);
            Ok(blob)
        }
    }

    fn delete(&self, key_id: &str) -> Result<()> {
        let target = Self::target_name(key_id);
        unsafe {
            CredDeleteW(&target, CRED_TYPE_GENERIC, None)
                .map_err(|e| DaemonError::Storage(format!("CredDelete failed: {}", e)))?;
        }
        Ok(())
    }

    fn exists(&self, key_id: &str) -> Result<bool> {
        let target = Self::target_name(key_id);
        let mut cred_ptr = std::ptr::null_mut();
        unsafe {
            match CredReadW(&target, CRED_TYPE_GENERIC, None, &mut cred_ptr) {
                Ok(_) => {
                    CredFree(cred_ptr as *const std::ffi::c_void);
                    Ok(true)
                }
                // ERROR_NOT_FOUND (1168) as HRESULT = 0x80070490
                Err(e) if e.code() == windows::core::HRESULT(0x80070490u32 as i32) => Ok(false),
                Err(e) => Err(DaemonError::Storage(format!(
                    "CredRead failed for '{key_id}': {e}"
                ))),
            }
        }
    }

    fn backend_name(&self) -> &'static str {
        "credential-manager"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_manager_round_trip() {
        let storage = CredentialManagerStorage::new();
        let key_id = "credsd-test-key-roundtrip";
        let data = b"test-encryption-key-32-bytes!!!!";

        let _ = storage.delete(key_id);

        storage.store(key_id, data).unwrap();
        assert!(storage.exists(key_id).unwrap());
        let retrieved = storage.retrieve(key_id).unwrap();
        assert_eq!(retrieved, data);

        storage.delete(key_id).unwrap();
        assert!(!storage.exists(key_id).unwrap());
    }

    #[test]
    fn missing_key_returns_error() {
        let storage = CredentialManagerStorage::new();
        assert!(!storage.exists("credsd-nonexistent-key").unwrap());
        assert!(storage.retrieve("credsd-nonexistent-key").is_err());
    }
}
