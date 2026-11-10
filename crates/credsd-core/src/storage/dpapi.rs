use crate::error::{DaemonError, Result};
use crate::storage::SecureStorage;
use std::path::PathBuf;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};

const ENTROPY: &[u8] = b"credsd-dpapi-v1";

pub struct DpapiStorage {
    dir: PathBuf,
}

impl Default for DpapiStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl DpapiStorage {
    pub fn new() -> Self {
        let dir = crate::config::platform::data_dir().join("dpapi");
        Self { dir }
    }

    fn blob_path(&self, key_id: &str) -> PathBuf {
        let safe_name: String = key_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        self.dir.join(format!("{}.dpapi", safe_name))
    }

    fn dpapi_encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let input_blob = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };

        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: ENTROPY.len() as u32,
            pbData: ENTROPY.as_ptr() as *mut u8,
        };

        let mut output_blob = CRYPT_INTEGER_BLOB::default();

        unsafe {
            CryptProtectData(
                &input_blob,
                None,
                Some(&entropy_blob),
                None,
                None,
                0,
                &mut output_blob,
            )
        }
        .map_err(|e| DaemonError::Storage(format!("CryptProtectData failed: {}", e)))?;

        let encrypted =
            unsafe { std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize) }
                .to_vec();

        unsafe {
            LocalFree(Some(HLOCAL(output_blob.pbData as *mut _)));
        }

        Ok(encrypted)
    }

    fn dpapi_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let input_blob = CRYPT_INTEGER_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };

        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: ENTROPY.len() as u32,
            pbData: ENTROPY.as_ptr() as *mut u8,
        };

        let mut output_blob = CRYPT_INTEGER_BLOB::default();

        unsafe {
            CryptUnprotectData(
                &input_blob,
                None,
                Some(&entropy_blob),
                None,
                None,
                0,
                &mut output_blob,
            )
        }
        .map_err(|e| DaemonError::Storage(format!(
            "CryptUnprotectData failed: {} — data may have been created by a different user or on a different machine. Run 'credsd bootstrap' to re-authenticate.",
            e
        )))?;

        let decrypted =
            unsafe { std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize) }
                .to_vec();

        unsafe {
            std::ptr::write_bytes(output_blob.pbData, 0, output_blob.cbData as usize);
            LocalFree(Some(HLOCAL(output_blob.pbData as *mut _)));
        }

        Ok(decrypted)
    }
}

impl SecureStorage for DpapiStorage {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir).map_err(|e| {
            DaemonError::Storage(format!("failed to create DPAPI storage directory: {}", e))
        })?;

        let encrypted = self.dpapi_encrypt(data)?;

        let target = self.blob_path(key_id);
        let tmp = target.with_extension("dpapi.tmp");
        std::fs::write(&tmp, &encrypted)
            .map_err(|e| DaemonError::Storage(format!("failed to write DPAPI blob: {}", e)))?;
        std::fs::rename(&tmp, &target)
            .map_err(|e| DaemonError::Storage(format!("failed to rename DPAPI blob: {}", e)))?;

        Ok(())
    }

    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(key_id);
        let encrypted = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                DaemonError::Storage(format!("key '{}' not found", key_id))
            } else {
                DaemonError::Storage(format!("failed to read key '{}': {}", key_id, e))
            }
        })?;
        self.dpapi_decrypt(&encrypted)
    }

    fn delete(&self, key_id: &str) -> Result<()> {
        let path = self.blob_path(key_id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DaemonError::Storage(format!(
                "failed to delete key '{}': {}",
                key_id, e
            ))),
        }
    }

    fn exists(&self, key_id: &str) -> Result<bool> {
        let path = self.blob_path(key_id);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(DaemonError::Storage(format!(
                "cannot stat key '{}': {}",
                key_id, e
            ))),
        }
    }

    fn backend_name(&self) -> &'static str {
        "dpapi"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip() {
        let storage = DpapiStorage::new();
        let key_id = "credsd-test-dpapi-roundtrip";
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
        let storage = DpapiStorage::new();
        assert!(!storage.exists("credsd-nonexistent-dpapi-key").unwrap());
        let err = storage
            .retrieve("credsd-nonexistent-dpapi-key")
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn backend_name_is_dpapi() {
        let storage = DpapiStorage::new();
        assert_eq!(storage.backend_name(), "dpapi");
    }
}
