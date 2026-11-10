use crate::config::platform;
use crate::error::{DaemonError, Result};
use crate::storage::SecureStorage;
use std::fs;
use std::path::PathBuf;

pub struct FileStorage {
    dir: PathBuf,
}

impl Default for FileStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl FileStorage {
    pub fn new() -> Self {
        Self {
            dir: platform::data_dir().join("keys"),
        }
    }

    fn key_path(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{}.key", key_id))
    }
}

impl SecureStorage for FileStorage {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<()> {
        fs::create_dir_all(&self.dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
        }

        let path = self.key_path(key_id);
        fs::write(&path, data)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        let path = self.key_path(key_id);
        fs::read(&path)
            .map_err(|e| DaemonError::Storage(format!("failed to read key '{}': {}", key_id, e)))
    }

    fn delete(&self, key_id: &str) -> Result<()> {
        let path = self.key_path(key_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DaemonError::Storage(format!(
                "cannot delete key '{}': {e}",
                path.display()
            ))),
        }
    }

    fn exists(&self, key_id: &str) -> Result<bool> {
        let path = self.key_path(key_id);
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(DaemonError::Storage(format!(
                "cannot stat key '{}': {e}",
                path.display()
            ))),
        }
    }

    fn backend_name(&self) -> &'static str {
        "file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };
        let data = b"encryption-key-bytes-here-32byte";
        storage.store("test-key", data).unwrap();
        assert!(storage.exists("test-key").unwrap());
        let retrieved = storage.retrieve("test-key").unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn missing_key_errors() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };
        assert!(!storage.exists("nonexistent").unwrap());
        assert!(storage.retrieve("nonexistent").is_err());
    }

    #[test]
    fn delete_removes_key() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage {
            dir: dir.path().to_path_buf(),
        };
        storage.store("to-delete", b"data").unwrap();
        assert!(storage.exists("to-delete").unwrap());
        storage.delete("to-delete").unwrap();
        assert!(!storage.exists("to-delete").unwrap());
    }
}
