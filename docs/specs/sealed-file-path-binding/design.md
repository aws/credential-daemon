# Design: Sealed-File Path Binding

## Shape

`EncryptionService::seal_to_file` and `open_from_file` pass the blob's path
relative to the daemon's data directory as AES-GCM AAD. No call-site changes —
the path is already a parameter at both ends. No version field, no fallback,
no migration.

## Decisions

### 1. Path as AAD, not path-in-plaintext

Two ways to bind ciphertext to a path:

- **AAD:** path bytes authenticated by the GCM tag. Decryption with a different
  path fails before any plaintext is produced.
- **Path-in-plaintext:** path encrypted inside the blob; opener decrypts,
  extracts the path, compares. Mismatch caught at application level after
  decryption succeeds.

AAD is strictly better: authentication failure at the crypto layer, no plaintext
in memory on a bad open, zero bytes added to ciphertext.

### 2. Relative path, not absolute

The AAD is the blob's path relative to the daemon's data directory:
`path.strip_prefix(data_dir())`. This means:

- Moving the data directory does not invalidate any sealed blob — the relative
  path within the data dir is what was sealed.
- Two blobs at different relative paths (e.g. `credentials/foo/ra_key.enc` vs
  `credentials/bar/ra_key.enc`) have distinct AADs, so copying one over the other
  fails authentication.

Using the absolute path would break all sealed blobs if the data directory is
ever relocated, without any security benefit over the relative form.

`canonicalize()` is intentionally avoided: it is fallible and resolves symlinks,
which could produce different bytes for the same logical file. Both seal and open
derive AAD from the same path, stripped to the same relative form.

### 3. No migration — re-bootstrap required on upgrade

A version field in `EncryptedData` would let `open_from_file` choose the right
AAD per file and keep existing credentials working. The migration code then has
to handle every blob type, test the fallback path, and stay in the codebase
permanently. Re-bootstrap is a one-time operator action; migration code is
permanent complexity.

### 4. In-memory `seal`/`open` remain unbound

`seal(plaintext)` / `open(sealed)` are used for `SecureStorage` key slots, which
have no filesystem path. Binding them is out of scope.

## Implementation

`seal_to_file` and `open_from_file` in `encryption.rs`:

```rust
pub fn seal_to_file(&self, path: &Path, plaintext: &[u8]) -> Result<()> {
    let rel = path.strip_prefix(data_dir()).unwrap_or(path);
    let aad = rel.as_os_str().as_encoded_bytes();
    let encrypted = self.encrypt_with_aad(plaintext, aad)?;
    // … atomic write unchanged …
}

pub fn open_from_file(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let rel = path.strip_prefix(data_dir()).unwrap_or(path);
    let aad = rel.as_os_str().as_encoded_bytes();
    let data: EncryptedData = serde_json::from_slice(&std::fs::read(path)?)?;
    self.decrypt_with_aad(&data, aad)
}
```

Internal `encrypt_with_aad` / `decrypt_with_aad` helpers take `aad: &[u8]`
and pass it to `aws_lc_rs::aead`. The existing `encrypt` / `decrypt` methods
call through with `aad = &[]`.

## File changes

| File | Role |
|---|---|
| `crates/credsd-core/src/encryption.rs` | `seal_to_file` and `open_from_file` derive AAD from path relative to data dir; internal helpers gain `aad: &[u8]` parameter |

`EncryptedData` struct is unchanged. All callers of `seal_to_file` /
`open_from_file` are unchanged — path was already a parameter.

## Rejected alternatives

**Absolute path as AAD.** Binds blobs to the specific filesystem location; data
directory relocation invalidates everything. No security benefit over the relative
form. Decision 2.

**Version field in `EncryptedData` for migration.** Keeps existing credentials
working across upgrade. Requires migration code that handles every blob type,
stays in the codebase permanently, and must be tested. Re-bootstrap is simpler.
Decision 3.

**Path-in-plaintext.** Decryption succeeds before the mismatch is detectable.
Plaintext in memory on a bad open. Decision 1.

**`canonicalize()` for the AAD path.** Fallible, resolves symlinks, could
produce different bytes for the same logical file. Decision 2.
