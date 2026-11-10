---
status: complete
created: 2026-10-07
---

# Requirements: Sealed-File Path Binding

## Summary

`EncryptionService::seal_to_file` and `open_from_file` bind each sealed blob to
its on-disk location. The AES-GCM AAD is the blob's path relative to the daemon's
data directory. A sealed blob decrypts only at its sealed path; copying it to a
different credential slot fails authentication at the crypto layer.

## Threat model

The adversary is a process running as the same OS uid as the credential owner.
It can read and write every file in that uid's caller root. It cannot read
the daemon's master key.

Specific attack: copy `callers/<uid>/credentials/foo/ra_key.enc` to
`callers/<uid>/credentials/malicious/ra_key.enc` (where `malicious` was
legitimately bootstrapped pointing to the same trust anchor and role). Without
path binding the daemon decrypts the copy and presents `foo`'s private key
under `malicious`'s identity. With path binding the copy fails to decrypt.

## Requirements

### Requirement 1: `seal_to_file` binds to the file's path

1.1. `EncryptionService::seal_to_file(path, plaintext)` SHALL use the file's
     path relative to the daemon's data directory as AES-GCM AAD. The AAD bytes
     SHALL be the relative path's raw OS bytes (`OsStr::as_encoded_bytes()`).

1.2. `EncryptionService::open_from_file(path)` SHALL derive AAD from the same
     relative path. Decryption of a file whose relative path differs from the
     path used at sealing SHALL fail with an authentication error.

1.3. The in-memory `seal()` / `open()` methods SHALL remain unbound (no AAD).
     They are used for `SecureStorage` key slots, which are identified by a
     string key rather than a filesystem path.

### Requirement 2: No migration — re-bootstrap required on upgrade

2.1. There SHALL be no migration path for files sealed before this change. The
     `EncryptedData` format SHALL NOT gain a version or binding field.

2.2. An existing sealed file opened after upgrade SHALL fail to decrypt with an
     authentication error, because its sealed AAD was empty. Re-bootstrap is
     required for all credentials on first start with a daemon that enforces
     path binding.

### Requirement 3: The detection boundary is stated

3.1. Path binding protects against same-uid file substitution at the blob level.
     It does not protect against replay of an archived valid (path, ciphertext)
     pair — both files must be restored together at the correct relative path.
     This is the same Case 1 limitation documented in the drift-detection spec.

3.2. `SecureStorage` key slots (master key, presence keys) are not covered.

3.3. Moving the daemon's data directory without changing relative paths within
     it does not invalidate sealed blobs — the AAD is the relative path, which
     is stable across data-directory relocation.

## Relationship to adjacent specs

**`drift-detection`.** Protects `config.toml` and `credentials.toml` routing
metadata via sealed snapshots. This spec closes the analogous gap on the
credential material blobs. Together they cover both layers: routing config and
material are each bound to their on-disk location.

**Storage backend specs (KKRS, TPM, Secure Enclave, DPAPI).** These govern how
the master key is held. Path binding does not change which key is used or how
it is stored.
