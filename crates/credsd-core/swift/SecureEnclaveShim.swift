// Secure Enclave access for the `secure-enclave` storage backend.
//
// CryptoKit's `SecureEnclave` types are Swift-only — `CryptoKit.framework` ships a
// `.swiftmodule` and no `Headers/` directory, so there is no C or Obj-C interface to bind
// against. This file is the whole reason the crate has a build script: it compiles to a
// static archive that `credsd-core` links, exposing a C ABI via `@_cdecl`.
//
// Why CryptoKit rather than `SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave`: the
// SecItem route reaches the Secure Enclave *through the data protection keychain*, which
// Apple documents (TN3137) as unavailable to `launchd` daemons regardless of packaging.
// CryptoKit reaches the enclave with no keychain, no entitlement and no code signing, which
// is the only route available to a system daemon. See `docs/key-security.md`, Path C.
//
// Memory contract, and the reason every function looks the same: Swift never allocates for
// Rust. The caller passes a buffer and its capacity; this side writes the required length
// through `len` unconditionally — including on `errBufferTooSmall`, so a caller can size a
// retry — and copies bytes only when they fit. Nothing crosses the boundary that either
// side has to free, so the `unsafe` block on the Rust side has no ownership rule to get
// wrong.
//
// Deprecation note: `kSecAttrAccessibleAlways` is `API_DEPRECATED(macos(10.9, 10.14))` and
// compiling this file warns about it. It is kept deliberately: it is the only protection
// class with no dependency on a login session, and a daemon that must unseal before any
// user logs in has no alternative. Suppressing the warning would hide the one line in this
// file that a future reader most needs to question.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

// Status codes returned to Rust. Negative so they can never be confused with a length.
// Kept in lockstep with `describe` in `src/storage/secure_enclave.rs`.
private let errOk: Int32 = 0
private let errUnavailable: Int32 = -1
private let errBufferTooSmall: Int32 = -2
private let errAccessControl: Int32 = -3
private let errGenerate: Int32 = -4
private let errRehydrate: Int32 = -5
private let errAgreement: Int32 = -6
private let errSeal: Int32 = -7
private let errOpen: Int32 = -8
private let errBadInput: Int32 = -9
private let errSign: Int32 = -10
private let errPresenceCancelled: Int32 = -11
private let errPresenceLockout: Int32 = -12
private let errPresenceUnavailable: Int32 = -13
private let errPresenceFailed: Int32 = -14

/// Uncompressed X9.63 form of a P-256 public key: `0x04 || X || Y`. Fixed width, which is
/// what lets `unwrap` split the ciphertext without a length prefix.
private let x963PublicKeyLength = 65

private func emit(
    _ data: Data,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ len: UnsafeMutablePointer<Int>
) -> Int32 {
    len.pointee = data.count
    guard data.count <= cap else { return errBufferTooSmall }
    data.copyBytes(to: out, count: data.count)
    return errOk
}

/// Maps the Rust-side `Protection` discriminant onto a keychain protection class.
///
/// Exposed as a parameter rather than hardcoded because which class works from a
/// pre-login daemon is the open question this backend exists to answer: CryptoKit's own
/// default is `afterFirstUnlock`, which fails with `errSecInteractionNotAllowed` before
/// any login.
private func protectionClass(_ selector: UInt32) -> CFString? {
    switch selector {
    case 0: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case 1: return kSecAttrAccessibleAlways
    case 2: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    default: return nil
    }
}

@_cdecl("credsd_se_available")
public func credsd_se_available() -> Int32 {
    SecureEnclave.isAvailable ? 1 : 0
}

/// Generates a P-256 key agreement key inside the Secure Enclave and returns its
/// `dataRepresentation` — an opaque blob only this machine's enclave can unwrap. The
/// private key itself never leaves hardware.
@_cdecl("credsd_se_generate")
public func credsd_se_generate(
    _ protection: UInt32,
    _ flags: UInt32,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ len: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return errUnavailable }
    guard let klass = protectionClass(protection) else { return errBadInput }
    guard
        let access = SecAccessControlCreateWithFlags(
            nil,
            klass,
            SecAccessControlCreateFlags(rawValue: CFOptionFlags(flags)),
            nil
        )
    else { return errAccessControl }

    guard
        let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    else { return errGenerate }

    return emit(key.dataRepresentation, out, cap, len)
}

/// ECIES seal against the enclave-resident key: ephemeral P-256 sender key, ECDH,
/// HKDF-SHA256 to an AES-256 key, AES-GCM. Output is `ephemeralPublicKey || sealedBox`.
///
/// The ephemeral key is generated in software on purpose — only the *recipient* key needs
/// to be hardware-bound, and generating a second enclave key per seal would be pure cost.
@_cdecl("credsd_se_wrap")
public func credsd_se_wrap(
    _ keyBlob: UnsafePointer<UInt8>,
    _ keyBlobLen: Int,
    _ plaintext: UnsafePointer<UInt8>,
    _ plaintextLen: Int,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ len: UnsafeMutablePointer<Int>
) -> Int32 {
    guard keyBlobLen > 0, plaintextLen > 0 else { return errBadInput }

    guard
        let enclaveKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: keyBlob, count: keyBlobLen)
        )
    else { return errRehydrate }

    let ephemeral = P256.KeyAgreement.PrivateKey()
    let ephemeralPublic = ephemeral.publicKey.x963Representation

    guard
        let shared = try? ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
    else { return errAgreement }

    let symmetric = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data(),
        sharedInfo: ephemeralPublic,
        outputByteCount: 32
    )

    guard
        let box = try? AES.GCM.seal(Data(bytes: plaintext, count: plaintextLen), using: symmetric),
        let combined = box.combined
    else { return errSeal }

    return emit(ephemeralPublic + combined, out, cap, len)
}

/// Reverses `credsd_se_wrap`. The ECDH half happens inside the enclave, so the plaintext
/// is recoverable only on the machine whose enclave issued `keyBlob`.
@_cdecl("credsd_se_unwrap")
public func credsd_se_unwrap(
    _ keyBlob: UnsafePointer<UInt8>,
    _ keyBlobLen: Int,
    _ ciphertext: UnsafePointer<UInt8>,
    _ ciphertextLen: Int,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ len: UnsafeMutablePointer<Int>
) -> Int32 {
    guard keyBlobLen > 0, ciphertextLen > x963PublicKeyLength else { return errBadInput }

    let wire = Data(bytes: ciphertext, count: ciphertextLen)
    // Re-base both slices: `AES.GCM.SealedBox(combined:)` and `x963Representation:` are
    // index-sensitive, and a `Data` slice carries the parent's non-zero start index.
    let ephemeralPublic = Data(wire[..<x963PublicKeyLength])
    let sealed = Data(wire[x963PublicKeyLength...])

    guard
        let enclaveKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: keyBlob, count: keyBlobLen)
        )
    else { return errRehydrate }

    guard
        let senderPublic = try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic),
        let shared = try? enclaveKey.sharedSecretFromKeyAgreement(with: senderPublic)
    else { return errAgreement }

    let symmetric = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data(),
        sharedInfo: ephemeralPublic,
        outputByteCount: 32
    )

    guard
        let box = try? AES.GCM.SealedBox(combined: sealed),
        let plaintext = try? AES.GCM.open(box, using: symmetric)
    else { return errOpen }

    return emit(plaintext, out, cap, len)
}

// ── Presence keys (presence-gated-operations) ────────────────────────────────────────────
//
// A presence key is a P-256 *signing* key in the enclave whose access control requires user
// presence for every use. It is created and used by the client, as the user, in the user's
// session; the daemon only ever sees the public half. The access-control policy is sealed into
// `dataRepresentation`, so the enclave enforces it whichever process presents the blob.

/// Generates a presence key. `flags` are raw `SecAccessControlCreateFlags`; the protection class
/// is fixed to `WhenPasscodeSetThisDeviceOnly`, which destroys the key if the passcode is removed.
/// Writes the key's `dataRepresentation` to `out` and its X9.63 public key to `pubOut`.
@_cdecl("credsd_presence_generate")
public func credsd_presence_generate(
    _ flags: UInt32,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ len: UnsafeMutablePointer<Int>,
    _ pubOut: UnsafeMutablePointer<UInt8>,
    _ pubCap: Int,
    _ pubLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return errUnavailable }
    guard
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            SecAccessControlCreateFlags(rawValue: CFOptionFlags(flags)),
            nil
        )
    else { return errAccessControl }
    guard let key = try? SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    else { return errGenerate }
    let rc = emit(key.dataRepresentation, out, cap, len)
    guard rc == errOk else { return rc }
    return emit(key.publicKey.x963Representation, pubOut, pubCap, pubLen)
}

/// Signs `message` (ECDSA P-256 over SHA-256, DER) with a presence key. `reason` is a
/// NUL-terminated UTF-8 string shown in the Touch ID prompt. Blocks until the user satisfies or
/// cancels the prompt.
@_cdecl("credsd_presence_sign")
public func credsd_presence_sign(
    _ keyBlob: UnsafePointer<UInt8>,
    _ keyBlobLen: Int,
    _ message: UnsafePointer<UInt8>,
    _ messageLen: Int,
    _ reason: UnsafePointer<CChar>,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ len: UnsafeMutablePointer<Int>
) -> Int32 {
    let context = LAContext()
    context.localizedReason = String(cString: reason)
    guard
        let key = try? SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: Data(bytes: keyBlob, count: keyBlobLen),
            authenticationContext: context
        )
    else { return errRehydrate }
    do {
        let signature = try key.signature(for: Data(bytes: message, count: messageLen))
        return emit(signature.derRepresentation, out, cap, len)
    } catch {
        if let code = presenceFailure(error) { return code }
        // Unclassified: hand the description back in `out` so the caller can show it.
        _ = emit(Data(String(describing: error).utf8), out, cap, len)
        return errSign
    }
}

/// Why the user-presence check failed, when the error carries a LocalAuthentication code —
/// directly, or as the underlying error of a CryptoKit / Security error.
private func presenceFailure(_ error: Error) -> Int32? {
    var next: NSError? = error as NSError
    while let e = next {
        if e.domain == LAErrorDomain {
            switch LAError.Code(rawValue: e.code) {
            case .userCancel, .systemCancel, .appCancel, .userFallback: return errPresenceCancelled
            case .biometryLockout: return errPresenceLockout
            case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet, .notInteractive:
                return errPresenceUnavailable
            case .authenticationFailed: return errPresenceFailed
            default: return nil
            }
        }
        next = e.userInfo[NSUnderlyingErrorKey] as? NSError
    }
    return nil
}
