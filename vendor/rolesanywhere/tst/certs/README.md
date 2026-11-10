# Test certificate & key fixtures

**All private keys in this directory are throwaway, locally-generated, TEST-ONLY
material.** None is associated with any AWS account, IAM Roles Anywhere trust anchor,
profile, or real identity. They exist solely as deterministic signing/parsing test
vectors and MUST NOT be used for anything else.

These fixtures are load-bearing: several tests are **known-answer tests** that assert the
exact signature/public-key/serial bytes a specific key produces (e.g. the RSA
sign-string vector verified byte-for-byte against OpenSSL and the Go reference tool). The
keys therefore cannot be blanked or regenerated without also updating those pinned
expected values.

## What each fixture is for

| File | Purpose |
|------|---------|
| `rsa-2048-key.pem` / `rsa-2048-cert.pem` | Primary RSA signing path; RSA known-answer vectors. |
| `ec-p256-key.pem` / `ec-p256-cert.pem` | Primary ECDSA (P-256) signing path. |
| `rsa-1024-key.pem` | Below the 2048-bit minimum — exercises the weak-key rejection path. |
| `p384-key-pkcs8.pem` / `p384-cert.pem` | Non-P-256 EC — exercises the P-256-only signer rejection (the cert still parses as `keyType: EC`). |
| `ed25519-key.pem` / `ed25519-cert.pem` | Unsupported key type — exercises the clean "unsupported" rejection. |
| `enc-rsa-key.pem` | Encrypted (password-protected) PKCS#8 — exercises the "no decryption support" rejection. |
| `malformed.pem` | Not valid PEM — exercises the parse-error path. |
| `large-serial-cert.pem` | Certificate with a large serial number — exercises big-integer serial decoding. |
| `negative-serial-cert.pem` | Certificate with a negative serial — exercises signed-integer serial decoding. |
| `ratest-ca-cert.pem` | Self-signed **test** CA cert (`CN=RolesAnywhereTestCA, O=RolesAnywhereTest`) — used as a single-cert `X-Amz-X509-Chain` fixture. |
| `ratest-client-cert.pem` | Leaf cert issued by the test CA above (`CN=RolesAnywhereTestClient`). Only the certificate is kept; its private key was discarded at generation time because no test signs with it. |
| `ratest-chain.pem` | The two certs above concatenated (leaf then CA) — a two-cert chain that exercises the multi-cert comma-join of the `X-Amz-X509-Chain` path. |

The three `ratest-*` certs are a self-signed hierarchy generated locally with OpenSSL, and
are unrelated to any live endpoint or account. No test pins their bytes — each one
recomputes its expectation from the fixture it reads — so they can be regenerated freely as
long as `ratest-ca-cert.pem` keeps exactly one CERTIFICATE block and `ratest-chain.pem`
exactly two, leaf first.

## How these were generated

All fixtures are throwaway, locally-generated OpenSSL material. The commands below are the
recipe; regenerating a key or cert requires re-pinning any known-answer test that reads it
(see the KATs in `serial.rs` and `signer.rs`).

```sh
# RSA-2048 key + self-signed cert
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-2048-key.pem
openssl req -new -x509 -key rsa-2048-key.pem -days 3650 -subj "/CN=RsaTest" -out rsa-2048-cert.pem

# EC P-256 key + self-signed cert
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec-p256-key.pem
openssl req -new -x509 -key ec-p256-key.pem -days 3650 -subj "/CN=EcTest" -out ec-p256-cert.pem

# Rejection-path keys (loaded but refused by the P-256-only / RSA>=2048 signer)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out rsa-1024-key.pem
openssl genpkey -algorithm EC  -pkeyopt ec_paramgen_curve:P-384 -out p384-key-pkcs8.pem
openssl genpkey -algorithm ED25519 -out ed25519-key.pem          # unsupported key TYPE
openssl pkcs8 -topk8 -in rsa-2048-key.pem -out enc-rsa-key.pem -passout pass:test  # encrypted PKCS#8

# Test CA hierarchy for the X-Amz-X509-Chain path. Both private keys are discarded:
# nothing signs with them, so only the certificates are kept.
openssl req -new -x509 -newkey rsa:2048 -nodes -keyout "$TMP/ca-key.pem" -days 3650 \
    -subj "/CN=RolesAnywhereTestCA/O=RolesAnywhereTest" -out ratest-ca-cert.pem
openssl req -new -newkey rsa:2048 -nodes -keyout "$TMP/leaf-key.pem" \
    -subj "/CN=RolesAnywhereTestClient/O=RolesAnywhereTest" -out "$TMP/leaf.csr"
openssl x509 -req -in "$TMP/leaf.csr" -CA ratest-ca-cert.pem -CAkey "$TMP/ca-key.pem" \
    -days 3650 -set_serial 2 -out ratest-client-cert.pem
cat ratest-client-cert.pem ratest-ca-cert.pem > ratest-chain.pem

# malformed.pem       — hand-written non-PEM bytes (parse-error path).
# large-serial-cert.pem / negative-serial-cert.pem — the serial bytes were hand-edited in the
#   DER after generation to force a large / negative serial (the cert signature is therefore
#   not valid, which is fine: these fixtures only exercise serial DECODING, never verification).
```
