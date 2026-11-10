//! SigV4 canonicalization: the pure, side-effect-free string-building that turns
//! the request into the canonical request, the string-to-sign, and the
//! Authorization header. A near-direct port of the canonicalization functions in
//! the Go reference's `signer.go`.
//!
//! `BTreeMap` is used for the header map because its iteration order is sorted by
//! key automatically: Go does this in two steps (collect into a map, then
//! `sort.Strings` the keys); `BTreeMap` collapses that into one (no separate sort
//! call needed).

use crate::types::SignerParams;
use aws_lc_rs::digest;
use std::collections::BTreeMap;

/// Headers excluded from the signature calculation:
///   - `authorization`: contains the signature itself, can't be part of its own input
///   - `user-agent`: can change between retries, not security-relevant
///   - `x-amzn-trace-id`: tracing header added by infrastructure, not part of request intent
const IGNORED_HEADERS: &[&str] = &["authorization", "user-agent", "x-amzn-trace-id"];

/// Canonicalize the query string for SigV4: the input is already URL-encoded and
/// sorted by key, so the only transform is `+` -> `%20`. (For CreateSession the
/// signed query carries the three ARNs; an empty string is also valid.)
pub fn create_canonical_query_string(query: &str) -> String {
    query.replace('+', "%20")
}

/// Canonicalize request headers for SigV4, producing the two strings that go into
/// the canonical request:
///   1. the canonical headers string — each header as `key:value`, one per line,
///      sorted alphabetically by key;
///   2. the signed headers string — just the key names, sorted and joined by `;`,
///      telling AWS which headers were included in the signature.
///
/// The process: lowercase every key (HTTP headers are case-insensitive), skip the
/// `IGNORED_HEADERS`, join duplicate-key values with `,`, trim leading/trailing
/// whitespace from each value, collapse interior space runs to one, and sort by
/// key (handled by `BTreeMap`).
///
/// `headers` is a slice of (key, value) pairs (all HTTP headers on the request).
/// Returns `(canonical_headers_string, signed_headers_string)`.
pub fn create_canonical_headers(headers: &[(String, String)]) -> (String, String) {
    // Value is a Vec because the same header key can appear multiple times.
    let mut header_map: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (key, value) in headers {
        // Normalize to lowercase
        let lower_key = key.to_lowercase();

        // Skip the ignored headers
        if IGNORED_HEADERS.contains(&lower_key.as_str()) {
            continue;
        }

        // Clean each value individually: trim leading/trailing whitespace, then
        // collapse interior space runs to one. NOTE: Go instead runs stripExcessSpaces
        // on the whole "key:value" line (ASCII 0x20 only). The two agree on the clean
        // ASCII header values the pipeline emits and differ only on colon-adjacent
        // leading/trailing or non-ASCII whitespace — an intentional, documented divergence
        // (see docs/changes-and-design-choices.md).
        let cleaned_value = collapse_whitespace(value.trim());

        // Group values by key - if "X-Custom" appears twice, we store both values
        header_map.entry(lower_key).or_default().push(cleaned_value);
    }

    let mut canonical_parts = Vec::new();
    let mut signed_keys = Vec::new();

    // Iterate in sorted order
    for (key, values) in &header_map {
        signed_keys.push(key.as_str());
        // Multiple values for the same key are joined with ","
        // e.g., "x-custom:value1,value2"
        canonical_parts.push(format!("{}:{}", key, values.join(",")));
    }

    // canonical_headers: "content-type:application/json\nhost:example.com\nx-amz-date:20240115T123000Z"
    // signed_headers: "content-type;host;x-amz-date"
    (canonical_parts.join("\n"), signed_keys.join(";"))
}

/// Collapse runs of consecutive spaces into a single space, e.g.
/// `"hello    world"` -> `"hello world"`. SigV4 requires header values
/// normalized this way so both sides hash the same bytes.
fn collapse_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c == ' ' {
            if !prev_space {
                result.push(c);
            }
            prev_space = true;
        } else {
            prev_space = false;
            result.push(c);
        }
    }
    result
}

/// Assemble the full canonical request string, then SHA-256 hash it.
///
/// The canonical request format (each piece separated by newlines):
///   1. HTTP method (always `POST` for CreateSession)
///   2. URI path (always `/sessions` for CreateSession)
///   3. Canonical query string (the encoded ARNs)
///   4. Canonical headers (sorted `key:value` pairs, one per line)
///   5. (blank line)
///   6. Signed headers (semicolon-separated key names)
///   7. SHA-256 hash of the request body (or of the empty string if no body)
///
/// Returns `(canonical_request_hash_hex, signed_headers_string)` — the second is
/// needed later for the Authorization header.
pub fn create_canonical_request(
    method: &str,
    path: &str,
    query_string: &str,
    headers: &[(String, String)],
    payload_hash: &str,
) -> (String, String) {
    // First canonicalize the query string and headers
    let canonical_query = create_canonical_query_string(query_string);
    let (canonical_headers, signed_headers) = create_canonical_headers(headers);

    // Assemble the canonical request string
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n\n{}\n{}",
        method, path, canonical_query, canonical_headers, signed_headers, payload_hash
    );

    // Hash the entire canonical request string with SHA-256 (via aws-lc-rs).
    let hash = digest::digest(&digest::SHA256, canonical_request.as_bytes());
    let hex_hash = hex::encode(hash.as_ref());

    (hex_hash, signed_headers)
}

/// Create the string-to-sign from the canonical request hash and signing
/// parameters — this is the actual string the private key signs. Format:
///   ```text
///   <algorithm>
///   <dateTime>
///   <scope>
///   <canonical request hash>
///   ```
/// In Go this is `CreateStringToSign()` in `signer.go`.
pub fn create_string_to_sign(canonical_request_hash: &str, params: &SignerParams) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        params.algorithm.as_str(),
        params.formatted_datetime(),
        params.scope(),
        canonical_request_hash
    )
}

/// Build the Authorization header value attached to the HTTP request. Format:
///   ```text
///   <algorithm> Credential=<serial_number>/<scope>, SignedHeaders=<signed_headers>, Signature=<signature>
///   ```
/// e.g. `AWS4-X509-RSA-SHA256 Credential=123456789/20240115/us-east-1/rolesanywhere/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=abcdef...`
///
/// Arguments:
///   - `params`: signing parameters (provides algorithm and scope)
///   - `serial_number`: the certificate's serial number, used as the credential identifier
///   - `signed_headers`: semicolon-separated list of headers that were signed
///   - `signature`: the hex-encoded signature bytes
pub fn build_authorization_header(
    params: &SignerParams,
    serial_number: &str,
    signed_headers: &str,
    signature: &str,
) -> String {
    format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        params.algorithm.as_str(),
        serial_number,
        params.scope(),
        signed_headers,
        signature
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SignerParams, SigningAlgorithm};
    use chrono::TimeZone;
    use proptest::prelude::*;

    /// SHA-256 of the empty string — the payload hash used when a request has no body.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    proptest! {
        /// PROP-collapse-whitespace: invariants of `collapse_whitespace` over arbitrary
        /// input (incl. Unicode, NBSP, tabs, multibyte, control chars, long ASCII-space
        /// runs). It must: never panic, return valid UTF-8 (the char loop must not split
        /// a codepoint), never contain a double ASCII space, be idempotent, and preserve
        /// every non-ASCII-space character in order. (collapse only touches ASCII 0x20.)
        #[test]
        fn prop_collapse_whitespace_invariants(s in any::<String>()) {
            let out = collapse_whitespace(&s);
            // No run of two ASCII spaces survives.
            prop_assert!(!out.contains("  "), "double space in {:?}", out);
            // Idempotent.
            prop_assert_eq!(collapse_whitespace(&out), out.clone());
            // Every non-(ASCII-space) char is preserved, in order.
            let kept: String = s.chars().filter(|&c| c != ' ').collect();
            let out_nonspace: String = out.chars().filter(|&c| c != ' ').collect();
            prop_assert_eq!(kept, out_nonspace);
        }
    }

    #[test]
    fn test_empty_query_string() {
        assert_eq!(create_canonical_query_string(""), "");
    }

    #[test]
    fn test_query_with_plus_encoding() {
        assert_eq!(
            create_canonical_query_string("key=hello+world&foo=bar+baz"),
            "key=hello%20world&foo=bar%20baz"
        );
    }

    #[test]
    fn test_query_without_spaces() {
        assert_eq!(
            create_canonical_query_string("action=CreateSession&version=2"),
            "action=CreateSession&version=2"
        );
    }

    #[test]
    fn test_canonical_headers_basic() {
        let headers = vec![
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let (canonical, signed) = create_canonical_headers(&headers);

        assert_eq!(signed, "content-type;host;x-amz-date");
        assert_eq!(
            canonical,
            "content-type:application/json\nhost:rolesanywhere.us-east-1.amazonaws.com\nx-amz-date:20240115T123000Z"
        );
    }

    #[test]
    fn test_ignored_headers_skipped() {
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Authorization".to_string(), "should-not-appear".to_string()),
            ("User-Agent".to_string(), "should-not-appear".to_string()),
            (
                "X-Amzn-Trace-Id".to_string(),
                "should-not-appear".to_string(),
            ),
        ];

        let (_, signed) = create_canonical_headers(&headers);
        assert_eq!(signed, "host");
    }

    #[test]
    fn test_whitespace_collapsed() {
        let headers = vec![("X-Custom".to_string(), "  hello    world  ".to_string())];

        let (canonical, _) = create_canonical_headers(&headers);
        assert_eq!(canonical, "x-custom:hello world");
    }

    #[test]
    fn test_duplicate_header_keys_joined() {
        let headers = vec![
            ("X-Custom".to_string(), "value1".to_string()),
            ("X-Custom".to_string(), "value2".to_string()),
        ];

        let (canonical, _) = create_canonical_headers(&headers);
        assert_eq!(canonical, "x-custom:value1,value2");
    }

    #[test]
    fn test_create_canonical_request() {
        let headers = vec![
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        // SHA-256 of empty string (no request body for this test)
        let payload_hash = EMPTY_SHA256;

        let (hash, signed_headers) =
            create_canonical_request("POST", "/sessions", "", &headers, payload_hash);

        // Hash should be 64 hex characters
        assert_eq!(hash.len(), 64);
        // Signed headers should be sorted and semicolon-joined
        assert_eq!(signed_headers, "content-type;host;x-amz-date");
    }

    #[test]
    fn test_canonical_request_with_query_string() {
        let headers = vec![
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
        ];

        let payload_hash = EMPTY_SHA256;

        // Same inputs but with a query string that has spaces encoded as +
        let (hash_with_query, _) = create_canonical_request(
            "POST",
            "/sessions",
            "key=hello+world",
            &headers,
            payload_hash,
        );

        // Different query string should produce different hash
        let (hash_without_query, _) =
            create_canonical_request("POST", "/sessions", "", &headers, payload_hash);
        assert_ne!(hash_with_query, hash_without_query);
    }

    #[test]
    fn test_canonical_request_different_payload_hash_produces_different_result() {
        let headers = vec![
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
        ];

        let empty_payload = EMPTY_SHA256;
        let some_payload = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";

        let (hash1, _) = create_canonical_request("POST", "/sessions", "", &headers, empty_payload);
        let (hash2, _) = create_canonical_request("POST", "/sessions", "", &headers, some_payload);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_canonical_request_same_inputs_produce_same_hash() {
        let headers = vec![
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
            ("X-Amz-X509".to_string(), "somecertdata".to_string()),
        ];

        let payload_hash = EMPTY_SHA256;

        let (hash1, _) = create_canonical_request("POST", "/sessions", "", &headers, payload_hash);
        let (hash2, _) = create_canonical_request("POST", "/sessions", "", &headers, payload_hash);

        // Deterministic — same input always gives same output
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_canonical_request_header_order_does_not_matter() {
        // Headers in different order should produce the same canonical request
        // because they get sorted internally
        let headers_order_a = vec![
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let headers_order_b = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
        ];

        let payload_hash = EMPTY_SHA256;

        let (hash_a, signed_a) =
            create_canonical_request("POST", "/sessions", "", &headers_order_a, payload_hash);
        let (hash_b, signed_b) =
            create_canonical_request("POST", "/sessions", "", &headers_order_b, payload_hash);

        assert_eq!(hash_a, hash_b);
        assert_eq!(signed_a, signed_b);
    }

    #[test]
    fn test_canonical_request_ignored_headers_dont_affect_hash() {
        let headers_without_ignored = vec![
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
        ];

        let headers_with_ignored = vec![
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
            ("Authorization".to_string(), "some-auth-value".to_string()),
            ("User-Agent".to_string(), "CredHelper/1.0".to_string()),
            ("X-Amzn-Trace-Id".to_string(), "trace-123".to_string()),
        ];

        let payload_hash = EMPTY_SHA256;

        let (hash1, _) = create_canonical_request(
            "POST",
            "/sessions",
            "",
            &headers_without_ignored,
            payload_hash,
        );
        let (hash2, _) =
            create_canonical_request("POST", "/sessions", "", &headers_with_ignored, payload_hash);

        // Ignored headers shouldn't change the output at all
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_create_string_to_sign() {
        let params = SignerParams {
            datetime: chrono::Utc
                .with_ymd_and_hms(2024, 1, 15, 12, 30, 0)
                .unwrap(),
            region: "us-east-1".to_string(),
            service: "rolesanywhere".to_string(),
            algorithm: SigningAlgorithm::RsaSha256,
        };

        let result = create_string_to_sign("abcdef1234567890", &params);

        assert_eq!(
            result,
            "AWS4-X509-RSA-SHA256\n20240115T123000Z\n20240115/us-east-1/rolesanywhere/aws4_request\nabcdef1234567890"
        );
    }

    #[test]
    fn test_string_to_sign_different_algorithm() {
        let params = SignerParams {
            datetime: chrono::Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap(),
            region: "eu-west-1".to_string(),
            service: "rolesanywhere".to_string(),
            algorithm: SigningAlgorithm::EcdsaSha256,
        };

        let result = create_string_to_sign("somehashvalue", &params);

        assert_eq!(
            result,
            "AWS4-X509-ECDSA-SHA256\n20240601T000000Z\n20240601/eu-west-1/rolesanywhere/aws4_request\nsomehashvalue"
        );
    }

    #[test]
    fn test_build_authorization_header() {
        let params = SignerParams {
            datetime: chrono::Utc
                .with_ymd_and_hms(2024, 1, 15, 12, 30, 0)
                .unwrap(),
            region: "us-east-1".to_string(),
            service: "rolesanywhere".to_string(),
            algorithm: SigningAlgorithm::RsaSha256,
        };

        let result = build_authorization_header(
            &params,
            "123456789",
            "content-type;host;x-amz-date",
            "abcdef0123456789",
        );

        assert_eq!(
            result,
            "AWS4-X509-RSA-SHA256 Credential=123456789/20240115/us-east-1/rolesanywhere/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=abcdef0123456789"
        );
    }

    #[test]
    fn test_build_authorization_header_ecdsa() {
        let params = SignerParams {
            datetime: chrono::Utc.with_ymd_and_hms(2025, 6, 10, 9, 0, 0).unwrap(),
            region: "us-west-2".to_string(),
            service: "rolesanywhere".to_string(),
            algorithm: SigningAlgorithm::EcdsaSha256,
        };

        let result = build_authorization_header(
            &params,
            "9876543210",
            "host;x-amz-date;x-amz-x509",
            "fedcba9876543210",
        );

        assert_eq!(
            result,
            "AWS4-X509-ECDSA-SHA256 Credential=9876543210/20250610/us-west-2/rolesanywhere/aws4_request, SignedHeaders=host;x-amz-date;x-amz-x509, Signature=fedcba9876543210"
        );
    }

    // ---- Known-answer tests for the FULLY-ASSEMBLED canonical request ----
    //
    // The tests above assert only STRUCTURE (hash length, determinism, order- and
    // ignored-header-invariance). A regression in the assembly `format!` at
    // `create_canonical_request` (a dropped blank line, a swapped separator, a
    // reordered field) would keep every one of them green. The KATs below pin the
    // exact SHA-256 of a realistic CreateSession canonical request to values computed
    // INDEPENDENTLY of this code (a standalone SHA-256 over the by-hand-assembled
    // string), so an assembly drift fails offline without needing the Go differential
    // shim. Each fixes a random-in-production field (the invocation-id UUID) to a
    // constant so the KAT is deterministic.
    //
    // NOTE (honesty): these values prove the assembly is SELF-CONSISTENT, not that the
    // string is Go-byte-identical — that remains the differential fuzzer's and the
    // pre-prod live test's job. Capturing the same hashes from the Go binary once on
    // the box would upgrade these to true Go-parity KATs.

    /// SHA-256 of the JSON body `{"durationSeconds":3600}` — the payload hash the
    /// pipeline computes for a default-duration request with no roleSessionName.
    const BODY_3600_SHA256: &str =
        "1a15f67f6619aa540b13e9a4c37d149fb2c9bdea25d82b73a3878826694dfe27";

    /// The signed query the pipeline emits for the three ARNs (already percent-encoded,
    /// keys alphabetical: profileArn < roleArn < trustAnchorArn).
    const KAT_QUERY: &str = "profileArn=arn%3Aaws%3Arolesanywhere%3Aus-east-1%3A123456789012%3Aprofile%2Fp&roleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fr&trustAnchorArn=arn%3Aaws%3Arolesanywhere%3Aus-east-1%3A123456789012%3Atrust-anchor%2Fta";

    /// The six headers the pipeline signs, in arbitrary input order (the canonicalizer
    /// sorts them). Invocation-id is pinned to a fixed UUID (random in production).
    fn kat_base_headers() -> Vec<(String, String)> {
        vec![
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
            (
                "X-Amz-X509".to_string(),
                "MIIBcertFIXTUREbase64".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Amz-Sdk-Invocation-Id".to_string(),
                "00000000-0000-4000-8000-000000000000".to_string(),
            ),
            (
                "Amz-Sdk-Request".to_string(),
                "attempt=1; max=3".to_string(),
            ),
        ]
    }

    #[test]
    fn kat_full_canonical_request_and_string_to_sign() {
        let (hash, signed_headers) = create_canonical_request(
            "POST",
            "/sessions",
            KAT_QUERY,
            &kat_base_headers(),
            BODY_3600_SHA256,
        );

        // Independently computed; NOT produced by create_canonical_request.
        assert_eq!(
            hash, "2ccabf6a9fb9684cb23878e5ed948ba0e04f2f190aed150f29acd360734aa944",
            "assembled canonical-request hash must match the independently-computed value \
             (a mismatch means the canonical-request assembly changed shape)"
        );
        assert_eq!(
            signed_headers,
            "amz-sdk-invocation-id;amz-sdk-request;content-type;host;x-amz-date;x-amz-x509"
        );

        // Feed the REAL hash (not a synthetic literal) into the string-to-sign and pin it,
        // so the STS construction is proven end-to-end against a real canonical hash.
        let params = SignerParams {
            datetime: chrono::Utc
                .with_ymd_and_hms(2024, 1, 15, 12, 30, 0)
                .unwrap(),
            region: "us-east-1".to_string(),
            service: "rolesanywhere".to_string(),
            algorithm: SigningAlgorithm::RsaSha256,
        };
        let sts = create_string_to_sign(&hash, &params);
        assert_eq!(
            sts,
            "AWS4-X509-RSA-SHA256\n20240115T123000Z\n20240115/us-east-1/rolesanywhere/aws4_request\n2ccabf6a9fb9684cb23878e5ed948ba0e04f2f190aed150f29acd360734aa944"
        );
    }

    #[test]
    fn kat_canonical_request_with_certificate_chain_header() {
        // Edge case: when a chain is supplied the pipeline adds `X-Amz-X509-Chain`
        // (base64 of each intermediate, comma-joined). Its key sorts AFTER `x-amz-x509`,
        // so it lands last in both the canonical headers and the signed-headers list.
        // Pins that the extra signed header changes the hash to a known value.
        let mut headers = kat_base_headers();
        headers.push((
            "X-Amz-X509-Chain".to_string(),
            "MIIBinterFIXTURE1,MIIBinterFIXTURE2".to_string(),
        ));

        let (hash, signed_headers) =
            create_canonical_request("POST", "/sessions", KAT_QUERY, &headers, BODY_3600_SHA256);

        assert_eq!(
            hash, "88d5654d25fae8e96a464b1261443e88da0c329c74430e7b703e89b2315c3941",
            "chain-header canonical hash must match the independently-computed value"
        );
        assert_eq!(
            signed_headers,
            "amz-sdk-invocation-id;amz-sdk-request;content-type;host;x-amz-date;x-amz-x509;x-amz-x509-chain",
            "x-amz-x509-chain must sort last in the signed-headers list"
        );
    }

    #[test]
    fn kat_canonical_request_pins_whitespace_normalization() {
        // Edge case: header-value normalization at the FULL-assembly level. The raw value
        // "  hello    world  " must normalize to "hello world" (trim + collapse ASCII
        // spaces) BEFORE it is hashed. This locks the documented per-value normalization
        // divergence (canonical.rs header-cleaning) into an offline KAT, not just the
        // isolated collapse_whitespace unit test. Uses a minimal 3-header set with a
        // simplified query so the pinned hash isolates the normalization behavior.
        let query = "profileArn=a&roleArn=b&trustAnchorArn=c";
        let headers = vec![
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
            // Untrimmed, interior double-spaces — must be normalized before hashing.
            ("X-Custom".to_string(), "  hello    world  ".to_string()),
        ];

        let (hash, signed_headers) =
            create_canonical_request("POST", "/sessions", query, &headers, BODY_3600_SHA256);

        // The independently-computed hash was taken over the NORMALIZED value
        // "x-custom:hello world" — so if normalization stops happening, the hash diverges.
        assert_eq!(
            hash, "782e39cbe4431b45040d799d2ded7a73224b2a1a14dd2a3cd13db7e3bb941683",
            "value whitespace must be trimmed + interior-collapsed before hashing"
        );
        assert_eq!(signed_headers, "host;x-amz-date;x-custom");
    }

    #[test]
    fn kat_canonical_request_pins_duplicate_key_join() {
        // Edge case: two values for the same header key must be comma-joined in insertion
        // order ("value1,value2") inside the canonical request. The isolated
        // test_duplicate_header_keys_joined proves the string; this pins that the joined
        // form flows correctly into the assembled-request hash.
        let query = "profileArn=a&roleArn=b&trustAnchorArn=c";
        let headers = vec![
            (
                "Host".to_string(),
                "rolesanywhere.us-east-1.amazonaws.com".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20240115T123000Z".to_string()),
            ("X-Custom".to_string(), "value1".to_string()),
            ("X-Custom".to_string(), "value2".to_string()),
        ];

        let (hash, signed_headers) =
            create_canonical_request("POST", "/sessions", query, &headers, BODY_3600_SHA256);

        assert_eq!(
            hash, "a68ddba07a2e612abe6095867b7a763581c1fcbcf508ac45338b4177aab7d282",
            "duplicate-key values must be comma-joined in order before hashing"
        );
        // A duplicate key appears ONCE in the signed-headers list.
        assert_eq!(signed_headers, "host;x-amz-date;x-custom");
    }
}
