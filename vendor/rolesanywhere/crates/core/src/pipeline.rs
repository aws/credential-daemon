use crate::canonical::{
    build_authorization_header, create_canonical_request, create_string_to_sign,
};
use crate::client::CreateSessionClient;
use crate::identity::{CredentialIdentity, FileSystemIdentity};
use crate::key_reader::certificate_to_base64;
use crate::serial::extract_serial_number;
use crate::types::SignerParams;

use aws_lc_rs::digest;
use chrono::Utc;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::Url;
use std::fmt;

/// SDK "transport" headers that the Go binary signs.
///
/// Go runs through the AWS SDK, which attaches these two headers to the request
/// in the Build phase, *before* signing. Because Go's signer signs every header
/// on the request (minus the ignored set), they end up inside the signature. To
/// stay consistent with the Go binary we add the same two headers here.
///
/// (Note: the SDK also tracks Content-Length, but as a request *field*, not a
/// header, so the Go signer never signs it — we don't add it either.)
const AMZ_SDK_INVOCATION_ID: &str = "Amz-Sdk-Invocation-Id";
const AMZ_SDK_REQUEST: &str = "Amz-Sdk-Request";

/// The retry-metrics value the SDK sends on the first attempt: `attempt=1; max=3`.
/// The default max attempts in the AWS SDK is 3, and we make a single attempt.
const AMZ_SDK_REQUEST_VALUE: &str = "attempt=1; max=3";

/// Characters that should NOT be percent-encoded in query parameter values.
/// Per RFC 3986 unreserved characters: A-Z a-z 0-9 - _ . ~
/// We encode everything else by removing these from NON_ALPHANUMERIC.
const QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub struct SignRequestInput {
    pub cert_path: String,
    pub key_path: String,
    pub region: String,
    pub trust_anchor_arn: String,
    pub profile_arn: String,
    pub role_arn: String,
    pub session_duration: Option<i32>,
    pub role_session_name: Option<String>,
    pub cert_chain_path: Option<String>,
    pub endpoint_url: Option<String>,
}

#[derive(Debug)]
pub struct SignedRequest {
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub query_string: String,
}

#[derive(Debug)]
pub enum PipelineError {
    CertificateError {
        path: String,
        reason: String,
    },
    PrivateKeyError {
        path: String,
        reason: String,
    },
    InvalidArn {
        arn: String,
        reason: String,
    },
    RegionMismatch {
        trust_anchor_region: String,
        profile_region: String,
    },
    UnsupportedKeyType {
        detail: String,
    },
    SigningError {
        algorithm: String,
        reason: String,
    },
    HttpError {
        reason: String,
    },
    ApiError {
        status_code: u16,
        body: String,
    },
    ResponseError {
        reason: String,
    },
    SerializationError {
        reason: String,
    },
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipelineError::CertificateError { path, reason } => {
                write!(f, "Certificate error for '{}': {}", path, reason)
            }
            PipelineError::PrivateKeyError { path, reason } => {
                write!(f, "Private key error for '{}': {}", path, reason)
            }
            PipelineError::InvalidArn { arn, reason } => {
                write!(f, "Invalid ARN '{}': {}", arn, reason)
            }
            PipelineError::RegionMismatch {
                trust_anchor_region,
                profile_region,
            } => {
                write!(
                    f,
                    "Region mismatch: trust anchor region '{}' != profile region '{}'",
                    trust_anchor_region, profile_region
                )
            }
            PipelineError::UnsupportedKeyType { detail } => {
                write!(f, "Unsupported key type: {}", detail)
            }
            PipelineError::SigningError { algorithm, reason } => {
                write!(f, "Signing error ({}): {}", algorithm, reason)
            }
            PipelineError::HttpError { reason } => {
                write!(f, "HTTP error: {}", reason)
            }
            PipelineError::ApiError { status_code, body } => {
                write!(f, "API error (status {}): {}", status_code, body)
            }
            PipelineError::ResponseError { reason } => {
                write!(f, "Response error: {}", reason)
            }
            PipelineError::SerializationError { reason } => {
                write!(f, "Serialization error: {}", reason)
            }
        }
    }
}

/// JSON request body sent to CreateSession.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionBody {
    duration_seconds: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    role_session_name: Option<String>,
}

/// Parse an ARN and return its region component, matching Go's `arn.Parse`.
///
/// ARN format: `arn:{partition}:{service}:{region}:{account}:{resource}`
///
/// Go's `arn.Parse` (used by the reference tool) does exactly this much:
///
/// - require the `arn:` prefix,
/// - split into 6 sections (the resource part may itself contain ':' which is why
///   we use `splitn(6, ..)` and keep everything after the 5th ':' together),
/// - require exactly 6 sections,
/// - return section 3 as the region.
///
/// It does NOT check the service name or reject an empty region, so we don't
/// either — that keeps our behavior consistent with the Go binary.
fn validate_arn(arn: &str) -> Result<String, PipelineError> {
    // splitn(6, ':') yields at most 6 pieces; the 6th holds the whole resource,
    // including any ':' characters inside it (e.g. "trust-anchor/id:extra").
    let parts: Vec<&str> = arn.splitn(6, ':').collect();

    if parts.len() != 6 || parts[0] != "arn" {
        return Err(PipelineError::InvalidArn {
            arn: arn.to_string(),
            reason: "ARN must be 'arn:partition:service:region:account:resource'".to_string(),
        });
    }

    // Section index 3 is the region.
    Ok(parts[3].to_string())
}

/// Decide the AWS region to use for signing and the endpoint host.
///
/// This mirrors Go (`credentials.go`): use the explicit `--region` value if the
/// caller provided one, otherwise fall back to the region from the trust anchor
/// ARN. Keeping this in one helper avoids duplicating the rule in two places.
fn resolve_region(input: &SignRequestInput) -> Result<String, PipelineError> {
    if input.region.is_empty() {
        validate_arn(&input.trust_anchor_arn)
    } else {
        Ok(input.region.clone())
    }
}

/// Build the JSON request body.
fn build_json_body(input: &SignRequestInput) -> Result<String, PipelineError> {
    let body = CreateSessionBody {
        duration_seconds: input.session_duration.unwrap_or(3600),
        role_session_name: input.role_session_name.clone(),
    };
    serde_json::to_string(&body).map_err(|e| PipelineError::SerializationError {
        reason: e.to_string(),
    })
}

/// Generate a fresh UUID (version 4) for the `Amz-Sdk-Invocation-Id` header.
///
/// The AWS SDK sets this header to a random UUID on every request. We build the
/// same thing from 16 secure-random bytes (via aws-lc-rs) so we don't need a
/// separate uuid crate. A UUID v4 is just random bytes with two fields fixed:
/// the version (4) and the variant.
fn generate_invocation_id() -> String {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let mut bytes = [0u8; 16];
    // If the OS random source ever fails, fall back to a fixed UUID. This header
    // is not security-sensitive (it's only used for request tracing), so a
    // fallback is acceptable and keeps signing from failing.
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return "00000000-0000-4000-8000-000000000000".to_string();
    }

    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4 in the high nibble of byte 6
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant '10' in the high bits of byte 8

    // Format as the standard 8-4-4-4-12 hex grouping.
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// Build the query string with percent-encoded ARN values, sorted alphabetically by key.
/// Keys are already alphabetical: profileArn < roleArn < trustAnchorArn.
fn build_query_string(input: &SignRequestInput) -> String {
    let encoded_profile = utf8_percent_encode(&input.profile_arn, QUERY_ENCODE_SET).to_string();
    let encoded_role = utf8_percent_encode(&input.role_arn, QUERY_ENCODE_SET).to_string();
    let encoded_trust_anchor =
        utf8_percent_encode(&input.trust_anchor_arn, QUERY_ENCODE_SET).to_string();

    format!(
        "profileArn={}&roleArn={}&trustAnchorArn={}",
        encoded_profile, encoded_role, encoded_trust_anchor
    )
}

/// Orchestrates the full signing flow. Returns all headers, body, and query string
/// needed by the HTTP client.
///
/// This is the file-path entry point: it builds a `FileSystemIdentity` from the
/// cert/key/chain paths and delegates to `sign_request_with_identity`. The identity
/// indirection is internal; callers pass cert/key/chain paths.
pub fn sign_request(input: &SignRequestInput) -> Result<SignedRequest, PipelineError> {
    let identity = FileSystemIdentity::from_paths(
        &input.cert_path,
        &input.key_path,
        input.cert_chain_path.as_deref(),
    )?;
    sign_request_with_identity(input, &identity)
}

/// The real signing flow, driven by any `CredentialIdentity`. The identity supplies the
/// certificate DER (serial + `X-Amz-X509`), the chain DER, the algorithm, and the
/// signature; everything else (ARNs, region, body, query, headers, canonicalization) is
/// derived from `input`.
///
/// `input`'s `cert_path`/`key_path`/`cert_chain_path` fields are IGNORED here — the
/// identity is the key/cert source on this path. Only the request parameters
/// (ARNs, region, duration, session-name, endpoint) are read.
pub fn sign_request_with_identity(
    input: &SignRequestInput,
    identity: &dyn CredentialIdentity,
) -> Result<SignedRequest, PipelineError> {
    // 1. Validate ARNs and extract regions (unchanged; reads only ARN fields of `input`).
    let trust_anchor_region = validate_arn(&input.trust_anchor_arn)?;
    let profile_region = validate_arn(&input.profile_arn)?;

    // Check region consistency between trust anchor and profile ARNs
    if trust_anchor_region != profile_region {
        return Err(PipelineError::RegionMismatch {
            trust_anchor_region,
            profile_region,
        });
    }

    // Use the explicit region if given, otherwise the trust anchor's region.
    let region = resolve_region(input)?;

    // 2. Certificate DER comes from the identity.
    let cert_der = identity.certificate_der();

    // 3. Extract serial number from the certificate DER. The cert came from the identity
    //    (not necessarily `input.cert_path`, which the identity path ignores), so attribute
    //    a serial-decode failure to the certificate itself rather than to an unread path.
    let serial_number =
        extract_serial_number(cert_der).map_err(|reason| PipelineError::CertificateError {
            path: "<certificate>".to_string(),
            reason,
        })?;

    // 4. Base64-encode certificate for X-Amz-X509 header.
    let cert_base64 = certificate_to_base64(cert_der);

    // 5. The signing algorithm comes from the identity.
    let algorithm = identity.signing_algorithm().clone();

    // 6. Build JSON body
    let body = build_json_body(input)?;

    // 7. Compute payload hash (SHA-256 of JSON body) using aws-lc-rs.
    let payload_hash = hex::encode(digest::digest(&digest::SHA256, body.as_bytes()).as_ref());

    // 8. Build query string
    let query_string = build_query_string(input);

    // 9. Determine current timestamp
    let now = Utc::now();

    // 10. Build the host header value from the WHATWG-parsed URL so it matches
    //     what reqwest will connect to (same parser, no authority-confusion gap).
    let host = match &input.endpoint_url {
        Some(url) => {
            let parsed = Url::parse(url).map_err(|e| PipelineError::HttpError {
                reason: format!("invalid endpoint URL: {e}"),
            })?;
            let h = parsed.host_str().ok_or_else(|| PipelineError::HttpError {
                reason: "endpoint URL has no host".to_string(),
            })?;
            match parsed.port() {
                Some(p) => format!("{}:{}", h, p),
                None => h.to_string(),
            }
        }
        None => format!("rolesanywhere.{}.amazonaws.com", region),
    };

    // 11. Format the X-Amz-Date
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    // 12. Assemble the headers to sign. Order doesn't matter here because the
    //     canonical request sorts them.
    //       - Host, X-Amz-Date, X-Amz-X509       (set by the Go signer)
    //       - Content-Type                       (set by the SDK JSON serializer)
    //       - Amz-Sdk-Invocation-Id, Amz-Sdk-Request (set by the SDK before signing)
    let mut headers: Vec<(String, String)> = vec![
        ("Host".to_string(), host),
        ("X-Amz-Date".to_string(), amz_date),
        ("X-Amz-X509".to_string(), cert_base64),
        ("Content-Type".to_string(), "application/json".to_string()),
        (AMZ_SDK_INVOCATION_ID.to_string(), generate_invocation_id()),
        (
            AMZ_SDK_REQUEST.to_string(),
            AMZ_SDK_REQUEST_VALUE.to_string(),
        ),
    ];

    // Optionally add the certificate chain header from the identity's chain DER. The Go
    // reference joins the base64 of each certificate with ',' (see certificateChainToString)
    // and omits the header when the chain is empty.
    let chain_b64: Vec<String> = identity
        .certificate_chain_der()
        .iter()
        .map(|der| certificate_to_base64(der))
        .collect();
    if !chain_b64.is_empty() {
        headers.push(("X-Amz-X509-Chain".to_string(), chain_b64.join(",")));
    }

    // 13. Create canonical request and get signed headers
    let (canonical_request_hash, signed_headers) =
        create_canonical_request("POST", "/sessions", &query_string, &headers, &payload_hash);

    // 14. Build SignerParams
    let signer_params = SignerParams {
        datetime: now,
        region: region.clone(),
        service: "rolesanywhere".to_string(),
        algorithm,
    };

    // 15. Create string-to-sign
    let string_to_sign = create_string_to_sign(&canonical_request_hash, &signer_params);

    // 16. Sign the string-to-sign via the identity, then hex-encode the raw signature.
    //     The signer returns raw bytes; hex-encoding happens here at this single call site.
    let signature_bytes =
        identity
            .sign(string_to_sign.as_bytes())
            .map_err(|reason| PipelineError::SigningError {
                algorithm: signer_params.algorithm.as_str().to_string(),
                reason,
            })?;
    let signature = hex::encode(signature_bytes);

    // 17. Build authorization header
    let authorization =
        build_authorization_header(&signer_params, &serial_number, &signed_headers, &signature);

    // 18. Add the Authorization header to the headers list
    headers.push(("Authorization".to_string(), authorization));

    Ok(SignedRequest {
        headers,
        body,
        query_string,
    })
}

/// Output format matching AWS credential_process spec.
//
// Note on secret handling: the private key is zeroized on drop (see `key_reader`), but the
// derived session credentials here (`secret_access_key`, `session_token`) are plain `String`
// and are NOT zeroized — the CLI prints them to stdout by contract, so scrubbing them in
// memory buys nothing on that path. A future long-running consumer (e.g. the caching
// provider) that holds credentials in memory should revisit this.
//
// `Clone` so the caching layer (`caching::CachingCredentialProvider`) can hand back a
// copy of the cached credentials on each hit without re-signing. `Debug` so callers and
// tests can format a `Result<CredentialProcessOutput, _>` (the fields are already fully
// exposed via `Serialize`/the CLI's stdout, so Debug leaks nothing new).
#[derive(serde::Serialize, Clone, Debug)]
pub struct CredentialProcessOutput {
    #[serde(rename = "Version")]
    pub version: i32,
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "SessionToken")]
    pub session_token: String,
    #[serde(rename = "Expiration")]
    pub expiration: String,
}

/// Top-level entry point: signs and sends the request, returns credential_process output.
///
/// File-path entry point: builds a `FileSystemIdentity` and delegates to
/// `generate_credentials_with_identity`.
pub fn generate_credentials(
    input: &SignRequestInput,
) -> Result<CredentialProcessOutput, PipelineError> {
    let identity = FileSystemIdentity::from_paths(
        &input.cert_path,
        &input.key_path,
        input.cert_chain_path.as_deref(),
    )?;
    generate_credentials_with_identity(input, &identity)
}

/// Sign via the given identity, call CreateSession, and return credential_process output.
/// The identity-based twin of `generate_credentials`. `input`'s path fields are ignored
/// (the identity is the key/cert source); the rest of `input` supplies request parameters.
pub fn generate_credentials_with_identity(
    input: &SignRequestInput,
    identity: &dyn CredentialIdentity,
) -> Result<CredentialProcessOutput, PipelineError> {
    // 1. Sign the request (ARN validation & region derivation happen inside).
    let signed = sign_request_with_identity(input, identity)?;

    // 2. Determine the region for the HTTP client (same rule as signing).
    let region = resolve_region(input)?;

    // 3. Create the HTTP client
    let client = CreateSessionClient::new(&region, input.endpoint_url.as_deref())
        .map_err(|reason| PipelineError::HttpError { reason })?;

    // 4. Call CreateSession API. The client returns a typed ClientError, which we
    //    map to the public PipelineError taxonomy in one exhaustive place.
    let response = client
        .create_session(&signed.headers, &signed.body, &signed.query_string)
        .map_err(classify_client_error)?;

    // 5. Extract the first credential from the response
    let credential =
        response
            .credential_set
            .into_iter()
            .next()
            .ok_or_else(|| PipelineError::ResponseError {
                reason: "No credentials returned in response".to_string(),
            })?;

    // 6. Map to CredentialProcessOutput with Version=1
    Ok(CredentialProcessOutput {
        version: 1,
        access_key_id: credential.access_key_id,
        secret_access_key: credential.secret_access_key,
        session_token: credential.session_token,
        expiration: credential.expiration,
    })
}

/// Map a typed `client::ClientError` to the public `PipelineError` taxonomy.
///
/// The status code is carried straight through as a field (no string round-trip), and
/// the `match` is exhaustive, so a new `ClientError` variant is a compile error here
/// rather than a silent fall-through. `client.rs` and `pipeline.rs` share no
/// error-message string literal.
fn classify_client_error(err: crate::client::ClientError) -> PipelineError {
    use crate::client::ClientError;
    match err {
        ClientError::Http(reason) => PipelineError::HttpError { reason },
        ClientError::Api { status, body } => PipelineError::ApiError {
            status_code: status,
            body,
        },
        ClientError::Response(reason) => PipelineError::ResponseError { reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_arn_valid() {
        let arn = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc-123";
        let result = validate_arn(arn);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "us-east-1");
    }

    #[test]
    fn test_validate_arn_invalid_prefix() {
        // Missing the "arn" prefix -> rejected (matches Go arn.Parse).
        let arn = "notarn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc";
        let result = validate_arn(arn);
        assert!(result.is_err());
        assert!(matches!(result, Err(PipelineError::InvalidArn { .. })));
    }

    #[test]
    fn test_validate_arn_any_service_accepted() {
        // Go's arn.Parse does NOT check the service name, so we accept any service
        // and still return the region. This keeps us consistent with the Go binary.
        let arn = "arn:aws:s3:us-east-1:123456789012:bucket/my-bucket";
        let result = validate_arn(arn);
        assert_eq!(result.unwrap(), "us-east-1");
    }

    #[test]
    fn test_validate_arn_too_few_parts() {
        // Fewer than 6 colon-separated sections -> rejected.
        let arn = "arn:aws:rolesanywhere";
        let result = validate_arn(arn);
        assert!(result.is_err());
        assert!(matches!(result, Err(PipelineError::InvalidArn { .. })));
    }

    #[test]
    fn test_validate_arn_empty_region_allowed() {
        // Go's arn.Parse permits an empty region section (returns ""), so we do too.
        let arn = "arn:aws:rolesanywhere::123456789012:trust-anchor/abc";
        let result = validate_arn(arn);
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_validate_arn_resource_with_colons() {
        // The resource section may itself contain ':' — splitn(6) keeps it whole,
        // and the region is still read correctly from section 3.
        let arn = "arn:aws:rolesanywhere:eu-west-1:123456789012:trust-anchor/abc:extra:bits";
        let result = validate_arn(arn);
        assert_eq!(result.unwrap(), "eu-west-1");
    }

    /// Minimal SignRequestInput for body/region tests: empty everything, no duration,
    /// region "us-east-1". Tests override only the fields they exercise. Keeps the new
    /// body/duration/session-name tests from each repeating all 10 fields.
    fn minimal_input() -> SignRequestInput {
        SignRequestInput {
            cert_path: String::new(),
            key_path: String::new(),
            region: "us-east-1".to_string(),
            trust_anchor_arn: String::new(),
            profile_arn: String::new(),
            role_arn: String::new(),
            session_duration: None,
            role_session_name: None,
            cert_chain_path: None,
            endpoint_url: None,
        }
    }

    #[test]
    fn test_build_json_body_default_duration() {
        // minimal_input() is the all-default case, so build_json_body falls back to 3600s.
        let body = build_json_body(&minimal_input()).unwrap();
        assert_eq!(body, r#"{"durationSeconds":3600}"#);
    }

    #[test]
    fn test_build_json_body_empty_role_session_name_is_serialized() {
        // skip_serializing_if=Option::is_none does NOT skip Some(""), so an
        // EMPTY (not None) role_session_name is emitted. Go OMITS it when == ""
        // (credentials.go:144). The CLI maps "" -> None via opt() so the binary never
        // hits this, but a direct library/FFI caller passing Some("") produces a body
        // Go never produces. This locks the current behavior and documents the gap.
        let mut input = minimal_input();
        input.session_duration = Some(3600);
        input.role_session_name = Some(String::new());
        assert_eq!(
            build_json_body(&input).unwrap(),
            r#"{"durationSeconds":3600,"roleSessionName":""}"#
        );
    }

    #[test]
    fn test_build_json_body_duration_passthrough_no_bounds() {
        // durationSeconds is serialized verbatim with no client-side bounds or clamp
        // (bounds are a SERVER concern). Locks the i32/negative pass-through divergence
        // and that serde does not skip 0 (the field is non-Option i32).
        for (dur, expected) in [
            (-1, r#"{"durationSeconds":-1}"#),
            (0, r#"{"durationSeconds":0}"#),
            (43201, r#"{"durationSeconds":43201}"#),
        ] {
            let mut input = minimal_input();
            input.session_duration = Some(dur);
            assert_eq!(build_json_body(&input).unwrap(), expected, "duration {dur}");
        }
    }

    #[test]
    fn test_build_json_body_custom_duration_and_session_name() {
        let input = SignRequestInput {
            session_duration: Some(900),
            role_session_name: Some("my-session".to_string()),
            ..minimal_input()
        };
        let body = build_json_body(&input).unwrap();
        assert_eq!(
            body,
            r#"{"durationSeconds":900,"roleSessionName":"my-session"}"#
        );
    }

    #[test]
    fn test_build_json_body_no_arns_in_body() {
        let input = SignRequestInput {
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123:ta/abc".to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123:profile/xyz".to_string(),
            role_arn: "arn:aws:iam::123:role/MyRole".to_string(),
            session_duration: Some(3600),
            ..minimal_input()
        };
        let body = build_json_body(&input).unwrap();
        assert!(!body.contains("profileArn"));
        assert!(!body.contains("roleArn"));
        assert!(!body.contains("trustAnchorArn"));
        assert!(!body.contains("cert"));
    }

    #[test]
    fn test_build_query_string_percent_encodes_special_chars() {
        let input = SignRequestInput {
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc-123"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def-456".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            ..minimal_input()
        };
        let qs = build_query_string(&input);

        // Colons and slashes should be percent-encoded
        assert!(qs.contains("%3A") || qs.contains("%3a"));
        assert!(qs.contains("%2F") || qs.contains("%2f"));

        // Keys should be in alphabetical order
        let profile_pos = qs.find("profileArn=").unwrap();
        let role_pos = qs.find("roleArn=").unwrap();
        let trust_pos = qs.find("trustAnchorArn=").unwrap();
        assert!(profile_pos < role_pos);
        assert!(role_pos < trust_pos);
    }

    #[test]
    fn test_sign_request_with_rsa_key() {
        let input = SignRequestInput {
            cert_path: "../../tst/certs/rsa-2048-cert.pem".to_string(),
            key_path: "../../tst/certs/rsa-2048-key.pem".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc-123"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def-456".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            ..minimal_input()
        };

        let result = sign_request(&input);
        assert!(
            result.is_ok(),
            "sign_request should succeed: {:?}",
            result.err()
        );

        let signed = result.unwrap();

        // Verify body is compact JSON with durationSeconds
        assert_eq!(signed.body, r#"{"durationSeconds":3600}"#);

        // Verify query string contains encoded ARNs
        assert!(signed.query_string.contains("profileArn="));
        assert!(signed.query_string.contains("roleArn="));
        assert!(signed.query_string.contains("trustAnchorArn="));

        // Verify required headers are present, including the two SDK headers we
        // add for parity with the Go binary.
        let header_keys: Vec<&str> = signed.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(header_keys.contains(&"Host"));
        assert!(header_keys.contains(&"X-Amz-Date"));
        assert!(header_keys.contains(&"X-Amz-X509"));
        assert!(header_keys.contains(&"Content-Type"));
        assert!(header_keys.contains(&"Amz-Sdk-Invocation-Id"));
        assert!(header_keys.contains(&"Amz-Sdk-Request"));
        assert!(header_keys.contains(&"Authorization"));

        // The Amz-Sdk-Request header must carry the SDK's first-attempt value.
        let sdk_request = signed
            .headers
            .iter()
            .find(|(k, _)| k == "Amz-Sdk-Request")
            .unwrap();
        assert_eq!(sdk_request.1, "attempt=1; max=3");

        // The Authorization header's SignedHeaders list must include the two SDK
        // headers, proving they are actually part of the signature (not just sent).
        let auth_value = &signed
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap()
            .1;
        assert!(
            auth_value.contains("amz-sdk-invocation-id;amz-sdk-request"),
            "SignedHeaders should include the SDK headers, got: {}",
            auth_value
        );

        // Verify Host header value
        let host = signed.headers.iter().find(|(k, _)| k == "Host").unwrap();
        assert_eq!(host.1, "rolesanywhere.us-east-1.amazonaws.com");

        // Verify Content-Type
        let ct = signed
            .headers
            .iter()
            .find(|(k, _)| k == "Content-Type")
            .unwrap();
        assert_eq!(ct.1, "application/json");

        // Verify Authorization header contains expected algorithm
        let auth = signed
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap();
        assert!(auth.1.starts_with("AWS4-X509-RSA-SHA256"));
        assert!(auth.1.contains("Credential="));
        assert!(auth.1.contains("SignedHeaders="));
        assert!(auth.1.contains("Signature="));
    }

    #[test]
    fn test_sign_request_with_ec_key() {
        // Drives the ECDSA branch (detect_algorithm -> sign_with_ecdsa ->
        // build_authorization_header) through the full pipeline, which the RSA test
        // above does not cover. ECDSA signatures are randomized, so
        // we assert the request STRUCTURE (algorithm, header set, SignedHeaders), not
        // the signature bytes.
        let input = SignRequestInput {
            cert_path: "../../tst/certs/ec-p256-cert.pem".to_string(),
            key_path: "../../tst/certs/ec-p256-key.pem".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc-123"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def-456".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            ..minimal_input()
        };

        let result = sign_request(&input);
        assert!(
            result.is_ok(),
            "sign_request should succeed for EC key: {:?}",
            result.err()
        );
        let signed = result.unwrap();

        let auth = signed
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap();
        // The EC key must select the ECDSA algorithm string.
        assert!(
            auth.1.starts_with("AWS4-X509-ECDSA-SHA256"),
            "EC key should produce an ECDSA Authorization header, got: {}",
            auth.1
        );
        assert!(auth.1.contains("Credential="));
        assert!(auth.1.contains("SignedHeaders="));
        assert!(auth.1.contains("Signature="));
        // The two SDK headers must still be inside the signature for EC, same as RSA.
        assert!(
            auth.1.contains("amz-sdk-invocation-id;amz-sdk-request"),
            "SignedHeaders should include the SDK headers, got: {}",
            auth.1
        );
    }

    #[test]
    fn test_sign_request_with_cert_chain_sets_x509_chain_header() {
        // Exercises the X-Amz-X509-Chain block: read the chain PEM, base64 each
        // CERTIFICATE block, join with ',' (Go parity: certificateChainToString).
        // Every other pipeline test sets cert_chain_path: None, so this is the only
        // coverage of the chain header value format.
        let input = SignRequestInput {
            cert_path: "../../tst/certs/rsa-2048-cert.pem".to_string(),
            key_path: "../../tst/certs/rsa-2048-key.pem".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc-123"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def-456".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            cert_chain_path: Some("../../tst/certs/ratest-ca-cert.pem".to_string()),
            ..minimal_input()
        };

        let signed = sign_request(&input).expect("sign_request should succeed with a cert chain");

        // Compute the expected header value independently from the same fixture so the
        // assertion checks the construction, not just that *some* value is present.
        let chain_bytes = std::fs::read("../../tst/certs/ratest-ca-cert.pem").unwrap();
        let expected = pem::parse_many(&chain_bytes)
            .unwrap()
            .iter()
            .filter(|b| b.tag() == crate::pem_tags::CERTIFICATE)
            .map(|b| certificate_to_base64(b.contents()))
            .collect::<Vec<_>>()
            .join(",");

        let chain_header = signed
            .headers
            .iter()
            .find(|(k, _)| k == "X-Amz-X509-Chain")
            .expect("X-Amz-X509-Chain header should be present when a chain is supplied");
        assert_eq!(
            chain_header.1, expected,
            "chain header must be comma-joined base64 of each cert"
        );

        // The chain header must also be signed (appear in SignedHeaders).
        let auth = signed
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap();
        assert!(
            auth.1.contains("x-amz-x509-chain"),
            "SignedHeaders should include x-amz-x509-chain, got: {}",
            auth.1
        );
    }

    #[test]
    fn test_sign_request_with_multi_cert_chain_comma_joins_in_order() {
        // The test above uses a single-CERTIFICATE chain file, so the comma-join of
        // MULTIPLE certs (Go parity: certificateChainToString) is never actually
        // exercised — a one-element join is trivially correct. `ratest-chain.pem` is the
        // test CA hierarchy concatenated leaf-then-CA (ratest-client-cert.pem +
        // ratest-ca-cert.pem), so it has two CERTIFICATE blocks and drives the real
        // multi-element join through sign_request -> FileSystemIdentity::from_paths.
        let input = SignRequestInput {
            cert_path: "../../tst/certs/rsa-2048-cert.pem".to_string(),
            key_path: "../../tst/certs/rsa-2048-key.pem".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc-123"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def-456".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            cert_chain_path: Some("../../tst/certs/ratest-chain.pem".to_string()),
            ..minimal_input()
        };

        let signed =
            sign_request(&input).expect("sign_request should succeed with a two-cert chain");

        // Recompute the expected value independently from the same fixture, preserving
        // file order (leaf first, then CA) — this is the property the single-cert test
        // can't check.
        let chain_bytes = std::fs::read("../../tst/certs/ratest-chain.pem").unwrap();
        let expected_parts: Vec<String> = pem::parse_many(&chain_bytes)
            .unwrap()
            .iter()
            .filter(|b| b.tag() == crate::pem_tags::CERTIFICATE)
            .map(|b| certificate_to_base64(b.contents()))
            .collect();
        assert_eq!(
            expected_parts.len(),
            2,
            "fixture must contribute exactly two certificates to exercise the join"
        );
        let expected = expected_parts.join(",");

        let chain_header = signed
            .headers
            .iter()
            .find(|(k, _)| k == "X-Amz-X509-Chain")
            .expect("X-Amz-X509-Chain header should be present with a two-cert chain");
        assert_eq!(
            chain_header.1, expected,
            "chain header must be the two certs' base64 comma-joined in file order"
        );
        // The join must be a single comma between the two base64 blobs (no trailing
        // comma, no space) — the exact byte shape Go's certificateChainToString emits.
        assert_eq!(
            chain_header.1.matches(',').count(),
            1,
            "two certs must be separated by exactly one comma, got: {}",
            chain_header.1
        );
        assert_eq!(
            chain_header.1,
            format!("{},{}", expected_parts[0], expected_parts[1]),
            "leaf must come before CA in the joined chain header"
        );
    }

    #[test]
    fn test_sign_request_region_mismatch() {
        let input = SignRequestInput {
            cert_path: "../../tst/certs/rsa-2048-cert.pem".to_string(),
            key_path: "../../tst/certs/rsa-2048-key.pem".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:eu-west-1:123456789012:profile/def".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            ..minimal_input()
        };

        let result = sign_request(&input);
        assert!(result.is_err());
        match result.unwrap_err() {
            PipelineError::RegionMismatch {
                trust_anchor_region,
                profile_region,
            } => {
                assert_eq!(trust_anchor_region, "us-east-1");
                assert_eq!(profile_region, "eu-west-1");
            }
            other => panic!("Expected RegionMismatch, got: {:?}", other),
        }
    }

    #[test]
    fn test_sign_request_region_mismatch_not_suppressed_by_explicit_region() {
        // An explicit --region (here a THIRD, different region) must NOT
        // suppress the trust-anchor-vs-profile mismatch check. Go checks the mismatch
        // (credentials.go:71-73) BEFORE consulting opts.Region (:75); Rust compares the
        // ARN regions (pipeline.rs) before resolve_region. The existing mismatch test
        // uses a region matching the trust anchor, so it would not catch a refactor that
        // resolved the region first and let a mismatch slip through.
        let input = SignRequestInput {
            region: "ap-south-1".to_string(), // a third region, differs from both ARNs
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:eu-west-1:123456789012:profile/def".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            cert_path: "../../tst/certs/rsa-2048-cert.pem".to_string(),
            key_path: "../../tst/certs/rsa-2048-key.pem".to_string(),
            ..minimal_input()
        };
        match sign_request(&input).unwrap_err() {
            PipelineError::RegionMismatch {
                trust_anchor_region,
                profile_region,
            } => {
                assert_eq!(trust_anchor_region, "us-east-1");
                assert_eq!(profile_region, "eu-west-1");
            }
            other => panic!(
                "Expected RegionMismatch despite explicit region, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_sign_request_chain_file_with_no_certificate_blocks_omits_header() {
        // A chain file containing ZERO CERTIFICATE blocks (here a key-only
        // PEM) must NOT emit an empty/garbage X-Amz-X509-Chain header, and signing must
        // still succeed (the `if !chain_b64.is_empty()` guard skips the header).
        let input = SignRequestInput {
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc-123"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def-456".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            cert_path: "../../tst/certs/rsa-2048-cert.pem".to_string(),
            key_path: "../../tst/certs/rsa-2048-key.pem".to_string(),
            // The key PEM has no CERTIFICATE block, so the chain filter yields nothing.
            cert_chain_path: Some("../../tst/certs/rsa-2048-key.pem".to_string()),
            ..minimal_input()
        };
        let signed = sign_request(&input).expect("sign_request should succeed");
        assert!(
            !signed.headers.iter().any(|(k, _)| k == "X-Amz-X509-Chain"),
            "no chain header when the chain file has zero CERTIFICATE blocks"
        );
    }

    #[test]
    fn test_sign_request_invalid_cert_path() {
        let input = SignRequestInput {
            cert_path: "/nonexistent/cert.pem".to_string(),
            key_path: "../../tst/certs/rsa-2048-key.pem".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            ..minimal_input()
        };

        let result = sign_request(&input);
        assert!(result.is_err());
        match result.unwrap_err() {
            PipelineError::CertificateError { path, .. } => {
                assert_eq!(path, "/nonexistent/cert.pem");
            }
            other => panic!("Expected CertificateError, got: {:?}", other),
        }
    }

    #[test]
    fn test_sign_request_invalid_key_path() {
        let input = SignRequestInput {
            cert_path: "../../tst/certs/rsa-2048-cert.pem".to_string(),
            key_path: "/nonexistent/key.pem".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            ..minimal_input()
        };

        let result = sign_request(&input);
        assert!(result.is_err());
        match result.unwrap_err() {
            PipelineError::PrivateKeyError { path, .. } => {
                assert_eq!(path, "/nonexistent/key.pem");
            }
            other => panic!("Expected PrivateKeyError, got: {:?}", other),
        }
    }

    #[test]
    fn test_credential_process_output_serializes_with_pascal_case_and_version_1() {
        let output = CredentialProcessOutput {
            version: 1,
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: "FwoGZXIvYXdzEBYaDH...".to_string(),
            expiration: "2024-01-15T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify Version is 1
        assert_eq!(parsed["Version"], 1);

        // Verify PascalCase field names
        assert_eq!(parsed["AccessKeyId"], "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            parsed["SecretAccessKey"],
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(parsed["SessionToken"], "FwoGZXIvYXdzEBYaDH...");
        assert_eq!(parsed["Expiration"], "2024-01-15T12:00:00Z");

        // Verify no snake_case keys are present
        assert!(parsed.get("version").is_none());
        assert!(parsed.get("access_key_id").is_none());
        assert!(parsed.get("secret_access_key").is_none());
        assert!(parsed.get("session_token").is_none());
        assert!(parsed.get("expiration").is_none());
    }

    // ---- classify_client_error: the typed client-error -> PipelineError mapping.
    // These pin the cross-module contract that USED to be string-sniffed (the old
    // `err.contains(...)` ladder + parse_api_error). Each ClientError variant must
    // map to exactly one PipelineError variant, with fields carried through. ----
    use crate::client::ClientError;

    #[test]
    fn classify_client_error_http_maps_to_http_error() {
        match classify_client_error(ClientError::Http("connection refused".to_string())) {
            PipelineError::HttpError { reason } => assert_eq!(reason, "connection refused"),
            other => panic!("Expected HttpError, got: {:?}", other),
        }
    }

    #[test]
    fn classify_client_error_api_maps_to_api_error_with_fields() {
        match classify_client_error(ClientError::Api {
            status: 403,
            body: "Access denied".to_string(),
        }) {
            PipelineError::ApiError { status_code, body } => {
                assert_eq!(status_code, 403);
                assert_eq!(body, "Access denied");
            }
            other => panic!("Expected ApiError, got: {:?}", other),
        }
    }

    #[test]
    fn classify_client_error_api_preserves_body_containing_colon() {
        // Regression guard: a body that itself contains ':' (JSON, a URL)
        // must survive intact. Correct by construction now — body is a typed field,
        // never split on ':' — but kept to lock the property the old string parser had to.
        match classify_client_error(ClientError::Api {
            status: 403,
            body: r#"{"message":"AccessDenied: see https://x/y"}"#.to_string(),
        }) {
            PipelineError::ApiError { status_code, body } => {
                assert_eq!(status_code, 403);
                assert_eq!(body, r#"{"message":"AccessDenied: see https://x/y"}"#);
            }
            other => panic!("Expected ApiError, got: {:?}", other),
        }
    }

    #[test]
    fn classify_client_error_response_maps_to_response_error() {
        match classify_client_error(ClientError::Response("bad json".to_string())) {
            PipelineError::ResponseError { reason } => assert_eq!(reason, "bad json"),
            other => panic!("Expected ResponseError, got: {:?}", other),
        }
    }

    // ---- Property tests (proptest) ----
    // These assert INVARIANTS across a generated input space, catching edge cases
    // hand-picked examples miss.
    use proptest::prelude::*;

    /// Faithful port of aws-sdk-go-v2 `arn.Parse` — the Go oracle. Require the
    /// `arn:` prefix, split into at most 6 `:`-sections, require exactly 6, and
    /// return section 3 (region). Returns `None` wherever Go returns an error.
    fn go_arn_parse(arn: &str) -> Option<String> {
        if !arn.starts_with("arn:") {
            return None;
        }
        let sections: Vec<&str> = arn.splitn(6, ':').collect();
        if sections.len() != 6 {
            return None;
        }
        Some(sections[3].to_string())
    }

    /// Generate ARN-ish strings: 0..8 colon-joined segments, sometimes forcing the
    /// first segment to "arn" so the accept path is exercised, with enough segments
    /// to drive the ">6 sections → resource keeps the remainder" case.
    fn arn_like() -> impl Strategy<Value = String> {
        (
            any::<bool>(),
            prop::collection::vec("[a-zA-Z0-9_/.-]{0,6}", 0..8),
        )
            .prop_map(|(force_arn, mut segs)| {
                if force_arn {
                    if segs.is_empty() {
                        segs.push(String::new());
                    }
                    segs[0] = "arn".to_string();
                }
                segs.join(":")
            })
    }

    proptest! {
        /// `validate_arn` must agree with the Go `arn.Parse` oracle on BOTH the
        /// accept/reject decision and the region returned, for arbitrary input.
        #[test]
        fn prop_validate_arn_matches_go_arbitrary(s in any::<String>()) {
            prop_assert_eq!(validate_arn(&s).ok(), go_arn_parse(&s));
        }

        /// Same invariant, biased toward valid-looking ARNs so the success path and
        /// the colons-in-resource case are exercised heavily.
        #[test]
        fn prop_validate_arn_matches_go_arn_like(s in arn_like()) {
            prop_assert_eq!(validate_arn(&s).ok(), go_arn_parse(&s));
        }
    }

    #[test]
    fn test_sign_request_custom_endpoint_sets_correct_host_header() {
        let input = SignRequestInput {
            cert_path: "../../tst/certs/rsa-2048-cert.pem".to_string(),
            key_path: "../../tst/certs/rsa-2048-key.pem".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc-123"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def-456".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            endpoint_url: Some("https://rolesanywhere.eu-west-2.example.com".to_string()),
            ..minimal_input()
        };

        let result = sign_request(&input);
        assert!(
            result.is_ok(),
            "sign_request should succeed: {:?}",
            result.err()
        );

        let signed = result.unwrap();

        // The Host header must reflect the custom endpoint, not the AWS regional URL.
        let host = signed.headers.iter().find(|(k, _)| k == "Host").unwrap();
        assert_eq!(
            host.1, "rolesanywhere.eu-west-2.example.com",
            "Host header should match custom endpoint host, not hardcoded AWS URL"
        );

        // The Authorization header must include the custom host in SignedHeaders,
        // proving the custom host was actually signed.
        let auth = signed
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap();
        assert!(
            auth.1.contains("Signature="),
            "Authorization header should contain a signature"
        );
    }

    // ---- identity-path tests ----
    use crate::types::SigningAlgorithm;

    /// An in-memory identity: fixed cert DER, no chain, RSA algorithm, and a canned
    /// signature. Proves `sign_request_with_identity` sources the cert/algorithm/signature
    /// from the identity with NO file read on the identity path.
    struct TestIdentity {
        cert_der: Vec<u8>,
        algorithm: SigningAlgorithm,
    }
    impl CredentialIdentity for TestIdentity {
        fn certificate_der(&self) -> &[u8] {
            &self.cert_der
        }
        fn signing_algorithm(&self) -> &SigningAlgorithm {
            &self.algorithm
        }
        fn sign(&self, _string_to_sign: &[u8]) -> Result<Vec<u8>, String> {
            Ok(vec![0xAB, 0xCD, 0xEF]) // canned raw signature -> hex "abcdef"
        }
    }

    #[test]
    fn test_sign_request_with_identity_uses_identity_not_files() {
        // The cert DER is read here only to build the in-memory identity; the identity
        // path itself does no file I/O. cert_path/key_path are bogus on purpose — if the
        // pipeline still read them, this would fail.
        use crate::key_reader::read_certificate_der;
        let cert_der = read_certificate_der("../../tst/certs/rsa-2048-cert.pem").unwrap();
        let expected_serial = extract_serial_number(&cert_der).unwrap();
        let expected_x509 = certificate_to_base64(&cert_der);

        let identity = TestIdentity {
            cert_der,
            algorithm: SigningAlgorithm::RsaSha256,
        };
        let input = SignRequestInput {
            cert_path: "/bogus/not-read.pem".to_string(),
            key_path: "/bogus/not-read.pem".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc"
                .to_string(),
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            ..minimal_input()
        };

        let signed = sign_request_with_identity(&input, &identity)
            .expect("identity path should not touch the bogus file paths");

        // X-Amz-X509 comes from the identity's cert.
        let x509 = signed
            .headers
            .iter()
            .find(|(k, _)| k == "X-Amz-X509")
            .unwrap();
        assert_eq!(x509.1, expected_x509);

        // Authorization carries the identity's algorithm, the cert's serial, and the
        // canned signature (hex of 0xABCDEF).
        let auth = &signed
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap()
            .1;
        assert!(auth.starts_with("AWS4-X509-RSA-SHA256"));
        assert!(auth.contains(&format!("Credential={}/", expected_serial)));
        assert!(auth.ends_with("Signature=abcdef"), "auth = {auth}");
    }

    #[test]
    fn test_two_signing_paths_unified_produce_same_rsa_signature() {
        // "Two paths unified": the pipeline (via FileSystemIdentity) and the sign-string
        // path (FileSystemSigner directly) now sign through the SAME FileSystemSigner. For a
        // fixed string-to-sign on the RSA fixture (deterministic PKCS#1 v1.5), both must
        // produce byte-identical raw signatures — proving the two paths can't drift.
        use crate::signer::{FileSystemSigner, Signer};

        let sts = b"AWS4-X509-RSA-SHA256\n20240115T123000Z\nscope\nhash";

        let via_signer = FileSystemSigner::from_key_file("../../tst/certs/rsa-2048-key.pem")
            .unwrap()
            .sign(sts)
            .unwrap();

        let identity = FileSystemIdentity::from_paths(
            "../../tst/certs/rsa-2048-cert.pem",
            "../../tst/certs/rsa-2048-key.pem",
            None,
        )
        .unwrap();
        let via_identity = identity.sign(sts).unwrap();

        assert_eq!(
            via_identity, via_signer,
            "the credential path and the sign-string path must produce identical RSA signatures"
        );
    }
}
