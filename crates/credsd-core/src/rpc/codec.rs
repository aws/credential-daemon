//! Framing for the line-delimited protocol: pure functions over bytes.
//!
//! One message is one compact JSON object plus a single `\n`. Nothing here
//! reads, writes, or awaits — a transport supplies the bytes.

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use super::{Notification, Request, Response, RpcError};
use crate::error::{DaemonError, Result};

/// Largest framed line accepted on decode, terminator included. Bounds the
/// buffer a transport must hold for one message, so a peer that never sends a
/// newline cannot drive it to grow without limit.
pub const MAX_LINE_LEN: usize = 1024 * 1024;

pub fn encode_request(request: &Request) -> Result<Vec<u8>> {
    encode(request)
}

pub fn encode_response<T: Serialize>(response: &Response<T>) -> Result<Vec<u8>> {
    encode(response)
}

/// Encode a notification (a message without `id`) into a framed line.
///
/// Notifications are the daemon's mechanism for streaming progress during long-running
/// operations (SSO device-code flow, account/role selection). They are valid JSON-RPC 2.0
/// and are distinguished from responses by the absence of `id`.
pub fn encode_notification<P: Serialize>(notification: &Notification<P>) -> Result<Vec<u8>> {
    encode(notification)
}

fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(message).map_err(DaemonError::from)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decode one framed line into a request. The trailing `\n` (or `\r\n`) is
/// optional, so a caller may pass a line with or without its terminator.
pub fn decode_request(line: &[u8]) -> std::result::Result<Request, RpcError> {
    decode(line)
}

pub fn decode_response<T: DeserializeOwned>(
    line: &[u8],
) -> std::result::Result<Response<T>, RpcError> {
    decode(line)
}

/// Two-stage on purpose: JSON that does not parse is `-32700`, JSON that parses
/// but is not a valid envelope is `-32600`. A single `from_slice` would collapse
/// the two into one code.
fn decode<T: DeserializeOwned>(line: &[u8]) -> std::result::Result<T, RpcError> {
    if line.len() > MAX_LINE_LEN {
        return Err(RpcError::parse_error(format!(
            "line exceeds {MAX_LINE_LEN} bytes"
        )));
    }
    let value: Value = serde_json::from_slice(trim_terminator(line))
        .map_err(|e| RpcError::parse_error(e.to_string()))?;
    // Numeric, not a domain code: a top-level array is a message shape the
    // envelope layer does not accept, so no domain operation is ever identified
    // and nothing domain-level is being refused. Keeping it numeric is also what
    // keeps this module free of domain vocabulary. The message names the domain
    // method that does the grouping, because a caller reaching for a batch wants
    // that and JSON-RPC's per-element semantics are what it must not get.
    if value.is_array() {
        return Err(RpcError::invalid_params(
            "JSON-RPC batches are not supported; use credential/get_batch",
        ));
    }
    serde_json::from_value(value).map_err(|e| RpcError::invalid_request(e.to_string()))
}

fn trim_terminator(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{
        Claim, CredentialEntry, CredentialResult, CredentialSourceType, CredentialSummary,
        CredentialType, DomainCode, GetBatchParams, GetBatchResult, GetParams, HealthResult, Id,
        ListResult, Material, Outcome, ProfileManifest, Projection, Provenance, Scope,
        SessionStatus, Version, CODE_INVALID_PARAMS, CODE_PARSE_ERROR, METHOD_CREDENTIAL_GET,
        METHOD_CREDENTIAL_GET_BATCH,
    };
    use chrono::{DateTime, Utc};
    use proptest::prelude::*;
    use serde_json::{Map, Number, Value};

    fn request_line(params_body: &str) -> Vec<u8> {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{METHOD_CREDENTIAL_GET}\",\"params\":{{\"profile\":\"{params_body}\"}}}}\n"
        )
        .into_bytes()
    }

    fn atomic_params(environment: &str) -> GetParams {
        GetParams {
            environment: environment.into(),
            credential: None,
            scope: None,
            claim: None,
            request_id: None,
        }
    }

    #[test]
    fn encoded_lines_end_in_exactly_one_newline() {
        let request = Request::with_params(
            Id::from("abc"),
            METHOD_CREDENTIAL_GET,
            &GetParams {
                claim: Some(Claim::Agentic),
                ..atomic_params("line\nbreak")
            },
        )
        .expect("object params");
        let line = encode_request(&request).expect("encode");
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
    }

    #[test]
    fn a_line_at_the_limit_decodes_and_one_byte_over_is_a_parse_error() {
        let overhead = request_line("").len();
        let at_limit = request_line(&"A".repeat(MAX_LINE_LEN - overhead));
        assert_eq!(at_limit.len(), MAX_LINE_LEN);
        decode_request(&at_limit).expect("a line at the limit must decode");

        let over_limit = request_line(&"A".repeat(MAX_LINE_LEN - overhead + 1));
        assert_eq!(over_limit.len(), MAX_LINE_LEN + 1);
        let err = decode_request(&over_limit).expect_err("one byte over must fail");
        assert_eq!(err.code, CODE_PARSE_ERROR);
    }

    #[test]
    fn the_limit_is_enforced_before_parsing() {
        let mut garbage = vec![b'{'; MAX_LINE_LEN + 1];
        garbage.push(b'\n');
        let err = decode_request(&garbage).expect_err("oversized input must fail");
        assert_eq!(err.code, CODE_PARSE_ERROR);
        assert!(err.message.contains("exceeds"), "{}", err.message);
    }

    #[test]
    fn a_top_level_array_is_an_envelope_failure_not_a_domain_one() {
        for batch in [
            "[]",
            "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system/health\"}]",
            "  [{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system/health\"}]  ",
        ] {
            let err = decode_request(format!("{batch}\n").as_bytes())
                .expect_err("batches are not supported");
            assert_eq!(err.code, CODE_INVALID_PARAMS, "{batch}");
            assert_eq!(
                err.domain_code(),
                None,
                "a batch is refused before any domain operation is identified: {batch}"
            );
            assert!(
                err.message.contains("credential/get_batch"),
                "{}",
                err.message
            );
        }
        let err = decode_response::<HealthResult>(b"[]\n").expect_err("batches are not supported");
        assert_eq!(err.code, CODE_INVALID_PARAMS);
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        for bad in ["", "\n", "{", "{oops}\n", "not json\n", "{}{}\n"] {
            let err = decode_request(bad.as_bytes()).expect_err("must not decode");
            assert_eq!(err.code, CODE_PARSE_ERROR, "{bad:?}");
        }
    }

    #[test]
    fn the_terminator_is_optional_and_crlf_is_tolerated() {
        let body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system/health\"}";
        for line in [body.to_owned(), format!("{body}\n"), format!("{body}\r\n")] {
            decode_request(line.as_bytes()).unwrap_or_else(|e| panic!("{line:?}: {e}"));
        }
    }

    fn id_strategy() -> impl Strategy<Value = Id> {
        prop_oneof![
            any::<i64>().prop_map(Id::from),
            any::<u64>().prop_map(|n| Id::Number(Number::from(n))),
            any::<String>().prop_map(Id::from),
        ]
    }

    fn params_strategy() -> impl Strategy<Value = Option<Map<String, Value>>> {
        proptest::option::of(
            prop::collection::vec((any::<String>(), any::<String>()), 0..4).prop_map(|pairs| {
                pairs
                    .into_iter()
                    .map(|(key, value)| (key, Value::String(value)))
                    .collect::<Map<String, Value>>()
            }),
        )
    }

    fn error_strategy() -> impl Strategy<Value = RpcError> {
        prop_oneof![
            (any::<i32>(), any::<String>()).prop_map(|(code, message)| RpcError {
                code,
                message,
                data: None
            }),
            (any::<String>(), any::<String>(), any::<String>()).prop_map(
                |(environment, message, remediation)| RpcError::reauth_required(
                    environment,
                    message,
                    remediation
                )
            ),
            any::<String>().prop_map(|message| RpcError::domain(DomainCode::Internal, message)),
        ]
    }

    /// Includes `None`, which the wire carries as an explicit `null`: a credential with no
    /// issuer-stated lifetime is a representable response, so the round trip has to survive
    /// it. Weighted toward a stated expiry because that is the common case, but `None` is
    /// generated often enough to fail a codec that drops or defaults the field.
    fn expiry_strategy() -> impl Strategy<Value = Option<DateTime<Utc>>> {
        prop_oneof![
            4 => (0i64..4_000_000_000).prop_map(|secs| Some(
                DateTime::from_timestamp(secs, 0).expect("timestamp within range")
            )),
            1 => Just(None),
        ]
    }

    /// Only names that satisfy `validate_name`: an arbitrary `String` no longer
    /// survives a round trip through params, which is the point of validating at
    /// deserialize time.
    fn name_strategy() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_-][a-zA-Z0-9._-]{0,63}"
    }

    proptest! {
        #[test]
        fn request_envelopes_round_trip(
            id in id_strategy(),
            method in any::<String>(),
            params in params_strategy(),
        ) {
            let request = Request { jsonrpc: Version::V2, id, method, params };
            let line = encode_request(&request).expect("encode");
            prop_assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
            let decoded = decode_request(&line).expect("decode");
            prop_assert_eq!(decoded, request);
        }

        #[test]
        fn success_response_envelopes_round_trip(id in id_strategy(), version in any::<String>()) {
            let response = Response::success(id, HealthResult { protocol: 1, version });
            let line = encode_response(&response).expect("encode");
            let decoded: Response<HealthResult> = decode_response(&line).expect("decode");
            prop_assert_eq!(decoded, response);
        }

        #[test]
        fn error_response_envelopes_round_trip(id in id_strategy(), error in error_strategy()) {
            let response: Response<HealthResult> = Response::failure(id, error);
            let line = encode_response(&response).expect("encode");
            let decoded: Response<HealthResult> = decode_response(&line).expect("decode");
            prop_assert_eq!(decoded, response);
        }

        // Compares re-encoded bytes rather than values: `CredentialResult` holds
        // live secrets and deliberately implements neither `PartialEq` nor a
        // revealing `Debug`.
        #[test]
        fn credential_results_round_trip(
            credential in name_strategy(),
            access_key_id in any::<String>(),
            secret_access_key in any::<String>(),
            session_token in any::<String>(),
            expires_at in expiry_strategy(),
            provenance in prop_oneof![
                Just(Provenance::CachedShared),
                Just(Provenance::MintedForRequest),
            ],
        ) {
            let result = CredentialResult {
                credential,
                material: Material::SessionCredentials {
                    access_key_id,
                    secret_access_key,
                    session_token,
                },
                expires_at,
                provenance,
            };
            let response = Response::success(Id::from(1), result);
            let line = encode_response(&response).expect("encode");
            let decoded: Response<CredentialResult> = decode_response(&line).expect("decode");
            match &decoded.outcome {
                Outcome::Result(_) => {}
                Outcome::Error(e) => prop_assert!(false, "decoded as error: {}", e),
            }
            prop_assert_eq!(encode_response(&decoded).expect("re-encode"), line);
        }

        #[test]
        fn batch_results_round_trip(
            credentials in prop::collection::vec(name_strategy(), 1..4),
            expires_at in expiry_strategy(),
        ) {
            let result = GetBatchResult {
                credentials: credentials.into_iter().map(|credential| CredentialResult {
                    credential,
                    material: Material::SessionCredentials {
                        access_key_id: "AKIA".into(),
                        secret_access_key: "secret".into(),
                        session_token: "token".into(),
                    },
                    expires_at,
                    provenance: Provenance::MintedForRequest,
                }).collect(),
            };
            let response = Response::success(Id::from(1), result);
            let line = encode_response(&response).expect("encode");
            let decoded: Response<GetBatchResult> = decode_response(&line).expect("decode");
            prop_assert_eq!(encode_response(&decoded).expect("re-encode"), line);
        }

        #[test]
        fn get_params_round_trip(
            environment in name_strategy(),
            credential in proptest::option::of(name_strategy()),
            scope in proptest::option::of(any::<String>().prop_map(|s| Scope(Value::String(s)))),
            claim in proptest::option::of(Just(Claim::Agentic)),
            request_id in proptest::option::of(any::<String>()),
        ) {
            let params = GetParams { environment, credential, scope, claim, request_id };
            let request = Request::with_params(Id::from(1), METHOD_CREDENTIAL_GET, &params)
                .expect("object params");
            let line = encode_request(&request).expect("encode");
            let decoded = decode_request(&line).expect("decode");
            prop_assert_eq!(decoded.params_as::<GetParams>().expect("params"), params);
        }

        #[test]
        fn batch_params_round_trip(environment in name_strategy()) {
            let params = GetBatchParams {
                environment,
                scope: None,
                claim: Some(Claim::Agentic),
                request_id: None,
            };
            let request = Request::with_params(Id::from(1), METHOD_CREDENTIAL_GET_BATCH, &params)
                .expect("object params");
            let line = encode_request(&request).expect("encode");
            let decoded = decode_request(&line).expect("decode");
            prop_assert_eq!(decoded.params_as::<GetBatchParams>().expect("params"), params);
        }

        #[test]
        fn manifests_round_trip(environment in name_strategy(), credential in name_strategy()) {
            let result = ProfileManifest {
                environment,
                credentials: vec![CredentialEntry {
                    projection: None,
                    credential,
                    kind: CredentialType::SessionCredentials,
                    source: CredentialSourceType::AwsIamUser,
                    env_var: None,
                    status: SessionStatus::NoSession,
                    default: true,
                }],
                projection: Projection {
                    projections: Default::default(),
                    region: Some("eu-central-1".into()),
                    sdk: Some(crate::config::SdkSettings {
                        retry_mode: Some("adaptive".into()),
                        max_attempts: Some(5),
                        ..Default::default()
                    }),
                    cli: None,
                },
            };
            let response = Response::success(Id::from(1), result);
            let line = encode_response(&response).expect("encode");
            let decoded: Response<ProfileManifest> = decode_response(&line).expect("decode");
            prop_assert_eq!(decoded, response);
        }

        #[test]
        fn enumerations_round_trip(environment in name_strategy(), credential in name_strategy()) {
            let result = ListResult {
                credentials: vec![CredentialSummary {
                    environment,
                    credential,
                    kind: CredentialType::AccessToken,
                    status: SessionStatus::Expiring,
                }],
            };
            let response = Response::success(Id::from(1), result);
            let line = encode_response(&response).expect("encode");
            let decoded: Response<ListResult> = decode_response(&line).expect("decode");
            prop_assert_eq!(decoded, response);
        }
    }
}
