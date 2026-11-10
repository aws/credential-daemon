//! Wire protocol for the daemon's Unix-domain-socket API.
//!
//! Line-delimited JSON-RPC 2.0: exactly one compact JSON object per line,
//! terminated by `\n`. A client needs nothing beyond `UnixStream`, `BufReader`,
//! and `serde_json`:
//!
//! ```text
//! → {"jsonrpc":"2.0","id":1,"method":"credential/get","params":{"profile":"dev"}}
//! ← {"jsonrpc":"2.0","id":1,"result":{"credential":"login","material":{"type":"session_credentials",…},…}}
//! ```
//!
//! This module holds the envelope; [`methods`] holds the method surface and is
//! re-exported here, so every type is reachable as `crate::rpc::*`.
//!
//! JSON-RPC batches (a top-level array) and notifications (a request without
//! `id`) are not part of this protocol. Retrieving every credential a profile
//! names in one all-or-none call is [`METHOD_CREDENTIAL_GET_BATCH`], a domain
//! method — which is exactly why the transport-level batch is not needed.
//!
//! # Classifying a failure
//!
//! The numeric `error.code` is reserved for *envelope*-level failures: the five
//! standard JSON-RPC codes and nothing else. Every *domain* failure carries
//! [`CODE_APPLICATION`] and puts its real discriminator in `data.code` as a
//! [`DomainCode`] string. So a caller reads exactly one field to classify —
//! numeric code for "did my message make sense", `data.code` for "what went
//! wrong" — never a layered combination of the two.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

pub mod codec;
pub mod methods;
#[cfg(unix)]
pub mod uds;

pub use methods::{
    AccountInfo, BootstrapRespondParams, Claim, ConfigGetParams, ConfigGetResult, ConfigSetParams,
    ConfigUnsetParams, CredentialEntry, CredentialRemoveParams, CredentialResult,
    CredentialSourceType, CredentialSummary, CredentialType, DescribeParams, EnvRemoveParams,
    GetBatchParams, GetBatchResult, GetParams, HealthResult, ImportOutcome, ImportParams,
    ImportProfile, ImportResult, ImportStatus, ListParams, ListResult, Material, OkResult,
    ProfileBootstrapParams, ProfileLoginParams, ProfileManifest, ProgressParams, Projection,
    Provenance, ProviderParams, ProviderParamsAwsLogin, ProviderParamsAwsWebIdentity,
    ProviderParamsIamUser, ProviderParamsJwt, ProviderParamsJwtBearer, ProviderParamsOauth,
    ProviderParamsRa, ProviderParamsSso, ProviderParamsStaticSecret, RevalidateParams, Scope,
    SessionStatus, METHOD_CONFIG_GET, METHOD_CONFIG_SET, METHOD_CONFIG_UNSET,
    METHOD_CREDENTIAL_GET, METHOD_CREDENTIAL_GET_BATCH, METHOD_CREDENTIAL_LIST,
    METHOD_CREDENTIAL_REMOVE, METHOD_ENV_REMOVE, METHOD_FILE_REVALIDATE, METHOD_PROFILE_BOOTSTRAP,
    METHOD_PROFILE_BOOTSTRAP_RESPOND, METHOD_PROFILE_DESCRIBE, METHOD_PROFILE_IMPORT,
    METHOD_PROFILE_LOGIN, METHOD_SYSTEM_HEALTH, NOTIFICATION_PROGRESS,
};

/// Wire protocol revision, reported by `system/health`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Malformed JSON, or a line over [`codec::MAX_LINE_LEN`].
pub const CODE_PARSE_ERROR: i32 = -32700;
/// Well-formed JSON that is not a valid request envelope.
pub const CODE_INVALID_REQUEST: i32 = -32600;
pub const CODE_METHOD_NOT_FOUND: i32 = -32601;
/// A message shape or a params object this API does not accept.
pub const CODE_INVALID_PARAMS: i32 = -32602;
pub const CODE_INTERNAL_ERROR: i32 = -32603;
/// The only code any domain failure ever uses; see [`DomainCode`].
pub const CODE_APPLICATION: i32 = -32000;

/// The `jsonrpc` member. Modelled as a one-variant enum so `"2.0"` is the only
/// value that deserializes and the only value that can be constructed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    #[default]
    #[serde(rename = "2.0")]
    V2,
}

/// A request identifier, echoed back verbatim on the response.
///
/// `Number` and `String` are the two valid forms for incoming request ids; `Null` is
/// used exclusively on outgoing error responses when the request id could not be
/// determined (JSON-RPC 2.0 §5). Incoming `null` ids are rejected by the custom
/// `Deserialize` impl so servers never echo a null id back as if it were meaningful.
/// [`Number`] rather than an integer keeps the caller's exact numeric form so the
/// echo is byte-faithful. With `untagged`, `Null` serializes as JSON `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Id {
    Number(Number),
    String(String),
    Null,
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::Number(n) => Ok(Id::Number(n)),
            serde_json::Value::String(s) => Ok(Id::String(s)),
            serde_json::Value::Null => Err(D::Error::custom("request id must not be null")),
            _ => Err(D::Error::custom("request id must be a number or string")),
        }
    }
}

impl From<i64> for Id {
    fn from(n: i64) -> Self {
        Self::Number(Number::from(n))
    }
}

impl From<String> for Id {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for Id {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

/// A request envelope. `params`, when present, is always a JSON object; the
/// by-position (array) form of JSON-RPC params is not supported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: Version,
    pub id: Id,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Map<String, Value>>,
}

impl Request {
    pub fn new(id: Id, method: impl Into<String>) -> Self {
        Self {
            jsonrpc: Version::V2,
            id,
            method: method.into(),
            params: None,
        }
    }

    /// Build a request whose `params` is the serialized form of `params`.
    ///
    /// Fails if `params` does not serialize to a JSON object.
    pub fn with_params<P: Serialize>(
        id: Id,
        method: impl Into<String>,
        params: &P,
    ) -> Result<Self, RpcError> {
        let value = serde_json::to_value(params)
            .map_err(|e| RpcError::internal(format!("params are not serializable: {e}")))?;
        match value {
            Value::Object(map) => Ok(Self {
                jsonrpc: Version::V2,
                id,
                method: method.into(),
                params: Some(map),
            }),
            _ => Err(RpcError::internal("params must serialize to a JSON object")),
        }
    }

    /// Deserialize `params` into a method's parameter type. Absent params are
    /// treated as an empty object, so a type whose every field is optional
    /// accepts them and one with a required field rejects them.
    pub fn params_as<T: DeserializeOwned>(&self) -> Result<T, RpcError> {
        let value = match &self.params {
            Some(params) => Value::Object(params.clone()),
            None => Value::Object(Map::new()),
        };
        serde_json::from_value(value).map_err(|e| RpcError::invalid_params(e.to_string()))
    }
}

/// A response envelope. `result` and `error` are mutually exclusive by
/// construction — [`Outcome`] is one or the other, never both and never neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Response<T> {
    pub jsonrpc: Version,
    pub id: Id,
    #[serde(flatten)]
    pub outcome: Outcome<T>,
}

/// Hand-written because the derived form (a flattened externally tagged enum)
/// would accept a message carrying *both* members and silently keep `result`.
/// The exclusivity has to hold on the wire, not just in the Rust type.
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Response<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire<T> {
            jsonrpc: Version,
            id: Id,
            #[serde(default = "Option::default")]
            result: Option<T>,
            #[serde(default)]
            error: Option<RpcError>,
        }

        let wire = Wire::<T>::deserialize(deserializer)?;
        let outcome = match (wire.result, wire.error) {
            (Some(result), None) => Outcome::Result(result),
            (None, Some(error)) => Outcome::Error(error),
            (Some(_), Some(_)) => {
                return Err(serde::de::Error::custom(
                    "response carries both result and error",
                ))
            }
            (None, None) => {
                return Err(serde::de::Error::custom(
                    "response carries neither result nor error",
                ))
            }
        };
        Ok(Self {
            jsonrpc: wire.jsonrpc,
            id: wire.id,
            outcome,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome<T> {
    Result(T),
    Error(RpcError),
}

impl<T> Response<T> {
    pub fn success(id: Id, result: T) -> Self {
        Self {
            jsonrpc: Version::V2,
            id,
            outcome: Outcome::Result(result),
        }
    }

    pub fn failure(id: Id, error: RpcError) -> Self {
        Self {
            jsonrpc: Version::V2,
            id,
            outcome: Outcome::Error(error),
        }
    }
}

/// The `error` member of a failed response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message} (code {code})")]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Map<String, Value>>,
}

/// Discriminator for a domain failure, carried as `data.code`. Never expressed
/// as a numeric `code`.
///
/// Every variant here is spelled *without* an `ERR_` prefix, and that is a rule
/// rather than a style choice: in this codebase an `ERR_`-prefixed name is a
/// numeric envelope code (`src/mcp/protocol.rs`'s `ERR_INVALID_PARAMS` is
/// `-32602`), while an unprefixed one is a domain string. A prefixed domain code
/// would read as an envelope code to anyone who greps for it, so domain codes
/// this API adds must stay unprefixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DomainCode {
    EnvironmentNotFound,
    ReauthRequired,
    /// The credential exists and is usable, but its kind cannot be projected onto
    /// the requested shape — an `access_token` asked for as session credentials.
    /// The spelling is carried over verbatim from the HTTP surface
    /// (`src/server/routes.rs:166`), not coined here, so the port does not silently
    /// rename a code a caller may already branch on.
    WrongCredentialType,
    ProviderUnavailable,
    Internal,
    /// The caller's `config.toml` or `credentials.toml` has drifted from its sealed snapshot.
    /// Credential operations are blocked. Run `creds revalidate` after verifying the contents;
    /// a file that does not parse is corrected or restored first (`drift-detection` 2.10).
    ConfigDrifted,
    /// The caller's integrity record cannot be opened, so neither file can be verified
    /// (`drift-detection` Requirement 10.6). Run `creds revalidate`: its approval shows both files
    /// in full, discloses that there is no record to compare them against, and replaces the record.
    IntegrityUnverifiable,
    /// Custody of the integrity record or the enrolled-key registry is broken (`drift-detection`
    /// Requirements 10.8-10.10). Nothing they govern is served, written, or approved until an
    /// operator restores ownership and modes and restarts the daemon. No client action remedies it.
    CustodyBroken,
    /// The SSO device-authorization poll window (5 minutes) expired before the user
    /// completed sign-in. Distinct from a transient network failure (`Internal`) so a
    /// client can prompt "timed out — run bootstrap again" rather than "internal error".
    AuthTimeout,
    /// The interactive bootstrap was cancelled before completion (e.g. the client closed
    /// the connection while waiting for account/role selection).
    AuthCancelled,
    /// A gated operation was not performed; `data.challenge` names what would approve it
    /// (`presence-gated-operations` Requirement 8.1). An error rather than a result, so a client
    /// that does not recognise it observes a failure instead of a completed operation.
    ApprovalRequired,
    /// `request/approve` did not satisfy the challenge; `data.reason` says why
    /// (`presence-gated-operations` Requirement 8.2). Never reported as invalid parameters.
    ApprovalRefused,
    /// No pending request by that identifier is visible to this caller. Unknown, discarded, and
    /// another uid's request are indistinguishable on the wire (Requirement 8.4).
    RequestNotFound,
    /// A domain code not recognised by this version.
    #[serde(other)]
    Unknown,
}

/// A JSON-RPC 2.0 notification (no `id` field): used for streaming progress during
/// long-running daemon-side operations (SSO device-code flow, account/role selection).
///
/// Notifications are valid JSON-RPC 2.0 and are distinguished from responses by the
/// absence of `id`. The client reads lines until it sees a line with its request `id`;
/// all lines without `id` are notifications handled in-line.
#[derive(Serialize)]
pub struct Notification<P: Serialize> {
    pub jsonrpc: Version,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<P>,
}

impl<P: Serialize> Notification<P> {
    pub fn new(method: impl Into<String>, params: P) -> Self {
        Self {
            jsonrpc: Version::V2,
            method: method.into(),
            params: Some(params),
        }
    }
}

impl RpcError {
    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::envelope(CODE_PARSE_ERROR, message)
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::envelope(CODE_INVALID_REQUEST, message)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::envelope(CODE_METHOD_NOT_FOUND, format!("unknown method: {method}"))
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::envelope(CODE_INVALID_PARAMS, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::envelope(CODE_INTERNAL_ERROR, message)
    }

    fn envelope(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// A domain failure: [`CODE_APPLICATION`] with `code` in `data`.
    pub fn domain(code: DomainCode, message: impl Into<String>) -> Self {
        let mut data = Map::new();
        data.insert("code".into(), json_string(code));
        Self {
            code: CODE_APPLICATION,
            message: message.into(),
            data: Some(data),
        }
    }

    /// The one domain failure with required extra context: which profile needs
    /// re-authentication and what the operator should run.
    pub fn reauth_required(
        environment: impl Into<String>,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let mut error = Self::domain(DomainCode::ReauthRequired, message);
        if let Some(data) = error.data.as_mut() {
            data.insert("environment".into(), Value::String(environment.into()));
            data.insert("remediation".into(), Value::String(remediation.into()));
        }
        error
    }

    /// A gated operation waiting on `challenge`. Remediation is the daemon's, so a client
    /// presents it rather than composing its own (Requirement 8.6).
    pub fn approval_required(
        challenge: &crate::presence::Challenge,
        remediation: impl Into<String>,
    ) -> Self {
        let mut error = Self::domain(
            DomainCode::ApprovalRequired,
            format!("approval required: {}", challenge.description),
        );
        if let Some(data) = error.data.as_mut() {
            data.insert(
                "challenge".into(),
                serde_json::to_value(challenge).unwrap_or(Value::Null),
            );
            data.insert("remediation".into(), Value::String(remediation.into()));
        }
        error
    }

    /// `request/approve` refused for `reason`, with the daemon's remediation (Requirement 8.6).
    pub fn approval_refused(
        reason: crate::presence::RefusalReason,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let mut error = Self::domain(DomainCode::ApprovalRefused, message);
        if let Some(data) = error.data.as_mut() {
            data.insert(
                "reason".into(),
                serde_json::to_value(reason).unwrap_or(Value::Null),
            );
            data.insert("remediation".into(), Value::String(remediation.into()));
        }
        error
    }

    /// One message for every not-found case, so they stay indistinguishable (Requirement 8.4).
    pub fn request_not_found() -> Self {
        Self::domain(DomainCode::RequestNotFound, "no such pending request")
    }

    /// The reason an `APPROVAL_REFUSED` error carries.
    pub fn refusal_reason(&self) -> Option<crate::presence::RefusalReason> {
        let value = self.data.as_ref()?.get("reason")?;
        serde_json::from_value(value.clone()).ok()
    }

    /// The daemon-supplied remediation, where the error carries one.
    pub fn remediation(&self) -> Option<String> {
        self.data
            .as_ref()?
            .get("remediation")?
            .as_str()
            .map(str::to_owned)
    }

    /// The challenge an `APPROVAL_REQUIRED` error carries.
    pub fn challenge(&self) -> Option<crate::presence::Challenge> {
        let value = self.data.as_ref()?.get("challenge")?;
        serde_json::from_value(value.clone()).ok()
    }

    /// The domain discriminator, or `None` for an envelope-level failure. The
    /// single field a caller reads to classify a failure.
    pub fn domain_code(&self) -> Option<DomainCode> {
        let value = self.data.as_ref()?.get("code")?;
        serde_json::from_value(value.clone()).ok()
    }
}

fn json_string(code: DomainCode) -> Value {
    serde_json::to_value(code).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::codec::decode_request;

    fn line(json: &str) -> Vec<u8> {
        format!("{json}\n").into_bytes()
    }

    #[test]
    fn version_serializes_as_two_point_zero() {
        let encoded = serde_json::to_string(&Version::V2).expect("serialize");
        assert_eq!(encoded, "\"2.0\"");
    }

    #[test]
    fn foreign_jsonrpc_versions_are_invalid_requests() {
        for version in ["\"1.0\"", "\"2\"", "\"2.00\"", "2.0", "null", "\"2.0 \""] {
            let bytes = line(&format!(
                "{{\"jsonrpc\":{version},\"id\":1,\"method\":\"system/health\"}}"
            ));
            let err = decode_request(&bytes).expect_err("must reject jsonrpc {version}");
            assert_eq!(err.code, CODE_INVALID_REQUEST, "jsonrpc {version}");
        }
    }

    #[test]
    fn missing_jsonrpc_member_is_an_invalid_request() {
        let err = decode_request(&line("{\"id\":1,\"method\":\"system/health\"}"))
            .expect_err("must reject");
        assert_eq!(err.code, CODE_INVALID_REQUEST);
    }

    #[test]
    fn id_accepts_numbers_and_strings_rejects_null_and_others() {
        for id in ["1", "-7", "0.5", "\"abc\""] {
            let bytes = line(&format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"system/health\"}}"
            ));
            decode_request(&bytes).unwrap_or_else(|e| panic!("id {id} must decode: {e}"));
        }
        // null is rejected on incoming request ids (JSON-RPC 2.0 §5 only allows null on
        // outgoing error responses when the request id could not be determined).
        for id in ["null", "[1]", "{}", "true"] {
            let bytes = line(&format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"system/health\"}}"
            ));
            assert!(decode_request(&bytes).is_err(), "id {id} must be rejected");
        }
    }

    #[test]
    fn null_id_serializes_for_parse_error_response() {
        let err: Response<HealthResult> =
            Response::failure(Id::Null, RpcError::parse_error("bad json"));
        let encoded = serde_json::to_string(&err).expect("serialize");
        assert!(
            encoded.contains("\"id\":null"),
            "parse-error response must carry null id: {encoded}"
        );
    }

    #[test]
    fn id_is_echoed_verbatim() {
        let bytes = line("{\"jsonrpc\":\"2.0\",\"id\":18446744073709551615,\"method\":\"x\"}");
        let request = decode_request(&bytes).expect("decode");
        let response: Response<HealthResult> =
            Response::success(request.id, HealthResult::default());
        let encoded = serde_json::to_string(&response).expect("serialize");
        assert!(encoded.contains("\"id\":18446744073709551615"), "{encoded}");
    }

    #[test]
    fn params_must_be_an_object() {
        let bytes = line("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":[\"dev\"]}");
        let err = decode_request(&bytes).expect_err("positional params must be rejected");
        assert_eq!(err.code, CODE_INVALID_REQUEST);
    }

    #[test]
    fn success_and_error_responses_have_the_expected_shape() {
        let ok = Response::success(Id::from(1), HealthResult::default());
        let encoded = serde_json::to_string(&ok).expect("serialize");
        assert!(
            encoded.starts_with("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"),
            "{encoded}"
        );
        assert!(!encoded.contains("\"error\""));

        let err: Response<HealthResult> =
            Response::failure(Id::from("a"), RpcError::method_not_found("nope"));
        let encoded = serde_json::to_string(&err).expect("serialize");
        assert!(
            encoded.starts_with("{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"error\":{"),
            "{encoded}"
        );
        assert!(!encoded.contains("\"result\""));
    }

    #[test]
    fn a_response_with_both_result_and_error_does_not_decode() {
        let bytes = line(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocol\":1,\"version\":\"0\"},\"error\":{\"code\":-32000,\"message\":\"x\"}}",
        );
        assert!(codec::decode_response::<HealthResult>(&bytes).is_err());
    }

    #[test]
    fn a_response_with_neither_result_nor_error_does_not_decode() {
        let bytes = line("{\"jsonrpc\":\"2.0\",\"id\":1}");
        assert!(codec::decode_response::<HealthResult>(&bytes).is_err());
    }

    #[test]
    fn domain_errors_carry_the_string_code_and_the_application_number() {
        for (code, wire) in [
            (DomainCode::EnvironmentNotFound, "ENVIRONMENT_NOT_FOUND"),
            (DomainCode::ReauthRequired, "REAUTH_REQUIRED"),
            // Byte-identical to the HTTP surface's spelling (`server/routes.rs:166`,
            // `:214`, `:249`), so the transport port does not rename a code a caller
            // already branches on.
            (DomainCode::WrongCredentialType, "WRONG_CREDENTIAL_TYPE"),
            (DomainCode::ProviderUnavailable, "PROVIDER_UNAVAILABLE"),
            (DomainCode::Internal, "INTERNAL"),
            (DomainCode::AuthTimeout, "AUTH_TIMEOUT"),
            (DomainCode::AuthCancelled, "AUTH_CANCELLED"),
        ] {
            let error = RpcError::domain(code, "boom");
            assert_eq!(error.code, CODE_APPLICATION);
            let data = error.data.as_ref().expect("data");
            assert_eq!(data.get("code"), Some(&Value::String(wire.into())));
            assert_eq!(error.domain_code(), Some(code));

            let encoded = serde_json::to_string(&error).expect("serialize");
            assert!(
                encoded.contains(&format!("\"code\":\"{wire}\"")),
                "{encoded}"
            );
            // The prefix rule, asserted rather than left to the doc comment: an
            // `ERR_`-prefixed name in this codebase is a numeric envelope code.
            assert!(!wire.starts_with("ERR_"), "{wire}");
        }
    }

    #[test]
    fn reauth_required_carries_profile_and_remediation() {
        let error = RpcError::reauth_required("dev", "session expired", "credsd login dev");
        assert_eq!(error.code, CODE_APPLICATION);
        assert_eq!(error.domain_code(), Some(DomainCode::ReauthRequired));
        let data = error.data.as_ref().expect("data");
        assert_eq!(data.get("environment"), Some(&Value::String("dev".into())));
        assert_eq!(
            data.get("remediation"),
            Some(&Value::String("credsd login dev".into()))
        );
    }

    #[test]
    fn envelope_errors_use_standard_codes_and_carry_no_domain_code() {
        for (error, code) in [
            (RpcError::parse_error("x"), CODE_PARSE_ERROR),
            (RpcError::invalid_request("x"), CODE_INVALID_REQUEST),
            (RpcError::method_not_found("x"), CODE_METHOD_NOT_FOUND),
            (RpcError::invalid_params("x"), CODE_INVALID_PARAMS),
            (RpcError::internal("x"), CODE_INTERNAL_ERROR),
        ] {
            assert_eq!(error.code, code);
            assert_eq!(error.data, None);
            assert_eq!(error.domain_code(), None);
        }
    }

    #[test]
    fn with_params_rejects_non_object_params() {
        let err = Request::with_params(Id::from(1), METHOD_SYSTEM_HEALTH, &vec!["dev"])
            .expect_err("array params must be rejected");
        assert_eq!(err.code, CODE_INTERNAL_ERROR);
    }
}
