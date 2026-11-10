use serde::Deserialize;
use std::fmt;
use std::io::Read;

const MAX_BODY_BYTES: usize = 64 * 1024;

fn read_bounded(response: reqwest::blocking::Response) -> Result<String, ClientError> {
    if let Some(len) = response.content_length() {
        if len > MAX_BODY_BYTES as u64 {
            return Err(ClientError::Response(format!(
                "response advertised {len} bytes; cap is {MAX_BODY_BYTES}"
            )));
        }
    }
    let mut buf = Vec::new();
    response
        .take(MAX_BODY_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| ClientError::Response(format!("reading response body: {e}")))?;
    if buf.len() > MAX_BODY_BYTES {
        return Err(ClientError::Response(format!(
            "response exceeded {MAX_BODY_BYTES} bytes"
        )));
    }
    String::from_utf8(buf)
        .map_err(|e| ClientError::Response(format!("response was not UTF-8: {e}")))
}

/// Error from a CreateSession HTTP call. Typed so the caller classifies by
/// `match`, not by sniffing message text.
#[derive(Debug)]
pub enum ClientError {
    /// Transport failure — no valid HTTP response (DNS, TLS, connection, timeout).
    /// Wraps the underlying reqwest message.
    Http(String),
    /// AWS returned a non-2xx response. `status` is the HTTP code; `body` is the
    /// raw response text (a service error like AccessDenied — never credentials,
    /// which only ever appear in a 2xx body).
    Api { status: u16, body: String },
    /// A 2xx response whose body could not be read or parsed as expected JSON.
    /// The message already carries its own prefix.
    Response(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // These message strings are part of the user-facing output (surfaced via
            // PipelineError::Display); keep them stable.
            ClientError::Http(reason) => write!(f, "HTTP request failed: {}", reason),
            ClientError::Api { status, body } => {
                write!(f, "CreateSession returned HTTP {}: {}", status, body)
            }
            ClientError::Response(reason) => write!(f, "{}", reason),
        }
    }
}

/// Response returned by CreateSessionClient after a successful API call.
#[derive(Debug)]
pub struct CreateSessionResponse {
    pub credential_set: Vec<Credential>,
}

/// A single set of temporary AWS credentials.
#[derive(Debug)]
pub struct Credential {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
}

/// Raw JSON response from the CreateSession API.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionApiResponse {
    credential_set: Vec<CredentialSetEntry>,
}

/// An entry in the credentialSet array.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialSetEntry {
    credentials: CredentialFields,
}

/// The credentials object within a credential set entry.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialFields {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

/// HTTP client for the IAM Roles Anywhere CreateSession API.
pub struct CreateSessionClient {
    http_client: reqwest::blocking::Client,
    pub(crate) base_url: String,
}

impl CreateSessionClient {
    /// Create a new client.
    ///
    /// `endpoint_url`: if `Some`, used as the base URL directly (and `region` is unused by this constructor).
    /// If `None`, defaults to `https://rolesanywhere.{region}.amazonaws.com`.
    /// Enforces TLS 1.2 as the minimum version using rustls.
    pub fn new(region: &str, endpoint_url: Option<&str>) -> Result<Self, String> {
        let http_client = reqwest::blocking::Client::builder()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .use_rustls_tls()
            // 30s connect timeout matches Go's aws-sdk-go-v2 BuildableClient
            // (`DefaultDialConnectTimeout`). Plus a 60s overall request timeout so a
            // stalled response after connect+TLS can't hang the caller indefinitely.
            // The 60s value was agreed with the team; this is an intentional
            // divergence from the Go reference tool, which sets no overall timeout.
            .connect_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(60))
            // CreateSession never redirects; following one would let a caller-set endpoint steer
            // the daemon to an arbitrary URL and read the response back.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        let base_url = match endpoint_url {
            Some(url) => {
                let parsed =
                    reqwest::Url::parse(url).map_err(|e| format!("invalid endpoint URL: {e}"))?;
                if parsed.scheme() != "https" {
                    return Err("endpoint URL must use https".to_string());
                }
                // Reject URLs with userinfo (user@host or user:pass@host): reqwest's WHATWG
                // URL parser strips userinfo before connecting, but the SigV4 signer reads the
                // raw URL string for the Host header — a divergence that lets an attacker route
                // a validly-signed request to a host of their choosing. Percent-encoded forms
                // (e.g. %40) are also caught because reqwest::Url::parse decodes them first.
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    return Err(
                        "endpoint URL must not contain userinfo (user@host form)".to_string()
                    );
                }
                if parsed.query().is_some() {
                    return Err("endpoint URL must not contain a query string".to_string());
                }
                if parsed.fragment().is_some() {
                    return Err("endpoint URL must not contain a fragment".to_string());
                }
                let path = parsed.path();
                if !path.is_empty() && path != "/" {
                    return Err("endpoint URL must not contain a path other than /".to_string());
                }
                // Build base_url from parsed components so the stored URL is always
                // canonical and matches what reqwest will connect to.
                let host = parsed.host_str().unwrap_or_default();
                match parsed.port() {
                    Some(p) => format!("https://{}:{}", host, p),
                    None => format!("https://{}", host),
                }
            }
            None => format!("https://rolesanywhere.{}.amazonaws.com", region),
        };

        Ok(Self {
            http_client,
            base_url,
        })
    }

    /// Send the signed POST request to the CreateSession endpoint.
    ///
    /// - `headers`: the full set of HTTP headers produced by the signing pipeline
    /// - `body`: the JSON request payload
    /// - `query_string`: URL-encoded query parameters (profileArn, roleArn, trustAnchorArn)
    pub fn create_session(
        &self,
        headers: &[(String, String)],
        body: &str,
        query_string: &str,
    ) -> Result<CreateSessionResponse, ClientError> {
        let url = format!("{}/sessions?{}", self.base_url, query_string);

        let mut request = self.http_client.post(&url);

        for (name, value) in headers {
            request = request.header(name.as_str(), value.as_str());
        }

        request = request.body(body.to_string());

        let response = request
            .send()
            .map_err(|e| ClientError::Http(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let body_text = read_bounded(response)
                .unwrap_or_else(|_| "<failed to read response body>".to_string());
            // Non-2xx: status code carried as a typed field (no string round-trip);
            // body is a service error — see the `ClientError::Api` doc comment.
            return Err(ClientError::Api {
                status: status.as_u16(),
                body: body_text,
            });
        }

        let response_text = read_bounded(response)?;

        parse_create_session_response(&response_text)
    }
}

/// Parse the CreateSession JSON response into our public types.
///
/// An empty `credentialSet` is NOT treated as an error here — like Go's deserializer,
/// this function only parses. The "no credentials returned" case is handled once, by
/// the pipeline (`generate_credentials`) when it pulls the first credential out.
fn parse_create_session_response(json: &str) -> Result<CreateSessionResponse, ClientError> {
    let api_response: CreateSessionApiResponse = serde_json::from_str(json)
        .map_err(|e| ClientError::Response(format!("Failed to parse response JSON: {}", e)))?;

    let credential_set = api_response
        .credential_set
        .into_iter()
        .map(|entry| Credential {
            access_key_id: entry.credentials.access_key_id,
            secret_access_key: entry.credentials.secret_access_key,
            session_token: entry.credentials.session_token,
            expiration: entry.credentials.expiration,
        })
        .collect();

    Ok(CreateSessionResponse { credential_set })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_error_http_display_matches_legacy_string() {
        // Pin the exact user-facing Display text (surfaced via PipelineError::Display).
        let e = ClientError::Http("connection refused".to_string());
        assert_eq!(e.to_string(), "HTTP request failed: connection refused");
    }

    #[test]
    fn client_error_api_display_matches_legacy_string() {
        let e = ClientError::Api {
            status: 403,
            body: "Access denied".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "CreateSession returned HTTP 403: Access denied"
        );
    }

    #[test]
    fn client_error_response_display_passes_message_through() {
        // Response carries its own already-prefixed message; Display passes it verbatim.
        let e = ClientError::Response("Failed to read response body: eof".to_string());
        assert_eq!(e.to_string(), "Failed to read response body: eof");
    }

    #[test]
    fn test_parse_valid_response() {
        let json = r#"{
            "credentialSet": [
                {
                    "credentials": {
                        "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                        "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        "sessionToken": "FwoGZXIvYXdzEBYaDH...",
                        "expiration": "2024-01-15T12:00:00Z"
                    }
                }
            ]
        }"#;

        let result = parse_create_session_response(json).unwrap();
        assert_eq!(result.credential_set.len(), 1);
        assert_eq!(
            result.credential_set[0].access_key_id,
            "AKIAIOSFODNN7EXAMPLE"
        );
        assert_eq!(
            result.credential_set[0].secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(
            result.credential_set[0].session_token,
            "FwoGZXIvYXdzEBYaDH..."
        );
        assert_eq!(result.credential_set[0].expiration, "2024-01-15T12:00:00Z");
    }

    #[test]
    fn test_parse_empty_credential_set_parses_to_empty() {
        // An empty credentialSet parses successfully into an empty Vec (matching Go's
        // deserializer). The "no credentials" error is raised later, by the pipeline.
        let json = r#"{"credentialSet": []}"#;

        let result = parse_create_session_response(json).expect("empty set should parse");
        assert!(result.credential_set.is_empty());
    }

    #[test]
    fn test_parse_malformed_json() {
        let json = r#"{"not valid json"#;

        let err = parse_create_session_response(json).unwrap_err();
        match err {
            ClientError::Response(msg) => {
                assert!(msg.contains("Failed to parse response JSON"), "got: {msg}")
            }
            other => panic!("Expected ClientError::Response, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_multiple_credentials() {
        let json = r#"{
            "credentialSet": [
                {
                    "credentials": {
                        "accessKeyId": "AKIA_FIRST",
                        "secretAccessKey": "secret1",
                        "sessionToken": "token1",
                        "expiration": "2024-01-15T12:00:00Z"
                    }
                },
                {
                    "credentials": {
                        "accessKeyId": "AKIA_SECOND",
                        "secretAccessKey": "secret2",
                        "sessionToken": "token2",
                        "expiration": "2024-01-16T12:00:00Z"
                    }
                }
            ]
        }"#;

        let result = parse_create_session_response(json).unwrap();
        assert_eq!(result.credential_set.len(), 2);
        assert_eq!(result.credential_set[0].access_key_id, "AKIA_FIRST");
        assert_eq!(result.credential_set[1].access_key_id, "AKIA_SECOND");
    }

    #[test]
    fn test_new_default_endpoint_builds_regional_url() {
        let client = CreateSessionClient::new("eu-west-2", None).unwrap();
        // base_url is pub(crate) so tests can assert the resolved endpoint without a
        // live HTTP call.
        assert_eq!(
            client.base_url,
            "https://rolesanywhere.eu-west-2.amazonaws.com"
        );
    }

    #[test]
    fn test_new_default_endpoint_china_region_is_commercial_suffix() {
        // Documented, intentional divergence: the default endpoint is commercial-`aws`-
        // partition only. For a China region we still build `.amazonaws.com` (NOT the
        // partition-correct `.amazonaws.com.cn`), so cn/gov users must pass --endpoint.
        // This guards against someone "fixing" it silently.
        let client = CreateSessionClient::new("cn-north-1", None).unwrap();
        assert_eq!(
            client.base_url, "https://rolesanywhere.cn-north-1.amazonaws.com",
            "default host is commercial-only; China needs an explicit --endpoint"
        );
    }

    #[test]
    fn test_parse_response_ignores_unknown_fields() {
        // Real CreateSession responses carry fields we don't model
        // (assumedRoleUser, packagedPolicySize, subjectArn, ...). serde ignores unknown
        // fields by default; this guards against a regression adding
        // #[serde(deny_unknown_fields)] that would break parsing of real responses as
        // the API gains fields. Mirrors Go's tolerant deserializer.
        let json = r#"{
            "subjectArn": "arn:aws:rolesanywhere:us-east-1:123:subject/abc",
            "credentialSet": [
                {
                    "assumedRoleUser": {"arn": "arn:aws:sts::123:assumed-role/x/y", "assumedRoleId": "AROA:y"},
                    "packedPolicySize": 0,
                    "roleArn": "arn:aws:iam::123:role/x",
                    "sourceIdentity": "src",
                    "credentials": {
                        "accessKeyId": "ASIA_X",
                        "secretAccessKey": "secret",
                        "sessionToken": "token",
                        "expiration": "2024-01-15T12:00:00Z",
                        "futureUnknownField": "ignored"
                    }
                }
            ]
        }"#;
        let result =
            parse_create_session_response(json).expect("must parse despite unknown fields");
        assert_eq!(result.credential_set.len(), 1);
        assert_eq!(result.credential_set[0].access_key_id, "ASIA_X");
        assert_eq!(result.credential_set[0].expiration, "2024-01-15T12:00:00Z");
    }

    #[test]
    fn test_new_custom_endpoint_with_trailing_slash() {
        // A single trailing slash (path "/") is accepted; base_url is built from
        // parsed host components, never from the raw input string.
        let client = CreateSessionClient::new(
            "eu-west-2",
            Some("https://rolesanywhere.eu-west-2.example.com/"),
        )
        .unwrap();
        assert_eq!(
            client.base_url,
            "https://rolesanywhere.eu-west-2.example.com"
        );
    }

    #[test]
    fn test_new_rejects_http_endpoint() {
        let err = CreateSessionClient::new("us-east-1", Some("http://example.com"))
            .err()
            .expect("http must be rejected");
        assert!(err.contains("https"), "got: {err}");
    }

    #[test]
    fn test_new_rejects_userinfo_in_endpoint() {
        // Literal @ in authority: the signer and reqwest agree on the host, but explicit
        // userinfo is a sign of URL crafting and should be rejected unconditionally.
        let err = CreateSessionClient::new(
            "us-east-1",
            Some("https://user:pass@rolesanywhere.us-east-1.amazonaws.com"),
        )
        .err()
        .expect("userinfo must be rejected");
        assert!(err.contains("userinfo"), "got: {err}");
    }

    /// The percent-encoded `@` bypass: `%40` in the authority is decoded by reqwest's
    /// WHATWG parser but not by the signer's raw-string host extractor, so a URL like
    /// `https://trusted.amazonaws.com%40attacker.com` routes to `attacker.com` while
    /// the SigV4 signature covers `trusted.amazonaws.com%40attacker.com` as the host.
    /// reqwest::Url::parse rejects the crafted URL outright (invalid domain after
    /// decoding the %40 to @), so the signer never receives it.
    #[test]
    fn test_new_rejects_percent_encoded_userinfo() {
        assert!(
            CreateSessionClient::new(
                "us-east-1",
                Some("https://trusted.amazonaws.com%40attacker.com/sessions"),
            )
            .is_err(),
            "percent-encoded @ must be rejected"
        );
    }

    #[test]
    fn test_parse_missing_fields() {
        let json = r#"{
            "credentialSet": [
                {
                    "credentials": {
                        "accessKeyId": "AKIA_TEST"
                    }
                }
            ]
        }"#;

        let err = parse_create_session_response(json).unwrap_err();
        match err {
            ClientError::Response(msg) => {
                assert!(msg.contains("Failed to parse response JSON"), "got: {msg}")
            }
            other => panic!("Expected ClientError::Response, got: {other:?}"),
        }
    }

    // The three authority-confusion URLs the reviewer identified: WHATWG stops the
    // authority at `\`, `?`, `#`, but a string-splitting parser does not — a gap
    // that lets an attacker get a request signed for the real host while reqwest
    // connects to attacker.example.
    #[test]
    fn new_rejects_backslash_authority_confusion() {
        let url = r"https://attacker.example\@rolesanywhere.us-east-1.amazonaws.com";
        assert!(CreateSessionClient::new("us-east-1", Some(url)).is_err());
    }

    #[test]
    fn new_rejects_query_authority_confusion() {
        let url = "https://attacker.example?@rolesanywhere.us-east-1.amazonaws.com";
        assert!(CreateSessionClient::new("us-east-1", Some(url)).is_err());
    }

    #[test]
    fn new_rejects_fragment_authority_confusion() {
        let url = "https://attacker.example#@rolesanywhere.us-east-1.amazonaws.com";
        assert!(CreateSessionClient::new("us-east-1", Some(url)).is_err());
    }
}
