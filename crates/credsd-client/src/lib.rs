//! Public client library for the AWS credential daemon.
//!
//! Speaks the daemon's line-delimited JSON-RPC 2.0 protocol over a Unix domain socket.
//! External Rust crates that want to obtain credentials without shelling out to `credsd`
//! can depend on this crate directly.
//!
//! # Quick start
//!
//! ```no_run
//! # async fn example() -> Result<(), credsd_client::ClientError> {
//! let client = credsd_client::Client::default(); // uses CREDSD_SOCKET or platform default
//! let cred = client.get_container_credentials("work", false).await?;
//! println!("{}", cred.access_key_id);
//! # Ok(())
//! # }
//! ```

// This crate speaks a socket protocol and touches no FFI, so the workspace's real `unsafe` (six
// files of platform syscalls, all in the daemon) has no business here. Denied at the crate root
// rather than in `[lints]`, which cannot mix `workspace = true` with a per-crate table.
#![deny(unsafe_code)]

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors returned by the client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("cannot connect to daemon socket: {0}")]
    Connect(#[source] std::io::Error),
    #[error("daemon transport failure: {0}")]
    Transport(#[source] std::io::Error),
    #[error("decode failure: {0}")]
    Decode(String),
    #[error("re-authentication required: {0}")]
    ReauthRequired(String),
    #[error("credential not found: {0}")]
    NotFound(String),
    #[error("daemon error: {0}")]
    Daemon(String),
}

/// Short-lived AWS session credentials returned by the daemon.
///
/// The key material is zeroized on drop; expiration is not secret and is not zeroized.
/// The `Debug` impl redacts the key material.
pub struct Credential {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: DateTime<Utc>,
}

impl Drop for Credential {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[redacted]")
            .field("session_token", &"[redacted]")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Async client for the credential daemon.
#[derive(Clone, Debug)]
pub struct Client {
    socket_path: PathBuf,
}

impl Default for Client {
    /// Resolves the socket path via the same logic as the CLI: `CREDSD_SOCKET`, then a live
    /// user-install socket if one exists, then the system socket.
    fn default() -> Self {
        Self {
            socket_path: credsd_core::config::platform::client_socket_path(),
        }
    }
}

impl Client {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Fetch the default credential for `env`. Backs `credential_process` generated configs
    /// and the ECS container endpoint.
    pub async fn get_container_credentials(
        &self,
        env: &str,
        agentic: bool,
    ) -> Result<Credential, ClientError> {
        fetch(&self.socket_path, env, None, agentic).await
    }

    /// Fetch a specific named credential within `env`. Backs `credsd get --env E --credential C`.
    pub async fn get_credential(
        &self,
        env: &str,
        credential: &str,
        agentic: bool,
    ) -> Result<Credential, ClientError> {
        fetch(&self.socket_path, env, Some(credential), agentic).await
    }
}

/// Optional blocking wrapper. Enabled by the `blocking` Cargo feature.
///
/// # Warning
/// Do **not** construct this inside an existing async runtime; calling
/// `tokio::runtime::Builder::new_current_thread().build()` inside a tokio context panics.
#[cfg(feature = "blocking")]
pub mod blocking {
    use super::*;

    pub struct Client {
        inner: super::Client,
        rt: tokio::runtime::Runtime,
    }

    impl Client {
        pub fn new(socket_path: impl Into<PathBuf>) -> Result<Self, ClientError> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| ClientError::Connect(e))?;
            Ok(Self {
                inner: super::Client::new(socket_path),
                rt,
            })
        }

        pub fn default() -> Result<Self, ClientError> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| ClientError::Connect(e))?;
            Ok(Self {
                inner: super::Client::default(),
                rt,
            })
        }

        pub fn get_container_credentials(
            &self,
            env: &str,
            agentic: bool,
        ) -> Result<Credential, ClientError> {
            self.rt
                .block_on(self.inner.get_container_credentials(env, agentic))
        }

        pub fn get_credential(
            &self,
            env: &str,
            credential: &str,
            agentic: bool,
        ) -> Result<Credential, ClientError> {
            self.rt
                .block_on(self.inner.get_credential(env, credential, agentic))
        }
    }
}

// ── Protocol internals ──────────────────────────────────────────────────────

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: u32,
    method: &'a str,
    params: GetParams<'a>,
}

#[derive(Serialize)]
struct GetParams<'a> {
    environment: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RpcResponse {
    Ok { result: CredentialResult },
    Err { error: RpcError },
}

#[derive(Deserialize)]
struct CredentialResult {
    #[expect(
        dead_code,
        reason = "part of the wire contract; deserialized so an unexpected shape still fails to \
                  parse, but this client resolves one named credential and so never reads the echo"
    )]
    credential: String,
    material: Material,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Material {
    SessionCredentials {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
    },
    /// A bearer token for a non-AWS API. Deserialized rather than left to the tag's
    /// unknown-variant error so the mismatch is reported as what it is — this client hands out
    /// AWS session credentials, and that credential is not one — instead of as a decode failure
    /// that reads like a protocol break. The token itself is not bound: nothing here would use
    /// it, and binding it would put material in a value only built to be rejected.
    AccessToken {},
}

#[derive(Deserialize, Debug)]
struct RpcError {
    #[expect(
        dead_code,
        reason = "the envelope's numeric code is deserialized to reject a malformed error object, \
                  but classification reads data.code — see the protocol's single-field rule"
    )]
    code: i32,
    message: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

impl RpcError {
    fn domain_code(&self) -> Option<&str> {
        self.data.as_ref()?.get("code").and_then(|v| v.as_str())
    }
}

#[cfg(unix)]
async fn fetch(
    socket_path: &Path,
    env: &str,
    credential: Option<&str>,
    agentic: bool,
) -> Result<Credential, ClientError> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(ClientError::Connect)?;

    let request = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "credential/get",
        params: GetParams {
            environment: env,
            credential,
            claim: if agentic { Some("agentic") } else { None },
        },
    };
    let mut line = serde_json::to_vec(&request).map_err(|e| ClientError::Decode(e.to_string()))?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .await
        .map_err(ClientError::Transport)?;

    let mut reader = BufReader::new(stream.take(1024 * 1024));
    let mut buf = Vec::new();
    let n = reader
        .read_until(b'\n', &mut buf)
        .await
        .map_err(ClientError::Transport)?;
    if n == 0 {
        return Err(ClientError::Transport(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "daemon closed connection without responding",
        )));
    }
    if !buf.ends_with(b"\n") {
        return Err(ClientError::Decode(
            "daemon response exceeded size limit".into(),
        ));
    }

    let response: RpcResponse =
        serde_json::from_slice(&buf).map_err(|e| ClientError::Decode(e.to_string()))?;

    match response {
        RpcResponse::Ok { result } => {
            let expiration = result.expires_at;
            let Material::SessionCredentials {
                access_key_id,
                secret_access_key,
                session_token,
            } = result.material
            else {
                return Err(ClientError::Daemon(format!(
                    "credential for env '{env}' provides an access token, not AWS session \
                     credentials"
                )));
            };
            Ok(Credential {
                access_key_id,
                secret_access_key,
                session_token,
                expiration,
            })
        }
        RpcResponse::Err { error } => Err(match error.domain_code() {
            Some("REAUTH_REQUIRED") => ClientError::ReauthRequired(error.message),
            Some("ENVIRONMENT_NOT_FOUND") => ClientError::NotFound(env.to_owned()),
            _ => ClientError::Daemon(error.message),
        }),
    }
}

#[cfg(not(unix))]
async fn fetch(
    _socket_path: &Path,
    _env: &str,
    _credential: Option<&str>,
    _agentic: bool,
) -> Result<Credential, ClientError> {
    Err(ClientError::Daemon(
        "credsd-client requires a Unix platform".to_owned(),
    ))
}

// ── Socket path resolution ──────────────────────────────────────────────────

// ── Full UDS API ─────────────────────────────────────────────────────────────

pub use credsd_core::credential_resolve::{fetch_credential_in_env, fetch_from_daemon_uds};
pub use credsd_core::error::{DaemonError, Result as DaemonResult};
pub use credsd_core::rpc::{
    ConfigGetResult, CredentialRemoveParams, CredentialSourceType, EnvRemoveParams, HealthResult,
    ListResult, OkResult, ProfileBootstrapParams, ProfileLoginParams, ProfileManifest,
    ProviderParams, ProviderParamsIamUser, ProviderParamsRa, ProviderParamsSso,
};

/// Handles interactive prompts during `bootstrap` and `login` flows.
///
/// All selection methods are synchronous. Implementations that read from stdin or
/// do other blocking I/O should use `tokio::task::block_in_place` internally.
/// Non-blocking notifications (`device_code`, `polling`) have default no-op
/// implementations. Selection methods are required because the daemon blocks
/// until they are answered.
pub trait BootstrapHandler: Send + Sync {
    /// SSO device-code flow: tell the user to visit `uri` with `code`.
    fn device_code(&self, uri: &str, code: &str) {
        let _ = (uri, code);
    }
    /// The daemon is polling; no action needed.
    fn polling(&self) {}
    /// OAuth redirect: the daemon is listening on a loopback port; direct the user to `url`.
    /// No respond notification is needed — the answer arrives out-of-band via the IdP redirect.
    fn authorize_url(&self, url: &str) {
        let _ = url;
    }
    /// Cross-device OAuth redirect: direct the user to `url` on whatever machine has a browser,
    /// and return the value the provider's confirmation page displayed. There is no listener for
    /// the redirect to reach, so the daemon blocks until this answers.
    ///
    /// The returned value carries an authorization code — do not log or echo it.
    fn authorize_code(&self, url: &str) -> Result<String, String>;
    /// Return the account id to use, or an error message to abort the flow.
    /// `accounts` is `(id, name, email)`.
    fn select_account(&self, accounts: &[(String, String, String)]) -> Result<String, String>;
    /// Return the role name to use, or an error message to abort the flow.
    fn select_role(&self, roles: &[String]) -> Result<String, String>;
    /// Return the MFA code, or an error message to abort the flow.
    fn mfa_code(&self, serial: &str) -> Result<String, String>;
}

/// Bootstrap or reconfigure a credential. Drives the full interactive flow via `handler`.
#[cfg(unix)]
pub async fn bootstrap(
    socket: &Path,
    params: &ProfileBootstrapParams,
    handler: &dyn BootstrapHandler,
) -> DaemonResult<()> {
    use credsd_core::rpc::{Id, Request, METHOD_PROFILE_BOOTSTRAP};
    let request = Request::with_params(Id::from(1i64), METHOD_PROFILE_BOOTSTRAP, params)
        .map_err(|e| DaemonError::config(format!("failed to encode request: {e}")))?;
    run_streaming_rpc(socket, request, Some(&params.environment), handler).await
}

/// Re-authenticate a credential whose session is spent.
#[cfg(unix)]
pub async fn login(
    socket: &Path,
    params: &ProfileLoginParams,
    handler: &dyn BootstrapHandler,
) -> DaemonResult<()> {
    use credsd_core::rpc::{Id, Request, METHOD_PROFILE_LOGIN};
    let request = Request::with_params(Id::from(1i64), METHOD_PROFILE_LOGIN, params)
        .map_err(|e| DaemonError::config(format!("failed to encode request: {e}")))?;
    run_streaming_rpc(socket, request, Some(&params.environment), handler).await
}

/// Return a profile's full manifest (credentials, region, sdk/cli settings).
#[cfg(unix)]
pub async fn describe(socket: &Path, environment: &str) -> DaemonResult<ProfileManifest> {
    use credsd_core::rpc::{uds, DescribeParams, METHOD_PROFILE_DESCRIBE};
    uds::call(
        socket,
        METHOD_PROFILE_DESCRIBE,
        &DescribeParams {
            environment: environment.to_owned(),
            request_id: None,
        },
        Some(environment),
    )
    .await
}

/// Enumerate credentials for `profile`, or all profiles when `None`.
#[cfg(unix)]
pub async fn list(socket: &Path, environment: Option<&str>) -> DaemonResult<ListResult> {
    use credsd_core::rpc::{uds, ListParams, METHOD_CREDENTIAL_LIST};
    uds::call(
        socket,
        METHOD_CREDENTIAL_LIST,
        &ListParams {
            environment: environment.map(str::to_owned),
            request_id: None,
        },
        environment,
    )
    .await
}

/// Read one config key for `profile`.
#[cfg(unix)]
pub async fn config_get(
    socket: &Path,
    environment: &str,
    key: &str,
) -> DaemonResult<ConfigGetResult> {
    use credsd_core::rpc::{uds, ConfigGetParams, METHOD_CONFIG_GET};
    uds::call(
        socket,
        METHOD_CONFIG_GET,
        &ConfigGetParams {
            environment: environment.to_owned(),
            key: key.to_owned(),
        },
        Some(environment),
    )
    .await
}

/// Set one config key for `profile`.
#[cfg(unix)]
pub async fn config_set(
    socket: &Path,
    environment: &str,
    key: &str,
    value: &str,
) -> DaemonResult<OkResult> {
    use credsd_core::rpc::{uds, ConfigSetParams, METHOD_CONFIG_SET};
    uds::call(
        socket,
        METHOD_CONFIG_SET,
        &ConfigSetParams {
            environment: environment.to_owned(),
            key: key.to_owned(),
            value: value.to_owned(),
        },
        Some(environment),
    )
    .await
}

/// Unset one config key for `profile`.
#[cfg(unix)]
pub async fn config_unset(socket: &Path, environment: &str, key: &str) -> DaemonResult<OkResult> {
    use credsd_core::rpc::{uds, ConfigUnsetParams, METHOD_CONFIG_UNSET};
    uds::call(
        socket,
        METHOD_CONFIG_UNSET,
        &ConfigUnsetParams {
            environment: environment.to_owned(),
            key: key.to_owned(),
        },
        Some(environment),
    )
    .await
}

/// Remove an environment (its credentials survive).
#[cfg(unix)]
pub async fn env_remove(socket: &Path, environment: &str) -> DaemonResult<OkResult> {
    use credsd_core::rpc::{uds, EnvRemoveParams, METHOD_ENV_REMOVE};
    uds::call(
        socket,
        METHOD_ENV_REMOVE,
        &EnvRemoveParams {
            environment: environment.to_owned(),
        },
        Some(environment),
    )
    .await
}

/// Remove a credential and destroy its encrypted material.
#[cfg(unix)]
pub async fn credential_remove(socket: &Path, credential: &str) -> DaemonResult<OkResult> {
    use credsd_core::rpc::{uds, CredentialRemoveParams, METHOD_CREDENTIAL_REMOVE};
    uds::call(
        socket,
        METHOD_CREDENTIAL_REMOVE,
        &CredentialRemoveParams {
            credential: credential.to_owned(),
        },
        Some(credential),
    )
    .await
}

/// Protocol liveness check.
#[cfg(unix)]
pub async fn health(socket: &Path) -> DaemonResult<HealthResult> {
    use credsd_core::rpc::{uds, METHOD_SYSTEM_HEALTH};
    uds::call(socket, METHOD_SYSTEM_HEALTH, &serde_json::json!({}), None).await
}

// Streaming RPC driver for bootstrap and login. Loops reading notification lines
// until a response with an `id` arrives, delegating interactive steps to `handler`.
#[cfg(unix)]
async fn run_streaming_rpc(
    socket: &Path,
    request: credsd_core::rpc::Request,
    subject: Option<&str>,
    handler: &dyn BootstrapHandler,
) -> DaemonResult<()> {
    use credsd_core::error::DaemonError;
    use credsd_core::rpc::{codec, uds, OkResult, Outcome, Response};
    use tokio::io::{AsyncReadExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket)
        .await
        .map_err(|e| DaemonError::unreachable(socket, &e, Some(e.kind())))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half.take(10 * 1024 * 1024));

    let req_bytes = codec::encode_request(&request)?;
    uds::write_frame(&mut write_half, socket, &req_bytes).await?;

    let mut line_buf = Vec::new();
    loop {
        line_buf.clear();
        if let Err(e) = uds::read_frame(&mut reader, socket, &mut line_buf).await {
            // The cap and a dropped peer both end a frame early; only an exhausted cap is the
            // daemon sending too much rather than the connection going away.
            if reader.get_ref().limit() == 0 {
                return Err(DaemonError::config("daemon response exceeded size limit"));
            }
            return Err(e);
        }

        let raw: serde_json::Value = serde_json::from_slice(&line_buf)
            .map_err(|e| DaemonError::config(format!("invalid JSON from daemon: {e}")))?;

        if raw.get("id").is_none() {
            let step_type = raw
                .get("params")
                .and_then(|p| p.get("type"))
                .and_then(|t| t.as_str())
                .unwrap_or("");
            let params = raw
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            let selection: Option<String> = match step_type {
                "device_code" => {
                    handler.device_code(
                        params
                            .get("verification_uri")
                            .and_then(|v| v.as_str())
                            .unwrap_or(""),
                        params
                            .get("user_code")
                            .and_then(|v| v.as_str())
                            .unwrap_or(""),
                    );
                    None
                }
                "polling" => {
                    handler.polling();
                    None
                }
                // The daemon listens on the loopback redirect; the client just opens the browser.
                "authorize_url" => {
                    handler.authorize_url(params.get("url").and_then(|v| v.as_str()).unwrap_or(""));
                    None
                }
                // Cross-device: no listener to redirect to, so the user carries the result back.
                "authorize_code" => Some(
                    handler
                        .authorize_code(params.get("url").and_then(|v| v.as_str()).unwrap_or(""))
                        .map_err(DaemonError::config)?,
                ),
                "select_account" => {
                    let accounts = params
                        .get("accounts")
                        .and_then(|a| a.as_array())
                        .map(|arr| {
                            arr.iter()
                                .map(|a| {
                                    (
                                        a.get("id")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_owned(),
                                        a.get("name")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_owned(),
                                        a.get("email")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_owned(),
                                    )
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    Some(
                        handler
                            .select_account(&accounts)
                            .map_err(DaemonError::config)?,
                    )
                }
                "select_role" => {
                    let roles = params
                        .get("roles")
                        .and_then(|r| r.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .map(str::to_owned)
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    Some(handler.select_role(&roles).map_err(DaemonError::config)?)
                }
                "mfa_required" => {
                    let serial = params.get("serial").and_then(|v| v.as_str()).unwrap_or("");
                    Some(handler.mfa_code(serial).map_err(DaemonError::config)?)
                }
                _ => None,
            };

            if let Some(sel) = selection {
                use credsd_core::rpc::METHOD_PROFILE_BOOTSTRAP_RESPOND;
                let notif = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": METHOD_PROFILE_BOOTSTRAP_RESPOND,
                    "params": { "selection": sel }
                });
                let mut bytes = serde_json::to_vec(&notif)
                    .map_err(|e| DaemonError::config(format!("failed to encode respond: {e}")))?;
                bytes.push(b'\n');
                uds::write_frame(&mut write_half, socket, &bytes).await?;
            }
            continue;
        }

        let response: Response<OkResult> = serde_json::from_value(raw)
            .map_err(|e| DaemonError::config(format!("failed to decode daemon response: {e}")))?;
        return match response.outcome {
            Outcome::Result(_) => Ok(()),
            Outcome::Error(e) => Err(uds::error_to_daemon(subject, e)),
        };
    }
}

#[cfg(test)]
#[cfg(unix)]
mod streaming_tests {
    use super::*;
    use credsd_core::rpc::{codec, DomainCode, Id, Request, Response, RpcError};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    struct NoPrompts;
    impl BootstrapHandler for NoPrompts {
        fn authorize_code(&self, _: &str) -> Result<String, String> {
            Err("no prompts in this test".into())
        }
        fn select_account(&self, _: &[(String, String, String)]) -> Result<String, String> {
            Err("no prompts in this test".into())
        }
        fn select_role(&self, _: &[String]) -> Result<String, String> {
            Err("no prompts in this test".into())
        }
        fn mfa_code(&self, _: &str) -> Result<String, String> {
            Err("no prompts in this test".into())
        }
    }

    /// A daemon that reads the request and answers with `reply` exactly as given, then hangs up.
    async fn exchange(name: &str, reply: Vec<u8>) -> DaemonResult<()> {
        let dir = std::env::temp_dir().join(format!("credsd-stream-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("s.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let daemon = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = Vec::new();
            BufReader::new(read)
                .read_until(b'\n', &mut line)
                .await
                .unwrap();
            write.write_all(&reply).await.unwrap();
        });
        let request =
            Request::with_params(Id::from(1i64), "profile/login", &serde_json::json!({})).unwrap();
        let outcome = run_streaming_rpc(&socket, request, None, &NoPrompts).await;
        daemon.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        outcome
    }

    /// A daemon that stops mid-frame is a transport failure, as on the one-shot path, and is not
    /// reported as an oversized response.
    #[tokio::test]
    async fn a_connection_dropped_mid_stream_is_unreachable() {
        let err = exchange("drop", br#"{"jsonrpc":"2.0","id":1,"res"#.to_vec())
            .await
            .unwrap_err();
        assert!(
            matches!(err, DaemonError::Unreachable { .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains("mid-response"), "got {err}");
    }

    /// A daemon that answers with an error frame is a daemon answer, passed through as worded.
    #[tokio::test]
    async fn a_daemon_error_frame_is_remote_verbatim() {
        let frame = codec::encode_response::<()>(&Response::failure(
            Id::from(1i64),
            RpcError::domain(
                DomainCode::Internal,
                "the identity provider refused the code",
            ),
        ))
        .unwrap();
        let err = exchange("remote", frame).await.unwrap_err();
        assert!(matches!(err, DaemonError::Remote(_)), "got {err:?}");
        assert_eq!(err.to_string(), "the identity provider refused the code");
    }
}
