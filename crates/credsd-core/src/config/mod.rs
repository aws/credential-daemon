//! Configuration parsing, TOML editing, and env management.

pub mod credentials;
pub mod keys;
pub mod platform;
pub mod snapshot;

use self::credentials::CredentialSources;
use crate::error::{DaemonError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use toml_edit::{DocumentMut, Item, Table};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityType {
    #[default]
    Human,
    Automation,
    Agent,
    /// An identity tier not recognised by this version. As a credential's type, this is the
    /// most-restrictive placement (Human-only access, not `Agent`'s least-restrictive one) since
    /// its real privilege can't be verified. As an env's type, it behaves like `Agent`: it may
    /// only compose `Agent`-tier credentials.
    #[serde(other)]
    Unknown,
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Human => write!(f, "human"),
            Self::Automation => write!(f, "automation"),
            Self::Agent => write!(f, "agent"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl IdentityType {
    /// Privilege lattice check: an env of type `self` may only compose credentials whose
    /// identity_type is equal or of equal privilege. Agent is the most restricted tier;
    /// a credential more permissive than the env would let agent-context requests reach
    /// human-privilege material.
    ///
    /// Lattice (ascending privilege): Agent ≤ Automation ≤ Human.
    /// An env may access a credential only when the credential's privilege ≤ env's privilege.
    /// A credential whose identity_type failed to parse as a known tier is `Unknown`; since its
    /// real privilege can't be verified, it is treated as the *highest* tier (Human-only access)
    /// rather than the lowest — an unrecognised tier must never be easier to reach than a
    /// correctly classified one.
    pub fn may_access(self, credential: IdentityType) -> bool {
        matches!(
            (self, credential),
            (_, IdentityType::Agent)
                | (IdentityType::Human, _)
                | (IdentityType::Automation, IdentityType::Automation)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    pub start_url: String,
    pub sso_region: String,
    pub account_id: String,
    pub role_name: String,
    /// Who this credential is *for*. Controls the privilege lattice check at bootstrap.
    #[serde(default, skip_serializing_if = "is_default_identity")]
    pub identity_type: IdentityType,
}

/// A long-term IAM key brokered into short-lived credentials via `sts:GetSessionToken`.
///
/// Only non-secret knobs live here. The key pair itself is never in `credentials.toml`: it is
/// stored encrypted at `credentials/<name>/iam_user.enc`, the same convention the SSO source uses
/// for its token (see `providers::iam_user`).
///
/// `mfa_serial`, when set, gates every `GetSessionToken` on a fresh TOTP code — which the daemon
/// cannot supply unattended. Such a source is renewable only from the session `credsd login`
/// persists: the daemon serves that until it expires, then reports `ReauthRequired`. Without
/// `mfa_serial` the stored key re-mints unattended as before.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamUserConfig {
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<i32>,
    /// ARN of the MFA device to require on `GetSessionToken` (e.g. `arn:aws:iam::123:mfa/user`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_serial: Option<String>,
    /// Who this credential is *for*. Controls the privilege lattice check at bootstrap.
    #[serde(default, skip_serializing_if = "is_default_identity")]
    pub identity_type: IdentityType,
}

/// A JWT held on credsd's behalf and served as the credential itself — the source for an API
/// that authenticates with a bearer JWT and has no OAuth flow to run: a CI-issued OIDC token, a
/// Kubernetes projected service-account token, an IdP token minted out of band.
///
/// The JWT is sealed under `credentials/<name>/jwt.enc`, never in `credentials.toml`, and its own
/// `exp` claim is the credential's expiry — the issuer already stated the lifetime, so credsd does
/// not invent a second one.
///
/// The JWT is content-only: the client reads the source file and passes the token bytes over
/// the socket. No path is stored — the daemon never holds or re-reads a caller-supplied path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Variable this credential is projected as into a child process. Defaults to
    /// the name derived from the credential when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// Who this credential is *for*. See [`SsoConfig::identity_type`].
    #[serde(default, skip_serializing_if = "is_default_identity")]
    pub identity_type: IdentityType,
}

/// A pre-issued secret the user already holds, served verbatim.
///
/// The smallest source there is: the credential *is* the secret. There is no issuer to
/// exchange with and nothing to renew from, so credsd is the seal, the optional expiry, and
/// the serving, and no more.
///
/// The secret is sealed under `credentials/<name>/static_secret.enc`, never in
/// `credentials.toml` — the same split every other source uses. Unlike `jwt` there is no
/// parseable lifetime to read out of it: an opaque secret states nothing about when it dies,
/// so the expiry is whatever the user declares and absent means never.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticSecretConfig {
    /// Variable this credential is projected as into a child process. Defaults to
    /// the name derived from the credential when absent, the same default as [`JwtConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// Absolute expiry (RFC 3339) the user declared. Absent means the secret never expires:
    /// credsd cannot derive a lifetime from an opaque string and does not invent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Where the secret came from, recorded for re-seal diagnostics only and never read at
    /// runtime. Caller-supplied text, so it is not interpolated into daemon log lines or
    /// error messages — mirrors the reason `JwtConfig` stores no path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_source: Option<String>,
    /// Who this credential is *for*. See [`SsoConfig::identity_type`].
    #[serde(default, skip_serializing_if = "is_default_identity")]
    pub identity_type: IdentityType,
}

/// OAuth2 login: an authorization-code + PKCE flow whose OIDC JWT is federated to AWS
/// credentials. Only non-secret knobs live here; tokens are sealed under
/// `callers/<uid>/credentials/<name>/` (`oauth_token.enc`), never in `credentials.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsWebIdentityConfig {
    /// OAuth endpoints + client id drive the interactive auth-code/refresh flow. Optional:
    /// `Option` so a token-seeded credential can carry only a pre-minted JWT + `role_arn`. No
    /// command creates one yet — that needs a `credential/seal_oauth` RPC — so today every
    /// credential written by `bootstrap` has all three set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// `AssumeRoleWithWebIdentity` target role.
    pub role_arn: String,
    /// STS region. Required, with no default: an entry without it does not parse.
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_session_name: Option<String>,
    /// Fixed loopback port for the OAuth callback server. Use when the IdP requires
    /// an exact redirect URI (e.g. Cognito). Omit for ephemeral.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_port: Option<u16>,
    /// Who this credential is *for*. Controls the privilege lattice check at bootstrap.
    #[serde(default, skip_serializing_if = "is_default_identity")]
    pub identity_type: IdentityType,
}

/// AWS Sign-In login (`aws login`): OAuth2 + PKCE + DPoP, federated to raw AWS credentials with
/// no STS call. The client id is fixed to the AWS CLI's; tokens and the DPoP key are sealed under
/// `callers/<uid>/credentials/<name>/`, never in `credentials.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsLoginConfig {
    /// Sign-In region; selects `https://{region}.signin.aws.amazon.com`. Required, with no default.
    pub region: String,
    /// Fixed loopback port for the callback server. Omit for ephemeral. Meaningless when
    /// `remote` is set, which has no listener to bind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_port: Option<u16>,
    /// Cross-device login: the browser runs on another machine, so Sign-In redirects to its own
    /// confirmation page and the user carries the result back by hand. Persisted because a
    /// re-login has to reach the same browser the first one did.
    #[serde(default)]
    pub remote: bool,
    /// Who this credential is *for*. Controls the privilege lattice check at bootstrap.
    #[serde(default, skip_serializing_if = "is_default_identity")]
    pub identity_type: IdentityType,
}

/// OAuth 2.0 client secret. Zeroed in memory on drop so it does not outlive its use and cannot
/// be recovered from a heap dump or core file. Never serialized — the secret lives in
/// `oauth_client_secret.enc`, not in `credentials.toml`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClientSecret(pub String);

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientSecret([redacted])")
    }
}

/// The OAuth 2.0 grant type for a token request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OauthGrant {
    ClientCredentials,
    /// A grant type this build does not implement yet. Parsing succeeds so a forward-looking
    /// entry does not make the whole file unloadable.
    #[serde(other)]
    Unsupported,
}

/// OAuth 2.0 JWT Bearer grant (RFC 7523): exchange a sealed assertion JWT for an AWS
/// access token at `token_url`. The assertion is sealed at bootstrap; re-bootstrap with
/// a fresh assertion to rotate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtBearerConfig {
    pub token_url: String,
    /// OAuth2 client ID to include in the token request. Required by some IdPs (e.g. Hydra v2)
    /// even when the JWT assertion is the sole proof of identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Who this credential is *for*. See [`SsoConfig::identity_type`].
    #[serde(default, skip_serializing_if = "is_default_identity")]
    pub identity_type: IdentityType,
}

/// OAuth 2.0 client-credentials (machine-to-machine) flow configuration.
///
/// `client_secret` is NOT stored here. `bootstrap` seals it to `oauth_client_secret.enc` in the
/// credential data dir; the provider unseals it at renew time. `credentials.toml` holds only
/// non-secret parameters — the same invariant [`RolesAnywhereConfig`] holds for private keys.
///
/// Authentication method is inferred at runtime:
/// - `oauth_client_secret.enc` present → `client_secret_basic`
/// - absent → `private_key_jwt` (ES256 key in `oauth_client_key.enc`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthConfig {
    pub token_url: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub grant: OauthGrant,
    /// Who this credential is *for*. See [`SsoConfig::identity_type`].
    #[serde(default, skip_serializing_if = "is_default_identity")]
    pub identity_type: IdentityType,
}

/// Serde helper: deserialize `Option<String>` and reject any value that is not a clean
/// `https://host[/...]` URL (no userinfo, no http, must parse as a valid URL). Uses
/// `reqwest::Url::parse` — the same WHATWG parser reqwest uses — so percent-encoded
/// userinfo (`%40`) is caught before the value reaches the vendored SigV4 signer.
fn https_endpoint_opt<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    use serde::de::Error as _;
    let Some(raw) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    let parsed = reqwest::Url::parse(&raw)
        .map_err(|e| D::Error::custom(format!("endpoint_url is not a valid URL: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(D::Error::custom("endpoint_url must be an https URL"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(D::Error::custom(
            "endpoint_url must not contain userinfo (user@host form)",
        ));
    }
    Ok(Some(raw))
}

/// IAM Roles Anywhere: exchange an X.509 certificate + private key for short-lived credentials
/// via the `rolesanywhere:CreateSession` API.
///
/// Only the non-secret request parameters live here (the three ARNs + optional knobs). The
/// certificate and private key are NOT paths and NOT in `credentials.toml`: `bootstrap` ingests
/// the PEMs and stores the private key encrypted (`ra_key.enc`) via [`EncryptionService`], the
/// same at-rest protection SSO/IAM-user secrets get — hardware-bound whenever the storage backend
/// is keychain/credential-manager/tpm. The key is decrypted in memory only at renew time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolesAnywhereConfig {
    pub trust_anchor_arn: String,
    pub profile_arn: String,
    pub role_arn: String,
    /// Region override. When omitted, the region is derived from the trust anchor ARN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_session_name: Option<String>,
    /// Override the CreateSession endpoint (required for non-commercial partitions: the crate's
    /// default host is `rolesanywhere.{region}.amazonaws.com`, commercial-`aws` only).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "https_endpoint_opt"
    )]
    pub endpoint_url: Option<String>,
    /// Who this credential is *for*. Controls the privilege lattice check at bootstrap.
    #[serde(default, skip_serializing_if = "is_default_identity")]
    pub identity_type: IdentityType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SdkSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_fips_endpoint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_dualstack_endpoint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_bundle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_attempts: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defaults_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sts_regional_endpoints: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_us_east_1_regional_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_request_compression: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_min_compression_size_bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_validation: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_configured_endpoint_urls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_ua_app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id_endpoint_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CliSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pager: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_timestamp_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_binary_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_follow_urlparam: Option<bool>,
}

/// An env: an ordered set of credentials to compose, plus the environment to hand a
/// subprocess.
///
/// A `credential` is the addressable atom — a `credentials.toml` entry (see
/// [`credentials::CredentialSource`]). An env references one or more; the **first** is the
/// env's default (the ambient identity a bare `aws` call uses), and every credential is also
/// reachable by name. Several envs may reference the same credential, which is how "same
/// login, different region" is expressed.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnvConfig {
    /// The credentials this env composes, in order. The first is the default. Empty means
    /// "a single credential named after the env" (the 1:1 shape `credsd bootstrap` writes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<String>,
    /// Legacy singular form (`credential = "x"`). Deserialize-only, folded into
    /// [`EnvConfig::credential_list`]; never re-serialized (the canonical form is
    /// `credentials`). Keeps pre-multi-credential config.toml files loading.
    #[serde(default, skip_serializing)]
    pub credential: Option<String>,
    /// Absent means `Human`, so a config written before this key existed keeps working. The
    /// escalation that absence would otherwise permit is closed at the write path instead:
    /// `identity_type` cannot be unset (see [`keys::is_unset_protected`]).
    #[serde(default, skip_serializing_if = "is_default_identity")]
    pub identity_type: IdentityType,
    /// Projections this env declares for the credentials it composes, overriding whatever each
    /// credential declares for itself. Keyed by credential name.
    ///
    /// A declaration is `<type>[:<address>]`, so this level can state a projection's address as well
    /// as its type. A map to the bare type could not: an address-bearing value would read as an
    /// unrecognised type under that enum's leniency, and the credential would be refused for a fault
    /// the user did not commit.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub projections: std::collections::BTreeMap<String, crate::projection::ProjectionDecl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk: Option<SdkSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli: Option<CliSettings>,
}

impl EnvConfig {
    /// The ordered credential list this env resolves. Precedence: explicit `credentials`
    /// list, else the legacy singular `credential`, else a one-element list of the env's own
    /// name (the bootstrap 1:1 default).
    pub fn credential_list(&self, env_name: &str) -> Vec<String> {
        if !self.credentials.is_empty() {
            self.credentials.clone()
        } else if let Some(ref c) = self.credential {
            vec![c.clone()]
        } else {
            vec![env_name.to_string()]
        }
    }

    /// The env's default credential — the first in [`EnvConfig::credential_list`]. This is the
    /// ambient identity served on the container endpoint and written as `[default]`.
    pub fn default_credential(&self, env_name: &str) -> String {
        // credential_list is never empty by construction.
        self.credential_list(env_name)
            .into_iter()
            .next()
            .unwrap_or_else(|| env_name.to_string())
    }
}

fn is_default_identity(t: &IdentityType) -> bool {
    *t == IdentityType::Human
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogConfig {
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub file: Option<PathBuf>,
}

/// Caller-verification settings. Increment 1 classifies and logs only — none of this
/// denies a request; see the `caller-verification-policy` spec.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    /// Binary names classified as agentic when found in a caller's lineage. Empty (the
    /// default) uses the built-in set; any non-empty list replaces it outright, so an
    /// operator can narrow as well as extend.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_binaries: Vec<String>,
}

impl AuthConfig {
    /// The effective allowlist: the configured one, or the built-in default set.
    ///
    /// Returning a borrowed slice keeps the built-in list from being cloned on every
    /// request. The default is deliberately best-effort — see [`DEFAULT_AGENT_BINARIES`]
    /// for what it cannot catch.
    pub fn agent_binaries(&self) -> &[String] {
        if self.agent_binaries.is_empty() {
            default_agent_binaries()
        } else {
            &self.agent_binaries
        }
    }
}

/// Binary names treated as agentic runtimes when found in a caller's ancestry.
/// Matched against the file stem only, so an agent installed anywhere is caught.
///
/// **Best-effort, and it misses whole classes of agent.** The kernel reports the
/// *interpreter* a process is executing, not the script it was launched from, so an
/// agent distributed as a shell, Node, or Python entrypoint appears in the chain as
/// `bash`, `node`, or `Python` — a name that is not on this list and must not be, since
/// adding it would match every unrelated Node or Python process on the host and bury the
/// signal. Verified on this codebase's own dev machine: `claude` (a Mach-O binary)
/// matches, while `q` and `kiro` are `#!/bin/sh` and `#!/usr/bin/env bash` wrappers that
/// do not. Only compiled agents match reliably today.
///
/// That is survivable because a miss is recoverable after the fact: the audit record
/// carries the *entire* ancestry, every node's path and `comm` included, so an agent this
/// list failed to name can still be identified from the logs and the list corrected
/// (`[auth] agent_binaries`) without a release. Requirement 7.10's graduation to
/// code-signature identity is the real fix.
///
/// A false positive here costs one mislabeled audit line while nothing is being denied.
/// That asymmetry **inverts** once enforcement lands, so this list must be re-examined
/// before Increment 2 rather than inherited.
///
/// Lives here in `credsd-core`, next to [`AuthConfig`], rather than in the daemon's
/// classifier: `AuthConfig::agent_binaries` needs the default, and a core type must not
/// reach into daemon (`server/`) code for it.
const DEFAULT_AGENT_BINARIES: &[&str] = &[
    // Verified against real installs.
    "claude",
    "kiro-cli", // the binary behind both the `q` and `kiro` wrappers
    "kiro",
    // Expected names, not verified here.
    "codex",
    "cursor-agent",
    "cursor",
    "aider",
    "gemini",
    "goose",
    "opencode",
    "amazonq",
    "windsurf",
    "cline",
    "continue",
    "copilot",
    "amp",
    "crush",
    "droid",
    "devin",
];

/// The built-in allowlist, owned so it can back a `&[String]` without allocating per
/// request. `q` is deliberately absent: it is a wrapper that execs `kiro-cli`, so the
/// entry would match no real process, while a one-character stem risks matching any
/// unrelated binary named `q`.
pub fn default_agent_binaries() -> &'static [String] {
    static DEFAULTS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    DEFAULTS.get_or_init(|| {
        DEFAULT_AGENT_BINARIES
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    })
}

/// Top-level daemon configuration parsed from config.toml.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DaemonConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<PathBuf>,
    #[serde(default)]
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default, rename = "environments")]
    pub envs: HashMap<String, EnvConfig>,
}

/// Keys that configured removed or unsupported features. Ignored with a warning rather
/// than rejected, so an existing config.toml keeps loading after the upgrade.
/// - `port`, `transport_mode`: configured the removed persistent TCP listener.
/// - `storage_backend`: never had any effect; the daemon always uses its built-in store.
const OBSOLETE_KEYS: &[&str] = &["port", "transport_mode", "storage_backend"];

fn warn_obsolete_keys(content: &str) {
    let Ok(doc) = content.parse::<DocumentMut>() else {
        return;
    };
    for key in OBSOLETE_KEYS {
        if doc.contains_key(key) {
            tracing::warn!(
                key = *key,
                "ignoring unsupported config key; it has no effect and can be removed"
            );
        }
    }
}

impl DaemonConfig {
    pub fn load() -> Result<Self> {
        Ok(Self::load_with_credentials()?.0)
    }

    /// Load `config.toml` and `credentials.toml` together.
    ///
    /// The two are validated as a unit because an env naming a missing credential is only
    /// detectable across both files. Callers that need the credentials (to build providers,
    /// or to report a credential's type) take them from here rather than loading twice.
    pub fn load_with_credentials() -> Result<(Self, CredentialSources)> {
        Self::load_from(&platform::config_dir())
    }

    /// Load config for the current OS user from `callers/<uid>/` under the daemon's data root.
    /// This is the correct call for any client-side code (exec, env, list) that needs the
    /// caller-scoped config — it avoids reading from the old global config path.
    #[cfg(unix)]
    pub fn load_for_current_user() -> Result<(Self, CredentialSources)> {
        let uid = nix::unistd::getuid().as_raw();
        Self::load_from(&platform::caller_root(uid))
    }

    #[cfg(not(unix))]
    pub fn load_for_current_user() -> Result<(Self, CredentialSources)> {
        Self::load_with_credentials()
    }

    /// Load config and credentials from an explicit directory (for per-caller scoped loading).
    /// Returns `(Self::default(), empty_credentials)` when the directory exists but has no config.
    pub fn load_from(dir: &std::path::Path) -> Result<(Self, CredentialSources)> {
        let (config, credentials) = Self::parse_from(dir)?;
        if let Err(errors) = config.validate(&credentials) {
            return Err(DaemonError::config(errors.join("\n")));
        }
        Ok((config, credentials))
    }

    /// [`load_from`](Self::load_from) without validating config against credentials. The drift
    /// check canonicalizes this, so a file that parses but does not validate is checked against
    /// its snapshot rather than read as drift.
    pub fn parse_from(dir: &std::path::Path) -> Result<(Self, CredentialSources)> {
        let creds_path = dir.join("credentials.toml");
        let credentials = credentials::load_from(&creds_path)?;

        let config_path = dir.join("config.toml");
        let Some(content) = read_if_present(&config_path)? else {
            return Ok((Self::default(), credentials));
        };
        warn_if_permissive(&config_path);
        warn_obsolete_keys(&content);
        let config = Self::from_text(&content).map_err(|e| {
            DaemonError::config(format!(
                "{}: parse error at {}",
                config_path.display(),
                located(e.span(), &content)
            ))
        })?;
        Ok((config, credentials))
    }

    /// Parse `content` as a `config.toml` without validating it against credentials. Used to
    /// seal exactly the text just written, not a re-read of the file.
    pub fn from_text(content: &str) -> std::result::Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    pub fn validate(
        &self,
        credentials: &CredentialSources,
    ) -> std::result::Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if let Some(ref path) = self.socket_path {
            if !path.is_absolute() {
                errors.push(format!(
                    "socket_path must be an absolute path, got '{}'",
                    path.display()
                ));
            }
        }

        if let Some(ref log) = self.log {
            if let Some(ref level) = log.level {
                const VALID_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];
                if !VALID_LEVELS.contains(&level.as_str()) {
                    errors.push(format!(
                        "invalid log.level: '{}' (expected one of: error, warn, info, debug, trace)",
                        level
                    ));
                }
            }
            if let Some(ref format) = log.format {
                const VALID_FORMATS: &[&str] = &["text", "json"];
                if !VALID_FORMATS.contains(&format.as_str()) {
                    errors.push(format!(
                        "invalid log.format: '{}' (expected one of: text, json)",
                        format
                    ));
                }
            }
        }

        for (name, env) in &self.envs {
            if let Err(e) = credentials::validate_name(name) {
                errors.push(format!("invalid env name: {}", e));
            }

            for credential in env.credential_list(name) {
                if !credentials.contains_key(&credential) {
                    errors.push(format!(
                        "env '{}' references credential '{}', which is not defined in {}",
                        name,
                        credential,
                        credentials::credentials_path().display()
                    ));
                } else if let Some(source) = credentials.get(&credential) {
                    let cred_identity = source.identity_type();
                    if !env.identity_type.may_access(cred_identity) {
                        errors.push(format!(
                            "env '{}' ({}) may not compose credential '{}' ({}): \
                             privilege lattice violation",
                            name, env.identity_type, credential, cred_identity
                        ));
                    }
                }
            }

            if env.identity_type == IdentityType::Agent {
                tracing::warn!(
                    "env '{}': agent identity has no scoping — credentials will \
                     have full role permissions (scoped credentials not yet available)",
                    name
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content =
            toml::to_string_pretty(self).map_err(|e| DaemonError::config(e.to_string()))?;
        write_config_file(&path, &content)
    }

    /// Insert or update an env in config.toml, preserving comments and formatting.
    /// Validates the resulting config before writing; returns an error if invalid.
    pub fn save_env(name: &str, env: &EnvConfig) -> Result<()> {
        credentials::validate_name(name)?;
        let credentials = credentials::load()?;

        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut doc = load_document(&path)?;
        upsert_env_in_doc(&mut doc, name, env)?;

        let text = doc.to_string();
        let candidate: DaemonConfig = toml::from_str(&text).map_err(|e| {
            DaemonError::config(format!(
                "invalid config after edit: parse error at {}",
                located(e.span(), &text)
            ))
        })?;
        if let Err(errors) = candidate.validate(&credentials) {
            return Err(DaemonError::config(errors.join("\n")));
        }

        write_config_file(&path, &doc.to_string())
    }

    /// Insert or update an env in `checked`, the bytes the caller verified, and write the result
    /// to `config_path`. Returns the written text. Edits `checked`, not a fresh read: the caller
    /// confirms the file still holds `checked` before calling, and this function does not
    /// re-verify it.
    pub fn save_env_in(
        config_path: &std::path::Path,
        checked: &str,
        name: &str,
        env: &EnvConfig,
    ) -> Result<String> {
        credentials::validate_name(name)?;
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut doc = checked
            .parse::<DocumentMut>()
            .map_err(|e| DaemonError::config(format!("invalid config: {}", e)))?;
        upsert_env_in_doc(&mut doc, name, env)?;
        let written = doc.to_string();
        write_config_file(config_path, &written)?;
        Ok(written)
    }

    /// Every env that references `credential`, sorted.
    ///
    /// The N:many relationship makes this the test for whether a credential is still live:
    /// removing one of several envs that reference it must not revoke the login.
    pub fn envs_using(&self, credential: &str) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .envs
            .iter()
            .filter(|(name, env)| env.credential_list(name).iter().any(|c| c == credential))
            .map(|(name, _)| name.as_str())
            .collect();
        names.sort_unstable();
        names
    }

    pub fn config_path() -> PathBuf {
        platform::config_dir().join("config.toml")
    }

    /// The socket to bind or dial: `CREDSD_SOCKET`, then the `socket_path` key, then the
    /// platform default. One source of truth for both `serve` and every client.
    pub fn effective_socket_path(&self) -> PathBuf {
        platform::socket_path_from_env()
            .or_else(|| self.socket_path.clone())
            .unwrap_or_else(platform::default_socket_path)
    }
}

/// Write a config file atomically, at mode `0600`, so a reader or a crash mid-write never
/// sees a partial file.
///
/// `truncate`-then-write leaves a window where the path holds neither the old content nor
/// the new: a crash, a kill, or a concurrent reader during that window finds an empty or
/// half-written file. Writing the full content to a temp file in the same directory, then
/// renaming it over `path`, replaces the directory entry in one syscall — any observer sees
/// either the complete old file or the complete new one. The temp file is created in `path`'s
/// own directory so the rename stays on one filesystem (`rename` cannot cross filesystems).
pub fn write_config_file(path: &std::path::Path, content: &str) -> Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(content.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    // The rename is atomic for a reader, but not yet durable: until the directory entry
    // reaches disk, a power loss can lose the rename and restore the old content. Syncing
    // the directory commits the new entry. Unix only — Windows cannot open a directory.
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Read a config file that is allowed not to exist, keeping "absent" distinct from
/// "present but unreadable".
///
/// The distinction is load-bearing, not cosmetic. Under a system install the daemon owns
/// `callers/<uid>/` at 0700, so a `Path::exists()` probe by any other uid answers `false` for
/// a file that is very much there — turning EACCES into "not configured" and a failed read
/// into a silent empty config. One `read_to_string` and a match on `NotFound` cannot make
/// that mistake, and closes the exists-then-read race as a side effect.
pub(crate) fn read_if_present(path: &std::path::Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(DaemonError::config(format!(
            "cannot read {}: {}",
            path.display(),
            e
        ))),
    }
}

/// Warn when a config file is readable beyond its owner. Never refuses to load — the
/// user may have deliberate reasons.
#[cfg(unix)]
pub(crate) fn warn_if_permissive(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode),
                "file has permissive permissions (expected 0600)",
            );
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn warn_if_permissive(_path: &std::path::Path) {}

pub fn ensure_config_dir() -> Result<PathBuf> {
    let dir = platform::config_dir();
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub(crate) fn load_document(path: &std::path::Path) -> Result<DocumentMut> {
    match read_if_present(path)? {
        Some(content) => content.parse::<DocumentMut>().map_err(|e| {
            DaemonError::config(format!(
                "failed to parse {}: parse error at {}",
                path.display(),
                located(e.span(), &content)
            ))
        }),
        None => Ok(DocumentMut::new()),
    }
}

/// Where a TOML parse error sits, as a line and column. The parser's own message quotes the
/// offending source line and serde's quotes values, so a secret pasted into the wrong file would
/// reach the caller through either. Nothing from `text` is quoted here.
pub fn located(span: Option<std::ops::Range<usize>>, text: &str) -> String {
    let Some(span) = span else {
        return "unknown position".to_owned();
    };
    let before = text.as_bytes().get(..span.start).unwrap_or(text.as_bytes());
    let line = before
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        .saturating_add(1);
    let line_start = before
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i.saturating_add(1));
    // Count characters, not bytes, so a multibyte character earlier on the line does not
    // shift the column.
    // Count characters, not bytes, so a multibyte character earlier on the line does not
    // shift the column.
    let column = String::from_utf8_lossy(before.get(line_start..).unwrap_or_default())
        .chars()
        .count()
        .saturating_add(1);
    format!("line {line}, column {column}")
}

/// Insert or update an env in a document (testable without filesystem).
fn upsert_env_in_doc(doc: &mut DocumentMut, name: &str, env: &EnvConfig) -> Result<()> {
    if !doc.contains_key("environments") {
        // Implicit on the *parent*: `[environments]` is omitted in favor of the
        // `[environments.<name>]` headers below it. Setting it on the env table instead
        // omits that env's own header, so an env whose every field is defaulted
        // renders as a bare `[environments]` and reads back as absent.
        let mut parent = Table::new();
        parent.set_implicit(true);
        doc["environments"] = Item::Table(parent);
    }

    let envs = doc["environments"]
        .as_table_mut()
        .ok_or_else(|| DaemonError::config("'environments' is not a table in config.toml"))?;

    let serialized = toml_edit::ser::to_document(env)
        .map_err(|e| DaemonError::config(format!("failed to serialize env: {}", e)))?;

    envs.insert(name, Item::Table(serialized.into_table()));
    Ok(())
}

/// Remove an env from a document (testable without filesystem).
fn remove_env_from_doc(doc: &mut DocumentMut, name: &str) -> bool {
    doc.get_mut("environments")
        .and_then(|i| i.as_table_mut())
        .is_some_and(|envs| envs.remove(name).is_some())
}

/// Set a single key on an env in config.toml, preserving comments and formatting.
pub fn set_env_key(env: &str, key_def: &keys::ConfigKeyDef, val: toml_edit::Value) -> Result<()> {
    let path = DaemonConfig::config_path();
    let mut doc = load_document(&path)?;

    let env_tbl = get_env_table_mut(&mut doc, env)?;

    match key_def.section {
        None => {
            set_value_preserving_decor(env_tbl, key_def.field, val);
        }
        Some(section) => {
            if !env_tbl.contains_key(section) {
                env_tbl.insert(section, Item::Table(Table::new()));
            }
            promote_inline_table(env_tbl, section);
            let section_tbl = env_tbl
                .get_mut(section)
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| {
                    DaemonError::config(format!("'{}' is not a table in env '{}'", section, env))
                })?;
            set_value_preserving_decor(section_tbl, key_def.field, val);
        }
    }

    write_config_file(&path, &doc.to_string())
}

fn promote_inline_table(parent: &mut Table, key: &str) {
    let inline = parent
        .get(key)
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_inline_table())
        .cloned();
    if let Some(inline) = inline {
        let mut tbl = inline.into_table();
        tbl.set_implicit(true);
        parent.insert(key, Item::Table(tbl));
    }
}

fn set_value_preserving_decor(table: &mut Table, field: &str, val: toml_edit::Value) {
    if let Some(existing) = table.get_mut(field).and_then(|i| i.as_value_mut()) {
        let decor = existing.decor().clone();
        *existing = val;
        *existing.decor_mut() = decor;
    } else {
        table.insert(field, Item::Value(val));
    }
}

/// Get a single key's value from an env, returned as a formatted string.
pub fn get_env_key(env: &str, key_def: &keys::ConfigKeyDef) -> Result<Option<String>> {
    let path = DaemonConfig::config_path();
    if !path.exists() {
        return Err(DaemonError::config(format!(
            "env '{}' not found. Run 'credsd bootstrap' first.",
            env
        )));
    }
    let doc = load_document(&path)?;

    let envs = doc.get("environments").ok_or_else(|| {
        DaemonError::config(format!(
            "env '{}' not found. Run 'credsd bootstrap' first.",
            env
        ))
    })?;
    let env_item = envs.get(env).ok_or_else(|| {
        DaemonError::config(format!(
            "env '{}' not found. Run 'credsd bootstrap' first.",
            env
        ))
    })?;

    let item = match key_def.section {
        None => env_item.get(key_def.field),
        Some(section) => env_item.get(section).and_then(|s| s.get(key_def.field)),
    };

    Ok(item.and_then(|i| i.as_value()).map(format_value))
}

/// Remove a single key from an env. Idempotent — missing keys are not an error.
pub fn unset_env_key(env: &str, key_def: &keys::ConfigKeyDef) -> Result<()> {
    let path = DaemonConfig::config_path();
    let mut doc = load_document(&path)?;

    let env_tbl = get_env_table_mut(&mut doc, env)?;

    match key_def.section {
        None => {
            env_tbl.remove(key_def.field);
        }
        Some(section) => {
            promote_inline_table(env_tbl, section);
            if let Some(section_tbl) = env_tbl.get_mut(section).and_then(|i| i.as_table_mut()) {
                section_tbl.remove(key_def.field);
                if section_tbl.is_empty() {
                    env_tbl.remove(section);
                }
            }
        }
    }

    write_config_file(&path, &doc.to_string())
}

/// Path-parameterized variants of the key/env mutation helpers for daemon-side, caller-scoped
/// writes where the caller root is `callers/<uid>/` rather than the global `config_dir`.
pub fn get_env_key_at(
    config_path: &std::path::Path,
    env: &str,
    key_def: &keys::ConfigKeyDef,
) -> Result<Option<String>> {
    let path = config_path.to_path_buf();
    if !path.exists() {
        return Err(DaemonError::config(format!(
            "env '{}' not found. Run 'credsd bootstrap' first.",
            env
        )));
    }
    let doc = load_document(&path)?;
    let envs = doc.get("environments").ok_or_else(|| {
        DaemonError::config(format!(
            "env '{}' not found. Run 'credsd bootstrap' first.",
            env
        ))
    })?;
    let env_item = envs.get(env).ok_or_else(|| {
        DaemonError::config(format!(
            "env '{}' not found. Run 'credsd bootstrap' first.",
            env
        ))
    })?;
    let item = match key_def.section {
        None => env_item.get(key_def.field),
        Some(s) => env_item.get(s).and_then(|sec| sec.get(key_def.field)),
    };
    Ok(item.and_then(|i| i.as_value()).map(format_value))
}

/// Set `key_def` in env `env` on `checked`, returning the edited text. Takes no path and writes
/// nothing: the caller verified these bytes and decides when the result is fit to write, so a
/// function that cannot open the file cannot edit a different version of it than was checked.
pub fn set_env_key_in(
    checked: &str,
    env: &str,
    key_def: &keys::ConfigKeyDef,
    val: toml_edit::Value,
) -> Result<String> {
    let mut doc = checked
        .parse::<DocumentMut>()
        .map_err(|e| DaemonError::config(format!("failed to parse config: {}", e)))?;
    let env_tbl = get_env_table_mut(&mut doc, env)?;
    match key_def.section {
        None => set_value_preserving_decor(env_tbl, key_def.field, val),
        Some(section) => {
            if !env_tbl.contains_key(section) {
                env_tbl.insert(section, Item::Table(toml_edit::Table::new()));
            }
            promote_inline_table(env_tbl, section);
            let section_tbl = env_tbl
                .get_mut(section)
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| {
                    DaemonError::config(format!("'{}' is not a table in env '{}'", section, env))
                })?;
            set_value_preserving_decor(section_tbl, key_def.field, val);
        }
    }
    Ok(doc.to_string())
}

/// Unset `key_def` in env `env` on `checked`, returning the edited text. See [`set_env_key_in`].
pub fn unset_env_key_in(checked: &str, env: &str, key_def: &keys::ConfigKeyDef) -> Result<String> {
    let mut doc = checked
        .parse::<DocumentMut>()
        .map_err(|e| DaemonError::config(format!("failed to parse config: {}", e)))?;
    let env_tbl = get_env_table_mut(&mut doc, env)?;
    match key_def.section {
        None => {
            env_tbl.remove(key_def.field);
        }
        Some(section) => {
            promote_inline_table(env_tbl, section);
            if let Some(section_tbl) = env_tbl.get_mut(section).and_then(|i| i.as_table_mut()) {
                section_tbl.remove(key_def.field);
                if section_tbl.is_empty() {
                    env_tbl.remove(section);
                }
            }
        }
    }
    Ok(doc.to_string())
}

/// Remove env `name` from `checked`, the bytes the caller verified, and write the result to
/// `config_path`. Returns the written text, or `None` (writing nothing) when there was no such
/// env. Edits `checked`, not a fresh read: the caller confirms the file still holds `checked`
/// before calling, and this function does not re-verify it.
pub fn remove_env_from(
    config_path: &std::path::Path,
    checked: &str,
    name: &str,
) -> Result<Option<String>> {
    let mut doc = checked.parse::<DocumentMut>().map_err(|e| {
        DaemonError::config(format!(
            "failed to parse config: parse error at {}",
            located(e.span(), checked)
        ))
    })?;
    if !remove_env_from_doc(&mut doc, name) {
        return Ok(None);
    }
    let written = doc.to_string();
    write_config_file(config_path, &written)?;
    Ok(Some(written))
}

fn get_env_table_mut<'a>(doc: &'a mut DocumentMut, env: &str) -> Result<&'a mut Table> {
    let envs = doc
        .get_mut("environments")
        .and_then(|i| i.as_table_mut())
        .ok_or_else(|| {
            DaemonError::config(format!(
                "env '{}' not found. Run 'credsd bootstrap' first.",
                env
            ))
        })?;

    envs.get_mut(env)
        .and_then(|i| i.as_table_mut())
        .ok_or_else(|| {
            DaemonError::config(format!(
                "env '{}' not found. Run 'credsd bootstrap' first.",
                env
            ))
        })
}

/// Collect (env_var_name, value) pairs for all config keys that have an `env_var` mapping set.
///
/// Takes the env's settings rather than its name, and so reads no file. The name-and-reread
/// form had to open `config.toml` — which under a system install belongs to the daemon and is
/// unreadable by the client that calls this — and returned an empty set on failure, so a
/// caller's `AWS_*` overrides silently went missing. Every caller already holds the settings
/// (from config, or from a `profile/describe` projection).
///
/// The traversal stays generic over [`keys::ALLOWED_KEYS`] rather than reading fields off
/// [`EnvConfig`] directly: that table is what defines which keys have an env-var spelling at
/// all, and a hand-written field list here would be a second place to add a key to.
pub fn resolve_env_vars(env: Option<&EnvConfig>) -> Vec<(&'static str, String)> {
    let Some(env) = env else {
        return Vec::new();
    };
    let env_item = match toml_edit::ser::to_document(env) {
        Ok(doc) => doc,
        Err(_) => return Vec::new(),
    };

    keys::ALLOWED_KEYS
        .iter()
        .filter_map(|k| {
            let env_var = k.env_var?;
            let item = match k.section {
                None => env_item.get(k.field),
                Some(section) => env_item.get(section).and_then(|s| s.get(k.field)),
            };
            let val = item.and_then(|i| i.as_value()).map(format_value)?;
            Some((env_var, val))
        })
        .collect()
}

pub(crate) fn format_value(v: &toml_edit::Value) -> String {
    match v {
        toml_edit::Value::String(s) => s.value().to_string(),
        toml_edit::Value::Integer(i) => i.value().to_string(),
        toml_edit::Value::Boolean(b) => b.value().to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toml_edit::value;

    #[test]
    fn aws_web_identity_rejects_the_removed_mode_key() {
        // `mode = "token"` was removed with the token path. Without deny_unknown_fields serde
        // drops it silently and the entry federates, which is the opposite of what the user wrote.
        let text = "role_arn = \"arn:aws:iam::123456789012:role/r\"\nmode = \"token\"\n";
        let err = toml::from_str::<AwsWebIdentityConfig>(text).unwrap_err();
        assert!(
            err.to_string().contains("unknown field `mode`"),
            "error should name the removed key: {err}"
        );
    }

    #[test]
    fn aws_web_identity_accepts_its_documented_keys() {
        let text = "role_arn = \"arn:aws:iam::123456789012:role/r\"\nregion = \"us-west-2\"\n";
        let config: AwsWebIdentityConfig = toml::from_str(text).unwrap();
        assert_eq!(config.region, "us-west-2");
    }

    #[test]
    fn aws_web_identity_config_requires_region() {
        let text = "role_arn = \"arn:aws:iam::123456789012:role/r\"\n";
        let err = toml::from_str::<AwsWebIdentityConfig>(text).unwrap_err();
        assert!(
            err.to_string().contains("missing field `region`"),
            "error should name the missing key: {err}"
        );
    }

    #[test]
    fn aws_login_config_requires_region() {
        let err = toml::from_str::<AwsLoginConfig>("remote = true\n").unwrap_err();
        assert!(
            err.to_string().contains("missing field `region`"),
            "error should name the missing key: {err}"
        );
    }

    #[test]
    fn located_counts_columns_in_characters_not_bytes() {
        // "é" is two bytes. The second `=` is character 9 on the line (column 9); the old byte
        // count would report column 10.
        let text = "a = \"é\" = 1";
        let at = text.find("= 1").unwrap();
        assert_eq!(located(Some(at..at + 1), text), "line 1, column 9");
    }

    #[test]
    fn a_parse_error_names_its_position_and_never_quotes_the_text() {
        let text = "[envs]\nsecret = \"sk-planted\n";
        let err = DaemonConfig::from_text(text).expect_err("unterminated string");
        let at = located(err.span(), text);
        assert!(at.starts_with("line 2, column "), "{at}");
        assert!(!at.contains("sk-planted"), "{at}");
    }

    #[test]
    fn the_default_allowlist_is_not_empty() {
        // An empty `[auth] agent_binaries` falls back to this; if it were empty the
        // classifier would silently match nothing at all.
        assert!(!default_agent_binaries().is_empty());
        assert!(default_agent_binaries()
            .iter()
            .all(|b| b == &b.to_lowercase()));
    }

    const CONFIG_WITH_COMMENTS: &str = r#"# Global daemon settings
port = 9765

# My production env
[environments.prod]
region = "us-east-1"

# Development env for testing
[environments.dev]
credential = "shared-login"
identity_type = "agent"
region = "us-west-2"
"#;

    fn sample_env() -> EnvConfig {
        EnvConfig {
            region: Some("eu-west-1".to_string()),
            ..Default::default()
        }
    }

    /// A credentials map covering every credential `CONFIG_WITH_COMMENTS` and `sample_env`
    /// can resolve to, so cross-file validation passes for any combination of them.
    fn sample_credential_sources() -> CredentialSources {
        sources_named("prod", IdentityType::Human)
            .into_iter()
            .chain(
                ["dev", "shared-login", "staging", "first", "new"]
                    .into_iter()
                    .map(|n| {
                        (
                            n.to_string(),
                            credentials::CredentialSource::AwsIdcSso(SsoConfig {
                                start_url: "https://myorg.awsapps.com/start".to_string(),
                                sso_region: "us-east-1".to_string(),
                                account_id: "111111111111".to_string(),
                                role_name: "AdminRole".to_string(),
                                identity_type: IdentityType::Human,
                            }),
                        )
                    }),
            )
            .collect()
    }

    fn sources_named(name: &str, identity_type: IdentityType) -> CredentialSources {
        [(
            name.to_string(),
            credentials::CredentialSource::AwsIdcSso(SsoConfig {
                start_url: "https://myorg.awsapps.com/start".to_string(),
                sso_region: "us-east-1".to_string(),
                account_id: "111111111111".to_string(),
                role_name: "AdminRole".to_string(),
                identity_type,
            }),
        )]
        .into_iter()
        .collect()
    }

    /// Exhaustive over the lattice: every (env, credential) pair, including the unparseable
    /// `Unknown` tier on both sides, checked against three independently-stated rules rather
    /// than a handful of examples — the pair space is small enough to cover completely.
    /// `Unknown` is not a rank in a total order: as a credential it's reachable only by the
    /// single most-trusted env (`Human`); as an env it behaves like the least-trusted (`Agent`).
    #[test]
    fn may_access_follows_the_privilege_lattice_for_every_pair() {
        let all = [
            IdentityType::Agent,
            IdentityType::Automation,
            IdentityType::Human,
            IdentityType::Unknown,
        ];
        for env in all {
            for credential in all {
                let expected = credential == IdentityType::Agent
                    || env == IdentityType::Human
                    || (env == IdentityType::Automation && credential == IdentityType::Automation);
                assert_eq!(
                    env.may_access(credential),
                    expected,
                    "env={env:?} credential={credential:?}"
                );
            }
        }
    }

    /// The regression this whole test guards: a credential with an unrecognised identity_type
    /// must not be served to Agent or Automation envs, even though Agent credentials are.
    #[test]
    fn unknown_credential_is_not_served_to_low_privilege_envs() {
        assert!(!IdentityType::Agent.may_access(IdentityType::Unknown));
        assert!(!IdentityType::Automation.may_access(IdentityType::Unknown));
        assert!(IdentityType::Human.may_access(IdentityType::Unknown));
    }

    #[test]
    fn save_env_preserves_comments() {
        let mut doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        upsert_env_in_doc(&mut doc, "staging", &sample_env()).unwrap();
        let output = doc.to_string();

        assert!(output.contains("# Global daemon settings"));
        assert!(output.contains("# My production env"));
        assert!(output.contains("# Development env for testing"));
        assert!(output.contains("[environments.staging]"));
        assert!(output.contains("region = \"eu-west-1\""));
    }

    #[test]
    fn save_env_does_not_disturb_existing_envs() {
        let mut doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        upsert_env_in_doc(&mut doc, "staging", &sample_env()).unwrap();
        let output = doc.to_string();

        // Existing envs still parseable
        let config: DaemonConfig = toml::from_str(&output).unwrap();
        assert_eq!(config.envs["prod"].region.as_deref(), Some("us-east-1"));
        assert_eq!(config.envs["dev"].identity_type, IdentityType::Agent);
        assert_eq!(config.envs["staging"].region.as_deref(), Some("eu-west-1"));
    }

    /// Pre-launch: the old `[profiles.*]` and `[envs.*]` tables are no longer accepted.
    /// Loading them deserializes to an empty set — the alias was dropped with the rename.
    #[test]
    fn legacy_profiles_section_no_longer_loads() {
        let legacy_profiles = "[profiles.old]\ncredential = \"c\"\n";
        let config: DaemonConfig = toml::from_str(legacy_profiles).unwrap();
        assert!(
            config.envs.is_empty(),
            "legacy [profiles.*] must not load into envs; got {:?}",
            config.envs
        );

        let legacy_envs = "[envs.old]\ncredential = \"c\"\n";
        let config: DaemonConfig = toml::from_str(legacy_envs).unwrap();
        assert!(
            config.envs.is_empty(),
            "legacy [envs.*] must not load into envs; got {:?}",
            config.envs
        );
    }

    #[test]
    fn remove_env_preserves_comments() {
        let mut doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        remove_env_from_doc(&mut doc, "dev");
        let output = doc.to_string();

        assert!(output.contains("# Global daemon settings"));
        assert!(output.contains("# My production env"));
        assert!(!output.contains("[environments.dev]"));
        assert!(!output.contains("shared-login"));
    }

    #[test]
    fn remove_env_leaves_other_envs_intact() {
        let mut doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        remove_env_from_doc(&mut doc, "dev");
        let output = doc.to_string();

        let config: DaemonConfig = toml::from_str(&output).unwrap();
        assert!(config.envs.contains_key("prod"));
        assert!(!config.envs.contains_key("dev"));
    }

    #[test]
    fn save_env_to_empty_document() {
        let mut doc = DocumentMut::new();
        upsert_env_in_doc(&mut doc, "first", &sample_env()).unwrap();
        let output = doc.to_string();

        let config: DaemonConfig = toml::from_str(&output).unwrap();
        assert_eq!(config.envs.len(), 1);
        assert_eq!(config.envs["first"].region.as_deref(), Some("eu-west-1"));
    }

    /// Every `EnvConfig` field is `skip_serializing_if`, so an all-defaults env
    /// serializes to an empty table. That table must still get a `[environments.<name>]`
    /// header — without one the env renders as a bare `[environments]` and reads back
    /// as absent, so adding the env appears to succeed and adds nothing.
    #[test]
    fn save_env_with_only_default_fields_survives_a_round_trip() {
        let mut doc = DocumentMut::new();
        upsert_env_in_doc(&mut doc, "bare", &EnvConfig::default()).unwrap();
        let output = doc.to_string();

        assert!(
            output.contains("[environments.bare]"),
            "expected an env header, got:\n{}",
            output
        );
        let config: DaemonConfig = toml::from_str(&output).unwrap();
        assert!(config.envs.contains_key("bare"), "env vanished");
    }

    #[test]
    fn save_env_overwrites_existing_env() {
        let mut doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        let updated = EnvConfig {
            credentials: vec!["shared-login".to_string()],
            identity_type: IdentityType::Automation,
            region: Some("ap-southeast-1".to_string()),
            ..Default::default()
        };
        upsert_env_in_doc(&mut doc, "prod", &updated).unwrap();
        let output = doc.to_string();

        let config: DaemonConfig = toml::from_str(&output).unwrap();
        assert_eq!(
            config.envs["prod"].credential_list("prod"),
            vec!["shared-login"]
        );
        assert_eq!(config.envs["prod"].identity_type, IdentityType::Automation);
        assert_eq!(
            config.envs["prod"].region.as_deref(),
            Some("ap-southeast-1")
        );
    }

    #[test]
    fn remove_nonexistent_env_is_noop() {
        let mut doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        remove_env_from_doc(&mut doc, "nonexistent");
        let output = doc.to_string();

        let config: DaemonConfig = toml::from_str(&output).unwrap();
        assert_eq!(config.envs.len(), 2);
    }

    #[test]
    fn round_trip_after_edits_still_parses() {
        let mut doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        upsert_env_in_doc(&mut doc, "new", &sample_env()).unwrap();
        remove_env_from_doc(&mut doc, "dev");
        let output = doc.to_string();

        let config: DaemonConfig = toml::from_str(&output).unwrap();
        assert!(config.envs.contains_key("new"));
        assert!(!config.envs.contains_key("dev"));
    }

    #[test]
    fn set_top_level_key_preserves_comments() {
        let mut doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("prod")
            .unwrap()
            .as_table_mut()
            .unwrap();
        env_tbl.insert(
            "region",
            Item::Value(value("us-west-2").into_value().unwrap()),
        );
        let output = doc.to_string();

        assert!(output.contains("# Global daemon settings"));
        assert!(output.contains("# My production env"));
        assert!(output.contains("region = \"us-west-2\""));
    }

    #[test]
    fn set_nested_key_creates_section() {
        let mut doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("prod")
            .unwrap()
            .as_table_mut()
            .unwrap();

        env_tbl.insert("sdk", Item::Table(Table::new()));
        let sdk = env_tbl.get_mut("sdk").unwrap().as_table_mut().unwrap();
        sdk.insert(
            "retry_mode",
            Item::Value(value("adaptive").into_value().unwrap()),
        );

        let output = doc.to_string();
        assert!(output.contains("retry_mode = \"adaptive\""));
    }

    #[test]
    fn set_nested_key_updates_existing() {
        let config_with_sdk = r#"port = 9765

[environments.prod]
mode = "sso"
region = "us-east-1"

[environments.prod.sdk]
retry_mode = "standard"
max_attempts = 3
"#;
        let mut doc: DocumentMut = config_with_sdk.parse().unwrap();
        let sdk = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("prod")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("sdk")
            .unwrap()
            .as_table_mut()
            .unwrap();
        sdk.insert(
            "retry_mode",
            Item::Value(value("adaptive").into_value().unwrap()),
        );

        let output = doc.to_string();
        assert!(output.contains("retry_mode = \"adaptive\""));
        assert!(output.contains("max_attempts = 3"));
    }

    #[test]
    fn unset_nested_key_removes_empty_section() {
        let config_with_sdk = r#"port = 9765

[environments.prod]
mode = "sso"
region = "us-east-1"

[environments.prod.sdk]
retry_mode = "adaptive"
"#;
        let mut doc: DocumentMut = config_with_sdk.parse().unwrap();
        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("prod")
            .unwrap()
            .as_table_mut()
            .unwrap();

        let sdk = env_tbl.get_mut("sdk").unwrap().as_table_mut().unwrap();
        sdk.remove("retry_mode");
        if sdk.is_empty() {
            env_tbl.remove("sdk");
        }

        let output = doc.to_string();
        assert!(!output.contains("[environments.prod.sdk]"));
        assert!(!output.contains("retry_mode"));
        assert!(output.contains("region = \"us-east-1\""));
    }

    #[test]
    fn unset_absent_key_is_noop() {
        let mut doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("prod")
            .unwrap()
            .as_table_mut()
            .unwrap();

        // Removing a key that doesn't exist is fine
        env_tbl.remove("nonexistent");
        let output = doc.to_string();
        assert_eq!(output, CONFIG_WITH_COMMENTS);
    }

    #[test]
    fn get_value_from_document() {
        let doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        let val = doc
            .get("environments")
            .and_then(|p| p.get("prod"))
            .and_then(|p| p.get("region"))
            .and_then(|i| i.as_value())
            .map(format_value);
        assert_eq!(val.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn get_absent_value_returns_none() {
        let doc: DocumentMut = CONFIG_WITH_COMMENTS.parse().unwrap();
        let val = doc
            .get("environments")
            .and_then(|p| p.get("prod"))
            .and_then(|p| p.get("sdk"))
            .and_then(|s| s.get("retry_mode"))
            .and_then(|i| i.as_value())
            .map(format_value);
        assert_eq!(val, None);
    }

    #[test]
    fn format_value_integer() {
        let v = value(42i64).into_value().unwrap();
        assert_eq!(format_value(&v), "42");
    }

    #[test]
    fn format_value_boolean() {
        let v = value(true).into_value().unwrap();
        assert_eq!(format_value(&v), "true");
    }

    #[test]
    fn format_value_string() {
        let v = value("hello").into_value().unwrap();
        assert_eq!(format_value(&v), "hello");
    }

    #[test]
    fn unset_nested_key_preserves_nonempty_section() {
        let config_with_sdk = r#"port = 9765

[environments.prod]
mode = "sso"
region = "us-east-1"

[environments.prod.sdk]
retry_mode = "adaptive"
max_attempts = 5
"#;
        let mut doc: DocumentMut = config_with_sdk.parse().unwrap();
        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("prod")
            .unwrap()
            .as_table_mut()
            .unwrap();

        let sdk = env_tbl.get_mut("sdk").unwrap().as_table_mut().unwrap();
        sdk.remove("retry_mode");
        // Section still has max_attempts, should NOT be removed
        assert!(!sdk.is_empty());

        let output = doc.to_string();
        assert!(output.contains("[environments.prod.sdk]"));
        assert!(output.contains("max_attempts = 5"));
        assert!(!output.contains("retry_mode"));
    }

    #[test]
    fn get_env_table_mut_missing_envs_table() {
        let config = r#"port = 9765
"#;
        let mut doc: DocumentMut = config.parse().unwrap();
        let result = get_env_table_mut(&mut doc, "demo");
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("demo"));
        assert!(err.contains("not found"));
    }

    #[test]
    fn get_env_table_mut_missing_env() {
        let config = r#"port = 9765

[environments.other]
mode = "sso"
"#;
        let mut doc: DocumentMut = config.parse().unwrap();
        let result = get_env_table_mut(&mut doc, "nonexistent");
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("nonexistent"));
        assert!(err.contains("not found"));
    }

    #[test]
    fn format_value_array_fallthrough() {
        use toml_edit::Array;
        let mut arr = Array::new();
        arr.push("a");
        arr.push("b");
        let v = toml_edit::Value::Array(arr);
        let formatted = format_value(&v);
        assert!(formatted.contains("a"));
        assert!(formatted.contains("b"));
    }

    #[test]
    fn set_value_preserves_multiline_comment_prefix() {
        let config = r#"[environments.demo]
mode = "sso"

# Line 1
# Line 2
# Line 3
region = "us-east-2"
"#;
        let mut doc: DocumentMut = config.parse().unwrap();
        let tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("demo")
            .unwrap()
            .as_table_mut()
            .unwrap();

        set_value_preserving_decor(tbl, "region", value("us-west-1").into_value().unwrap());

        let output = doc.to_string();
        assert!(output.contains("# Line 1"));
        assert!(output.contains("# Line 2"));
        assert!(output.contains("# Line 3"));
        assert!(output.contains("region = \"us-west-1\""));
    }

    #[test]
    fn set_value_preserves_inline_suffix_comment() {
        let config = r#"[environments.demo]
mode = "sso"
region = "us-east-2" # deploy region
"#;
        let mut doc: DocumentMut = config.parse().unwrap();
        let tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("demo")
            .unwrap()
            .as_table_mut()
            .unwrap();

        set_value_preserving_decor(tbl, "region", value("eu-west-1").into_value().unwrap());

        let output = doc.to_string();
        assert!(output.contains("region = \"eu-west-1\" # deploy region"));
    }

    #[test]
    fn set_value_preserves_trailing_comment_after_last_key() {
        let config =
            "[environments.demo]\nmode = \"sso\"\nregion = \"us-east-1\"\n# trailing comment\n";
        let mut doc: DocumentMut = config.parse().unwrap();
        let tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("demo")
            .unwrap()
            .as_table_mut()
            .unwrap();

        set_value_preserving_decor(tbl, "region", value("us-west-2").into_value().unwrap());
        let output = doc.to_string();
        assert!(output.contains("# trailing comment"));
        assert!(output.contains("region = \"us-west-2\""));
    }

    #[test]
    fn obsolete_transport_keys_are_ignored_not_rejected() {
        // An upgraded config.toml still carries port/transport_mode; loading must not fail.
        let config: DaemonConfig =
            toml::from_str("port = 9765\ntransport_mode = \"both\"\n").unwrap();
        assert!(config.envs.is_empty());
        assert!(config.socket_path.is_none());
        assert!(config.validate(&CredentialSources::new()).is_ok());
    }

    #[test]
    fn warn_obsolete_keys_detects_both() {
        // Exercises the detection path; the warning itself goes to tracing.
        for key in OBSOLETE_KEYS {
            let doc = format!("{} = 1\n", key).parse::<DocumentMut>().unwrap();
            assert!(doc.contains_key(key));
        }
        warn_obsolete_keys("port = 9765\ntransport_mode = \"tcp\"\n");
        warn_obsolete_keys("not valid toml [[[");
    }

    static SOCKET_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `CREDSD_SOCKET` is process-global while the test binary runs its cases on parallel
    /// threads, so a case that sets the variable would otherwise decide the outcome of one
    /// that assumes it is absent. Every test touching the variable goes through here, which
    /// holds a lock for its lifetime and restores the prior value on `Drop` — so a failed
    /// assertion unwinds without leaking the override into the rest of the suite.
    struct SocketEnv {
        prev: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl SocketEnv {
        fn set(value: &str) -> Self {
            Self::apply(Some(value))
        }

        fn unset() -> Self {
            Self::apply(None)
        }

        fn apply(value: Option<&str>) -> Self {
            let lock = SOCKET_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let prev = std::env::var_os("CREDSD_SOCKET");
            match value {
                Some(v) => std::env::set_var("CREDSD_SOCKET", v),
                None => std::env::remove_var("CREDSD_SOCKET"),
            }
            Self { prev, _lock: lock }
        }
    }

    impl Drop for SocketEnv {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var("CREDSD_SOCKET", v),
                None => std::env::remove_var("CREDSD_SOCKET"),
            }
        }
    }

    /// An absolute socket path for the host: on Windows the UDS equivalent is a named pipe
    /// in the device namespace, where a Unix-style `/tmp/...` path is not absolute.
    fn abs_socket(name: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!(r"\\.\pipe\{}", name))
        } else {
            PathBuf::from(format!("/tmp/{}", name))
        }
    }

    fn config_with_socket_path(path: &std::path::Path) -> DaemonConfig {
        DaemonConfig {
            socket_path: Some(path.to_path_buf()),
            ..Default::default()
        }
    }

    #[test]
    fn socket_path_override() {
        let _env = SocketEnv::unset();
        let config: DaemonConfig =
            toml::from_str("port = 9765\nsocket_path = \"/custom/path.sock\"\n").unwrap();
        assert_eq!(
            config.effective_socket_path(),
            std::path::PathBuf::from("/custom/path.sock")
        );
    }

    #[test]
    fn socket_path_default_when_absent() {
        let _env = SocketEnv::unset();
        let config: DaemonConfig = toml::from_str("port = 9765\n").unwrap();
        assert!(config.socket_path.is_none());
        let path = config.effective_socket_path();
        assert!(path.to_str().unwrap().contains("credsd"));
        assert_eq!(path, platform::default_socket_path());
    }

    #[test]
    fn env_socket_path_wins_over_config_key() {
        let from_env = abs_socket("credsd-from-env.sock");
        let _env = SocketEnv::set(from_env.to_str().unwrap());

        let config = config_with_socket_path(&abs_socket("credsd-from-config.sock"));
        assert_eq!(config.effective_socket_path(), from_env);
    }

    #[test]
    fn env_socket_path_wins_over_platform_default() {
        let from_env = abs_socket("credsd-env-only.sock");
        let _env = SocketEnv::set(from_env.to_str().unwrap());

        let config = DaemonConfig::default();
        assert!(config.socket_path.is_none());
        assert_eq!(config.effective_socket_path(), from_env);
        assert_ne!(from_env, platform::default_socket_path());
    }

    #[test]
    fn blank_env_socket_path_falls_through() {
        let from_config = abs_socket("credsd-from-config.sock");
        for blank in ["", " ", "\t\n"] {
            let _env = SocketEnv::set(blank);
            assert_eq!(
                config_with_socket_path(&from_config).effective_socket_path(),
                from_config,
                "blank {:?} should not displace the config key",
                blank
            );
            assert_eq!(
                DaemonConfig::default().effective_socket_path(),
                platform::default_socket_path(),
                "blank {:?} should not displace the platform default",
                blank
            );
        }
    }

    /// A relative `CREDSD_SOCKET` is dropped, not resolved: the daemon and its clients each
    /// resolve the socket from their own working directory, so honoring one would let them
    /// disagree about which file to use. Falling through leaves both on the same path.
    #[test]
    fn relative_env_socket_path_is_ignored() {
        let from_config = abs_socket("credsd-from-config.sock");
        for relative in ["relative/path.sock", "credsd.sock", "./credsd.sock"] {
            let _env = SocketEnv::set(relative);
            assert_eq!(
                config_with_socket_path(&from_config).effective_socket_path(),
                from_config,
                "relative {:?} should not displace the config key",
                relative
            );
            assert_eq!(
                DaemonConfig::default().effective_socket_path(),
                platform::default_socket_path(),
                "relative {:?} should not displace the platform default",
                relative
            );
        }
    }

    #[test]
    fn set_key_promotes_inline_table() {
        let config = r#"port = 9765

[environments.demo]
mode = "sso"
region = "us-east-1"
cli = { output = "json" }
"#;
        let mut doc: DocumentMut = config.parse().unwrap();
        let key_def = keys::find_key("cli.output").unwrap();
        let val = key_def.value_type.validate("table", "cli.output").unwrap();

        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("demo")
            .unwrap()
            .as_table_mut()
            .unwrap();

        promote_inline_table(env_tbl, "cli");
        let section_tbl = env_tbl.get_mut("cli").unwrap().as_table_mut().unwrap();
        set_value_preserving_decor(section_tbl, key_def.field, val);

        let output = doc.to_string();
        assert!(output.contains("output = \"table\""));
        let reparsed: DaemonConfig = toml::from_str(&output).unwrap();
        assert_eq!(
            reparsed.envs["demo"]
                .cli
                .as_ref()
                .unwrap()
                .output
                .as_deref(),
            Some("table")
        );
    }

    #[test]
    fn unset_key_promotes_inline_table() {
        let config = r#"port = 9765

[environments.demo]
mode = "sso"
sdk = { retry_mode = "adaptive", max_attempts = 5 }
"#;
        let mut doc: DocumentMut = config.parse().unwrap();
        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("demo")
            .unwrap()
            .as_table_mut()
            .unwrap();

        promote_inline_table(env_tbl, "sdk");
        let sdk = env_tbl.get_mut("sdk").unwrap().as_table_mut().unwrap();
        sdk.remove("retry_mode");

        let output = doc.to_string();
        assert!(!output.contains("retry_mode"));
        assert!(output.contains("max_attempts = 5"));
    }

    #[test]
    fn validate_rejects_relative_socket_path() {
        let config = DaemonConfig {
            socket_path: Some(PathBuf::from("relative/path")),
            ..Default::default()
        };
        let errors = config.validate(&CredentialSources::new()).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("socket_path must be an absolute path"));
        assert!(errors[0].contains("relative/path"));
    }

    #[test]
    fn validate_rejects_invalid_log_level() {
        let config = DaemonConfig {
            log: Some(LogConfig {
                level: Some("bogus".to_string()),
                format: None,
                file: None,
            }),
            ..Default::default()
        };
        let errors = config.validate(&CredentialSources::new()).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("invalid log.level: 'bogus'"));
    }

    fn config_with_envs(envs: &[(&str, EnvConfig)]) -> DaemonConfig {
        DaemonConfig {
            envs: envs
                .iter()
                .map(|(n, p)| (n.to_string(), p.clone()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn validate_rejects_env_naming_undefined_credential() {
        let config = config_with_envs(&[("broken", EnvConfig::default())]);
        let errors = config.validate(&CredentialSources::new()).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("env 'broken'"));
        assert!(errors[0].contains("credential 'broken'"));
    }

    /// The message must name the credential, not the env — the two differ exactly when
    /// the reference is explicit, which is when a typo is hardest to spot.
    #[test]
    fn validate_names_the_missing_credential_not_the_env() {
        let config = config_with_envs(&[(
            "dev",
            EnvConfig {
                credential: Some("tpyo".to_string()),
                ..Default::default()
            },
        )]);
        let errors = config.validate(&CredentialSources::new()).unwrap_err();
        assert!(errors[0].contains("credential 'tpyo'"), "{:?}", errors);
    }

    #[test]
    fn credential_name_defaults_to_the_env_name() {
        assert_eq!(EnvConfig::default().default_credential("dev"), "dev");
        assert_eq!(EnvConfig::default().credential_list("dev"), vec!["dev"]);
    }

    #[test]
    fn env_credentials_parse_list_and_singular() {
        // Canonical ordered-list form; first is the default.
        let list: DaemonConfig =
            toml::from_str("[environments.prod]\ncredentials = [\"a\", \"b\"]\n").unwrap();
        assert_eq!(list.envs["prod"].credential_list("prod"), vec!["a", "b"]);
        assert_eq!(list.envs["prod"].default_credential("prod"), "a");

        let singular: DaemonConfig =
            toml::from_str("[environments.dev]\ncredential = \"shared\"\n").unwrap();
        assert_eq!(singular.envs["dev"].credential_list("dev"), vec!["shared"]);

        let bare: DaemonConfig = toml::from_str("[environments.solo]\n").unwrap();
        assert_eq!(bare.envs["solo"].credential_list("solo"), vec!["solo"]);
    }

    #[test]
    fn envs_using_finds_every_sharer_and_ignores_others() {
        let shared = EnvConfig {
            credential: Some("shared-login".to_string()),
            ..Default::default()
        };
        let config = config_with_envs(&[
            ("dev-tokyo", shared.clone()),
            ("dev", shared),
            ("prod", EnvConfig::default()),
        ]);

        assert_eq!(config.envs_using("shared-login"), vec!["dev", "dev-tokyo"]);
        assert_eq!(config.envs_using("prod"), vec!["prod"]);
        assert!(config.envs_using("nobody").is_empty());
    }

    #[test]
    fn validate_accepts_two_envs_sharing_one_credential() {
        let shared = EnvConfig {
            credential: Some("shared-login".to_string()),
            ..Default::default()
        };
        let config = config_with_envs(&[("dev", shared.clone()), ("dev-tokyo", shared)]);
        assert!(config.validate(&sample_credential_sources()).is_ok());
    }

    #[test]
    fn validate_rejects_a_env_name_that_escapes_the_data_dir() {
        let config = config_with_envs(&[("../evil", EnvConfig::default())]);
        let errors = config.validate(&CredentialSources::new()).unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("invalid env name")),
            "{:?}",
            errors
        );
    }

    #[test]
    fn validate_collects_multiple_errors() {
        let mut envs = HashMap::new();
        envs.insert("bad".to_string(), EnvConfig::default());
        let config = DaemonConfig {
            auth: AuthConfig::default(),
            socket_path: Some(PathBuf::from("not/absolute")),
            log: Some(LogConfig {
                level: Some("verbose".to_string()),
                format: None,
                file: None,
            }),
            envs,
        };
        let errors = config.validate(&CredentialSources::new()).unwrap_err();
        assert!(
            errors.len() >= 3,
            "expected at least 3 errors, got {}: {:?}",
            errors.len(),
            errors
        );
    }

    #[test]
    fn save_env_rejects_invalid_config() {
        let base_config = r#"port = 9765

[environments.prod]
region = "us-east-1"
"#;
        let mut doc: DocumentMut = base_config.parse().unwrap();
        let invalid_env = EnvConfig {
            credentials: vec!["never-defined".to_string()],
            region: Some("us-west-2".to_string()),
            ..Default::default()
        };
        upsert_env_in_doc(&mut doc, "broken", &invalid_env).unwrap();

        let candidate: DaemonConfig = toml::from_str(&doc.to_string()).unwrap();
        let result = candidate.validate(&sample_credential_sources());
        assert!(
            result.is_err(),
            "expected validation to reject an env naming an undefined credential"
        );
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("env 'broken'")));
        assert!(errors.iter().any(|e| e.contains("never-defined")));

        // Verify original config is still valid (untouched file scenario)
        let original: DaemonConfig = toml::from_str(base_config).unwrap();
        assert!(original.validate(&sample_credential_sources()).is_ok());
    }

    #[test]
    fn validate_accepts_valid_config() {
        let mut envs = HashMap::new();
        envs.insert(
            "prod".to_string(),
            EnvConfig {
                region: Some("us-east-1".to_string()),
                ..Default::default()
            },
        );
        let config = DaemonConfig {
            auth: AuthConfig::default(),
            // On Windows the UDS equivalent is a named pipe (`\\.\pipe\...`),
            // which is an absolute device-namespace path; a Unix `.sock` path is
            // not absolute there and would spuriously fail validation.
            socket_path: Some(if cfg!(windows) {
                PathBuf::from(r"\\.\pipe\credsd-test")
            } else {
                PathBuf::from("/var/run/credsd.sock")
            }),
            log: Some(LogConfig {
                level: Some("info".to_string()),
                format: Some("json".to_string()),
                file: None,
            }),
            envs,
        };
        assert!(config.validate(&sample_credential_sources()).is_ok());
    }

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn write_creates_at_600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_config_file(&path, "port = 9765\n").unwrap();

        assert_eq!(mode_of(&path), 0o600, "got {:o}", mode_of(&path));
        assert_eq!(fs::read_to_string(&path).unwrap(), "port = 9765\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_narrows_an_existing_permissive_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "port = 1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_config_file(&path, "port = 9765\n").unwrap();

        assert_eq!(mode_of(&path), 0o600, "got {:o}", mode_of(&path));
        assert_eq!(fs::read_to_string(&path).unwrap(), "port = 9765\n");
    }

    /// A rewrite must leave nothing of the longer previous content behind.
    #[test]
    fn write_truncates_previous_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_config_file(&path, "port = 9765\n# a long trailing comment\n").unwrap();
        write_config_file(&path, "port = 1\n").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "port = 1\n");
    }

    /// A failure at the rename must leave `path` exactly as it was and leave no temp file.
    /// A directory at `path` makes the rename fail after the content is written and synced,
    /// which is the window a crash would land in. Directory mode bits are not used to force
    /// the failure, so this holds when the tests run as root.
    #[test]
    fn a_failed_write_leaves_the_previous_path_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("marker"), "untouched").unwrap();

        assert!(write_config_file(&path, "port = 1\n").is_err());
        assert_eq!(
            fs::read_to_string(path.join("marker")).unwrap(),
            "untouched"
        );
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "temp file leaked after a failed rename"
        );
    }

    /// `persist` must rename the temp file onto `path`, not leave it sitting beside it.
    #[test]
    fn write_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_config_file(&path, "port = 9765\n").unwrap();

        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1, "temp file was not cleaned up by persist");
    }

    #[cfg(unix)]
    #[test]
    fn load_succeeds_with_permissive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "port = 9765\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let _: DaemonConfig = toml::from_str(&content).unwrap();
    }

    /// The distinction H2 turned on: a config that is absent yields defaults, but a config that
    /// exists and cannot be read is an error. The `Path::exists()` probe this replaced answered
    /// `false` for both, so a caller reading a daemon-owned 0700 tree was told it had no config.
    #[test]
    fn read_if_present_reports_absent_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_if_present(&dir.path().join("config.toml"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn read_if_present_returns_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "port = 9765\n").unwrap();
        assert_eq!(
            read_if_present(&path).unwrap().as_deref(),
            Some("port = 9765\n")
        );
    }

    /// Root bypasses file modes, so this asserts nothing when run as root — skip rather than
    /// fail, and keep the assertion honest for the ordinary case.
    #[cfg(unix)]
    #[test]
    fn read_if_present_reports_unreadable_as_an_error_naming_the_path() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::getuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "port = 9765\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        let err = read_if_present(&path).unwrap_err().to_string();
        assert!(
            err.contains("config.toml"),
            "error must name the file: {err}"
        );
    }

    /// `load_from` inherits the distinction: an unreadable `config.toml` must not read as an
    /// unconfigured daemon, which is what sent `creds list` to "No envs configured".
    #[cfg(unix)]
    #[test]
    fn load_from_fails_on_an_unreadable_config_rather_than_defaulting() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::getuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("config.toml"), "[environments.dev]\n").unwrap();
        fs::set_permissions(
            dir.path().join("config.toml"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();

        assert!(DaemonConfig::load_from(dir.path()).is_err());
    }

    /// An absent directory is still an unconfigured daemon, not a failure — `bootstrap` runs
    /// against a machine with no config at all.
    #[test]
    fn load_from_an_empty_directory_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let (config, credentials) = DaemonConfig::load_from(dir.path()).unwrap();
        assert!(config.envs.is_empty());
        assert!(credentials.is_empty());
    }

    /// `resolve_env_vars` reads the env's settings, not a file. Its `env_var` mappings are the
    /// only reason `creds run` sets `AWS_ENDPOINT_URL` and friends at all.
    #[test]
    fn resolve_env_vars_maps_sdk_settings_to_aws_variables() {
        let env = EnvConfig {
            sdk: Some(SdkSettings {
                endpoint_url: Some("https://localhost:4566".into()),
                max_attempts: Some(7),
                ..Default::default()
            }),
            ..Default::default()
        };
        let vars = resolve_env_vars(Some(&env));
        assert_eq!(
            vars.iter()
                .find(|(k, _)| *k == "AWS_ENDPOINT_URL")
                .map(|(_, v)| v.as_str()),
            Some("https://localhost:4566")
        );
        assert_eq!(
            vars.iter()
                .find(|(k, _)| *k == "AWS_MAX_ATTEMPTS")
                .map(|(_, v)| v.as_str()),
            Some("7")
        );
    }

    #[test]
    fn resolve_env_vars_of_nothing_is_empty() {
        assert!(resolve_env_vars(None).is_empty());
        assert!(resolve_env_vars(Some(&EnvConfig::default())).is_empty());
    }

    /// The edit is made from the checked text, not from whatever is on disk.
    #[test]
    fn remove_env_from_edits_the_checked_text_not_the_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let checked = "[environments.dev]\n\n[environments.keep]\n";
        write_config_file(&path, &format!("{checked}[environments.hand]\n")).unwrap();

        let written = remove_env_from(&path, checked, "dev")
            .unwrap()
            .expect("dev was checked, so it is removed");

        assert!(!written.contains("[environments.dev]"));
        assert!(
            !written.contains("hand"),
            "the hand edit must not be written"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), written);
        assert_eq!(remove_env_from(&path, checked, "absent").unwrap(), None);
    }

    /// The edit comes out of the text passed in, and the file is left to the caller to write.
    #[test]
    fn set_env_key_in_edits_only_the_text_it_was_given() {
        let checked = "[environments.dev]\n\n[environments.keep]\n";
        let key_def = keys::find_key("description").unwrap();

        let edited =
            set_env_key_in(checked, "dev", key_def, toml_edit::Value::from("set")).unwrap();

        assert!(edited.contains("description = \"set\""));
        assert!(edited.contains("[environments.keep]"));
        assert!(set_env_key_in(checked, "absent", key_def, toml_edit::Value::from("set")).is_err());
    }

    /// The edit comes out of the text passed in, and the file is left to the caller to write.
    #[test]
    fn unset_env_key_in_edits_only_the_text_it_was_given() {
        let checked = "[environments.dev]\ndescription = \"kept\"\n";
        let key_def = keys::find_key("description").unwrap();

        let edited = unset_env_key_in(checked, "dev", key_def).unwrap();

        assert!(!edited.contains("description"));
        assert!(edited.contains("[environments.dev]"));
        assert_eq!(
            unset_env_key_in(&edited, "dev", key_def).unwrap(),
            edited,
            "unsetting a key that is not there leaves the text alone"
        );
    }

    #[test]
    fn validate_agent_without_scoping_does_not_fail() {
        // An agent env whose implicit credential (the env name itself) is also agent-typed
        // must pass the lattice check — same-privilege composition is allowed.
        let sources = sources_named("dev", IdentityType::Agent);
        let config = config_with_envs(&[(
            "dev",
            EnvConfig {
                identity_type: IdentityType::Agent,
                ..Default::default()
            },
        )]);
        assert!(config.validate(&sources).is_ok());
    }

    /// The original report: a second bootstrap on an existing env with mixed-privilege
    /// credentials must be rejected. This is the multi-credential case the previous
    /// single-credential guard missed.
    #[test]
    fn validate_rejects_agent_env_with_one_human_credential_among_several() {
        let mut sources = sources_named("prod-human", IdentityType::Human);
        sources.extend(sources_named("agent-cred", IdentityType::Agent));

        let config = config_with_envs(&[(
            "dev",
            EnvConfig {
                credentials: vec!["prod-human".into(), "agent-cred".into()],
                identity_type: IdentityType::Agent,
                ..Default::default()
            },
        )]);
        // agent env may not compose prod-human (human)
        let errs = config.validate(&sources).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("privilege") && e.contains("prod-human")),
            "{errs:?}"
        );
    }

    /// The regression surface for the `IdentityType::Unknown` fail-open fix: a credential whose
    /// identity_type didn't parse as a known tier (`serde(other)` lands here) must fail
    /// validation — and so fail the whole file's `load_from` — for any env below `Human`,
    /// not just pass through as if it were the least-privileged tier.
    #[test]
    fn validate_rejects_agent_or_automation_env_composing_an_unknown_credential() {
        let sources = sources_named("drifted", IdentityType::Unknown);
        for identity_type in [IdentityType::Agent, IdentityType::Automation] {
            let config = config_with_envs(&[(
                "dev",
                EnvConfig {
                    credentials: vec!["drifted".into()],
                    identity_type,
                    ..Default::default()
                },
            )]);
            let errs = config.validate(&sources).unwrap_err();
            assert!(
                errs.iter()
                    .any(|e| e.contains("privilege") && e.contains("drifted")),
                "{identity_type:?}: {errs:?}"
            );
        }
    }

    #[test]
    fn validate_accepts_human_env_composing_an_unknown_credential() {
        let sources = sources_named("drifted", IdentityType::Unknown);
        let config = config_with_envs(&[(
            "dev",
            EnvConfig {
                credentials: vec!["drifted".into()],
                identity_type: IdentityType::Human,
                ..Default::default()
            },
        )]);
        assert!(config.validate(&sources).is_ok());
    }

    #[test]
    fn get_env_key_at_errors_on_missing_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // File exists but contains no matching env.
        std::fs::write(&path, "[environments.real-env]\n").unwrap();
        let err = get_env_key_at(&path, "nonexistent", &keys::ALLOWED_KEYS[0])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("nonexistent"),
            "error should name the env: {err}"
        );
    }

    #[test]
    fn get_env_key_at_errors_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml"); // does not exist
        let err = get_env_key_at(&path, "any-env", &keys::ALLOWED_KEYS[0])
            .unwrap_err()
            .to_string();
        assert!(err.contains("any-env"), "error should name the env: {err}");
    }

    #[test]
    fn get_env_key_at_returns_none_for_unset_key_in_existing_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[environments.dev]\n").unwrap();
        // key "region" exists in the key table but is not set in this env
        let result = get_env_key_at(&path, "dev", &keys::ALLOWED_KEYS[0]).unwrap();
        assert!(result.is_none());
    }

    fn ra_config_with_endpoint(
        endpoint: &str,
    ) -> std::result::Result<RolesAnywhereConfig, toml::de::Error> {
        let s = format!(
            r#"
trust_anchor_arn = "arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/ta"
profile_arn = "arn:aws:rolesanywhere:us-east-1:111111111111:profile/p"
role_arn = "arn:aws:iam::111111111111:role/r"
endpoint_url = {endpoint:?}
"#
        );
        toml::from_str(&s)
    }

    #[test]
    fn ra_endpoint_url_accepts_clean_https_url() {
        assert!(
            ra_config_with_endpoint("https://rolesanywhere.us-gov-west-1.amazonaws.com").is_ok()
        );
    }

    #[test]
    fn ra_endpoint_url_rejects_http() {
        assert!(ra_config_with_endpoint("http://rolesanywhere.us-east-1.amazonaws.com").is_err());
    }

    #[test]
    fn ra_endpoint_url_rejects_userinfo() {
        assert!(
            ra_config_with_endpoint("https://user@rolesanywhere.us-east-1.amazonaws.com").is_err()
        );
    }

    /// The percent-encoded @ bypass (`%40`): reqwest's WHATWG parser rejects or decodes
    /// it before exposing authority — either the URL fails to parse (invalid domain after
    /// decoding %40 to @) or userinfo is detected. Either way the value is rejected before
    /// it can reach the vendored SigV4 signer.
    #[test]
    fn ra_endpoint_url_rejects_percent_encoded_userinfo() {
        assert!(ra_config_with_endpoint("https://trusted.amazonaws.com%40attacker.com").is_err());
    }
}
