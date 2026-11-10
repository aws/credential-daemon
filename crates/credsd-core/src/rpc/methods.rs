//! The method surface: names, params, and results.
//!
//! Split from the envelope in [`super`] because the two change for different
//! reasons — the envelope is settled by Requirement 9 and the methods by
//! Requirement 10 — and because every type here is reachable as `crate::rpc::*`
//! through the re-exports in [`super`].
//!
//! Wire vocabularies are reused from the tree rather than redefined:
//! [`CredentialType`] is the kind discriminant, [`CredentialSourceType`] mirrors
//! `CredentialSource`'s tags, and [`SessionStatus`] transcribes the states
//! `credential_status` already distinguishes. A consumer that reads a manifest
//! entry and a material response must not get two names for one thing.

use std::fmt;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::PROTOCOL_VERSION;
use crate::config::credentials::validate_name;

/// The kind discriminant, reused verbatim from the credential model rather than
/// paralleled here. Re-exported so the protocol surface is readable as one thing.
pub use crate::credentials::CredentialType;

/// Every constraint `validate_name` enforces, stated without the offending value.
///
/// A name arriving in `params` is an arbitrary JSON string, so `/`, `..`, newlines,
/// control characters, and unbounded length are all reachable here for the first
/// time — the HTTP surface got path-segment filtering from the router for free, and
/// JSON params get none. `validate_name`'s own messages interpolate the name, which
/// is precisely the log-forging vector once that text lands in `RpcError::message`
/// and something logs it, so the rule is echoed and the input never is.
const NAME_RULE: &str =
    "invalid name; use letters, digits, '.', '_', or '-', max 64 characters, not starting with '.'";

fn checked<E: serde::de::Error>(field: &str, name: &str) -> Result<(), E> {
    validate_name(name).map_err(|_| E::custom(format!("{field}: {NAME_RULE}")))
}

/// An `https://` endpoint URL, checked at deserialize time.
///
/// These strings arrive from any local uid and become the daemon's outbound POST target. Two
/// things follow, and neither is the caller's to decide:
///
/// - **`https` is mandatory.** An `http://` token endpoint would carry the authorization code and
///   the PKCE verifier in cleartext, then re-POST the refresh token in cleartext on every renewal,
///   indefinitely.
/// - **No userinfo.** `https://user:pass@host/` smuggles credentials into a URL the daemon dials
///   and logs; RFC 3986 §3.2.1 deprecates the form outright.
///
/// A syntactic check, not a parse: scheme, non-empty authority, no `@`. That is all this needs to
/// decide, and it avoids taking a URL crate into the wire types for it. Reachability of the host
/// is deliberately not checked here — that is the request's job to report.
///
/// Enforced at deserialization because that is the one path every caller passes through; a second
/// entry point cannot skip it.
/// The default scope list when the field is absent, since `serde(default, deserialize_with)`
/// skips the deserializer on an absent field. Both routes to a missing `openid` — absent and
/// present-but-lacking — end at the same value.
fn default_oauth_scopes() -> Vec<String> {
    vec!["openid".to_string()]
}

/// The scope list, guaranteed to contain `openid`.
///
/// The whole federation path depends on `openid`: without it the AS may return only an opaque
/// access token, and `web_identity_token` then falls back to that — which STS rejects while
/// `bootstrap` blames `role_arn`. Field-level defaulting only fires on an absent field, so `[]`
/// and `["profile"]` used to survive; this closes both by inspecting the deserialized value.
///
/// `openid` is prepended when missing rather than appended so it is the first scope in the
/// authorize URL — some ASes treat scope order as significant.
fn ensure_openid_scope<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    let mut scopes: Vec<String> = Vec::deserialize(deserializer)?;
    if !scopes.iter().any(|s| s == "openid") {
        scopes.insert(0, "openid".into());
    }
    Ok(scopes)
}

fn validate_https_url(url: &str) -> std::result::Result<(), String> {
    let parsed =
        reqwest::Url::parse(url).map_err(|e| format!("endpoint must be a valid URL: {e}"))?;
    if parsed.scheme() != "https" {
        return Err(
            "endpoint must be https; an http endpoint would send the authorization code, the \
             PKCE verifier, and every refresh token in cleartext"
                .to_string(),
        );
    }
    // Reject userinfo in both literal (@) and percent-encoded (%40) form: reqwest's WHATWG
    // parser decodes percent-encoding before exposing username/password, catching the bypass
    // that string-splitting on '@' misses.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("endpoint must not embed userinfo (user@host or user:pass@host)".to_string());
    }
    if parsed.host().is_none() {
        return Err("endpoint must name a host".to_string());
    }
    Ok(())
}

fn https_endpoint<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    use serde::de::Error;
    let raw = String::deserialize(deserializer)?;
    validate_https_url(&raw).map_err(D::Error::custom)?;
    Ok(raw)
}

fn https_endpoint_opt<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    use serde::de::Error;
    let Some(raw) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    validate_https_url(&raw).map_err(D::Error::custom)?;
    Ok(Some(raw))
}

fn profile_name<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let name = String::deserialize(deserializer)?;
    checked("environment", &name)?;
    Ok(name)
}

fn optional_profile_name<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let name = Option::<String>::deserialize(deserializer)?;
    if let Some(name) = name.as_deref() {
        checked("environment", name)?;
    }
    Ok(name)
}

fn optional_credential_name<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let name = Option::<String>::deserialize(deserializer)?;
    if let Some(name) = name.as_deref() {
        checked("credential", name)?;
    }
    Ok(name)
}

/// Atomic retrieval: material for exactly one credential, or a failure. Never a
/// default, a sibling, or a profile-shaped result.
///
/// Material-bearing, so this method is reachable over the Unix socket only. It
/// must never appear in an MCP `tools/list`, under any configuration — a
/// credential in a model's context is a credential in a transcript. The same
/// holds for [`METHOD_CREDENTIAL_GET_BATCH`].
pub const METHOD_CREDENTIAL_GET: &str = "credential/get";

/// Aggregate retrieval: every credential a profile names, satisfied wholly or not
/// at all. The caller names the profile and *not* the membership; see
/// [`GetBatchParams`] for why that is the load-bearing part.
pub const METHOD_CREDENTIAL_GET_BATCH: &str = "credential/get_batch";

/// Enumeration: what credentials exist, what kind each is, and whether it has a
/// live session. Carries no material, so this is the one retrieval-adjacent method
/// a model-facing carrier may expose — and Requirement 13 AC 4 caps it at exactly
/// that, which is why it is not also the manifest.
pub const METHOD_CREDENTIAL_LIST: &str = "credential/list";

/// Manifest: one profile's credentials plus the inputs a projection needs.
///
/// A separate method from [`METHOD_CREDENTIAL_LIST`] rather than a wider result on
/// it. Requirement 6 AC 3 obliges the manifest to carry every datum a projection
/// needs; Requirement 13 AC 4 caps the model-facing enumeration at a credential's
/// name, kind, and status and *nothing more*. One method cannot satisfy both, and
/// varying the field set by carrier is prohibited outright — Requirement 13 AC 6
/// permits carrier-specific exposure and forbids carrier-specific semantics. So the
/// subject decides: region and the SDK/CLI knobs are properties of a profile, and
/// live on the profile-subject method. Unix socket only.
pub const METHOD_PROFILE_DESCRIBE: &str = "environment/describe";

/// Protocol handshake. Carries the version identifier a shim compares against
/// its own; see [`HealthResult`].
pub const METHOD_SYSTEM_HEALTH: &str = "system/health";
/// MCP-compatible notification method for streaming progress (device-code flow, polling steps).
/// Daemon sends these as JSON-RPC notifications (no `id`) during long-running bootstrap/login.
pub const NOTIFICATION_PROGRESS: &str = "notifications/progress";

/// Params for [`METHOD_CREDENTIAL_GET`].
///
/// The request names both halves of the decision: `profile` is the authorization
/// context that supplies restriction (boundary, region, subprocess config), and
/// `credential` selects the material within it. Naming them separately is what
/// keeps an atomic retrieval from yielding material that escaped a restriction
/// the same material would carry under an aggregate retrieval — a credential the
/// named profile does not reach fails as *not found*, indistinguishably from one
/// that does not exist.
///
/// Unknown members are rejected rather than ignored: silently dropping a
/// misspelled `claim` would *reduce* restriction, so the strict reading is the
/// fail-closed one.
///
/// `PartialEq` but not `Eq`, because [`Scope`] holds arbitrary JSON and JSON
/// numbers are not reflexively equal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetParams {
    #[serde(deserialize_with = "profile_name")]
    pub environment: String,
    /// Absent means the credential the profile is configured with. It never
    /// widens to a default or a sibling of the requested one.
    #[serde(
        default,
        deserialize_with = "optional_credential_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<Claim>,
    /// Caller-supplied correlation id, opaque to the daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// A caller-supplied session policy, which can only ever narrow.
///
/// **The grammar is not settled**, so this is a placeholder: it holds whatever
/// JSON the eventual policy shape turns out to be, and settling that shape will
/// not move the field it sits in. Carrying it now is the point — adding the field
/// later is the breaking change; adding variants inside it is not.
///
/// What *is* settled is the meaning of its absence — *boundary-scoped*, never
/// *unscoped*. There is deliberately no parameter that broadens, replaces, or
/// suppresses a boundary, and a malformed scope must fail the retrieval rather
/// than fall back to unscoped material.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scope(pub Value);

/// A scope document may name resources that are themselves sensitive, and the
/// audit trail is required to record a digest of it rather than the document. A
/// derived `Debug` on the enclosing params would defeat that with one log line.
impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scope(<policy>)")
    }
}

/// A caller's self-reported identity claim.
///
/// One variant, and no boolean: the *presence* of `claim` is the assertion and
/// its absence means unstated. There is deliberately no way to say "I am not an
/// agent" — the claim may only ever add restriction, so a caller cannot talk
/// itself out of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Claim {
    Agentic,
    /// A claim not recognised by this version — ignored.
    #[serde(other)]
    Unknown,
}

/// Params for [`METHOD_CREDENTIAL_GET_BATCH`]: a profile, and nothing that names
/// membership.
///
/// The absence of a `requests` list is the design. A caller-composed set would be
/// a third retrieval subject, and it would hollow out the all-or-none guarantee:
/// failing a caller-chosen batch atomically is not enforcing any property *of the
/// aggregate*, because the aggregate would not exist as a daemon-side concept.
/// Membership is credsd's to determine, so the invariant is credsd's to enforce.
///
/// This shape deliberately overlaps [`GetParams`] on `{ profile }`. The two
/// operations are distinguished by method name and result type, not by params
/// shape, and they stay distinct even for a profile reaching exactly one
/// credential — which is every profile today. `deny_unknown_fields` is what keeps
/// a caller from smuggling membership in as `credential` or `requests`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetBatchParams {
    #[serde(deserialize_with = "profile_name")]
    pub environment: String,
    /// Applies to every credential in the aggregate; there is no per-element
    /// scope, because there is no per-element request to carry one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<Claim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Params for [`METHOD_CREDENTIAL_LIST`]. Every field is optional, so `{}` is a
/// valid request; the object exists so filters can be added without changing the
/// method's shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListParams {
    /// Restricts the manifest to one profile. Absent means every profile.
    #[serde(
        default,
        deserialize_with = "optional_profile_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Result of [`METHOD_CREDENTIAL_LIST`]: enumeration, capped by Requirement 13 AC 4.
///
/// Flat rather than grouped by profile. Each entry carries the profile it belongs
/// to because the model's use for this method is composing a `launch_command`, which
/// names a profile — the association is what makes the list actionable, not an extra
/// disclosure about the credential. AC 4's "nothing more" governs the credential's own
/// attributes, and `source` and `default` are the two this deliberately omits.
///
/// This type MUST NOT grow toward [`ProfileManifest`]. Requirement 11 AC 2 makes any
/// field it gains permanent, and AC 4 binds it on the model-facing carrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListResult {
    pub credentials: Vec<CredentialSummary>,
}

/// One credential as a model may see it: where to ask for it, what it is, and
/// whether it would work right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub environment: String,
    pub credential: String,
    pub kind: CredentialType,
    pub status: SessionStatus,
}

/// Params for [`METHOD_PROFILE_DESCRIBE`]: exactly one profile, required.
///
/// No "all profiles" form. The manifest is the input to building one environment,
/// and a caller that has not yet chosen a profile is enumerating, which is
/// [`METHOD_CREDENTIAL_LIST`]'s job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescribeParams {
    #[serde(deserialize_with = "profile_name")]
    pub environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Result of [`METHOD_PROFILE_DESCRIBE`]: the manifest. Contains no material and no
/// value that would be secret if logged.
///
/// Returned directly rather than wrapped in a single-field result type — there is
/// one profile per call and nothing to put beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileManifest {
    pub environment: String,
    /// A `Vec` even though a profile names exactly one credential today: the shape
    /// has to stay well-formed if that becomes several, and a scalar field could not.
    pub credentials: Vec<CredentialEntry>,
    pub projection: Projection,
}

/// The profile-level inputs a projection needs, so that a shim building an
/// environment never parses `config.toml`.
///
/// The SDK and CLI settings are the config types themselves, not a parallel wire
/// copy of their ~20 optional fields. That is the point: Requirement 6 AC 3 says if
/// a projection needs a datum the manifest carries it, and a hand-transcribed copy
/// is exactly how a datum goes missing when one of them gains a field. Their field
/// names are already this protocol's casing, and neither type holds a secret.
///
/// `identity_type` is deliberately absent. It is an authorization input rather than
/// a projection one, and returning it would tell a caller how it is about to be
/// classified.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Projection {
    /// The env's per-credential projection declarations, so a client resolves the same set the
    /// daemon would without reading `config.toml` (retrieval spec Req 6 AC 3).
    ///
    /// Carries each declaration's address as well as its type, for the same reason the config map
    /// does: a client that received only the type could not reproduce the daemon's resolution, which
    /// is the one property this field exists to provide.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub projections: std::collections::BTreeMap<String, crate::projection::ProjectionDecl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk: Option<crate::config::SdkSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli: Option<crate::config::CliSettings>,
}

/// The daemon's projection of an env it loaded. Paired with the inverse below so the field
/// list is written once: a projection input added to [`crate::config::EnvConfig`] and not
/// carried here is a datum that silently goes missing from every client-side materialization
/// (Req 6 AC 3).
impl From<&crate::config::EnvConfig> for Projection {
    fn from(env: &crate::config::EnvConfig) -> Self {
        Self {
            projections: env.projections.clone(),
            region: env.region.clone(),
            sdk: env.sdk.clone(),
            cli: env.cli.clone(),
        }
    }
}

/// A client's reconstruction of the env behind a manifest, for the renderers that take an
/// `EnvConfig`. Only the projection fields are recoverable — `credentials` and `identity_type`
/// are deliberately not on the wire (the credential list arrives as
/// [`ProfileManifest::credentials`]; `identity_type` is an authorization input the daemon does
/// not disclose), so they stay at their defaults.
impl From<&Projection> for crate::config::EnvConfig {
    fn from(p: &Projection) -> Self {
        Self {
            projections: p.projections.clone(),
            region: p.region.clone(),
            sdk: p.sdk.clone(),
            cli: p.cli.clone(),
            ..Self::default()
        }
    }
}

/// One credential as seen without asking for it: what it is, where it comes from,
/// whether it currently has a session, and whether it is the profile's default.
///
/// Status is reported here even where a material-bearing response would withhold
/// it, which is the point of the manifest: a shim can tell the user *which* login
/// is missing without first provoking a failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub credential: String,
    pub kind: CredentialType,
    pub source: CredentialSourceType,
    /// The environment variable a token-form credential is exported as, when it named one other
    /// than the default. Present so a client can materialize an env-var credential straight from
    /// this manifest without reading `credentials.toml` (retrieval spec Req 6 AC 3). Absent for
    /// AWS-profile credentials and for token credentials using the derived name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// The projection this credential declares for itself, when it declares one. The lowest of
    /// the three association levels: an env's declaration overrides it, and an invocation's
    /// overrides both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<crate::projection::ProjectionType>,
    pub status: SessionStatus,
    /// The one credential a projection may place in the ambient credential slot,
    /// which holds exactly one. Under the shipped 1:1 cardinality a profile's
    /// sole credential is its default, so this is always `true` today; it exists
    /// so the field is present before M:N makes it interesting. Always emitted,
    /// so absence is never read as `false`.
    pub default: bool,
}

/// Where a credential comes from, as a discriminant only.
///
/// Mirrors `CredentialSource`'s tags rather than embedding it: the manifest needs
/// the source *type*, not the source's configuration, which holds account ids and
/// role names. `Unsupported` mirrors that type's `#[serde(other)]` catch-all, so a
/// source type this build has no provider for still lists rather than breaking the
/// manifest — and so a consumer reading a newer daemon's manifest degrades to
/// "something I don't handle" instead of failing to parse.
///
/// snake_case, not the kebab-case `CredentialSource` uses. That type's tags are
/// spelled for `credentials.toml`, a file a shim never reads — which is the whole
/// point of Requirement 6 AC 3 — so inheriting its spelling would buy no
/// compatibility while splitting the casing of a single wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSourceType {
    AwsIdcSso,
    AwsIamUser,
    /// An X.509 certificate exchanged for credentials via IAM Roles Anywhere.
    /// Added after the initial port: `CredentialSource` grew a third supported
    /// variant, and `#[serde(other)]` covers deserialization only, so without an
    /// explicit variant a fully-supported source would have no serialize path and
    /// would report as `Unsupported`.
    AwsRolesAnywhere,
    /// An OAuth2 login federated to AWS credentials via `AssumeRoleWithWebIdentity`.
    #[serde(rename = "aws_web_identity")]
    AwsWebIdentity,
    /// An AWS Sign-In login (`aws login`) federated straight to AWS credentials.
    AwsLogin,
    /// A bearer JWT served as the credential itself, for an API that is not AWS.
    Jwt,
    /// An OAuth 2.0 client-credentials (2LO) token endpoint. No provider yet; the variant
    /// exists so `CredentialSource::Oauth` has a serialize path and does not fall through to
    /// `Unsupported` on the wire.
    Oauth,
    /// An OAuth 2.0 JWT Bearer grant (RFC 7523). No provider yet; the variant exists so
    /// `CredentialSource::JwtBearer` has a serialize path and does not fall through to
    /// `Unsupported` on the wire.
    JwtBearer,
    /// A pre-issued opaque secret served verbatim, for an API that is not AWS. Carries no
    /// issuer-stated lifetime, so its `expires_at` is whatever the user declared, or `null`.
    StaticSecret,
    #[serde(other)]
    Unsupported,
}

impl CredentialSourceType {
    /// The human-facing spelling of this source type, as `creds list`'s MODE column and
    /// diagnostics use it.
    ///
    /// Kebab-case, matching `credentials.toml`'s tags rather than this protocol's snake_case
    /// wire spelling: it is what an operator already reads in that file and in the docs, and
    /// `CredentialSource::type_name` delegates here so the two cannot drift.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AwsIdcSso => "aws-idc-sso",
            Self::AwsIamUser => "aws-iam-user",
            Self::AwsRolesAnywhere => "aws-roles-anywhere",
            Self::AwsWebIdentity => "aws-web-identity",
            Self::AwsLogin => "aws-login",
            Self::Jwt => "jwt",
            Self::Oauth => "oauth",
            Self::JwtBearer => "jwt-bearer",
            Self::StaticSecret => "static-secret",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Whether a credential currently has a usable session, and if not, why not.
///
/// A transcription of the states `crate::credential_status` already distinguishes,
/// not a new vocabulary — deliberately including the ones that look redundant.
/// `Corrupt`, `Unreadable`, and `DecryptFailed` are three different operator
/// actions, and `Unknown` means the daemon could not look rather than that it
/// looked and found nothing. Collapsing any of them is the choice that would be
/// permanent under an additive-only code rule, so none are collapsed.
///
/// snake_case to match the rest of this protocol; `credential_status` returns prose,
/// so there is no existing wire spelling to inherit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    /// Live, but inside the refresh window a shim should not start long work in.
    Expiring,
    Expired,
    /// Never logged in, or the token was removed.
    NoSession,
    /// A token is present but not parseable — its expiry cannot be read.
    Corrupt,
    Unreadable,
    DecryptFailed,
    /// Encryption is unavailable, so the token could not be examined at all. Not
    /// the same as `NoSession`: nothing was ruled out.
    Unknown,
    /// The IdP rejected the refresh token, so the login cannot renew itself: the user must sign in
    /// again. Distinct from `Expired`, which says the session lapsed and can still be renewed.
    SignInRequired,
}

impl SessionStatus {
    /// The operator-facing spelling, as `creds list`'s STATUS column prints it. The wire
    /// spelling with the underscore turned back into a space — one mapping, so a variant
    /// cannot be added without a display for it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expiring => "expiring",
            Self::Expired => "expired",
            Self::NoSession => "no session",
            Self::Corrupt => "corrupt",
            Self::Unreadable => "unreadable",
            Self::DecryptFailed => "decrypt failed",
            Self::Unknown => "unknown",
            Self::SignInRequired => "sign in required",
        }
    }
}

/// Material for one credential, naming which credential it is.
///
/// One type serves both the atomic result and the elements of an aggregate. Self-
/// describing entries are required for the aggregate, where the caller supplied
/// no list and so has no index to match against; on the atomic call the echo is
/// what tells a caller which credential `GetParams::credential: None` resolved to.
/// A consumer therefore writes one parser, not two.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CredentialResult {
    #[zeroize(skip)]
    pub credential: String,
    pub material: Material,
    /// RFC 3339 and absolute, or `null` for a credential with no issuer-stated
    /// lifetime. A relative lifetime would let a consumer's clock skew silently
    /// extend the credential's life, so it stays prohibited; `null` says "never
    /// expires", which is a different claim from "expires in N seconds".
    ///
    /// Serialized without `skip_serializing_if` on purpose: the wire contract is an
    /// explicit `null`, not an absent field, so a consumer can distinguish
    /// "no expiry" from "this daemon did not tell me".
    ///
    /// Not secret, so it is left out of the zeroizing set.
    #[zeroize(skip)]
    pub expires_at: Option<DateTime<Utc>>,
    #[zeroize(skip)]
    pub provenance: Provenance,
}

/// Whether the material in a response is shared or was minted for this request.
///
/// A consumer needs this to decide whether caching locally is even meaningful: a
/// shared session is reusable across profiles that name the same credential,
/// while a scoped session generally is not. Nothing in the API requires a
/// consumer to cache — this only tells it whether it may.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    CachedShared,
    MintedForRequest,
    /// A provenance category not recognised by this version.
    #[serde(other)]
    Unknown,
}

/// Result of [`METHOD_CREDENTIAL_GET_BATCH`]: every credential the profile names.
///
/// There is no per-element status and no partial-success flag, by construction: a
/// batch either yields every credential or returns one error and no material at
/// all. A caller cannot opt out by reading past a failed element, because there is
/// no element-level result to read. A partial answer would produce an environment
/// that presents as configured and fails later, and naming which element failed
/// would turn a denial into a discovery primitive.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GetBatchResult {
    pub credentials: Vec<CredentialResult>,
}

/// Secret material handed to the caller.
///
/// Internally tagged on `type`, never `untagged`: untagged picks a variant by
/// field shape, so a subset/superset payload can parse as the wrong kind and an
/// unknown variant yields an opaque error. For a secret-bearing type that is
/// fail-open. The tag fails closed, naming the variant it did not recognize.
///
/// The tag *values* are [`CredentialType`]'s wire strings, not a parallel set, so
/// the kind a manifest reports and the kind a material response carries are the
/// same string. That tag is also the explicit kind discriminant on the response —
/// a consumer never infers kind from which fields are present.
///
/// Field names follow the consumer's vocabulary (`AWS_ACCESS_KEY_ID` and the
/// `credential_process` schema), which is why they are not spelled the way
/// `CredentialData`'s equivalents are. The kind vocabulary is shared; the field
/// vocabulary belongs to whoever reads the fields.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Material {
    SessionCredentials {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
    },
    /// A bearer token for a non-AWS API. `token_type` is the OAuth2 `token_type` the issuer
    /// returned (`Bearer` for everything credsd obtains today) rather than an assumption the
    /// consumer makes: it is what belongs in the `Authorization` header before the token, and a
    /// DPoP-bound token is spelled `DPoP` there.
    AccessToken {
        token: String,
        #[zeroize(skip)]
        token_type: String,
    },
}

/// Hand-written so no secret can reach a log through `{:?}`, directly or via a
/// `Debug` of any struct that contains this one.
impl fmt::Debug for Material {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionCredentials { .. } => f.write_str("SessionCredentials(<redacted>)"),
            Self::AccessToken { .. } => f.write_str("AccessToken(<redacted>)"),
        }
    }
}

/// Result of [`METHOD_SYSTEM_HEALTH`]. The method takes no params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResult {
    /// The contract. This is the only field a consumer may branch on: a consumer
    /// cannot assume the daemon it reached is the binary it shipped with, so the
    /// protocol revision must be asked for explicitly and never inferred from
    /// `version`. Additive changes — a new credential kind, a new domain code, a
    /// new manifest field — do not increment it; removing a field, repurposing a
    /// code, or changing a default does.
    pub protocol: u32,
    /// Informational only: the daemon binary's version, for logs and bug reports.
    pub version: String,
}

impl Default for HealthResult {
    fn default() -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Mutation methods (UDS only; extend the retrieval surface with config/credential writes)
// ──────────────────────────────────────────────────────────────────────────────

/// Set a single config key on an env. Daemon-side, caller-scoped.
pub const METHOD_CONFIG_SET: &str = "config/set";
/// Get a single config key from an env. Daemon-side, caller-scoped.
pub const METHOD_CONFIG_GET: &str = "config/get";
/// Remove a single config key from an env. Daemon-side, caller-scoped.
pub const METHOD_CONFIG_UNSET: &str = "config/unset";
/// Remove a credential (source + encrypted material). Daemon-side, caller-scoped.
pub const METHOD_CREDENTIAL_REMOVE: &str = "credential/remove";
/// Remove an env. Daemon-side, caller-scoped.
pub const METHOD_ENV_REMOVE: &str = "environment/remove";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSetParams {
    #[serde(deserialize_with = "profile_name")]
    pub environment: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigGetParams {
    #[serde(deserialize_with = "profile_name")]
    pub environment: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigGetResult {
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUnsetParams {
    #[serde(deserialize_with = "profile_name")]
    pub environment: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRemoveParams {
    #[serde(deserialize_with = "profile_name")]
    pub credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvRemoveParams {
    #[serde(deserialize_with = "profile_name")]
    pub environment: String,
}

/// Unit result: the method succeeded, nothing to return.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OkResult {}

// ──────────────────────────────────────────────────────────────────────────────
// Import (UDS only; non-streaming batch seal of discovered static-key profiles)
// ──────────────────────────────────────────────────────────────────────────────

/// Import a batch of discovered static-key profiles as `iam-user` credentials.
///
/// Non-streaming: the client parses the AWS shared-credentials file (which the scoped daemon
/// user cannot read) and sends the discovered profiles; the daemon seals each key pair and
/// writes the per-uid tree under one write lock. Additive — a name that already exists is
/// skipped, never clobbered.
pub const METHOD_PROFILE_IMPORT: &str = "environment/import";

/// Params for [`METHOD_PROFILE_IMPORT`]: the discovered profiles and a dry-run flag.
///
/// No `Zeroize` derive on the struct itself: each [`ImportProfile`] is `ZeroizeOnDrop`, so the
/// secrets scrub when the `Vec` drops. Names are NOT validated at deserialize time — an invalid
/// name is a per-profile *skip* (Req 2.4), not a params error, so it must survive decoding.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportParams {
    pub profiles: Vec<ImportProfile>,
    #[serde(default)]
    pub dry_run: bool,
}

/// One discovered profile carrying its long-term key pair. Reuses [`ProviderParamsIamUser`]'s
/// zeroizing conventions: the secret is zeroized on drop and redacted from `Debug` (Req 6.1).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ImportProfile {
    #[zeroize(skip)]
    pub name: String,
    #[zeroize(skip)]
    pub access_key_id: String,
    /// The long-term secret access key. MUST NOT appear in logs or Debug output.
    pub secret_access_key: String,
    #[zeroize(skip)]
    pub region: String,
    /// `"human"`, `"automation"`, or `"agent"`. Absent means `"human"`.
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
}

impl fmt::Debug for ImportProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportProfile")
            .field("name", &self.name)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("region", &self.region)
            .field("identity_type", &self.identity_type)
            .finish()
    }
}

/// Result of [`METHOD_PROFILE_IMPORT`]: one outcome per submitted profile, in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub outcomes: Vec<ImportOutcome>,
}

/// A single profile's import outcome, so the client can print the summary without re-deciding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportOutcome {
    pub name: String,
    pub status: ImportStatus,
    /// Present for a skip; names why (already exists, invalid name). Never carries secret material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What happened (or would happen) to one profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportStatus {
    Imported,
    Skipped,
    /// `dry_run`: would import were this a real run.
    WouldImport,
    /// `dry_run`: would skip (for the same reason a real run would).
    WouldSkip,
}

/// Decoded DER triple returned by `decode_der` helpers: `(cert_der, key_der, chain_der)`.
pub type DecodedDer = (Vec<u8>, Vec<u8>, Vec<Vec<u8>>);

// ──────────────────────────────────────────────────────────────────────────────
// Bootstrap and login methods (UDS only; daemon-side interactive provider flows)
// ──────────────────────────────────────────────────────────────────────────────

/// Run a provider's full bootstrap flow on the daemon and stream notifications back.
/// The three provider flows: SSO (interactive device code + account/role selection),
/// IAM-user (client sends key material), Roles Anywhere (client sends cert/key DER).
pub const METHOD_PROFILE_BOOTSTRAP: &str = "environment/bootstrap";

/// Re-authenticate using saved provider config. SSO re-runs the device code flow;
/// IAM-user with MFA asks for a code; other sources are no-ops.
pub const METHOD_PROFILE_LOGIN: &str = "environment/login";

/// Client-to-daemon notification (no `id`) carrying the user's selection in response to a
/// `notifications/progress` step during bootstrap/login (account, role, or MFA code).
/// Not a dispatchable method — `serve_connection` routes it into the in-flight slot directly.
pub const METHOD_PROFILE_BOOTSTRAP_RESPOND: &str = "environment/bootstrap/respond";

/// Re-seal the snapshot of every drifted load-bearing file in the caller's own caller root. Gated:
/// a drifted root raises one challenge whose description is the drifted files' contents.
pub const METHOD_FILE_REVALIDATE: &str = "file/revalidate";

/// Parameters for `file/revalidate`: none. The daemon derives the caller root from the peer uid,
/// and a snapshot covers its whole file, so a selector naming one environment or credential would
/// reseal more than it names (drift-detection Requirement 4.3). Unknown fields are refused.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevalidateParams {}

// ──────────────────────────────────────────────────────────────────────────────
// Provider-params inline types for profile/bootstrap
// ──────────────────────────────────────────────────────────────────────────────

/// The provider choice and its inline parameters for `profile/bootstrap`.
///
/// AwsIamUser and AwsRolesAnywhere contain secret material and do NOT implement Debug —
/// their manual Debug impls redact the secret fields.
///
/// # Security invariant — content only, no file paths
///
/// Every field in every `ProviderParams*` struct MUST carry content (keys, tokens, secrets,
/// configuration values), never a file path. If a caller supplies a path on the command line,
/// the **client** reads it and sends the contents; the daemon never opens caller-supplied paths.
///
/// This is the OS enforcement mechanism: the client process runs as the caller's uid, so the
/// kernel enforces filesystem access at `open()` time on the client side. The daemon, running as
/// a privileged service user, would bypass that check — giving any caller read access to any
/// file the daemon can open (confused-deputy). Keeping paths off the wire eliminates the attack
/// surface entirely rather than trying to validate paths after the fact.
///
/// Adding a `*_file` or `*_path` field to any `ProviderParams*` struct violates this invariant.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderParams {
    AwsIdcSso(ProviderParamsSso),
    AwsIamUser(ProviderParamsIamUser),
    AwsRolesAnywhere(ProviderParamsRa),
    #[serde(rename = "aws_web_identity")]
    AwsWebIdentity(ProviderParamsAwsWebIdentity),
    AwsLogin(ProviderParamsAwsLogin),
    Jwt(ProviderParamsJwt),
    Oauth(ProviderParamsOauth),
    JwtBearer(ProviderParamsJwtBearer),
    StaticSecret(ProviderParamsStaticSecret),
    /// A provider type not recognised by this version.
    #[serde(other)]
    Unknown,
}

impl fmt::Debug for ProviderParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwsIdcSso(s) => f.debug_tuple("AwsIdcSso").field(s).finish(),
            Self::AwsIamUser(i) => f.debug_tuple("AwsIamUser").field(i).finish(),
            Self::AwsRolesAnywhere(r) => f.debug_tuple("AwsRolesAnywhere").field(r).finish(),
            Self::AwsWebIdentity(o) => f.debug_tuple("AwsWebIdentity").field(o).finish(),
            Self::AwsLogin(a) => f.debug_tuple("AwsLogin").field(a).finish(),
            Self::Jwt(j) => f.debug_tuple("Jwt").field(j).finish(),
            Self::Oauth(o) => f.debug_tuple("Oauth").field(o).finish(),
            Self::JwtBearer(j) => f.debug_tuple("JwtBearer").field(j).finish(),
            Self::StaticSecret(s) => f.debug_tuple("StaticSecret").field(s).finish(),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// `static-secret` provider params — carries the secret itself alongside the non-secret knobs,
/// the same shape `jwt` uses: the daemon-side bootstrap seals it inline, so a client holding the
/// secret needs no second round trip. Debug redacts the secret (manual impl below). Rotating it
/// later is another [`METHOD_PROFILE_BOOTSTRAP`] with a fresh value — there is no standalone
/// seal method, and no way to ask credsd to obtain one.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProviderParamsStaticSecret {
    /// The secret, verbatim. MUST NOT appear in logs or Debug output. Opaque: no structure is
    /// assumed and none is parsed.
    pub secret: String,
    /// Variable this credential projects as into a child process. `None` means the default
    /// (the credential name, upper-cased), the same one `jwt` uses.
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// Absolute expiry the user declared. `None` means the secret never expires — credsd
    /// cannot read a lifetime out of an opaque string and does not invent one.
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Where the secret came from, recorded for diagnostics only. Never read at runtime and
    /// never interpolated into a daemon message: it is caller-supplied text.
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_source: Option<String>,
    /// `"human"`, `"automation"`, or `"agent"`. Absent means `"human"`.
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
}

impl fmt::Debug for ProviderParamsStaticSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderParamsStaticSecret")
            .field("secret", &"<redacted>")
            .field("env_var", &self.env_var)
            .field("expires_at", &self.expires_at)
            .field("secret_source", &self.secret_source)
            .field("identity_type", &self.identity_type)
            .finish()
    }
}

/// `jwt` provider params — carries the JWT itself alongside the non-secret knobs, following
/// the same pattern iam-user and roles-anywhere follow: the daemon-side bootstrap seals the
/// secret inline, so a client with the token already in hand does not need a second round trip.
/// Debug redacts the JWT (manual impl below). Re-sealing later is another
/// [`METHOD_PROFILE_BOOTSTRAP`] with a fresh token — there is no standalone seal method.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProviderParamsJwt {
    /// The bearer JWT. MUST NOT appear in logs or Debug output.
    pub jwt: String,
    /// Variable this credential projects as into a child process. `None` means the default
    /// (the credential name, upper-cased), same one `credsd get --format shell` uses.
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// `"human"`, `"automation"`, or `"agent"`. Absent means `"human"`.
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
}

impl fmt::Debug for ProviderParamsJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderParamsJwt")
            .field("jwt", &"<redacted>")
            .field("env_var", &self.env_var)
            .field("identity_type", &self.identity_type)
            .finish()
    }
}

/// `aws-web-identity` provider params — OAuth endpoints and a role ARN, no secrets, safe to Debug.
///
/// The authorization code, the PKCE verifier, and every token stay daemon-side: the client sends
/// these knobs, opens a browser at the URL the daemon reports, and never handles material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderParamsAwsWebIdentity {
    #[serde(deserialize_with = "https_endpoint")]
    pub authorization_endpoint: String,
    #[serde(deserialize_with = "https_endpoint")]
    pub token_endpoint: String,
    pub client_id: String,
    /// Defaults to `["openid"]` rather than empty. The whole federation path depends on the AS
    /// returning an id_token — it is the JWT STS validates — and without the scope an AS may
    /// return only an opaque access token, which `web_identity_token` then falls back to and STS
    /// rejects with a message that blames the role ARN. Defaulted here as well as in the CLI
    /// because the CLI is not the only caller of this RPC.
    #[serde(
        default = "default_oauth_scopes",
        deserialize_with = "ensure_openid_scope"
    )]
    pub scopes: Vec<String>,
    pub role_arn: String,
    /// STS region. Required, with no default: a missing region is a parse error, not a guess.
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_session_name: Option<String>,
    /// `"human"`, `"automation"`, or `"agent"`. Absent means `"human"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
    /// Fixed loopback port for the OAuth callback server. Use when the IdP requires
    /// an exact redirect URI (e.g. Cognito). Omit for ephemeral.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_port: Option<u16>,
}

/// `aws-login` provider params — no secrets, safe to Debug. The client id and redirect shape are
/// fixed to the AWS CLI's, so the only knobs are the Sign-In region, the callback port, and which
/// of the two login flows to run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderParamsAwsLogin {
    /// Sign-In region. Required, with no default: a missing region is a parse error, not a guess.
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_port: Option<u16>,
    /// Cross-device login: no loopback listener, and the user carries the authorization result
    /// back by hand. For a host whose browser is somewhere else, such as one reached over SSH.
    #[serde(default)]
    pub remote: bool,
    /// `"human"`, `"automation"`, or `"agent"`. Absent means `"human"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
}

/// SSO provider params — no secrets, safe to Debug.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderParamsSso {
    pub start_url: String,
    /// Region of the IAM Identity Center instance. Required, with no default.
    pub sso_region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,
    /// `"human"`, `"automation"`, or `"agent"`. Absent means `"human"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
}

/// IAM-user provider params — contains secret material; Debug redacts `secret_access_key`.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProviderParamsIamUser {
    #[zeroize(skip)]
    pub access_key_id: String,
    /// The long-term secret access key. MUST NOT appear in logs or Debug output.
    pub secret_access_key: String,
    #[zeroize(skip)]
    pub region: String,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<i32>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_serial: Option<String>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
}

impl fmt::Debug for ProviderParamsIamUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderParamsIamUser")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("region", &self.region)
            .field("duration_seconds", &self.duration_seconds)
            .field("mfa_serial", &self.mfa_serial)
            .field("identity_type", &self.identity_type)
            .finish()
    }
}

/// Roles Anywhere provider params — contains secret key material; Debug redacts `key_der`.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProviderParamsRa {
    #[zeroize(skip)]
    pub trust_anchor_arn: String,
    #[zeroize(skip)]
    pub profile_arn: String,
    #[zeroize(skip)]
    pub role_arn: String,
    /// Base64-encoded DER of the leaf certificate (not secret).
    #[zeroize(skip)]
    pub cert_der: String,
    /// Base64-encoded DER of the private key. MUST NOT appear in logs or Debug output.
    pub key_der: String,
    /// PEM tag identifying the key format: `"PKCS8"`, `"RSA"`, or `"EC"`.
    #[zeroize(skip)]
    pub key_tag: String,
    /// Base64-encoded DER of each intermediate certificate (empty if no chain).
    #[zeroize(skip)]
    #[serde(default)]
    pub chain_der: Vec<String>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<i32>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_session_name: Option<String>,
    #[zeroize(skip)]
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "https_endpoint_opt"
    )]
    pub endpoint_url: Option<String>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
}

impl fmt::Debug for ProviderParamsRa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderParamsRa")
            .field("trust_anchor_arn", &self.trust_anchor_arn)
            .field("profile_arn", &self.profile_arn)
            .field("role_arn", &self.role_arn)
            .field("cert_der", &"<der>")
            .field("key_der", &"<redacted>")
            .field("key_tag", &self.key_tag)
            .field("chain_der_count", &self.chain_der.len())
            .field("region", &self.region)
            .finish()
    }
}

impl ProviderParamsRa {
    /// Decode the base64-encoded cert, key, and chain DERs.
    /// Returns `(cert_der, key_der, chain_der)`.
    /// `key_der` bytes are returned in a `Vec<u8>` — the caller wraps it in `Zeroizing`.
    pub fn decode_der(&self) -> Result<DecodedDer, String> {
        let cert = BASE64
            .decode(&self.cert_der)
            .map_err(|e| format!("cert_der: {e}"))?;
        let key = BASE64
            .decode(&self.key_der)
            .map_err(|e| format!("key_der: {e}"))?;
        let chain = self
            .chain_der
            .iter()
            .enumerate()
            .map(|(i, b)| BASE64.decode(b).map_err(|e| format!("chain_der[{i}]: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((cert, key, chain))
    }
}

/// `oauth` provider params — client-credentials (2LO) token endpoint. `client_secret` is
/// secret material; Debug redacts it.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProviderParamsOauth {
    #[zeroize(skip)]
    pub token_url: String,
    #[zeroize(skip)]
    pub client_id: String,
    /// The OAuth 2.0 client secret (client_secret_basic). Mutually exclusive with
    /// `private_key_pem`. MUST NOT appear in logs or Debug output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// PEM-encoded ES256 private key for `private_key_jwt` client authentication.
    /// Stored encrypted at rest; never written to credentials.toml.
    /// Mutually exclusive with `client_secret`. MUST NOT appear in logs or Debug output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
}

impl fmt::Debug for ProviderParamsOauth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderParamsOauth")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "private_key_pem",
                &self.private_key_pem.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .field("identity_type", &self.identity_type)
            .finish()
    }
}

/// `jwt-bearer` provider params. The assertion is content, not a path: the client reads
/// the assertion file and passes its bytes, ensuring access is bounded by the caller's
/// own permissions. MUST NOT appear in logs or Debug output.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProviderParamsJwtBearer {
    #[zeroize(skip)]
    #[serde(deserialize_with = "https_endpoint")]
    pub token_url: String,
    /// The signed JWT assertion. Sealed to disk at bootstrap; never stored in credentials.toml.
    pub assertion: String,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
}

impl fmt::Debug for ProviderParamsJwtBearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderParamsJwtBearer")
            .field("token_url", &self.token_url)
            .field("assertion", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("identity_type", &self.identity_type)
            .finish()
    }
}

/// Params for [`METHOD_PROFILE_BOOTSTRAP`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileBootstrapParams {
    #[serde(deserialize_with = "profile_name")]
    pub environment: String,
    #[serde(
        default,
        deserialize_with = "optional_credential_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub credential: Option<String>,
    pub provider: ProviderParams,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Params for [`METHOD_PROFILE_LOGIN`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileLoginParams {
    #[serde(deserialize_with = "profile_name")]
    pub environment: String,
    #[serde(
        default,
        deserialize_with = "optional_credential_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Client-to-daemon notification for [`METHOD_PROFILE_BOOTSTRAP_RESPOND`].
/// Carries the user's selection (account id, role name, or MFA code).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapRespondParams {
    pub selection: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Progress notification payload types for streaming bootstrap/login
// ──────────────────────────────────────────────────────────────────────────────

/// One entry in the account list sent during SSO account selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub id: String,
    pub name: String,
    pub email: String,
}

/// `params` payload of a `notifications/progress` notification.
///
/// Externally tagged on `type` so the client can branch on the step without knowing
/// every variant. The tag values are stable wire strings — changing one is a breaking
/// protocol change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProgressParams {
    /// SSO device-code flow has started. The client opens the browser and shows the code.
    DeviceCode {
        verification_uri: String,
        user_code: String,
    },
    /// SSO token polling is in progress. The client may show a spinner; no action needed.
    Polling,
    /// SSO account selection required. The client shows the list and sends a respond notification.
    SelectAccount { accounts: Vec<AccountInfo> },
    /// SSO role selection required. The client shows the list and sends a respond notification.
    SelectRole { roles: Vec<String> },
    /// IAM-user MFA code required. The client prompts stdin and sends a respond notification.
    MfaRequired { serial: String },
    /// An OAuth authorization-code flow is waiting on the browser. The client opens `url`; the
    /// daemon is already listening on the loopback `redirect_uri` embedded in it.
    ///
    /// No response notification follows — unlike the `Select*` steps, the answer arrives out of
    /// band, as the IdP's redirect to the daemon's own listener. The client's only job is to open
    /// the URL, which carries no secret: the PKCE challenge is public and the verifier never
    /// leaves the daemon.
    AuthorizeUrl { url: String },
    /// A cross-device OAuth authorization-code flow is waiting on a browser the daemon cannot be
    /// redirected to. The client shows `url`, then sends the value the provider's confirmation
    /// page displayed back as a respond notification.
    ///
    /// Unlike [`AuthorizeUrl`](Self::AuthorizeUrl) the answer cannot arrive out of band, which is
    /// the whole reason this step exists: there is no listener for the redirect to reach. What
    /// the user pastes carries an authorization code, so a client MUST NOT log or echo it.
    AuthorizeCode { url: String },
    /// A progress step not recognised by this version — the client should skip it.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{Id, Request, Response, Version, CODE_INVALID_PARAMS};

    /// The endpoint check is the daemon's only defense against being told to POST a PKCE
    /// verifier and a refresh token somewhere in cleartext. Asserted through `Request::params_as`,
    /// the path every caller actually takes.
    /// A raw RPC caller that omits `region` must be refused at parse time, before any approval
    /// challenge is built. The field is `String`, so there is no absent state to guess a default for.
    #[test]
    fn aws_web_identity_rpc_without_region_fails_to_parse() {
        let value = serde_json::json!({
            "environment": "dev",
            "provider": {
                "type": "aws_web_identity",
                "authorization_endpoint": "https://idp.example/authorize",
                "token_endpoint": "https://idp.example/token",
                "client_id": "cid",
                "role_arn": "arn:aws:iam::111111111111:role/r"
            }
        });
        let map = value.as_object().expect("object").clone();
        let err = Request {
            jsonrpc: Version::V2,
            id: Id::from(1),
            method: "profile/bootstrap".into(),
            params: Some(map),
        }
        .params_as::<ProfileBootstrapParams>()
        .expect_err("missing region must not parse");
        assert!(err.to_string().contains("missing field `region`"), "{err}");
    }

    /// A raw RPC `aws_iam_user` payload without `region` is refused at parse time, before any
    /// approval challenge. The field is `String`, so there is no absent state to default.
    #[test]
    fn aws_iam_user_rpc_without_region_fails_to_parse() {
        let value = serde_json::json!({
            "environment": "dev",
            "provider": {
                "type": "aws_iam_user",
                "access_key_id": "AKIAEXAMPLE",
                "secret_access_key": "secret"
            }
        });
        let map = value.as_object().expect("object").clone();
        let err = Request {
            jsonrpc: Version::V2,
            id: Id::from(1),
            method: "profile/bootstrap".into(),
            params: Some(map),
        }
        .params_as::<ProfileBootstrapParams>()
        .expect_err("missing region must not parse");
        assert!(err.to_string().contains("missing field `region`"), "{err}");
    }

    proptest::proptest! {
        /// A raw `aws_login` RPC caller that omits `region` is refused at parse time, whatever else
        /// the payload carries; a present region of any string parses. Region is `String`, so the
        /// approval challenge never has an absent value to describe.
        #[test]
        fn aws_login_rpc_region_presence_decides_the_parse(
            region in proptest::option::of(".*"),
            callback_port in proptest::option::of(proptest::num::u16::ANY),
            remote in proptest::bool::ANY,
            identity_type in proptest::option::of(proptest::sample::select(vec!["human", "automation", "agent"])),
        ) {
            let mut provider = serde_json::Map::new();
            provider.insert("type".into(), "aws_login".into());
            provider.insert("remote".into(), remote.into());
            if let Some(port) = callback_port {
                provider.insert("callback_port".into(), port.into());
            }
            if let Some(kind) = identity_type {
                provider.insert("identity_type".into(), kind.into());
            }
            if let Some(region) = &region {
                provider.insert("region".into(), region.as_str().into());
            }
            let params = serde_json::json!({ "environment": "dev", "provider": provider });
            let parsed = Request {
                jsonrpc: Version::V2,
                id: Id::from(1),
                method: "profile/bootstrap".into(),
                params: params.as_object().cloned(),
            }
            .params_as::<ProfileBootstrapParams>();
            match region {
                Some(_) => proptest::prop_assert!(parsed.is_ok(), "{:?}", parsed.err()),
                None => {
                    let err = parsed.expect_err("missing region must not parse");
                    proptest::prop_assert!(
                        err.to_string().contains("missing field `region`"),
                        "{err}"
                    );
                }
            }
        }
    }

    /// A raw RPC `aws_idc_sso` payload without `sso_region` is refused at parse time, before any
    /// approval challenge, the same as `aws_web_identity`.
    #[test]
    fn aws_idc_sso_rpc_without_sso_region_fails_to_parse() {
        let value = serde_json::json!({
            "environment": "dev",
            "provider": {
                "type": "aws_idc_sso",
                "start_url": "https://example.awsapps.com/start"
            }
        });
        let map = value.as_object().expect("object").clone();
        let err = Request {
            jsonrpc: Version::V2,
            id: Id::from(1),
            method: "profile/bootstrap".into(),
            params: Some(map),
        }
        .params_as::<ProfileBootstrapParams>()
        .expect_err("missing sso_region must not parse");
        assert!(
            err.to_string().contains("missing field `sso_region`"),
            "{err}"
        );
    }

    #[test]
    fn aws_web_identity_endpoints_must_be_https_without_userinfo() {
        let params = |endpoint: &str| {
            serde_json::json!({
                "environment": "dev",
                "provider": {
                    "type": "aws_web_identity",
                    "authorization_endpoint": "https://idp.example/authorize",
                    "token_endpoint": endpoint,
                    "client_id": "cid",
                    "role_arn": "arn:aws:iam::111111111111:role/r",
                    "region": "us-east-1"
                }
            })
        };
        let decode = |endpoint: &str| {
            let value = params(endpoint);
            let map = value.as_object().expect("object").clone();
            Request {
                jsonrpc: Version::V2,
                id: Id::from(1),
                method: "profile/bootstrap".into(),
                params: Some(map),
            }
            .params_as::<ProfileBootstrapParams>()
        };

        assert!(decode("https://idp.example/token").is_ok());
        // `scopes` omitted must default to openid, not to empty: an AS given no scope may return
        // no id_token, and STS then rejects the opaque access token.
        let decoded = decode("https://idp.example/token").expect("decode");
        match decoded.provider {
            ProviderParams::AwsWebIdentity(oauth) => {
                assert_eq!(oauth.scopes, vec!["openid".to_string()])
            }
            other => panic!("expected aws_web_identity, got {other:?}"),
        }
        assert!(decode("https://idp.example:8443/token?x=1").is_ok());

        // Explicit routes to a missing `openid`: `[]` skips the field's default (serde only
        // fires it on ABSENT), and `["profile"]` never contained `openid`. Both must land on a
        // scope list that starts with `openid`, since the whole federation path depends on it.
        let with_scopes = |scopes: serde_json::Value| {
            let mut v = params("https://idp.example/token");
            v["provider"]["scopes"] = scopes;
            let map = v.as_object().expect("object").clone();
            Request {
                jsonrpc: Version::V2,
                id: Id::from(1),
                method: "profile/bootstrap".into(),
                params: Some(map),
            }
            .params_as::<ProfileBootstrapParams>()
            .expect("decode")
        };
        for (input, want) in [
            (serde_json::json!([]), vec!["openid".to_string()]),
            (
                serde_json::json!(["profile"]),
                vec!["openid".to_string(), "profile".to_string()],
            ),
            (
                serde_json::json!(["openid", "profile"]),
                vec!["openid".to_string(), "profile".to_string()],
            ),
        ] {
            let decoded = with_scopes(input.clone());
            match decoded.provider {
                ProviderParams::AwsWebIdentity(oauth) => {
                    assert_eq!(oauth.scopes, want, "input {input}")
                }
                other => panic!("expected aws_web_identity, got {other:?}"),
            }
        }

        for rejected in [
            "http://idp.example/token",
            "HTTP://idp.example/token",
            "https://user:pass@idp.example/token",
            "https://",
            "idp.example/token",
            "file:///etc/passwd",
            // Percent-encoded @ bypass: WHATWG decodes %40, making the URL either
            // invalid (bad domain) or expose userinfo — rejected either way.
            "https://trusted.example.com%40attacker.com/token",
        ] {
            assert!(
                decode(rejected).is_err(),
                "{rejected} must be rejected as a token endpoint"
            );
        }
    }

    #[test]
    fn ra_endpoint_url_rejects_crafted_urls() {
        let make = |endpoint: Option<&str>| {
            let mut obj = serde_json::json!({
                "trust_anchor_arn": "arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/ta",
                "profile_arn": "arn:aws:rolesanywhere:us-east-1:111111111111:profile/p",
                "role_arn": "arn:aws:iam::111111111111:role/r",
                "cert_der": "dGVzdA==",
                "key_der": "dGVzdA==",
                "key_tag": "PRIVATE KEY"
            });
            if let Some(url) = endpoint {
                obj["endpoint_url"] = serde_json::json!(url);
            }
            serde_json::from_value::<ProviderParamsRa>(obj)
        };

        assert!(make(None).is_ok(), "absent endpoint_url must be accepted");
        assert!(
            make(Some("https://rolesanywhere.us-east-1.amazonaws.com")).is_ok(),
            "clean https URL must be accepted"
        );

        for rejected in [
            "http://rolesanywhere.us-east-1.amazonaws.com",
            "https://user@rolesanywhere.us-east-1.amazonaws.com",
            // %40 (percent-encoded @) bypass — WHATWG decodes it, either surfacing
            // userinfo or making the domain invalid; either way it is rejected.
            "https://trusted.amazonaws.com%40attacker.com",
        ] {
            assert!(
                make(Some(rejected)).is_err(),
                "{rejected} must be rejected as an RA endpoint_url"
            );
        }
    }

    /// Every projection input must survive the round trip. A field added to `EnvConfig` and not
    /// to `Projection` (or to either `From`) makes a client-side materialization silently drop
    /// it, which is the failure Req 6 AC 3 exists to prevent.
    #[test]
    fn projection_round_trips_every_field_it_carries() {
        let env = crate::config::EnvConfig {
            region: Some("us-west-2".into()),
            sdk: Some(crate::config::SdkSettings {
                endpoint_url: Some("https://localhost:4566".into()),
                max_attempts: Some(7),
                ..Default::default()
            }),
            cli: Some(crate::config::CliSettings {
                output: Some("json".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let projection = Projection::from(&env);
        let back = crate::config::EnvConfig::from(&projection);

        assert_eq!(Projection::from(&back), projection);
        assert_eq!(back.region, env.region);
        // Compared through TOML because neither settings type is `PartialEq`, and this asserts
        // over every field rather than a hand-picked few.
        let rendered = |e: &crate::config::EnvConfig| toml::to_string(e).expect("serialize");
        assert_eq!(rendered(&back), rendered(&env));
    }

    /// The two fields deliberately absent from the wire must not reappear via the inverse:
    /// `identity_type` is an authorization input the daemon does not disclose, and the credential
    /// list travels as `ProfileManifest::credentials`.
    #[test]
    fn projection_does_not_carry_credentials_or_identity_type() {
        let env = crate::config::EnvConfig {
            credentials: vec!["ra-main".into()],
            identity_type: crate::config::IdentityType::Agent,
            region: Some("us-east-1".into()),
            ..Default::default()
        };
        let back = crate::config::EnvConfig::from(&Projection::from(&env));
        assert!(back.credentials.is_empty());
        assert_eq!(
            back.identity_type,
            crate::config::IdentityType::default(),
            "identity_type must not travel on the manifest"
        );
    }

    /// The discriminant and the configured source must agree about what a credential can be
    /// projected as: the daemon sends the discriminant and the client resolves the projection
    /// from it, so a disagreement is a credential the daemon serves and the client cannot render.
    #[test]
    fn source_type_and_credential_source_agree_on_supported_projections() {
        use crate::config::credentials::CredentialSource;
        use crate::config::{IamUserConfig, RolesAnywhereConfig, SsoConfig};

        let sources = [
            CredentialSource::AwsIdcSso(SsoConfig {
                start_url: "https://example.awsapps.com/start".into(),
                sso_region: "us-east-1".into(),
                account_id: "111111111111".into(),
                role_name: "Admin".into(),
                identity_type: Default::default(),
            }),
            CredentialSource::AwsIamUser(IamUserConfig {
                region: "us-east-1".into(),
                duration_seconds: None,
                mfa_serial: None,
                identity_type: Default::default(),
            }),
            CredentialSource::AwsRolesAnywhere(RolesAnywhereConfig {
                trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:1:trust-anchor/ta".into(),
                profile_arn: "arn:aws:rolesanywhere:us-east-1:1:profile/p".into(),
                role_arn: "arn:aws:iam::1:role/r".into(),
                region: None,
                duration_seconds: None,
                role_session_name: None,
                endpoint_url: None,
                identity_type: Default::default(),
            }),
            CredentialSource::Unsupported,
        ];
        for source in sources {
            let discriminant = source.source_type();
            assert_eq!(
                source.supported_projections(),
                crate::projection::supported(discriminant),
                "{discriminant:?}"
            );
            assert_eq!(source.type_name(), discriminant.as_str());
        }
    }

    const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const SESSION_TOKEN: &str = "FwoGZXIvYXdzEBYaDHNlY3JldA";

    fn credential_result() -> CredentialResult {
        CredentialResult {
            credential: "login".into(),
            material: Material::SessionCredentials {
                access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
                secret_access_key: SECRET_KEY.into(),
                session_token: SESSION_TOKEN.into(),
            },
            expires_at: Some(DateTime::from_timestamp(1_800_000_000, 0).expect("valid timestamp")),
            provenance: Provenance::CachedShared,
        }
    }

    const BEARER_TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1In0.c2ln";

    fn token_result() -> CredentialResult {
        CredentialResult {
            credential: "login".into(),
            material: Material::AccessToken {
                token: BEARER_TOKEN.into(),
                token_type: "Bearer".into(),
            },
            expires_at: Some(DateTime::from_timestamp(1_800_000_000, 0).expect("valid timestamp")),
            provenance: Provenance::CachedShared,
        }
    }

    /// A credential with no issuer-stated lifetime must serialize `expires_at` as an explicit
    /// `null`, never as an absent key. The distinction is the consumer's: `null` says "never
    /// expires", an absent field says "this daemon did not tell me", and only one of those is
    /// safe to cache forever. A `skip_serializing_if` on the field would silently convert the
    /// first into the second and pass every round-trip test, so the key's presence is asserted
    /// directly against the JSON.
    #[test]
    fn a_missing_expiry_serializes_as_explicit_null() {
        let mut result = token_result();
        result.expires_at = None;

        let json = serde_json::to_value(&result).expect("serialize");
        let obj = json.as_object().expect("object");
        assert!(
            obj.contains_key("expires_at"),
            "expires_at must be present as null, not omitted: {json}"
        );
        assert_eq!(obj["expires_at"], serde_json::Value::Null, "{json}");

        let text = serde_json::to_string(&result).expect("serialize");
        assert!(text.contains("\"expires_at\":null"), "{text}");
    }

    /// The null is understood on the way back in, so a consumer and the daemon agree that the
    /// field is absent-of-expiry rather than absent-of-information.
    #[test]
    fn an_explicit_null_expiry_round_trips() {
        let mut result = token_result();
        result.expires_at = None;

        let text = serde_json::to_string(&result).expect("serialize");
        let back: CredentialResult = serde_json::from_str(&text).expect("deserialize");
        assert!(back.expires_at.is_none());
    }

    fn atomic_params(profile: &str) -> GetParams {
        GetParams {
            environment: profile.into(),
            credential: None,
            scope: None,
            claim: None,
            request_id: None,
        }
    }

    fn entry() -> CredentialEntry {
        CredentialEntry {
            projection: None,
            credential: "login".into(),
            kind: CredentialType::SessionCredentials,
            source: CredentialSourceType::AwsIdcSso,
            env_var: None,
            status: SessionStatus::Active,
            default: true,
        }
    }

    #[test]
    fn method_names_are_singular_and_do_not_collide_with_mcp() {
        assert_eq!(METHOD_CREDENTIAL_GET, "credential/get");
        assert_eq!(METHOD_CREDENTIAL_GET_BATCH, "credential/get_batch");
        assert_eq!(METHOD_CREDENTIAL_LIST, "credential/list");
        assert_eq!(METHOD_PROFILE_DESCRIBE, "environment/describe");
        assert_eq!(METHOD_SYSTEM_HEALTH, "system/health");
        for reserved in ["initialize", "tools/list", "tools/call"] {
            assert!(![
                METHOD_CREDENTIAL_GET,
                METHOD_CREDENTIAL_GET_BATCH,
                METHOD_CREDENTIAL_LIST,
                METHOD_PROFILE_DESCRIBE,
                METHOD_SYSTEM_HEALTH,
            ]
            .contains(&reserved));
        }
    }

    #[test]
    fn absent_claim_is_unstated() {
        let params: GetParams =
            serde_json::from_str("{\"environment\":\"dev\"}").expect("must deserialize");
        assert_eq!(params.claim, None);
    }

    #[test]
    fn agentic_claim_is_the_only_recognized_value() {
        let params: GetParams =
            serde_json::from_str("{\"environment\":\"dev\",\"claim\":\"agentic\"}")
                .expect("must deserialize");
        assert_eq!(params.claim, Some(Claim::Agentic));
        assert_eq!(
            serde_json::to_string(&Claim::Agentic).expect("serialize"),
            "\"agentic\""
        );
    }

    #[test]
    fn no_serialized_form_asserts_non_agent_status() {
        // Structured forms (bool, number, object) must not deserialize — only string
        // enum values are valid. Unknown string values parse as Claim::Unknown (graceful
        // degradation) rather than failing, so they are excluded from this list.
        for claim in ["false", "true", "0", "{\"agentic\":false}"] {
            let json = format!("{{\"environment\":\"dev\",\"claim\":{claim}}}");
            assert!(
                serde_json::from_str::<GetParams>(&json).is_err(),
                "claim {claim} must not deserialize"
            );
        }
        // Unknown string claims parse as Claim::Unknown (not as Agentic).
        for claim in [
            "\"human\"",
            "\"not_agentic\"",
            "\"none\"",
            "\"NONE\"",
            "\"Agentic\"",
            "\"\"",
        ] {
            let json = format!("{{\"environment\":\"dev\",\"claim\":{claim}}}");
            let parsed = serde_json::from_str::<GetParams>(&json)
                .expect("unknown string claim should parse as Unknown");
            assert_eq!(
                parsed.claim,
                Some(Claim::Unknown),
                "claim {claim} should parse as Unknown, not Agentic"
            );
        }
    }

    #[test]
    fn null_claim_means_unstated_not_non_agent() {
        let params: GetParams = serde_json::from_str("{\"environment\":\"dev\",\"claim\":null}")
            .expect("null is the absent case");
        assert_eq!(params.claim, None);
    }

    #[test]
    fn an_unstated_claim_is_omitted_from_the_wire_form() {
        let encoded = serde_json::to_string(&atomic_params("dev")).expect("serialize");
        assert_eq!(encoded, "{\"environment\":\"dev\"}");
    }

    #[test]
    fn get_params_reject_unknown_members() {
        let json = "{\"environment\":\"dev\",\"claimed\":\"agentic\"}";
        assert!(serde_json::from_str::<GetParams>(json).is_err());
    }

    #[test]
    fn get_params_require_a_profile() {
        let request = Request::new(Id::from(1), METHOD_CREDENTIAL_GET);
        let err = request
            .params_as::<GetParams>()
            .expect_err("profile is required");
        assert_eq!(err.code, CODE_INVALID_PARAMS);
    }

    #[test]
    fn an_absent_credential_is_the_profiles_configured_one() {
        let params: GetParams =
            serde_json::from_str("{\"environment\":\"dev\"}").expect("must deserialize");
        assert_eq!(params.credential, None);

        let named: GetParams =
            serde_json::from_str("{\"environment\":\"dev\",\"credential\":\"login\"}")
                .expect("must deserialize");
        assert_eq!(named.credential.as_deref(), Some("login"));
    }

    #[test]
    fn an_absent_scope_means_boundary_scoped_and_is_omitted_from_the_wire_form() {
        let params: GetParams =
            serde_json::from_str("{\"environment\":\"dev\"}").expect("must deserialize");
        assert_eq!(params.scope, None);

        let scoped = GetParams {
            scope: Some(Scope(serde_json::json!({"Version": "2012-10-17"}))),
            ..atomic_params("dev")
        };
        let encoded = serde_json::to_string(&scoped).expect("serialize");
        assert_eq!(
            encoded,
            "{\"environment\":\"dev\",\"scope\":{\"Version\":\"2012-10-17\"}}"
        );
    }

    #[test]
    fn debug_does_not_leak_a_scope_document() {
        let params = GetParams {
            scope: Some(Scope(
                serde_json::json!({"Resource": "arn:aws:s3:::secret-bucket"}),
            )),
            ..atomic_params("dev")
        };
        let rendered = format!("{params:?}");
        assert!(!rendered.contains("secret-bucket"), "{rendered}");
        assert!(rendered.contains("Scope(<policy>)"), "{rendered}");
    }

    /// Names that JSON params make reachable for the first time. Under HTTP the
    /// router filtered these incidentally — a path segment cannot hold a `/` or a
    /// newline, and the request line bounded the length.
    const REJECTED_NAMES: [&str; 12] = [
        "",
        "dev\nprofile = admin",
        "dev\u{7}",
        "dev\u{0}",
        "../../etc",
        "a/b",
        "a\\b",
        "..",
        ".hidden",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "café",
        "dev profile",
    ];

    const ACCEPTED_NAMES: [&str; 5] = ["dev", "dev-1", "dev_1", "dev.1", "A0"];

    #[test]
    fn every_name_field_validates_at_deserialize_time() {
        for name in REJECTED_NAMES {
            let encoded = serde_json::to_string(name).expect("serialize");
            for json in [
                format!("{{\"environment\":{encoded}}}"),
                format!("{{\"environment\":\"dev\",\"credential\":{encoded}}}"),
            ] {
                assert!(
                    serde_json::from_str::<GetParams>(&json).is_err(),
                    "must not deserialize: {json}"
                );
            }
            let batch = format!("{{\"environment\":{encoded}}}");
            assert!(
                serde_json::from_str::<GetBatchParams>(&batch).is_err(),
                "must not deserialize: {batch}"
            );
            assert!(
                serde_json::from_str::<ListParams>(&batch).is_err(),
                "must not deserialize: {batch}"
            );
        }

        for name in ACCEPTED_NAMES {
            let json = format!("{{\"environment\":\"{name}\",\"credential\":\"{name}\"}}");
            let params: GetParams =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
            assert_eq!(params.environment, name);
            serde_json::from_str::<GetBatchParams>(&format!("{{\"environment\":\"{name}\"}}"))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            serde_json::from_str::<ListParams>(&format!("{{\"environment\":\"{name}\"}}"))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn an_invalid_name_surfaces_as_invalid_params_without_echoing_the_input() {
        let forged = "dev\n[audit] profile = admin";
        let request = Request::with_params(
            Id::from(1),
            METHOD_CREDENTIAL_GET,
            &serde_json::json!({"environment": forged}),
        )
        .expect("object params");
        let err = request
            .params_as::<GetParams>()
            .expect_err("a forged name must not deserialize");

        assert_eq!(err.code, CODE_INVALID_PARAMS);
        // The whole point: this message is logged, so it must carry the rule and
        // never the value. `validate_name`'s own messages interpolate the name.
        assert!(!err.message.contains("admin"), "{}", err.message);
        assert!(!err.message.contains('\n'), "{}", err.message);
        assert!(err.message.contains("environment: "), "{}", err.message);
        assert!(err.message.contains("max 64 characters"), "{}", err.message);
    }

    #[test]
    fn a_name_at_the_length_limit_is_accepted_and_one_over_is_not() {
        let at_limit = "n".repeat(64);
        let over = "n".repeat(65);
        serde_json::from_str::<GetParams>(&format!("{{\"environment\":\"{at_limit}\"}}"))
            .expect("64 characters is the limit, not one past it");
        assert!(
            serde_json::from_str::<GetParams>(&format!("{{\"environment\":\"{over}\"}}")).is_err(),
            "65 characters must be rejected"
        );
    }

    #[test]
    fn batch_params_name_a_profile_and_nothing_else() {
        let params: GetBatchParams = serde_json::from_str("{\"environment\":\"dev\"}")
            .expect("a profile is the whole subject");
        assert_eq!(params.environment, "dev");
        assert_eq!(
            serde_json::to_string(&params).expect("serialize"),
            "{\"environment\":\"dev\"}"
        );
    }

    #[test]
    fn batch_params_reject_caller_supplied_membership() {
        for smuggled in [
            "{\"environment\":\"dev\",\"credential\":\"login\"}",
            "{\"environment\":\"dev\",\"credentials\":[\"login\"]}",
            "{\"environment\":\"dev\",\"requests\":[{\"environment\":\"dev\"}]}",
            "{\"requests\":[{\"environment\":\"dev\"}]}",
        ] {
            assert!(
                serde_json::from_str::<GetBatchParams>(smuggled).is_err(),
                "membership is credsd's to determine: {smuggled}"
            );
        }
    }

    #[test]
    fn a_batch_requires_a_profile() {
        let request = Request::new(Id::from(1), METHOD_CREDENTIAL_GET_BATCH);
        let err = request
            .params_as::<GetBatchParams>()
            .expect_err("profile is required");
        assert_eq!(err.code, CODE_INVALID_PARAMS);
    }

    #[test]
    fn a_batch_result_has_no_per_element_status_and_names_each_credential() {
        let result = GetBatchResult {
            credentials: vec![credential_result()],
        };
        let encoded = serde_json::to_value(&result).expect("serialize");
        let keys: Vec<&String> = encoded.as_object().expect("object").keys().collect();
        assert_eq!(
            keys,
            vec!["credentials"],
            "no room for a partial-success flag"
        );

        let element = encoded["credentials"][0]
            .as_object()
            .expect("element object");
        let mut element_keys: Vec<&str> = element.keys().map(String::as_str).collect();
        element_keys.sort_unstable();
        assert_eq!(
            element_keys,
            ["credential", "expires_at", "material", "provenance"]
        );
        assert_eq!(element["credential"], serde_json::json!("login"));
    }

    #[test]
    fn list_params_accept_an_empty_object() {
        let params: ListParams = serde_json::from_str("{}").expect("all fields are optional");
        assert_eq!(params, ListParams::default());
        assert_eq!(
            serde_json::to_string(&ListParams::default()).expect("serialize"),
            "{}"
        );
    }

    #[test]
    fn a_manifest_entry_carries_every_datum_a_shim_needs_and_no_material() {
        let manifest = ProfileManifest {
            environment: "dev".into(),
            credentials: vec![entry()],
            projection: Projection::default(),
        };
        let encoded = serde_json::to_value(&manifest).expect("serialize");
        let manifest_entry = &encoded["credentials"][0];
        let mut keys: Vec<&str> = manifest_entry
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["credential", "default", "kind", "source", "status"],
            "a field added here has to justify itself against Requirement 6 AC 2"
        );
        assert_eq!(
            manifest_entry,
            &serde_json::json!({
                "credential": "login",
                "kind": "session_credentials",
                "source": "aws_idc_sso",
                "status": "active",
                "default": true,
            })
        );

        // Requirement 6 AC 2, stated as a property rather than left implicit in
        // the exact shape above. Asserted on keys rather than on rendered text
        // because a kind or status *value* may legitimately contain "token".
        let object = manifest_entry.as_object().expect("object");
        for material_bearing in ["material", "access_key_id", "secret_access_key", "token"] {
            assert!(
                !object.contains_key(material_bearing),
                "{material_bearing} in {manifest_entry}"
            );
        }
    }

    #[test]
    fn enumeration_omits_the_two_fields_the_manifest_adds() {
        let result = ListResult {
            credentials: vec![CredentialSummary {
                environment: "dev".into(),
                credential: "login".into(),
                kind: CredentialType::SessionCredentials,
                status: SessionStatus::Active,
            }],
        };
        let encoded = serde_json::to_value(&result).expect("serialize");
        let summary = encoded["credentials"][0].as_object().expect("object");
        let mut keys: Vec<&str> = summary.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["credential", "environment", "kind", "status"]);

        // Requirement 13 AC 4 caps this method at name, kind, and status. These are
        // the two fields the manifest carries and enumeration must not, and the
        // model-facing carrier is why: a field added here is permanent.
        for manifest_only in ["source", "default", "projection", "region"] {
            assert!(
                !summary.contains_key(manifest_only),
                "{manifest_only} must not reach the enumeration"
            );
        }
    }

    #[test]
    fn the_projection_carries_profile_config_and_not_the_authorization_input() {
        let manifest = ProfileManifest {
            environment: "dev".into(),
            credentials: vec![entry()],
            projection: Projection {
                projections: Default::default(),
                region: Some("us-west-2".into()),
                sdk: Some(crate::config::SdkSettings {
                    endpoint_url: Some("https://example.invalid".into()),
                    ..Default::default()
                }),
                cli: None,
            },
        };
        let encoded = serde_json::to_value(&manifest).expect("serialize");
        assert_eq!(
            encoded["projection"]["region"],
            serde_json::json!("us-west-2")
        );
        assert_eq!(
            encoded["projection"]["sdk"]["endpoint_url"],
            serde_json::json!("https://example.invalid")
        );
        // Absent options are omitted, so a shim distinguishes "unset" from "empty"
        // without a sentinel, and the ~20 SDK/CLI knobs cost nothing when unused.
        let projection = encoded["projection"].as_object().expect("object");
        assert!(!projection.contains_key("cli"));
        // An authorization input, not a projection one: disclosing it would tell a
        // caller how it is about to be classified.
        assert!(!projection.contains_key("identity_type"));

        let empty = serde_json::to_string(&Projection::default()).expect("serialize");
        assert_eq!(empty, "{}");
    }

    #[test]
    fn describe_requires_a_profile_and_rejects_unknown_members() {
        let params: DescribeParams =
            serde_json::from_str("{\"environment\":\"dev\"}").expect("profile alone is valid");
        assert_eq!(params.environment, "dev");
        assert!(serde_json::from_str::<DescribeParams>("{}").is_err());
        assert!(
            serde_json::from_str::<DescribeParams>(
                "{\"environment\":\"dev\",\"credential\":\"x\"}"
            )
            .is_err(),
            "the manifest has no credential selector to smuggle membership through"
        );
        assert!(
            serde_json::from_str::<DescribeParams>("{\"environment\":\"../etc\"}").is_err(),
            "names are validated at deserialize time"
        );
    }

    #[test]
    fn the_kind_vocabulary_is_shared_between_manifest_and_material() {
        let kind = serde_json::to_value(CredentialType::SessionCredentials).expect("serialize");
        let material = serde_json::to_value(credential_result()).expect("serialize");
        assert_eq!(
            material["material"]["type"], kind,
            "a consumer must not get two names for one kind"
        );
        assert_eq!(kind, serde_json::json!("session_credentials"));
        assert_eq!(
            serde_json::to_value(CredentialType::AccessToken).expect("serialize"),
            serde_json::json!("access_token")
        );
    }

    #[test]
    fn source_types_mirror_the_config_variants_and_degrade_on_an_unknown_one() {
        // snake_case, deliberately *not* `CredentialSource`'s kebab-case tags: the
        // variants are mirrored, the spelling is this protocol's. See the type's docs.
        for (source, wire) in [
            (CredentialSourceType::AwsIdcSso, "\"aws_idc_sso\""),
            (CredentialSourceType::AwsIamUser, "\"aws_iam_user\""),
            (
                CredentialSourceType::AwsRolesAnywhere,
                "\"aws_roles_anywhere\"",
            ),
            (CredentialSourceType::Unsupported, "\"unsupported\""),
        ] {
            assert_eq!(serde_json::to_string(&source).expect("serialize"), wire);
        }
        let future: CredentialSourceType = serde_json::from_str("\"some-future-source\"")
            .expect("an unknown source must not fail");
        assert_eq!(future, CredentialSourceType::Unsupported);
    }

    #[test]
    fn session_status_preserves_all_nine_states() {
        let states = [
            (SessionStatus::Active, "\"active\""),
            (SessionStatus::Expiring, "\"expiring\""),
            (SessionStatus::Expired, "\"expired\""),
            (SessionStatus::NoSession, "\"no_session\""),
            (SessionStatus::Corrupt, "\"corrupt\""),
            (SessionStatus::Unreadable, "\"unreadable\""),
            (SessionStatus::DecryptFailed, "\"decrypt_failed\""),
            (SessionStatus::Unknown, "\"unknown\""),
            (SessionStatus::SignInRequired, "\"sign_in_required\""),
        ];
        for (status, wire) in states {
            assert_eq!(serde_json::to_string(&status).expect("serialize"), wire);
            let decoded: SessionStatus = serde_json::from_str(wire).expect("round trip");
            assert_eq!(decoded, status);
        }
        // The count is the assertion: `credential_status` distinguishes nine
        // states, and dropping one here would silently collapse two operator
        // actions into one.
        assert_eq!(states.len(), 9);
    }

    #[test]
    fn provenance_distinguishes_shared_material_from_minted_material() {
        for (provenance, wire) in [
            (Provenance::CachedShared, "\"cached_shared\""),
            (Provenance::MintedForRequest, "\"minted_for_request\""),
        ] {
            assert_eq!(serde_json::to_string(&provenance).expect("serialize"), wire);
        }
        let encoded = serde_json::to_string(&credential_result()).expect("serialize");
        assert!(
            encoded.contains("\"provenance\":\"cached_shared\""),
            "{encoded}"
        );
    }

    #[test]
    fn a_result_without_provenance_is_rejected() {
        let json = "{\"credential\":\"login\",\"material\":{\"type\":\"session_credentials\",\"access_key_id\":\"a\",\"secret_access_key\":\"b\",\"session_token\":\"c\"},\"expires_at\":\"2027-01-01T00:00:00Z\"}";
        assert!(
            serde_json::from_str::<CredentialResult>(json).is_err(),
            "provenance is not optional: a consumer must not have to assume it"
        );
    }

    #[test]
    fn unknown_material_tag_is_rejected_by_name() {
        let json = "{\"credential\":\"login\",\"material\":{\"type\":\"gcp_token\",\"access_key_id\":\"a\",\"secret_access_key\":\"b\",\"session_token\":\"c\"},\"expires_at\":\"2027-01-01T00:00:00Z\",\"provenance\":\"cached_shared\"}";
        let err =
            serde_json::from_str::<CredentialResult>(json).expect_err("unknown tag must fail");
        let message = err.to_string();
        assert!(message.contains("gcp_token"), "{message}");
        assert!(message.contains("session_credentials"), "{message}");
    }

    #[test]
    fn material_without_a_tag_is_rejected() {
        let json = "{\"credential\":\"login\",\"material\":{\"access_key_id\":\"a\",\"secret_access_key\":\"b\",\"session_token\":\"c\"},\"expires_at\":\"2027-01-01T00:00:00Z\",\"provenance\":\"cached_shared\"}";
        assert!(serde_json::from_str::<CredentialResult>(json).is_err());
    }

    /// Every material variant, through every wrapper that could render one. A new variant that
    /// forgot its `Debug` arm derives one that prints the secret, so the loop is over variants
    /// rather than over one representative.
    #[test]
    fn debug_does_not_leak_secret_material() {
        for build in [credential_result, token_result] {
            let result = build();
            for rendered in [
                format!("{result:?}"),
                format!("{:?}", result.material),
                format!("{:?}", Response::success(Id::from(1), build())),
                format!("{:#?}", build()),
                format!(
                    "{:?}",
                    GetBatchResult {
                        credentials: vec![build()]
                    }
                ),
            ] {
                assert!(!rendered.contains(SECRET_KEY), "{rendered}");
                assert!(!rendered.contains(SESSION_TOKEN), "{rendered}");
                assert!(!rendered.contains(BEARER_TOKEN), "{rendered}");
                assert!(!rendered.contains("AKIAIOSFODNN7EXAMPLE"), "{rendered}");
                assert!(rendered.contains("redacted"), "{rendered}");
            }
        }
    }

    #[test]
    fn jwt_bearer_params_do_not_disclose_the_token() {
        const JWT: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1IiwiZXhwIjo5OTk5OTk5OTk5fQ.sig";

        let bootstrap = ProviderParamsJwt {
            jwt: JWT.into(),
            env_var: Some("GITHUB_TOKEN".into()),
            identity_type: Some("automation".into()),
        };
        for rendered in [format!("{bootstrap:?}"), format!("{bootstrap:#?}")] {
            assert!(
                !rendered.contains(JWT),
                "bootstrap params leak the JWT: {rendered}"
            );
            assert!(rendered.contains("redacted"), "{rendered}");
            assert!(rendered.contains("GITHUB_TOKEN"), "{rendered}");
        }
    }

    #[test]
    fn zeroize_clears_material_but_keeps_the_credential_name() {
        for build in [credential_result, token_result] {
            let mut result = build();
            result.zeroize();
            assert_eq!(result.credential, "login");
            match &result.material {
                Material::SessionCredentials {
                    access_key_id,
                    secret_access_key,
                    session_token,
                } => {
                    assert!(access_key_id.is_empty());
                    assert!(secret_access_key.is_empty());
                    assert!(session_token.is_empty());
                }
                // `token_type` is deliberately `zeroize(skip)`: it is the public
                // `Authorization` scheme, not secret, and a consumer needs it after the token
                // has been scrubbed to report what it was holding.
                Material::AccessToken { token, token_type } => {
                    assert!(token.is_empty());
                    assert_eq!(token_type, "Bearer");
                }
            }
        }
    }

    #[test]
    fn import_profile_redacts_and_zeroizes_its_secret() {
        const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let mut profile = ImportProfile {
            name: "work".into(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: SECRET.into(),
            region: "us-east-1".into(),
            identity_type: None,
        };
        for rendered in [format!("{profile:?}"), format!("{profile:#?}")] {
            assert!(!rendered.contains(SECRET), "leaked secret: {rendered}");
            assert!(rendered.contains("redacted"), "{rendered}");
            assert!(rendered.contains("work"), "{rendered}");
        }
        // The whole batch round-trips, dry_run defaults to false, and the params Debug (which
        // delegates to the redacting ImportProfile Debug) does not leak the secret.
        let json = format!(
            "{{\"profiles\":[{{\"name\":\"work\",\"access_key_id\":\"a\",\"secret_access_key\":\"{SECRET}\",\"region\":\"us-east-1\"}}]}}"
        );
        let params: ImportParams = serde_json::from_str(&json).expect("decode");
        assert!(!params.dry_run);
        assert_eq!(params.profiles[0].name, "work");
        assert!(
            !format!("{params:?}").contains(SECRET),
            "params Debug leaked secret"
        );

        profile.zeroize();
        assert!(profile.secret_access_key.is_empty());
        assert_eq!(profile.name, "work", "name is not secret and is preserved");
    }

    #[test]
    fn import_status_wire_spellings_are_snake_case() {
        for (status, wire) in [
            (ImportStatus::Imported, "\"imported\""),
            (ImportStatus::Skipped, "\"skipped\""),
            (ImportStatus::WouldImport, "\"would_import\""),
            (ImportStatus::WouldSkip, "\"would_skip\""),
        ] {
            assert_eq!(serde_json::to_string(&status).expect("serialize"), wire);
        }
    }

    #[test]
    fn health_result_reports_protocol_one_and_the_crate_version() {
        let health = HealthResult::default();
        assert_eq!(health.protocol, 1);
        assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn with_params_builds_an_object_and_round_trips_through_params_as() {
        let params = GetParams {
            credential: Some("login".into()),
            claim: Some(Claim::Agentic),
            request_id: Some("corr-1".into()),
            ..atomic_params("dev")
        };
        let request = Request::with_params(Id::from(1), METHOD_CREDENTIAL_GET, &params)
            .expect("object params");
        assert_eq!(request.params_as::<GetParams>().expect("decode"), params);
    }
}
