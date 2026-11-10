//! Which projection each credential of a selection takes, and whether the resulting set can be
//! delivered at all.
//!
//! A projection is *chosen*, not deduced. A credential may declare the projection it takes, an
//! environment may override that for the credentials it composes, and an invocation may override
//! both. [`resolve`] applies that precedence, refuses a projection the credential's type cannot
//! take, and refuses a set whose projections collide — all before any credential material is
//! fetched, so a refusal costs no fetch and leaks nothing.
//!
//! Every projection occupies an [`Address`] in the child: a variable name, a profile name, or one
//! of the two singleton slots. Two credentials cannot share an address, and a singleton slot holds
//! exactly one credential, so collision is a property of the resolved set rather than a check each
//! projection type writes for itself.
//!
//! The endpoint is an address, not a per-credential projection. `credential-endpoint` is
//! declarable, but it resolves to the container-discovery singleton being *filled by the default
//! identity* — the credential keeps its own primary projection. Modelling it as a second
//! projection for that credential would contradict "exactly one projection per credential", since
//! the default identity is by definition a credential that already takes `aws-profile`.
//!
//! Naming: [`crate::rpc::Projection`] is an older, unrelated use of the word — the env settings
//! (region, sdk, cli) a manifest carries so a client can render without reading config. Nothing
//! here touches it.

use serde::{Deserialize, Serialize};

use crate::error::{DaemonError, Result};
use crate::rpc::CredentialSourceType;

/// Whether `name` is usable as an environment variable name.
///
/// Checked where the address space is known rather than at parse time, so a declaration carrying a
/// bad name still loads and is refused by credential with a message naming the malformation.
pub fn valid_env_var(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A way a credential becomes reachable by a child process.
///
/// Kebab-case on the wire and in config, one spelling at every association level, so a credential
/// entry, an env entry, and a command-line override cannot disagree about how to name the same
/// projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionType {
    /// A `[profile <cred>]` entry in the generated AWS config, resolved through a
    /// `credential_process` line. The first such credential also fills the default-profile slot.
    AwsProfile,
    /// The credential's material, exported as an environment variable in the child.
    ///
    /// Unlike [`AwsProfile`](Self::AwsProfile), which hands the child a *reference* the SDK
    /// resolves per call, this hands over the value once, at spawn: a child outliving the token's
    /// expiry keeps a stale one.
    EnvVar,
    /// An HTTP credential endpoint the child discovers from a fixed pair of variables. Requires a
    /// facility, so it is the projection that makes an invocation resident.
    CredentialEndpoint,
    /// A projection type this build does not recognise. Unknown spellings parse to this rather
    /// than failing the whole file, and [`resolve`] refuses the credential instead of projecting
    /// it by another type.
    #[serde(other)]
    Unsupported,
}

/// How many credentials one projection type may project in one invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cardinality {
    One,
    Many,
}

/// The slot in a child that a projection occupies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address {
    /// A named AWS profile.
    Profile(String),
    /// An environment variable.
    EnvVar(String),
    /// The generated config's `[default]` profile. Singleton.
    DefaultProfile,
    /// The container-credentials discovery variables. Singleton.
    ContainerEndpoint,
}

impl Address {
    /// How many credentials this address admits.
    pub fn cardinality(&self) -> Cardinality {
        match self {
            Self::Profile(_) | Self::EnvVar(_) => Cardinality::Many,
            Self::DefaultProfile | Self::ContainerEndpoint => Cardinality::One,
        }
    }

    /// How the address is named in a refusal, in the vocabulary the user configured it with.
    pub fn describe(&self) -> String {
        match self {
            Self::Profile(p) => format!("profile '{p}'"),
            Self::EnvVar(v) => format!("variable '{v}'"),
            Self::DefaultProfile => "the default profile".to_owned(),
            Self::ContainerEndpoint => "the container credentials endpoint".to_owned(),
        }
    }
}

impl ProjectionType {
    /// The human- and config-facing spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwsProfile => "aws-profile",
            Self::EnvVar => "env-var",
            Self::CredentialEndpoint => "credential-endpoint",
            Self::Unsupported => "unsupported",
        }
    }

    /// How many credentials this type may project in one invocation.
    pub fn cardinality(self) -> Cardinality {
        match self {
            Self::AwsProfile | Self::EnvVar => Cardinality::Many,
            // One container-discovery slot, so one credential.
            Self::CredentialEndpoint | Self::Unsupported => Cardinality::One,
        }
    }

    /// Whether providing this projection obliges the shim to stay resident for the child.
    pub fn requires_facility(self) -> bool {
        matches!(self, Self::CredentialEndpoint)
    }

    /// Whether an address in this type's space may be declared.
    ///
    /// A type fixes its address rather than offering it when the space holds one address, or when the
    /// address is determined by the credential projected. `aws-profile` is the second case: a profile
    /// is named for its credential, which is already the handle in `--credential` and in the
    /// generated config, and letting a projection re-point it would give one credential two names
    /// with nothing in the child to map between them.
    pub fn address_declarable(self) -> bool {
        matches!(self, Self::EnvVar)
    }
}

/// A declaration at one association level: a projection type, and the address it takes where its
/// type admits one.
///
/// A pair rather than a bare [`ProjectionType`] because precedence has to be spellable and not only
/// resolvable. A level whose representation holds only a type cannot participate in the address
/// ladder, and under [`ProjectionType`]'s deliberate leniency about unknown spellings an
/// address-bearing value would not merely fail to parse — it would read as a type this build does not
/// recognise, and the credential would be refused for the wrong reason.
///
/// Spelled `<type>[:<address>]` in configuration, on the wire, and on the command line, so one
/// vocabulary covers every level (Req 2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionDecl {
    pub projection: ProjectionType,
    /// The address this level declares, if it declared one. `None` leaves the address to a lower
    /// level or to derivation — it is not a claim that the type's default applies.
    pub address: Option<String>,
}

impl ProjectionDecl {
    /// A declaration naming a type and no address.
    pub fn new(projection: ProjectionType) -> Self {
        Self {
            projection,
            address: None,
        }
    }

    /// A declaration naming both.
    pub fn with_address(projection: ProjectionType, address: impl Into<String>) -> Self {
        Self {
            projection,
            address: Some(address.into()),
        }
    }

    /// Split `<type>[:<address>]` without judging either half.
    ///
    /// `parse_type` decides how strictly the type is read: leniently for configuration, where an
    /// unknown spelling must not make a file unloadable, and strictly for a command line, where a
    /// typo is better answered at the argument.
    fn split(s: &str, parse_type: impl FnOnce(&str) -> Result<ProjectionType>) -> Result<Self> {
        let (type_part, address) = match s.split_once(':') {
            Some((t, addr)) => (t, Some(addr.to_owned())),
            None => (s, None),
        };
        Ok(Self {
            projection: parse_type(type_part)?,
            address,
        })
    }
}

/// Strict about the type, because a command line has no obligation to tolerate a typo.
impl std::str::FromStr for ProjectionDecl {
    type Err = DaemonError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::split(s, str::parse)
    }
}

impl std::fmt::Display for ProjectionDecl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.address {
            Some(addr) => write!(f, "{}:{}", self.projection.as_str(), addr),
            None => write!(f, "{}", self.projection.as_str()),
        }
    }
}

impl Serialize for ProjectionDecl {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// Lenient about the type and total over the address, so one forward-looking entry cannot make a
/// configuration file or a manifest unloadable. An unrecognised type becomes
/// [`ProjectionType::Unsupported`] and an unusable address is carried as written; [`resolve`] refuses
/// either, by credential, with a message naming which fault it is.
impl<'de> Deserialize<'de> for ProjectionDecl {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::split(&raw, |t| {
            Ok(t.parse().unwrap_or(ProjectionType::Unsupported))
        })
        .map_err(serde::de::Error::custom)
    }
}

/// Strict where the serde impl is lenient, and deliberately so. Config parses an unknown spelling
/// to [`ProjectionType::Unsupported`] so one forward-looking entry cannot make a file unloadable;
/// a command line has no such obligation, and a typo there is better answered at the argument than
/// by a resolver refusal further in.
impl std::str::FromStr for ProjectionType {
    type Err = DaemonError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "aws-profile" => Ok(Self::AwsProfile),
            "env-var" => Ok(Self::EnvVar),
            "credential-endpoint" => Ok(Self::CredentialEndpoint),
            other => Err(DaemonError::config(format!(
                "unknown projection '{other}'; known projections are {}",
                describe_supported(&[Self::AwsProfile, Self::EnvVar, Self::CredentialEndpoint]),
            ))),
        }
    }
}

/// The projections a source of a given kind can be projected as, most-preferred first.
///
/// Empty for [`CredentialSourceType::Unsupported`] — a source no provider can resolve has no
/// projection, which is what makes an env composing it an error rather than a silently empty
/// profile.
pub fn supported(source: CredentialSourceType) -> &'static [ProjectionType] {
    use CredentialSourceType as S;
    match source {
        S::AwsIdcSso | S::AwsIamUser | S::AwsRolesAnywhere | S::AwsWebIdentity | S::AwsLogin => &[
            ProjectionType::AwsProfile,
            ProjectionType::CredentialEndpoint,
        ],
        // Bearer-token sources have no AWS profile to render as — an SDK reading a
        // `credential_process` line would get a token it cannot use — and nothing to serve on an
        // AWS container endpoint. Their projection is the variable the API's own client reads.
        S::Jwt | S::Oauth | S::JwtBearer | S::StaticSecret => &[ProjectionType::EnvVar],
        S::Unsupported => &[],
    }
}

/// The projection a source takes when no level declares one.
pub fn default_projection(source: CredentialSourceType) -> Option<ProjectionType> {
    supported(source).first().copied()
}

pub fn describe_supported(allowed: &[ProjectionType]) -> String {
    if allowed.is_empty() {
        return "no projection".to_owned();
    }
    allowed
        .iter()
        .map(|p| format!("'{}'", p.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The projection table, pinned to its literal values per source kind. A test that read
    /// `supported` back would not catch the table being wrong, so each row is spelled out.
    #[test]
    fn supported_projections_match_the_spec_table_per_source_kind() {
        use CredentialSourceType as S;
        use ProjectionType::{AwsProfile, CredentialEndpoint, EnvVar};
        let table: [(S, &[ProjectionType]); 10] = [
            (S::AwsIdcSso, &[AwsProfile, CredentialEndpoint]),
            (S::AwsIamUser, &[AwsProfile, CredentialEndpoint]),
            (S::AwsRolesAnywhere, &[AwsProfile, CredentialEndpoint]),
            (S::AwsWebIdentity, &[AwsProfile, CredentialEndpoint]),
            (S::AwsLogin, &[AwsProfile, CredentialEndpoint]),
            (S::Jwt, &[EnvVar]),
            (S::Oauth, &[EnvVar]),
            (S::JwtBearer, &[EnvVar]),
            (S::StaticSecret, &[EnvVar]),
            (S::Unsupported, &[]),
        ];
        for (source, expected) in table {
            assert_eq!(supported(source), expected, "projections for {source:?}");
        }
    }

    /// Unknown spellings parse rather than failing the file they arrived in; `resolve` is what
    /// refuses them.
    #[test]
    fn unknown_spelling_deserializes_to_unsupported() {
        let parsed: ProjectionType = serde_json::from_str("\"http-proxy\"").unwrap();
        assert_eq!(parsed, ProjectionType::Unsupported);
    }

    /// The config spelling is the wire spelling, at every level (Req 2.7).
    #[test]
    fn projection_types_round_trip_through_their_config_spelling() {
        for p in [
            ProjectionType::AwsProfile,
            ProjectionType::EnvVar,
            ProjectionType::CredentialEndpoint,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{}\"", p.as_str()));
            assert_eq!(serde_json::from_str::<ProjectionType>(&json).unwrap(), p);
        }
    }

    /// Req 2.13: a declaration carries a type and an address through one spelling, at every level.
    #[test]
    fn a_declaration_round_trips_through_one_spelling() {
        for spelled in ["env-var", "env-var:MY_API_KEY", "aws-profile"] {
            let parsed: ProjectionDecl = spelled.parse().unwrap();
            assert_eq!(parsed.to_string(), spelled);
            let json = serde_json::to_string(&parsed).unwrap();
            assert_eq!(
                serde_json::from_str::<ProjectionDecl>(&json).unwrap(),
                parsed
            );
        }
    }

    /// Req 7.5 with 2.13: an unrecognised type still degrades rather than failing the file it
    /// arrived in, and it degrades with its address intact so the refusal can describe both.
    #[test]
    fn an_unknown_type_with_an_address_still_deserializes() {
        let parsed: ProjectionDecl = serde_json::from_str("\"file:/run/secrets/.env\"").unwrap();
        assert_eq!(parsed.projection, ProjectionType::Unsupported);
        assert_eq!(parsed.address.as_deref(), Some("/run/secrets/.env"));
    }
}
