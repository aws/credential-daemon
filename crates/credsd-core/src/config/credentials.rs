//! Credential source definitions (`credentials.toml`) and their data directories.
//!
//! A credential source is everything needed to resolve one credential, independent of any
//! env that consumes it. Envs in `config.toml` name a source; several may name the
//! same one, so a single login serves all of them.
//!
//! Distinct from [`crate::credentials`], which models a *resolved* credential — the
//! short-lived material a source produces.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use toml_edit::{DocumentMut, Item};

use super::{
    load_document, platform, read_if_present, warn_if_permissive, write_config_file,
    AwsLoginConfig, AwsWebIdentityConfig, IamUserConfig, JwtBearerConfig, JwtConfig, OauthConfig,
    RolesAnywhereConfig, SsoConfig, StaticSecretConfig,
};
use crate::error::{DaemonError, Result};
use crate::rpc::CredentialSourceType;

/// Every field required to resolve one credential, tagged by source type.
///
/// Requiredness is structural rather than validated: a `type = "aws-idc-sso"` entry missing
/// `account_id` fails to parse with a message naming the field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum CredentialSource {
    AwsIdcSso(SsoConfig),
    /// A long-term IAM key brokered into short-lived session credentials.
    AwsIamUser(IamUserConfig),
    /// An X.509 certificate + private key exchanged for credentials via IAM Roles Anywhere.
    AwsRolesAnywhere(RolesAnywhereConfig),
    /// An OAuth2 login (auth-code + PKCE, optional DPoP) federated to AWS credentials.
    #[serde(rename = "aws-web-identity")]
    AwsWebIdentity(AwsWebIdentityConfig),
    /// An AWS Sign-In login (`aws login`) federated straight to AWS credentials.
    AwsLogin(AwsLoginConfig),
    /// A bearer JWT held on credsd's behalf and served as the credential itself.
    Jwt(JwtConfig),
    /// A pre-issued opaque secret the user already holds, served verbatim. Structurally the
    /// `Jwt` family — seal and serve, nothing exchanged — minus a parseable lifetime.
    StaticSecret(StaticSecretConfig),
    /// An OAuth 2.0 client-credentials (2LO) token endpoint — machine-to-machine, no user
    /// interaction required. The client secret is NOT in `credentials.toml`; it is sealed to
    /// `oauth_client_secret.enc` by bootstrap and unsealed at renew time.
    Oauth(OauthConfig),
    /// OAuth 2.0 JWT Bearer grant (RFC 7523): exchange a locally-held assertion JWT for an
    /// access token. The assertion file is re-read on each refresh. No provider yet; the
    /// variant is here so that a forward-looking entry parses cleanly.
    JwtBearer(JwtBearerConfig),
    /// A source type with no provider implemented yet. Unknown tags parse to this
    /// instead of failing, so one forward-looking entry cannot make the whole file
    /// unloadable and take every unrelated env down with it.
    #[serde(other)]
    Unsupported,
}

impl CredentialSource {
    pub fn type_name(&self) -> &'static str {
        self.source_type().as_str()
    }

    /// This source's wire discriminant — the configuration stripped off, leaving only which
    /// kind of source it is. The one place the two vocabularies are mapped onto each other, so
    /// a new `CredentialSource` variant cannot be added without confronting its wire spelling.
    pub fn source_type(&self) -> CredentialSourceType {
        match self {
            Self::AwsIdcSso(_) => CredentialSourceType::AwsIdcSso,
            Self::AwsIamUser(_) => CredentialSourceType::AwsIamUser,
            Self::AwsRolesAnywhere(_) => CredentialSourceType::AwsRolesAnywhere,
            Self::AwsWebIdentity(_) => CredentialSourceType::AwsWebIdentity,
            Self::AwsLogin(_) => CredentialSourceType::AwsLogin,
            Self::Jwt(_) => CredentialSourceType::Jwt,
            Self::StaticSecret(_) => CredentialSourceType::StaticSecret,
            Self::Oauth(_) => CredentialSourceType::Oauth,
            Self::JwtBearer(_) => CredentialSourceType::JwtBearer,
            Self::Unsupported => CredentialSourceType::Unsupported,
        }
    }

    /// The kind of credential this source resolves to — the manifest's per-entry discriminant.
    ///
    /// Every AWS-facing source mints session credentials; a `jwt` source serves the token itself.
    /// Computed from the full source, not the discriminant, because a source's kind can depend on
    /// its configuration.
    pub fn served_kind(&self) -> crate::rpc::CredentialType {
        use crate::rpc::CredentialType;
        match self {
            Self::Jwt(_) | Self::Oauth(_) | Self::JwtBearer(_) | Self::StaticSecret(_) => {
                CredentialType::AccessToken
            }
            _ => CredentialType::SessionCredentials,
        }
    }

    /// The environment variable a token-form credential asks to be exported as, if it named one.
    /// `None` for AWS-profile sources (they are not env-var projected) and for a token source that
    /// left the variable to the default.
    pub fn env_var(&self) -> Option<&str> {
        match self {
            Self::Jwt(c) => c.env_var.as_deref(),
            Self::StaticSecret(c) => c.env_var.as_deref(),
            _ => None,
        }
    }

    /// The projections this source can take, most-preferred first.
    ///
    /// Delegated to [`crate::projection::supported`], keyed on the discriminant: a client
    /// resolving from a `profile/describe` manifest has only the discriminant, and a second copy
    /// of the mapping here is how the two would come to disagree about what a source can take.
    pub fn supported_projections(&self) -> &'static [crate::projection::ProjectionType] {
        crate::projection::supported(self.source_type())
    }

    /// The identity classification of this credential — who it is *for*. Unclassified sources
    /// (including `Unsupported`) default to `Human` so an unknown credential never masquerades
    /// as a more-restricted one.
    pub fn identity_type(&self) -> crate::config::IdentityType {
        match self {
            Self::AwsIdcSso(c) => c.identity_type,
            Self::AwsIamUser(c) => c.identity_type,
            Self::AwsRolesAnywhere(c) => c.identity_type,
            Self::AwsWebIdentity(c) => c.identity_type,
            Self::AwsLogin(c) => c.identity_type,
            Self::Jwt(c) => c.identity_type,
            Self::StaticSecret(c) => c.identity_type,
            Self::Oauth(c) => c.identity_type,
            Self::JwtBearer(c) => c.identity_type,
            Self::Unsupported => crate::config::IdentityType::default(),
        }
    }

    /// The projection used when no level declares one — the first supported projection.
    pub fn default_projection(&self) -> Option<crate::projection::ProjectionType> {
        crate::projection::default_projection(self.source_type())
    }
}

pub type CredentialSources = HashMap<String, CredentialSource>;

pub fn credentials_path() -> PathBuf {
    platform::config_dir().join("credentials.toml")
}

/// The directory holding a credential's encrypted artifacts.
///
/// `credential` becomes a path component, so callers must have passed it through
/// [`validate_name`] first. Every entry point does: the CLI on its arguments, and
/// [`load`] on every key it reads.
pub fn credential_data_dir(credential: &str) -> PathBuf {
    platform::data_dir().join("credentials").join(credential)
}

pub fn load() -> Result<CredentialSources> {
    load_from(&credentials_path())
}

/// Load credentials from an explicit path (used for per-caller scoped loading).
pub fn load_from(path: &std::path::Path) -> Result<CredentialSources> {
    let Some(content) = super::read_if_present(path)? else {
        return Ok(CredentialSources::new());
    };
    warn_if_permissive(path);

    let credentials: CredentialSources = toml::from_str(&content).map_err(|e| {
        DaemonError::config(format!(
            "{}: parse error at {}",
            path.display(),
            super::located(e.span(), &content)
        ))
    })?;

    for name in credentials.keys() {
        validate_name(name)?;
    }
    Ok(credentials)
}

/// Parse `content` as a `credentials.toml`. The text form of [`load_from`], for a caller that
/// already holds the bytes it verified and must not read the file a second time to validate
/// against them.
pub fn from_text(content: &str) -> Result<CredentialSources> {
    let credentials: CredentialSources = toml::from_str(content)
        .map_err(|e| DaemonError::config(format!("failed to parse credentials: {}", e)))?;
    for name in credentials.keys() {
        validate_name(name)?;
    }
    Ok(credentials)
}

/// Insert or update a credential, preserving comments and formatting.
pub fn upsert_credential(name: &str, entry: &CredentialSource) -> Result<()> {
    validate_name(name)?;
    let path = credentials_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut doc = load_document(&path)?;
    upsert_in_doc(&mut doc, name, entry)?;
    write_config_file(&path, &doc.to_string())
}

/// Path-parameterized variant of [`upsert_credential`] for daemon-side, caller-scoped writes.
///
/// The daemon writes to `callers/<uid>/credentials.toml` rather than the global path, so the
/// human-uid caller root is isolated from the daemon's own global state. No cross-file
/// validation is performed here: the caller is responsible for writing the credential before
/// the env that references it (orphan credentials are harmless; an env referencing a missing
/// credential is not).
pub fn upsert_credential_at(
    credentials_path: &std::path::Path,
    name: &str,
    entry: &CredentialSource,
) -> Result<()> {
    validate_name(name)?;
    if let Some(parent) = credentials_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let path = credentials_path.to_path_buf();
    let mut doc = load_document(&path)?;
    upsert_in_doc(&mut doc, name, entry)?;
    write_config_file(&path, &doc.to_string())
}

/// Insert or update credential `name` in `checked`, the bytes the caller verified, and write the
/// result to `credentials_path`. Returns the written text. Edits `checked`, not a fresh read: the
/// caller confirms the file still holds `checked` before calling, and this function does not
/// re-verify it.
pub fn upsert_credential_in(
    credentials_path: &std::path::Path,
    checked: &str,
    name: &str,
    entry: &CredentialSource,
) -> Result<String> {
    validate_name(name)?;
    if let Some(parent) = credentials_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut doc = checked
        .parse::<DocumentMut>()
        .map_err(|e| DaemonError::config(format!("failed to parse credentials: {}", e)))?;
    upsert_in_doc(&mut doc, name, entry)?;
    let written = doc.to_string();
    write_config_file(credentials_path, &written)?;
    Ok(written)
}

/// Parse credentials text, validating every name as `load_from` does.
pub fn parse_sources(content: &str) -> Result<CredentialSources> {
    let credentials: CredentialSources = toml::from_str(content).map_err(|e| {
        DaemonError::config(format!(
            "failed to parse credentials: parse error at {}",
            super::located(e.span(), content)
        ))
    })?;
    for name in credentials.keys() {
        validate_name(name)?;
    }
    Ok(credentials)
}

/// Remove credential `name` from `checked`, the bytes the caller verified, and write the result
/// to `credentials_path`. Returns the written text, or `None` (writing nothing) when there was no
/// such credential. Refuses, leaving the file as it is, when the file no longer holds `checked`
/// immediately before the write. The check narrows the window for a same-uid edit to the time
/// between the read and the write; it does not close it.
///
/// `before_write` sees the exact text about to be written. A failure there leaves the file as it
/// was, so a caller can seal state for the new text before the file changes. When the write
/// fails after that, `before_write` runs again with `checked` to put the seal back in step with
/// the file, so a retry of the same removal succeeds normally. If that rollback also fails, the
/// seal is left ahead of the file and every retry is refused as drift; `creds revalidate` recovers
/// it.
pub fn remove_credential_from(
    credentials_path: &std::path::Path,
    checked: &str,
    name: &str,
    before_write: impl FnMut(&str) -> Result<()>,
) -> Result<Option<String>> {
    remove_credential_with(
        credentials_path,
        checked,
        name,
        before_write,
        write_config_file,
    )
}

/// [`remove_credential_from`] with the file write injectable, so a test can fail the write
/// without depending on the caller's uid or permissions.
fn remove_credential_with(
    credentials_path: &std::path::Path,
    checked: &str,
    name: &str,
    mut before_write: impl FnMut(&str) -> Result<()>,
    write: impl FnOnce(&std::path::Path, &str) -> Result<()>,
) -> Result<Option<String>> {
    let mut doc = checked.parse::<DocumentMut>().map_err(|e| {
        DaemonError::config(format!(
            "failed to parse credentials: parse error at {}",
            super::located(e.span(), checked)
        ))
    })?;
    if doc.remove(name).is_none() {
        return Ok(None);
    }
    let written = doc.to_string();
    before_write(&written)?;
    let write = read_if_present(credentials_path).and_then(|on_disk| {
        if on_disk.as_deref() == Some(checked) {
            write(credentials_path, &written)
        } else {
            Err(DaemonError::config(
                "credentials changed after they were checked; nothing was removed",
            ))
        }
    });
    if let Err(err) = write {
        return Err(match before_write(checked) {
            Ok(()) => err,
            Err(rollback) => DaemonError::config(format!(
                "{err}; the snapshot rollback also failed: {rollback}"
            )),
        });
    }
    Ok(Some(written))
}

/// Insert or update a credential in a document (testable without filesystem).
///
/// Replaces the entry's keys when it already exists, so keys owned by a previous source
/// type — including any stale secret material — do not linger after a re-bootstrap.
/// Comments and unrelated entries elsewhere in the document are left untouched.
fn upsert_in_doc(doc: &mut DocumentMut, name: &str, entry: &CredentialSource) -> Result<()> {
    // `#[serde(other)]` governs deserialization only, so this variant serializes happily to
    // `type = "unsupported"` — an entry no provider can resolve. Refuse before rendering.
    if matches!(entry, CredentialSource::Unsupported) {
        return Err(DaemonError::config(
            "cannot write a credential whose source type is not supported",
        ));
    }

    let rendered = toml_edit::ser::to_document(entry)
        .map_err(|e| DaemonError::config(format!("failed to serialize credential: {}", e)))?;

    if let Some(existing) = doc.get_mut(name).and_then(Item::as_table_mut) {
        existing.clear();
        for (key, item) in rendered.iter() {
            existing.insert(key, item.clone());
        }
        return Ok(());
    }

    doc.insert(name, Item::Table(rendered.into_table()));
    Ok(())
}

const MAX_NAME_LEN: usize = 64;

/// Validate an env or credential name for use as both a TOML key and a path component.
///
/// Names reach the filesystem as directory names under `credentials/`, so this is the
/// boundary that keeps `--env ../../etc` from escaping the data directory.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(DaemonError::config("name must not be empty"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(DaemonError::config(format!(
            "name '{}' is {} characters; the maximum is {}",
            name,
            name.len(),
            MAX_NAME_LEN
        )));
    }
    // Also covers "." and "..", which the character set below would otherwise allow.
    if name.starts_with('.') {
        return Err(DaemonError::config(format!(
            "name '{}' must not start with '.'",
            name
        )));
    }
    // "default" renders as `[profile default]` in credential_process output, which shadows the
    // bare `[default]` section that SDKs read for the default profile — a different identity.
    if name == "default" {
        return Err(DaemonError::config(
            "name 'default' is reserved: it would render as '[profile default]' in AWS credential \
             files, shadowing the '[default]' section. Use a distinct name.",
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-'))
    {
        return Err(DaemonError::config(format!(
            "name '{}' contains invalid character '{}'; use letters, digits, '.', '_', or '-'",
            name, bad
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::panic_in_result_fn,
    reason = "assert_eq! in async test fns returning Result is idiomatic"
)]
mod tests {
    use super::*;

    fn sso_entry() -> CredentialSource {
        CredentialSource::AwsIdcSso(SsoConfig {
            start_url: "https://example.awsapps.com/start".into(),
            sso_region: "us-east-1".into(),
            account_id: "111111111111".into(),
            role_name: "Developer".into(),
            identity_type: Default::default(),
        })
    }

    #[test]
    fn parses_sso_entry() {
        let toml = r#"
[dev]
type = "aws-idc-sso"
start_url = "https://example.awsapps.com/start"
sso_region = "us-east-1"
account_id = "111111111111"
role_name = "Developer"
"#;
        let credentials: CredentialSources = toml::from_str(toml).unwrap();
        match &credentials["dev"] {
            CredentialSource::AwsIdcSso(sso) => {
                assert_eq!(sso.start_url, "https://example.awsapps.com/start");
                assert_eq!(sso.account_id, "111111111111");
                assert_eq!(sso.role_name, "Developer");
            }
            other => panic!("expected sso, got {:?}", other),
        }
    }

    #[test]
    fn missing_field_names_the_field() {
        let toml = r#"
[dev]
type = "aws-idc-sso"
start_url = "https://example.awsapps.com/start"
sso_region = "us-east-1"
role_name = "Developer"
"#;
        let err = toml::from_str::<CredentialSources>(toml)
            .unwrap_err()
            .to_string();
        assert!(err.contains("account_id"), "unexpected error: {}", err);
    }

    #[test]
    fn unknown_type_parses_as_unsupported() {
        let toml = r#"
[legacy]
type = "some-future-source"
some_field = "value"
"#;
        let credentials: CredentialSources = toml::from_str(toml).unwrap();
        assert!(matches!(
            credentials["legacy"],
            CredentialSource::Unsupported
        ));
    }

    #[test]
    fn unknown_type_does_not_break_sibling_entries() {
        let toml = r#"
[future]
type = "iam"

[dev]
type = "aws-idc-sso"
start_url = "https://example.awsapps.com/start"
sso_region = "us-east-1"
account_id = "111111111111"
role_name = "Developer"
"#;
        let credentials: CredentialSources = toml::from_str(toml).unwrap();
        assert!(matches!(credentials["dev"], CredentialSource::AwsIdcSso(_)));
        assert!(matches!(
            credentials["future"],
            CredentialSource::Unsupported
        ));
    }

    #[test]
    fn upsert_writes_a_new_table() {
        let mut doc = DocumentMut::new();
        upsert_in_doc(&mut doc, "dev", &sso_entry()).unwrap();
        let out = doc.to_string();
        assert!(out.contains("[dev]"));
        assert!(out.contains(r#"type = "aws-idc-sso""#));
        assert!(out.contains(r#"account_id = "111111111111""#));
    }

    #[test]
    fn upsert_preserves_comments_and_unrelated_entries() {
        let original = r#"# my credential sources
[dev]
type = "aws-idc-sso"
start_url = "https://old.awsapps.com/start"
sso_region = "us-west-2"
account_id = "999999999999"
role_name = "Old"

# keep me
[other]
type = "aws-idc-sso"
start_url = "https://other.awsapps.com/start"
sso_region = "eu-west-1"
account_id = "222222222222"
role_name = "Reader"
"#;
        let mut doc = original.parse::<DocumentMut>().unwrap();
        upsert_in_doc(&mut doc, "dev", &sso_entry()).unwrap();
        let out = doc.to_string();

        assert!(out.contains("# my credential sources"));
        assert!(out.contains("# keep me"));
        assert!(out.contains(r#"account_id = "111111111111""#));
        assert!(!out.contains("999999999999"));
        assert!(out.contains(r#"account_id = "222222222222""#));
    }

    #[test]
    fn upsert_drops_stale_keys_from_a_prior_source_type() {
        // A [dev] entry left over from an iam-user source, carrying secret material the
        // new aws-idc-sso source does not own. Re-bootstrapping must not leave it behind.
        let original = r#"[dev]
type = "aws-iam-user"
access_key_id = "AKIAOLD"
secret_access_key = "leftover-secret"
"#;
        let mut doc = original.parse::<DocumentMut>().unwrap();
        upsert_in_doc(&mut doc, "dev", &sso_entry()).unwrap();
        let out = doc.to_string();

        assert!(out.contains(r#"type = "aws-idc-sso""#));
        assert!(
            !out.contains("secret_access_key"),
            "stale secret key must not linger: {out}"
        );
        assert!(!out.contains("leftover-secret"));
        assert!(!out.contains("AKIAOLD"));
    }

    #[test]
    fn upsert_same_type_updates_fields_and_reverts_omitted_to_default() {
        // Same-type re-bootstrap: a set field is overwritten, and a field the new entry
        // leaves at its default (identity_type Human, which serializes to no key) must
        // revert rather than keep the stale "agent" label.
        let original = r#"[dev]
type = "aws-idc-sso"
start_url = "https://example.awsapps.com/start"
sso_region = "us-east-1"
account_id = "999999999999"
role_name = "Developer"
identity_type = "agent"
"#;
        let mut doc = original.parse::<DocumentMut>().unwrap();
        // sso_entry() has account_id 111.. and identity_type at its Human default.
        upsert_in_doc(&mut doc, "dev", &sso_entry()).unwrap();
        let out = doc.to_string();

        assert!(out.contains(r#"account_id = "111111111111""#));
        assert!(!out.contains("999999999999"));
        assert!(
            !out.contains("identity_type"),
            "omitted default field must not linger: {out}"
        );

        let credentials: CredentialSources = toml::from_str(&out).unwrap();
        match &credentials["dev"] {
            CredentialSource::AwsIdcSso(sso) => {
                assert_eq!(sso.account_id, "111111111111");
                assert_eq!(sso.identity_type, crate::config::IdentityType::default());
            }
            other => panic!("expected sso, got {other:?}"),
        }
    }

    /// `upsert_in_doc` renders through serde rather than a hand-kept field list, so this is
    /// what catches a field that stops being written — a `skip_serializing_if` added to
    /// `SsoConfig`, say. Compare every field, not just the variant.
    #[test]
    fn upsert_round_trips_every_field() {
        let mut doc = DocumentMut::new();
        upsert_in_doc(&mut doc, "dev", &sso_entry()).unwrap();
        let credentials: CredentialSources = toml::from_str(&doc.to_string()).unwrap();
        match (&credentials["dev"], &sso_entry()) {
            (CredentialSource::AwsIdcSso(got), CredentialSource::AwsIdcSso(want)) => {
                assert_eq!(got.start_url, want.start_url);
                assert_eq!(got.sso_region, want.sso_region);
                assert_eq!(got.account_id, want.account_id);
                assert_eq!(got.role_name, want.role_name);
            }
            (other, _) => panic!("expected sso, got {:?}", other),
        }
    }

    #[test]
    fn unsupported_entry_cannot_be_written() {
        let mut doc = DocumentMut::new();
        assert!(upsert_in_doc(&mut doc, "x", &CredentialSource::Unsupported).is_err());
    }

    #[test]
    fn remove_from_doc_leaves_others() {
        let mut doc = r#"
[dev]
type = "aws-idc-sso"
start_url = "a"
sso_region = "b"
account_id = "c"
role_name = "d"

[keep]
type = "aws-idc-sso"
start_url = "a"
sso_region = "b"
account_id = "c"
role_name = "d"
"#
        .parse::<DocumentMut>()
        .unwrap();
        doc.remove("dev");
        let out = doc.to_string();
        assert!(!out.contains("[dev]"));
        assert!(out.contains("[keep]"));
    }

    #[test]
    fn a_hand_edit_on_disk_refuses_the_removal_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let checked = "[dev]\ntype = \"sso\"\n[keep]\ntype = \"sso\"\n";
        let edited = format!("{checked}[hand]\ntype = \"sso\"\n");
        std::fs::write(&path, &edited).unwrap();
        let mut sealed = Vec::new();

        let refused = remove_credential_from(&path, checked, "dev", |text| {
            sealed.push(text.to_owned());
            Ok(())
        });

        assert!(refused.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
        let [attempted, rolled_back] = sealed.as_slice() else {
            panic!("expected a seal for the new text and a rollback, got {sealed:?}");
        };
        assert!(!attempted.contains("[dev]"));
        assert_eq!(rolled_back, checked);
    }

    #[test]
    fn a_failed_write_reseals_the_checked_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let checked = "[dev]\ntype = \"sso\"\n[keep]\ntype = \"sso\"\n";
        std::fs::write(&path, checked).unwrap();
        let mut sealed = Vec::new();

        let refused = remove_credential_with(
            &path,
            checked,
            "dev",
            |text| {
                sealed.push(text.to_owned());
                Ok(())
            },
            |_, _| Err(DaemonError::config("write failed")),
        );

        assert!(refused.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), checked);
        let [_attempted, rolled_back] = sealed.as_slice() else {
            panic!("expected a seal for the new text and a rollback, got {sealed:?}");
        };
        assert_eq!(rolled_back, checked);
    }

    #[test]
    fn a_failed_before_write_leaves_the_file_as_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let checked = "[dev]\ntype = \"sso\"\n[keep]\ntype = \"sso\"\n";
        std::fs::write(&path, checked).unwrap();

        let refused = remove_credential_from(&path, checked, "dev", |_| {
            Err(DaemonError::config("seal failed"))
        });

        assert!(refused.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), checked);
    }

    #[test]
    fn a_failed_write_after_the_seal_reseals_the_checked_text() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the file should be fails the re-read, which runs after the seal.
        let path = dir.path().join("credentials.toml");
        std::fs::create_dir(&path).unwrap();
        let checked = "[dev]\ntype = \"sso\"\n[keep]\ntype = \"sso\"\n";
        let mut sealed = Vec::new();

        let refused = remove_credential_from(&path, checked, "dev", |text| {
            sealed.push(text.to_owned());
            Ok(())
        });

        assert!(refused.is_err());
        let [attempted, rolled_back] = sealed.as_slice() else {
            panic!("expected a seal for the new text and a rollback, got {sealed:?}");
        };
        assert!(!attempted.contains("[dev]"));
        assert_eq!(rolled_back, checked);
    }

    #[test]
    fn validate_name_accepts_ordinary_names() {
        for name in ["dev", "dev-1", "dev_1", "dev.1", "A0", "x"] {
            assert!(validate_name(name).is_ok(), "rejected '{}'", name);
        }
    }

    #[test]
    fn validate_name_rejects_path_traversal() {
        for name in ["..", ".", "../etc", "a/b", "a\\b", "./x"] {
            assert!(validate_name(name).is_err(), "accepted '{}'", name);
        }
    }

    #[test]
    fn validate_name_rejects_empty_and_overlong() {
        assert!(validate_name("").is_err());
        assert!(validate_name(&"a".repeat(MAX_NAME_LEN)).is_ok());
        assert!(validate_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn validate_name_rejects_shell_and_whitespace_characters() {
        for name in ["a b", "a;b", "a$b", "a\nb", "a\0b", "café"] {
            assert!(validate_name(name).is_err(), "accepted '{}'", name);
        }
    }

    #[test]
    fn validate_name_error_names_the_offending_character() {
        let err = validate_name("a/b").unwrap_err().to_string();
        assert!(err.contains('/'), "unexpected error: {}", err);
    }

    #[test]
    fn credential_data_dir_is_under_credentials() {
        let dir = credential_data_dir("dev");
        assert!(dir.ends_with("credentials/dev"));
    }

    #[test]
    fn parses_iam_user_entry() {
        // The secret is no longer in credentials.toml (it lives in iam_user.enc), so an entry is
        // just the non-secret knobs.
        let toml = "[work]\ntype = \"aws-iam-user\"\nregion = \"us-east-1\"\nduration_seconds = 43200\n\n[auto]\ntype = \"aws-iam-user\"\nregion = \"us-west-2\"\n";
        let credentials: CredentialSources = toml::from_str(toml).unwrap();
        match &credentials["work"] {
            CredentialSource::AwsIamUser(c) => {
                assert_eq!(c.region, "us-east-1");
                assert_eq!(c.duration_seconds, Some(43200));
            }
            other => panic!("expected aws-iam-user, got {:?}", other),
        }
        match &credentials["auto"] {
            CredentialSource::AwsIamUser(c) => {
                assert!(c.duration_seconds.is_none());
                assert!(c.mfa_serial.is_none());
            }
            other => panic!("expected aws-iam-user, got {:?}", other),
        }
    }

    #[test]
    fn parses_iam_user_mfa_serial() {
        let toml = "[work]\ntype = \"aws-iam-user\"\nregion = \"us-east-1\"\nmfa_serial = \"arn:aws:iam::111111111111:mfa/user\"\n";
        let credentials: CredentialSources = toml::from_str(toml).unwrap();
        match &credentials["work"] {
            CredentialSource::AwsIamUser(c) => {
                assert_eq!(
                    c.mfa_serial.as_deref(),
                    Some("arn:aws:iam::111111111111:mfa/user")
                )
            }
            other => panic!("expected aws-iam-user, got {:?}", other),
        }
    }

    #[test]
    fn iam_user_missing_region_names_the_field() {
        let toml = "[work]\ntype = \"aws-iam-user\"\n";
        let err = toml::from_str::<CredentialSources>(toml)
            .unwrap_err()
            .to_string();
        assert!(err.contains("region"), "unexpected error: {}", err);
    }

    /// `creds login` has to reach the same browser the first login did, and the stored config is
    /// the only record of which one that was — so `remote` must survive the round trip, and an
    /// entry written before the field existed must still read as same-device.
    #[test]
    fn aws_login_remote_round_trips_and_defaults_to_same_device(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::config::AwsLoginConfig;

        let remote = AwsLoginConfig {
            region: "us-east-1".into(),
            callback_port: None,
            remote: true,
            identity_type: Default::default(),
        };
        let serialized = toml::to_string(&remote)
            .map_err(|e| crate::error::DaemonError::config(e.to_string()))?;
        assert!(toml::from_str::<AwsLoginConfig>(&serialized)?.remote);

        assert!(!toml::from_str::<AwsLoginConfig>("region = \"us-east-1\"\n")?.remote);
        Ok(())
    }

    #[test]
    fn oauth_client_credentials_round_trip() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        use crate::config::OauthGrant;

        let original = OauthConfig {
            token_url: "https://auth.example.com/token".into(),
            client_id: "my-service-client".into(),
            scope: Some("read write".into()),
            grant: OauthGrant::ClientCredentials,
            identity_type: Default::default(),
        };

        let serialized = toml::to_string(&original)
            .map_err(|e| crate::error::DaemonError::config(e.to_string()))?;
        // client_secret must not appear in the serialized output
        assert!(
            !serialized.contains("client_secret"),
            "client_secret leaked into credentials.toml: {serialized}"
        );
        let restored: OauthConfig = toml::from_str(&serialized)?;

        assert_eq!(restored.token_url, original.token_url);
        assert_eq!(restored.client_id, original.client_id);
        assert_eq!(restored.scope, original.scope);
        assert!(
            matches!(restored.grant, OauthGrant::ClientCredentials),
            "grant variant changed after round-trip"
        );
        Ok(())
    }

    #[test]
    fn oauth_toml_with_legacy_client_secret_field_is_ignored(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A hand-authored entry with client_secret must parse without error — the field is
        // silently ignored so existing files do not break on upgrade.
        use crate::config::OauthGrant;
        let toml_input = concat!(
            "token_url = \"https://auth.example.com/token\"\n",
            "client_id = \"my-client\"\n",
            "client_secret = \"old-secret\"\n",
            "grant = \"client-credentials\"\n",
        );
        let config: OauthConfig = toml::from_str(toml_input)?;
        assert_eq!(config.client_id, "my-client");
        assert!(matches!(config.grant, OauthGrant::ClientCredentials));
        Ok(())
    }

    /// `#[serde(other)]` on `OauthGrant::Unsupported` is the mechanism that prevents a
    /// forward-looking grant type from making the whole credentials file unparseable. Verifying it
    /// here catches any accidental removal of that attribute.
    #[test]
    fn unknown_grant_degrades_gracefully() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::config::OauthGrant;

        let toml_input = concat!(
            "token_url = \"https://auth.example.com/token\"\n",
            "client_id = \"my-client\"\n",
            "client_secret = \"s3cr3t\"\n",
            "grant = \"some-future-grant\"\n",
        );

        let config: OauthConfig = toml::from_str(toml_input)?;
        assert!(
            matches!(config.grant, OauthGrant::Unsupported),
            "unknown grant should degrade to Unsupported, got {:?}",
            config.grant
        );
        Ok(())
    }

    #[test]
    fn client_secret_debug_redacts_value() {
        use crate::config::ClientSecret;
        const SECRET: &str = "xK9mP2nQ8rL5wA3j-very-secret";
        let s = ClientSecret(SECRET.into());
        let debug_output = format!("{s:?}");
        assert!(
            !debug_output.contains(SECRET),
            "secret leaked into Debug output: {debug_output}"
        );
        assert!(
            debug_output.contains("[redacted]"),
            "redaction marker absent from Debug output: {debug_output}"
        );
    }
}
