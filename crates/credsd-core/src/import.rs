//! Import existing long-lived credentials from external stores into credsd.
//!
//! Import is the bulk, offline counterpart to `bootstrap`: it reads an external credential
//! store, discovers what it holds, and ingests each entry (seals the secret, writes the
//! `credentials.toml` source, and wraps it in a same-named env). It never mutates the source
//! it reads from — migration is additive on both sides.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::config::credentials::{self, CredentialSource};
use crate::config::{IamUserConfig, IdentityType};
use crate::encryption::SecretString;
use crate::error::{DaemonError, Result};
use crate::rpc::ImportProfile;

/// An external store credsd can import credentials from.
pub enum ImportSource {
    /// The AWS shared-credentials file (`~/.aws/credentials` by default). Only profiles carrying
    /// a static `aws_access_key_id`/`aws_secret_access_key` pair are importable — each becomes an
    /// `iam-user` credential. Profiles resolved indirectly (SSO, `credential_process`,
    /// `source_profile`) hold no secret of their own and are skipped.
    AwsProfiles {
        /// Override for the credentials-file path. Defaults to `$AWS_SHARED_CREDENTIALS_FILE`,
        /// then `~/.aws/credentials`.
        path: Option<PathBuf>,
        /// Where a profile's region may come from. A profile that resolves none is skipped.
        region: RegionInputs,
    },
    /// An import source not recognised by this version.
    Unsupported,
}

struct Discovered {
    name: String,
    source: CredentialSource,
    secret: ImportSecret,
}

enum ImportSecret {
    IamUserKey {
        access_key_id: String,
        secret_access_key: SecretString,
    },
}

impl ImportSource {
    fn discover(&self) -> Result<Vec<Discovered>> {
        match self {
            Self::AwsProfiles { path, region } => discover_aws_profiles(path.as_ref(), region),
            Self::Unsupported => Ok(vec![]),
        }
    }
}

impl Discovered {
    /// Map to the wire type the client sends to the daemon. The secret moves into the
    /// zeroizing [`ImportProfile::secret_access_key`]; discovery always classifies imported
    /// keys as `human`, so `identity_type` is left `None` (the daemon defaults to `human`).
    fn into_import_profile(self) -> ImportProfile {
        let region = match &self.source {
            CredentialSource::AwsIamUser(c) => c.region.clone(),
            _ => String::new(),
        };
        let ImportSecret::IamUserKey {
            access_key_id,
            secret_access_key,
        } = self.secret;
        ImportProfile {
            name: self.name,
            access_key_id,
            secret_access_key: secret_access_key.expose_secret().to_string(),
            region,
            identity_type: None,
        }
    }
}

/// Discover importable profiles and map them to the wire type the client sends to the daemon.
///
/// Client-side: parses the AWS shared-credentials file (which lives under the caller's `$HOME`,
/// unreadable by the scoped daemon user), filters to complete static-key profiles, and zeroizes
/// its parse buffers. Sealing and the dedupe/dry-run decision happen daemon-side against the
/// per-uid tree (Req 2).
pub fn discover_import_profiles(source: &ImportSource) -> Result<Vec<ImportProfile>> {
    Ok(source
        .discover()?
        .into_iter()
        .map(Discovered::into_import_profile)
        .collect())
}

/// Where a profile's region may come from, after the profile's own `region` key in the credentials
/// file: `--region`, `AWS_REGION`, `AWS_DEFAULT_REGION`, then `region` under the profile's section
/// of the config file.
#[derive(Default)]
pub struct RegionInputs {
    pub flag: Option<String>,
    pub aws_region: Option<String>,
    pub aws_default_region: Option<String>,
    pub config_path: Option<PathBuf>,
}

impl RegionInputs {
    /// The inputs as this process sees them. An empty value counts as unset, as the AWS CLI reads it.
    pub fn from_environment(flag: Option<String>) -> Self {
        Self {
            flag: flag.filter(|r| !r.is_empty()),
            aws_region: env_non_empty("AWS_REGION"),
            aws_default_region: env_non_empty("AWS_DEFAULT_REGION"),
            config_path: default_aws_config_path(),
        }
    }
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Default path to the AWS shared-credentials file, honouring `$AWS_SHARED_CREDENTIALS_FILE`.
pub fn default_aws_credentials_path() -> Option<PathBuf> {
    aws_file_path(
        std::env::var_os("AWS_SHARED_CREDENTIALS_FILE"),
        std::env::var_os("HOME"),
        "credentials",
    )
}

/// Default path to the AWS config file, honouring `$AWS_CONFIG_FILE`.
pub fn default_aws_config_path() -> Option<PathBuf> {
    aws_file_path(
        std::env::var_os("AWS_CONFIG_FILE"),
        std::env::var_os("HOME"),
        "config",
    )
}

fn aws_file_path(
    explicit: Option<OsString>,
    home: Option<OsString>,
    file: &str,
) -> Option<PathBuf> {
    explicit
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            home.filter(|h| !h.is_empty())
                .map(|h| PathBuf::from(h).join(".aws").join(file))
        })
}

/// One AWS INI file's sections: the section name, then its lower-cased keys.
type IniSections = Vec<(String, HashMap<String, Zeroizing<String>>)>;

/// The region one profile resolves to, or empty when no source names one. The credentials file's
/// own `region` key comes first: imports before the AWS CLI order relied on it.
fn resolve_region(
    profile: &str,
    credentials_region: Option<String>,
    inputs: &RegionInputs,
    config: &IniSections,
) -> String {
    credentials_region
        .or_else(|| inputs.flag.clone())
        .or_else(|| inputs.aws_region.clone())
        .or_else(|| inputs.aws_default_region.clone())
        .or_else(|| config_region(config, profile))
        .unwrap_or_default()
}

/// `region` under the profile's config section: `[default]`, or `[profile NAME]` for any other.
fn config_region(config: &IniSections, profile: &str) -> Option<String> {
    let section = if profile == "default" {
        "default".to_string()
    } else {
        format!("profile {profile}")
    };
    config
        .iter()
        .find(|(s, _)| *s == section)
        .and_then(|(_, keys)| keys.get("region"))
        .map(|z| z.to_string())
        .filter(|r| !r.is_empty())
}

/// The config file's sections. A missing file is no sections, as the AWS CLI treats it.
fn read_config_sections(path: Option<&PathBuf>) -> Result<IniSections> {
    let Some(path) = path else {
        return Ok(vec![]);
    };
    match std::fs::read_to_string(path).map(Zeroizing::new) {
        Ok(content) => Ok(parse_ini(&content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.into()),
    }
}

fn discover_aws_profiles(path: Option<&PathBuf>, region: &RegionInputs) -> Result<Vec<Discovered>> {
    let owned;
    let path = match path {
        Some(p) => p,
        None => {
            owned = default_aws_credentials_path().ok_or_else(|| {
                DaemonError::config("cannot locate ~/.aws/credentials; pass --from <path>")
            })?;
            &owned
        }
    };
    if !path.exists() {
        return Err(DaemonError::config(format!(
            "{} does not exist",
            path.display()
        )));
    }

    let content = Zeroizing::new(std::fs::read_to_string(path)?);
    let config = read_config_sections(region.config_path.as_ref())?;

    let mut found = Vec::new();
    for (name, keys) in parse_ini(&content) {
        let (Some(akid), Some(secret)) = (
            keys.get("aws_access_key_id"),
            keys.get("aws_secret_access_key"),
        ) else {
            continue;
        };
        if akid.is_empty() || secret.is_empty() {
            continue;
        }
        let credentials_region = keys
            .get("region")
            .map(|z| z.to_string())
            .filter(|r| !r.is_empty());
        // Empty when no source names one; `decide` skips the profile.
        let region = resolve_region(&name, credentials_region, region, &config);
        found.push(Discovered {
            name,
            source: CredentialSource::AwsIamUser(IamUserConfig {
                region,
                duration_seconds: None,
                mfa_serial: None,
                identity_type: IdentityType::Human,
            }),
            secret: ImportSecret::IamUserKey {
                access_key_id: akid.to_string(),
                secret_access_key: SecretString::from(secret.to_string()),
            },
        });
    }
    Ok(found)
}

/// The daemon's per-profile import decision, evaluated against the caller's real per-uid tree.
pub enum Decision {
    Import,
    Skip(String),
}

/// Decide a single profile's fate: skip an invalid name, a profile with no region (an empty
/// `region` means none was named or passed), or one that already exists (import is additive,
/// never a clobber), otherwise import. Pure — the daemon reuses it under its write lock so the
/// skip reasons are defined in one place.
pub fn decide(name: &str, region: &str, existing: &credentials::CredentialSources) -> Decision {
    if let Err(e) = credentials::validate_name(name) {
        return Decision::Skip(e.to_string());
    }
    if region.is_empty() {
        return Decision::Skip(
            "no region: set region for the profile in the credentials or config file, pass \
             --region, or set AWS_REGION or AWS_DEFAULT_REGION"
                .to_string(),
        );
    }
    if existing.contains_key(name) {
        return Decision::Skip("a credential with this name already exists".to_string());
    }
    Decision::Import
}

/// Minimal INI parse for AWS credential/config files. Values are `Zeroizing<String>` so
/// secret material (aws_secret_access_key) is scrubbed when the map drops.
fn parse_ini(content: &str) -> IniSections {
    let mut sections: IniSections = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            sections.push((name.trim().to_string(), HashMap::new()));
        } else if let Some((key, value)) = line.split_once('=') {
            if let Some((_, keys)) = sections.last_mut() {
                keys.insert(
                    key.trim().to_ascii_lowercase(),
                    Zeroizing::new(value.trim().to_string()),
                );
            }
        }
    }
    sections
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_profiles_keys_and_skips_comments() {
        let ini = "\
# a comment
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

; another comment
[work]
AWS_ACCESS_KEY_ID = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
region = us-west-2
";
        let sections = parse_ini(ini);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].0, "default");
        assert_eq!(
            sections[1].1.get("aws_access_key_id").map(|z| z.as_str()),
            Some("AKIAI44QH8DHBEXAMPLE"),
            "keys are lower-cased so mixed-case headers still match"
        );
        assert_eq!(
            sections[1].1.get("region").map(|z| z.as_str()),
            Some("us-west-2")
        );
    }

    fn write_credentials(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        std::fs::write(&path, body).unwrap();
        (dir, path)
    }

    #[test]
    fn discover_keeps_static_key_profiles_and_drops_the_rest() {
        let (_dir, path) = write_credentials(
            "\
[static]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[sso-derived]
sso_session = my-sso
sso_account_id = 123456789012

[process-backed]
credential_process = /usr/bin/get-creds

[half]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
",
        );
        let inputs = RegionInputs {
            flag: Some("eu-central-1".into()),
            ..Default::default()
        };
        let found = discover_aws_profiles(Some(&path), &inputs).unwrap();
        assert_eq!(
            found.len(),
            1,
            "only the complete static-key profile imports"
        );
        assert_eq!(found[0].name, "static");
        assert_eq!(region_of(&found[0]), "eu-central-1");
        match &found[0].secret {
            ImportSecret::IamUserKey {
                access_key_id,
                secret_access_key,
            } => {
                assert_eq!(access_key_id, "AKIAIOSFODNN7EXAMPLE");
                assert_eq!(
                    secret_access_key.expose_secret(),
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                );
            }
        }
    }

    fn region_of(d: &Discovered) -> String {
        match &d.source {
            CredentialSource::AwsIamUser(c) => c.region.clone(),
            other => panic!("expected iam-user, got {:?}", other),
        }
    }

    /// Discover profile `p` with the given credentials-file and config-file `region` values and
    /// flag and environment values. Each call writes its own temp files.
    fn region_for_p(
        creds_region: Option<&str>,
        config_region: Option<&str>,
        flag: Option<&str>,
        aws_region: Option<&str>,
        aws_default_region: Option<&str>,
    ) -> String {
        let dir = tempfile::tempdir().unwrap();
        let creds = dir.path().join("credentials");
        let config = dir.path().join("config");
        let creds_line = creds_region.map_or(String::new(), |r| format!("region = {r}\n"));
        std::fs::write(
            &creds,
            format!("[p]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = secret\n{creds_line}"),
        )
        .unwrap();
        let config_line = config_region.map_or(String::new(), |r| format!("region = {r}\n"));
        std::fs::write(&config, format!("[profile p]\n{config_line}")).unwrap();
        let inputs = RegionInputs {
            flag: flag.map(str::to_string),
            aws_region: aws_region.map(str::to_string),
            aws_default_region: aws_default_region.map(str::to_string),
            config_path: Some(config),
        };
        let found = discover_aws_profiles(Some(&creds), &inputs).unwrap();
        region_of(&found[0])
    }

    /// Every subset of the five sources, in order: the first one present wins, and none present
    /// leaves the region empty (a skip).
    #[test]
    fn region_resolves_in_order_for_every_source_combination() {
        const ORDER: [&str; 5] = [
            "creds-region",
            "flag-region",
            "aws-region",
            "default-region",
            "config-region",
        ];
        for mask in 0u8..32 {
            let picked = |bit: usize| (mask & (1 << bit) != 0).then_some(ORDER[bit]);
            let expected = (0..5usize)
                .find(|&bit| mask & (1 << bit) != 0)
                .map_or("", |bit| ORDER[bit]);
            let got = region_for_p(picked(0), picked(4), picked(1), picked(2), picked(3));
            assert_eq!(got, expected, "sources {mask:05b}");
        }
    }

    #[test]
    fn credentials_key_beats_the_flag_and_every_env_var() {
        assert_eq!(
            region_for_p(
                Some("creds-region"),
                Some("config-region"),
                Some("flag-region"),
                Some("aws-region"),
                Some("default-region"),
            ),
            "creds-region"
        );
    }

    #[test]
    fn the_flag_beats_the_env_vars_and_the_config_file() {
        assert_eq!(
            region_for_p(
                None,
                Some("config-region"),
                Some("flag-region"),
                Some("aws-region"),
                Some("default-region"),
            ),
            "flag-region"
        );
    }

    #[test]
    fn aws_region_beats_aws_default_region_and_the_config_file() {
        assert_eq!(
            region_for_p(
                None,
                Some("config-region"),
                None,
                Some("aws-region"),
                Some("default-region"),
            ),
            "aws-region"
        );
    }

    #[test]
    fn the_config_file_is_used_only_when_nothing_above_it_is_set() {
        assert_eq!(
            region_for_p(None, Some("config-region"), None, None, None),
            "config-region"
        );
        assert_eq!(
            region_for_p(None, None, None, None, None),
            "",
            "no source set: the profile is skipped"
        );
    }

    #[test]
    fn config_region_reads_only_the_profiles_own_section() {
        let dir = tempfile::tempdir().unwrap();
        let creds = dir.path().join("credentials");
        let config = dir.path().join("config");
        let key = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = secret\n";
        std::fs::write(&creds, format!("[default]\n{key}\n[p]\n{key}\n[q]\n{key}")).unwrap();
        std::fs::write(
            &config,
            "[default]\nregion = default-config\n\n[profile p]\nregion = p-config\n\n[q]\nregion = bare-section\n",
        )
        .unwrap();
        let inputs = RegionInputs {
            config_path: Some(config),
            ..Default::default()
        };
        let found = discover_aws_profiles(Some(&creds), &inputs).unwrap();
        let region = |name: &str| {
            region_of(
                found
                    .iter()
                    .find(|d| d.name == name)
                    .expect("profile found"),
            )
        };
        assert_eq!(region("default"), "default-config");
        assert_eq!(region("p"), "p-config");
        assert_eq!(
            region("q"),
            "",
            "a bare [q] section is not the q profile's config"
        );
    }

    #[test]
    fn a_missing_config_file_is_not_an_error() {
        let (dir, path) = write_credentials(
            "[p]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = secret\n",
        );
        let inputs = RegionInputs {
            flag: Some("us-east-1".into()),
            config_path: Some(dir.path().join("absent")),
            ..Default::default()
        };
        let found = discover_aws_profiles(Some(&path), &inputs).unwrap();
        assert_eq!(region_of(&found[0]), "us-east-1");
    }

    #[test]
    fn aws_file_path_prefers_the_explicit_variable_then_home() {
        let home = Some(OsString::from("/home/u"));
        assert_eq!(
            aws_file_path(Some(OsString::from("/x/config")), home.clone(), "config"),
            Some(PathBuf::from("/x/config"))
        );
        assert_eq!(
            aws_file_path(Some(OsString::new()), home.clone(), "config"),
            Some(PathBuf::from("/home/u/.aws/config"))
        );
        assert_eq!(aws_file_path(None, None, "config"), None);
    }

    #[test]
    fn discover_import_profiles_maps_name_key_region_and_defaults_identity() {
        let (dir, path) = write_credentials(
            "[work]\naws_access_key_id = AKIAI44QH8DHBEXAMPLE\naws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\n",
        );
        let config = dir.path().join("config");
        std::fs::write(&config, "[profile work]\nregion = us-west-2\n").unwrap();
        let profiles = discover_import_profiles(&ImportSource::AwsProfiles {
            path: Some(path),
            region: RegionInputs {
                config_path: Some(config),
                ..Default::default()
            },
        })
        .unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "work");
        assert_eq!(profiles[0].access_key_id, "AKIAI44QH8DHBEXAMPLE");
        assert_eq!(
            profiles[0].secret_access_key,
            "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
        );
        assert_eq!(profiles[0].region, "us-west-2");
        assert_eq!(
            profiles[0].identity_type, None,
            "discovery classifies imported keys as human via the daemon default"
        );
    }

    #[test]
    fn decide_imports_new_valid_names_and_skips_existing_or_unsafe() {
        let mut existing = credentials::CredentialSources::new();
        existing.insert("taken".to_string(), CredentialSource::Unsupported);

        assert!(matches!(
            decide("fresh", "us-east-1", &existing),
            Decision::Import
        ));
        assert!(matches!(
            decide("taken", "us-east-1", &existing),
            Decision::Skip(_)
        ));
        assert!(matches!(
            decide("../etc", "us-east-1", &existing),
            Decision::Skip(_)
        ));
    }

    #[test]
    fn decide_skips_a_profile_with_no_region_and_names_the_flag() {
        let existing = credentials::CredentialSources::new();
        match decide("fresh", "", &existing) {
            Decision::Skip(reason) => assert!(reason.contains("--region"), "{reason}"),
            Decision::Import => panic!("a profile with no region must not import"),
        }
    }

    #[test]
    fn discover_errors_when_the_file_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope");
        assert!(discover_aws_profiles(Some(&path), &RegionInputs::default()).is_err());
    }

    proptest! {
        #[test]
        fn parse_ini_never_panics_and_keeps_only_real_keys(input in "(?s).*") {
            for (_section, keys) in parse_ini(&input) {
                for k in keys.keys() {
                    prop_assert!(!k.contains('['));
                    prop_assert_eq!(k, &k.to_ascii_lowercase());
                }
            }
        }

        #[test]
        fn keys_before_a_section_are_dropped(key in "[a-z_]{1,12}", value in "[a-zA-Z0-9]{1,12}") {
            let ini = format!("{key} = {value}\n[s]\nother = 1\n");
            let sections = parse_ini(&ini);
            prop_assert_eq!(sections.len(), 1);
            prop_assert_eq!(&sections[0].0, "s");
            prop_assert!(!sections[0].1.contains_key(&key));
        }
    }
}
