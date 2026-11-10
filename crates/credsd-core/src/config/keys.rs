//! Allowed config keys, validation rules, and protected-key policy.

use toml_edit::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    String,
    Boolean,
    Integer,
    Enum(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy)]
pub struct ConfigKeyDef {
    pub key: &'static str,
    pub section: Option<&'static str>,
    pub field: &'static str,
    pub value_type: ValueType,
    pub description: &'static str,
    pub env_var: Option<&'static str>,
    pub aws_config_key: Option<&'static str>,
}

pub static ALLOWED_KEYS: &[ConfigKeyDef] = &[
    // Top-level env keys
    ConfigKeyDef {
        key: "region",
        section: None,
        field: "region",
        value_type: ValueType::String,
        description: "AWS region for this env",
        env_var: None, // region injection handled separately (AWS_REGION + AWS_DEFAULT_REGION)
        aws_config_key: None, // region handled directly from EnvConfig.region
    },
    ConfigKeyDef {
        key: "identity_type",
        section: None,
        field: "identity_type",
        value_type: ValueType::Enum(&["human", "automation", "agent"]),
        description: "Identity classification",
        env_var: None,
        aws_config_key: None,
    },
    ConfigKeyDef {
        key: "description",
        section: None,
        field: "description",
        value_type: ValueType::String,
        description: "Human-readable env description",
        env_var: None,
        aws_config_key: None,
    },
    // sdk.* keys — env var + config file
    ConfigKeyDef {
        key: "sdk.endpoint_url",
        section: Some("sdk"),
        field: "endpoint_url",
        value_type: ValueType::String,
        description: "Global endpoint URL override",
        env_var: Some("AWS_ENDPOINT_URL"),
        aws_config_key: Some("endpoint_url"),
    },
    ConfigKeyDef {
        key: "sdk.use_fips_endpoint",
        section: Some("sdk"),
        field: "use_fips_endpoint",
        value_type: ValueType::Boolean,
        description: "Use FIPS endpoints",
        env_var: Some("AWS_USE_FIPS_ENDPOINT"),
        aws_config_key: Some("use_fips_endpoint"),
    },
    ConfigKeyDef {
        key: "sdk.use_dualstack_endpoint",
        section: Some("sdk"),
        field: "use_dualstack_endpoint",
        value_type: ValueType::Boolean,
        description: "Use dual-stack endpoints",
        env_var: Some("AWS_USE_DUALSTACK_ENDPOINT"),
        aws_config_key: Some("use_dualstack_endpoint"),
    },
    ConfigKeyDef {
        key: "sdk.ca_bundle",
        section: Some("sdk"),
        field: "ca_bundle",
        value_type: ValueType::String,
        description: "Path to CA certificate bundle",
        env_var: Some("AWS_CA_BUNDLE"),
        aws_config_key: Some("ca_bundle"),
    },
    ConfigKeyDef {
        key: "sdk.retry_mode",
        section: Some("sdk"),
        field: "retry_mode",
        value_type: ValueType::Enum(&["standard", "adaptive", "legacy"]),
        description: "SDK retry strategy",
        env_var: Some("AWS_RETRY_MODE"),
        aws_config_key: Some("retry_mode"),
    },
    ConfigKeyDef {
        key: "sdk.max_attempts",
        section: Some("sdk"),
        field: "max_attempts",
        value_type: ValueType::Integer,
        description: "Maximum retry attempts",
        env_var: Some("AWS_MAX_ATTEMPTS"),
        aws_config_key: Some("max_attempts"),
    },
    ConfigKeyDef {
        key: "sdk.defaults_mode",
        section: Some("sdk"),
        field: "defaults_mode",
        value_type: ValueType::Enum(&[
            "legacy",
            "standard",
            "in-region",
            "cross-region",
            "mobile",
            "auto",
        ]),
        description: "Smart configuration defaults mode",
        env_var: Some("AWS_DEFAULTS_MODE"),
        aws_config_key: Some("defaults_mode"),
    },
    ConfigKeyDef {
        key: "sdk.sts_regional_endpoints",
        section: Some("sdk"),
        field: "sts_regional_endpoints",
        value_type: ValueType::Enum(&["regional", "legacy"]),
        description: "STS endpoint resolution strategy",
        env_var: Some("AWS_STS_REGIONAL_ENDPOINTS"),
        aws_config_key: Some("sts_regional_endpoints"),
    },
    ConfigKeyDef {
        key: "sdk.s3_us_east_1_regional_endpoint",
        section: Some("sdk"),
        field: "s3_us_east_1_regional_endpoint",
        value_type: ValueType::Enum(&["regional", "legacy"]),
        description: "S3 us-east-1 endpoint resolution",
        env_var: Some("AWS_S3_US_EAST_1_REGIONAL_ENDPOINT"),
        aws_config_key: Some("s3_us_east_1_regional_endpoint"),
    },
    ConfigKeyDef {
        key: "sdk.disable_request_compression",
        section: Some("sdk"),
        field: "disable_request_compression",
        value_type: ValueType::Boolean,
        description: "Disable request payload compression",
        env_var: Some("AWS_DISABLE_REQUEST_COMPRESSION"),
        aws_config_key: Some("disable_request_compression"),
    },
    ConfigKeyDef {
        key: "sdk.request_min_compression_size_bytes",
        section: Some("sdk"),
        field: "request_min_compression_size_bytes",
        value_type: ValueType::Integer,
        description: "Minimum payload size for compression (bytes)",
        env_var: Some("AWS_REQUEST_MIN_COMPRESSION_SIZE_BYTES"),
        aws_config_key: Some("request_min_compression_size_bytes"),
    },
    ConfigKeyDef {
        key: "sdk.ignore_configured_endpoint_urls",
        section: Some("sdk"),
        field: "ignore_configured_endpoint_urls",
        value_type: ValueType::Boolean,
        description: "Ignore custom endpoint URL configurations",
        env_var: Some("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"),
        aws_config_key: Some("ignore_configured_endpoint_urls"),
    },
    ConfigKeyDef {
        key: "sdk.sdk_ua_app_id",
        section: Some("sdk"),
        field: "sdk_ua_app_id",
        value_type: ValueType::String,
        description: "Application ID for SDK user-agent tracking",
        env_var: Some("AWS_SDK_UA_APP_ID"),
        aws_config_key: Some("sdk_ua_app_id"),
    },
    ConfigKeyDef {
        key: "sdk.account_id_endpoint_mode",
        section: Some("sdk"),
        field: "account_id_endpoint_mode",
        value_type: ValueType::Enum(&["preferred", "disabled", "required"]),
        description: "Account-based endpoint routing mode",
        env_var: Some("AWS_ACCOUNT_ID_ENDPOINT_MODE"),
        aws_config_key: Some("account_id_endpoint_mode"),
    },
    // sdk.* keys — config file only (no env var analog)
    ConfigKeyDef {
        key: "sdk.parameter_validation",
        section: Some("sdk"),
        field: "parameter_validation",
        value_type: ValueType::Boolean,
        description: "Client-side parameter validation",
        env_var: None,
        aws_config_key: Some("parameter_validation"),
    },
    // cli.* keys — env var + config file
    ConfigKeyDef {
        key: "cli.output",
        section: Some("cli"),
        field: "output",
        value_type: ValueType::Enum(&["json", "text", "table", "yaml", "yaml-stream"]),
        description: "Default output format",
        env_var: Some("AWS_DEFAULT_OUTPUT"),
        aws_config_key: Some("output"),
    },
    ConfigKeyDef {
        key: "cli.pager",
        section: Some("cli"),
        field: "pager",
        value_type: ValueType::String,
        description: "Pager command (empty string disables). Stored but not projected — AWS_PAGER is a shell command line executed by the CLI; projecting it across the daemon trust boundary allows code execution as the calling user.",
        env_var: None,
        aws_config_key: None,
    },
    // cli.* keys — config file only (no env var analog)
    ConfigKeyDef {
        key: "cli.cli_timestamp_format",
        section: Some("cli"),
        field: "cli_timestamp_format",
        value_type: ValueType::Enum(&["iso8601", "wire"]),
        description: "Timestamp display format (CLI only)",
        env_var: None,
        aws_config_key: Some("cli_timestamp_format"),
    },
    ConfigKeyDef {
        key: "cli.cli_binary_format",
        section: Some("cli"),
        field: "cli_binary_format",
        value_type: ValueType::Enum(&["base64", "raw-in-base64-out"]),
        description: "Binary value encoding format (CLI only)",
        env_var: None,
        aws_config_key: Some("cli_binary_format"),
    },
    ConfigKeyDef {
        key: "cli.cli_follow_urlparam",
        section: Some("cli"),
        field: "cli_follow_urlparam",
        value_type: ValueType::Boolean,
        description: "Fetch content from URL parameters (CLI only)",
        env_var: None,
        aws_config_key: Some("cli_follow_urlparam"),
    },
];

static PROTECTED_KEYS: &[(&str, &str)] = &[(
    "credential",
    "use 'credsd bootstrap' to change the credential source",
)];

/// Keys that may be set but not removed, with the reason. A key is listed here when its absent
/// form is more permissive than some value it can hold, which makes unsetting it a way to gain
/// privilege rather than a way to tidy up.
static UNSET_PROTECTED_KEYS: &[(&str, &str)] = &[(
    "identity_type",
    "an absent identity_type is read as 'human', the most privileged tier, so removing it would \
     grant privilege rather than drop it. Set it to an explicit tier instead",
)];

pub fn find_key(key: &str) -> Option<&'static ConfigKeyDef> {
    ALLOWED_KEYS.iter().find(|k| k.key == key)
}

/// The reason `key` cannot be unset, or `None` when removing it is allowed. Separate from
/// [`is_protected`], which blocks reads and writes alike: these keys stay readable and settable.
pub fn is_unset_protected(key: &str) -> Option<&'static str> {
    UNSET_PROTECTED_KEYS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, reason)| *reason)
}

pub fn is_protected(key: &str) -> Option<&'static str> {
    PROTECTED_KEYS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, reason)| *reason)
}

impl ValueType {
    pub fn validate(&self, input: &str, key: &str) -> Result<toml_edit::Value, String> {
        match self {
            ValueType::String => {
                if input.is_empty() && key != "cli.pager" {
                    return Err(format!("value cannot be empty for '{}'", key));
                }
                // Values are rendered into the generated AWS config, where a line break starts
                // a new directive, and into approval text, where a bidi override hides what the
                // approver reads. The renderer refuses them too; this reports it at the source.
                if let Some(c) = input
                    .chars()
                    .find(|c| c.is_control() || crate::log::is_invisible_format(*c as u32))
                {
                    return Err(format!(
                        "value for '{}' contains control or invisible character {:?}",
                        key, c
                    ));
                }
                Ok(Value::from(input))
            }
            ValueType::Boolean => match input.to_lowercase().as_str() {
                "true" => Ok(Value::from(true)),
                "false" => Ok(Value::from(false)),
                _ => Err(format!("expected 'true' or 'false', got '{}'", input)),
            },
            ValueType::Integer => {
                let n: i64 = input
                    .parse()
                    .map_err(|_| format!("expected a positive integer, got '{}'", input))?;
                if n <= 0 {
                    return Err(format!("expected a positive integer, got '{}'", input));
                }
                Ok(Value::from(n))
            }
            ValueType::Enum(options) => {
                if options.contains(&input) {
                    Ok(Value::from(input))
                } else {
                    Err(format!(
                        "expected one of [{}], got '{}'",
                        options.join(", "),
                        input
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_key_top_level() {
        let def = find_key("region").unwrap();
        assert_eq!(def.field, "region");
        assert_eq!(def.section, None);
    }

    #[test]
    fn find_key_nested() {
        let def = find_key("sdk.retry_mode").unwrap();
        assert_eq!(def.field, "retry_mode");
        assert_eq!(def.section, Some("sdk"));
    }

    #[test]
    fn find_key_unknown_returns_none() {
        assert!(find_key("nonexistent").is_none());
        assert!(find_key("sdk.nonexistent").is_none());
    }

    #[test]
    fn protected_exact_match() {
        let reason = is_protected("credential").unwrap();
        assert!(reason.contains("bootstrap"));
    }

    /// Credential-source fields live in credentials.toml now, so `config set` has no opinion
    /// about them — it rejects them as unknown keys rather than as protected ones.
    #[test]
    fn credential_source_fields_are_not_env_keys() {
        assert!(is_protected("sso.start_url").is_none());
        assert!(is_protected("mode").is_none());
        assert!(find_key("sso.start_url").is_none());
        assert!(find_key("mode").is_none());
    }

    #[test]
    fn protected_unknown_is_not_protected() {
        assert!(is_protected("region").is_none());
        assert!(is_protected("sdk.retry_mode").is_none());
    }

    /// `identity_type` stays readable and settable; only removing it is refused. An absent key
    /// reads as the most privileged tier, so an unset would raise privilege.
    #[test]
    fn identity_type_may_be_set_but_not_unset() {
        assert!(is_protected("identity_type").is_none());
        assert!(find_key("identity_type").is_some());
        let reason = is_unset_protected("identity_type").unwrap();
        assert!(reason.contains("human"), "reason names the tier: {reason}");
    }

    #[test]
    fn ordinary_keys_may_be_unset() {
        assert!(is_unset_protected("region").is_none());
        assert!(is_unset_protected("sdk.retry_mode").is_none());
        assert!(is_unset_protected("description").is_none());
    }

    #[test]
    fn validate_string_accepts_nonempty() {
        let result = ValueType::String.validate("us-east-1", "region");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_string_rejects_empty() {
        let result = ValueType::String.validate("", "region");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn validate_string_rejects_control_characters() {
        for input in [
            "https://e.example\ncredential_process = /tmp/x",
            "a\rb",
            "a\tb",
            "a\u{1b}[2Kb",
            "a\u{7f}",
        ] {
            let err = ValueType::String
                .validate(input, "sdk.endpoint_url")
                .unwrap_err();
            assert!(
                err.contains("control or invisible character"),
                "{input:?}: {err}"
            );
        }
    }

    /// Every code point is checked, not a sample: a value that carries any Cf character
    /// (except the joiners emoji and Indic text need) is refused, and any other char is kept.
    #[test]
    fn validate_string_refuses_every_invisible_format_character() {
        for cp in 0..=0x10FFFF_u32 {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            let input = format!("a{c}b");
            let joiner = matches!(cp, 0x200C | 0x200D);
            let refused = c.is_control() || (crate::log::is_invisible_format(cp) && !joiner);
            let result = ValueType::String.validate(&input, "sdk.endpoint_url");
            assert_eq!(result.is_err(), refused, "U+{cp:04X}: {result:?}");
        }
        assert!(ValueType::String
            .validate("a\u{202E}b", "sdk.endpoint_url")
            .is_err());
        assert!(ValueType::String
            .validate("a\u{200D}b", "sdk.endpoint_url")
            .is_ok());
    }

    #[test]
    fn validate_string_allows_empty_for_pager() {
        let result = ValueType::String.validate("", "cli.pager");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_boolean_true() {
        let v = ValueType::Boolean
            .validate("true", "sdk.use_fips_endpoint")
            .unwrap();
        assert_eq!(v.as_bool(), Some(true));
    }

    #[test]
    fn validate_boolean_false_case_insensitive() {
        let v = ValueType::Boolean
            .validate("False", "sdk.use_fips_endpoint")
            .unwrap();
        assert_eq!(v.as_bool(), Some(false));
    }

    #[test]
    fn validate_boolean_rejects_invalid() {
        let result = ValueType::Boolean.validate("yes", "sdk.use_fips_endpoint");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 'true' or 'false'"));
    }

    #[test]
    fn validate_integer_positive() {
        let v = ValueType::Integer
            .validate("5", "sdk.max_attempts")
            .unwrap();
        assert_eq!(v.as_integer(), Some(5));
    }

    #[test]
    fn validate_integer_rejects_zero() {
        let result = ValueType::Integer.validate("0", "sdk.max_attempts");
        assert!(result.is_err());
    }

    #[test]
    fn validate_integer_rejects_negative() {
        let result = ValueType::Integer.validate("-1", "sdk.max_attempts");
        assert!(result.is_err());
    }

    #[test]
    fn validate_integer_rejects_non_numeric() {
        let result = ValueType::Integer.validate("abc", "sdk.max_attempts");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected a positive integer"));
    }

    #[test]
    fn validate_enum_accepts_valid() {
        let opts = &["standard", "adaptive", "legacy"];
        let v = ValueType::Enum(opts)
            .validate("adaptive", "sdk.retry_mode")
            .unwrap();
        assert_eq!(v.as_str(), Some("adaptive"));
    }

    #[test]
    fn validate_enum_rejects_invalid() {
        let opts = &["standard", "adaptive", "legacy"];
        let result = ValueType::Enum(opts).validate("exponential", "sdk.retry_mode");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("expected one of"));
        assert!(err.contains("exponential"));
    }

    #[test]
    fn round_trip_set_get_unset_top_level() {
        use toml_edit::{DocumentMut, Item};

        let config = r#"port = 9765

[environments.demo]
mode = "sso"
region = "us-east-1"
"#;
        let mut doc: DocumentMut = config.parse().unwrap();
        let key_def = find_key("region").unwrap();

        // SET: change region
        let val = key_def.value_type.validate("us-west-2", "region").unwrap();
        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("demo")
            .unwrap()
            .as_table_mut()
            .unwrap();
        env_tbl.insert(key_def.field, Item::Value(val));

        // GET: verify
        let got = doc
            .get("environments")
            .unwrap()
            .get("demo")
            .unwrap()
            .get("region")
            .unwrap()
            .as_str();
        assert_eq!(got, Some("us-west-2"));

        // UNSET: remove
        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("demo")
            .unwrap()
            .as_table_mut()
            .unwrap();
        env_tbl.remove("region");

        let gone = doc
            .get("environments")
            .unwrap()
            .get("demo")
            .unwrap()
            .get("region");
        assert!(gone.is_none());
    }

    #[test]
    fn round_trip_set_get_unset_nested() {
        use toml_edit::{DocumentMut, Item, Table};

        let config = r#"port = 9765

[environments.demo]
mode = "sso"
region = "us-east-1"
"#;
        let mut doc: DocumentMut = config.parse().unwrap();
        let key_def = find_key("sdk.retry_mode").unwrap();

        // SET: create sdk section and set retry_mode
        let val = key_def
            .value_type
            .validate("adaptive", "sdk.retry_mode")
            .unwrap();
        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("demo")
            .unwrap()
            .as_table_mut()
            .unwrap();
        env_tbl.insert("sdk", Item::Table(Table::new()));
        let sdk = env_tbl.get_mut("sdk").unwrap().as_table_mut().unwrap();
        sdk.insert(key_def.field, Item::Value(val));

        // GET: verify
        let got = doc
            .get("environments")
            .unwrap()
            .get("demo")
            .unwrap()
            .get("sdk")
            .unwrap()
            .get("retry_mode")
            .unwrap()
            .as_str();
        assert_eq!(got, Some("adaptive"));

        // UNSET: remove key, then remove empty section
        let env_tbl = doc
            .get_mut("environments")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("demo")
            .unwrap()
            .as_table_mut()
            .unwrap();
        let sdk = env_tbl.get_mut("sdk").unwrap().as_table_mut().unwrap();
        sdk.remove("retry_mode");
        if sdk.is_empty() {
            env_tbl.remove("sdk");
        }

        let output = doc.to_string();
        assert!(!output.contains("sdk"));
        assert!(!output.contains("retry_mode"));
        assert!(output.contains("region = \"us-east-1\""));
    }

    #[test]
    fn protected_key_set_rejected() {
        let result = is_protected("credential");
        assert!(result.is_some());
        assert!(result.unwrap().contains("bootstrap"));
    }

    #[test]
    fn unknown_key_not_found() {
        assert!(find_key("typo.key").is_none());
        assert!(find_key("sdk.nonexistent").is_none());
    }

    #[test]
    fn invalid_type_produces_descriptive_error() {
        let key_def = find_key("sdk.max_attempts").unwrap();
        let err = key_def
            .value_type
            .validate("-1", "sdk.max_attempts")
            .unwrap_err();
        assert!(err.contains("positive integer"));
        assert!(err.contains("-1"));
    }

    #[test]
    fn config_keys_json_output() {
        let entries: Vec<serde_json::Value> = ALLOWED_KEYS
            .iter()
            .map(|k| {
                serde_json::json!({
                    "key": k.key,
                    "type": match k.value_type {
                        ValueType::String => "string",
                        ValueType::Boolean => "boolean",
                        ValueType::Integer => "integer",
                        ValueType::Enum(_) => "enum",
                    },
                    "description": k.description,
                })
            })
            .collect();
        let json = serde_json::to_string_pretty(&entries).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 23);
        assert_eq!(parsed[0]["key"], "region");
    }
}
