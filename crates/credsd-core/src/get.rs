//! Credential output formatting for CLI consumers.

use crate::credential_env::format_env_vars;
use crate::credentials::{CredentialData, Credentials};
use crate::error::{DaemonError, Result};
use crate::wire::ContainerCredentialResponse;

/// Whether a format names a variable, and so needs one resolved before it can render.
///
/// Only the eval-style formats do. `raw` and `credential-process` are machine-readable shapes with
/// no variable in them, which is why the caller resolves an address for these three and nothing else
/// — a `credential_process` invocation is on an SDK's hot path and should not pay for a lookup it
/// cannot use.
pub fn names_a_variable(format: OutputFormat) -> bool {
    matches!(
        format,
        OutputFormat::Shell | OutputFormat::Fish | OutputFormat::PowerShell
    )
}

/// Credential output serialization formats for CLI consumers.
#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Raw,
    CredentialProcess,
    Shell,
    Fish,
    PowerShell,
}

impl OutputFormat {
    pub fn from_str_opt(s: Option<&str>) -> Result<Self> {
        match s {
            None => Ok(Self::Raw),
            Some("credential-process") => Ok(Self::CredentialProcess),
            Some("shell") => Ok(Self::Shell),
            Some("fish") => Ok(Self::Fish),
            Some("powershell") => Ok(Self::PowerShell),
            Some(other) => Err(DaemonError::config(format!(
                "unknown format '{}'. Valid: credential-process, shell, fish, powershell",
                other
            ))),
        }
    }
}

/// The `format_env_vars` name of an eval-style format, which selects its quoting rule.
fn eval_format(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Fish => "fish",
        OutputFormat::PowerShell => "powershell",
        OutputFormat::Shell | OutputFormat::Raw | OutputFormat::CredentialProcess => "shell",
    }
}

/// Serialize credentials into the requested output format.
///
/// `token_var` is the variable an eval-style format exports a bearer token as — the address the
/// credential's projection resolved to, supplied by the caller rather than fixed here. A constant
/// would put `get` and `run` at different addresses for one credential, which Requirement 3.5 of
/// `credential-projection` forbids: the same selection resolves the same way for every consumer.
/// Ignored by the formats that name no variable.
pub fn format_credentials(
    creds: &Credentials,
    format: OutputFormat,
    token_var: &str,
) -> Result<String> {
    match &creds.data {
        CredentialData::SessionCredentials {
            access_key,
            secret_key,
            session_token,
        } => {
            // The ECS contract and `credential_process` both require an absolute
            // `Expiration`, and `Credentials::session` cannot construct a session credential
            // without one — so this arm is unreachable except from a sealed file whose
            // `expires_at` is null. Refuse rather than fabricate an expiry: a substituted
            // value is exactly the clock-skew hazard the absolute-expiry rule exists to stop.
            let Some(expires_at) = creds.expires_at else {
                return Err(DaemonError::provider(
                    "session credentials carry no expiry; refusing to emit AWS credentials \
                     whose lifetime cannot be stated",
                ));
            };
            let expiration = expires_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            match format {
                OutputFormat::Raw => {
                    let resp = ContainerCredentialResponse {
                        access_key_id: access_key.clone(),
                        secret_access_key: secret_key.clone(),
                        token: session_token.clone(),
                        expiration,
                    };
                    serde_json::to_string_pretty(&resp)
                        .map_err(|e| DaemonError::provider(e.to_string()))
                }
                OutputFormat::CredentialProcess => {
                    let output = serde_json::json!({
                        "Version": 1,
                        "AccessKeyId": access_key,
                        "SecretAccessKey": secret_key,
                        "SessionToken": session_token,
                        "Expiration": expiration,
                    });
                    serde_json::to_string(&output).map_err(|e| DaemonError::provider(e.to_string()))
                }
                OutputFormat::Shell | OutputFormat::Fish | OutputFormat::PowerShell => {
                    let vars = [
                        ("AWS_ACCESS_KEY_ID", access_key),
                        ("AWS_SECRET_ACCESS_KEY", secret_key),
                        ("AWS_SESSION_TOKEN", session_token),
                    ];
                    format_env_vars(&vars, eval_format(format))
                }
            }
        }
        CredentialData::AccessToken { token } => {
            // An `Option<String>` so a token with no stated lifetime serializes as an
            // explicit `null`, matching the `credential/get` wire contract. An absent field
            // would leave a consumer unable to tell "never expires" from "not reported".
            let expiration = creds
                .expires_at
                .map(|at| at.format("%Y-%m-%dT%H:%M:%SZ").to_string());
            match format {
                OutputFormat::Raw => serde_json::to_string_pretty(&serde_json::json!({
                    "Token": token,
                    "Expiration": expiration,
                }))
                .map_err(|e| DaemonError::provider(e.to_string())),
                // `credential_process` is an AWS SDK contract: the SDK expects an access key
                // triple and has no interpretation for a bearer token. Refusing here is the
                // configuration error surfacing at the one place that can name both sides.
                OutputFormat::CredentialProcess => Err(DaemonError::provider(
                    "credential provides an access token, which the AWS credential_process \
                     protocol cannot carry",
                )),
                OutputFormat::Shell | OutputFormat::Fish | OutputFormat::PowerShell => {
                    format_env_vars(&[(token_var, token)], eval_format(format))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_env::{quote_fish, quote_posix, quote_powershell};
    use chrono::{TimeZone, Utc};
    use proptest::prelude::*;

    fn token_creds(token: &str) -> Credentials {
        Credentials::access_token(
            token.to_owned(),
            Some(Utc.timestamp_opt(1_800_000_000, 0).unwrap()),
        )
    }

    /// The AWS SDK's `credential_process` schema has no field a bearer token belongs in, so this
    /// combination must fail rather than emit a document the SDK would parse into empty keys.
    #[test]
    fn a_token_cannot_be_a_credential_process_document() {
        let err = format_credentials(
            &token_creds("t"),
            OutputFormat::CredentialProcess,
            "CREDSD_TOKEN",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("credential_process"), "{err}");
        assert!(!err.contains('t') || !err.contains("\"t\""), "{err}");
    }

    /// Only the eval formats name a variable. `credential-process` runs on an SDK's hot path, so a
    /// caller must be able to skip resolving an address it would not use.
    #[test]
    fn only_eval_formats_name_a_variable() {
        assert!(names_a_variable(OutputFormat::Shell));
        assert!(names_a_variable(OutputFormat::Fish));
        assert!(names_a_variable(OutputFormat::PowerShell));
        assert!(!names_a_variable(OutputFormat::Raw));
        assert!(!names_a_variable(OutputFormat::CredentialProcess));
    }

    proptest! {
        /// The eval formats carry the token through byte-for-byte: a shell eval that truncated or
        /// re-encoded it would export a token the API rejects, and the failure would surface at
        /// the API rather than here. Arbitrary strings, because a token is opaque — JWTs carry
        /// `.` and `-`, and a provider's opaque token can carry anything.
        ///
        /// `Raw` is excluded deliberately, not overlooked: JSON escapes control characters, so its
        /// contract is decoded equality rather than substring identity — asserted in
        /// `raw_stays_parseable_json`, which is the stronger check for that format.
        #[test]
        fn eval_formats_carry_the_token_verbatim(token in ".{1,200}") {
            // Each shell's quoting rule is proven to round-trip in `credential_env`; here the
            // property is that the token reaches that rule unaltered.
            let shell_out = format_credentials(&token_creds(&token), OutputFormat::Shell, "CREDSD_TOKEN").expect("shell");
            let fish_out = format_credentials(&token_creds(&token), OutputFormat::Fish, "CREDSD_TOKEN").expect("fish");
            let ps_out = format_credentials(&token_creds(&token), OutputFormat::PowerShell, "CREDSD_TOKEN").expect("powershell");
            prop_assert_eq!(shell_out, format!("export CREDSD_TOKEN={}", quote_posix(&token)));
            prop_assert_eq!(fish_out, format!("set -x CREDSD_TOKEN {}", quote_fish(&token)));
            prop_assert_eq!(ps_out, format!("$env:CREDSD_TOKEN={}", quote_powershell(&token)));
        }

        /// Session keys were printed bare, so a secret or session token holding shell syntax ran
        /// when the output was eval'd.
        #[test]
        fn session_credentials_are_quoted_in_every_eval_format(secret in ".{1,64}") {
            let creds = Credentials::session(
                "AKIDEXAMPLE".into(),
                secret.clone(),
                "tok".into(),
                Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            );
            let shell = format_credentials(&creds, OutputFormat::Shell, "X").expect("shell");
            let fish = format_credentials(&creds, OutputFormat::Fish, "X").expect("fish");
            let ps = format_credentials(&creds, OutputFormat::PowerShell, "X").expect("powershell");
            let expected = [
                (shell, format!("export AWS_SECRET_ACCESS_KEY={}\n", quote_posix(&secret))),
                (fish, format!("set -x AWS_SECRET_ACCESS_KEY {}\n", quote_fish(&secret))),
                (ps, format!("$env:AWS_SECRET_ACCESS_KEY={}\n", quote_powershell(&secret))),
            ];
            for (out, line) in expected {
                prop_assert!(out.contains(&line), "{} lacks {}", out, line);
            }
        }

        /// `raw` is the machine-readable form, so it must stay parseable for every token — the
        /// case a hand-rolled `format!` would break on a `"` or a backslash.
        #[test]
        fn raw_stays_parseable_json(token in ".{1,200}") {
            let out = format_credentials(&token_creds(&token), OutputFormat::Raw, "CREDSD_TOKEN").expect("formats");
            let parsed: serde_json::Value = serde_json::from_str(&out).expect("raw must be JSON");
            prop_assert_eq!(parsed["Token"].as_str(), Some(token.as_str()));
            prop_assert_eq!(parsed["Expiration"].as_str(), Some("2027-01-15T08:00:00Z"));
        }

        /// The eval formats name the variable a shell will export. Asserted per shell because
        /// each has its own syntax and only the variable name is shared.
        #[test]
        fn eval_formats_export_the_token_variable(token in "[A-Za-z0-9._-]{1,64}") {
            let creds = token_creds(&token);
            // Token alphabet [A-Za-z0-9._-] contains no shell-special chars; quoting is
            // transparent and the output equals the bare-token form inside single quotes.
            prop_assert_eq!(
                format_credentials(&creds, OutputFormat::Shell, "CREDSD_TOKEN").expect("shell"),
                format!("export CREDSD_TOKEN='{token}'")
            );
            prop_assert_eq!(
                format_credentials(&creds, OutputFormat::Fish, "CREDSD_TOKEN").expect("fish"),
                format!("set -x CREDSD_TOKEN '{token}'")
            );
            prop_assert_eq!(
                format_credentials(&creds, OutputFormat::PowerShell, "CREDSD_TOKEN").expect("powershell"),
                format!("$env:CREDSD_TOKEN='{token}'")
            );
        }
    }
}
