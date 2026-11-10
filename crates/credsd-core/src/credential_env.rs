//! Environment variable assembly for child processes.

use crate::config::{self, EnvConfig};
use crate::error::{DaemonError, Result};

/// The complete set of environment state needed to connect to a credential endpoint.
pub struct CredentialEnv {
    pub uri: String,
    pub auth_token: String,
    pub region: Option<String>,
    pub extra_env: Vec<(&'static str, String)>,
}

const CONFLICTING_VARS: &[&str] = &[
    // Static credential vars — superseded by the container endpoint.
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    // Alternative AWS credential-source vars that would override or race the container endpoint.
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    // Loader/interpreter hijack vars — allow ambient LD_PRELOAD etc. to ride into the child.
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    // Shell interpreter vars that execute arbitrary code when the child is a shell or script.
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "IFS",
    // Language runtime hijack vars.
    "PYTHONPATH",
    "RUBYLIB",
    "PERL5LIB",
    "PERL5OPT",
];

impl CredentialEnv {
    pub fn new(port: u16, env_name: &str, token: &str, env: Option<&EnvConfig>) -> Self {
        Self {
            uri: format!(
                "http://127.0.0.1:{}/container_credentials/{}",
                port, env_name
            ),
            auth_token: format!("Bearer {}", token),
            region: env.and_then(|p| p.region.clone()),
            extra_env: config::resolve_env_vars(env),
        }
    }

    /// Inject credential env vars and remove conflicting ones from a child command.
    pub fn apply_to_command(&self, cmd: &mut tokio::process::Command) {
        cmd.env("AWS_CONTAINER_CREDENTIALS_FULL_URI", &self.uri)
            .env("AWS_CONTAINER_AUTHORIZATION_TOKEN", &self.auth_token)
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("AWS_CONFIG_FILE", "/dev/null");

        if let Some(ref r) = self.region {
            cmd.env("AWS_REGION", r);
            cmd.env("AWS_DEFAULT_REGION", r);
        }

        for (key, val) in &self.extra_env {
            cmd.env(key, val);
        }

        for var in CONFLICTING_VARS {
            cmd.env_remove(var);
        }
    }

    /// The variables this endpoint contributes, in the order they are rendered.
    ///
    /// `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` are deliberately absent: those are
    /// blocked in the child by [`Self::apply_to_command`], and printing `/dev/null` assignments
    /// in an eval-able rendering would break a shell the user pasted them into.
    pub fn vars(&self) -> Vec<(String, String)> {
        let mut vars = vec![
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI".to_owned(),
                self.uri.clone(),
            ),
            (
                "AWS_CONTAINER_AUTHORIZATION_TOKEN".to_owned(),
                self.auth_token.clone(),
            ),
        ];
        if let Some(ref r) = self.region {
            vars.push(("AWS_REGION".to_owned(), r.clone()));
            vars.push(("AWS_DEFAULT_REGION".to_owned(), r.clone()));
        }
        vars.extend(
            self.extra_env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone())),
        );
        vars
    }

    /// Render env vars as shell-evaluable text (shell, fish, powershell, json).
    pub fn format(&self, format: &str) -> Result<String> {
        format_env_vars(&self.vars(), format)
    }
}

/// Render `vars` as shell-evaluable text, in the order given.
///
/// Shared by the endpoint rendering above and by `run --dry-run`, which has to describe a
/// replacing invocation too — one with no endpoint, and so no URI and no token.
///
/// Values are borrowed and quoted straight into one buffer sized up front, so a secret is copied
/// once, into the returned text, rather than into clones and intermediate strings that are freed
/// unscrubbed.
pub fn format_env_vars<K: AsRef<str>, V: AsRef<str>>(
    vars: &[(K, V)],
    format: &str,
) -> Result<String> {
    for (name, _) in vars {
        check_var_name(name.as_ref())?;
    }
    let (prefix, sep, quote): (&str, &str, fn(&mut String, &str)) = match format {
        "shell" => ("export ", "=", push_posix),
        "fish" => ("set -x ", " ", push_fish),
        "powershell" => ("$env:", "=", push_powershell),
        "json" => {
            let map: serde_json::Map<String, serde_json::Value> = vars
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_ref().to_owned(),
                        serde_json::Value::String(v.as_ref().to_owned()),
                    )
                })
                .collect();
            return serde_json::to_string_pretty(&map)
                .map_err(|e| DaemonError::provider(e.to_string()));
        }
        other => {
            return Err(DaemonError::config(format!(
                "unknown format '{}'. Valid: shell, fish, powershell, json",
                other
            )))
        }
    };

    // No rule more than quadruples a value (POSIX writes `'` as four bytes), so the buffer never
    // grows, and never leaves a partial copy behind in the allocation it moved out of.
    let capacity = vars
        .iter()
        .map(|(k, v)| {
            [prefix.len(), k.as_ref().len(), sep.len(), 3]
                .into_iter()
                .fold(v.as_ref().len().saturating_mul(4), usize::saturating_add)
        })
        .fold(0, usize::saturating_add);
    let mut out = String::with_capacity(capacity);
    for (i, (k, v)) in vars.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(prefix);
        out.push_str(k.as_ref());
        out.push_str(sep);
        quote(&mut out, v.as_ref());
    }
    debug_assert!(out.len() <= capacity);
    Ok(out)
}

/// A name is printed unquoted, so one that is not a plain identifier is refused rather than
/// rendered: some names reach here from configuration (a projection's variable), and a name
/// such as `X=1;curl…;Y` would otherwise run as part of the `eval`.
pub(crate) fn check_var_name(name: &str) -> Result<()> {
    if crate::projection::valid_env_var(name) {
        Ok(())
    } else {
        Err(DaemonError::config(format!(
            "{name:?} is not a valid environment variable name; use letters, digits and '_', \
             not starting with a digit"
        )))
    }
}

pub fn quote_posix(value: &str) -> String {
    let mut out = String::new();
    push_posix(&mut out, value);
    out
}

#[cfg(test)]
pub(crate) fn quote_fish(value: &str) -> String {
    let mut out = String::new();
    push_fish(&mut out, value);
    out
}

#[cfg(test)]
pub(crate) fn quote_powershell(value: &str) -> String {
    let mut out = String::new();
    push_powershell(&mut out, value);
    out
}

/// POSIX single quotes take every byte literally except `'` itself, which has no escape inside
/// them: close the quote, emit an escaped quote, reopen.
fn push_posix(out: &mut String, value: &str) {
    out.push('\'');
    for c in value.chars() {
        if c == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
}

/// fish single quotes honor two escapes, `\\` and `\'`, so a backslash must be doubled as well
/// as the quote — the POSIX `'\''` form would leave a trailing backslash to swallow the quote.
fn push_fish(out: &mut String, value: &str) {
    out.push('\'');
    for c in value.chars() {
        if matches!(c, '\\' | '\'') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('\'');
}

/// PowerShell single-quoted strings escape a quote by doubling it, and treat the typographic
/// single quotes U+2018–U+201B as quote characters too, so each of those is doubled as well.
fn push_powershell(out: &mut String, value: &str) {
    out.push('\'');
    for c in value.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
}

/// The variable a token credential is exported as. Precedence matches projection resolution: the
/// env's declared address, then the credential's own `env_var`, then the name derived from the
/// credential. `get` and the shell both call this, so one credential lands in one place.
pub fn token_variable(
    env_decl: Option<&str>,
    credential_decl: Option<&str>,
    credential: &str,
) -> String {
    env_decl
        .or(credential_decl)
        .map_or_else(|| derive_env_var(credential), str::to_owned)
}

/// The variable an `env-var` credential is exported as when no level declares one: the credential's
/// name, upper-cased with `.`, `-`, and `_` folded to `_`, prefixed with `_` if that would otherwise
/// begin with a digit.
///
/// A function of the credential's name alone, so a credential's address does not move when the
/// selection around it changes. A single constant shared by every `env-var` credential would collide
/// for any two of them, and since a token source admits no second projection type there would be
/// nothing to re-point — the selection would be unrunnable rather than merely awkward.
///
/// Not injective: names admit `.`, `-`, and `_` where a variable admits only `_`, so `my-static` and
/// `my.static` fold together. That is a collision like any other — refused by the resolver,
/// and resolvable by declaring an address.
pub fn derive_env_var(credential: &str) -> String {
    let folded: String = credential
        .chars()
        .map(|c| match c {
            '.' | '-' | '_' => '_',
            other => other.to_ascii_uppercase(),
        })
        .collect();
    // A variable name may not begin with a digit, and a credential name may.
    if folded.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{folded}")
    } else {
        folded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::valid_env_var;
    use proptest::prelude::*;

    fn arb_port() -> impl Strategy<Value = u16> {
        1024..=65535u16
    }

    fn arb_env() -> impl Strategy<Value = String> {
        "[a-zA-Z][a-zA-Z0-9_-]{0,30}"
    }

    fn arb_token() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9+/=]{16,64}"
    }

    fn arb_region() -> impl Strategy<Value = String> {
        "(us|eu|ap)-(east|west|central|south|north|southeast|northeast)-[1-3]"
    }

    fn make_env(region: Option<String>) -> EnvConfig {
        EnvConfig {
            region,
            ..Default::default()
        }
    }

    /// A declared `env_var` names the token and beats the derived name; without one the name derives.
    #[test]
    fn token_variable_prefers_the_declared_name() {
        assert_eq!(token_variable(None, Some("MY_TOKEN"), "work"), "MY_TOKEN");
        assert_eq!(token_variable(None, None, "my-token"), "MY_TOKEN");
        assert_eq!(
            token_variable(Some("ENV_WINS"), Some("CRED"), "work"),
            "ENV_WINS"
        );
    }

    proptest! {
        /// Plain credential names always derive a name a shell can export: every character folds to
        /// `[A-Za-z0-9_]`. A name outside that set reaches `format_env_vars`, which refuses it.
        #[test]
        fn plain_credential_name_derives_a_valid_variable(name in "[A-Za-z0-9._-]{1,40}") {
            prop_assert!(valid_env_var(&derive_env_var(&name)));
        }

        #[test]
        fn leading_digit_gets_an_underscore_prefix(name in "[0-9][A-Za-z0-9._-]{0,20}") {
            prop_assert!(derive_env_var(&name).starts_with('_'));
        }

        /// Arbitrary input, including adversarial bytes, never leaves a separator in the output.
        #[test]
        fn derived_name_keeps_no_separator(name in ".*") {
            let var = derive_env_var(&name);
            prop_assert!(!var.contains('.') && !var.contains('-'));
        }

        /// `.` and `-` fold to `_`, which is why `my-static` and `my.static` collide by design.
        #[test]
        fn dot_and_dash_fold_like_underscore(name in "[a-z0-9._-]{1,40}") {
            let underscored = name.replace(['.', '-'], "_");
            prop_assert_eq!(derive_env_var(&name), derive_env_var(&underscored));
        }
    }

    proptest! {
        #[test]
        fn shell_output_has_export_on_every_line(
            port in arb_port(),
            env in arb_env(),
            token in arb_token(),
            region in proptest::option::of(arb_region()),
        ) {
            let pcfg = make_env(region.clone());
            let cred_env = CredentialEnv::new(port, &env, &token, Some(&pcfg));
            let output = cred_env.format("shell").unwrap();
            for line in output.lines() {
                prop_assert!(
                    line.starts_with("export "),
                    "shell line missing 'export' prefix: {:?}",
                    line
                );
            }
        }

        #[test]
        fn shell_output_contains_credentials_uri(
            port in arb_port(),
            env in arb_env(),
            token in arb_token(),
            region in proptest::option::of(arb_region()),
        ) {
            let pcfg = make_env(region.clone());
            let cred_env = CredentialEnv::new(port, &env, &token, Some(&pcfg));
            let output = cred_env.format("shell").unwrap();
            prop_assert!(output.contains("AWS_CONTAINER_CREDENTIALS_FULL_URI"));
            prop_assert!(output.contains("AWS_CONTAINER_AUTHORIZATION_TOKEN"));
            let expected_host = format!("127.0.0.1:{}", port);
            prop_assert!(output.contains(&expected_host));
            prop_assert!(output.contains(&env));
        }

        #[test]
        fn region_present_iff_configured(
            port in arb_port(),
            env in arb_env(),
            token in arb_token(),
            region in proptest::option::of(arb_region()),
        ) {
            let pcfg = make_env(region.clone());
            let cred_env = CredentialEnv::new(port, &env, &token, Some(&pcfg));
            let output = cred_env.format("shell").unwrap();
            if region.is_some() {
                prop_assert!(output.contains("AWS_REGION"));
                prop_assert!(output.contains("AWS_DEFAULT_REGION"));
            } else {
                prop_assert!(!output.contains("AWS_REGION"));
                prop_assert!(!output.contains("AWS_DEFAULT_REGION"));
            }
        }

        #[test]
        fn fish_output_uses_set_x(
            port in arb_port(),
            env in arb_env(),
            token in arb_token(),
            region in proptest::option::of(arb_region()),
        ) {
            let pcfg = make_env(region.clone());
            let cred_env = CredentialEnv::new(port, &env, &token, Some(&pcfg));
            let output = cred_env.format("fish").unwrap();
            for line in output.lines() {
                prop_assert!(
                    line.starts_with("set -x "),
                    "fish line missing 'set -x' prefix: {:?}",
                    line
                );
            }
        }

        #[test]
        fn powershell_output_uses_env_prefix(
            port in arb_port(),
            env in arb_env(),
            token in arb_token(),
            region in proptest::option::of(arb_region()),
        ) {
            let pcfg = make_env(region.clone());
            let cred_env = CredentialEnv::new(port, &env, &token, Some(&pcfg));
            let output = cred_env.format("powershell").unwrap();
            for line in output.lines() {
                prop_assert!(
                    line.starts_with("$env:"),
                    "powershell line missing '$env:' prefix: {:?}",
                    line
                );
            }
        }

        #[test]
        fn json_output_is_valid_json(
            port in arb_port(),
            env in arb_env(),
            token in arb_token(),
            region in proptest::option::of(arb_region()),
        ) {
            let pcfg = make_env(region.clone());
            let cred_env = CredentialEnv::new(port, &env, &token, Some(&pcfg));
            let output = cred_env.format("json").unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
            let obj = parsed.as_object().unwrap();
            prop_assert!(obj.contains_key("AWS_CONTAINER_CREDENTIALS_FULL_URI"));
            prop_assert!(obj.contains_key("AWS_CONTAINER_AUTHORIZATION_TOKEN"));
            if region.is_some() {
                prop_assert!(obj.contains_key("AWS_REGION"));
                prop_assert!(obj.contains_key("AWS_DEFAULT_REGION"));
                prop_assert_eq!(obj.len(), 4);
            } else {
                prop_assert_eq!(obj.len(), 2);
            }
        }

        #[test]
        fn json_key_count_matches_line_count_in_shell(
            port in arb_port(),
            env in arb_env(),
            token in arb_token(),
            region in proptest::option::of(arb_region()),
        ) {
            let pcfg = make_env(region.clone());
            let cred_env = CredentialEnv::new(port, &env, &token, Some(&pcfg));
            let shell_lines = cred_env.format("shell").unwrap().lines().count();
            let json_output = cred_env.format("json").unwrap();
            let json_keys: serde_json::Value = serde_json::from_str(&json_output).unwrap();
            let json_count = json_keys.as_object().unwrap().len();
            prop_assert_eq!(shell_lines, json_count);
        }

        #[test]
        fn unknown_format_returns_error(
            port in arb_port(),
            env in arb_env(),
            token in arb_token(),
            format in "[a-z]{1,10}".prop_filter("not a valid format",
                |s| !["shell", "fish", "powershell", "json"].contains(&s.as_str())),
        ) {
            let cred_env = CredentialEnv::new(port, &env, &token, None::<&EnvConfig>);
            prop_assert!(cred_env.format(&format).is_err());
        }
    }

    #[test]
    fn extra_env_injected_into_shell_output() {
        let cred_env = CredentialEnv {
            uri: "http://127.0.0.1:9765/container_credentials/demo".into(),
            auth_token: "Bearer tok123".into(),
            region: Some("us-east-1".into()),
            extra_env: vec![
                (
                    "AWS_ENDPOINT_URL",
                    "https://custom.endpoint.example.com".into(),
                ),
                ("AWS_USE_FIPS_ENDPOINT", "true".into()),
                ("AWS_USE_DUALSTACK_ENDPOINT", "false".into()),
                ("AWS_RETRY_MODE", "adaptive".into()),
                ("AWS_MAX_ATTEMPTS", "5".into()),
                ("AWS_DEFAULT_OUTPUT", "json".into()),
            ],
        };
        let output = cred_env.format("shell").unwrap();

        assert!(output.contains("export AWS_ENDPOINT_URL='https://custom.endpoint.example.com'"));
        assert!(output.contains("export AWS_USE_FIPS_ENDPOINT='true'"));
        assert!(output.contains("export AWS_USE_DUALSTACK_ENDPOINT='false'"));
        assert!(output.contains("export AWS_RETRY_MODE='adaptive'"));
        assert!(output.contains("export AWS_MAX_ATTEMPTS='5'"));
        assert!(output.contains("export AWS_DEFAULT_OUTPUT='json'"));
        assert!(!output.contains("AWS_PAGER"));
        assert!(!output.contains("AWS_CA_BUNDLE"));
    }

    #[test]
    fn extra_env_injected_into_json_output() {
        let cred_env = CredentialEnv {
            uri: "http://127.0.0.1:9765/container_credentials/demo".into(),
            auth_token: "Bearer tok123".into(),
            region: Some("us-west-2".into()),
            extra_env: vec![("AWS_CA_BUNDLE", "/etc/ssl/ca.pem".into())],
        };
        let output = cred_env.format("json").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let obj = parsed.as_object().unwrap();

        assert_eq!(obj.get("AWS_CA_BUNDLE").unwrap(), "/etc/ssl/ca.pem");
        assert!(!obj.contains_key("AWS_ENDPOINT_URL"));
        assert!(!obj.contains_key("AWS_RETRY_MODE"));
    }

    #[test]
    fn dry_run_placeholder_propagates_through_all_formats() {
        let cred_env = CredentialEnv {
            uri: "http://127.0.0.1:9999/container_credentials/default".into(),
            auth_token: "<redacted-dry-run>".into(),
            region: None,
            extra_env: vec![],
        };
        for fmt in ["shell", "fish", "powershell", "json"] {
            let out = cred_env.format(fmt).unwrap();
            assert!(
                out.contains("<redacted-dry-run>"),
                "format {fmt}: dry-run placeholder missing from output: {out}"
            );
        }
    }

    #[test]
    fn no_extra_env_means_no_extra_vars() {
        let cred_env = CredentialEnv {
            uri: "http://127.0.0.1:9765/container_credentials/demo".into(),
            auth_token: "Bearer tok123".into(),
            region: Some("us-east-1".into()),
            extra_env: vec![],
        };
        let output = cred_env.format("json").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let obj = parsed.as_object().unwrap();

        assert_eq!(obj.len(), 4);
        assert!(!obj.contains_key("AWS_ENDPOINT_URL"));
        assert!(!obj.contains_key("AWS_DEFAULT_OUTPUT"));
    }

    /// Reads one quoted word the way the shell would, returning the value and the unconsumed
    /// rest, or `None` if the word does not close. A value that "escaped" its quotes shows up as
    /// a non-empty rest.
    fn unquote_posix(s: &str) -> Option<(String, String)> {
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        loop {
            match chars.peek() {
                Some('\'') => {
                    chars.next();
                    loop {
                        match chars.next()? {
                            '\'' => break,
                            c => out.push(c),
                        }
                    }
                }
                Some('\\') => {
                    chars.next();
                    match chars.next()? {
                        '\'' => out.push('\''),
                        _ => return None,
                    }
                }
                _ => return Some((out, chars.collect())),
            }
        }
    }

    fn unquote_fish(s: &str) -> Option<(String, String)> {
        let mut chars = s.chars();
        if chars.next()? != '\'' {
            return None;
        }
        let mut out = String::new();
        loop {
            match chars.next()? {
                '\'' => return Some((out, chars.collect())),
                '\\' => match chars.next()? {
                    e @ ('\\' | '\'') => out.push(e),
                    e => {
                        out.push('\\');
                        out.push(e);
                    }
                },
                c => out.push(c),
            }
        }
    }

    fn is_ps_quote(c: char) -> bool {
        matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}')
    }

    fn unquote_powershell(s: &str) -> Option<(String, String)> {
        let mut chars = s.chars().peekable();
        if !is_ps_quote(chars.next()?) {
            return None;
        }
        let mut out = String::new();
        loop {
            let c = chars.next()?;
            if !is_ps_quote(c) {
                out.push(c);
                continue;
            }
            match chars.peek() {
                Some(&n) if is_ps_quote(n) => {
                    out.push(n);
                    chars.next();
                }
                _ => return Some((out, chars.collect())),
            }
        }
    }

    proptest! {
        #[test]
        fn posix_quoting_round_trips_any_value(v in any::<String>()) {
            let quoted = quote_posix(&v);
            prop_assert_eq!(unquote_posix(&quoted), Some((v.clone(), String::new())));
        }

        #[test]
        fn fish_quoting_round_trips_any_value(v in any::<String>()) {
            let quoted = quote_fish(&v);
            prop_assert_eq!(unquote_fish(&quoted), Some((v.clone(), String::new())));
        }

        #[test]
        fn powershell_quoting_round_trips_any_value(v in any::<String>()) {
            let quoted = quote_powershell(&v);
            prop_assert_eq!(unquote_powershell(&quoted), Some((v.clone(), String::new())));
        }
    }

    const HOSTILE: &[&str] = &[
        "plain",
        "",
        "it's",
        "\"; touch /tmp/pwned; echo \"",
        "$(id)",
        "`id`",
        "${HOME}",
        "a\\",
        "a\\'b",
        "line1\nexport INJECTED=1",
        "trailing'",
        "\u{2019}; Remove-Item x; \u{2019}",
    ];

    /// The decoders above model the shells; this checks the POSIX model against a real one, so a
    /// quoting rule the model gets wrong cannot pass by agreeing with itself.
    #[cfg(unix)]
    #[test]
    fn posix_output_evaluates_to_the_value_in_a_real_shell() {
        for v in HOSTILE {
            let script = format!(
                "{}\nprintf %s \"$V\"",
                format_env_vars(&[("V", *v)], "shell").unwrap()
            );
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(&script)
                .env_remove("INJECTED")
                .output()
                .expect("run sh");
            assert!(
                out.status.success(),
                "{v:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(String::from_utf8(out.stdout).unwrap(), *v, "{v:?}");
        }
    }

    #[test]
    fn every_format_renders_one_line_per_hostile_value_without_breaking_quotes() {
        for v in HOSTILE {
            let vars = [("V".to_owned(), (*v).to_owned())];
            for (fmt, prefix, unquote) in [
                (
                    "shell",
                    "export V=",
                    unquote_posix as fn(&str) -> Option<(String, String)>,
                ),
                ("fish", "set -x V ", unquote_fish),
                ("powershell", "$env:V=", unquote_powershell),
            ] {
                let out = format_env_vars(&vars, fmt).unwrap();
                let word = out.strip_prefix(prefix).expect(fmt);
                assert_eq!(
                    unquote(word),
                    Some(((*v).to_owned(), String::new())),
                    "{fmt}: {v:?}"
                );
            }
        }
    }

    #[test]
    fn a_variable_name_that_is_not_an_identifier_is_refused() {
        for name in ["X=1;id;Y", "1X", "", "A B", "A$B", "A\nB"] {
            let vars = [(name.to_owned(), "v".to_owned())];
            for fmt in ["shell", "fish", "powershell", "json"] {
                assert!(format_env_vars(&vars, fmt).is_err(), "{fmt}: {name:?}");
            }
        }
        assert!(format_env_vars(&[("_A1", "v")], "shell").is_ok());
    }
}
