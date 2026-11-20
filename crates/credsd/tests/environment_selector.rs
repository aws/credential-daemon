use std::process::Command;

#[test]
fn environment_flags_fail_before_cli_parsing_without_echoing_the_value() {
    const MESSAGE: &str = "error: --environment is not supported; name a credential with --credential <NAME> (or --name <NAME>)\n";
    for flag in [
        "--environment",
        "--env",
        "--environment=secret-value",
        "--env=secret-value",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_creds"))
            .args(["unknown-command", flag])
            .output()
            .expect("run creds");
        assert_eq!(output.status.code(), Some(2), "{flag}");
        assert!(output.stdout.is_empty(), "{flag}");
        assert_eq!(String::from_utf8(output.stderr).unwrap(), MESSAGE, "{flag}");
    }
}
