#![allow(
    clippy::print_stdout,
    reason = "CLI binary — stdout is the output channel"
)]
use clap::{Parser, Subcommand, ValueEnum};
use credsd_core::log::escape_terminal;
use credsd_core::wire::ClaimedIdentity;
use std::path::PathBuf;
use std::process::ExitCode;

// The ephemeral loopback-TCP proxy `credsd run` mints, and its bearer middleware, are the
// client's only axum-bound code. They live here rather than in `credsd-core` so the shared
// crate stays axum-free.
#[cfg(test)]
mod command_reference;
#[cfg(unix)]
mod presence;

// Re-export the core modules the local `proxy` / `middleware` modules address as `crate::…`,
// so they need not spell out `credsd_core::` at every use site.
pub use credsd_core::{auth, credential_resolve, credentials, error};

/// Map the `--agentic` flag to a claim. Presence is the whole signal: there is
/// deliberately no way to assert *non*-agent status, which would be an evasion
/// primitive rather than a control.
fn claimed_identity(agentic: bool) -> ClaimedIdentity {
    if agentic {
        ClaimedIdentity::Agentic
    } else {
        ClaimedIdentity::Unstated
    }
}

#[derive(Parser)]
#[command(name = "creds", version, about = "AWS Credential Daemon")]
struct Cli {
    /// Config directory override (equivalent to CREDSD_CONFIG_DIR)
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,

    /// Suppress info/warn output (level=error)
    #[arg(short = 'q', long, global = true)]
    quiet: bool,

    /// Enable debug output (level=debug)
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    /// Write logs to file (append mode)
    #[arg(long, global = true)]
    log_file: Option<PathBuf>,

    /// Log format: text, json
    #[arg(long, global = true)]
    log_format: Option<String>,

    /// Socket path override (equivalent to CREDSD_SOCKET)
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "parsed once at startup; boxing the bootstrap arguments buys nothing"
)]
enum Commands {
    /// Bootstrap a credential (provider config + initial auth), optionally wrapping it in an env.
    ///
    /// The flag picks the mode:
    ///   `--credential X`            → credential X only (an atom, to compose into envs later).
    ///   `--env Y`                   → credential Y + a same-named single-credential env Y (1:1).
    ///   `--env Y --credential X`    → credential X + env Y referencing it.
    /// At least one of `--env`/`--credential` is required. If the credential already exists and
    /// no provider is given, re-authenticates using saved config.
    Bootstrap {
        /// Env to create wrapping the credential. Alone, also names the credential.
        #[arg(long = "environment", alias = "env")]
        env: Option<String>,
        /// Credential to create/configure. Alone, no env is created; with `--env`, names the
        /// credential something other than the env.
        #[arg(long)]
        credential: Option<String>,

        #[command(subcommand)]
        provider: Option<BootstrapProvider>,
    },
    /// Re-authenticate credentials whose unattended renewal is spent (SSO session expired, MFA
    /// session lapsed). Runs the interactive flow each source requires and persists the result
    /// so the daemon can serve again. `--env` loops over every credential in the env;
    /// `--credential` re-auths a single one.
    Login {
        /// Env whose credentials to re-authenticate (loops over all of them).
        #[arg(
            long = "environment",
            alias = "env",
            required_unless_present = "credential"
        )]
        env: Option<String>,
        /// A single credential to re-authenticate.
        #[arg(long, required_unless_present = "env")]
        credential: Option<String>,
    },
    /// Fetch credentials from the daemon (for credential_process / shell eval).
    ///
    /// `--env <env> --credential <cred>` resolves that credential under the env's authority —
    /// what a generated `credential_process` line calls. `--env <name>` alone resolves the
    /// env's default (first) credential; bare `--credential <name>` resolves only when the
    /// name is also a configured env (the shipped 1:1 shape).
    Get {
        /// Env whose default credential to fetch, or the authorization context for --credential.
        #[arg(
            long = "environment",
            alias = "env",
            required_unless_present = "credential"
        )]
        env: Option<String>,
        /// A single credential to fetch, resolved under --env's authority when given.
        #[arg(long, required_unless_present = "env")]
        credential: Option<String>,
        /// Output format: credential-process, shell, fish, powershell (default: raw JSON)
        #[arg(long)]
        format: Option<String>,
        /// Declare this caller as agentic, adding agent treatment in the daemon's audit
        /// trail. The claim can only ever add restriction, never remove it, and
        /// the daemon walks the process tree regardless of whether it is passed.
        #[arg(long)]
        agentic: bool,
    },
    /// List configured credentials and their status
    List {
        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Remove an env, or a credential and its encrypted data.
    Remove {
        /// Env to remove (leaves its credentials intact).
        #[arg(
            long = "environment",
            alias = "env",
            required_unless_present = "credential"
        )]
        env: Option<String>,
        /// Credential to remove, along with its encrypted data.
        #[arg(long)]
        credential: Option<String>,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Re-seal hand-edited config files after reviewing their contents. Takes no selector: a
    /// snapshot covers its whole file, so every drifted file is shown and resealed together.
    Revalidate,
    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Import existing credentials from an external store (non-destructive migration).
    Import {
        #[command(subcommand)]
        source: ImportSourceCmd,
    },
    /// Manage pending presence-gate requests.
    Request {
        #[command(subcommand)]
        action: RequestAction,
    },
    /// Deprecated: use `creds request` instead.
    #[command(hide = true)]
    Approve {
        #[arg(required_unless_present = "list")]
        id: Option<String>,
        #[arg(long, conflicts_with = "withdraw")]
        list: bool,
        #[arg(long)]
        withdraw: bool,
    },
    /// Manage the presence key that approves gated operations with Touch ID
    Presence {
        #[command(subcommand)]
        action: PresenceAction,
    },
}

#[derive(Debug, Subcommand)]
enum PresenceAction {
    /// Create a presence key in the Secure Enclave and request its enrollment
    Enroll {
        /// biometry: Touch ID only, invalidated if fingerprints change; presence: Touch ID or passcode
        #[arg(long, default_value = "biometry")]
        policy: String,
    },
    /// Revoke this uid's presence key
    Revoke,
    /// Show this uid's presence key
    Status,
}

#[derive(Debug, Subcommand)]
enum RequestAction {
    /// List pending requests (yours; every uid's under sudo)
    List,
    /// Approve a pending request with Touch ID (as its owner) or as root under sudo
    Approve {
        /// Pending request id (req-…)
        id: String,
    },
    /// Withdraw a pending request (owner only; nothing is changed)
    Withdraw {
        /// Pending request id (req-…)
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ImportSourceCmd {
    /// Import static-key profiles from the AWS shared-credentials file. Each importable profile
    /// (one carrying an `aws_access_key_id`/`aws_secret_access_key` pair) becomes an `iam-user`
    /// credential wrapped in a same-named env; SSO and `credential_process` profiles are skipped.
    /// The source file is read only, never modified.
    AwsProfiles {
        /// Credentials file to read (default: $AWS_SHARED_CREDENTIALS_FILE, then ~/.aws/credentials).
        #[arg(long)]
        from: Option<PathBuf>,
        /// Region for imported profiles that name none. Without it, such a profile is skipped.
        #[arg(long)]
        region: Option<String>,
        /// List what would be imported without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Print the config file path
    Path,
    /// Set an env configuration value
    Set {
        /// Config key (e.g., region, sdk.retry_mode, cli.output)
        key: String,
        /// Value to set
        value: String,
        /// Env to modify (required; never inferred from $AWS_PROFILE)
        #[arg(long = "environment", alias = "env", required = true)]
        env: String,
    },
    /// Get an env configuration value
    Get {
        /// Config key to read
        key: String,
        /// Env to read from (required; never inferred from $AWS_PROFILE)
        #[arg(long = "environment", alias = "env", required = true)]
        env: String,
    },
    /// Remove an env configuration value (revert to default)
    Unset {
        /// Config key to remove
        key: String,
        /// Env to modify (required; never inferred from $AWS_PROFILE)
        #[arg(long = "environment", alias = "env", required = true)]
        env: String,
    },
    /// List available configuration keys
    Keys {
        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        format: String,
    },
}

#[derive(Debug, Subcommand)]
enum BootstrapProvider {
    /// Bootstrap with AWS SSO (IAM Identity Center)
    AwsIdcSso {
        #[arg(long)]
        start_url: String,
        /// Region of the IAM Identity Center instance. Required; there is no default.
        #[arg(long)]
        sso_region: String,
        #[arg(long)]
        account_id: Option<String>,
        #[arg(long)]
        role_name: Option<String>,
        #[arg(long, value_enum)]
        identity_type: Option<CliIdentityType>,
    },
    /// Bootstrap with a long-term IAM key brokered via sts:GetSessionToken.
    ///
    /// The secret access key is read with echo disabled (never argv — arguments leak through `ps`
    /// and shell history); a piped secret manager still works.
    AwsIamUser {
        #[arg(long)]
        access_key_id: String,
        /// Region whose regional STS endpoint brokers the session (GetSessionToken is called there).
        /// Required; there is no default.
        #[arg(long)]
        region: String,
        #[arg(long)]
        duration_seconds: Option<i32>,
        /// MFA device ARN. When set, sessions require an MFA code, so the key can't be
        /// brokered unattended — authenticate with `credsd login --env <env>`.
        #[arg(long)]
        mfa_serial: Option<String>,
        #[arg(long, value_enum)]
        identity_type: Option<CliIdentityType>,
    },
    /// Bootstrap with IAM Roles Anywhere: ingest an X.509 cert + private key and store the key
    /// encrypted, then exchange it for credentials via rolesanywhere:CreateSession.
    ///
    /// The private key PEM is read from `--private-key` at bootstrap and sealed to `ra_key.enc`;
    /// the daemon never keeps the plaintext key or the file path.
    AwsRolesAnywhere {
        #[arg(long)]
        trust_anchor_arn: String,
        #[arg(long)]
        profile_arn: String,
        #[arg(long)]
        role_arn: String,
        /// Path to the PEM leaf certificate (read once, stored as public DER).
        #[arg(long)]
        certificate: String,
        /// Path to the PEM private key (read once, sealed encrypted; never persisted as a path).
        #[arg(long)]
        private_key: String,
        /// Optional path to an intermediate-certificate chain PEM.
        #[arg(long)]
        cert_chain: Option<String>,
        /// Region override; when omitted, derived from the trust anchor ARN.
        #[arg(long)]
        region: Option<String>,
        #[arg(long)]
        duration_seconds: Option<i32>,
        #[arg(long)]
        role_session_name: Option<String>,
        /// Override the CreateSession endpoint (required for cn/gov partitions).
        #[arg(long)]
        endpoint_url: Option<String>,
        #[arg(long, value_enum)]
        identity_type: Option<CliIdentityType>,
    },
    /// Bootstrap with an OAuth2 login (authorization-code + PKCE) federated to
    /// AWS via `sts:AssumeRoleWithWebIdentity`. Opens a browser.
    ///
    /// The daemon runs the flow: it binds the loopback redirect listener, exchanges the code, and
    /// seals the tokens. This client only opens the URL the daemon reports and never sees a token.
    #[command(name = "aws-web-identity")]
    AwsWebIdentity {
        /// OAuth authorization endpoint.
        #[arg(long)]
        authorization_endpoint: String,
        /// OAuth token endpoint.
        #[arg(long)]
        token_endpoint: String,
        /// OAuth client id.
        #[arg(long)]
        client_id: String,
        /// Target role for AssumeRoleWithWebIdentity.
        #[arg(long)]
        role_arn: String,
        /// OAuth scope (repeatable). Defaults to `openid`, which is what makes the IdP return
        /// the id_token STS validates; without it an AS may return only an opaque access token,
        /// which STS rejects.
        #[arg(long = "scope", default_value = "openid")]
        scope: Vec<String>,
        /// STS region. Required; there is no default.
        #[arg(long)]
        region: String,
        #[arg(long)]
        duration_seconds: Option<i32>,
        #[arg(long)]
        role_session_name: Option<String>,
        #[arg(long, value_enum)]
        identity_type: Option<CliIdentityType>,
        /// Fixed loopback port for the OAuth callback (pre-register with IdP).
        /// Must be in the unprivileged range; port 0 is rejected because it binds
        /// ephemerally and the resulting URI will not match any pre-registered redirect URI.
        #[arg(long, value_parser = clap::value_parser!(u16).range(
            credsd_core::providers::oauth::callback::CALLBACK_PORT_MIN as i64
            ..=credsd_core::providers::oauth::callback::CALLBACK_PORT_MAX as i64
        ))]
        callback_port: Option<u16>,
    },
    /// Log in with AWS Sign-In (`aws login`). Prints a URL to open in a browser; the credential is
    /// AWS session credentials, with no role to assume. Uses the AWS CLI's client id, so Sign-In
    /// may refuse it.
    ///
    /// By default the browser must be on this machine, because Sign-In redirects to a loopback
    /// port the daemon is listening on. Pass `--remote` when it is not — on a host reached over
    /// SSH, say — and Sign-In will instead show you a code to paste back here.
    #[command(name = "aws-login")]
    AwsLogin {
        /// Sign-In region. Selects the Sign-In endpoint the login runs against.
        #[arg(long)]
        region: String,
        #[arg(long, value_enum)]
        identity_type: Option<CliIdentityType>,
        /// Fixed loopback port for the callback. Must be in the unprivileged range.
        #[arg(long, value_parser = clap::value_parser!(u16).range(
            credsd_core::providers::oauth::callback::CALLBACK_PORT_MIN as i64
            ..=credsd_core::providers::oauth::callback::CALLBACK_PORT_MAX as i64
        ), conflicts_with = "remote")]
        callback_port: Option<u16>,
        /// The browser is on another machine: bind no loopback listener, and prompt for the code
        /// Sign-In displays once you have authorized there. Recorded, so `creds login` reuses it.
        #[arg(long)]
        remote: bool,
    },
    /// Bootstrap with a bearer JWT read from disk (a CI-issued OIDC token, a k8s projected
    /// service-account token, an IdP token minted out of band). The credential IS the JWT — no
    /// exchange, no federation.
    ///
    /// The token is read from `--token-file` once at bootstrap and sealed to `jwt.enc`; the path is
    /// recorded so a re-seal can name it again. There is no interactive login for this source —
    /// re-run this command with a fresh token file to replace an expired token. `--env-var` names
    /// the variable a child receives it as; the default is the credential name, upper-cased.
    Jwt {
        /// Path holding the JWT. Read once, sealed, never re-read by the daemon.
        #[arg(long)]
        token_file: String,
        /// Variable exported to a child process. Defaults to the credential name, upper-cased.
        #[arg(long)]
        env_var: Option<String>,
        #[arg(long, value_enum)]
        identity_type: Option<CliIdentityType>,
    },
    /// Bootstrap an OAuth 2.0 client-credentials (2LO) credential. The secret is stored
    /// in credentials.toml; use sealed storage (keychain/TPM) for automation environments.
    Oauth {
        #[arg(long)]
        token_url: String,
        #[arg(long)]
        client_id: String,
        /// Prompt for client secret (client_secret_basic). Mutually exclusive with --private-key.
        /// The secret is read from the terminal, never passed as an argument.
        #[arg(long, conflicts_with = "private_key")]
        client_secret: bool,
        /// Path to a PEM-encoded ES256 private key (private_key_jwt). Mutually exclusive with --client-secret.
        #[arg(long, conflicts_with = "client_secret")]
        private_key: Option<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long, value_enum, default_value = "automation")]
        identity_type: CliIdentityType,
    },
    /// Bootstrap with a secret you already hold — an API key, a personal access token, any
    /// pre-issued secret string. The credential IS the secret: nothing is exchanged and nothing
    /// is federated.
    ///
    /// The secret is read from `--secret-file` or from stdin, never from an argument, because an
    /// argument leaks through `ps` and shell history. On a terminal you are prompted with echo
    /// disabled; piping from a secret manager works unchanged.
    ///
    /// credsd cannot tell when a pre-issued secret dies, so `--expires-at` is how you say. Left
    /// off, the credential never expires and reads `active` indefinitely. Re-run this command
    /// with a new value to rotate — there is no interactive login, because there is no issuer.
    StaticSecret {
        /// Path holding the secret, or `-` for stdin. Omit to read stdin. Read once, sealed,
        /// never re-read by the daemon and never stored as a path.
        #[arg(long)]
        secret_file: Option<String>,
        /// Variable exported to a child process. Defaults to the credential name, upper-cased.
        #[arg(long)]
        env_var: Option<String>,
        /// Absolute expiry (RFC 3339), for a secret you know rotates on a date. Omit for a
        /// secret with no known end.
        #[arg(long)]
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        #[arg(long, value_enum)]
        identity_type: Option<CliIdentityType>,
    },
    /// Bootstrap a JWT-bearer credential.
    ///
    /// The CLI reads the assertion and passes its contents to the daemon; the daemon
    /// never sees the path. Use `-` to read from stdin.
    ///
    /// Experimental: subject to change without the compatibility guarantees given to
    /// default-on features.
    #[cfg(feature = "jwt-bearer")]
    JwtBearer {
        #[arg(long)]
        token_url: String,
        /// Path to a file containing the JWT assertion, or `-` to read from stdin.
        /// The CLI reads it and passes the contents; the daemon never sees the path.
        #[arg(long)]
        assertion_file: String,
        #[arg(long)]
        client_id: Option<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long, value_enum, default_value = "automation")]
        identity_type: CliIdentityType,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum CliIdentityType {
    Human,
    Automation,
    Agent,
}

impl From<CliIdentityType> for credsd_core::config::IdentityType {
    fn from(v: CliIdentityType) -> Self {
        match v {
            CliIdentityType::Human => Self::Human,
            CliIdentityType::Automation => Self::Automation,
            CliIdentityType::Agent => Self::Agent,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Some(ref dir) = cli.config_dir {
        std::env::set_var("CREDSD_CONFIG_DIR", dir);
    }

    if let Some(ref sock) = cli.socket {
        std::env::set_var("CREDSD_SOCKET", sock);
    }

    if cli.quiet && cli.verbose {
        eprintln!("error: --quiet and --verbose are mutually exclusive");
        return ExitCode::FAILURE;
    }

    // `config: None` — the client is not a reader of `callers/<uid>/config.toml`; the daemon owns
    // that tree, under a system install at a mode the client cannot open. The read this replaces
    // resolved to `None` on failure anyway, so the settings never applied, they just failed
    // silently. `init_logging` resolves the same `CREDSD_LOG_*` / `RUST_LOG` fallbacks for every
    // caller, so what the file used to carry is still settable — persistently, via the
    // environment rather than a file only the daemon can read.
    credsd_core::log::init_logging(
        cli.quiet,
        cli.verbose,
        cli.log_file.as_deref(),
        cli.log_format.as_deref(),
        None,
    );

    // Most commands succeed or fail, and nothing else; `succeeded` lifts those into the exit code
    // dispatch returns. Only the shell verbs, `config get` have a code of their own to report — a
    // child's exit status, or "the key is unset" — and they are the arms that return one directly.
    let succeeded = |r: credsd_core::error::Result<()>| r.map(|()| ExitCode::SUCCESS);

    let result = match cli.command {
        Commands::Login { env, credential } => succeeded(cmd_login(env, credential).await),
        Commands::Bootstrap {
            env,
            credential,
            provider,
        } => succeeded(cmd_bootstrap(env, credential, provider).await),
        Commands::Get {
            env,
            credential,
            format,
            agentic,
        } => succeeded(cmd_get(env, credential, format, claimed_identity(agentic)).await),
        Commands::Config { action } => match action {
            ConfigAction::Path => {
                print!(
                    "{}",
                    credsd_core::config::platform::caller_config_path_for_current_user().display()
                );
                Ok(ExitCode::SUCCESS)
            }
            ConfigAction::Set { key, value, env } => {
                succeeded(cmd_config_set(env, &key, &value).await)
            }
            ConfigAction::Get { key, env } => cmd_config_get(env, &key).await,
            ConfigAction::Unset { key, env } => succeeded(cmd_config_unset(env, &key).await),
            ConfigAction::Keys { format } => succeeded(cmd_config_keys(&format)),
        },
        Commands::List { format } => succeeded(cmd_list(&format).await),
        Commands::Import { source } => succeeded(cmd_import(source).await),
        #[cfg(unix)]
        Commands::Request { action } => succeeded(match action {
            RequestAction::List => presence::list().await,
            RequestAction::Approve { id } => presence::approve(&id).await,
            RequestAction::Withdraw { id } => presence::withdraw(&id).await,
        }),
        #[cfg(unix)]
        Commands::Approve { id, list, withdraw } => succeeded(match id {
            Some(id) if withdraw => presence::withdraw(&id).await,
            Some(id) if !list => presence::approve(&id).await,
            _ => presence::list().await,
        }),
        #[cfg(unix)]
        Commands::Presence { action } => succeeded(match action {
            PresenceAction::Enroll { policy } => presence::enroll(&policy).await,
            PresenceAction::Revoke => presence::revoke().await,
            PresenceAction::Status => presence::status().await,
        }),
        #[cfg(not(unix))]
        Commands::Request { .. } | Commands::Approve { .. } | Commands::Presence { .. } => Err(
            credsd_core::error::DaemonError::config("not supported on this platform"),
        ),
        Commands::Remove {
            env,
            credential,
            force,
        } => succeeded(cmd_remove(env, credential, force).await),
        Commands::Revalidate => succeeded(cmd_revalidate().await),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {}", escape_terminal(&e));
            ExitCode::FAILURE
        }
    }
}

/// `credsd import` — parse the AWS shared-credentials file client-side, then seal the discovered
/// profiles through the daemon's `profile/import` RPC. The client never opens the keystore.
#[cfg(unix)]
async fn cmd_import(source: ImportSourceCmd) -> credsd_core::error::Result<()> {
    use credsd_core::config::platform;
    use credsd_core::import::{discover_import_profiles, ImportSource, RegionInputs};
    use credsd_core::rpc::{uds, ImportParams, ImportResult, ImportStatus, METHOD_PROFILE_IMPORT};

    let (import_source, dry_run) = match source {
        ImportSourceCmd::AwsProfiles {
            from,
            region,
            dry_run,
        } => (
            ImportSource::AwsProfiles {
                path: from,
                region: RegionInputs::from_environment(region),
            },
            dry_run,
        ),
    };

    // Discovery and INI parsing stay client-side: the file lives under the caller's $HOME, which
    // the scoped daemon user cannot read.
    let profiles = discover_import_profiles(&import_source)?;
    if profiles.is_empty() {
        eprintln!("No importable credentials found.");
        return Ok(());
    }

    let socket = platform::client_socket_path();
    let params = ImportParams { profiles, dry_run };
    // An import that would bind into existing environments is gated. Approving grants one re-send
    // of this exact batch, so a Touch ID approval here retries at once.
    let result: ImportResult = match uds::call(&socket, METHOD_PROFILE_IMPORT, &params, None).await
    {
        Err(credsd_core::error::DaemonError::ApprovalRequired(challenge)) => {
            if !presence::satisfy(&challenge).await? {
                return Err(credsd_core::error::DaemonError::config(format!(
                    "not imported: approve request {}, then re-run this import",
                    challenge.id
                )));
            }
            uds::call(&socket, METHOD_PROFILE_IMPORT, &params, None).await?
        }
        other => other?,
    };

    let mut imported = 0usize;
    for outcome in &result.outcomes {
        match outcome.status {
            ImportStatus::Imported => {
                eprintln!("imported '{}'", outcome.name);
                imported = imported.saturating_add(1);
            }
            ImportStatus::WouldImport => eprintln!("would import '{}'", outcome.name),
            ImportStatus::Skipped | ImportStatus::WouldSkip => eprintln!(
                "skip '{}': {}",
                outcome.name,
                outcome.reason.as_deref().unwrap_or("skipped")
            ),
        }
    }
    if !dry_run {
        eprintln!("\nImported {} credential(s).", imported);
    }
    Ok(())
}

#[cfg(not(unix))]
async fn cmd_import(_source: ImportSourceCmd) -> credsd_core::error::Result<()> {
    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform",
    ))
}

/// `credsd bootstrap` — thin relay to `profile/bootstrap` on the daemon.
///
/// Sends the provider params (reading any secrets from the terminal, never argv) and drives the
/// streaming notifications interactively: `device_code` opens the browser and shows the code,
/// `select_account`/`select_role` prompt stdin and send a respond notification, `polling` is
/// silent. When no provider is given, re-authenticates via `profile/login` (same daemon RPC).
#[cfg(unix)]
async fn cmd_bootstrap(
    env: Option<String>,
    credential: Option<String>,
    provider: Option<BootstrapProvider>,
) -> credsd_core::error::Result<()> {
    use credsd_client::{ProfileBootstrapParams, ProfileLoginParams};
    use credsd_core::config::platform;
    use credsd_core::error::DaemonError;

    let (credential, environment, write_env) = match (credential, env) {
        (Some(c), Some(e)) => (c, e, true),
        (Some(c), None) => (c.clone(), c, false),
        (None, Some(e)) => (e.clone(), e, true),
        (None, None) => {
            return Err(DaemonError::config(
                "specify --env and a provider, e.g.: creds bootstrap --env <name> <provider>",
            ))
        }
    };

    // No `ensure_config_dir()`: the daemon creates and owns `callers/<uid>/`, and a client that
    // pre-created it would either fail on the daemon-owned parent or leave a directory with the
    // wrong owner for the daemon to then refuse (Req 15).
    let socket = platform::client_socket_path();

    match provider {
        None => {
            // Re-auth: send profile/login.
            let params = ProfileLoginParams {
                environment: environment.clone(),
                credential: if credential != environment {
                    Some(credential)
                } else {
                    None
                },
                request_id: None,
            };
            send_login_rpc(&socket, &params).await
        }
        Some(p) => {
            let _ = write_env; // write_env is implicit in the daemon model
            let provider_params = build_provider_params(p)?;
            let params = ProfileBootstrapParams {
                environment,
                credential: if credential.is_empty() {
                    None
                } else {
                    Some(credential)
                },
                provider: provider_params,
                request_id: None,
            };
            send_bootstrap_rpc(&socket, &params).await
        }
    }
}

#[cfg(not(unix))]
async fn cmd_bootstrap(
    _env: Option<String>,
    _credential: Option<String>,
    _provider: Option<BootstrapProvider>,
) -> credsd_core::error::Result<()> {
    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform",
    ))
}

/// `credsd login` — thin relay to `profile/login` on the daemon.
#[cfg(unix)]
async fn cmd_login(
    env: Option<String>,
    credential: Option<String>,
) -> credsd_core::error::Result<()> {
    use credsd_client::ProfileLoginParams;
    use credsd_core::config::platform;
    use credsd_core::error::DaemonError;

    let environment = match (&env, &credential) {
        (Some(e), _) => e.clone(),
        (None, Some(c)) => c.clone(),
        (None, None) => return Err(DaemonError::config("specify --env or --credential")),
    };

    let socket = platform::client_socket_path();

    let params = ProfileLoginParams {
        environment,
        credential: credential.clone(),
        request_id: None,
    };
    send_login_rpc(&socket, &params).await
}

#[cfg(not(unix))]
async fn cmd_login(
    _env: Option<String>,
    _credential: Option<String>,
) -> credsd_core::error::Result<()> {
    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform",
    ))
}

/// Build `ProviderParams` from the parsed CLI provider subcommand.
/// Reads secrets from the terminal where needed (IAM user key, RA private key).
#[cfg(unix)]
fn build_provider_params(
    provider: BootstrapProvider,
) -> credsd_core::error::Result<credsd_client::ProviderParams> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use credsd_client::{
        ProviderParams, ProviderParamsIamUser, ProviderParamsRa, ProviderParamsSso,
    };
    use credsd_core::bootstrap::read_secret;
    use credsd_core::error::DaemonError;

    match provider {
        BootstrapProvider::AwsIdcSso {
            start_url,
            sso_region,
            account_id,
            role_name,
            identity_type,
        } => Ok(ProviderParams::AwsIdcSso(ProviderParamsSso {
            start_url,
            sso_region,
            account_id,
            role_name,
            identity_type: identity_type_str(identity_type),
        })),

        BootstrapProvider::AwsIamUser {
            access_key_id,
            region,
            duration_seconds,
            mfa_serial,
            identity_type,
        } => {
            let secret_access_key = read_secret("Secret access key: ")?;
            if secret_access_key.is_empty() {
                return Err(DaemonError::config("secret access key must not be empty"));
            }
            Ok(ProviderParams::AwsIamUser(ProviderParamsIamUser {
                access_key_id,
                secret_access_key,
                region,
                duration_seconds,
                mfa_serial,
                identity_type: identity_type_str(identity_type),
            }))
        }

        BootstrapProvider::AwsRolesAnywhere {
            trust_anchor_arn,
            profile_arn,
            role_arn,
            certificate,
            private_key,
            cert_chain,
            region,
            duration_seconds,
            role_session_name,
            endpoint_url,
            identity_type,
        } => {
            let (key_der, key_tag) = rolesanywhere_core::key_reader::read_private_key_der(
                &private_key,
            )
            .map_err(|e| DaemonError::config(format!("private key '{}': {e}", private_key)))?;
            let cert_der = rolesanywhere_core::key_reader::read_certificate_der(&certificate)
                .map_err(|e| DaemonError::config(format!("certificate '{}': {e}", certificate)))?;
            let chain_der =
                rolesanywhere_core::key_reader::read_certificate_chain_der(cert_chain.as_deref())
                    .map_err(|e| DaemonError::config(format!("certificate chain: {e}")))?;

            Ok(ProviderParams::AwsRolesAnywhere(ProviderParamsRa {
                trust_anchor_arn,
                profile_arn,
                role_arn,
                cert_der: BASE64.encode(&cert_der),
                key_der: BASE64.encode(key_der.as_slice()),
                key_tag,
                chain_der: chain_der.iter().map(|c| BASE64.encode(c)).collect(),
                region,
                duration_seconds,
                role_session_name,
                endpoint_url,
                identity_type: identity_type_str(identity_type),
            }))
        }
        BootstrapProvider::AwsWebIdentity {
            authorization_endpoint,
            token_endpoint,
            client_id,
            role_arn,
            scope,
            region,
            duration_seconds,
            role_session_name,
            identity_type,
            callback_port,
        } => Ok(ProviderParams::AwsWebIdentity(
            credsd_core::rpc::ProviderParamsAwsWebIdentity {
                authorization_endpoint,
                token_endpoint,
                client_id,
                scopes: scope,
                role_arn,
                region,
                duration_seconds,
                role_session_name,
                identity_type: identity_type_str(identity_type),
                callback_port,
            },
        )),
        BootstrapProvider::AwsLogin {
            region,
            identity_type,
            callback_port,
            remote,
        } => Ok(ProviderParams::AwsLogin(
            credsd_core::rpc::ProviderParamsAwsLogin {
                region,
                callback_port,
                remote,
                identity_type: identity_type_str(identity_type),
            },
        )),
        BootstrapProvider::Jwt {
            token_file,
            env_var,
            identity_type,
        } => {
            let jwt = std::fs::read_to_string(&token_file)
                .map_err(|e| DaemonError::config(format!("token file '{token_file}': {e}")))?
                .trim()
                .to_owned();
            Ok(ProviderParams::Jwt(credsd_core::rpc::ProviderParamsJwt {
                jwt,
                env_var,
                identity_type: identity_type_str(identity_type),
            }))
        }
        BootstrapProvider::StaticSecret {
            secret_file,
            env_var,
            expires_at,
            identity_type,
        } => {
            use credsd_core::bootstrap::{read_secret_text, SecretInput};
            use std::io::IsTerminal;
            // Absent or `-` both mean stdin. Translated here rather than inside the reader so a
            // file genuinely named `-` stays reachable as `./-`.
            let input = match secret_file.as_deref() {
                None | Some("-") => SecretInput::Stdin,
                Some(path) => SecretInput::File(path),
            };
            if matches!(input, SecretInput::Stdin) && std::io::stdin().is_terminal() {
                eprintln!("Paste the secret, then press Enter:");
            }
            let secret = read_secret_text(input, "Secret: ")?;
            if secret.is_empty() {
                // Refused here as well as daemon-side: the client can name which input was
                // empty, and a round trip that seals nothing is worth not making.
                return Err(DaemonError::config(
                    "the secret is empty; provide a value via --secret-file or stdin",
                ));
            }
            Ok(ProviderParams::StaticSecret(
                credsd_core::rpc::ProviderParamsStaticSecret {
                    secret: secret.to_string(),
                    env_var,
                    expires_at,
                    // Recorded for diagnostics so a re-seal can name where the secret came
                    // from. The daemon never reads it and never echoes it.
                    secret_source: Some(match secret_file.as_deref() {
                        None | Some("-") => "stdin".to_owned(),
                        Some(path) => path.to_owned(),
                    }),
                    identity_type: identity_type_str(identity_type),
                },
            ))
        }
        BootstrapProvider::Oauth {
            token_url,
            client_id,
            client_secret,
            private_key,
            scope,
            identity_type,
        } => {
            use credsd_core::bootstrap::read_secret;
            let client_secret = if client_secret {
                Some(read_secret("Client secret: ")?)
            } else {
                None
            };
            // Read private key PEM from file path if provided.
            let private_key_pem = private_key
                .as_deref()
                .map(|path| {
                    std::fs::read_to_string(path)
                        .map_err(|e| DaemonError::config(format!("--private-key '{path}': {e}")))
                })
                .transpose()?;
            Ok(ProviderParams::Oauth(
                credsd_core::rpc::ProviderParamsOauth {
                    token_url,
                    client_id,
                    client_secret,
                    private_key_pem,
                    scope,
                    identity_type: identity_type_str(Some(identity_type)),
                },
            ))
        }
        #[cfg(feature = "jwt-bearer")]
        BootstrapProvider::JwtBearer {
            token_url,
            assertion_file,
            client_id,
            scope,
            identity_type,
        } => {
            use credsd_core::bootstrap::{read_secret_text, SecretInput};
            let input = if assertion_file == "-" {
                SecretInput::Stdin
            } else {
                SecretInput::File(&assertion_file)
            };
            let assertion = read_secret_text(input, "Assertion: ")?.to_string();
            Ok(ProviderParams::JwtBearer(
                credsd_core::rpc::ProviderParamsJwtBearer {
                    token_url,
                    assertion,
                    client_id,
                    scope,
                    identity_type: identity_type_str(Some(identity_type)),
                },
            ))
        }
    }
}

fn identity_type_str(t: Option<CliIdentityType>) -> Option<String> {
    t.map(|t| match t {
        CliIdentityType::Human => "human".into(),
        CliIdentityType::Automation => "automation".into(),
        CliIdentityType::Agent => "agent".into(),
    })
}

/// Send a `profile/bootstrap` RPC and handle streaming notifications interactively.
#[cfg(unix)]
async fn send_bootstrap_rpc(
    socket: &std::path::Path,
    params: &credsd_client::ProfileBootstrapParams,
) -> credsd_core::error::Result<()> {
    use credsd_core::error::DaemonError;
    match credsd_client::bootstrap(socket, params, &StdinBootstrapHandler).await {
        // Overwriting an existing credential is gated. Approving grants one re-send of these
        // exact params, so a Touch ID approval here retries at once; anything else leaves the
        // user to approve elsewhere and re-run, and nothing has been written in the meantime.
        Err(DaemonError::ApprovalRequired(challenge)) => {
            if presence::satisfy(&challenge).await? {
                credsd_client::bootstrap(socket, params, &StdinBootstrapHandler).await
            } else {
                Err(DaemonError::config(format!(
                    "not applied: approve request {}, then re-run this bootstrap",
                    challenge.id
                )))
            }
        }
        other => other,
    }
}

/// Send a `profile/login` RPC and handle streaming notifications interactively.
#[cfg(unix)]
async fn send_login_rpc(
    socket: &std::path::Path,
    params: &credsd_client::ProfileLoginParams,
) -> credsd_core::error::Result<()> {
    credsd_client::login(socket, params, &StdinBootstrapHandler).await
}

/// Interactive `BootstrapHandler` that drives SSO/MFA flows from stdin/stdout.
///
/// Implements [`credsd_client::BootstrapHandler`]: selection methods block in-place
/// so they can be called synchronously from within an async task without spawning.
#[cfg(unix)]
struct StdinBootstrapHandler;

#[cfg(unix)]
impl credsd_client::BootstrapHandler for StdinBootstrapHandler {
    fn device_code(&self, uri: &str, code: &str) {
        eprintln!("\nOpening browser for SSO authentication...");
        eprintln!(
            "If the browser doesn't open, visit: {}",
            credsd_core::log::escape_log(uri)
        );
        eprintln!(
            "Enter this code when prompted: {}\n",
            credsd_core::log::escape_log(code)
        );
        if reqwest::Url::parse(uri).is_ok_and(|u| u.scheme() == "https") {
            let _ = open::that(uri);
        } else {
            eprintln!(
                "creds: verification URI is not HTTPS, open manually: {}",
                credsd_core::log::escape_log(uri)
            );
        }
    }

    /// Print only. Passing the URL to an opener puts it in that process's argv, where other local
    /// users can read it and race the callback.
    fn authorize_url(&self, url: &str) {
        eprintln!(
            "\nOpen this URL in a browser to complete login:\n{}\n",
            credsd_core::log::escape_log(url)
        );
    }

    /// Print the URL, then read the code back from stdin.
    ///
    /// The code is echoed by the terminal, as a pasted value has to be for the user to see it
    /// landed. That is tolerable only because the code is single-use and bound to a PKCE verifier
    /// that never leaves the daemon, so a copy left in scrollback redeems nothing.
    fn authorize_code(&self, url: &str) -> Result<String, String> {
        eprintln!(
            "\nOpen this URL in a browser on any machine to complete login:\n{}\n",
            credsd_core::log::escape_log(url)
        );
        eprint!("Paste the code Sign-In displayed: ");
        use std::io::Write as _;
        std::io::stderr().flush().ok();
        let code = tokio::task::block_in_place(read_line_stdin);
        let code = code.trim().to_owned();
        if code.is_empty() {
            return Err("no code entered; login cancelled".to_owned());
        }
        Ok(code)
    }

    fn select_account(&self, accounts: &[(String, String, String)]) -> Result<String, String> {
        eprintln!("\nAvailable accounts:");
        let options: Vec<(String, String)> = accounts
            .iter()
            .map(|(id, name, _email)| {
                let label = if name.is_empty() {
                    "(unnamed)".to_owned()
                } else {
                    name.clone()
                };
                (label, id.clone())
            })
            .collect();
        choose_option_sync(&options).map_err(|e| e.to_string())
    }

    fn select_role(&self, roles: &[String]) -> Result<String, String> {
        eprintln!("\nAvailable roles:");
        let options: Vec<(String, String)> = roles.iter().map(|r| (r.clone(), r.clone())).collect();
        choose_option_sync(&options).map_err(|e| e.to_string())
    }

    fn mfa_code(&self, _serial: &str) -> Result<String, String> {
        use std::io::Write as _;
        eprint!("MFA code: ");
        std::io::stderr().flush().ok();
        let code = tokio::task::block_in_place(read_line_stdin);
        let code = code.trim().to_owned();
        if code.is_empty() {
            return Err("MFA code must not be empty".to_owned());
        }
        Ok(code)
    }
}

/// Synchronous counterpart to the former `choose_option`. Uses `block_in_place` for the
/// stdin prompt so it can be called from a sync `BootstrapHandler` method inside an async task.
#[cfg(unix)]
fn choose_option_sync(options: &[(String, String)]) -> credsd_core::error::Result<String> {
    use credsd_core::error::DaemonError;
    for (i, (label, _)) in options.iter().enumerate() {
        eprintln!(
            "  {}) {}",
            i.saturating_add(1),
            escape_terminal(label.as_str())
        );
    }
    match options {
        [] => Err(DaemonError::config(
            "the daemon offered nothing to choose from",
        )),
        [(_, only)] => Ok(only.clone()),
        _ => {
            let count = options.len();
            let idx = tokio::task::block_in_place(|| prompt_selection_sync(count))?;
            options
                .get(idx)
                .map(|(_, value)| value.clone())
                .ok_or_else(|| DaemonError::config("selection out of range"))
        }
    }
}

/// Read one line from stdin on a blocking thread (must be called via spawn_blocking).
fn read_line_stdin() -> String {
    use std::io::BufRead;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s).ok();
    s
}

/// A string field of a notification's params, or `""` when absent or not a string.
#[cfg(test)]
fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

/// An array field of a notification's params, or empty when absent or not an array.
#[cfg(test)]
fn json_array<'a>(value: &'a serde_json::Value, key: &str) -> &'a [serde_json::Value] {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// Prompt for a 1-indexed selection from a list of `count` items.
/// Must be called from within spawn_blocking (or a non-async context); blocks stdin.
fn prompt_selection_sync(count: usize) -> credsd_core::error::Result<usize> {
    use std::io::Write;
    loop {
        eprint!("Select [1-{count}]: ");
        std::io::stderr().flush().ok();

        // EOF is a closed stdin, not an invalid answer. Re-prompting it burns a full core for as
        // long as the process lives — and the daemon holds this uid's write lock throughout, so
        // the spin blocks the user's own next bootstrap too.
        let line = read_line_stdin();
        if line.is_empty() {
            return Err(credsd_core::error::DaemonError::config(
                "stdin closed before a selection was made",
            ));
        }

        // `wrapping_sub` turns the 0 answer into an out-of-range index rather than a special
        // case, so the range check is `n <= count` alone.
        if let Some(idx) = line
            .trim()
            .parse::<usize>()
            .ok()
            .map(|n| n.wrapping_sub(1))
            .filter(|idx| *idx < count)
        {
            return Ok(idx);
        }
        eprintln!("Invalid selection. Enter a number between 1 and {count}.");
    }
}

/// Ask the daemon for a profile's manifest — the client's whole view of its own configuration.
///
/// The client does not read `config.toml`. Under a system install the daemon owns
/// `callers/<uid>/` at 0700 and is that tree's sole reader and writer (Req 15), so a client
/// parsing it would get EACCES; worse, `Path::exists()` reports EACCES as "absent", so the
/// reads this replaces turned an unreadable config into an empty one and told the user to run a
/// bootstrap they had already run. `profile/describe` exists precisely so a shim never parses
/// that file (Req 6 AC 3).
#[cfg(unix)]
async fn describe(
    socket: &std::path::Path,
    environment: &str,
) -> credsd_core::error::Result<credsd_client::ProfileManifest> {
    use credsd_core::error::DaemonError;
    credsd_client::describe(socket, environment)
        .await
        .map_err(|e| match e {
            // The daemon will not distinguish "no such env" from "you may not have it", so the
            // remediation has to cover both: bootstrap is what creates the env *and* what
            // provisions this uid's authorization root.
            DaemonError::EnvNotFound(name) => DaemonError::config(format!(
                "env '{name}' not found. Run 'creds bootstrap' first."
            )),
            other => other,
        })
}

/// Fetch an env's credentials from the daemon and print them in the requested format.
///
/// The daemon is the only source. Fetching directly from the provider would reach the same
/// material without the caller assessment that `serve` performs on every request, so the
/// audit record would be avoidable by whoever most wants to avoid it.
#[cfg(unix)]
async fn cmd_get(
    env: Option<String>,
    credential: Option<String>,
    format: Option<String>,
    claimed: ClaimedIdentity,
) -> credsd_core::error::Result<()> {
    use credsd_client::{fetch_credential_in_env, fetch_from_daemon_uds};
    use credsd_core::config::platform;
    use credsd_core::error::DaemonError;
    use credsd_core::get;
    use std::io::IsTerminal;

    let fmt = get::OutputFormat::from_str_opt(format.as_deref())?;
    let socket = platform::client_socket_path();

    // Errors pass through as `uds::call` classified them: only a transport failure says to start
    // the daemon, so a reachable daemon's answer is never reworded here.

    // A `--credential` alongside its `--env` selects that credential under the env's authority
    // (the atom/group `credential_process` path). Bare `--credential X` has no authorization
    // context, so it resolves only when X is also a configured env (the shipped 1:1 shape).
    // `--env` alone resolves the env's default credential.
    let fetch = || async {
        match (&credential, &env) {
            (Some(cred), Some(env_name)) => {
                fetch_credential_in_env(&socket, env_name, cred, claimed).await
            }
            (Some(cred), None) => fetch_from_daemon_uds(&socket, cred, claimed).await,
            (None, Some(env_name)) => fetch_from_daemon_uds(&socket, env_name, claimed).await,
            (None, None) => Err(DaemonError::config("specify --env or --credential")),
        }
    };

    let creds = match fetch().await {
        Ok(creds) => creds,
        // Interactive terminal: drive the login flow inline and retry once, so a foreground
        // `get`/`exec` recovers without a separate command. Non-tty (SDK, CI) just errors.
        Err(DaemonError::ReauthRequired(_)) if std::io::stdin().is_terminal() => {
            // Route re-authentication through the daemon via profile/login so the token
            // is updated in callers/<uid>/credentials/<cred>/sso_token.enc.
            let environment = env
                .as_deref()
                .or(credential.as_deref())
                .unwrap_or_default()
                .to_string();
            let login_params = credsd_client::ProfileLoginParams {
                environment,
                credential: credential.clone(),
                request_id: None,
            };
            send_login_rpc(&socket, &login_params).await?;
            fetch().await?
        }
        Err(e) => return Err(e),
    };
    // Which variable an eval-style format exports is the credential's resolved address, not a
    // constant, so `get --format shell` and `run` put one credential in one place. Resolved only for
    // the formats that name a variable: `credential-process` is on an SDK's hot path and names none.
    // A token exports under the credential's address from the env's manifest, the same declared
    // `env_var` `run` honors. Only the formats that name a variable need it.
    let token_var = match &creds.data {
        credsd_core::credentials::CredentialData::AccessToken { .. }
            if get::names_a_variable(fmt) =>
        {
            token_address(&socket, env.as_deref(), credential.as_deref()).await?
        }
        _ => String::new(),
    };

    let output = get::format_credentials(&creds, fmt, &token_var)?;
    println!("{}", output);
    Ok(())
}

/// The variable a token credential exports under, resolved the way `run` resolves it. With `--env`,
/// the env's manifest supplies the env-level address and the credential's own `env_var`. A credential
/// named without a set of its own is described under its own name, as before.
#[cfg(unix)]
async fn token_address(
    socket: &std::path::Path,
    env: Option<&str>,
    credential: Option<&str>,
) -> credsd_core::error::Result<String> {
    use credsd_core::error::DaemonError;

    if let Some(env) = env {
        let manifest = describe(socket, env).await?;
        let found = match credential {
            Some(name) => manifest.credentials.iter().find(|e| e.credential == name),
            None => manifest.credentials.iter().find(|e| e.default),
        };
        if let Some(entry) = found {
            return Ok(address_of(&manifest.projection.projections, entry));
        }
        if credential.is_none() {
            return Err(DaemonError::config(format!(
                "env '{env}' has no default credential"
            )));
        }
    }
    let name = credential.ok_or_else(|| DaemonError::config("specify --env or --credential"))?;
    let manifest = describe(socket, name).await?;
    let entry = manifest
        .credentials
        .iter()
        .find(|e| e.credential == name)
        .ok_or_else(|| {
            DaemonError::config(format!(
                "credential '{name}' is not served under its own name"
            ))
        })?;
    Ok(address_of(&std::collections::BTreeMap::new(), entry))
}

/// One credential's address: the env-level declaration for it, then its own `env_var`, then derived.
fn address_of(
    env_decls: &std::collections::BTreeMap<String, credsd_core::projection::ProjectionDecl>,
    entry: &credsd_core::rpc::CredentialEntry,
) -> String {
    let env_decl = env_decls
        .get(&entry.credential)
        .and_then(|d| d.address.as_deref());
    credsd_core::credential_env::token_variable(
        env_decl,
        entry.env_var.as_deref(),
        &entry.credential,
    )
}

/// The format argument is still validated before the transport error, so a bad `--format`
/// is reported as a bad `--format` on every platform rather than being masked by the
/// missing daemon.
#[cfg(not(unix))]
async fn cmd_get(
    env: Option<String>,
    credential: Option<String>,
    format: Option<String>,
    claimed: ClaimedIdentity,
) -> credsd_core::error::Result<()> {
    use credsd_core::get;

    let _ = get::OutputFormat::from_str_opt(format.as_deref())?;
    let _ = (env, credential, claimed);

    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform \
         (named pipe transport pending).",
    ))
}

/// List every credential this uid may reach, once each, with its source type and session status.
///
/// Two RPCs' worth of information: `credential/list` enumerates (it is the only method with an
/// all-profiles form), then one `profile/describe` per profile supplies the source type that
/// enumeration deliberately withholds (Req 13 AC 4). No local status computation — the daemon
/// owns the sealed tokens, so it is the only party that can read their expiry.
#[cfg(unix)]
async fn cmd_list(format: &str) -> credsd_core::error::Result<()> {
    use credsd_core::config::platform;

    match format {
        "text" | "json" => {}
        other => {
            return Err(credsd_core::error::DaemonError::config(format!(
                "unknown format '{}': expected 'text' or 'json'",
                other
            )));
        }
    }

    let socket = platform::client_socket_path();
    let listed = credsd_client::list(&socket, None).await?;

    // Profile order as the daemon enumerated it, deduped: a profile appears once per credential
    // it composes, and each is described once.
    let mut profiles: Vec<&str> = Vec::new();
    for summary in &listed.credentials {
        if !profiles.contains(&summary.environment.as_str()) {
            profiles.push(&summary.environment);
        }
    }

    if profiles.is_empty() {
        if format == "json" {
            println!("[]");
        } else {
            eprintln!("No envs configured. Run 'creds bootstrap' to get started.");
        }
        return Ok(());
    }

    let mut manifests = Vec::with_capacity(profiles.len());
    for environment in profiles {
        manifests.push(describe(&socket, environment).await?);
    }
    let rows = list_rows(&manifests);

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&list_json(&rows))?);
    } else {
        print!("{}", list_text(&rows));
    }
    Ok(())
}

/// One row per credential, in first-seen order: a credential composed into several envs is
/// still one credential, with one source and one session.
#[cfg(unix)]
fn list_rows(
    manifests: &[credsd_client::ProfileManifest],
) -> Vec<&credsd_core::rpc::CredentialEntry> {
    let mut rows: Vec<&credsd_core::rpc::CredentialEntry> = Vec::new();
    for entry in manifests.iter().flat_map(|m| &m.credentials) {
        if !rows.iter().any(|r| r.credential == entry.credential) {
            rows.push(entry);
        }
    }
    rows
}

#[cfg(unix)]
fn list_json(rows: &[&credsd_core::rpc::CredentialEntry]) -> serde_json::Value {
    rows.iter()
        .map(|c| {
            serde_json::json!({
                "name": c.credential,
                "mode": c.source.as_str(),
                "status": c.status.as_str(),
            })
        })
        .collect()
}

/// MODE is as wide as the longest source spelling, `aws-roles-anywhere`.
#[cfg(unix)]
fn list_text(rows: &[&credsd_core::rpc::CredentialEntry]) -> String {
    let mut out = format!("{:<15} {:<18} STATUS\n", "CREDENTIAL", "MODE");
    for entry in rows {
        out.push_str(&format!(
            "{:<15} {:<18} {}\n",
            escape_terminal(entry.credential.as_str()),
            escape_terminal(entry.source.as_str()),
            escape_terminal(entry.status.as_str()),
        ));
    }
    out
}

/// `list` enumerates through the daemon, and no daemon transport exists on this platform yet.
#[cfg(not(unix))]
async fn cmd_list(format: &str) -> credsd_core::error::Result<()> {
    let _ = format;
    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform \
         (named pipe transport pending).",
    ))
}

#[cfg(unix)]
async fn cmd_config_set(env: String, key: &str, value: &str) -> credsd_core::error::Result<()> {
    use credsd_core::config::keys;
    use credsd_core::error::DaemonError;

    if let Some(reason) = keys::is_protected(key) {
        return Err(DaemonError::config(format!(
            "cannot set '{}' — {}",
            key, reason
        )));
    }
    let key_def = keys::find_key(key).ok_or_else(|| {
        DaemonError::config(format!(
            "unknown config key '{}'. Run 'creds config keys' to see available settings.",
            key
        ))
    })?;
    key_def.value_type.validate(value, key).map_err(|e| {
        let type_name = match key_def.value_type {
            keys::ValueType::String => "string",
            keys::ValueType::Boolean => "boolean",
            keys::ValueType::Integer => "integer",
            keys::ValueType::Enum(_) => "enum",
        };
        DaemonError::config(format!(
            "'{}' is not a valid {} for '{}'. {}",
            value, type_name, key, e
        ))
    })?;

    let socket = credsd_core::config::platform::client_socket_path();
    let set: credsd_core::error::Result<credsd_core::rpc::OkResult> = credsd_core::rpc::uds::call(
        &socket,
        credsd_core::rpc::METHOD_CONFIG_SET,
        &credsd_core::rpc::ConfigSetParams {
            environment: env.clone(),
            key: key.to_owned(),
            value: value.to_owned(),
        },
        Some(&env),
    )
    .await;
    performed_on_approval(set.map(|_| ())).await
}

#[cfg(not(unix))]
async fn cmd_config_set(_: String, _: &str, _: &str) -> credsd_core::error::Result<()> {
    Err(credsd_core::error::DaemonError::config(
        "not supported on this platform",
    ))
}

#[cfg(unix)]
async fn cmd_config_get(env: String, key: &str) -> credsd_core::error::Result<ExitCode> {
    use credsd_core::config::keys;
    use credsd_core::error::DaemonError;

    if let Some(reason) = keys::is_protected(key) {
        return Err(DaemonError::config(format!(
            "cannot read '{}' via config get — {}",
            key, reason
        )));
    }
    keys::find_key(key).ok_or_else(|| {
        DaemonError::config(format!(
            "unknown config key '{}'. Run 'creds config keys' to see available settings.",
            key
        ))
    })?;

    let socket = credsd_core::config::platform::client_socket_path();
    let result = credsd_client::config_get(&socket, &env, key).await?;

    // An unset key exits 1 with no output, so `$(creds config get …)` in a shell distinguishes
    // "unset" from "set to the empty string" without parsing prose. Not an error: nothing is
    // printed on stderr either, so a script can test the status without filtering a message.
    match result.value {
        Some(val) => {
            println!("{}", escape_terminal(&val));
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::FAILURE),
    }
}

#[cfg(not(unix))]
async fn cmd_config_get(_: String, _: &str) -> credsd_core::error::Result<ExitCode> {
    Err(credsd_core::error::DaemonError::config(
        "not supported on this platform",
    ))
}

#[cfg(unix)]
async fn cmd_config_unset(env: String, key: &str) -> credsd_core::error::Result<()> {
    use credsd_core::config::keys;
    use credsd_core::error::DaemonError;

    if let Some(reason) = keys::is_protected(key) {
        return Err(DaemonError::config(format!(
            "cannot unset '{}' — {}",
            key, reason
        )));
    }
    if let Some(reason) = keys::is_unset_protected(key) {
        return Err(DaemonError::config(format!(
            "cannot unset '{}' — {}",
            key, reason
        )));
    }
    keys::find_key(key).ok_or_else(|| {
        DaemonError::config(format!(
            "unknown config key '{}'. Run 'creds config keys' to see available settings.",
            key
        ))
    })?;

    let socket = credsd_core::config::platform::client_socket_path();
    performed_on_approval(
        credsd_client::config_unset(&socket, &env, key)
            .await
            .map(|_| ()),
    )
    .await
}

#[cfg(not(unix))]
async fn cmd_config_unset(_: String, _: &str) -> credsd_core::error::Result<()> {
    Err(credsd_core::error::DaemonError::config(
        "not supported on this platform",
    ))
}

fn cmd_config_keys(format: &str) -> credsd_core::error::Result<()> {
    use credsd_core::config::keys::{self, ValueType};

    match format {
        "json" => {
            let entries: Vec<serde_json::Value> = keys::ALLOWED_KEYS
                .iter()
                .map(|k| {
                    // `values` is present only for an enum, so it is built into the object rather
                    // than assigned afterwards — the assignment form indexed a `Value`, which
                    // panics on anything that is not a map.
                    let values = match k.value_type {
                        ValueType::Enum(opts) => serde_json::json!(opts),
                        _ => serde_json::Value::Null,
                    };
                    let mut obj = serde_json::Map::new();
                    obj.insert("key".into(), k.key.into());
                    obj.insert(
                        "type".into(),
                        match k.value_type {
                            ValueType::String => "string",
                            ValueType::Boolean => "boolean",
                            ValueType::Integer => "integer",
                            ValueType::Enum(_) => "enum",
                        }
                        .into(),
                    );
                    obj.insert("description".into(), k.description.into());
                    if !values.is_null() {
                        obj.insert("values".into(), values);
                    }
                    serde_json::Value::Object(obj)
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        _ => {
            let col_width = keys::ALLOWED_KEYS
                .iter()
                .map(|k| k.key.len())
                .max()
                .unwrap_or(20)
                .saturating_add(2);
            let header_key = "KEY";
            let header_type = "TYPE";
            let header_desc = "DESCRIPTION";
            println!(
                "{:<width$} {:<10} {}",
                header_key,
                header_type,
                header_desc,
                width = col_width
            );
            let mut last_section: Option<Option<&str>> = None;
            for k in keys::ALLOWED_KEYS {
                let current_section = k.section;
                if last_section.as_ref() != Some(&current_section) {
                    if last_section.is_some() {
                        println!();
                    }
                    last_section = Some(current_section);
                }
                let type_str = match k.value_type {
                    ValueType::String => "string",
                    ValueType::Boolean => "boolean",
                    ValueType::Integer => "integer",
                    ValueType::Enum(opts) => {
                        println!(
                            "{:<width$} {:<10} {} [{}]",
                            k.key,
                            "enum",
                            k.description,
                            opts.join(", "),
                            width = col_width
                        );
                        continue;
                    }
                };
                println!(
                    "{:<width$} {:<10} {}",
                    k.key,
                    type_str,
                    k.description,
                    width = col_width
                );
            }
        }
    }
    Ok(())
}

/// Drop an env's composition. Its credentials are untouched — they are reusable atoms.
#[cfg(unix)]
async fn remove_env(socket: &std::path::Path, name: &str) -> credsd_core::error::Result<()> {
    performed_on_approval(credsd_client::env_remove(socket, name).await.map(|_| ())).await
}

/// `creds revalidate`. A caller root with nothing drifted returns without a challenge.
#[cfg(unix)]
async fn cmd_revalidate() -> credsd_core::error::Result<()> {
    use credsd_core::rpc::{uds, OkResult, RevalidateParams, METHOD_FILE_REVALIDATE};
    let socket = credsd_core::config::platform::client_socket_path();
    let result: credsd_core::error::Result<OkResult> = uds::call(
        &socket,
        METHOD_FILE_REVALIDATE,
        &RevalidateParams::default(),
        None,
    )
    .await;
    match result {
        Ok(_) => {
            println!(
                "nothing to revalidate: config.toml and credentials.toml match their snapshots"
            );
            Ok(())
        }
        Err(e) => performed_on_approval(Err(e)).await,
    }
}

#[cfg(not(unix))]
async fn cmd_revalidate() -> credsd_core::error::Result<()> {
    Err(credsd_core::error::DaemonError::config(
        "not supported on this platform",
    ))
}

/// For a gated operation that approval itself performs, so there is nothing to re-send. A Touch ID
/// approval here completes it; otherwise it stays pending until approved elsewhere, and the
/// caller is told nothing has changed yet rather than reporting a change that did not happen.
#[cfg(unix)]
async fn performed_on_approval(
    result: credsd_core::error::Result<()>,
) -> credsd_core::error::Result<()> {
    use credsd_core::error::DaemonError;
    match result {
        Err(DaemonError::ApprovalRequired(challenge)) => {
            if presence::satisfy(&challenge).await? {
                Ok(())
            } else {
                Err(DaemonError::config(format!(
                    "not applied yet: it takes effect when request {} is approved",
                    challenge.id
                )))
            }
        }
        other => other,
    }
}

/// Delete a credential and its sealed material. The daemon refuses while an env still
/// references it.
#[cfg(unix)]
async fn remove_credential(socket: &std::path::Path, name: &str) -> credsd_core::error::Result<()> {
    performed_on_approval(
        credsd_client::credential_remove(socket, name)
            .await
            .map(|_| ()),
    )
    .await
}

/// Remove an env or a credential — every deletion through the daemon.
///
/// Nothing is deleted locally. The sealed material and both TOML files live under
/// `callers/<uid>/`, a tree the daemon owns at 0700; the client-side deletion this replaces hit
/// EACCES on that parent, read it as "nothing to delete", and reported success while the
/// credential and its sealed key survived — the daemon could still mint sessions from it. The
/// daemon's own answer is now the report: `ENVIRONMENT_NOT_FOUND` means nothing was removed.
///
/// There is no remove-everything form. Each removal is a gated operation the daemon describes
/// and performs on its own approval; a client-side loop over them could only enumerate what
/// `credential/list` shows, which omits credentials no env references, and would report a reset
/// that left those credentials and their sealed keys on disk.
#[cfg(unix)]
async fn cmd_remove(
    env: Option<String>,
    credential: Option<String>,
    force: bool,
) -> credsd_core::error::Result<()> {
    use credsd_core::config::platform;
    use credsd_core::error::DaemonError;
    use std::io::{self, BufRead, Write};

    let socket = platform::client_socket_path();

    let confirm = |prompt: &str| -> credsd_core::error::Result<bool> {
        if force {
            return Ok(true);
        }
        eprint!("{}", prompt);
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        Ok(line.trim().eq_ignore_ascii_case("y"))
    };

    // Removing a credential (an atom): the daemon refuses while any env still references it,
    // since that would leave the env pointing at a credential it can no longer resolve.
    if let Some(credential) = credential {
        if !confirm(&format!(
            "Remove credential '{}' and its encrypted data? [y/N] ",
            credential
        ))? {
            eprintln!("Cancelled.");
            return Ok(());
        }
        remove_credential(&socket, &credential).await?;
        eprintln!("Removed credential '{}' and its sealed data.", credential);
        return Ok(());
    }

    // Removing an env: drop the composition only. Credentials are reusable atoms and are
    // left intact — `remove --credential` deletes those.
    let env = env.ok_or_else(|| DaemonError::config("specify --env or --credential"))?;
    if !confirm(&format!(
        "Remove env '{}'? (its credentials are left intact) [y/N] ",
        env
    ))? {
        eprintln!("Cancelled.");
        return Ok(());
    }
    remove_env(&socket, &env).await?;
    eprintln!("Removed env '{}'. Credentials left intact.", env);
    Ok(())
}

/// Removal is a daemon mutation, and no daemon transport exists on this platform yet.
#[cfg(not(unix))]
async fn cmd_remove(
    env: Option<String>,
    credential: Option<String>,
    force: bool,
) -> credsd_core::error::Result<()> {
    let _ = (env, credential, force);
    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform \
         (named pipe transport pending).",
    ))
}

#[cfg(test)]
#[allow(
    clippy::panic_in_result_fn,
    reason = "assert_eq! in async test fns returning Result is idiomatic"
)]
mod tests {
    use super::*;
    use clap::Parser;

    /// `docs/reference/commands.md` documents every subcommand and long flag this binary
    /// accepts, and nothing it does not (user-documentation Requirement 3.2).
    #[test]
    fn command_reference_matches_the_cli() {
        use clap::CommandFactory;
        let doc = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/reference/commands.md"
        ))
        .expect("read docs/reference/commands.md");
        // `jwt-bearer` is compiled only with its feature, so its section is expected only then.
        let doc = if cfg!(feature = "jwt-bearer") {
            doc
        } else {
            doc.split("\n### ")
                .filter(|s| !s.starts_with("creds bootstrap jwt-bearer"))
                .collect::<Vec<_>>()
                .join("\n### ")
        };
        let problems = command_reference::discrepancies(&Cli::command(), &doc);
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    fn parse(args: &[&str]) -> Commands {
        let argv = std::iter::once("credsd").chain(args.iter().copied());
        Cli::try_parse_from(argv).unwrap().command
    }

    /// A notification field that is absent, null, or the wrong type reads as empty rather than
    /// panicking. The indexing this replaced panicked on a `params` that was not an object, which
    /// a peer daemon of a different version could legitimately send.
    #[test]
    fn json_accessors_default_instead_of_panicking() {
        let obj = serde_json::json!({ "user_code": "ABCD-1234", "accounts": [1, 2] });
        assert_eq!(json_str(&obj, "user_code"), "ABCD-1234");
        assert_eq!(json_str(&obj, "absent"), "");
        assert_eq!(json_str(&obj, "accounts"), "", "wrong type reads as empty");
        assert_eq!(json_array(&obj, "accounts").len(), 2);
        assert!(json_array(&obj, "absent").is_empty());
        assert!(json_array(&obj, "user_code").is_empty());

        for not_a_map in [
            serde_json::Value::Null,
            serde_json::json!("string"),
            serde_json::json!([1, 2]),
        ] {
            assert_eq!(json_str(&not_a_map, "user_code"), "");
            assert!(json_array(&not_a_map, "accounts").is_empty());
        }
    }

    /// A sole option is taken without reading stdin — the property that makes a non-interactive
    /// `bootstrap` work when the account or role is unambiguous.
    #[test]
    fn a_single_option_is_chosen_without_prompting() {
        let only = [(
            "Prod (111111111111)".to_string(),
            "111111111111".to_string(),
        )];
        assert_eq!(choose_option_sync(&only).unwrap(), "111111111111");
    }

    /// No options is an error, not a prompt for a choice that cannot be made. Without this the
    /// selection prompt would ask for a number between 1 and 0.
    #[test]
    fn no_options_is_an_error() {
        let err = choose_option_sync(&[]).unwrap_err().to_string();
        assert!(err.contains("nothing to choose from"), "{err}");
    }

    #[test]
    fn config_dir_flag_parses_as_global() {
        let cli = Cli::try_parse_from(["credsd", "--config-dir", "/tmp/x", "list"]).unwrap();
        assert_eq!(
            cli.config_dir.as_deref(),
            Some(std::path::Path::new("/tmp/x"))
        );
    }

    #[test]
    fn get_parses_credential_flag() {
        match parse(&["get", "--credential", "ra-main"]) {
            Commands::Get {
                env, credential, ..
            } => {
                assert_eq!(env, None);
                assert_eq!(credential.as_deref(), Some("ra-main"));
            }
            _ => panic!("expected Get"),
        }
    }

    /// `env` wrote a credential-resolving AWS config to a caller-chosen path and exited, leaving
    /// it for any later reader. It is gone, not hidden: a hidden alias would keep the write.
    #[test]
    fn env_is_not_a_subcommand() {
        assert!(Cli::try_parse_from(["credsd", "env", "--environment", "work"]).is_err());
    }

    /// `--sandbox` is gone from every subcommand: it was advertised as a security control
    /// while being discarded at dispatch. A stale caller passing it must fail loudly rather
    /// than parse and appear isolated when nothing is isolating anything.
    #[test]
    fn sandbox_is_not_accepted_anywhere() {
        assert!(Cli::try_parse_from(["credsd", "get", "--env", "dev", "--sandbox"]).is_err());
    }

    /// `--standalone` is gone from every subcommand. A stale script or harness passing it
    /// must fail loudly rather than parse and quietly fetch by some other route.
    #[test]
    fn standalone_is_not_accepted_anywhere() {
        assert!(Cli::try_parse_from(["credsd", "get", "--env", "dev", "--standalone"]).is_err());
    }

    #[test]
    fn bootstrap_sso_parses() {
        let cmd = parse(&[
            "bootstrap",
            "--credential",
            "dev",
            "aws-idc-sso",
            "--start-url",
            "https://example.awsapps.com/start",
            "--sso-region",
            "us-west-2",
        ]);
        assert!(matches!(cmd, Commands::Bootstrap { .. }));
    }

    #[test]
    fn bootstrap_sso_with_account_role() {
        let cmd = parse(&[
            "bootstrap",
            "--credential",
            "prod",
            "aws-idc-sso",
            "--start-url",
            "https://example.awsapps.com/start",
            "--sso-region",
            "us-west-2",
            "--account-id",
            "123456789012",
            "--role-name",
            "AdminRole",
        ]);
        assert!(matches!(cmd, Commands::Bootstrap { .. }));
    }

    /// A remote login binds no listener, so a fixed callback port would record a redirect URI
    /// nothing uses. Rejecting the pair at parse time says so before the browser is involved.
    #[test]
    fn bootstrap_aws_login_remote_rejects_a_callback_port() {
        let cmd = parse(&[
            "bootstrap",
            "--credential",
            "dev",
            "aws-login",
            "--region",
            "us-east-1",
            "--remote",
        ]);
        match cmd {
            Commands::Bootstrap {
                provider:
                    Some(BootstrapProvider::AwsLogin {
                        remote,
                        callback_port,
                        ..
                    }),
                ..
            } => {
                assert!(remote);
                assert_eq!(callback_port, None);
            }
            other => panic!("expected aws-login, got {other:?}"),
        }
        assert!(
            Cli::try_parse_from([
                "credsd",
                "bootstrap",
                "--credential",
                "dev",
                "aws-login",
                "--region",
                "us-east-1",
                "--remote",
                "--callback-port",
                "5000",
            ])
            .err()
            .expect("remote with a callback port must not parse")
            .kind()
                == clap::error::ErrorKind::ArgumentConflict
        );
    }

    /// `aws-login` signs in against a regional Sign-In host, so a region the caller never named
    /// must fail at parse time rather than fall back to a default. `aws-web-identity` is the same:
    /// see `bootstrap_aws_web_identity_requires_region`.
    #[test]
    fn bootstrap_aws_login_requires_region() {
        let err = Cli::try_parse_from(["credsd", "bootstrap", "--credential", "dev", "aws-login"])
            .err()
            .expect("aws-login without --region must not parse");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--region"), "{err}");
        assert!(matches!(
            parse(&[
                "bootstrap",
                "--credential",
                "dev",
                "aws-login",
                "--region",
                "us-west-2",
            ]),
            Commands::Bootstrap {
                provider: Some(BootstrapProvider::AwsLogin { region, .. }),
                ..
            } if region == "us-west-2"
        ));
    }

    /// `aws-iam-user` has no default `--region`: GetSessionToken is called against that region's
    /// STS endpoint, so guessing us-east-1 would broker the session in the wrong place.
    #[test]
    fn bootstrap_aws_iam_user_requires_region() {
        let argv = [
            "credsd",
            "bootstrap",
            "--credential",
            "dev",
            "aws-iam-user",
            "--access-key-id",
            "AKIAEXAMPLE",
        ];
        let err = Cli::try_parse_from(argv)
            .err()
            .expect("aws-iam-user without --region must not parse");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--region"), "{err}");

        let with_region = [argv.as_slice(), &["--region", "us-west-2"]].concat();
        let Commands::Bootstrap {
            provider: Some(BootstrapProvider::AwsIamUser { region, .. }),
            ..
        } = Cli::try_parse_from(with_region).unwrap().command
        else {
            panic!("expected Bootstrap AwsIamUser");
        };
        assert_eq!(region, "us-west-2");
    }

    /// `aws-idc-sso` has no default `--sso-region`: the Identity Center instance lives in one
    /// region, and guessing us-east-1 would point the login at the wrong portal.
    #[test]
    fn bootstrap_aws_idc_sso_requires_sso_region() {
        let argv = [
            "credsd",
            "bootstrap",
            "--credential",
            "dev",
            "aws-idc-sso",
            "--start-url",
            "https://example.awsapps.com/start",
        ];
        let err = Cli::try_parse_from(argv)
            .err()
            .expect("aws-idc-sso without --sso-region must not parse");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--sso-region"), "{err}");

        let with_region = [argv.as_slice(), &["--sso-region", "eu-west-1"]].concat();
        let Commands::Bootstrap {
            provider: Some(BootstrapProvider::AwsIdcSso { sso_region, .. }),
            ..
        } = Cli::try_parse_from(with_region).unwrap().command
        else {
            panic!("expected Bootstrap AwsIdcSso");
        };
        assert_eq!(sso_region, "eu-west-1");
    }

    /// `aws-web-identity` has no default region: the STS endpoint is a property of the account the
    /// role lives in, and guessing us-east-1 would federate against the wrong one silently.
    #[test]
    fn bootstrap_aws_web_identity_requires_region() {
        let argv = [
            "credsd",
            "bootstrap",
            "--credential",
            "dev",
            "aws-web-identity",
            "--authorization-endpoint",
            "https://idp.example.com/authorize",
            "--token-endpoint",
            "https://idp.example.com/token",
            "--client-id",
            "client",
            "--role-arn",
            "arn:aws:iam::123456789012:role/Dev",
        ];
        let err = Cli::try_parse_from(argv)
            .err()
            .expect("aws-web-identity without --region must not parse");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--region"), "{err}");

        let with_region = [argv.as_slice(), &["--region", "us-west-2"]].concat();
        let Commands::Bootstrap {
            provider: Some(BootstrapProvider::AwsWebIdentity { region, .. }),
            ..
        } = Cli::try_parse_from(with_region).unwrap().command
        else {
            panic!("expected Bootstrap AwsWebIdentity");
        };
        assert!(format!("{region:?}").contains("us-west-2"), "{region:?}");
    }

    #[test]
    fn bootstrap_iam_user_parses() {
        let cmd = parse(&[
            "bootstrap",
            "--credential",
            "work",
            "aws-iam-user",
            "--access-key-id",
            "AKIAEXAMPLE",
            "--region",
            "us-east-1",
        ]);
        match cmd {
            Commands::Bootstrap {
                provider:
                    Some(BootstrapProvider::AwsIamUser {
                        access_key_id,
                        region,
                        ..
                    }),
                ..
            } => {
                assert_eq!(access_key_id, "AKIAEXAMPLE");
                assert_eq!(region, "us-east-1");
            }
            _ => panic!("expected Bootstrap AwsIamUser"),
        }
    }

    #[test]
    fn bootstrap_iam_user_accepts_mfa_serial() {
        let cmd = parse(&[
            "bootstrap",
            "--credential",
            "work",
            "aws-iam-user",
            "--access-key-id",
            "AKIAEXAMPLE",
            "--region",
            "us-east-1",
            "--mfa-serial",
            "arn:aws:iam::111111111111:mfa/user",
        ]);
        match cmd {
            Commands::Bootstrap {
                provider: Some(BootstrapProvider::AwsIamUser { mfa_serial, .. }),
                ..
            } => assert_eq!(
                mfa_serial.as_deref(),
                Some("arn:aws:iam::111111111111:mfa/user")
            ),
            _ => panic!("expected Bootstrap AwsIamUser"),
        }
    }

    #[test]
    fn login_parses_with_env() {
        match parse(&["login", "--env", "work"]) {
            Commands::Login { env, credential } => {
                assert_eq!(env.as_deref(), Some("work"));
                assert_eq!(credential, None);
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn login_requires_a_env() {
        assert!(Cli::try_parse_from(["credsd", "login"]).is_err());
    }

    #[test]
    fn bootstrap_iam_user_secret_is_not_an_arg() {
        let err = Cli::try_parse_from([
            "credsd",
            "bootstrap",
            "--credential",
            "work",
            "aws-iam-user",
            "--access-key-id",
            "AKIAEXAMPLE",
            "--secret-access-key",
            "shhh",
        ]);
        assert!(
            err.is_err(),
            "secret-access-key must not be a recognized flag"
        );
    }

    #[test]
    fn config_set_parses() {
        let cmd = parse(&["config", "set", "region", "us-east-2", "--env", "demo"]);
        match cmd {
            Commands::Config {
                action: ConfigAction::Set { key, value, env },
            } => {
                assert_eq!(key, "region");
                assert_eq!(value, "us-east-2");
                assert_eq!(env, "demo");
            }
            _ => panic!("expected Config Set"),
        }
    }

    #[test]
    fn config_get_parses() {
        let cmd = parse(&["config", "get", "region", "--env", "demo"]);
        match cmd {
            Commands::Config {
                action: ConfigAction::Get { key, env },
            } => {
                assert_eq!(key, "region");
                assert_eq!(env, "demo");
            }
            _ => panic!("expected Config Get"),
        }
    }

    #[test]
    fn config_unset_parses() {
        let cmd = parse(&["config", "unset", "sdk.retry_mode", "--env", "demo"]);
        match cmd {
            Commands::Config {
                action: ConfigAction::Unset { key, env },
            } => {
                assert_eq!(key, "sdk.retry_mode");
                assert_eq!(env, "demo");
            }
            _ => panic!("expected Config Unset"),
        }
    }

    #[test]
    fn config_keys_parses() {
        let cmd = parse(&["config", "keys"]);
        match cmd {
            Commands::Config {
                action: ConfigAction::Keys { format },
            } => {
                assert_eq!(format, "text");
            }
            _ => panic!("expected Config Keys"),
        }
    }

    #[test]
    fn config_keys_json_parses() {
        let cmd = parse(&["config", "keys", "--format", "json"]);
        match cmd {
            Commands::Config {
                action: ConfigAction::Keys { format },
            } => {
                assert_eq!(format, "json");
            }
            _ => panic!("expected Config Keys with json format"),
        }
    }

    #[test]
    fn list_default_format_is_text() {
        let cmd = parse(&["list"]);
        match cmd {
            Commands::List { format } => assert_eq!(format, "text"),
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn list_json_format_parses() {
        let cmd = parse(&["list", "--format", "json"]);
        match cmd {
            Commands::List { format } => assert_eq!(format, "json"),
            _ => panic!("expected List with json format"),
        }
    }

    #[tokio::test]
    async fn config_set_rejects_protected_key() {
        let result = cmd_config_set("demo".into(), "credential", "other").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("cannot set 'credential'"));
        assert!(err.contains("bootstrap"));
    }

    #[tokio::test]
    async fn config_set_rejects_unknown_key() {
        let result = cmd_config_set("demo".into(), "typo.key", "value").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("unknown config key 'typo.key'"));
        assert!(err.contains("creds config keys"));
    }

    #[tokio::test]
    async fn config_set_rejects_invalid_value() {
        let result = cmd_config_set("demo".into(), "sdk.max_attempts", "-1").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("'-1' is not a valid integer for 'sdk.max_attempts'"));
    }

    #[tokio::test]
    async fn config_set_rejects_invalid_enum() {
        let result = cmd_config_set("demo".into(), "sdk.retry_mode", "exponential").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("'exponential' is not a valid enum for 'sdk.retry_mode'"));
        assert!(err.contains("expected one of"));
    }

    #[tokio::test]
    async fn config_set_rejects_invalid_boolean() {
        let result = cmd_config_set("demo".into(), "sdk.use_fips_endpoint", "yes").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("'yes' is not a valid boolean for 'sdk.use_fips_endpoint'"));
    }

    /// Credential-source fields moved to credentials.toml, which `config set` does not edit
    /// at all — so they are rejected as unknown rather than as protected.
    #[tokio::test]
    async fn config_set_rejects_credential_source_keys() {
        let result = cmd_config_set("demo".into(), "sso.start_url", "https://x.com").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("unknown config key 'sso.start_url'"));
    }

    #[tokio::test]
    async fn config_unset_rejects_protected_key() {
        let result = cmd_config_unset("demo".into(), "credential").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("cannot unset 'credential'"));
    }

    #[tokio::test]
    async fn config_unset_rejects_unknown_key() {
        let result = cmd_config_unset("demo".into(), "fake.key").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("unknown config key 'fake.key'"));
    }

    #[tokio::test]
    async fn config_get_rejects_unknown_key() {
        let result = cmd_config_get("demo".into(), "bogus").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("unknown config key 'bogus'"));
    }

    /// The Info.plist `build.rs` embeds in this binary's `__TEXT,__info_plist` section, read as
    /// the linker sees it. A `[[bin]]` rename that left build.rs behind cannot silently drop the
    /// section — Cargo rejects a `rustc-link-arg-bin` naming no bin target — but nothing but this
    /// checks that the embedded plist still names the binary it is embedded in, which is what a
    /// packaging or signing script keys on.
    #[test]
    fn embedded_plist_names_this_binary() {
        let plist = include_str!(concat!(env!("OUT_DIR"), "/Info.plist"));
        assert!(
            plist.contains(&format!(
                "<key>CFBundleExecutable</key>\n    <string>{}</string>",
                env!("CARGO_BIN_NAME")
            )),
            "CFBundleExecutable is not the bin name {}:\n{plist}",
            env!("CARGO_BIN_NAME")
        );
        // Substitution is per-crate, so the daemon's copy of this check cannot speak for it.
        assert!(
            !plist.contains('@'),
            "unsubstituted placeholder in:\n{plist}"
        );
    }

    #[test]
    fn environment_flag_is_the_canonical_spelling() {
        // --environment is the primary flag; --env is a hidden alias. Both must parse.
        let with_canonical = parse(&["get", "--environment", "dev"]);
        let with_alias = parse(&["get", "--env", "dev"]);
        match (with_canonical, with_alias) {
            (Commands::Get { env: a, .. }, Commands::Get { env: b, .. }) => {
                assert_eq!(a.as_deref(), Some("dev"));
                assert_eq!(b.as_deref(), Some("dev"));
            }
            _ => panic!("expected Get command"),
        }
    }

    #[cfg(unix)]
    fn manifest(
        environment: &str,
        credentials: &[(&str, credsd_core::rpc::CredentialSourceType)],
    ) -> credsd_client::ProfileManifest {
        use credsd_core::rpc::{CredentialEntry, SessionStatus};
        credsd_client::ProfileManifest {
            environment: environment.to_owned(),
            credentials: credentials
                .iter()
                .map(|(name, source)| CredentialEntry {
                    credential: (*name).to_owned(),
                    kind: credsd_core::credentials::CredentialType::SessionCredentials,
                    source: *source,
                    env_var: None,
                    projection: None,
                    status: SessionStatus::Active,
                    default: true,
                })
                .collect(),
            projection: Default::default(),
        }
    }

    /// A credential shared by two envs lists once, in the order first enumerated.
    #[cfg(unix)]
    #[test]
    fn list_rows_are_one_per_credential() {
        use credsd_core::rpc::CredentialSourceType::{AwsIamUser, AwsIdcSso};
        let manifests = [
            manifest("dev", &[("shared", AwsIdcSso)]),
            manifest("prod", &[("shared", AwsIdcSso), ("ci", AwsIamUser)]),
        ];
        let names: Vec<&str> = list_rows(&manifests)
            .iter()
            .map(|r| r.credential.as_str())
            .collect();
        assert_eq!(names, ["shared", "ci"]);
    }

    #[cfg(unix)]
    #[test]
    fn list_json_is_a_flat_array_of_name_mode_status() {
        use credsd_core::rpc::CredentialSourceType::AwsRolesAnywhere;
        let manifests = [manifest("dev", &[("ra", AwsRolesAnywhere)])];
        assert_eq!(
            list_json(&list_rows(&manifests)),
            serde_json::json!([
                { "name": "ra", "mode": "aws-roles-anywhere", "status": "active" }
            ])
        );
    }

    /// The longest source spelling still leaves a gap before STATUS, and no env or region
    /// column is printed.
    #[cfg(unix)]
    #[test]
    fn list_text_has_three_aligned_columns() {
        use credsd_core::rpc::CredentialSourceType::AwsRolesAnywhere;
        let manifests = [manifest("dev", &[("ra", AwsRolesAnywhere)])];
        let text = list_text(&list_rows(&manifests));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0].split_whitespace().collect::<Vec<_>>(),
            ["CREDENTIAL", "MODE", "STATUS"]
        );
        assert_eq!(
            lines[1].split_whitespace().collect::<Vec<_>>(),
            ["ra", "aws-roles-anywhere", "active"]
        );
        assert_eq!(lines[0].find("STATUS"), lines[1].find("active"));
    }

    #[cfg(unix)]
    #[test]
    fn list_text_escapes_daemon_supplied_names() {
        use credsd_core::rpc::CredentialSourceType::AwsIdcSso;
        let manifests = [manifest("dev", &[("evil\x1b[2J", AwsIdcSso)])];
        assert!(!list_text(&list_rows(&manifests)).contains('\x1b'));
    }
}
