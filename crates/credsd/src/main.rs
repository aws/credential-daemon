#![allow(
    clippy::print_stdout,
    reason = "CLI binary — stdout is the output channel"
)]
use clap::{Parser, Subcommand, ValueEnum};
use credsd_core::log::escape_terminal;
use credsd_core::rpc::{LogoutResult, ProviderLogout};
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

fn names_an_environment(args: impl IntoIterator<Item = std::ffi::OsString>) -> bool {
    args.into_iter()
        .skip(1)
        .take_while(|arg| arg != "--")
        .any(|arg| {
            arg == "--environment"
                || arg == "--env"
                || arg
                    .to_str()
                    .is_some_and(|s| s.starts_with("--environment=") || s.starts_with("--env="))
        })
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
enum TagAction {
    /// Add or overwrite tags.
    Set {
        /// The credential to tag.
        #[arg(long, visible_alias = "name")]
        credential: String,
        /// `KEY=VALUE` pairs.
        #[arg(required = true, value_name = "KEY=VALUE", value_parser = parse_tag_pair)]
        pairs: Vec<(String, String)>,
    },
    /// Remove tags by key. A key the credential lacks is not an error.
    Unset {
        /// The credential to untag.
        #[arg(long, visible_alias = "name")]
        credential: String,
        /// Keys to remove.
        #[arg(required = true, value_name = "KEY")]
        keys: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "parsed once per process; boxing the provider would only complicate matching"
)]
enum Commands {
    /// Bootstrap a credential (provider config + initial auth). Creates only the credential. If no
    /// provider is given, re-authenticates using saved config.
    Bootstrap {
        /// Credential to create or replace.
        #[arg(
            long,
            visible_alias = "name",
            required_unless_present = "name_prefix",
            conflicts_with = "name_prefix"
        )]
        credential: Option<String>,

        /// aws-login only: name the credential after the identity that signs in, under this
        /// prefix (e.g. `login.`). The final name is printed.
        #[arg(long)]
        name_prefix: Option<String>,

        /// A `KEY=VALUE` tag for the credential; repeatable. Given, the tags replace the
        /// credential's set; absent, a replaced credential keeps its tags.
        #[arg(long = "tag", global = true, value_name = "KEY=VALUE", value_parser = parse_tag_pair)]
        tags: Vec<(String, String)>,

        #[command(subcommand)]
        provider: Option<BootstrapProvider>,
    },
    /// Re-authenticate a credential whose unattended renewal is spent (SSO session expired, MFA
    /// session lapsed). Runs the interactive flow its source requires and persists the result
    /// so the daemon can serve again.
    Login {
        /// The credential to re-authenticate.
        #[arg(long, visible_alias = "name")]
        credential: String,
    },
    /// Sign a credential out. Its sealed session is deleted and its entry is kept, so `creds
    /// login --credential <name>` signs it in again. Not gated.
    Logout {
        /// The credential to sign out.
        #[arg(long)]
        credential: String,
    },
    /// Fetch credentials from the daemon (for credential_process / shell eval).
    ///
    /// `--credential <cred>` fetches that credential by name, under its own restrictions.
    Get {
        /// The credential to fetch.
        #[arg(long, visible_alias = "name")]
        credential: String,
        /// With --role, another account of an aws-idc-sso credential's sign-in: its stored one, or
        /// one it allows (--allow-role at bootstrap).
        #[arg(long, requires = "role")]
        account: Option<String>,
        /// With --account, the role to fetch in that account.
        #[arg(long, requires = "account")]
        role: Option<String>,
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
        /// Only credentials carrying this tag: `KEY=VALUE`, or `KEY` for any value; repeatable.
        #[arg(long = "tag", value_name = "KEY[=VALUE]", value_parser = parse_tag_condition)]
        tags: Vec<(String, Option<String>)>,
    },
    /// Set or unset a credential's tags. Tags are labels for `list --tag`, not secrets and not
    /// authorization.
    Tag {
        #[command(subcommand)]
        action: TagAction,
    },
    /// Remove a credential and its encrypted data.
    Remove {
        /// Credential to remove, along with its encrypted data.
        #[arg(long, visible_alias = "name")]
        credential: String,
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
    /// credential; SSO and `credential_process` profiles are skipped.
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
        /// Another account and role of the sign-in that `creds get --account --role` may fetch.
        /// Repeatable. Without any, a new credential serves only its account and role; a
        /// re-bootstrap keeps the stored list.
        #[arg(long = "allow-role", value_name = "ACCOUNT_ID:ROLE_NAME", value_parser = parse_role_pair)]
        allow_role: Vec<credsd_core::config::RolePair>,
        /// Clear the credential's allowed roles, leaving only its stored account and role.
        /// Without this and without `--allow-role`, a re-bootstrap keeps the stored list.
        #[arg(long, conflicts_with = "allow_role")]
        clear_allowed_roles: bool,
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
        /// brokered unattended — authenticate with `creds login --credential <name>`.
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
    if names_an_environment(std::env::args_os()) {
        eprintln!(
            "error: --environment is not supported; name a credential with --credential <NAME> (or --name <NAME>)"
        );
        return ExitCode::from(2);
    }
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
    // dispatch returns.
    let succeeded = |r: credsd_core::error::Result<()>| r.map(|()| ExitCode::SUCCESS);

    let result = match cli.command {
        Commands::Login { credential } => succeeded(cmd_login(credential).await),
        Commands::Logout { credential } => cmd_logout(credential).await,
        Commands::Bootstrap {
            credential,
            name_prefix,
            tags,
            provider,
        } => succeeded(cmd_bootstrap(credential, name_prefix, tags, provider).await),
        Commands::Get {
            credential,
            account,
            role,
            format,
            agentic,
        } => succeeded(
            cmd_get(
                credential,
                account.zip(role),
                format,
                claimed_identity(agentic),
            )
            .await,
        ),
        Commands::Config { action } => match action {
            ConfigAction::Path => {
                print!(
                    "{}",
                    credsd_core::config::platform::caller_config_path_for_current_user().display()
                );
                Ok(ExitCode::SUCCESS)
            }
        },
        Commands::List { format, tags } => succeeded(cmd_list(&format, tags).await),
        Commands::Tag { action } => succeeded(cmd_tag(action).await),
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
        Commands::Remove { credential, force } => succeeded(cmd_remove(credential, force).await),
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

/// `creds import` — parse the AWS shared-credentials file client-side, then seal each discovered
/// profile through one `credential/import` call. The client never opens the keystore.
#[cfg(unix)]
async fn cmd_import(source: ImportSourceCmd) -> credsd_core::error::Result<()> {
    use credsd_core::config::platform;
    use credsd_core::import::{discover_import_profiles, ImportSource, RegionInputs};
    use credsd_core::rpc::{
        uds, ImportOutcome, ImportParams, ImportStatus, METHOD_CREDENTIAL_IMPORT,
    };

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
    let mut imported = 0usize;
    for profile in profiles {
        let params = ImportParams { profile, dry_run };
        // An import over sealed data left behind is gated. Approving grants one re-send of this
        // exact call, so a Touch ID approval here retries at once.
        let outcome: ImportOutcome =
            match uds::call(&socket, METHOD_CREDENTIAL_IMPORT, &params, None).await {
                Err(credsd_core::error::DaemonError::ApprovalRequired(challenge)) => {
                    if !presence::satisfy(&challenge).await? {
                        return Err(credsd_core::error::DaemonError::config(format!(
                            "not imported: approve request {}, then re-run this import",
                            challenge.id
                        )));
                    }
                    uds::call(&socket, METHOD_CREDENTIAL_IMPORT, &params, None).await?
                }
                other => other?,
            };
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
    credential: Option<String>,
    name_prefix: Option<String>,
    tags: Vec<(String, String)>,
    provider: Option<BootstrapProvider>,
) -> credsd_core::error::Result<()> {
    use credsd_client::{ProfileBootstrapParams, ProfileLoginParams};
    use credsd_core::config::platform;

    // No `ensure_config_dir()`: the daemon creates and owns `callers/<uid>/`, and a client that
    // pre-created it would either fail on the daemon-owned parent or leave a directory with the
    // wrong owner for the daemon to then refuse (Req 15).
    let socket = platform::client_socket_path();

    let tags = (!tags.is_empty()).then(|| unique_keys(tags)).transpose()?;
    match provider {
        None if tags.is_some() => Err(credsd_core::error::DaemonError::config(
            "--tag needs a provider; use 'creds tag set' to tag an existing credential",
        )),
        None => {
            let credential = credential.ok_or_else(|| {
                credsd_core::error::DaemonError::config(
                    "--name-prefix needs a provider; give --credential to re-authenticate",
                )
            })?;
            let params = ProfileLoginParams {
                credential,
                request_id: None,
            };
            send_login_rpc(&socket, &params).await
        }
        Some(p) => {
            let params = ProfileBootstrapParams {
                credential,
                name_prefix,
                provider: build_provider_params(p)?,
                tags,
                request_id: None,
            };
            let result = send_bootstrap_rpc(&socket, &params).await?;
            if let (Some(name), Some(who)) = (&result.credential, &result.identity) {
                eprintln!(
                    "Saved credential '{}', signed in as {} {} in account {}.",
                    credsd_core::log::escape_terminal(name),
                    credsd_core::log::escape_terminal(&who.kind),
                    credsd_core::log::escape_terminal(&who.name),
                    credsd_core::log::escape_terminal(&who.account)
                );
            }
            Ok(())
        }
    }
}

#[cfg(not(unix))]
async fn cmd_bootstrap(
    _credential: Option<String>,
    _name_prefix: Option<String>,
    _tags: Vec<(String, String)>,
    _provider: Option<BootstrapProvider>,
) -> credsd_core::error::Result<()> {
    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform",
    ))
}

/// `creds login` — thin relay to `credential/login` on the daemon.
#[cfg(unix)]
async fn cmd_login(credential: String) -> credsd_core::error::Result<()> {
    use credsd_client::ProfileLoginParams;
    use credsd_core::config::platform;

    let socket = platform::client_socket_path();
    let params = ProfileLoginParams {
        credential,
        request_id: None,
    };
    send_login_rpc(&socket, &params).await
}

#[cfg(not(unix))]
async fn cmd_login(_credential: String) -> credsd_core::error::Result<()> {
    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform",
    ))
}

/// `ACCOUNT_ID:ROLE_NAME`, each side checked by the rules a stored pair and a request's pair
/// share. A second `:` lands in the role, which refuses it.
fn parse_role_pair(value: &str) -> Result<credsd_core::config::RolePair, String> {
    let (account_id, role_name) = value
        .split_once(':')
        .ok_or("expected ACCOUNT_ID:ROLE_NAME")?;
    credsd_core::config::check_account_id(account_id)?;
    credsd_core::config::check_role_name(role_name)?;
    Ok(credsd_core::config::RolePair {
        account_id: account_id.to_owned(),
        role_name: role_name.to_owned(),
    })
}

/// What `creds logout` prints for the daemon's answer: a line for stdout, or, when SSO could not
/// end the session, a warning for stderr and exit code 1.
fn logout_report(credential: &str, result: &LogoutResult) -> Result<String, String> {
    match &result.provider {
        ProviderLogout::None => Ok(format!("{credential} was already signed out")),
        ProviderLogout::Ended => Ok(format!(
            "signed out of {credential}; the access-portal session ended. Run \
             `creds login --credential {credential}` to sign in again"
        )),
        ProviderLogout::TokenRejected => Ok(format!(
            "signed out of {credential}; its token no longer works at SSO, but the access-portal \
             session may still be live. Run `creds login --credential {credential}` to sign in \
             again"
        )),
        ProviderLogout::LocalOnly => Ok(format!(
            "signed out of {credential}; run `creds login --credential {credential}` to sign in again"
        )),
        ProviderLogout::Failed {
            start_url,
            access_token_expires_at,
        } => {
            let token = access_token_expires_at.as_deref().map_or(String::new(), |at| {
                format!(" The access token stays valid until {at}; the SSO session may last longer.")
            });
            Err(format!(
                "warning: signed out of {credential} here, but SSO did not end the session, which \
                 may still be live. To end the SSO session, sign out at {start_url}.{token}"
            ))
        }
    }
}

/// Exits 1 with the warning on stderr when SSO could not end the session: the error-on-stderr
/// convention of the exit-code table, though the local session is gone.
#[cfg(unix)]
async fn cmd_logout(credential: String) -> credsd_core::error::Result<ExitCode> {
    let socket = credsd_core::config::platform::client_socket_path();
    let result = credsd_client::credential_logout(&socket, &credential).await?;
    Ok(match logout_report(&credential, &result) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(warning) => {
            eprintln!("{warning}");
            ExitCode::FAILURE
        }
    })
}

#[cfg(not(unix))]
async fn cmd_logout(_credential: String) -> credsd_core::error::Result<ExitCode> {
    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform",
    ))
}

/// Collects `pairs` into a map, refusing a key given twice by name (credential-tags 3.7).
fn unique_keys<V>(
    pairs: Vec<(String, V)>,
) -> credsd_core::error::Result<std::collections::BTreeMap<String, V>> {
    let mut map = std::collections::BTreeMap::new();
    for (k, v) in pairs {
        // Keys fold to lowercase, so `Team` and `team` are one key given twice.
        if map.insert(k.to_ascii_lowercase(), v).is_some() {
            return Err(credsd_core::error::DaemonError::config(format!(
                "tag {k:?} is given twice"
            )));
        }
    }
    Ok(map)
}

/// `KEY=VALUE`. The grammar itself is the daemon's to enforce; this only splits.
fn parse_tag_pair(value: &str) -> Result<(String, String), String> {
    value
        .split_once('=')
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .ok_or_else(|| "expected KEY=VALUE".to_owned())
}

/// `KEY=VALUE`, or a bare `KEY` that matches any value.
fn parse_tag_condition(value: &str) -> Result<(String, Option<String>), String> {
    Ok(match value.split_once('=') {
        Some((k, v)) => (k.to_owned(), Some(v.to_owned())),
        None => (value.to_owned(), None),
    })
}

/// `creds tag set|unset` — thin relay to `credential/tag`.
#[cfg(unix)]
async fn cmd_tag(action: TagAction) -> credsd_core::error::Result<()> {
    let params = match action {
        TagAction::Set { credential, pairs } => credsd_core::rpc::CredentialTagParams {
            credential,
            set: unique_keys(pairs)?,
            unset: Vec::new(),
        },
        TagAction::Unset { credential, keys } => credsd_core::rpc::CredentialTagParams {
            credential,
            set: credsd_core::tags::Tags::new(),
            unset: unique_keys(keys.into_iter().map(|k| (k, ())).collect())?
                .into_keys()
                .collect(),
        },
    };
    let socket = credsd_core::config::platform::client_socket_path();
    credsd_client::credential_tag(&socket, &params)
        .await
        .map(drop)
}

#[cfg(not(unix))]
async fn cmd_tag(_action: TagAction) -> credsd_core::error::Result<()> {
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
            allow_role,
            clear_allowed_roles,
        } => Ok(ProviderParams::AwsIdcSso(ProviderParamsSso {
            start_url,
            sso_region,
            account_id,
            role_name,
            identity_type: identity_type_str(identity_type),
            // Absent keeps the stored list; `[]` clears it. Only an explicit flag says which,
            // so no flag at all has to send nothing (credential-retrieval-api Req 17 AC 11).
            allowed_roles: if clear_allowed_roles {
                Some(Vec::new())
            } else if allow_role.is_empty() {
                None
            } else {
                Some(allow_role)
            },
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
) -> credsd_core::error::Result<credsd_client::BootstrapResult> {
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

/// Fetch one named credential through the daemon and format it for the caller.
#[cfg(unix)]
async fn cmd_get(
    credential: String,
    pair: Option<(String, String)>,
    format: Option<String>,
    claimed: ClaimedIdentity,
) -> credsd_core::error::Result<()> {
    use credsd_core::config::platform;
    use credsd_core::error::DaemonError;
    use credsd_core::get;
    use std::io::IsTerminal;

    let fmt = get::OutputFormat::from_str_opt(format.as_deref())?;
    let socket = platform::client_socket_path();
    let fetch = || async {
        if let Some((account_id, role_name)) = &pair {
            credsd_core::credential_resolve::fetch_role_credential(
                &socket,
                None,
                Some(&credential),
                account_id,
                role_name,
                claimed,
            )
            .await
        } else {
            credsd_core::credential_resolve::fetch_credential(&socket, &credential, claimed).await
        }
    };

    let creds = match fetch().await {
        Ok(served) => served,
        Err(DaemonError::ReauthRequired(_)) if std::io::stdin().is_terminal() => {
            let login_params = credsd_client::ProfileLoginParams {
                credential: credential.clone(),
                request_id: None,
            };
            send_login_rpc(&socket, &login_params).await?;
            fetch().await?
        }
        Err(e) => return Err(e),
    };
    let token_var = match &creds.data {
        credsd_core::credentials::CredentialData::AccessToken { .. }
            if get::names_a_variable(fmt) =>
        {
            get::token_export_name(&credential)
        }
        _ => String::new(),
    };

    let output = get::format_credentials(&creds, fmt, &token_var)?;
    println!("{}", output);
    Ok(())
}

/// The format argument is still validated before the transport error, so a bad `--format`
/// is reported as a bad `--format` on every platform rather than being masked by the
/// missing daemon.
#[cfg(not(unix))]
async fn cmd_get(
    credential: String,
    pair: Option<(String, String)>,
    format: Option<String>,
    claimed: ClaimedIdentity,
) -> credsd_core::error::Result<()> {
    use credsd_core::get;

    let _ = get::OutputFormat::from_str_opt(format.as_deref())?;
    let _ = (credential, pair, claimed);

    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform \
         (named pipe transport pending).",
    ))
}

/// List every credential this uid holds, once each, with its kind and session status.
///
/// One RPC: `credential/list` enumerates credentials,
/// and carries each one's kind. No local status computation — the daemon owns the sealed
/// tokens, so it is the only party that can read their expiry.
#[cfg(unix)]
async fn cmd_list(
    format: &str,
    tags: Vec<(String, Option<String>)>,
) -> credsd_core::error::Result<()> {
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
    let rows = credsd_client::list(
        &socket,
        None,
        (!tags.is_empty()).then(|| unique_keys(tags)).transpose()?,
    )
    .await?
    .credentials;

    if rows.is_empty() {
        if format == "json" {
            println!("[]");
        } else {
            eprintln!("No credentials configured. Run 'creds bootstrap' to get started.");
        }
        return Ok(());
    }

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&list_json(&rows))?);
    } else {
        print!("{}", list_text(&rows));
    }
    Ok(())
}

#[cfg(unix)]
fn list_json(rows: &[credsd_core::rpc::CredentialSummary]) -> serde_json::Value {
    rows.iter()
        .map(|c| {
            serde_json::json!({
                "name": c.credential,
                "kind": c.kind.as_str(),
                "status": c.status.as_str(),
                "tags": c.tags,
            })
        })
        .collect()
}

/// Columns are at least 15 and 19 wide (KIND fits `session_credentials`) and grow to the
/// longest escaped value, so a long name such as `login.<account>-role-<role>` keeps the
/// columns after it aligned.
#[cfg(unix)]
fn list_text(rows: &[credsd_core::rpc::CredentialSummary]) -> String {
    let cells: Vec<[String; 4]> = rows
        .iter()
        .map(|entry| {
            let tags = entry.tags.iter().map(|(k, v)| format!("{k}={v}"));
            [
                escape_terminal(entry.credential.as_str()).to_string(),
                escape_terminal(entry.kind.as_str()).to_string(),
                escape_terminal(entry.status.as_str()).to_string(),
                escape_terminal(&tags.collect::<Vec<_>>().join(" ")).to_string(),
            ]
        })
        .collect();
    let width = |i: usize, min: usize| {
        cells
            .iter()
            .filter_map(|c| c.get(i))
            .map(|cell| cell.chars().count())
            .fold(min, usize::max)
    };
    let (name_w, kind_w, status_w) = (width(0, 15), width(1, 19), width(2, 6));
    let mut out = String::new();
    let header = ["CREDENTIAL", "KIND", "STATUS", "TAGS"].map(str::to_owned);
    for [name, kind, status, tags] in std::iter::once(&header).chain(&cells) {
        let line = format!("{name:<name_w$} {kind:<kind_w$} {status:<status_w$} {tags}");
        // Only padding is trimmed; a value may end in a space.
        out.push_str(if tags.is_empty() {
            line.trim_end()
        } else {
            &line
        });
        out.push('\n');
    }
    out
}

/// `list` enumerates through the daemon, and no daemon transport exists on this platform yet.
#[cfg(not(unix))]
async fn cmd_list(
    format: &str,
    _tags: Vec<(String, Option<String>)>,
) -> credsd_core::error::Result<()> {
    let _ = format;
    Err(credsd_core::error::DaemonError::config(
        "a running daemon is not yet supported on this platform \
         (named pipe transport pending).",
    ))
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

/// Delete a credential and its sealed material, on approval.
#[cfg(unix)]
async fn remove_credential(socket: &std::path::Path, name: &str) -> credsd_core::error::Result<()> {
    performed_on_approval(
        credsd_client::credential_remove(socket, name)
            .await
            .map(|_| ()),
    )
    .await
}

/// Remove one named credential through the daemon's presence-gated mutation.
#[cfg(unix)]
async fn cmd_remove(credential: String, force: bool) -> credsd_core::error::Result<()> {
    use credsd_core::config::platform;
    use std::io::{self, BufRead, Write};

    let socket = platform::client_socket_path();
    if !force {
        eprint!(
            "Remove credential '{}' and its encrypted data? [y/N] ",
            credential
        );
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        if !line.trim().eq_ignore_ascii_case("y") {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }
    remove_credential(&socket, &credential).await?;
    eprintln!("Removed credential '{}' and its sealed data.", credential);
    Ok(())
}

#[cfg(not(unix))]
async fn cmd_remove(credential: String, force: bool) -> credsd_core::error::Result<()> {
    let _ = (credential, force);
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
            Commands::Get { credential, .. } => assert_eq!(credential, "ra-main"),
            _ => panic!("expected Get"),
        }
    }

    #[test]
    fn credential_selector_is_required_and_name_is_its_alias() {
        // Each command, and the arguments it needs besides the selector.
        let commands: [(&[&str], &[&str]); 6] = [
            (&["bootstrap"], &[]),
            (&["login"], &[]),
            (&["get"], &[]),
            (&["remove"], &[]),
            (&["tag", "set"], &["team=payments"]),
            (&["tag", "unset"], &["team"]),
        ];
        let argv = |command: &[&str], selector: &[&str], rest: &[&str]| {
            let mut argv = vec!["creds"];
            argv.extend(command.iter().chain(selector).chain(rest));
            Cli::try_parse_from(argv)
        };
        for (command, rest) in commands {
            assert!(argv(command, &[], rest).is_err(), "{command:?}");
            for spelling in ["--credential", "--name"] {
                assert!(
                    argv(command, &[spelling, "work"], rest).is_ok(),
                    "{command:?} {spelling}"
                );
                assert!(
                    argv(command, &[spelling, "work", "--credential", "other"], rest).is_err(),
                    "{command:?} repeats the selector"
                );
            }
        }
    }

    /// credential-tags 5.4: the tag filter exists only on `list`, and only `bootstrap` sets tags
    /// through `--tag`. Walks every command, so a new one that grows `--tag` fails here.
    #[test]
    fn only_list_and_bootstrap_take_a_tag() {
        fn walk(cmd: &clap::Command, path: String, out: &mut Vec<String>) {
            if cmd.get_arguments().any(|a| a.get_long() == Some("tag")) {
                out.push(path.clone());
            }
            for sub in cmd.get_subcommands() {
                walk(sub, format!("{path} {}", sub.get_name()), out);
            }
        }
        let mut found = Vec::new();
        walk(
            &<Cli as clap::CommandFactory>::command(),
            "creds".into(),
            &mut found,
        );
        assert_eq!(found, ["creds bootstrap", "creds list"]);
    }

    /// `bootstrap` takes exactly one of the credential selector and `--name-prefix`
    /// (`credential-only-addressing` Requirement 1.2).
    #[test]
    fn bootstrap_takes_a_selector_or_a_name_prefix_but_not_both() {
        let parse = |args: &[&str]| {
            let mut argv = vec!["creds", "bootstrap"];
            argv.extend_from_slice(args);
            Cli::try_parse_from(argv)
        };
        assert!(parse(&["--name-prefix", "login."]).is_ok());
        for spelling in ["--credential", "--name"] {
            assert!(parse(&[spelling, "work", "--name-prefix", "login."]).is_err());
        }
        assert!(parse(&[]).is_err());
    }

    proptest::proptest! {
        /// `--account` and `--role` select a pair together or not at all, as the daemon requires
        /// (Requirement 17 AC 1): either alone is refused before anything is sent.
        #[test]
        fn get_takes_account_and_role_together_or_neither(
            account in "[0-9]{12}",
            role in "[A-Za-z0-9+=,.@_-]{1,64}",
        ) {
            let get = |extra: &[&str]| {
                let mut args = vec!["credsd", "get", "--credential", "acme"];
                args.extend_from_slice(extra);
                Cli::try_parse_from(args)
            };
            // `=` keeps a role that starts with `-` a value, not a flag.
            let (account, role) = (format!("--account={account}"), format!("--role={role}"));
            proptest::prop_assert!(get(&[&account, &role]).is_ok());
            proptest::prop_assert!(get(&[&account]).is_err());
            proptest::prop_assert!(get(&[&role]).is_err());
        }

        /// Each `--allow-role ACCOUNT:ROLE` becomes one allowed pair of the credential, in order;
        /// anything missing a side or the separator is refused at parse time. Naming no pair at
        /// all sends no list, which keeps a credential's own (credential-retrieval-api Req 17
        /// AC 11), so it must never be confused with the empty list that clears one.
        #[test]
        fn bootstrap_sso_allow_role_becomes_the_allowed_pairs(
            pairs in proptest::collection::vec(("[0-9]{12}", "[A-Za-z0-9+=,.@_-]{1,64}"), 0..5),
            // Missing a side or the separator, a short or non-digit account, a role outside
            // Identity Center's characters or over 64, and a second `:` (which would land in
            // the role): each would seal a pair no request can ever match.
            malformed in proptest::prop_oneof![
                "[0-9]{12}", ":[A-Za-z]{1,8}", "[0-9]{12}:",
                "[0-9]{1,11}:[A-Za-z]{1,8}", "[0-9]{13,16}:[A-Za-z]{1,8}", "[0-9]{6}[a-z]{6}:Admin",
                "[0-9]{12}:[A-Za-z]{1,8}[/ *!]{1,3}", "[0-9]{12}:[A-Za-z]{65,70}",
                "[0-9]{12}:[A-Za-z]{1,8}:[A-Za-z]{1,8}",
            ],
        ) {
            let base = [
                "credsd", "bootstrap", "--credential", "acme", "aws-idc-sso",
                "--start-url", "https://example.awsapps.com/start", "--sso-region", "us-east-1",
            ];
            let flags: Vec<String> = pairs.iter().map(|(a, r)| format!("{a}:{r}")).collect();
            let mut args: Vec<&str> = base.to_vec();
            let flags: Vec<String> = flags.iter().map(|f| format!("--allow-role={f}")).collect();
            args.extend(flags.iter().map(String::as_str));
            let Commands::Bootstrap { provider: Some(provider), .. } = Cli::try_parse_from(&args).expect("parses").command else {
                return Err(proptest::test_runner::TestCaseError::fail("expected Bootstrap"));
            };
            let Ok(credsd_client::ProviderParams::AwsIdcSso(sso)) = build_provider_params(provider) else {
                return Err(proptest::test_runner::TestCaseError::fail("expected aws-idc-sso params"));
            };
            match sso.allowed_roles {
                None => proptest::prop_assert!(pairs.is_empty(), "a named pair always sends a list"),
                Some(list) => {
                    let got: Vec<(String, String)> =
                        list.into_iter().map(|p| (p.account_id, p.role_name)).collect();
                    proptest::prop_assert_eq!(&got, &pairs);
                    proptest::prop_assert!(!got.is_empty(), "no pair sends no list, never an empty one");
                }
            }

            let mut bad: Vec<&str> = base.to_vec();
            let malformed = format!("--allow-role={malformed}");
            bad.push(&malformed);
            proptest::prop_assert!(Cli::try_parse_from(&bad).is_err());
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

    fn try_parse(args: &[&str]) -> Result<Commands, clap::Error> {
        let argv = std::iter::once("credsd").chain(args.iter().copied());
        Cli::try_parse_from(argv).map(|cli| cli.command)
    }

    const SSO_BOOTSTRAP: [&str; 8] = [
        "bootstrap",
        "--credential",
        "dev",
        "aws-idc-sso",
        "--start-url",
        "https://example.awsapps.com/start",
        "--sso-region",
        "us-west-2",
    ];

    #[test]
    fn bootstrap_takes_repeatable_tags() {
        let mut args = SSO_BOOTSTRAP.to_vec();
        args.extend(["--tag", "team=payments", "--tag", "stage=prod"]);
        try_parse(&args).expect("--tag is repeatable on bootstrap");
    }

    /// Bootstrap sets tags, so a bare key has nothing to set: refused as a bad value, not as an
    /// unknown flag.
    #[test]
    fn bootstrap_tag_needs_a_value() {
        let mut args = SSO_BOOTSTRAP.to_vec();
        args.extend(["--tag", "team"]);
        let err = try_parse(&args).expect_err("a bare key was accepted");
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation, "{err}");
    }

    #[test]
    fn tag_set_and_unset_parse() {
        try_parse(&[
            "tag",
            "set",
            "--credential",
            "dev",
            "team=payments",
            "stage=prod",
        ])
        .expect("tag set");
        try_parse(&["tag", "unset", "--credential", "dev", "team", "stage"]).expect("tag unset");
    }

    proptest::proptest! {
        /// Distinct keys pass through unchanged; any repeat, in any case, is refused naming the
        /// key as the repeat spelled it, since keys fold to lowercase (spec 1.4, 3.7).
        #[test]
        fn a_repeated_tag_key_is_refused_by_name(
            pairs in proptest::collection::btree_map("[a-z0-9][a-z0-9._-]{0,20}", "[ -~]{0,20}", 0..8),
            dup in proptest::option::of(proptest::prelude::any::<proptest::sample::Index>()),
            upper in proptest::prelude::any::<bool>(),
        ) {
            let mut list: Vec<(String, String)> = pairs.clone().into_iter().collect();
            match dup.filter(|_| !list.is_empty()) {
                None => proptest::prop_assert_eq!(unique_keys(list).expect("distinct"), pairs),
                Some(i) => {
                    let (k, _) = list[i.index(list.len())].clone();
                    let k = if upper { k.to_ascii_uppercase() } else { k };
                    list.push((k.clone(), "again".into()));
                    let err = unique_keys(list).expect_err("repeat accepted").to_string();
                    proptest::prop_assert!(err.contains(&format!("{k:?}")), "{err}");
                }
            }
        }
    }

    #[test]
    fn list_takes_a_tag_filter_with_key_only_entries() {
        try_parse(&["list", "--tag", "team=payments", "--tag", "stage"]).expect("list --tag");
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

    /// Clearing the allowed list is its own flag, because no `--allow-role` means "keep what the
    /// credential has" (credential-retrieval-api Req 17 AC 11) and so cannot also mean "empty it".
    /// Asking for both at once is a parse error rather than a silent winner.
    #[test]
    fn bootstrap_sso_clear_allowed_roles_sends_an_empty_list() {
        let allowed = |args: &[&str]| {
            let base = [
                "bootstrap",
                "--credential",
                "dev",
                "aws-idc-sso",
                "--start-url",
                "https://example.awsapps.com/start",
                "--sso-region",
                "us-west-2",
            ];
            let Commands::Bootstrap {
                provider: Some(provider),
                ..
            } = parse(&[&base[..], args].concat())
            else {
                panic!("expected a bootstrap with a provider");
            };
            let Ok(credsd_client::ProviderParams::AwsIdcSso(sso)) = build_provider_params(provider)
            else {
                panic!("expected aws-idc-sso params");
            };
            sso.allowed_roles
        };
        assert_eq!(allowed(&[]), None, "no flag keeps the stored list");
        assert_eq!(
            allowed(&["--clear-allowed-roles"]),
            Some(Vec::new()),
            "the flag clears it"
        );
        assert_eq!(
            allowed(&["--allow-role", "111111111111:Admin"])
                .expect("a named pair sends a list")
                .len(),
            1
        );

        let both = [
            "credsd",
            "bootstrap",
            "--credential",
            "dev",
            "aws-idc-sso",
            "--start-url",
            "https://example.awsapps.com/start",
            "--sso-region",
            "us-west-2",
            "--allow-role",
            "111111111111:Admin",
            "--clear-allowed-roles",
        ];
        assert!(
            Cli::try_parse_from(both).is_err(),
            "allowing a pair and clearing the list are contradictory"
        );
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
    fn logout_names_one_credential() {
        match parse(&["logout", "--credential", "work"]) {
            Commands::Logout { credential } => assert_eq!(credential, "work"),
            _ => panic!("expected Logout"),
        }
        assert!(
            Cli::try_parse_from(["creds", "logout"]).is_err(),
            "logout must name the credential"
        );
    }

    /// AC 17: only `ended`, an accepted `Logout`, may say the access-portal session ended.
    #[test]
    fn an_ended_logout_says_the_access_portal_session_ended() {
        let Ok(line) = logout_report("work", &LogoutResult::from(ProviderLogout::Ended)) else {
            panic!("an ended provider logout must exit zero");
        };
        assert!(line.contains("signed out of work"), "{line}");
        assert!(line.contains("the access-portal session ended"), "{line}");
        assert!(!line.contains("may still be live"), "{line}");
    }

    /// AC 17: `token_rejected` says only that the token no longer works at SSO and that the
    /// access-portal session may still be live, never that it ended.
    #[test]
    fn a_token_rejected_logout_says_the_token_no_longer_works_and_the_session_may_be_live() {
        let Ok(line) = logout_report("work", &LogoutResult::from(ProviderLogout::TokenRejected))
        else {
            panic!("a token_rejected provider logout must exit zero");
        };
        assert!(line.contains("signed out of work"), "{line}");
        assert!(line.contains("token no longer works at SSO"), "{line}");
        assert!(
            line.contains("access-portal session may still be live"),
            "{line}"
        );
        assert!(!line.contains("session ended"), "{line}");
    }

    #[test]
    fn logout_says_whether_it_signed_out_and_warns_when_the_provider_logout_failed() {
        assert_eq!(
            logout_report("work", &LogoutResult::from(ProviderLogout::LocalOnly)),
            Ok("signed out of work; run `creds login --credential work` to sign in again".into())
        );
        assert_eq!(
            logout_report("work", &LogoutResult::from(ProviderLogout::None)),
            Ok("work was already signed out".into())
        );
        let url = "https://example.awsapps.com/start";
        for expires in [Some("2999-01-01T00:00:00Z"), None] {
            let failed = LogoutResult::from(ProviderLogout::Failed {
                start_url: url.into(),
                access_token_expires_at: expires.map(Into::into),
            });
            let Err(warning) = logout_report("work", &failed) else {
                panic!("a failed provider logout must exit non-zero");
            };
            assert!(warning.contains("signed out of work here"), "{warning}");
            assert!(
                warning.contains(&format!("To end the SSO session, sign out at {url}")),
                "{warning}"
            );
            // The expiry is the access token's, never presented as the session's end.
            match expires {
                Some(at) => {
                    assert!(
                        warning.contains(&format!("The access token stays valid until {at}")),
                        "{warning}"
                    );
                    assert!(
                        warning.contains("the SSO session may last longer"),
                        "{warning}"
                    );
                    assert_eq!(warning.matches(at).count(), 1, "{warning}");
                }
                None => assert!(!warning.contains("until"), "{warning}"),
            }
        }
    }

    #[test]
    fn login_names_one_credential() {
        match parse(&["login", "--credential", "work"]) {
            Commands::Login { credential } => assert_eq!(credential, "work"),
            _ => panic!("expected Login"),
        }
    }

    /// Login and bootstrap are credential-addressed: `--env` is refused rather than ignored, and
    /// a credential is required (credential-retrieval-api Requirement 15 AC 10).
    #[test]
    fn login_and_bootstrap_take_a_credential_and_refuse_an_env() {
        for argv in [
            &["creds", "login"][..],
            &["creds", "login", "--env", "work"],
            &[
                "creds",
                "bootstrap",
                "--env",
                "work",
                "jwt",
                "--token-file",
                "t",
            ],
        ] {
            assert!(Cli::try_parse_from(argv).is_err(), "{argv:?}");
        }
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
    fn config_only_exposes_path() {
        assert!(matches!(
            parse(&["config", "path"]),
            Commands::Config {
                action: ConfigAction::Path
            }
        ));
        for action in ["set", "get", "unset", "keys"] {
            match Cli::try_parse_from(["credsd", "config", action]) {
                Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand),
                Ok(_) => panic!("config {action} unexpectedly parsed"),
            }
        }
    }

    #[test]
    fn list_default_format_is_text() {
        let cmd = parse(&["list"]);
        match cmd {
            Commands::List { format, .. } => assert_eq!(format, "text"),
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn list_json_format_parses() {
        let cmd = parse(&["list", "--format", "json"]);
        match cmd {
            Commands::List { format, .. } => assert_eq!(format, "json"),
            _ => panic!("expected List with json format"),
        }
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
    fn environment_flags_are_detected_exactly() {
        for flag in ["--environment", "--env", "--environment=dev", "--env=dev"] {
            assert!(names_an_environment(["get".into(), flag.into()]));
        }
        assert!(!names_an_environment([
            "get".into(),
            "--env-var=TOKEN".into()
        ]));
        assert!(!names_an_environment([
            "get".into(),
            "--".into(),
            "--env".into()
        ]));
    }

    #[cfg(unix)]
    fn summary(name: &str) -> credsd_core::rpc::CredentialSummary {
        credsd_core::rpc::CredentialSummary {
            environment: None,
            credential: name.to_owned(),
            kind: credsd_core::credentials::CredentialType::SessionCredentials,
            source: credsd_core::rpc::CredentialSourceType::AwsRolesAnywhere,
            status: credsd_core::rpc::SessionStatus::Active,
            tags: credsd_core::tags::Tags::new(),
        }
    }

    /// Requirement 4.7: `--format json` rows carry `tags`, `{}` when there are none.
    #[cfg(unix)]
    #[test]
    fn list_json_is_a_flat_array_of_name_kind_status_and_tags() {
        assert_eq!(
            list_json(&[summary("ra")]),
            serde_json::json!([
                { "name": "ra", "kind": "session_credentials", "status": "active", "tags": {} }
            ])
        );
    }

    /// The longest kind spelling still leaves a gap before STATUS, and no env or region
    /// column is printed.
    #[cfg(unix)]
    #[test]
    fn list_text_has_four_aligned_columns() {
        let text = list_text(&[summary("ra")]);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0].split_whitespace().collect::<Vec<_>>(),
            ["CREDENTIAL", "KIND", "STATUS", "TAGS"]
        );
        assert_eq!(
            lines[1].split_whitespace().collect::<Vec<_>>(),
            ["ra", "session_credentials", "active"]
        );
        assert_eq!(lines[0].find("STATUS"), lines[1].find("active"));
    }

    /// A name longer than the minimum width widens its column instead of pushing KIND and
    /// STATUS out of line; short names keep the minimum widths.
    #[cfg(unix)]
    #[test]
    fn list_text_widens_for_a_long_name() {
        let long = "login.123456789012-role-AWSReservedSSO_PowerUserAccess_-2509f939";
        let text = list_text(&[summary("ra"), summary(long)]);
        let lines: Vec<&str> = text.lines().collect();
        let kind_at = lines[0].find("KIND").unwrap();
        let status_at = lines[0].find("STATUS").unwrap();
        assert_eq!(kind_at, long.len() + 1);
        for line in &lines[1..] {
            assert_eq!(line.find("session_credentials"), Some(kind_at), "{line}");
            assert_eq!(line.find("active"), Some(status_at), "{line}");
        }
        assert_eq!(list_text(&[summary("ra")]).find("KIND"), Some(16));
    }

    #[cfg(unix)]
    proptest::proptest! {
        /// Requirement 4.7: every row's TAGS cell starts under the header and holds the row's
        /// tags as `key=value` pairs in key order, whatever the names, statuses, and tags.
        #[test]
        fn list_text_shows_each_rows_tags_under_tags(
            rows in proptest::collection::vec((
                "[a-z0-9][a-z0-9._-]{0,40}",
                proptest::sample::select(vec![
                    credsd_core::rpc::SessionStatus::Active,
                    credsd_core::rpc::SessionStatus::NoSession,
                    credsd_core::rpc::SessionStatus::DecryptFailed,
                ]),
                proptest::collection::btree_map("[a-z0-9][a-z0-9._-]{0,10}", "[ -~]{0,12}", 0..4),
            ), 1..6)
        ) {
            let rows: Vec<_> = rows
                .into_iter()
                .map(|(name, status, tags)| credsd_core::rpc::CredentialSummary { status, tags, ..summary(&name) })
                .collect();
            let text = list_text(&rows);
            let lines: Vec<&str> = text.lines().collect();
            let at = lines[0].find("TAGS").expect("TAGS header");
            proptest::prop_assert_eq!(lines[0].get(at..), Some("TAGS"));
            for (row, line) in rows.iter().zip(&lines[1..]) {
                let want = row.tags.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" ");
                proptest::prop_assert_eq!(line.get(at..).unwrap_or(""), want.as_str(), "{}", line);
                if !want.is_empty() {
                    proptest::prop_assert_eq!(line.get(at.saturating_sub(1)..at), Some(" "));
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn list_text_escapes_daemon_supplied_names() {
        assert!(!list_text(&[summary("evil\x1b[2J")]).contains('\x1b'));
    }
}
