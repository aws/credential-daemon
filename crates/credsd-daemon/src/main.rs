#![allow(
    clippy::print_stdout,
    reason = "CLI binary — stdout is the output channel"
)]
//! `credsd-daemon` — the privileged, long-running credential server.
//!
//! It binds the per-uid Unix domain socket, authenticates peers by UID, and serves
//! credentials to SDK-aware tools. It also owns the service-install arms (`install` /
//! `uninstall` / `status`), which render a service definition that runs this same binary's
//! `serve`. The unprivileged client CLI (bootstrap, get, exec, run, list, …) is the
//! separate `credsd` binary.

// Re-export the core modules so this bin's own modules (`server`, `credential_store`,
// `install`, …) can keep addressing shared internals as `crate::config`, `crate::error`,
// etc., rather than spelling out `credsd_core::` at every use site.
pub use credsd_core::{config, credentials, encryption, error, providers, storage};

mod credential_store;
mod hardening;
mod install;
mod server;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::LazyLock;

/// `--version` output. The backend line is what the release build checks to prove the shipped
/// binary carries the backends it should and no others.
static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    let backends: Vec<&str> = storage::Backend::COMPILED
        .iter()
        .map(|b| b.as_str())
        .collect();
    format!(
        "{}\nstorage backends: {}",
        env!("CARGO_PKG_VERSION"),
        backends.join(", ")
    )
});

#[derive(Parser)]
#[command(
    name = "credsd",
    version,
    long_version = LONG_VERSION.as_str(),
    about = "AWS Credential Daemon (server)"
)]
struct Cli {
    /// Storage backend (e.g. data-protection-keychain, secure-enclave, tpm, file).
    /// Unset, the daemon probes for a hardware-backed backend and fails if none is found.
    #[arg(long, global = true)]
    storage_backend: Option<String>,

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

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the credential server (blocks, serves on a Unix domain socket until stopped)
    Serve {
        /// Acknowledge that the file storage backend provides no hardware protection and
        /// allow it anyway. Any process running as your uid can read the encryption key.
        #[arg(long)]
        insecure_backend: bool,
        /// Assert this is a system-service invocation; enforces that the process is running
        /// as the credsd service account. Baked in by `credsd install` (system path only).
        #[arg(long)]
        system: bool,
    },
    /// Install credsd as a system service running as the scoped 'credsd' user (requires root).
    /// On macOS, pass --user to install as a user-scoped service instead (no root required).
    Install {
        /// macOS only: install as a user-scoped LaunchAgent instead of a system daemon.
        /// WARNING: secrets will be owned by your login user. See the security prompt for details.
        #[arg(long)]
        user: bool,
        /// Skip the interactive security warning for --user installs (for scripted use).
        #[arg(long)]
        skip_security_warning: bool,
    },
    /// Remove the credsd system service (requires root; leaves config and credentials intact).
    /// On macOS, pass --user to remove a user-scoped install instead.
    Uninstall {
        /// macOS only: remove the user-scoped service instead of the system service.
        #[arg(long)]
        user: bool,
        /// Also delete the master encryption key from the keystore named by --storage-backend,
        /// quarantining the sealed credentials first. Asks for a typed confirmation. WARNING:
        /// every credential sealed under that key becomes permanently undecryptable.
        #[arg(long)]
        purge_key: bool,
    },
    /// Check service install and runtime status
    Status {
        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Initialize the keystore for the selected storage backend (mint the master key).
    /// Run this once after install before starting serve. `sudo credsd install` runs
    /// this automatically; use it manually to re-initialize after a keystore reset
    /// without reinstalling. Idempotent — safe to re-run on an already-initialized keystore.
    ///
    /// Pass --reset to perform a keystore reset after hardware key loss (TPM only on Linux).
    /// Confirms the existing key is actually unreadable, prompts for typed confirmation from
    /// the terminal, quarantines the now-undecryptable blobs, and mints a fresh key.
    /// WARNING: this permanently abandons all sealed credentials.
    Init {
        /// Perform a keystore reset after hardware key loss (TPM, Linux only). Requires a
        /// typed confirmation on /dev/tty. Use only when serve reports the key cannot be
        /// unsealed (TPM reset, PCR 7 violation, etc.).
        #[arg(long)]
        reset: bool,
    },
}

/// True for a Finder or `open` launch of `Credsd.app`: LaunchServices runs
/// `Contents/MacOS/credsd` with no arguments and no terminal, so clap's usage text would go
/// nowhere. The bundle exists to carry the daemon's entitlement, not to be launched.
fn launched_with_nothing_to_say() -> bool {
    use std::io::IsTerminal;
    std::env::args().count() == 1 && !std::io::stderr().is_terminal()
}

/// Root never reads `[log]` from config.toml. That file lives in the data dir, which install
/// chowns to the service account, so a root process honoring it would send its own log writes
/// wherever the service account points them: `init_logging` creates and appends to that path as
/// root. Non-root callers still load the config.
fn config_for_logging(
    is_root: bool,
    load: impl FnOnce() -> Option<config::DaemonConfig>,
) -> Option<config::DaemonConfig> {
    if is_root {
        None
    } else {
        load()
    }
}

#[tokio::main]
async fn main() {
    if launched_with_nothing_to_say() {
        std::process::exit(2);
    }

    let cli = Cli::parse();

    if let Some(ref dir) = cli.config_dir {
        std::env::set_var("CREDSD_CONFIG_DIR", dir);
    }

    if let Err(e) = credsd_core::config::platform::check_data_dir_override() {
        eprintln!("{e}");
        std::process::exit(1);
    }

    if cli.quiet && cli.verbose {
        eprintln!("error: --quiet and --verbose are mutually exclusive");
        std::process::exit(1);
    }

    let config = config_for_logging(nix::unistd::geteuid().is_root(), || {
        config::DaemonConfig::load().ok()
    });
    let log_config = config.as_ref().and_then(|c| c.log.as_ref());

    // For `serve` only: fall back to the platform-default log file when no source supplies one.
    // Keeps the documented default (/Library/Logs/credsd/credsd.log, /var/log/credsd/credsd.log)
    // without install baking a path it derived by reading config.toml as root.
    let serve_system_scope = match cli.command {
        Commands::Serve { system, .. } => Some(system),
        _ => None,
    };
    let serve_default_log;
    let effective_log_file = if serve_system_scope.is_some()
        && cli.log_file.is_none()
        && log_config.and_then(|c| c.file.as_deref()).is_none()
        && std::env::var_os("CREDSD_LOG_FILE").is_none()
    {
        serve_default_log = serve_default_log_path(serve_system_scope == Some(true));
        Some(serve_default_log.as_path())
    } else {
        cli.log_file.as_deref()
    };

    credsd_core::log::init_logging(
        cli.quiet,
        cli.verbose,
        effective_log_file,
        cli.log_format.as_deref(),
        log_config,
    );

    let sb = cli.storage_backend.as_deref();

    let result = match cli.command {
        Commands::Serve {
            insecure_backend,
            system,
        } => cmd_serve(sb, insecure_backend, system).await,
        Commands::Install {
            user,
            skip_security_warning,
        } => {
            let opts = install::InstallOpts {
                log_file: cli.log_file.clone(),
                storage_backend: cli.storage_backend.clone(),
                quiet: cli.quiet,
                user,
                skip_security_warning,
            };
            install::install(&opts)
        }
        Commands::Uninstall { user, purge_key } => {
            install::uninstall(cli.quiet, user, purge_key, sb)
        }
        Commands::Status { format } => cmd_status(&format),
        Commands::Init { reset } => cmd_init(sb, reset),
    };

    if let Err(e) = result {
        // The trace as well as stderr: a LaunchDaemon's plist names no StandardErrorPath, so
        // stderr alone is recorded nowhere. Escaped for the sink only — stderr is a terminal,
        // where escaping would mangle the message the operator reads.
        tracing::error!(error = %credsd_core::log::escape_log(&e), "command failed");
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// A non-system `serve` defaults inside its own data directory: the platform default is owned
/// by the `credsd` account and a daemon running as a login uid cannot write it.
#[cfg(unix)]
fn serve_default_log_path(system: bool) -> PathBuf {
    if system {
        return credsd_core::config::platform::log_file_path();
    }
    credsd_core::config::platform::user_log_file_path()
        .unwrap_or_else(credsd_core::config::platform::log_file_path)
}

#[cfg(not(unix))]
fn serve_default_log_path(_system: bool) -> PathBuf {
    credsd_core::config::platform::log_file_path()
}

/// No idle exit. Under socket activation init starts the daemon on boot or first connect, and
/// once up the resident refresh task (`store.spawn_refresh_task`) plus the per-caller warm
/// cache must survive between requests — a `Type=oneshot`/`RemainAfterExit` or an idle timeout
/// would drop the warm state and turn every gap between requests into a cold start. The daemon
/// therefore serves until stopped; activation covers the start, not a stop.
async fn cmd_serve(
    storage_backend: Option<&str>,
    insecure_backend: bool,
    system: bool,
) -> error::Result<()> {
    let backend = storage_backend.ok_or_else(|| {
        error::DaemonError::config(
            "credsd serve requires --storage-backend (e.g. --storage-backend tpm). \
             For a service install, re-run 'sudo credsd install' to bake it in. \
             For manual use, pass the flag directly.",
        )
    })?;

    #[cfg(unix)]
    require_scoped_user(system)?;

    // Before the encryption key or any credential enters memory, and after logging is up
    // so the controls' own records land. A process-global, irreversible side effect
    // belongs at the entry point rather than inside `server::start`.
    hardening::apply();

    // No global config load at startup: each caller's config is loaded lazily from
    // callers/<uid>/ on their first authorized request.
    config::ensure_config_dir()?;

    tracing::info!(transport = "uds", "starting daemon");

    server::start(backend, insecure_backend).await
}

/// Check the running uid. Root is always refused.
/// When `system` is true (set by `credsd install` for system-service installs), also enforces
/// that the process is the `credsd` service account — required because the system daemon chowns
/// per-user sockets to other uids, which only works as that account.
#[cfg(unix)]
fn require_scoped_user(system: bool) -> error::Result<()> {
    let euid = nix::unistd::geteuid();
    if euid.is_root() {
        return Err(error::DaemonError::config(
            "'credsd serve' must not run as root. Start the installed service instead.",
        ));
    }
    if system {
        let credsd_uid = nix::unistd::User::from_name(crate::config::platform::CREDSD_USER)
            .ok()
            .flatten()
            .map(|u| u.uid);
        if let Some(uid) = credsd_uid {
            if euid != uid {
                return Err(error::DaemonError::config(format!(
                    "'credsd serve --system' must run as the '{}' service account (uid {}), not uid {}.",
                    crate::config::platform::CREDSD_USER,
                    uid.as_raw(),
                    euid.as_raw(),
                )));
            }
        }
    }
    Ok(())
}

fn cmd_status(format: &str) -> error::Result<()> {
    let status = install::status()?;

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        _ => {
            println!(
                "installed: {}\nrunning:   {}",
                status.installed, status.running
            );
            if let Some(ref bin) = status.binary_path {
                println!("binary:    {}", bin);
            }
            if !status.args.is_empty() {
                println!("args:      {}", status.args.join(" "));
            }
            for (label, value) in [
                ("backend:  ", &status.storage_backend),
                ("data dir: ", &status.data_dir),
                ("socket:   ", &status.socket_path),
            ] {
                if let Some(value) = value {
                    println!("{label} {value}");
                }
            }
        }
    }
    Ok(())
}

fn cmd_init(storage_backend: Option<&str>, reset: bool) -> error::Result<()> {
    let backend = storage_backend.ok_or_else(|| {
        error::DaemonError::config(
            "credsd init requires --storage-backend; \
             specify the backend to initialize (e.g. --storage-backend tpm).",
        )
    })?;

    if reset {
        return cmd_init_reset(backend);
    }

    init_for_this_scope(backend)
}

/// Root cannot run `serve`, so a root `init` is only ever preparing the system service's
/// keystore rather than this process's.
#[cfg(unix)]
fn init_for_this_scope(backend: &str) -> error::Result<()> {
    if nix::unistd::geteuid().is_root() {
        return encryption::ensure_system_service_key(backend);
    }
    encryption::init_encryption_with_backend(Some(backend)).map(|_| ())
}

#[cfg(not(unix))]
fn init_for_this_scope(backend: &str) -> error::Result<()> {
    encryption::init_encryption_with_backend(Some(backend)).map(|_| ())
}

#[cfg(target_os = "linux")]
const RESET_WARNING: &str = "\
WARNING: keystore reset — all sealed credentials will be permanently abandoned.

The sealed blobs cannot be decrypted after this operation; they will be moved to
quarantine but cannot be recovered without the old key, which no longer exists.
Every environment will require re-authentication.

Only proceed if credsd serve told you the key cannot be unsealed (TPM reset,
PCR 7 policy violation, replaced TPM, etc.).

Type 'yes' to continue: ";

fn cmd_init_reset(backend: &str) -> error::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if backend != credsd_core::storage::Backend::Tpm.as_str() {
            return Err(error::DaemonError::config(
                "credsd init --reset only supports --storage-backend tpm. \
                 For other backends, re-run 'sudo credsd install' to reinitialize.",
            ));
        }
        if !install::confirm_typed_yes(RESET_WARNING)? {
            return Err(error::DaemonError::config("reset cancelled"));
        }
        encryption::rekey_encryption_with_backend(backend)?;
        // When run as root the new sealed blob and sidecar are root-owned 0600.
        // Chown the data tree so the service user can read them at startup.
        #[cfg(unix)]
        if nix::unistd::geteuid().is_root() {
            let data_dir = credsd_core::config::platform::data_dir();
            let owner = format!(
                "{}:{}",
                credsd_core::config::platform::CREDSD_USER,
                credsd_core::config::platform::CREDSD_GROUP
            );
            let status = std::process::Command::new("/usr/bin/chown")
                .args(["-R", &owner, &data_dir.display().to_string()])
                .status()
                .map_err(|e| {
                    error::DaemonError::config(format!(
                        "chown failed after reset; the new key files are root-owned and the \
                         service will not start. Run: chown -R {owner} {}. Error: {e}",
                        data_dir.display()
                    ))
                })?;
            if !status.success() {
                return Err(error::DaemonError::config(format!(
                    "chown -R {owner} {} failed (exit {}); the new key files are root-owned \
                     and the service will not start. Re-run manually.",
                    data_dir.display(),
                    status.code().unwrap_or(-1)
                )));
            }
        }
        return Ok(());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = backend;
        Err(error::DaemonError::config(
            "credsd init --reset is only supported on Linux (TPM backend). \
             On macOS, re-run 'sudo credsd install' to reinitialize.",
        ))
    }
}

#[cfg(test)]
#[path = "../../credsd/src/command_reference.rs"]
mod command_reference;

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Root must not load the config for logging; a non-root caller still does. Regressing
    /// either arm (root reads the config, or non-root skips it) fails here.
    #[test]
    fn root_never_loads_the_logging_config() {
        use std::cell::Cell;
        let loads = Cell::new(0);
        let load = || {
            loads.set(loads.get() + 1);
            Some(config::DaemonConfig::default())
        };
        assert!(config_for_logging(true, load).is_none());
        assert_eq!(loads.get(), 0);
        assert!(config_for_logging(false, load).is_some());
        assert_eq!(loads.get(), 1);
    }

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
        let problems = command_reference::discrepancies(&Cli::command(), &doc);
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    #[test]
    fn serve_takes_no_arguments() {
        assert!(matches!(
            Cli::try_parse_from(["credsd", "serve"]).unwrap().command,
            Commands::Serve { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn serve_refuses_root() {
        if nix::unistd::geteuid().is_root() {
            require_scoped_user(false).expect_err("root must be refused");
            require_scoped_user(true).expect_err("root must be refused in system mode too");
        } else {
            require_scoped_user(false).expect("non-root must be allowed in user mode");
        }
    }

    #[cfg(unix)]
    #[test]
    fn serve_system_enforces_credsd_account() {
        let euid = nix::unistd::geteuid();
        if euid.is_root() {
            return; // root path covered by serve_refuses_root
        }
        let credsd_uid = nix::unistd::User::from_name(crate::config::platform::CREDSD_USER)
            .ok()
            .flatten()
            .map(|u| u.uid);
        match credsd_uid {
            Some(uid) if euid == uid => {
                require_scoped_user(true).expect("credsd user must be allowed in system mode");
            }
            Some(_) => {
                require_scoped_user(true).expect_err("human uid must be refused in system mode");
            }
            None => {
                // No credsd account (dev machine): system flag still allows non-root.
                require_scoped_user(true).expect("non-root allowed when credsd account absent");
            }
        }
    }

    #[test]
    fn serve_rejects_removed_transport_flags() {
        for argv in [
            vec!["credsd", "serve", "--tcp"],
            vec!["credsd", "serve", "--port", "9000"],
        ] {
            assert!(
                Cli::try_parse_from(argv.clone()).is_err(),
                "{:?} should no longer parse",
                argv
            );
        }
    }

    #[test]
    fn config_dir_flag_parses_as_global() {
        let cli = Cli::try_parse_from(["credsd", "--config-dir", "/tmp/x", "serve"]).unwrap();
        assert_eq!(
            cli.config_dir.as_deref(),
            Some(std::path::Path::new("/tmp/x"))
        );
    }

    /// Round-trip guard: every argv `credsd install` bakes into a service
    /// definition must be accepted by this binary's own parser. A mismatch produces a
    /// service that fails at login, far from any test.
    #[test]
    fn install_args_are_accepted_by_serve() {
        use install::{program_arguments, InstallOpts};
        use std::path::Path;

        let log_file = Path::new("/tmp/credsd-roundtrip.log");
        for opts in [
            InstallOpts::default(),
            InstallOpts {
                storage_backend: Some("file".to_string()),
                log_file: Some(log_file.to_path_buf()),
                quiet: true,
                ..Default::default()
            },
        ] {
            let args = program_arguments(&opts, Some(log_file));
            let argv = std::iter::once("credsd".to_string()).chain(args.iter().cloned());
            let parsed = Cli::try_parse_from(argv);
            assert!(
                parsed.is_ok(),
                "serve rejected baked args {:?}: {}",
                args,
                parsed.err().unwrap()
            );
            assert!(matches!(parsed.unwrap().command, Commands::Serve { .. }));
        }
    }

    /// A user-scoped `serve` has to default somewhere it can actually write: the system default
    /// is a directory the `credsd` account owns, so a LaunchAgent running as a login user gets
    /// nothing but an open failure — and the failure is invisible because logging is what broke.
    #[cfg(unix)]
    #[test]
    fn a_user_scoped_serve_defaults_to_a_log_it_can_write() {
        let system = serve_default_log_path(true);
        assert_eq!(
            system,
            credsd_core::config::platform::log_file_path(),
            "the system service keeps the documented platform default"
        );
        if let Some(user_default) = credsd_core::config::platform::user_log_file_path() {
            let user = serve_default_log_path(false);
            assert_eq!(user, user_default);
            assert_ne!(user, system);
        }
    }

    #[test]
    fn status_default_format_is_text() {
        match Cli::try_parse_from(["credsd", "status"]).unwrap().command {
            Commands::Status { format } => assert_eq!(format, "text"),
            _ => panic!("expected Status"),
        }
    }
}
