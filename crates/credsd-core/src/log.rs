use crate::config::LogConfig;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Wraps any `Display` value so its rendered output replaces control characters and
/// backslashes with escape sequences, preventing log-line injection. Escaped ranges:
/// C0 (U+0000–U+001F, except tab), DEL (U+007F), C1 (U+0080–U+009F),
/// Unicode line/paragraph separators (U+2028–U+2029), the format characters in
/// `is_invisible_format`, and backslash.
pub struct EscapeLog<T>(T);

impl<T: std::fmt::Display> std::fmt::Display for EscapeLog<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct EscapeWrite<'a, 'b>(&'a mut std::fmt::Formatter<'b>);
        impl std::fmt::Write for EscapeWrite<'_, '_> {
            fn write_str(&mut self, s: &str) -> std::fmt::Result {
                for c in s.chars() {
                    let cp = c as u32;
                    if c == '\\' {
                        self.0.write_str("\\\\")?;
                    } else if (c != '\t' && cp < 0x20)
                        || cp == 0x7F
                        || (0x80..=0x9F).contains(&cp)
                        || c == '\u{2028}'
                        || c == '\u{2029}'
                        || is_invisible_format(cp)
                    {
                        write!(self.0, "\\x{:02X}", cp)?;
                    } else {
                        write!(self.0, "{c}")?;
                    }
                }
                Ok(())
            }
        }
        use std::fmt::Write;
        write!(EscapeWrite(f), "{}", self.0)
    }
}

/// Wrap any `Display` value so its rendered output has all C0 control characters
/// (except tab), backslashes, and the format characters in `is_invisible_format` replaced with
/// escape sequences.
pub fn escape_log<T: std::fmt::Display>(v: T) -> EscapeLog<T> {
    EscapeLog(v)
}

/// Every general-category Cf code point (Unicode 17.0.0) except ZWNJ U+200C and ZWJ U+200D,
/// which shape emoji and Indic text and so must reach the terminal. Cf is not exposed by Rust's
/// `char` API, so the table is generated from `unicodedata`; regenerate it when Unicode moves:
///
/// ```text
/// python3 -c "import unicodedata as u;cs=[c for c in range(0x110000) if u.category(chr(c))=='Cf' and c not in(0x200C,0x200D)];r=[];[r.append([c,c]) if not r or c!=r[-1][1]+1 else r[-1].__setitem__(1,c) for c in cs];print(*[f'0x{a:X}..=0x{b:X},' for a,b in r],sep='\n')"
/// ```
const FORMAT_CHARS: &[RangeInclusive<u32>] = &[
    0xAD..=0xAD,
    0x600..=0x605,
    0x61C..=0x61C,
    0x6DD..=0x6DD,
    0x70F..=0x70F,
    0x890..=0x891,
    0x8E2..=0x8E2,
    0x180E..=0x180E,
    0x200B..=0x200B,
    0x200E..=0x200F,
    0x202A..=0x202E,
    0x2060..=0x2064,
    0x2066..=0x206F,
    0xFEFF..=0xFEFF,
    0xFFF9..=0xFFFB,
    0x110BD..=0x110BD,
    0x110CD..=0x110CD,
    0x13430..=0x1343F,
    0x1BCA0..=0x1BCA3,
    0x1D173..=0x1D17A,
    0xE0001..=0xE0001,
    0xE0020..=0xE007F,
];

/// Format characters that hide or reorder text (bidi overrides, zero-width spaces). ZWJ and ZWNJ
/// are not in the table, so emoji and Indic text pass.
pub fn is_invisible_format(cp: u32) -> bool {
    FORMAT_CHARS.iter().any(|r| r.contains(&cp))
}

/// Wraps any `Display` value for safe terminal output: replaces C0 control characters
/// (U+0000–U+001F, except newline U+000A and tab U+0009), DEL (U+007F), and C1
/// controls (U+0080–U+009F), and the format characters in `is_invisible_format`, with U+FFFD.
/// Newlines and tabs pass through so multiline output remains readable.
pub struct EscapeTerminal<T>(T);

impl<T: std::fmt::Display> std::fmt::Display for EscapeTerminal<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct TermWrite(String);
        impl std::fmt::Write for TermWrite {
            fn write_str(&mut self, s: &str) -> std::fmt::Result {
                for c in s.chars() {
                    let cp = c as u32;
                    if (cp < 0x20 && c != '\n' && c != '\t')
                        || cp == 0x7F
                        || (0x80..=0x9F).contains(&cp)
                        || is_invisible_format(cp)
                    {
                        self.0.push('\u{FFFD}');
                    } else {
                        self.0.push(c);
                    }
                }
                Ok(())
            }
        }
        let mut w = TermWrite(String::new());
        use std::fmt::Write;
        write!(w, "{}", self.0)?;
        f.pad(&w.0)
    }
}

/// Wrap any `Display` value so control characters are replaced with U+FFFD before
/// printing to a terminal. Safe to use in `println!`/`eprintln!` wherever the value
/// originates from an external source (daemon response, config file, network).
pub fn escape_terminal<T: std::fmt::Display>(v: T) -> EscapeTerminal<T> {
    EscapeTerminal(v)
}

/// Size at which a file log rotates. credsd is a low-chatter daemon (startup +
/// refresh events, not per-request), so a small cap with a few generations is
/// ample; this matches the scale of neighboring agents under /Library/Logs.
const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
/// Rotated generations kept: credsd.log.1 .. credsd.log.{LOG_KEEP}.
const LOG_KEEP: usize = 3;

/// Dependency crates held at `info` when credsd runs at `debug` or `trace`.
///
/// The SDK orchestrator and the HTTP/2 stack log every attempt and frame at debug. The SSO
/// device flow polls `CreateToken` every few seconds while a person completes the browser step,
/// so `-v` buried credsd's own events under thousands of SDK lines. `RUST_LOG` still overrides
/// this outright for anyone debugging the SDK itself.
const QUIET_DEPENDENCIES: &[&str] = &[
    "aws_config",
    "aws_runtime",
    "aws_sdk",
    "aws_smithy",
    "h2",
    "hyper",
    "hyper_util",
    "rustls",
];

/// The filter for a resolved level: the level itself, plus [`QUIET_DEPENDENCIES`] capped at
/// `info` when the level is more verbose than that. Targets match by prefix, so `aws_sdk`
/// covers every `aws_sdk_*` crate.
fn filter_directives(level: &str) -> String {
    if !matches!(level, "debug" | "trace") {
        return level.to_string();
    }
    let mut directives = level.to_string();
    for target in QUIET_DEPENDENCIES {
        directives.push_str(&format!(",{target}=info"));
    }
    directives
}

fn resolve_level(quiet: bool, verbose: bool, config_level: Option<&str>) -> &'static str {
    if quiet {
        "error"
    } else if verbose {
        "debug"
    } else {
        match config_level {
            Some("error") => "error",
            Some("warn") => "warn",
            Some("debug") => "debug",
            Some("trace") => "trace",
            _ => "info",
        }
    }
}

/// A `CREDSD_LOG_*` setting, or `None` when unset or blank.
///
/// Blank reads as unset, matching [`crate::config::platform::socket_path_from_env`]: an
/// exported-but-empty variable must fall through rather than resolve to an empty level or path.
fn env_setting(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    (!value.trim().is_empty()).then_some(value)
}

/// Resolve `[log]` settings and install the subscriber.
///
/// Precedence: flag, then `config`, then `CREDSD_LOG_LEVEL` / `CREDSD_LOG_FORMAT` /
/// `CREDSD_LOG_FILE`, then the default. `RUST_LOG` still overrides the level outright, since a
/// filter directive says more than a bare level can.
///
/// The environment is read here rather than at the CLI boundary so every caller resolves the
/// same way by construction: the daemon, the client — which under a system install cannot read
/// `callers/<uid>/config.toml` at all and so passes `config: None` — and any library consumer.
/// clap `env` attributes would have covered only whichever binary declared them.
pub fn init_logging(
    quiet: bool,
    verbose: bool,
    log_file: Option<&Path>,
    log_format: Option<&str>,
    config: Option<&LogConfig>,
) {
    let env_level = env_setting("CREDSD_LOG_LEVEL");
    let env_format = env_setting("CREDSD_LOG_FORMAT");
    let env_file = env_setting("CREDSD_LOG_FILE").map(PathBuf::from);

    let config_level = config
        .and_then(|c| c.level.as_deref())
        .or(env_level.as_deref());
    let config_format = config
        .and_then(|c| c.format.as_deref())
        .or(env_format.as_deref());
    let config_file = config
        .and_then(|c| c.file.as_deref())
        .or(env_file.as_deref());

    let effective_file = log_file.or(config_file);
    let effective_format = log_format.or(config_format).unwrap_or("text");
    let use_json = effective_format == "json";

    let env_filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    } else {
        EnvFilter::new(filter_directives(resolve_level(
            quiet,
            verbose,
            config_level,
        )))
    };

    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());

    let stderr_text = if !use_json {
        Some(
            tracing_subscriber::fmt::layer()
                .with_ansi(is_tty)
                .with_target(false)
                .with_writer(std::io::stderr),
        )
    } else {
        None
    };

    let stderr_json = if use_json {
        Some(
            tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_target(false)
                .with_writer(std::io::stderr),
        )
    } else {
        None
    };

    let file_mutex = effective_file.and_then(|path| {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!(
                        "warning: could not create log directory '{}': {}",
                        parent.display(),
                        e
                    );
                    return None;
                }
            }
        }
        match open_log_file(path) {
            Ok(f) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
                }
                // Existing size counts toward the cap, since we append.
                let len = f.metadata().map(|m| m.len()).unwrap_or(0);
                Some(Arc::new(Mutex::new(LogFile { handle: f, len })))
            }
            Err(e) => {
                eprintln!(
                    "warning: could not open log file '{}': {}",
                    path.display(),
                    e
                );
                None
            }
        }
    });

    let file_writer = file_mutex
        .as_ref()
        .zip(effective_file)
        .map(|(m, path)| FileWriter {
            file: m.clone(),
            path: path.to_path_buf(),
        });

    let file_text = if !use_json {
        file_writer.clone().map(|w| {
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(w)
        })
    } else {
        None
    };

    let file_json = if use_json {
        file_writer.map(|w| {
            tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_target(false)
                .with_writer(w)
        })
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stderr_text)
        .with(stderr_json)
        .with(file_text)
        .with(file_json)
        .init();

    #[cfg(unix)]
    if let (Some(mutex), Some(path)) = (file_mutex, effective_file) {
        let path = path.to_path_buf();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let Ok(mut sig) = signal(SignalKind::hangup()) else {
                return;
            };
            loop {
                sig.recv().await;
                match open_log_file(&path) {
                    Ok(new_file) => {
                        if let Ok(mut guard) = mutex.lock() {
                            let len = new_file.metadata().map(|m| m.len()).unwrap_or(0);
                            guard.handle = new_file;
                            guard.len = len;
                        }
                        tracing::info!("log file reopened after SIGHUP");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to reopen log file after SIGHUP");
                    }
                }
            }
        });
    }

    let mut destinations = vec!["stderr"];
    if effective_file.is_some() {
        destinations.push("file");
    }
    tracing::info!(
        destinations = destinations.join(", "),
        "logging initialized"
    );
}

/// Created at 0600 rather than narrowed afterwards: the callers' `set_permissions` only repairs a
/// file that already existed, and a discarded failure there must not leave a new log readable.
fn open_log_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Open file plus the bytes written to it since it was opened, tracked so the
/// writer can rotate without a `stat` syscall on every line.
struct LogFile {
    handle: std::fs::File,
    len: u64,
}

// ponytail: MakeWriter needs a concrete type; this wraps the file with its path
// and size counter so writes can trigger size-based rotation.
#[derive(Clone)]
struct FileWriter {
    file: Arc<Mutex<LogFile>>,
    path: PathBuf,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FileWriter {
    type Writer = FileWriterGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        FileWriterGuard(self)
    }
}

struct FileWriterGuard<'a>(&'a FileWriter);

impl std::io::Write for FileWriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self
            .0
            .file
            .lock()
            .map_err(|_| std::io::Error::other("lock poisoned"))?;
        // Saturating throughout: a wrapped length would read as a nearly-empty file and stop
        // rotation for the next 16 exabytes of logging, and the write itself is unaffected by
        // whether the counter is exact at the ceiling.
        if guard.len.saturating_add(buf.len() as u64) > LOG_MAX_BYTES {
            // A failed rotation is not a failed write: keep appending to the
            // handle we already hold rather than dropping the event.
            let _ = rotate(&self.0.path, &mut guard);
        }
        let n = std::io::Write::write(&mut guard.handle, buf)?;
        guard.len = guard.len.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .file
            .lock()
            .map_err(|_| std::io::Error::other("lock poisoned"))
            .and_then(|mut g| std::io::Write::flush(&mut g.handle))
    }
}

/// Rotate `path` in place: `path.{N-1}` → `path.{N}` (oldest dropped), then
/// `path` → `path.1`, and reopen a fresh empty `path`.
///
/// On any filesystem error the caller's handle is left open and writable, so a
/// failed rotation degrades to appending past the cap rather than losing the
/// sink. `len` is therefore reset before the first fallible step: every exit
/// path must leave it under the cap, or the next line re-enters rotation and
/// cascades the generation shift, discarding good history on each pass.
fn rotate(path: &Path, log: &mut LogFile) -> std::io::Result<()> {
    log.len = 0;
    let _ = std::io::Write::flush(&mut log.handle);

    // `n` is bounded by `LOG_KEEP`, so `n + 1` cannot overflow; `saturating_add` says so without
    // relying on the reader to check the loop bound.
    for n in (1..LOG_KEEP).rev() {
        let from = rotated_path(path, n);
        if from.exists() {
            let _ = std::fs::rename(&from, rotated_path(path, n.saturating_add(1)));
        }
    }
    let active = rotated_path(path, 1);
    std::fs::rename(path, &active)?;

    let fresh = match open_log_file(path) {
        Ok(f) => f,
        Err(e) => {
            // The live handle still points at the inode now named `.1`. Move it
            // back so the open fd and `path` agree again; the alternative leaves
            // every later write landing in a file the user is not tailing.
            let _ = std::fs::rename(&active, path);
            return Err(e);
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    log.handle = fresh;
    Ok(())
}

fn rotated_path(path: &Path, n: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}", n));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_new_log_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("credsd.log");
        open_log_file(&path).expect("open");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn level_quiet() {
        assert_eq!(resolve_level(true, false, None), "error");
    }

    #[test]
    fn level_verbose() {
        assert_eq!(resolve_level(false, true, None), "debug");
    }

    #[test]
    fn level_config() {
        assert_eq!(resolve_level(false, false, Some("warn")), "warn");
        assert_eq!(resolve_level(false, false, Some("trace")), "trace");
    }

    #[test]
    fn level_default() {
        assert_eq!(resolve_level(false, false, None), "info");
        assert_eq!(resolve_level(false, false, Some("bogus")), "info");
    }

    /// At debug and trace, SDK and HTTP/2 crates stay at info so a polling device flow doesn't
    /// bury credsd's own events. At info and quieter, the level alone already covers them.
    #[test]
    fn verbose_levels_cap_dependencies_at_info() {
        for level in ["debug", "trace"] {
            let directives = filter_directives(level);
            assert!(directives.starts_with(level), "{directives}");
            for target in QUIET_DEPENDENCIES {
                assert!(
                    directives.contains(&format!(",{target}=info")),
                    "{target} missing from {directives}"
                );
            }
            assert!(EnvFilter::try_new(&directives).is_ok(), "{directives}");
        }
        for level in ["error", "warn", "info"] {
            assert_eq!(filter_directives(level), level);
        }
    }

    /// Blank reads as unset, so an exported-but-empty `CREDSD_LOG_LEVEL` falls through to the
    /// default instead of resolving to an empty filter directive. Each case uses its own variable
    /// name, so this needs no lock against the other env-reading tests.
    #[test]
    fn env_setting_treats_blank_as_unset() {
        assert_eq!(env_setting("CREDSD_TEST_LOG_UNSET"), None);

        std::env::set_var("CREDSD_TEST_LOG_BLANK", "");
        assert_eq!(env_setting("CREDSD_TEST_LOG_BLANK"), None);

        std::env::set_var("CREDSD_TEST_LOG_WHITESPACE", "  \t ");
        assert_eq!(env_setting("CREDSD_TEST_LOG_WHITESPACE"), None);

        std::env::set_var("CREDSD_TEST_LOG_SET", "trace");
        assert_eq!(
            env_setting("CREDSD_TEST_LOG_SET").as_deref(),
            Some("trace"),
            "a real value must survive"
        );
    }

    /// The env fallback must reach exactly the levels the flags cannot express: `-q`/`-v` only
    /// reach error/info/debug, so `warn` and `trace` were only ever settable through the config
    /// file the client can no longer read.
    #[test]
    fn env_level_reaches_the_levels_no_flag_can() {
        for level in ["warn", "trace"] {
            assert_eq!(resolve_level(false, false, Some(level)), level);
        }
    }

    #[test]
    fn escape_log_passthrough_for_safe_strings() {
        assert_eq!(escape_log("hello world").to_string(), "hello world");
        assert_eq!(escape_log("tab\there").to_string(), "tab\there");
        assert_eq!(escape_log("unicode: €").to_string(), "unicode: €");
    }

    #[test]
    fn escape_log_replaces_newlines_and_control_chars() {
        assert_eq!(escape_log("line1\nline2").to_string(), "line1\\x0Aline2");
        assert_eq!(escape_log("cr\r").to_string(), "cr\\x0D");
        assert_eq!(escape_log("\x00nul").to_string(), "\\x00nul");
        assert_eq!(escape_log("a\x1Fb").to_string(), "a\\x1Fb");
        // backslash is doubled so the encoding is injective
        assert_eq!(escape_log("a\\x0Ab").to_string(), "a\\\\x0Ab");
        assert_eq!(escape_log("back\\slash").to_string(), "back\\\\slash");
        // DEL, C1, and Unicode line seps
        assert_eq!(escape_log("\x7F").to_string(), "\\x7F");
        assert_eq!(escape_log("\u{85}").to_string(), "\\x85");
        assert_eq!(escape_log("\u{2028}").to_string(), "\\x2028");
        assert_eq!(escape_log("\u{2029}").to_string(), "\\x2029");
    }

    /// A bidi override reorders the rest of a log line when a terminal renders it, the same
    /// way it reorders an approver's screen, so the log sink escapes the format set too.
    #[test]
    fn escape_log_replaces_bidi_and_zero_width_format_chars() {
        assert_eq!(escape_log("\u{202E}evil").to_string(), "\\x202Eevil");
        assert_eq!(escape_log("a\u{200B}b").to_string(), "a\\x200Bb");
        // ZWNJ and ZWJ shape emoji and Indic text, so the log keeps them as the screens do.
        assert_eq!(
            escape_log("\u{200C}\u{200D}").to_string(),
            "\u{200C}\u{200D}"
        );
    }

    /// Adversarial inputs: every format character in the table, mixed with arbitrary chars.
    /// Ranges and joiners are excluded by `is_invisible_format`, so the property is the table.
    #[test]
    fn escape_log_output_contains_no_format_character() {
        use proptest::prelude::*;
        let format_chars: Vec<char> = FORMAT_CHARS
            .iter()
            .cloned()
            .flatten()
            .filter_map(char::from_u32)
            .collect();
        let input_char = prop_oneof![any::<char>(), prop::sample::select(format_chars)];
        proptest!(|(chars in proptest::collection::vec(input_char, 0..64))| {
            let input: String = chars.into_iter().collect();
            let out = escape_log(&input).to_string();
            prop_assert!(out.chars().all(|c| !is_invisible_format(c as u32)), "{out:?}");
        });
    }

    #[test]
    fn escape_terminal_passthrough_for_safe_strings() {
        assert_eq!(escape_terminal("hello world").to_string(), "hello world");
        assert_eq!(escape_terminal("tab\there").to_string(), "tab\there");
        assert_eq!(escape_terminal("line\nbreak").to_string(), "line\nbreak");
        assert_eq!(escape_terminal("unicode: €").to_string(), "unicode: €");
    }

    #[test]
    fn escape_terminal_replaces_control_chars_with_replacement() {
        assert_eq!(
            escape_terminal("\x1B[31mred\x1B[0m").to_string(),
            "\u{FFFD}[31mred\u{FFFD}[0m"
        );
        assert_eq!(escape_terminal("a\x00b").to_string(), "a\u{FFFD}b");
        assert_eq!(
            escape_terminal("\x08backspace").to_string(),
            "\u{FFFD}backspace"
        );
        assert_eq!(escape_terminal("\x7F").to_string(), "\u{FFFD}");
        assert_eq!(escape_terminal("\u{85}").to_string(), "\u{FFFD}");
    }

    /// Bidi overrides and zero-width format characters print nothing of their own, so a value
    /// carrying them can show an approver different text than the daemon holds: an RLO reverses
    /// the rest of a line, a ZWSP splits a word so it reads as another one. Both are category Cf.
    #[test]
    fn escape_terminal_replaces_bidi_and_zero_width_format_chars() {
        assert_eq!(escape_terminal("\u{202E}evil").to_string(), "\u{FFFD}evil");
        assert_eq!(escape_terminal("a\u{200B}b").to_string(), "a\u{FFFD}b");
        assert_eq!(
            escape_terminal("\u{2066}x\u{2069}").to_string(),
            "\u{FFFD}x\u{FFFD}"
        );
        assert_eq!(escape_terminal("\u{FEFF}").to_string(), "\u{FFFD}");
    }

    #[test]
    fn escape_terminal_spares_joiners_and_code_points_just_outside_format_ranges() {
        // ZWNJ/ZWJ carry meaning in Indic and emoji sequences; they must reach the terminal.
        assert_eq!(
            escape_terminal("\u{200C}\u{200D}").to_string(),
            "\u{200C}\u{200D}"
        );
        for cp in [0x200A_u32, 0x2065, 0x202F, 0x2070] {
            let s = char::from_u32(cp).unwrap().to_string();
            assert_eq!(escape_terminal(&s).to_string(), s, "U+{cp:04X}");
        }
    }

    /// Exhaustive over the tag block: each character here smuggles text the approver cannot see.
    #[test]
    fn escape_terminal_replaces_every_tag_character() {
        for cp in std::iter::once(0xE0001).chain(0xE0020..=0xE007F) {
            let s = char::from_u32(cp).unwrap().to_string();
            assert_eq!(escape_terminal(&s).to_string(), "\u{FFFD}", "U+{cp:04X}");
        }
    }

    /// Every listed character is replaced. Completeness is pinned by the count in the next test.
    #[test]
    fn escape_terminal_replaces_every_format_character_in_the_table() {
        for cp in FORMAT_CHARS.iter().cloned().flatten() {
            let s = char::from_u32(cp).unwrap().to_string();
            assert_eq!(escape_terminal(&s).to_string(), "\u{FFFD}", "U+{cp:04X}");
        }
    }

    /// 170 Cf code points in Unicode 17.0.0, less ZWNJ and ZWJ. A dropped entry changes the count.
    #[test]
    fn the_format_table_covers_every_cf_character_but_the_joiners() {
        assert_eq!(FORMAT_CHARS.iter().cloned().flatten().count(), 168);
        // Literal spot checks against Unicode 17.0.0 Cf, independent of the table itself.
        for cp in [
            0xAD, 0x8E2, 0x180E, 0x2060, 0xFFFB, 0x110BD, 0x110CD, 0x13430, 0x1BCA3, 0x1D17A,
            0xE0001, 0xE007F,
        ] {
            assert!(is_invisible_format(cp), "U+{cp:04X}");
        }
        for cp in [0x200C, 0x200D, 0x110CE, 0xE0000] {
            assert!(!is_invisible_format(cp), "U+{cp:04X}");
        }
    }

    #[test]
    fn the_format_table_is_sorted_and_disjoint() {
        for range in FORMAT_CHARS {
            assert!(!range.is_empty(), "{range:?}");
        }
        for pair in FORMAT_CHARS.windows(2) {
            assert!(
                pair[0].end() < pair[1].start(),
                "{:?} vs {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn rotated_path_appends_generation_suffix() {
        let p = rotated_path(Path::new("/tmp/credsd/credsd.log"), 2);
        assert_eq!(p, PathBuf::from("/tmp/credsd/credsd.log.2"));
    }

    /// Append `line` to the active file and track its size the way `write()` does.
    fn append(log: &mut LogFile, line: &str) {
        let n = std::io::Write::write(&mut log.handle, line.as_bytes()).unwrap();
        log.len = log.len.saturating_add(n as u64);
    }

    #[test]
    fn rotate_shifts_generations_and_resets_len() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("credsd.log");

        let handle = open_log_file(&base).unwrap();
        let mut log = LogFile { handle, len: 0 };
        append(&mut log, "first generation\n");

        rotate(&base, &mut log).unwrap();

        // Active file is fresh and empty; prior content moved to .1.
        assert_eq!(log.len, 0);
        assert!(base.exists());
        assert_eq!(std::fs::metadata(&base).unwrap().len(), 0);
        assert_eq!(
            std::fs::read_to_string(rotated_path(&base, 1)).unwrap(),
            "first generation\n"
        );

        // A second rotation shifts .1 -> .2 and drops nothing yet (KEEP=3).
        append(&mut log, "second generation\n");
        rotate(&base, &mut log).unwrap();
        assert_eq!(
            std::fs::read_to_string(rotated_path(&base, 2)).unwrap(),
            "first generation\n"
        );
        assert_eq!(
            std::fs::read_to_string(rotated_path(&base, 1)).unwrap(),
            "second generation\n"
        );
    }

    #[test]
    fn failed_rotation_resets_len_and_keeps_sink_writable() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("credsd.log");
        std::fs::write(rotated_path(&base, 1), "older\n").unwrap();

        let handle = open_log_file(&base).unwrap();
        let mut log = LogFile { handle, len: 0 };
        append(&mut log, "active\n");

        // An external rotator moved the active file away; renaming it now fails.
        std::fs::remove_file(&base).unwrap();

        assert!(rotate(&base, &mut log).is_err());

        // The invariant that matters: len is back under the cap, so the next
        // line does not re-enter rotation and cascade the generation shift.
        assert_eq!(log.len, 0);
        // The handle we still hold stays writable — a failed rotation degrades
        // to appending, it does not lose the sink.
        assert!(std::io::Write::write_all(&mut log.handle, b"after\n").is_ok());
        // The pre-existing generation survived (shifted, not destroyed).
        assert_eq!(
            std::fs::read_to_string(rotated_path(&base, 2)).unwrap(),
            "older\n"
        );
    }

    #[test]
    fn rotate_drops_oldest_beyond_keep() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("credsd.log");

        // Pre-seed the maximum kept generations.
        for n in 1..=LOG_KEEP {
            std::fs::write(rotated_path(&base, n), format!("gen{}\n", n)).unwrap();
        }
        std::fs::write(&base, "active\n").unwrap();

        let handle = open_log_file(&base).unwrap();
        let mut log = LogFile { handle, len: 7 };
        rotate(&base, &mut log).unwrap();

        // Oldest (.{KEEP}) is overwritten by the shift, not left as a stale gen.
        assert_eq!(
            std::fs::read_to_string(rotated_path(&base, 1)).unwrap(),
            "active\n"
        );
        assert_eq!(
            std::fs::read_to_string(rotated_path(&base, LOG_KEEP)).unwrap(),
            format!("gen{}\n", LOG_KEEP - 1)
        );
    }
}
