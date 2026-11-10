//! Process-tree ancestry collection for caller classification.
//!
//! Collection only: this module gathers evidence and reports why a walk ended. It
//! renders no verdict — see `server::classify` for classification and the
//! `caller-verification-policy` spec for the enforcement layer that consumes it.
//!
//! The walk stops at the user boundary: it never traverses into a process owned by
//! a different user than the caller. That is a deliberate scope limit, not a
//! workaround. Ancestors above the boundary are session infrastructure (`login`,
//! `launchd`, `sshd`, `systemd`) that cannot host an agentic runtime for this user,
//! and an attacker who does control a process there already outranks any defense
//! ancestry classification could offer. The kernel enforces the same line
//! independently — macOS `PROC_PIDTBSDINFO` returns `EPERM` cross-user, and Linux
//! `/proc/<pid>/exe` is unreadable cross-user — so stopping here also avoids
//! reporting an unreadable ancestor as a broken walk.

use serde::Serialize;
use std::path::PathBuf;

/// Upper bound on ancestry walk length. Real lineages are single-digit; this only
/// bounds a corrupted or adversarial parent chain.
pub const MAX_ANCESTRY_DEPTH: usize = 64;

/// Whether this platform can supply parent PID, owning uid, and start time. All
/// three are required: without start times the walk cannot validate against PID
/// recycling, and a chain that skipped that check must not be reported as complete.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const ANCESTRY_SUPPORTED: bool = true;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const ANCESTRY_SUPPORTED: bool = false;

/// Maximum length of a kernel `comm` value, on both Linux (`TASK_COMM_LEN - 1`) and
/// macOS (`MAXCOMLEN - 1`). Allowlist entries are truncated to this before being
/// compared against a `comm`.
pub const COMM_MAX_LEN: usize = 15;

/// Identity and lineage facts for one process, read together so a single syscall or
/// `/proc` read serves all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFacts {
    pub ppid: u32,
    /// Owning user. Compared against the caller's to find the walk boundary.
    pub uid: u32,
    /// Kernel-held process name, truncated to `COMM_MAX_LEN`. Survives the
    /// executable being unlinked, so it is the fallback when `binary_path` is gone.
    pub comm: Option<String>,
    /// Platform-relative and only comparable against other values from the same
    /// platform: clock ticks since boot on Linux, absolute microseconds on macOS.
    /// `None` when the kernel withheld it, which is expected cross-user.
    pub start_time: Option<u64>,
}

/// The executable path for a process, or why it is missing.
///
/// The reason is retained rather than collapsed to `None` so the classifier can hold
/// `comm` to a strict precedence: a name the process itself can set is an acceptable
/// substitute for a *deleted* executable, but not for one the kernel merely refused
/// to disclose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BinaryPath {
    Known {
        path: PathBuf,
    },
    /// The executable has been unlinked, so the kernel has no path to report. Normal
    /// for a long-running process whose package was upgraded in place.
    Deleted,
    /// The kernel declined to report the path.
    Denied,
    /// No path source exists on this platform. Constructed only by the fallback `binary_path` for
    /// non-linux/macos targets, but matched on every platform.
    // `allow` rather than `expect`: tests construct this, so the lint fires for the bin build and
    // not under `--all-targets`, and an `expect` would be unfulfilled in one of the two.
    #[cfg_attr(
        any(target_os = "linux", target_os = "macos"),
        allow(
            dead_code,
            reason = "constructed only by the non-linux/macos `binary_path` fallback, which is \
                      cfg'd out here; the variant is still matched, so removing it would not \
                      simplify the match"
        )
    )]
    Unsupported,
}

impl BinaryPath {
    pub fn known(&self) -> Option<&PathBuf> {
        match self {
            Self::Known { path } => Some(path),
            _ => None,
        }
    }
}

/// One node in a caller's ancestry.
///
/// Two independent names are recorded because either can be missing. `binary_path`
/// is the stronger signal but disappears once the executable is unlinked — which
/// happens routinely when a long-running agent is upgraded in place, and can also be
/// done deliberately. `comm` is weaker (15 bytes, and writable by the process on
/// Linux) but is held in kernel memory and survives that.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub uid: u32,
    pub binary_path: BinaryPath,
    pub comm: Option<String>,
    pub start_time: Option<u64>,
}

impl ProcessNode {
    /// Whether this process can be matched against the agent allowlist at all.
    ///
    /// Mirrors the classifier's precedence rule rather than merely asking whether
    /// some name exists: a `comm` counts only when it is the accepted substitute for
    /// a deleted executable. A `Denied` path leaves the process unmatchable even
    /// though a `comm` may be present, and such a node is opaque — its presence
    /// means the chain cannot support a negative finding.
    pub fn is_identifiable(&self) -> bool {
        match &self.binary_path {
            BinaryPath::Known { .. } => true,
            BinaryPath::Deleted => self.comm.is_some(),
            BinaryPath::Denied | BinaryPath::Unsupported => false,
        }
    }
}

/// Why an ancestry walk stopped.
///
/// `ReachedRoot` and `UserBoundary` are both *complete* outcomes — the walk saw
/// every process it was entitled to and able to see. The rest mean the walk could
/// not finish, which is a different thing from finding nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum WalkTermination {
    ReachedRoot,
    /// The next ancestor belongs to another user, so the caller's own lineage has
    /// been fully traversed. A complete outcome.
    UserBoundary {
        at_pid: u32,
        uid: u32,
    },
    DepthLimit,
    ParentUnavailable {
        at_pid: u32,
    },
    /// A parent that started *after* its child: the PPID has been recycled, so the
    /// chain beyond this point is unrelated to the caller.
    StartTimeViolation {
        child: u32,
        parent: u32,
    },
    /// Start time was unavailable for `at_pid` or its parent on a platform that is
    /// expected to supply it. Recycle validation could not be performed; per
    /// caller-verification-policy AC 7.9 the chain must not be reported as complete.
    StartTimeUnavailable {
        at_pid: u32,
    },
    PlatformUnsupported,
}

/// A caller's parent chain plus the reason the walk ended.
#[derive(Debug, Clone, Serialize)]
pub struct Ancestry {
    pub chain: Vec<ProcessNode>,
    pub termination: WalkTermination,
}

impl Ancestry {
    /// Whether the chain is a complete view of the caller's own lineage, and so can
    /// support a negative finding. A depth-limited or broken chain cannot.
    pub fn is_complete(&self) -> bool {
        matches!(
            self.termination,
            WalkTermination::ReachedRoot | WalkTermination::UserBoundary { .. }
        )
    }
}

/// A caller's ancestry serialized for a mutation's audit record: names and pids only, never a
/// command line. `None` when the transport supplied no pid to walk from.
pub fn ancestry_field(pid: Option<i32>) -> Option<String> {
    let pid = u32::try_from(pid?).ok()?;
    serde_json::to_string(&collect_ancestry(pid)).ok()
}

/// Walk from `pid` toward the root, collecting each ancestor's binary path and
/// start time, stopping at the root or the user boundary.
///
/// Stepping child → parent validates that the parent started no later than the
/// child (guarding against a recycled PPID). This does *not* defeat double-fork
/// reparenting: a process reparented to init has a legitimately older parent and
/// passes cleanly.
pub fn collect_ancestry(pid: u32) -> Ancestry {
    let Some(caller) = process_facts(pid) else {
        return Ancestry {
            chain: vec![],
            termination: if ANCESTRY_SUPPORTED {
                WalkTermination::ParentUnavailable { at_pid: pid }
            } else {
                WalkTermination::PlatformUnsupported
            },
        };
    };

    let session_uid = caller.uid;
    let mut chain = vec![ProcessNode {
        pid,
        uid: caller.uid,
        binary_path: binary_path(pid),
        comm: caller.comm.clone(),
        start_time: caller.start_time,
    }];
    let mut facts = caller;
    let mut current = pid;

    loop {
        if chain.len() >= MAX_ANCESTRY_DEPTH {
            return Ancestry {
                chain,
                termination: WalkTermination::DepthLimit,
            };
        }

        // A self-parent would otherwise spin.
        if facts.ppid == 0 || facts.ppid == current {
            return Ancestry {
                chain,
                termination: WalkTermination::ReachedRoot,
            };
        }

        let Some(parent) = process_facts(facts.ppid) else {
            return Ancestry {
                chain,
                termination: WalkTermination::ParentUnavailable { at_pid: facts.ppid },
            };
        };

        if parent.uid != session_uid {
            return Ancestry {
                chain,
                termination: WalkTermination::UserBoundary {
                    at_pid: facts.ppid,
                    uid: parent.uid,
                },
            };
        }

        match (facts.start_time, parent.start_time) {
            (Some(child_start), Some(parent_start)) if parent_start > child_start => {
                return Ancestry {
                    chain,
                    termination: WalkTermination::StartTimeViolation {
                        child: current,
                        parent: facts.ppid,
                    },
                };
            }
            (Some(_), Some(_)) => {}
            // On supported platforms every same-uid process must have a start time.
            // A missing value means recycle validation cannot be performed; per
            // caller-verification-policy AC 7.9 the chain must not complete.
            _ if ANCESTRY_SUPPORTED => {
                return Ancestry {
                    chain,
                    termination: WalkTermination::StartTimeUnavailable { at_pid: current },
                };
            }
            _ => {}
        }

        chain.push(ProcessNode {
            pid: facts.ppid,
            uid: parent.uid,
            binary_path: binary_path(facts.ppid),
            comm: parent.comm.clone(),
            start_time: parent.start_time,
        });

        current = facts.ppid;
        facts = parent;
    }
}

/// Read lineage and identity facts for the given process.
#[cfg(target_os = "linux")]
pub fn process_facts(pid: u32) -> Option<ProcessFacts> {
    use std::os::unix::fs::MetadataExt;

    // /proc/<pid> is owned by the user the process runs as, so one stat supplies the
    // uid without parsing /proc/<pid>/status.
    let uid = std::fs::metadata(format!("/proc/{}", pid)).ok()?.uid();

    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // `pid (comm) state ppid ...` — comm can contain parens and spaces, so bound it
    // by the first '(' and the last ')'. `split_once`/`rsplit_once` already land past
    // their delimiter, so there is no offset to add to a byte index.
    let (_, after_open) = stat.split_once('(')?;
    let (comm, after_close) = after_open.rsplit_once(')')?;
    // The first token after the ')' is `state` (proc(5) field 3), so field N sits at
    // index N-3: ppid (4) at 1, starttime (22) at 19.
    let fields: Vec<&str> = after_close.split_whitespace().collect();
    Some(ProcessFacts {
        ppid: fields.get(1)?.parse().ok()?,
        uid,
        comm: (!comm.is_empty()).then(|| comm.to_string()),
        start_time: fields.get(19).and_then(|s| s.parse().ok()),
    })
}

/// Read lineage and identity facts for the given process.
///
/// Two flavors are needed. `PROC_PIDT_SHORTBSDINFO` yields ppid and uid for any
/// process regardless of owner; `PROC_PIDTBSDINFO` carries the start time but
/// returns `EPERM` cross-user, so its absence is expected at the boundary and not
/// an error.
#[cfg(target_os = "macos")]
pub fn process_facts(pid: u32) -> Option<ProcessFacts> {
    const MAXCOMLEN: usize = 16;
    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDT_SHORTBSDINFO: i32 = 13;

    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut std::ffi::c_void,
            buffersize: i32,
        ) -> i32;
    }

    /// `struct proc_bsdshortinfo` from <sys/proc_info.h>.
    #[repr(C)]
    struct ProcBsdShortInfo {
        pbsi_pid: u32,
        pbsi_ppid: u32,
        pbsi_pgid: u32,
        pbsi_status: u32,
        pbsi_comm: [u8; MAXCOMLEN],
        pbsi_flags: u32,
        pbsi_uid: u32,
        pbsi_gid: u32,
        pbsi_ruid: u32,
        pbsi_rgid: u32,
        pbsi_svuid: u32,
        pbsi_svgid: u32,
        pbsi_rfu: u32,
    }

    /// `struct proc_bsdinfo` from <sys/proc_info.h>, laid out in full rather than
    /// truncated with padding because `pbi_start_tvsec` sits at the end.
    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [u8; MAXCOMLEN],
        pbi_name: [u8; 2 * MAXCOMLEN],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    let mut short = std::mem::MaybeUninit::<ProcBsdShortInfo>::uninit();
    // SAFETY: `proc_pidinfo` writes at most `buffersize` bytes into `buffer`, and the size passed
    // is the size of the very struct the pointer came from. The buffer is left uninitialized on
    // purpose — the kernel is the writer — and is read only after the return value confirms a
    // full-size write.
    let ret = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDT_SHORTBSDINFO,
            0,
            short.as_mut_ptr() as *mut std::ffi::c_void,
            std::mem::size_of::<ProcBsdShortInfo>() as i32,
        )
    };
    if ret < std::mem::size_of::<ProcBsdShortInfo>() as i32 {
        return None;
    }
    // SAFETY: proc_pidinfo reported writing at least the full struct size.
    let short = unsafe { short.assume_init() };

    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::uninit();
    // SAFETY: as above — the buffer and the declared size are the same struct, and the result is
    // read only once the return value confirms a full-size write. This flavor returns EPERM
    // cross-user, which is why a short write is expected rather than exceptional here.
    let ret = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr() as *mut std::ffi::c_void,
            std::mem::size_of::<ProcBsdInfo>() as i32,
        )
    };
    let start_time = if ret >= std::mem::size_of::<ProcBsdInfo>() as i32 {
        // SAFETY: proc_pidinfo reported writing at least the full struct size.
        let info = unsafe { info.assume_init() };
        info.pbi_start_tvsec
            .checked_mul(1_000_000)
            .and_then(|us| us.checked_add(info.pbi_start_tvusec))
    } else {
        None
    };

    // The name is NUL-terminated unless it fills the field exactly, in which case there is no
    // terminator. Splitting on NUL and taking the first run is both the terminator scan and the
    // bound, so the two cannot disagree about where the name ends.
    let comm = short
        .pbsi_comm
        .split(|&b| b == 0)
        .next()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Some(ProcessFacts {
        ppid: short.pbsi_ppid,
        uid: short.pbsi_uid,
        comm,
        start_time,
    })
}

/// Read lineage and identity facts for the given process.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn process_facts(_pid: u32) -> Option<ProcessFacts> {
    None
}

/// Resolve the executable path for the given process.
///
/// A deleted executable is reported by the kernel as the original target with a
/// " (deleted)" suffix. That is still a usable name, so it is kept as `Known` with
/// the marker stripped — unlike macOS, Linux does not lose the path here.
#[cfg(target_os = "linux")]
pub fn binary_path(pid: u32) -> BinaryPath {
    match std::fs::read_link(format!("/proc/{}/exe", pid)) {
        Ok(path) => {
            let stripped = path
                .to_str()
                .and_then(|s| s.strip_suffix(" (deleted)"))
                .map(PathBuf::from);
            BinaryPath::Known {
                path: stripped.unwrap_or(path),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BinaryPath::Deleted,
        Err(_) => BinaryPath::Denied,
    }
}

/// Resolve the executable path for the given process.
///
/// Unlike Linux, macOS reports nothing at all once the executable is unlinked:
/// `proc_pidpath` fails with `ENOENT`, which is distinguished here from the `EPERM`
/// of a path the kernel withheld.
#[cfg(target_os = "macos")]
pub fn binary_path(pid: u32) -> BinaryPath {
    extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut std::ffi::c_void, buffersize: u32) -> i32;
    }

    // PROC_PIDPATHINFO_MAXSIZE
    const PATH_MAX_LEN: usize = 4 * 1024;

    let mut buf = vec![0u8; PATH_MAX_LEN];
    // SAFETY: `proc_pidpath` writes at most `buffersize` bytes, and `buffersize` is `buf.len()`
    // rather than the constant, so the two cannot disagree. The buffer is zero-initialized, so
    // even a partial write leaves no uninitialized bytes behind for the truncate below to read.
    let len = unsafe {
        proc_pidpath(
            pid as i32,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len() as u32,
        )
    };
    if len > 0 {
        buf.truncate(len as usize);
        return match String::from_utf8(buf) {
            Ok(path) => BinaryPath::Known {
                path: PathBuf::from(path),
            },
            Err(_) => BinaryPath::Denied,
        };
    }

    match std::io::Error::last_os_error().kind() {
        std::io::ErrorKind::NotFound => BinaryPath::Deleted,
        _ => BinaryPath::Denied,
    }
}

/// Resolve the executable path for the given process.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn binary_path(_pid: u32) -> BinaryPath {
    BinaryPath::Unsupported
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_facts_are_readable() {
        let facts = process_facts(std::process::id());
        if ANCESTRY_SUPPORTED {
            let facts = facts.expect("own process facts must be readable");
            assert!(facts.ppid > 0);
            assert!(
                facts.start_time.is_some(),
                "start time is required for recycle validation within our own uid"
            );
        }
    }

    // Gated with the `getuid` extern it calls: on Windows there is no such symbol, and
    // `ANCESTRY_SUPPORTED` is a runtime check, so the body must not be compiled there.
    #[cfg(unix)]
    #[test]
    fn own_uid_matches_the_process_uid() {
        if ANCESTRY_SUPPORTED {
            let facts = process_facts(std::process::id()).expect("own facts");
            // SAFETY: getuid is always safe and cannot fail.
            let expected = unsafe { libc_getuid() };
            assert_eq!(facts.uid, expected);
        }
    }

    #[cfg(unix)]
    extern "C" {
        #[link_name = "getuid"]
        fn libc_getuid() -> u32;
    }

    #[test]
    fn ancestry_from_self_is_complete() {
        let ancestry = collect_ancestry(std::process::id());

        if !ANCESTRY_SUPPORTED {
            assert_eq!(ancestry.termination, WalkTermination::PlatformUnsupported);
            assert!(!ancestry.is_complete());
            return;
        }

        assert_eq!(ancestry.chain[0].pid, std::process::id());
        assert!(
            ancestry.is_complete(),
            "a walk within our own session must complete, at the root or the user \
             boundary: {:?}",
            ancestry.termination
        );
        assert!(
            ancestry.chain.len() >= 2,
            "the test runner always has a parent: {:?}",
            ancestry.chain
        );
    }

    #[test]
    fn ancestry_field_is_absent_without_a_pid_and_parses_with_one() {
        assert_eq!(ancestry_field(None), None);

        let pid = i32::try_from(std::process::id()).expect("pid fits i32");
        let field = ancestry_field(Some(pid)).expect("own pid serializes");
        let parsed: serde_json::Value = serde_json::from_str(&field).expect("valid JSON");
        assert!(parsed.get("termination").is_some());
        if ANCESTRY_SUPPORTED {
            assert_eq!(parsed["chain"][0]["pid"], u64::from(std::process::id()));
        }
    }

    #[test]
    fn ancestry_never_crosses_the_user_boundary() {
        let ancestry = collect_ancestry(std::process::id());
        let session_uid = ancestry.chain.first().map(|n| n.uid);
        for node in &ancestry.chain {
            assert_eq!(
                Some(node.uid),
                session_uid,
                "pid {} belongs to another user and must not be in the chain",
                node.pid
            );
        }
        // The boundary process itself is reported but never traversed into.
        if let WalkTermination::UserBoundary { at_pid, uid } = ancestry.termination {
            assert_ne!(Some(uid), session_uid);
            assert!(!ancestry.chain.iter().any(|n| n.pid == at_pid));
        }
    }

    #[test]
    fn ancestry_start_times_are_non_decreasing_toward_root() {
        let ancestry = collect_ancestry(std::process::id());
        // Ancestors are ordered caller → root, so each parent must have started no
        // later than its child.
        for pair in ancestry.chain.windows(2) {
            if let (Some(child), Some(parent)) = (pair[0].start_time, pair[1].start_time) {
                assert!(
                    parent <= child,
                    "parent {} started after child {}",
                    pair[1].pid,
                    pair[0].pid
                );
            }
        }
    }

    #[test]
    fn ancestry_is_depth_bounded() {
        let ancestry = collect_ancestry(std::process::id());
        assert!(ancestry.chain.len() <= MAX_ANCESTRY_DEPTH);
    }

    #[test]
    fn unknown_pid_terminates_without_panicking() {
        // u32::MAX is above every platform's pid_max, so it cannot exist.
        let ancestry = collect_ancestry(u32::MAX);
        assert!(!ancestry.is_complete());
        assert!(ancestry.chain.is_empty());
    }

    #[test]
    fn complete_and_incomplete_terminations_are_distinguished() {
        let complete = [
            WalkTermination::ReachedRoot,
            WalkTermination::UserBoundary { at_pid: 1, uid: 0 },
        ];
        let incomplete = [
            WalkTermination::DepthLimit,
            WalkTermination::ParentUnavailable { at_pid: 42 },
            WalkTermination::StartTimeViolation {
                child: 42,
                parent: 7,
            },
            WalkTermination::StartTimeUnavailable { at_pid: 42 },
            WalkTermination::PlatformUnsupported,
        ];
        for termination in complete {
            assert!(
                Ancestry {
                    chain: vec![],
                    termination: termination.clone()
                }
                .is_complete(),
                "{:?} should be complete",
                termination
            );
        }
        for termination in incomplete {
            assert!(
                !Ancestry {
                    chain: vec![],
                    termination: termination.clone()
                }
                .is_complete(),
                "{:?} should not be complete",
                termination
            );
        }
    }

    #[test]
    fn own_binary_path_resolves() {
        if ANCESTRY_SUPPORTED {
            let resolved = binary_path(std::process::id());
            let path = resolved
                .known()
                .unwrap_or_else(|| panic!("own binary path must resolve, got {:?}", resolved));
            assert!(path.is_absolute(), "{:?}", path);
        }
    }

    #[test]
    fn a_node_with_a_readable_path_is_identifiable() {
        let node = ProcessNode {
            pid: 100,
            uid: 501,
            binary_path: BinaryPath::Known {
                path: PathBuf::from("/bin/zsh"),
            },
            comm: Some("zsh".to_string()),
            start_time: Some(1),
        };
        assert!(node.is_identifiable());
    }

    #[test]
    fn identifiability_follows_the_classifier_precedence_rule() {
        let with_comm = |binary_path: BinaryPath| ProcessNode {
            pid: 100,
            uid: 501,
            binary_path,
            comm: Some("claude".to_string()),
            start_time: Some(1),
        };

        // A deleted binary is the one case where `comm` is an accepted substitute.
        assert!(with_comm(BinaryPath::Deleted).is_identifiable());
        assert!(!with_comm(BinaryPath::Denied).is_identifiable());
        assert!(!with_comm(BinaryPath::Unsupported).is_identifiable());

        let mut no_comm = with_comm(BinaryPath::Deleted);
        no_comm.comm = None;
        assert!(!no_comm.is_identifiable());
    }
}
