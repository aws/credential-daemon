//! Caller classification from collected process evidence.
//!
//! Classification only — no verdicts. This layer turns an ancestry walk plus a
//! caller's self-report into a `CallerAssessment` for audit; the enforcement layer
//! that maps assessments to allow/deny decisions is a separate increment.

use super::process_tree::{collect_ancestry, Ancestry, BinaryPath, WalkTermination, COMM_MAX_LEN};
use serde::Serialize;
use std::path::Path;

// The claim type lives in `credsd-core`; re-exported so the daemon's own
// `classify::ClaimedIdentity` references keep resolving. The claim now arrives as a
// JSON-RPC params field rather than an HTTP header, so no header-parsing lives here.
pub use credsd_core::wire::ClaimedIdentity;

/// What the ancestry walk established about agentic ancestors.
///
/// `NoneFound` and `Indeterminate` are deliberately distinct: the first is a
/// positive finding over a complete lineage, the second is an absence of evidence.
/// Collapsing them would let a failed walk read as a clean one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AgentEvidence {
    /// An allowlisted agent binary was found at `depth` steps from the caller
    /// (0 = the caller itself).
    Matched {
        pid: u32,
        /// The executable path when known, otherwise the kernel `comm` that matched.
        name: String,
        matched_on: MatchSource,
        depth: usize,
    },
    /// The walk completed — at the root or the user boundary — every process in it
    /// was identifiable, and no agent appeared anywhere in the caller's own lineage.
    NoneFound,
    /// The walk could not complete, so absence of a match proves nothing.
    Indeterminate(WalkTermination),
    /// The walk completed but at least one process could not be named at all, so an
    /// agent could be hiding in the gap.
    OpaqueAncestor { pid: u32, depth: usize },
}

impl AgentEvidence {
    /// Stable name for the log's `observed` field, so a query does not have to match on
    /// `Debug` formatting.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Matched { .. } => "matched",
            Self::NoneFound => "none_found",
            Self::Indeterminate(_) => "indeterminate",
            Self::OpaqueAncestor { .. } => "opaque_ancestor",
        }
    }

    /// The matched agent's name, for the audit record (Req 7.8).
    pub fn matched_name(&self) -> Option<&str> {
        match self {
            Self::Matched { name, .. } => Some(name),
            _ => None,
        }
    }

    /// The matched agent's distance from the caller (Req 7.8).
    pub fn matched_depth(&self) -> Option<usize> {
        match self {
            Self::Matched { depth, .. } => Some(*depth),
            _ => None,
        }
    }
}

/// Which name an agent match was made against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchSource {
    /// The executable path — the stronger signal.
    BinaryPath,
    /// The kernel `comm`, used when the executable has been unlinked. Truncated to
    /// 15 bytes and settable by the process itself, so it is weaker evidence.
    Comm,
}

/// The full evidence record for one credential request.
#[derive(Debug, Clone, Serialize)]
pub struct CallerAssessment {
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub transport: &'static str,
    pub env: String,
    pub claimed: ClaimedIdentity,
    pub observed: AgentEvidence,
    pub ancestry: Option<Ancestry>,
}

impl CallerAssessment {
    /// Assess a caller, walking its ancestry when the transport supplied a PID.
    ///
    /// A positive claim does not short-circuit the walk: the ancestry is still the
    /// only source of the detail an audit trail needs, and skipping it would erase
    /// the difference between an agent that self-reported and one that did not.
    pub fn collect(
        pid: Option<u32>,
        uid: Option<u32>,
        transport: &'static str,
        env: impl Into<String>,
        claimed: ClaimedIdentity,
        agent_binaries: &[String],
    ) -> Self {
        let (observed, ancestry) = match pid {
            Some(pid) => {
                let ancestry = collect_ancestry(pid);
                (classify(&ancestry, agent_binaries), Some(ancestry))
            }
            None => (
                AgentEvidence::Indeterminate(WalkTermination::ParentUnavailable { at_pid: 0 }),
                None,
            ),
        };

        Self {
            pid,
            uid,
            transport,
            env: env.into(),
            claimed,
            observed,
            ancestry,
        }
    }

    /// Whether the caller should be treated as agentic, combining observation with
    /// the self-report. A claim can only add agentic status, never remove it.
    pub fn is_agentic(&self) -> bool {
        self.claimed == ClaimedIdentity::Agentic
            || matches!(self.observed, AgentEvidence::Matched { .. })
    }

    /// How the claim and the observation line up, as a single named signal.
    ///
    /// Derived rather than stored: a stored field could drift out of agreement with
    /// `claimed`/`observed`, which must remain separate and uncollapsed (Req 8.4). This
    /// adds a name for the combination without replacing either input.
    pub fn signal(&self) -> Signal {
        let observed_agent = matches!(self.observed, AgentEvidence::Matched { .. });
        match (self.claimed, observed_agent) {
            (ClaimedIdentity::Unstated | ClaimedIdentity::Unknown, true) => Signal::UnreportedAgent,
            (ClaimedIdentity::Agentic, true) => Signal::ConfirmedAgent,
            (ClaimedIdentity::Agentic, false) => Signal::ClaimOnly,
            (ClaimedIdentity::Unstated | ClaimedIdentity::Unknown, false) => {
                match self.observed {
                    AgentEvidence::NoneFound => Signal::NoAgent,
                    // Neither a match nor a sound negative: the walk could not settle it.
                    _ => Signal::Undetermined,
                }
            }
        }
    }

    /// The most specific name for the caller, for a log line that has no room for the
    /// whole chain. `None` when no name could be established at all.
    ///
    /// This is a name, never a command line: `argv` routinely carries tokens and
    /// passwords, and Req 6.5 keeps credential material out of the audit record.
    pub fn caller_name(&self) -> Option<&str> {
        let node = self.ancestry.as_ref()?.chain.first()?;
        node.binary_path
            .known()
            .and_then(|p| p.to_str())
            .or(node.comm.as_deref())
    }

    /// Emit the audit record (Req 6.1, 6.4, 7.8, 8.4, 8.5).
    ///
    /// The full assessment — including every ancestor's name and the walk's termination
    /// reason — is serialized into one field, so an agent the allowlist failed to
    /// recognize is still recoverable from the log after the fact. That is what makes a
    /// best-effort allowlist safe to ship: it governs what is *classified*, not what is
    /// *recorded*.
    pub fn log(&self) {
        let signal = self.signal();
        let evidence = serde_json::to_string(self)
            .unwrap_or_else(|_| r#"{"error":"assessment failed to serialize"}"#.to_string());

        // An agent in the lineage that did not self-report is the highest-value signal
        // this feature produces — it means a stale allowlist or an evasion attempt — so
        // it is emitted at a level that separates it from routine traffic (Req 8.5).
        if signal == Signal::UnreportedAgent {
            tracing::warn!(
                pid = self.pid,
                uid = self.uid,
                transport = self.transport,
                // Recorded as a str, never `%`: the env arrives from caller-supplied params,
                // and Display would write a caller-supplied newline raw, letting it forge a
                // whole audit record in the text formatter.
                env = self.env.as_str(),
                signal = signal.as_str(),
                claimed = ?self.claimed,
                observed = self.observed.as_str(),
                agent = self.observed.matched_name(),
                depth = self.observed.matched_depth(),
                caller = self.caller_name(),
                agentic = self.is_agentic(),
                evidence = %evidence,
                "caller assessment: agent in lineage did not self-report"
            );
            return;
        }

        tracing::info!(
            pid = self.pid,
            uid = self.uid,
            transport = self.transport,
            env = self.env.as_str(),
            signal = signal.as_str(),
            claimed = ?self.claimed,
            observed = self.observed.as_str(),
            agent = self.observed.matched_name(),
            depth = self.observed.matched_depth(),
            caller = self.caller_name(),
            agentic = self.is_agentic(),
            evidence = %evidence,
            "caller assessment"
        );
    }
}

/// How a caller's claim lines up with what the walk observed (Req 8.5).
///
/// Named so each combination is greppable on its own rather than requiring an operator
/// to reconstruct a conjunction of `claimed` and `observed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    /// An allowlisted agent is in the lineage and the caller did not say so. Either a
    /// stale allowlist or an evasion attempt; the highest-value signal here.
    UnreportedAgent,
    /// Claim and observation agree.
    ConfirmedAgent,
    /// The caller declared itself agentic but the walk found no allowlisted agent —
    /// expected for an in-house harness, or where the walk cannot see (Windows).
    ClaimOnly,
    /// A complete walk over fully identifiable ancestors found no agent.
    NoAgent,
    /// The walk could not support any finding: incomplete, or an ancestor that could
    /// not be named. Distinct from `NoAgent`, which is a positive result.
    Undetermined,
}

impl Signal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnreportedAgent => "unreported_agent",
            Self::ConfirmedAgent => "confirmed_agent",
            Self::ClaimOnly => "claim_only",
            Self::NoAgent => "no_agent",
            Self::Undetermined => "undetermined",
        }
    }
}

/// Search an ancestry for an allowlisted agent, nearest the caller first.
///
/// A match is reported on either the executable path or the kernel `comm`, because
/// the path vanishes when a running agent's binary is unlinked — which happens
/// whenever a long-lived agent is upgraded in place. Matching on path alone would
/// silently miss exactly the process this classifier exists to find.
pub fn classify(ancestry: &Ancestry, agent_binaries: &[String]) -> AgentEvidence {
    let mut opaque: Option<(u32, usize)> = None;

    for (depth, node) in ancestry.chain.iter().enumerate() {
        // Strict precedence. `comm` is consulted only when the executable itself is
        // gone (`Deleted`), never to supplement or override a path we could read, and
        // never when the kernel merely withheld one. A process can set its own
        // `comm`, so using it as a general matching channel would let any process
        // manufacture a match against a name its executable does not have. Confined
        // to the deleted-binary case that spoofability is harmless: claiming to be an
        // agent can only narrow the claimant's own access, never widen it.
        let matched = match &node.binary_path {
            BinaryPath::Known { path } => is_agent_binary(path, agent_binaries)
                .then(|| (path.to_string_lossy().into_owned(), MatchSource::BinaryPath)),
            BinaryPath::Deleted => node
                .comm
                .as_ref()
                .filter(|comm| is_agent_comm(comm, agent_binaries))
                .map(|comm| (comm.clone(), MatchSource::Comm)),
            BinaryPath::Denied | BinaryPath::Unsupported => None,
        };

        if let Some((name, matched_on)) = matched {
            return AgentEvidence::Matched {
                pid: node.pid,
                name,
                matched_on,
                depth,
            };
        }

        if !node.is_identifiable() && opaque.is_none() {
            opaque = Some((node.pid, depth));
        }
    }

    // Only a complete walk can support a negative finding. An incomplete one may
    // have stopped short of the agent.
    if !ancestry.is_complete() {
        return AgentEvidence::Indeterminate(ancestry.termination.clone());
    }

    // A complete walk still cannot support a negative finding if some process in it
    // could not be named at all.
    match opaque {
        Some((pid, depth)) => AgentEvidence::OpaqueAncestor { pid, depth },
        None => AgentEvidence::NoneFound,
    }
}

/// Match a binary path against the allowlist by file stem, case-insensitively.
/// The stem drops a `.exe` suffix so one list serves every platform.
fn is_agent_binary(path: &Path, agent_binaries: &[String]) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    agent_binaries
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(stem))
}

/// Match a kernel `comm` against the allowlist. Each entry is truncated to
/// `COMM_MAX_LEN` first, since the kernel truncates the name it stores and a longer
/// allowlist entry would otherwise never compare equal.
fn is_agent_comm(comm: &str, agent_binaries: &[String]) -> bool {
    // `comm` is a bare name, but a path can reach it: macOS sets it from the last
    // path component, and a process can write an arbitrary string on Linux.
    let name = Path::new(comm)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(comm);

    agent_binaries.iter().any(|candidate| {
        let truncated = truncate_to_comm_len(candidate);
        truncated.eq_ignore_ascii_case(name) || truncated.eq_ignore_ascii_case(comm)
    })
}

/// Truncate on a char boundary so a multi-byte allowlist entry cannot panic.
fn truncate_to_comm_len(candidate: &str) -> &str {
    if candidate.len() <= COMM_MAX_LEN {
        return candidate;
    }
    // The highest char boundary at or below the cap. `char_indices` yields boundaries directly,
    // so there is no decrementing scan to walk off the front and no index the slice can reject.
    let end = candidate
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|i| *i <= COMM_MAX_LEN)
        .last()
        .unwrap_or(0);
    candidate.get(..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::process_tree::ProcessNode;
    use credsd_core::config::default_agent_binaries;
    use std::path::PathBuf;

    fn allowlist() -> Vec<String> {
        default_agent_binaries().to_vec()
    }

    /// A node with a readable executable path.
    fn node(pid: u32, path: &str) -> ProcessNode {
        ProcessNode {
            pid,
            uid: 501,
            binary_path: BinaryPath::Known {
                path: PathBuf::from(path),
            },
            comm: Path::new(path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned()),
            start_time: Some(1),
        }
    }

    /// A node whose executable was unlinked, leaving only `comm`.
    fn deleted_node(pid: u32, comm: Option<&str>) -> ProcessNode {
        ProcessNode {
            pid,
            uid: 501,
            binary_path: BinaryPath::Deleted,
            comm: comm.map(str::to_string),
            start_time: Some(1),
        }
    }

    /// A node the kernel refused to describe.
    fn denied_node(pid: u32, comm: Option<&str>) -> ProcessNode {
        ProcessNode {
            pid,
            uid: 501,
            binary_path: BinaryPath::Denied,
            comm: comm.map(str::to_string),
            start_time: Some(1),
        }
    }

    fn ancestry(chain: Vec<ProcessNode>, termination: WalkTermination) -> Ancestry {
        Ancestry { chain, termination }
    }

    #[test]
    fn matches_agent_in_ancestry_at_correct_depth() {
        let a = ancestry(
            vec![
                node(100, "/usr/bin/bash"),
                node(50, "/opt/homebrew/bin/claude"),
                node(1, "/sbin/launchd"),
            ],
            WalkTermination::ReachedRoot,
        );
        match classify(&a, &allowlist()) {
            AgentEvidence::Matched {
                pid,
                depth,
                name,
                matched_on,
            } => {
                assert_eq!(pid, 50);
                assert_eq!(depth, 1);
                assert_eq!(name, "/opt/homebrew/bin/claude");
                assert_eq!(matched_on, MatchSource::BinaryPath);
            }
            other => panic!("expected match, got {:?}", other),
        }
    }

    #[test]
    fn matches_nearest_agent_when_several_are_present() {
        let a = ancestry(
            vec![
                node(100, "/usr/bin/bash"),
                node(50, "/bin/codex"),
                node(20, "/bin/claude"),
            ],
            WalkTermination::ReachedRoot,
        );
        match classify(&a, &allowlist()) {
            AgentEvidence::Matched { pid, depth, .. } => {
                assert_eq!(pid, 50);
                assert_eq!(depth, 1);
            }
            other => panic!("expected match, got {:?}", other),
        }
    }

    #[test]
    fn matches_the_caller_itself_at_depth_zero() {
        let a = ancestry(
            vec![node(100, "/usr/local/bin/claude")],
            WalkTermination::ReachedRoot,
        );
        assert!(matches!(
            classify(&a, &allowlist()),
            AgentEvidence::Matched { depth: 0, .. }
        ));
    }

    #[test]
    fn complete_walk_without_agent_is_none_found() {
        let a = ancestry(
            vec![node(100, "/usr/bin/bash"), node(1, "/sbin/init")],
            WalkTermination::ReachedRoot,
        );
        assert_eq!(classify(&a, &allowlist()), AgentEvidence::NoneFound);
    }

    #[test]
    fn walk_stopped_at_the_user_boundary_is_none_found() {
        // The common case on a login shell: the lineage tops out at a root-owned
        // `login`. The caller's own lineage was fully seen, so a negative finding is
        // sound — treating this as indeterminate would make classification useless.
        let a = ancestry(
            vec![node(100, "/bin/zsh"), node(90, "/bin/login")],
            WalkTermination::UserBoundary { at_pid: 80, uid: 0 },
        );
        assert_eq!(classify(&a, &allowlist()), AgentEvidence::NoneFound);
    }

    #[test]
    fn incomplete_walk_without_agent_is_indeterminate_not_none_found() {
        for termination in [
            WalkTermination::DepthLimit,
            WalkTermination::ParentUnavailable { at_pid: 7 },
            WalkTermination::StartTimeViolation {
                child: 100,
                parent: 7,
            },
            WalkTermination::PlatformUnsupported,
        ] {
            let a = ancestry(vec![node(100, "/usr/bin/bash")], termination.clone());
            assert_eq!(
                classify(&a, &allowlist()),
                AgentEvidence::Indeterminate(termination),
                "an incomplete walk must never read as a clean one"
            );
        }
    }

    #[test]
    fn an_agent_found_before_the_walk_broke_still_matches() {
        // Evidence already in hand is not invalidated by a later failure.
        let a = ancestry(
            vec![node(100, "/bin/claude"), denied_node(50, None)],
            WalkTermination::ParentUnavailable { at_pid: 50 },
        );
        assert!(matches!(
            classify(&a, &allowlist()),
            AgentEvidence::Matched { pid: 100, .. }
        ));
    }

    #[test]
    fn deleted_binary_falls_back_to_comm() {
        // An agent upgraded in place while running: the executable is unlinked, so
        // only `comm` remains. Missing this is a fail-open on the exact process the
        // classifier exists to find.
        let a = ancestry(
            vec![node(100, "/bin/bash"), deleted_node(50, Some("claude"))],
            WalkTermination::ReachedRoot,
        );
        match classify(&a, &allowlist()) {
            AgentEvidence::Matched {
                pid,
                matched_on,
                name,
                ..
            } => {
                assert_eq!(pid, 50);
                assert_eq!(matched_on, MatchSource::Comm);
                assert_eq!(name, "claude");
            }
            other => panic!("expected a comm match, got {:?}", other),
        }
    }

    #[test]
    fn comm_is_not_consulted_when_the_path_is_readable() {
        // Strict precedence: a process whose executable is plainly not an agent
        // cannot acquire agent status by naming its thread "claude".
        let mut spoofer = node(50, "/tmp/definitely-not-an-agent");
        spoofer.comm = Some("claude".to_string());
        let a = ancestry(
            vec![node(100, "/bin/bash"), spoofer],
            WalkTermination::ReachedRoot,
        );
        assert_eq!(classify(&a, &allowlist()), AgentEvidence::NoneFound);
    }

    #[test]
    fn comm_is_not_consulted_when_the_path_was_merely_denied() {
        // A withheld path is not the same as a deleted one: nothing licenses trusting
        // a self-set name here, so the node is opaque rather than matched.
        let a = ancestry(
            vec![node(100, "/bin/bash"), denied_node(50, Some("claude"))],
            WalkTermination::ReachedRoot,
        );
        assert_eq!(
            classify(&a, &allowlist()),
            AgentEvidence::OpaqueAncestor { pid: 50, depth: 1 }
        );
    }

    #[test]
    fn a_wholly_unidentifiable_ancestor_blocks_a_negative_finding() {
        let a = ancestry(
            vec![node(100, "/bin/bash"), deleted_node(50, None)],
            WalkTermination::ReachedRoot,
        );
        assert_eq!(
            classify(&a, &allowlist()),
            AgentEvidence::OpaqueAncestor { pid: 50, depth: 1 },
            "an agent could be hiding in a process we cannot name"
        );
    }

    #[test]
    fn a_match_outranks_a_later_opaque_ancestor() {
        let a = ancestry(
            vec![node(100, "/bin/claude"), denied_node(50, None)],
            WalkTermination::ReachedRoot,
        );
        assert!(matches!(
            classify(&a, &allowlist()),
            AgentEvidence::Matched { pid: 100, .. }
        ));
    }

    #[test]
    fn empty_allowlist_matches_nothing() {
        let a = ancestry(vec![node(100, "/bin/claude")], WalkTermination::ReachedRoot);
        assert_eq!(classify(&a, &[]), AgentEvidence::NoneFound);
    }

    #[test]
    fn comm_match_tolerates_kernel_truncation() {
        // The kernel stores at most 15 bytes, so a longer allowlist entry must be
        // truncated before comparison or it could never match.
        let long = "a-very-long-agent-binary-name".to_string();
        let truncated = long.get(..COMM_MAX_LEN).expect("ascii, so a byte boundary");
        let a = ancestry(
            vec![deleted_node(100, Some(truncated))],
            WalkTermination::ReachedRoot,
        );
        assert!(matches!(
            classify(&a, &[long]),
            AgentEvidence::Matched {
                matched_on: MatchSource::Comm,
                ..
            }
        ));
    }

    /// The contract the truncation must satisfy: the longest prefix that fits the kernel's
    /// `comm` field and ends on a char boundary. Asserted directly rather than through
    /// `classify`, so a boundary walk that quietly drops a char it could have kept is caught.
    #[test]
    fn truncation_keeps_the_longest_prefix_that_fits() {
        for candidate in [
            "",
            "short",
            "a-very-long-agent-binary-name",
            "агентский-бинарник",
            "日本語のバイナリ名",
        ] {
            let truncated = truncate_to_comm_len(candidate);
            assert!(
                candidate.starts_with(truncated),
                "{candidate:?} -> {truncated:?} is not a prefix"
            );
            if candidate.len() <= COMM_MAX_LEN {
                assert_eq!(truncated, candidate, "a short name must survive intact");
                continue;
            }
            assert!(
                truncated.len() <= COMM_MAX_LEN,
                "{candidate:?} -> {truncated:?} exceeds the cap"
            );
            // Nothing longer would have fit: taking one more char passes the cap.
            let next = candidate
                .get(truncated.len()..)
                .and_then(|rest| rest.chars().next())
                .map_or(0, char::len_utf8);
            assert!(
                truncated.len().saturating_add(next) > COMM_MAX_LEN,
                "{candidate:?} -> {truncated:?} discarded a char that fit"
            );
        }
    }

    #[test]
    fn multibyte_allowlist_entry_does_not_panic_on_truncation() {
        // Truncation must land on a char boundary.
        let entry = "агентский-бинарник".to_string();
        let a = ancestry(
            vec![deleted_node(100, Some("claude"))],
            WalkTermination::ReachedRoot,
        );
        assert_eq!(classify(&a, &[entry]), AgentEvidence::NoneFound);
    }

    #[test]
    fn match_is_case_insensitive_and_ignores_exe_suffix() {
        // Separators are platform-native, so this uses `/` rather than a Windows
        // path literal, which `Path` would treat as one component on Unix.
        for path in ["/bin/Claude", "/bin/CLAUDE", "/tools/claude.exe"] {
            assert!(
                is_agent_binary(Path::new(path), &allowlist()),
                "{} should match",
                path
            );
        }
    }

    #[test]
    fn similar_names_do_not_match() {
        for path in ["/bin/claudette", "/bin/my-claude", "/bin/cursor-helper"] {
            assert!(
                !is_agent_binary(Path::new(path), &allowlist()),
                "{} should not match",
                path
            );
        }
    }

    #[test]
    fn claim_adds_agentic_status_when_nothing_was_observed() {
        let assessment = CallerAssessment {
            pid: Some(100),
            uid: Some(501),
            transport: "uds",
            env: "dev".to_string(),
            claimed: ClaimedIdentity::Agentic,
            observed: AgentEvidence::NoneFound,
            ancestry: None,
        };
        assert!(assessment.is_agentic());
    }

    #[test]
    fn absent_claim_does_not_clear_an_observed_agent() {
        let assessment = CallerAssessment {
            pid: Some(100),
            uid: Some(501),
            transport: "uds",
            env: "dev".to_string(),
            claimed: ClaimedIdentity::Unstated,
            observed: AgentEvidence::Matched {
                pid: 50,
                name: "/bin/claude".to_string(),
                matched_on: MatchSource::BinaryPath,
                depth: 1,
            },
            ancestry: None,
        };
        assert!(assessment.is_agentic());
    }

    #[test]
    fn unstated_claim_with_no_observation_is_not_agentic() {
        let assessment = CallerAssessment {
            pid: Some(100),
            uid: None,
            transport: "uds",
            env: "dev".to_string(),
            claimed: ClaimedIdentity::Unstated,
            observed: AgentEvidence::NoneFound,
            ancestry: None,
        };
        assert!(!assessment.is_agentic());
    }

    #[test]
    fn missing_pid_yields_indeterminate_and_no_ancestry() {
        let assessment = CallerAssessment::collect(
            None,
            None,
            "uds",
            "dev",
            ClaimedIdentity::Unstated,
            &allowlist(),
        );
        assert!(matches!(
            assessment.observed,
            AgentEvidence::Indeterminate(_)
        ));
        assert!(assessment.ancestry.is_none());
        assert!(!assessment.is_agentic());
    }

    #[test]
    fn collect_walks_the_real_ancestry_of_this_process() {
        let assessment = CallerAssessment::collect(
            Some(std::process::id()),
            None,
            "uds",
            "dev",
            ClaimedIdentity::Unstated,
            &allowlist(),
        );
        let ancestry = assessment.ancestry.expect("pid was supplied");
        // Where the platform cannot supply process facts the chain is empty by design,
        // so the walk is only assertable on the platforms that support one.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(ancestry.chain[0].pid, std::process::id());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert!(ancestry.chain.is_empty());
    }

    #[test]
    fn assessment_serializes_without_dropping_evidence() {
        let assessment = CallerAssessment {
            pid: Some(100),
            uid: Some(501),
            transport: "uds",
            env: "dev".to_string(),
            claimed: ClaimedIdentity::Agentic,
            observed: AgentEvidence::Indeterminate(WalkTermination::DepthLimit),
            ancestry: Some(ancestry(
                vec![node(100, "/bin/bash"), deleted_node(50, Some("claude"))],
                WalkTermination::DepthLimit,
            )),
        };
        let json = serde_json::to_value(&assessment).expect("assessment must serialize");
        assert_eq!(json["claimed"], "agentic");
        assert_eq!(json["observed"]["result"], "indeterminate");
        assert_eq!(json["observed"]["reason"], "depth_limit");
        assert_eq!(json["ancestry"]["termination"]["reason"], "depth_limit");
        // The path state must survive serialization: an auditor has to be able to
        // tell a deleted binary from a withheld one.
        assert_eq!(
            json["ancestry"]["chain"][0]["binary_path"]["state"],
            "known"
        );
        assert_eq!(
            json["ancestry"]["chain"][1]["binary_path"]["state"],
            "deleted"
        );
        assert_eq!(json["ancestry"]["chain"][1]["comm"], "claude");
    }

    fn assessment(claimed: ClaimedIdentity, observed: AgentEvidence) -> CallerAssessment {
        CallerAssessment {
            pid: Some(100),
            uid: Some(501),
            transport: "uds",
            env: "dev".to_string(),
            claimed,
            observed,
            ancestry: None,
        }
    }

    fn matched() -> AgentEvidence {
        AgentEvidence::Matched {
            pid: 50,
            name: "/bin/claude".to_string(),
            matched_on: MatchSource::BinaryPath,
            depth: 1,
        }
    }

    #[test]
    fn signal_distinguishes_every_claim_observation_combination() {
        use ClaimedIdentity::{Agentic, Unstated};
        let cases = [
            (Unstated, matched(), Signal::UnreportedAgent),
            (Agentic, matched(), Signal::ConfirmedAgent),
            (Agentic, AgentEvidence::NoneFound, Signal::ClaimOnly),
            (Unstated, AgentEvidence::NoneFound, Signal::NoAgent),
        ];
        for (claimed, observed, expected) in cases {
            assert_eq!(
                assessment(claimed, observed.clone()).signal(),
                expected,
                "claimed {:?} + observed {:?}",
                claimed,
                observed
            );
        }
    }

    #[test]
    fn an_unsettled_walk_never_reports_as_no_agent() {
        // Req 7.5/8.5: the absence of a match is only a finding when the walk could
        // actually have seen one. Both failure shapes must stay out of `NoAgent`.
        for observed in [
            AgentEvidence::Indeterminate(WalkTermination::DepthLimit),
            AgentEvidence::Indeterminate(WalkTermination::PlatformUnsupported),
            AgentEvidence::OpaqueAncestor { pid: 50, depth: 1 },
        ] {
            assert_eq!(
                assessment(ClaimedIdentity::Unstated, observed.clone()).signal(),
                Signal::Undetermined,
                "{:?} must not read as a clean negative",
                observed
            );
        }
    }

    #[test]
    fn a_claim_is_never_collapsed_into_the_observation() {
        // Req 8.4: the signal names the combination; it must not overwrite either input.
        let a = assessment(ClaimedIdentity::Agentic, matched());
        assert_eq!(a.signal(), Signal::ConfirmedAgent);
        assert_eq!(a.claimed, ClaimedIdentity::Agentic);
        assert!(matches!(a.observed, AgentEvidence::Matched { .. }));

        let json = serde_json::to_value(&a).expect("must serialize");
        assert_eq!(json["claimed"], "agentic");
        assert_eq!(json["observed"]["result"], "matched");
    }

    #[test]
    fn caller_name_prefers_the_path_and_falls_back_to_comm() {
        let mut a = assessment(ClaimedIdentity::Unstated, AgentEvidence::NoneFound);

        a.ancestry = Some(ancestry(
            vec![node(100, "/bin/zsh"), node(50, "/bin/claude")],
            WalkTermination::ReachedRoot,
        ));
        assert_eq!(
            a.caller_name(),
            Some("/bin/zsh"),
            "the caller, not the agent"
        );

        a.ancestry = Some(ancestry(
            vec![deleted_node(100, Some("zsh"))],
            WalkTermination::ReachedRoot,
        ));
        assert_eq!(a.caller_name(), Some("zsh"));

        a.ancestry = Some(ancestry(
            vec![deleted_node(100, None)],
            WalkTermination::ReachedRoot,
        ));
        assert_eq!(a.caller_name(), None);

        a.ancestry = None;
        assert_eq!(a.caller_name(), None);
    }

    #[test]
    fn matched_attribution_is_present_only_for_a_match() {
        let m = matched();
        assert_eq!(m.matched_name(), Some("/bin/claude"));
        assert_eq!(m.matched_depth(), Some(1));

        for other in [
            AgentEvidence::NoneFound,
            AgentEvidence::Indeterminate(WalkTermination::DepthLimit),
            AgentEvidence::OpaqueAncestor { pid: 50, depth: 1 },
        ] {
            assert_eq!(other.matched_name(), None);
            assert_eq!(other.matched_depth(), None);
        }
    }
}
