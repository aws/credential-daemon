# Security Policy

## Reporting a Vulnerability

We kindly ask that you **do not** open a public GitHub issue to report security concerns.

Instead, please submit the issue to the AWS Vulnerability Disclosure Program via
[HackerOne](https://hackerone.com/aws_vdp) or send your report via
[email](mailto:aws-security@amazon.com).

Amazon Web Services (AWS) practices industry-standard Coordinated Vulnerability Disclosure (CVD)
with the goal of reducing adversary advantage while a security vulnerability is being addressed.
The [CERT® Guide to Coordinated Vulnerability Disclosure](https://certcc.github.io/CERT-Guide-to-CVD/tutorials/cvd_in_a_nutshell/)
provides information about the CVD process, and outlines tools and practices that can help
achieve this goal.

For more details, visit the
[AWS Vulnerability Reporting Page](https://aws.amazon.com/security/vulnerability-reporting/).

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof of concept
- The affected version(s)
- Any suggested fix (optional)

## Scope

This project handles AWS credentials and cryptographic key material. The
following are in scope for security reports:

- Credential exposure (plaintext leaks, insufficient zeroization)
- Authentication bypass (HMAC, bearer token, IMDSv2 session)
- Encryption weaknesses (key derivation, storage, envelope model)
- Privilege escalation (daemon user boundary, sandbox escape)
- Local network attacks (SSRF via loopback, cross-user credential access)

## Process Hardening

`credsd serve` holds the encryption key, every provider's refresh token, and live session
credentials in memory for the life of the process. At startup it applies the
anti-inspection controls the platform offers:

| Control | Platform | Applies in |
|---|---|---|
| `RLIMIT_CORE=0` (soft and hard) — no core dump of the address space on a crash | Linux, macOS | every build |
| `PR_SET_DUMPABLE=0` — denies `ptrace` attach and `/proc/<pid>/{mem,maps,environ}` | Linux | every build |
| `ptrace(PT_DENY_ATTACH)` — denies debugger attachment | macOS | **release builds only** |

These sit *behind* the transport boundary and do not replace it. They reduce what a
same-user process that was never granted a profile can read, and they keep the address
space out of a core file. They do **not** suppress every on-disk crash artifact — see the
macOS crash-reporter caveat below.

### These controls assume you trust how the daemon was launched

They protect a **running** daemon from a process that arrives later. They do not protect a
daemon that an attacker started.

A debugger that is attached *before* the daemon's own code runs keeps full access.
`gdb ./credsd serve` on Linux reads credentials out of a release build: the tracing
relationship is established by `fork` + `PTRACE_TRACEME` + `execve` before `main`, the
kernel checks `PR_SET_DUMPABLE` only at *attach* time, and clearing the flag afterwards
does not revoke a tracer already in place. (Verified — a breakpoint placed after the
`prctl` call returns successfully still reads the process's secrets.) On macOS
`PT_DENY_ATTACH` does block launch-under-debugger — but only a debugger, which is the
least of what a hostile launcher can do. Note the mechanism, because it looks like a bug:
`ptrace(2)` terminates an already-traced process rather than failing the request, so a
release daemon started under a debugger **exits with status 45** instead of refusing.

**No in-process control can close this, and none is meant to.** An attacker who decides how
the daemon starts does not need a debugger: `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES`, a
patched binary, or simply their own build with the hardening removed all work. A process
asking the kernel to protect itself cannot defend against whoever chose to run that process.

Two things follow, and they are the actual security requirements here:

1. **Launch `credsd serve` from a trusted path** — a supervisor-managed service
   (`launchd`, `systemd`) whose unit file and binary are not writable by the account the
   daemon serves. This assumption is load-bearing.
2. **Kernel-enforced-at-`exec` protection is the real fix**, because it is not the
   process's request to make: on macOS, a binary signed with the hardened runtime and
   without the `get-task-allow` entitlement cannot be attached to *even by its launcher*.
   Linux has no direct equivalent, which is why (1) carries the weight there.

Corollary for maintainers: the fact that `gdb ./credsd serve` still works on Linux is
**not** a gap to be closed with `PR_SET_PTRACER` (which grants `ptrace` permission — the
inverse) or a Yama `ptrace_scope` change. It is a boundary of the technique.

### Specifically not defended against

- **Root, or any process with `CAP_SYS_PTRACE`.** Both bypass every control above by
  design. Root is already out of scope below.
- **A debug build on macOS.** `PT_DENY_ATTACH` is skipped when `debug_assertions` is
  enabled, so a `cargo build` (non-`--release`) daemon can be attached to. Do not run one
  where its credentials matter.
- **The macOS crash reporter.** `RLIMIT_CORE=0` stops the kernel writing a core file; it
  does not reach `ReportCrash`, which still writes an `.ips` report to
  `~/Library/Logs/DiagnosticReports/` on a crash. That report is not an address-space dump,
  but it does carry every thread's register file by value (29 general-purpose registers per
  thread on arm64, plus `pc`/`lr`/`sp`/`fp` and the instruction bytes around the fault), so
  key material that happened to be in a register at crash time reaches disk. Suppressing it
  would mean installing our own Mach exception handler, which risks swallowing real
  crashes; treat crash reports from a daemon host as sensitive instead.
- **Swap.** Secrets are not `mlock`ed; a page holding credential material may reach swap.
- **`credsd run`'s proxy.** It holds live session credentials for the child command's
  lifetime and is not hardened — `RLIMIT_CORE` would be inherited by the child, and the
  dumpable flag is reset by `execve`.

A hardening call the platform rejects is logged and non-fatal; the daemon's own log records
which controls took effect.

## OAuth Loopback Callback — Fixed Port

`--callback-port` (for `creds bootstrap aws-login`) binds a fixed loopback port so the
redirect URI can be pre-registered with IdPs that require an exact URI match (e.g.
Cognito). This narrows the attack surface for the callback relative to a random ephemeral
port:

**DoS (out of scope):** Another local process can occupy the fixed port before the flow
starts, causing `bind` to fail with a clear error. This is a local denial-of-service and
is out of scope per the policy below.

**Code-redirect (MEDIUM / local attacker):** An attacker who knows the registered
`client_id` and redirect URI can race the flow:
1. Wait for the user's bootstrap to release the port (e.g. after a timeout).
2. Bind the same port.
3. Start a separate authorization request against the same public app using their own PKCE
   verifier.
4. If the IdP silently re-uses the user's live session, it redirects a code to the
   attacker's listener.

PKCE does not prevent this because the attacker controls their own verifier; PKCE only
prevents an attacker from redeeming a code they intercepted from someone else's flow.

This scenario requires: (a) a local attacker, (b) a public OAuth client (no client
secret), (c) the IdP silently reusing an existing session without a new consent
prompt, and (d) precise timing. It is not a defect in this codebase — it is inherent to
RFC 8252 loopback redirects with a pre-registered port — but it is a threat-model delta
worth knowing. Mitigation: use a private client (client secret or `private_key_jwt`),
which makes step 3 unreachable without the secret.

## Out of Scope

- Denial of service against the local daemon (local attacker already has DoS)
- Attacks requiring root on the same machine (root is trusted at install time)
- Social engineering or phishing
- Memory inspection or crash-dump recovery by a privileged process (see Process Hardening)
