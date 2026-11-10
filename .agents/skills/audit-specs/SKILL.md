---
name: audit-specs
description: Audit specs for drift between requirements and implementation. Checks completed specs for regressions and validates requirement coverage. Use when asked to audit specs, check for drift, or verify spec compliance.
capabilities: read files, run shell commands, optionally delegate subtasks
---

# Spec Audit Skill

Audit the project's specs for drift between completed requirements and the current
codebase.

> **Spec location.** Specs live in `docs/specs/`, committed and present in a fresh clone.
> That is the only source of truth; this skill does not read any other spec directory a
> working tree may happen to carry.

## Arguments

The skill accepts an optional argument: a spec name or comma-separated list of spec names to audit.

- no argument — audit all completed specs (default behavior)
- `env-command` — audit only the `env-command` spec
- `env-command, get-output` — audit only the listed specs

When specific specs are provided, still verify they are complete — skip any that are not and note them in the output.

## Scope

Only audit specs whose `requirements.md` declares status `complete`. Specs with status `proposal`, `accepted`, or `draft` are not yet implemented — skip them.

Status is declared in one of two forms, both in use: a frontmatter-style `status: complete` line, or a bold prose `**Status:** complete` line. Match either — a pattern that only matches the first form silently skips most specs rather than reporting that it found none.

If no specs are complete (or none of the requested specs are complete), report that and exit.

## Procedure

### Step 1: Discover completed specs

**If specific specs were requested:**

Check each requested spec's status:
```bash
grep -lEi "^(status:|\*\*Status:\*\*) *complete" docs/specs/{spec_name}/requirements.md
```

Report any requested specs that were skipped (not found or not complete).

**If no specs were specified (audit all):**

```bash
grep -rlEi "^(status:|\*\*Status:\*\*) *complete" docs/specs/*/requirements.md
```

For each completed spec, extract:
- The spec name (directory name)
- All MUST/SHALL acceptance criteria (the verifiable assertions)
- The File Changes table from `design.md` (identifies which source files implement the spec)

### Step 2: Parallel verification

If your harness supports delegation, run one subagent per completed spec; otherwise work
through the specs in sequence, applying the same prompt to each. Each receives:
- The spec name
- The full `requirements.md` content
- The File Changes table from `design.md`
- Instructions below

**Prompt template:**

> You are auditing the spec `{spec_name}` for drift. The spec has `status: complete`, meaning the code MUST conform to every MUST/SHALL criterion in the requirements.
>
> Requirements:
> {requirements_md_content}
>
> Files that implement this spec (from design.md):
> {file_changes_table}
>
> For each MUST/SHALL acceptance criterion:
> 1. Read the implementing source file(s)
> 2. Determine if the criterion is still satisfied by the current code
> 3. If satisfied: mark as PASS
> 4. If violated (code no longer matches the requirement): mark as DRIFT with a one-line explanation of what changed
> 5. If the implementing file no longer exists: mark as DRIFT (file missing)
>
> Return a JSON object:
> ```json
> {
>   "spec": "{spec_name}",
>   "total_criteria": <number>,
>   "pass": <number>,
>   "drift": [
>     {
>       "requirement": <requirement number>,
>       "criterion": <criterion number>,
>       "text": "<the MUST/SHALL statement>",
>       "reason": "<what drifted and why>"
>     }
>   ]
> }
> ```
>
> Be precise. A criterion PASSes if the code satisfies it — even if the implementation approach differs from what design.md described. Only flag DRIFT when a MUST/SHALL is violated by the current code.
>
> Do NOT flag proposal/accepted specs referenced from this spec — only verify THIS spec's own criteria against the current code.

### Step 3: Aggregate and report

Once every spec has been checked, combine the results into a summary:

```
## Spec Audit Results

**Completed specs audited:** N
**Total MUST/SHALL criteria:** N
**Passing:** N
**Drift detected:** N

### Drift Details

| Spec | Req | AC | Criterion | Reason |
|------|-----|----|-----------|--------|
| env-command | 5 | 1 | URI SHALL be http://127.0.0.1:{port}/... | Port construction moved to CredentialEnv::new |
```

If no drift is detected, report:

```
## Spec Audit Results

**Completed specs audited:** N
**Total MUST/SHALL criteria:** N
**All passing. No drift detected.**
```

## Constraints

- Do NOT modify any files. This is a read-only audit.
- Do NOT audit specs with status `proposal` or `accepted` — they are not yet implemented.
- Do NOT flag acceptance criteria that use SHOULD/MAY — only MUST/SHALL are auditable assertions.
- Do NOT flag criteria about behavior that requires runtime testing (e.g., "MUST NOT add more than 5ms latency") — only flag criteria verifiable by code inspection.
- Keep each unit of work focused on one spec. Parallelism, where available, comes from
  running those units concurrently — not from broadening any one of them.
