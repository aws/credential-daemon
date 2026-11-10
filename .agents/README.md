# Agent Guidance

Agent-neutral guidance for AI coding agents working on credsd, in a form any agent
harness can consume.

`AGENTS.md` at the repo root is the entry point and holds the always-on rules — build
commands, code style, commit conventions, spec coherence. This directory holds the parts
that are too long or too situational to keep there:

| Path | Contents |
|------|----------|
| `rules/` | Standing rules that apply to every change, referenced from the skills |
| `skills/` | Task-scoped procedures invoked on demand, one directory per skill |

Where a file is adapted from third-party work, it carries the source and license in its
frontmatter and an attribution note in the body — `rules/minimalism.md` derives from the
MIT-licensed `ponytail` skill.

## Why these files are agent-neutral

Agent-specific config is gitignored (`.claude/`, `.cursor/`, `.cursorrules`,
`.github/copilot-instructions.md`) because it encodes one vendor's file layout,
frontmatter schema, and tool names. What survives that stripping — the threat model, the
checklists, the report format, the definition of a finding worth reporting — is
project knowledge, and it belongs in the repo where it can be reviewed and versioned
alongside the code it describes.

So these files describe *what to do* and deliberately not *which tool call to make*.
Where a procedure needs a capability (read a file, run a command, delegate a subtask),
it names the capability rather than a vendor's tool name.

## Using them with your agent

Most harnesses discover instructions from a directory they own. Point yours at these
files rather than copying them — a copy silently goes stale.

**Claude Code** reads `.claude/skills/<name>/SKILL.md` and expects YAML frontmatter with
`name`, `description`, and optionally `allowed-tools`. Symlink the body and add
frontmatter locally, or symlink the whole directory if you keep the frontmatter here:

```bash
mkdir -p .claude/skills
ln -s ../../.agents/skills/security-review .claude/skills/security-review
ln -s ../../.agents/skills/audit-specs .claude/skills/audit-specs
```

**Other harnesses** — adapt as needed; the content is plain Markdown with no required
schema. Keep the adaptation local and gitignored.

## Scope

Only guidance that is genuinely project knowledge lives here. Skills that automate a
maintainer's own workflow, or that depend on account-specific access, stay local and
uncommitted — they would be noise or dead weight to a contributor.
