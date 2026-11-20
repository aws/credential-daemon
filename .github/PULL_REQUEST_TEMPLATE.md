## Summary

<!-- One-paragraph description of what this PR does and why.

If AI tools generated a meaningful portion of this change (beyond autocomplete or
reformatting), say so here — CONTRIBUTING.md § AI-Assisted Contributions requires the
disclosure, and it helps reviewers calibrate. -->

## Checklist

- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --locked` passes
- [ ] Every commit carries a `Signed-off-by` line (DCO) — `git commit -s`
- [ ] Spec coherence: if this PR changes behavior covered by a `docs/specs/*/` spec, the spec is updated in this PR
- [ ] No secrets, credentials, or personal paths in committed files
- [ ] Commit messages follow conventional commit style (`type: description`)
