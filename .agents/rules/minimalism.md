---
name: minimalism
description: Laziest-senior-dev decision ladder — evaluate before writing any code
source: https://github.com/DietrichGebert/ponytail/blob/main/skills/ponytail/SKILL.md
license: MIT
---

# Minimalism

> **Attribution.** The ladder below is adapted from the `ponytail` skill by Dietrich
> Gebert ([DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail),
> `skills/ponytail/SKILL.md`), MIT-licensed. Condensed and specialized for a Rust
> codebase: the upstream rungs for native platform features and web-specific examples are
> dropped, `std`/Cargo idioms substituted, and the "Never cut" and "Code smells" sections
> are credsd-specific additions. The upstream skill is broader — it carries intensity
> levels, persistence rules, and bug-fix guidance worth reading in full.

Before writing code, descend this ladder. Stop at the first rung that applies:

1. **Does this need to exist?** If no caller needs it, don't write it.
2. **Already in this codebase?** Reuse it. Check before creating.
3. **Standard library does it?** `std` over crates. `std::sync::Mutex` over `parking_lot`.
4. **Already-installed dependency does it?** Use what's in Cargo.toml.
5. **One line does it?** Inline over abstraction. Three similar lines over a premature helper.
6. **Only then:** write the minimum that passes the acceptance criteria.

## Never cut

- Input validation at system boundaries
- Error handling on fallible operations
- Security invariants (zeroize, no secret logging)
- Platform correctness (`#[cfg(...)]` where required)

## Code smells to flag

- A struct used in exactly one place and immediately destructured
- A new crate added for something achievable in <20 lines
- A wrapper type that adds no behavior over the inner type
- A module split for <150 lines of code
