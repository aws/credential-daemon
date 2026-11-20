# Design: Sign-In Partitions

**Status:** draft
**Requirements:** [requirements.md](requirements.md)

## Overview

`AwsLoginProvider::new` resolves the Sign-In host once, from the credential's region, through
`signin_base_url(region)`. Every Sign-In request the provider makes reuses that one URL.

## Resolution

`signin_base_url` matches the region against an ordered table of `(region prefix, sign-in
domain)` pairs, most specific prefix first, so `us-gov-`, `us-isob-`, `us-isof-`, and `us-iso-`
are tried before the commercial `us-`. After the prefix, the rest of the region must be exactly
`{name}-{number}`: one label of lowercase letters and digits, a dash, and a decimal number.
Anything else matches no partition and is refused.

The table mirrors the non-FIPS, non-dual-stack rules in the AWS Sign-In endpoint rule set, which
the AWS CLI applies for `aws login`. The partition DNS suffix cannot be used to build the host,
because the Sign-In domains differ from it for most partitions (for example `aws-iso` serves
Sign-In at `c2shome.ic.gov` while its DNS suffix is `c2s.ic.gov`).

## Why a table, not a resolver

No dependency in the build exposes partition resolution as a public API: the AWS SDK crates keep
their endpoint rule engines private. A short, ordered table with a strict shape check is smaller
than vendoring a rule engine, and it cannot produce a host outside the eight listed domains.

## Security properties

- **P1. The domain is fixed.** The host is always `{region}.{one of eight domains}`. The region
  passes a DNS-label character check and the shape check, so it cannot add a dot-separated
  label, a port, user-info, or a path.
- **P2. Fail closed.** An unrecognized region is refused, never mapped to the commercial host.

## File changes

| File | Change |
|---|---|
| `crates/credsd-core/src/providers/aws_login.rs` | `signin_base_url`, used by `AwsLoginProvider::new`; tests |
| `docs/reference/commands.md`, `docs/reference/configuration.md` | State that `--region` selects the partition's Sign-In host |
