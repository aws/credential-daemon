# Requirements: Sign-In Partitions

**Status:** draft
**Feature:** `sign-in-partitions`
**Scope:** The AWS Sign-In host an `aws-login` credential talks to, for every AWS partition.

## Introduction

An `aws-login` credential signs in through AWS Sign-In and refreshes its session at the same
Sign-In host. Each AWS partition (commercial, GovCloud, China, the European Sovereign Cloud,
and the isolated partitions) serves Sign-In from its own domain. The host is chosen from the
credential's region exactly as the AWS CLI chooses it for `aws login`, so a credential works
wherever `aws login` works and talks to the same service.

## Glossary

- **Sign-In host**: the HTTPS origin that serves `/v1/authorize`, `/v1/token`, and
  `/v1/sessions/confirmation` for an `aws-login` credential.
- **Partition**: a group of AWS regions that share a DNS domain, identified by the region's
  name.

## Requirement 1: The Sign-In host follows the region's partition

**User story:** As a customer in any AWS partition, I want `aws-login` to sign in at my
partition's Sign-In host, so that credsd works where `aws login` works.

### Acceptance Criteria

1.1. The system SHALL derive the Sign-In host from the credential's region as
     `https://{region}.{sign-in domain}`, where the sign-in domain is the partition's:

| Partition | Regions | Sign-in domain |
|---|---|---|
| `aws` | `us-`, `eu-`, `ap-`, `sa-`, `ca-`, `me-`, `af-`, `il-`, `mx-` followed by `{name}-{number}` | `signin.aws.amazon.com` |
| `aws-us-gov` | `us-gov-{name}-{number}` | `signin.amazonaws-us-gov.com` |
| `aws-cn` | `cn-{name}-{number}` | `signin.amazonaws.cn` |
| `aws-eusc` | `eusc-de-{name}-{number}` | `signin.amazonaws-eusc.eu` |
| `aws-iso` | `us-iso-{name}-{number}` | `signin.c2shome.ic.gov` |
| `aws-iso-b` | `us-isob-{name}-{number}` | `signin.sc2shome.sgov.gov` |
| `aws-iso-e` | `eu-isoe-{name}-{number}` | `signin.csphome.adc-e.uk` |
| `aws-iso-f` | `us-isof-{name}-{number}` | `signin.csphome.hci.ic.gov` |

1.2. WHEN a region matches no partition in 1.1, THEN the system SHALL refuse to build the
     credential, with an error naming the region, and SHALL NOT fall back to the commercial
     host.

1.3. The Sign-In host SHALL be HTTPS, and its host name SHALL be the region followed by one
     of the sign-in domains in 1.1. No value a caller supplies SHALL change the domain or add
     a scheme, port, user-info, path, or query to the host.

1.4. The same host SHALL serve the authorization URL, the token exchange, the refresh, and the
     cross-device confirmation redirect for one credential.

## Requirement 2: Validation happens where the credential is built

2.1. The region check of Requirement 1 SHALL run when the provider is built, so a hand-edited
     `credentials.toml` region is refused before any request is made.

## Non-Goals

- **Dual-stack Sign-In hosts.** The AWS CLI uses the hosts in 1.1 for `aws login`.
- **A custom endpoint override.** No caller supplies a Sign-In URL.

## Open Questions

1. **FIPS.** The AWS CLI honors `use_fips_endpoint` for `aws login`, with hosts
   `signin-fips.{region}.{partition DNS suffix}`, except GovCloud, which uses
   `{region}.signin-fips.amazonaws-us-gov.com` (and `signin-fips.amazonaws-us-gov.com` for
   `us-gov-west-1`). Supporting it needs a per-credential `fips` setting passed at bootstrap.
   Whether and when to add it is open.
2. **New partitions.** A partition added after this table fails closed (1.2) until the table is
   extended. The AWS CLI instead treats an unrecognized region as commercial. Failing closed is
   chosen because a wrong guess sends the refresh token to the wrong partition's service.
