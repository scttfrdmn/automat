# automat and AWS Control Tower

This page describes automat v1. Where implementation is still in progress (evidence manifests, the onboarding bundle), ROADMAP.md is authoritative; every claim here is re-verified against code before v1 ships.

People reasonably ask how automat relates to AWS Control Tower. Short answer: they share a mechanical core — both drive the same AWS Organizations primitives — and differ in almost everything wrapped around it. This page states the overlap and the differences in both directions, so you can decide honestly. In several situations Control Tower is the better choice; automat exists for the situations where it isn't an option at all.

## What both do

- Create accounts via `organizations:CreateAccount` and place them into a target OU (there is no privileged API underneath either tool; account creation is the same primitive for everyone).
- Attach preventive guardrails as Service Control Policies at the OU level (in automat's case these are its baseline-protection and profile SCPs; its framework catalogs deliberately assert no preventive claims — see below).
- Deploy detective controls (AWS Config recorder + managed rules) into new accounts so they are evaluated from early in their life.
- Baseline new accounts by assuming a provisioning role inside them.
- Maintain an inventory of the accounts they govern.

## What Control Tower does that automat does not

| Capability | Notes |
|---|---|
| Full landing zone | Dedicated log-archive and audit accounts, org-wide CloudTrail, centralized Config aggregation. automat deploys per-account baselines only. |
| Continuous drift detection | Control Tower watches for divergence and notifies. automat's `verify` is point-in-time; you schedule it (cron/CI) or run it before an assessment. |
| Console experience | Dashboards, compliance status views, click-ops enrollment. automat is a CLI with exit codes. |
| Proactive controls | CloudFormation-hook controls that block noncompliant resources at provision time. automat has no CloudFormation integration. |
| Large managed control catalog | Hundreds of AWS-managed controls, mapped to multiple frameworks, updated by AWS. automat ships small, explicit catalogs you can read in one sitting. |
| Self-service account requests | Account Factory via Service Catalog, and Account Factory for Terraform. automat vends from the CLI by an authorized operator. |
| Identity Center setup | Landing zone wires up AWS IAM Identity Center. automat leaves identity to you. |
| Managed evolution | AWS updates Control Tower's controls and baselines over time. automat's catalogs change only when you change them (which cuts both ways — see below). |

## What automat does that Control Tower does not

| Capability | Notes |
|---|---|
| Delegated, OU-scoped vending from a member account | automat's core trick: central IT grants a scoped delegation policy plus one broker role, and a member account vends within its OU subtree. Control Tower must be deployed in, and operated from, the org management account. |
| No landing-zone prerequisite | automat works against bare AWS Organizations. No OU restructuring, no mandatory shared accounts, no multi-week enablement project. |
| Standalone-account bootstrap | A lone account with no organization can run `automat init` and become the management account of its own fresh org, then vend. |
| Compliance-framework-first catalogs | Controls are organized by framework (CMMC 2.0 Level 1, NIST 800-171 r2/r3) with per-control crosswalks, statement text, and source provenance (NIST catalog hashes, AWS mapping sources) — not by AWS service. |
| Explicit enforcement honesty | Every control declares its class: detective Config rule or procedural — plus a separate baseline-protection class carrying the SCPs that guard the detective baseline itself. Framework catalogs never claim preventive enforcement automat cannot honestly deliver. Procedural controls generate attestation stubs instead of silently vanishing. `verify` reports "N of M enforceable by this tool" — it never claims coverage it doesn't deliver. |
| Composable control sets with checked union semantics | Control sets merge under defined laws (denies union, allowlists intersect, parameter conflicts are hard errors, cross-framework duplicates dedupe via crosswalks). The merged artifact is itself versioned and hashed. |
| Evidence manifests | Every vend writes a signed, hash-chained record: what was attached, when, by whom, under which artifact hash. The "born compliant" claim is backed by a chain of custody, not a screenshot. |
| Reviewable trust surface | The entire grant central IT approves is one delegation policy statement and one IAM role (~60 lines). Compare with security-reviewing a landing zone. |
| Single static binary | No service footprint, no additional AWS cost for the tool itself, scriptable, CI-friendly. |

## Honest caveats

- **Drift**: automat mitigates tampering structurally (a baseline-protection SCP denies disabling the detective controls, and member accounts cannot detach their own SCPs), but structural protection plus scheduled `verify` is not equivalent to managed continuous drift detection. If you need the latter and can host Control Tower, use Control Tower.
- **Scale of catalog**: Control Tower's control library is far larger. automat's catalogs are small on purpose — auditable by a human — and grow only with the frameworks it targets.
- **Coexistence**: inside a Control Tower-managed organization, accounts created outside Account Factory show as unenrolled, and enrolling them applies Control Tower's baselines over automat's. Running both against the same OU is not recommended; running Control Tower for the enterprise while automat manages a delegated research OU is possible but should be agreed with whoever operates Control Tower.

## When to choose which

Choose **Control Tower** when central IT will own and operate account governance in the management account, wants AWS-managed controls and dashboards, and the organization can absorb the landing-zone deployment.

Choose **automat** when vending must be delegated below the management account; when the organization will not or cannot deploy Control Tower; when a standalone account needs to become its own organization; or when the requirement is framework-specific (CMMC/800-171) evidence with explicit, auditable control provenance rather than a broad managed baseline.
