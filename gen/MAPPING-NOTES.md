# MAPPING-NOTES — cmmc-l1

Rationale for every enforcement-class assignment in `catalogs/cmmc-l1.json`.
**Each of the fifteen assignments below is intended for hand review before Phase 1.**

## The rule I applied

A control is **`config-rule`** if AWS's published conformance-pack mapping associates
Config rules with it, and **`procedural`** if it does not. Nothing here is my judgment
about whether a requirement *could* be automated — the assignment follows the evidence
in `gen/sources/aws-config-cmmc-l1.json`, which is the join of two AWS documents whose
hashes are recorded in the artifact's `sources`.

Two consequences worth stating plainly:

- **No control is class `scp` in this catalog.** The conformance pack is a detective
  mapping; it says nothing about preventive policy. Deriving Deny statements from
  requirement text would be me inventing enforcement AWS does not claim, and an SCP
  is the one thing in automat that can lock an operator out of their own account.
  The region/service allowlists and the baseline-protection set (DESIGN §10) are
  separate control sets, not derived from CMMC text.
- **No control is class `baseline-protection`.** That set is its own catalog
  (`catalogs/baseline-protection.json`, still to be written).

Result: 15 controls — **9 `config-rule`**, **6 `procedural`**, 0 `scp`,
0 `baseline-protection`. `TestEnforcementBreakdownIsPinned` fails if any of this
changes without a corresponding edit here.

## The join, and why it needs one

AWS publishes its mapping under CMMC 1.0-era identifiers (`AC.L1-3.1.1`) that embed an
800-171 Rev 2 requirement number. The CMMC final rule uses different identifiers
(`AC.L1-b.1.i`, per 32 CFR 170.14(c)(1)). The R2 number is the join key. Each control
records the AWS-side identifier in `crosswalk.aws_config_mapping_id` so the join is
auditable and the legacy numbering stays addressable.

AWS maps rules to only 9 of the 15 requirements. The compiler refuses to run if AWS
maps rules to an R2 requirement that no Level 1 control claims (`compile.go`, orphan
check) — a silently dropped mapping is a coverage gap, not a rounding error.

## The fifteen assignments

### `config-rule` — AWS maps Config rules to these

| # | Control | R2 | AWS id | Rules | One-line rationale |
|---|---|---|---|---|---|
| i | `AC.L1-b.1.i` | 3.1.1 | `AC.L1-3.1.1` | 44 | AWS maps 44 rules (IAM least-privilege, MFA, key rotation, public-exposure checks) to "limit access to authorized users"; detective, since who is *authorized* is an account-local fact no rule can know. |
| ii | `AC.L1-b.1.ii` | 3.1.2 | `AC.L1-3.1.2` | 35 | AWS maps 35 rules covering permitted transactions and functions — IAM policy shape plus the same public-exposure set; heavy overlap with (i) is upstream's, not mine, and union will dedupe by rule identifier. |
| iii | `AC.L1-b.1.iii` | 3.1.20 | `AC.L1-3.1.20` | 20 | AWS maps 20 rules about external connections (IGW routes, public IPs, open ports, public S3); detective. |
| v | `IA.L1-b.1.v` | 3.5.1 | `IA.L1-3.5.1` | 9 | AWS maps 9 **logging** rules to "identify users, processes, devices" — its reading is that identification is evidenced by attributable logs. Worth a look during review: the mapping is defensible but not the only reading. |
| vi | `IA.L1-b.1.vi` | 3.5.2 | `IA.L1-3.5.2` | 6 | AWS maps 6 authentication rules (password policy, user and root MFA, EMR Kerberos); the closest fit in the whole pack. |
| x | `SC.L1-b.1.x` | 3.13.1 | `SC.L1-3.13.1` | 35 | AWS maps 35 boundary-protection rules (TLS enforcement, node-to-node encryption, WAF, VPC placement, GuardDuty, Security Hub) to monitoring and protecting communications at boundaries. |
| xii | `SI.L1-b.1.xii` | 3.14.1 | `SI.L1-3.14.1` | 3 | AWS maps `cloudwatch-alarm-action-check`, `guardduty-enabled-centralized`, `securityhub-enabled` — flaw *identification and reporting*. Note what this does not cover: "correct in a timely manner" is remediation, which nothing here observes. |
| xiii | `SI.L1-b.1.xiii` | 3.14.2 | `SI.L1-3.14.2` | 1 | AWS maps `guardduty-enabled-centralized` alone as malicious-code protection. Thin, and honestly reported as such: one detective rule is not endpoint protection. |
| xv | `SI.L1-b.1.xv` | 3.14.5 | `SI.L1-3.14.5` | 1 | AWS maps `ecr-private-image-scanning-enabled` as periodic and real-time scanning — container images only, and it does not cover files from external sources. |

### `procedural` — AWS maps nothing to these

| # | Control | R2 | Attestation stub | One-line rationale |
|---|---|---|---|---|
| iv | `AC.L1-b.1.iv` | 3.1.22 | `publicly-accessible-content.md` | Control of information posted on public systems is a *review process* — who approves content before publication — and AWS maps no rule to 3.1.22. |
| vii | `MP.L1-b.1.vii` | 3.8.3 | `media-sanitization.md` | Media sanitization before disposal or reuse is physical; AWS handles its own storage media under the shared-responsibility model, and no rule observes yours. |
| viii | `PE.L1-b.1.viii` | 3.10.1 | `physical-access.md` | Physical access limitation is inherited from AWS data-center controls for cloud-only workloads and is not observable through any API. |
| ix | `PE.L1-b.1.ix` | 3.10.3/.4/.5 | `visitor-access.md` | Visitor escort, physical access logs, and access-device management — the one requirement that maps to three R2 requirements, all physical, none observable. |
| xi | `SC.L1-b.1.xi` | 3.13.5 | `publicly-accessible-subnetworks.md` | Separation of publicly accessible components into their own subnetworks is an architecture property; AWS maps no rule to 3.13.5. |
| xiv | `SI.L1-b.1.xiv` | 3.14.4 | `malicious-code-updates.md` | "Update protection mechanisms when new releases are available" is a maintenance process; no rule observes an update having happened. |

All six use `frequency: annual`, matching the annual self-assessment and affirmation
cycle of 32 CFR 170.15(c). Each stub carries `guidance` text stating what to record and,
where relevant, what is inherited from AWS.

### Three procedural assignments a reviewer may want to overturn

Recorded in `candidateForEnforcement` (`gen/catalog/enforcement.go`) rather than acted on,
because promoting one means automat asserting an enforcement AWS does not, and that
assertion lands in an evidence manifest:

- **`AC.L1-b.1.iv`** — the pack has `s3-bucket-public-read-prohibited`,
  `s3-bucket-public-write-prohibited`, `ssm-document-not-public` and friends, but AWS maps
  them to 3.1.1 and 3.1.2. They bear on public exposure of *resources*, not on review of
  *content*.
- **`SC.L1-b.1.xi`** — `subnet-auto-assign-public-ip-disabled` and
  `ec2-instance-no-public-ip` are partial evidence of segmentation; AWS maps them to 3.1.20
  and 3.13.1.
- **`SI.L1-b.1.xiv`** — GuardDuty updates its own detections, which arguably satisfies the
  requirement implicitly; nothing observes it.

If you want any of these promoted, the honest form is a **second** enforcement class on the
control with the rule reused from its upstream home, not a re-mapping — and then
`TestEnforcementBreakdownIsPinned` and this table both need updating.

## Parameter union orders

Rules carry the pack's own default parameters (resolved from its `Fn::If`/`Ref` defaults).
Each parameter declares the order union uses when two control sets bind it (DESIGN §9).
`orderFor` **errors on an undeclared parameter** rather than defaulting — a wrong default
either loosens a control or turns a legitimate union into a spurious conflict.

| Parameter | Order | Why |
|---|---|---|
| `maxAccessKeyAge`, `MaxPasswordAge`, `maxCredentialUsageAge` | `min` | Age ceilings: a shorter maximum is stricter. |
| `MinimumPasswordLength`, `PasswordReusePrevention` | `max` | Strength floors: a larger requirement is stricter. |
| `RequireLowercaseCharacters`, `RequireUppercaseCharacters`, `RequireNumbers`, `RequireSymbols` | `exact` | Booleans have no ordering; disagreement must be resolved explicitly. |
| `alarmActionRequired`, `insufficientDataActionRequired`, `okActionRequired` | `exact` | Booleans, same reasoning. Note the pack sets `okActionRequired: false`. |
| `blockedActionsPatterns`, `authorizedTcpPorts`, `blockedPort1`–`blockedPort5` | `exact` | Conceptually unions of blocked items / intersections of allowed ones, but the pack encodes them as comma-separated strings. Merging strings by guesswork is exactly what DESIGN §9 forbids, so these are `exact` until the union code can model set-valued parameters. **Open question** — see `docs/open-questions.md`. |

## What this catalog does not claim

Stated here because `verify` prints the same thing from the artifact (DESIGN §12):

- 6 of 15 requirements have no technical enforcement in this catalog and produce
  attestation stubs.
- The 9 mapped requirements are **detective**, not preventive: Config reports
  noncompliance, it does not prevent it.
- `SI.L1-b.1.xiii` (malicious code protection) rests on a single rule, and
  `SI.L1-b.1.xv` (scanning) covers container images only.
- Rule *presence* is what automat verifies. Whether resources are compliant is a
  finding, not a baseline property.
