# MAPPING-NOTES — cmmc-l1

Rationale for every enforcement-class assignment in `catalogs/cmmc-l1.json`.
**Each of the fifteen assignments below is intended for hand review before Phase 1.**

## The rule I applied

There are two layers, kept structurally distinct in the artifact by each binding's
`provenance` field:

- **The aws-mapping layer.** A control is **`config-rule`** if AWS's published
  conformance-pack mapping associates Config rules with it. This layer is
  mechanically generated from `gen/sources/aws-config-cmmc-l1.json` — the join of
  two AWS documents whose hashes are recorded in the artifact's `sources` — and is
  **never hand-edited**. Nothing here is judgment about whether a requirement
  *could* be automated.
- **The curated layer.** Three controls AWS leaves without technical coverage carry
  bindings automat asserts itself, each with `provenance: "curated"` and a
  `rationale` in the artifact. These were promoted by hand review (see
  [Curated bindings](#curated-bindings-the-three-promoted-controls)). They are
  **additive**: those controls keep `procedural` and their attestation stubs.

The two layers stay separable so a reviewer can audit automat's claims apart from
AWS's, and so regenerating the catalog cannot silently overwrite a reviewed binding.
`TestAWSMappingLayerIsMechanical` and `TestCuratedBindingsAreExactlyTheReviewedOnes`
enforce both properties.

Two consequences worth stating plainly:

- **No control is class `scp` in this catalog, and that is permanent by design, not a
  gap awaiting work.** Preventive posture for CMMC Level 1 belongs to the
  baseline-protection set and to profile SCPs (region and service allowlists), which
  are separate control sets and not derived from requirement text. The conformance
  pack is a detective mapping and says nothing about preventive policy; deriving Deny
  statements from requirement prose would be inventing enforcement AWS does not
  claim, and an SCP is the one thing in automat that can lock an operator out of
  their own account.
- **No control is class `baseline-protection`.** That set is its own catalog
  (`catalogs/baseline-protection.json`, still to be written).

Result: 15 controls — **12 `config-rule`**, **6 `procedural`**, 0 `scp`,
0 `baseline-protection`. The two counts sum to more than 15 because the three curated
controls carry both classes. `TestEnforcementBreakdownIsPinned` fails if any of this
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

Three of the six also carry curated `config-rule` bindings; the class and stub remain
because those rules observe a symptom of the requirement, not the requirement.

| # | Control | R2 | Attestation stub | One-line rationale |
|---|---|---|---|---|
| iv | `AC.L1-b.1.iv` | 3.1.22 | `publicly-accessible-content.md` | Control of information posted on public systems is a *review process* — who approves content before publication — and AWS maps no rule to 3.1.22. Carries 3 curated rules. |
| vii | `MP.L1-b.1.vii` | 3.8.3 | `media-sanitization.md` | Media sanitization before disposal or reuse is physical; AWS handles its own storage media under the shared-responsibility model, and no rule observes yours. |
| viii | `PE.L1-b.1.viii` | 3.10.1 | `physical-access.md` | Physical access limitation is inherited from AWS data-center controls for cloud-only workloads and is not observable through any API. |
| ix | `PE.L1-b.1.ix` | 3.10.3/.4/.5 | `visitor-access.md` | Visitor escort, physical access logs, and access-device management — the one requirement that maps to three R2 requirements, all physical, none observable. |
| xi | `SC.L1-b.1.xi` | 3.13.5 | `publicly-accessible-subnetworks.md` | Separation of publicly accessible components into their own subnetworks is an architecture property; AWS maps no rule to 3.13.5. Carries 2 curated rules. |
| xiv | `SI.L1-b.1.xiv` | 3.14.4 | `malicious-code-updates.md` | "Update protection mechanisms when new releases are available" is a maintenance process; no rule observes an update having happened. Carries 1 curated rule. |

All six use `frequency: annual`, matching the annual self-assessment and affirmation
cycle of 32 CFR 170.15(c). Each stub carries `guidance` text stating what to record and,
where relevant, what is inherited from AWS.

### Curated bindings: the three promoted controls

Reviewed and approved by hand. Each of these six bindings is automat asserting an
enforcement AWS does not claim, which is why each carries its `rationale` **into the
artifact** — a reader of `catalogs/cmmc-l1.json` can see exactly which associations are
ours, and why, without reading this file. Defined in `curatedBindings`
(`gen/catalog/enforcement.go`).

Every rule named below is already in the conformance pack; nothing is invented. What is
curated is the additional association, not the rule. And all three controls **keep
`procedural` and their attestation stubs**: in each case the rules observe a symptom of
the requirement rather than the requirement itself, and dropping the stub would claim
more coverage than the rules deliver (DESIGN §12).

| Control | Curated rules | Why, and what it still does not cover |
|---|---|---|
| `AC.L1-b.1.iv` | `s3-bucket-public-read-prohibited`, `s3-bucket-public-write-prohibited`, `s3-account-level-public-access-blocks-periodic` | The three together detect the common ways Federal Contract Information becomes publicly reachable, plus the account-level preventive floor beneath them. AWS maps all three to 3.1.1/3.1.2. They observe *exposure*; the requirement is a *review process*, which no rule can see. |
| `SC.L1-b.1.xi` | `subnet-auto-assign-public-ip-disabled`, `ec2-instance-no-public-ip` | A subnet that auto-assigns public IPs is not an internal network, and an instance with a public IP sits on the boundary regardless of subnet intent. AWS maps these to 3.1.20 and 3.13.1. Whether a topology genuinely separates public components is an architecture question. |
| `SI.L1-b.1.xiv` | `guardduty-enabled-centralized` | A managed detection service updates its own threat intelligence, so keeping it enabled is the AWS-native form of "update when new releases are available". AWS maps it to 3.14.1/3.14.2. Nothing observes the update itself, and it says nothing about protection on instances. |

`IA.L1-b.1.v` was reviewed and **left as-is** under the aws-mapping layer: AWS's reading
that identification is evidenced by attributable logs is defensible, and second-guessing
a mapping AWS does publish is a different kind of act from filling a gap it leaves.

Adding a curated binding must fail `TestCuratedBindingsAreExactlyTheReviewedOnes`, which
enumerates the set above rather than deriving it — a new claim about what automat enforces
should not be able to arrive quietly.

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
| `blockedActionsPatterns`, `blockedPort1`–`blockedPort5` | `set-union` | Deny-shaped sets: the members are *prohibited* items, so prohibiting more is stricter. |
| `authorizedTcpPorts` | `set-intersect` | Allow-shaped set: the members are *permitted* items, so permitting fewer is stricter. |

The two set orders are the only monotone resolutions for their shapes, and
`internal/artifact/order.go` implements exactly that: `Resolve` is a meet, with
idempotence, commutativity, associativity, and monotonicity stated as property tests over
generated bindings (`order_test.go`). Monotonicity is the load-bearing one — a
non-monotone order silently loosens a control when two catalogs are compiled together.
Two conflict cases are deliberately *not* resolved: disjoint `set-intersect` sets (an
empty allowlist is a parameter Config rejects, not "permit nothing"), and two bindings
declaring different orders or separators for one parameter.

**Caveat for Phase 4, `blockedPort1`–`blockedPort5`.** These five are one prohibited-port
set spread across five single-valued slots — `RESTRICTED_INCOMING_TRAFFIC` types each
parameter as a lone integer. `set-union` is still the right order per slot (dropping
either input's port would permit traffic that input forbade), but the artifact-level union
must **re-slot** the unioned ports across the five parameters and hard-error above five,
rather than emit a joined value the rule would reject. Noted in
`gen/catalog/enforcement.go` at the declaration and in `docs/open-questions.md`.

## What this catalog does not claim

Stated here because `verify` prints the same thing from the artifact (DESIGN §12):

- 6 of 15 requirements produce attestation stubs, and 3 of those 6 have only curated
  technical coverage — rules that observe a symptom, not the requirement.
- All 12 `config-rule` requirements are **detective**, not preventive: Config reports
  noncompliance, it does not prevent it. No requirement in this catalog is preventively
  enforced, by design (see above).
- 6 of the bindings are automat's own judgment rather than AWS's, and say so in the
  artifact.
- `SI.L1-b.1.xiii` (malicious code protection) rests on a single rule, and
  `SI.L1-b.1.xv` (scanning) covers container images only.
- Rule *presence* is what automat verifies. Whether resources are compliant is a
  finding, not a baseline property.
