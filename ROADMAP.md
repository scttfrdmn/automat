# ROADMAP — automat

Phases are ordered so the compatibility contract (schema) exists before anything consumes it, and so every phase ends with something demonstrable. Each phase = tagged milestone.

## Phase 0 — Contract first: schema + catalogs
- JSON Schemas: control artifact, environment profile, evidence manifest (`schema/`), with Go types, canonicalization, content hashing, round-trip tests.
- `gen/`: compile CMMC L1 catalog from NIST/FAR OSCAL sources joined with the AWS Config CMMC L1 conformance-pack mapping; record source hashes. Vendor output to `catalogs/cmmc-l1.json`.
- Same pipeline for `800-171r2` and `800-171r3` (enforcement mappings may be partial — mark unmapped controls `procedural` with a TODO provenance note rather than dropping them).
- Baseline-protection control set as data (`catalogs/baseline-protection.json`) — **done**. Seven controls covering all five of DESIGN §10's bullets, compiled from `gen/sources/baseline-protection.json` by `gen/catalog/baseline.go` and swept by the same `make catalogs-check` as `cmmc-l1`. The `_comment`/`design_basis`/`extends_design` discipline is load-bearing rather than decorative: the compiler refuses to build an action §10 does not enumerate unless the source says why, and the reason is folded into the control's `statement` so it reaches the artifact a reviewer actually holds. This is also the artifact that gives the SCP packer a real subject (see `docs/open-questions.md` Q6).
- **Accept:** `go run ./gen/catalog -sources gen/sources -out catalogs` produces `catalogs/cmmc-l1.json` that validates against the schema and hashes deterministically; golden files for all three catalogs. (There is no `automat compile` subcommand — the compiler is maintainer tooling, not an operator-facing command; see `docs/cli-surface.md`.)

## Phase 1 — Preflight + onboarding bundle
- `login` (SSO device flow via ssooidc + credential chain), `preflight` (three-state machine, quota + permission report with SCP-caveat wording), `setup --request` (onboarding bundle: delegation policy, vendor role CFN + TF, README).
- **Accept:** golden-file tests for bundle output; fake-backed preflight covers all three states and the "member with vendor role" variant.

## Phase 2 — Vend (management + standalone paths)
- `init` (CreateOrganization ALL + research OU), `vend` end-to-end in MANAGEMENT state: create → poll → move → SCP ensure (control + region + service + baseline-protection) → assume into child → recorder/delivery channel/conformance pack → attestation stubs → evidence manifest.
- SCP packer: quota-aware (5-per-target, size limits), deterministic output, golden-tested.
- Resumable requests (`--resume`), parked-account handling.
- **A policy failure after a successful create/move is a resumable parked state, never a fatal error.** Written down here because it is an ordering requirement on `vend`, not an error-handling preference. DESIGN §5 names `parked` for create-without-move; step 4's failures land in the same state for the same reason — the account exists, so exiting non-zero without recording it strands a real AWS account with no OU, no SCPs, and nothing in the manifest pointing at it. The specific failures that must park rather than abort: `CreatePolicy` rejecting a document (`MalformedPolicyDocument` — a hand-authored Sid collision is one path, which is why `gen/catalog/baseline.go` refuses duplicate Sids at compile time), `AttachPolicy` hitting the five-per-target quota, and `AccessDenied` from an incomplete delegation. All three are recoverable by `vend --resume <request-id>` after the operator fixes the cause, and none is recoverable by re-running `vend` from the top, which would create a second account. Q13 adds a fourth: an `AccessDenied` on `PutRolePolicy` against a baseline role is automat's own control, not a missing grant, and must not be reported as one.
- **Cosigning and freshness fields — done, schema and data only** (DESIGN §11a, `schema/CHANGELOG.md`). Profile documents carry an optional `signatures[]` array of attestation predicates over the document's content hash — each with a **role** from a closed five-value vocabulary and a **required statement**, never a bare signature — plus a **required `review_by` date**; evidence records carry the profile id, its content hash, and the set of attestations that **verified** (always empty in v1). Landed before `internal/evidence` writes its first record because retrofitting the *record* shape once records exist in the wild is a versioning event rather than a changelog line. A signature attests **provenance only**; trust is an operator determination against a trust policy the operator maintains; automat ships **no trust anchor and no default**, and **verification, trust-policy loading, and any registry are deliberately not implemented**. Listed in `schema/CHANGELOG.md` for maintainer ratification, since `signatures[]` adds structure rather than only tightening.
- **Accept:** full vend pipeline runs against fakes with every step idempotent (run twice = no diff); manifest chain validates.

### The environment profile — renamed, and gaining the region and service sets (Q14)

**Decided by the maintainer on Q14; the rename and the fields have both landed.** `profile/v1` is now `environment-profile/v1` because "profile" named three unrelated documents (the per-vend input, obligation profiles, and the classification profiles below) plus a fourth automat cannot rename — the **AWS credential profile**. `vend`'s input flag is `--environment-profile`; `--profile` stays reserved for the AWS sense. DESIGN §7a states the taxonomy, `schema/CHANGELOG.md` records the rename field by field, and it moved every record hash, so the golden manifest was regenerated. **This is why the golden file exists:** the diff is the field name and the hashes that must follow it, and nothing else. The region and service sets below landed with the rename's own tightenings — see `schema/CHANGELOG.md`, "Pre-publication change to environment-profile/v1: five tightenings, found by writing the drift detector."

The fields the decision requires, all of which land **with item A** below, since the region and service SCP shapes are one body of work:
- Both sets are **allowlists** — `aws:RequestedRegion` and service deny SCPs — and each carries its **exemption list as catalog data, never hardcoded** (same pattern as `exempt_principals`). The global-service list is the one that bricks an account when wrong.
- **Opt-in region enablement stays a separate field.** One is a boundary (what a principal may call), the other an Account Management API action at baseline time. `baseline.regions.{home,enable,disable}` already is that field and must not become the allowlist.
- **The narrowing invariant:** the environment profile may only ever narrow. Union of controls, **intersection** of permitted behavior — the union law on a different lattice. The packer's can-any-merge-widen property coverage gains region and service **sets** as subjects, not only statements.
- **The empty-set guard.** AUDIT-0's H5 found the empty set is the absorbing element of the meet; the concrete consequence is a deny-all that bricks an account *after* create and move succeeded. `minItems: 1` **and** a hard error at **plan** time naming which inputs produced the emptiness. Never silent, never at apply. Golden-tested.
- The shape must be **checkable by `verify`** (Phase 4), not merely emittable.
- Plus the environment profile's references to obligation profile ids, a classification level once the pass below lands, and the operator determinations DESIGN requires be recorded and hashed — what the manifest's environment-profile record points at.

### Carried to AUDIT-2 for ratification

Rule 6 lets an audit-driven or review-driven change that **strictly tightens**
validation land without pre-approval, and requires it to be ratified. This is the
list AUDIT-2 must work through; each item names where the reasoning lives, so the
audit records a decision rather than rediscovering the change.

- **RATIFIED at the task #12 review — `evidence-manifest/v1`:
  `records[].request_id` gained a pattern** (`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`,
  previously `minLength: 1` only). Pre-publication, so no version bump; after
  publication it would be a major one. It is the single field in a record a human
  copies back onto a command line as `vend --resume <request-id>`, which is why it
  is worth narrowing rather than tidying. Reasoning in `schema/CHANGELOG.md`. The
  reasoning generalizes and is now **CLAUDE.md rule 8**; AUDIT-2 must run rule 8's
  enumeration sweep over every round-trip field, not merely confirm this one.
- **RATIFIED at the task #12 review — the Go enforcement-set validator was
  tightened to match the published schema.** `Enforcement.validate` checked only
  `scp_arns` for empty members and none of the five arrays for duplicates, while
  the schema has declared `uniqueItems` and `minLength: 1` on all of them since
  Phase 0. No `schema/` file changed. Found by reading the schema in full while
  writing `internal/evidence/schema_conformance_test.go` — i.e. by the test's
  preparation rather than by the test. Ratified on the reasoning that "three SCPs
  attached" and "two SCPs, one listed twice" are different claims to someone
  counting them.
- **RATIFIED at the task #12 review — three more round-trip fields patterned under
  the new rule 8.** `manifest.id`, `custody_transfer.successor_manifest_id`, and
  `signature.key_id` were all `minLength: 1`; they now share `$defs/round_trip_id`
  and `$defs/round_trip_ref`. Found by running rule 8's enumeration sweep on the
  schema the rule was generalized *from*, rather than deferring it — a rule not
  applied to its own source file has already failed. Reasoning in
  `schema/CHANGELOG.md`. AUDIT-2 still owes the sweep over the other three
  schemas and over what the CLI and error paths print, since a field becomes a
  round-trip field the moment a remediation message tells someone to type it.
- **RATIFIED at AUDIT-2, 2026-08-08 — `control-artifact/v1`'s content hash now covers
  a payload object** rather than a bare `controls[]` array. Landed with E1/E3 because
  the alternative was an unhashed security-relevant field
  (`region_deny_exempt_services`, whose corruption both bricks an account and
  silently widens a Deny), but it **restructures rather than strictly tightens** —
  reviewed on that basis and ratified as-is rather than unwound, since the code was
  already running and unwinding a live content-hash definition would have cost more
  than it bought. Committed in `6700bc0` with the reasoning in `schema/CHANGELOG.md`.
  Every artifact hash moved, including `cmmc-l1`'s, which gained no field.
- **RATIFIED at AUDIT-2, 2026-08-08 — `environment-profile/v1`: five fields
  tightened** —
  `environment_profile.title`/`.description` to `$defs/prose`/`long_prose`,
  `placement.ou_path[]` to `$defs/ou_name`, `account.email_pattern` to an explicit
  charset with `maxLength: 254` (the old `^[^@\s]+@[^@\s]+$` admitted control bytes
  and a 4KB address), `account.tags` to `$defs/tag_key`/`tag_value` with
  `maxProperties: 48`, and both `local_dir` fields to `$defs/local_dir` (the old
  `minLength: 1` admitted `/etc`, `../../..`, and `~/`). All strictly tightening and
  pre-publication, so they land under rule 6's audit-driven clause. Found by writing
  `internal/envprofile`'s `TestGoAndSchemaAgreeOnRejection` — the schema was the
  looser layer in every case, which is the wrong direction for the one document type
  that is **hand-written**, since the schema is what the operator's editor checks
  while they write it. Reasoning per field in `schema/CHANGELOG.md`, along with the
  three asymmetries that are asserted to remain asymmetric and the one production
  defect (`CanonicalContentJSON` conflating an empty permitted *set* with an empty
  permitted *block*) the same tests found.
- **substrate#577** (root has no stable identity) as evidence the emulator probe
  paid for itself independent of the migration decision. See Phase 3 below.

### Scheduled pass: institutional classification profiles — **AFTER task #13 lands, BEFORE AUDIT-2. Do not start until `vend` works.**

Recorded now so it is not lost, and gated deliberately: this is a new document type and the argument for it is only legible once there is a vended account to rate.

**Why this is publishable rather than a local convention.** HEISC's *Data Classification Toolkit* (EDUCAUSE/Internet2) is a compiled reading list, **last reviewed July 2015**, not a normative model — there is no community-consensus level scheme to defer to. That negative result is the justification: a generalized model is worth publishing precisely because nothing occupies the slot. Live and adjacent groups exist — the EDUCAUSE HEISC 800-171 Compliance Community Group (~600 members, published a NIST SP 800-171 Toolkit) and the Regulated Research Community of Practice (SSP workshops, NSPM-33) — and HECVAT is the governance precedent (EDUCAUSE + Internet2 + REN-ISAC, 2016; unified framework 2025, replacing scattered spreadsheets). Data classification remains an open community problem; see the UW-Madison survey and peer-policy gap analysis, *EDUCAUSE Review* 2025. Every one of these gets a citation with a retrieval date and hash, like any other source.

**Six-institution sample the model must fit.** UC (IS-3/SC-0002): 4 levels P1–P4, numeric **ascending** (P4 highest), 350+ controls, a separate Availability axis, classification determined by Proprietors with SMEs and Unit Information Security Leads. Harvard: 5 levels DSL 1–5 ascending, with **two layered policies** (enterprise HEISP + research overlay HRDSP) sharing one classification table. Stanford: 3 levels Low/Moderate/High, each with its own minimum-security-standards document. U-M: 4 levels Restricted/High/Moderate/Low — **Restricted is the top and the names run downward** — mapped onto NIST directly (Restricted ≈ NIST Moderate) with per-data-type templates (FISMA, HIPAA, CUI). MIT: 3 levels Low/Medium/High. Georgia Tech (SGA IT Board): 5 levels adopted wholesale from Harvard, which is forking already happening in the wild.

**Model requirements, each a test rather than a paragraph:**
- Level count varies (3/4/5). **Never assume four.**
- Ordering is an explicit **required integer rank**. Never infer order from labels — U-M and Harvard sort opposite by name, so both are test fixtures.
- Highest-water-mark composition is universal: an element meeting two definitions takes the higher, a dataset takes the highest of any element, deliberate over-classification is documented. Same "stricter wins" principle as the union law, on a different lattice — say so where a reader will connect them.
- The dominant idiom is **resources rated for a level** (Harvard FASRC rates Cannon DSL1–2, routes DSL3 to FASSE, has no DSL5 systems; Stanford's Yen is Low/Moderate with Nero/Carina for High). This is what automat vends, so **"this account is rated for \<level\>" should become the tool's primary framing.**
- Institutional schemes **route to** external obligations rather than replacing them (U-M's NIST mapping). Model as an informational `references` relation to obligation profiles. **No automatic composition** — the operator declares which obligations apply.
- Profile-to-profile inheritance within one issuer (Harvard's two layered policies).
- A new document type, **sibling to the obligation profile, not a variant**. automat **never classifies data**: determination is a human role named in the profile, and level selection for a vended account is an operator determination, recorded and hashed. **No evaluable trigger expressions — if a matcher starts taking shape, stop and flag it.**

**Ship automat's own interpretations as DERIVED artifacts; the provenance honesty is the entire point.** automat is the interpreter, never the author, and the institution has reviewed and endorsed nothing. Every derived profile carries source title, URL, retrieval date, sha256, attribution, and a test-guarded non-endorsement statement: *"This is automat's interpretation of a published policy. It was not authored, reviewed, or endorsed by \<institution\>. The institution's own policy governs; verify against it."* Derived artifacts may claim only the `interpreted-by` role. **Every control in a derived profile must trace to a cited section of the source document — where the source is silent, the profile is silent.** Filling a gap with a sensible-looking control silently converts "UC's policy says" into "automat thinks UC should say", and that is a finding, not a nice touch. Ship exactly **two**: UC IS-3 and one of MIT or Stanford — the pair that maximally stresses level count and naming — pinned by a test. An explicit field distinguishes shipped-and-maintained from example-and-forked; derived institutional profiles are **examples**.

**`docs/institutional-profiles.md`:** the generalized model, the six-institution sample as evidence, the HEISC/HECVAT context, and the cosigning trust model. Written so it could be taken to the HEISC 800-171 group or RRCoP — but **automat proposes a format, never a governance body**, and must never become a registry or standards owner.

## Phase 3 — Brokered vend (the university path)
- `broker/` — **task 1 done.** `broker.Assume` assumes the vendor role via `awsapi.STSAPI`, resolving the ExternalId through `config.ResolveExternalID` (never a bare value), and returns an `aws.Config` that builds a working `awsapi.OrgVendAPI` client. Session lifetime is single-assumption-per-vend by design; re-assumption is deferred to whichever later task's wiring shows a real need for it (see the package doc). Failures produce rule-7 remediation matching `preflight.checkVendorRole`'s wording for the same failure. Pulled `github.com/aws/aws-sdk-go-v2/credentials` from indirect to direct in `go.mod` — no new version, already pre-approved (CLAUDE.md).
- **Task 2 done.** `vend.go`'s `vendOrgClient` classifies STANDALONE/MANAGEMENT/MEMBER the same way `preflight.classify` does, and picks `globals.go`'s new `brokeredOrgVendClient` (built on `broker.Assume`) rather than the native `orgVendClient` when the caller is a member of the organization. `org.Brokered` is now genuinely produced, not only wired — a denial on an account/OU operation names the vendor role's file, and a denial on a policy operation (always delegated, never brokered) names the delegation policy, per `org.Ensurer.denied`'s existing branch. The create-lands-under-root-then-move race is unchanged: `park`/`vendResumeHint` already read from `awsapi.PermissionError` regardless of which credential produced it, so no separate handling was needed for the brokered path. One `aws.Config` is built per vend and shared across the plan and apply passes, matching task 1's single-assumption design — confirmed by test rather than assumed.
- **Task 3 done.** `setup` (MANAGEMENT side) applies the delegation policy and creates the vendor role directly, via two new `awsapi` interfaces (`OrgSetupAPI`, `IAMRoleAPI`) and `internal/org.EnsureDelegationPolicy`/`EnsureVendorRole`. Decided against render-then-apply: `VendorRoleCFN`/`VendorRoleTF` produce CloudFormation/Terraform text, but `iam.CreateRole`/`PutRolePolicy`/`organizations.PutResourcePolicy` all take raw JSON policy content — no template-consuming path existed either way. `internal/bundle` gained `VendorRoleTrustPolicyJSON`/`VendorRolePermissionsPolicyJSON`, reusing `DelegationPolicy`'s struct-marshaled `policyDocument` shape rather than the templates. A sharper finding shaped the delegation-policy half: Organizations holds exactly ONE resource policy per organization — `PutResourcePolicy` replaces it wholesale, with no per-statement update and no owner tag on the document to check first. `EnsureDelegationPolicy` reads first and refuses (does not merge, does not overwrite) when a policy already exists that is not already automat's own rendering of the request. `setup` gained `--external-id-ref`, since apply has no template parameter to defer the ExternalId to and AUDIT-1 already ruled out automat generating one.
- **Task 4 done, finding resolved upstream.** `test/integration/broker_test.go` exercises `broker.Assume` against a real substrate server, in its own module (`test/integration/go.mod`) with its own `make integration` target, never in `make test`. The property this task was scoped to test — substrate's auth controller enforcing a vendor role's trust policy and `sts:ExternalId` condition on `AssumeRole` — did not exist in substrate v0.94.0: `AssumeRole` there checked only that the role existed. Filed as substrate#593, fixed in **v0.95.0**, which the module now pins. Rewritten to test it for real: a signed IAM user (not the unauthenticated `test`/`test` credentials, which substrate never evaluates against a trust policy) succeeds with the right ExternalId, fails with none, and fails against a role trusting a different account. docs/testing-strategy.md carries the full history.
- Nested OU creation within depth limits — the native-path logic (`internal/org/ou.go`'s `MaxOUDepth`/`depthOf`) already exists; doing the same creates through a brokered credential is task 2's work, not new logic.
- **Accept:** fake-backed MEMBER vend; failure modes (unassumable role, missing delegation) produce actionable remediation text naming the exact missing grant.

### Emulator integration for `broker` — done, on the second try

Approved in Phase 2 and deliberately **not built** then: `broker` was a Phase 3
deliverable, and integration tests for a package that did not exist yet would have
been speculation.

The plan's premise, as written when this section was drafted: `broker`'s surface is
`sts:AssumeRole` and `sts:GetCallerIdentity`, and the emulator was expected to be the
package where it "earns its place" rather than duplicating a fake, because its auth
controller was believed to IAM-enforce a role's trust policy and its `ExternalId`
condition on assumption — the one thing a hand-rolled `STSAPI` fake cannot refuse for
the right reason. **That premise did not hold when this module was first built**:
substrate v0.94.0's `AssumeRole` checked only that the named role existed; the trust
policy and any `ExternalId` condition were stored and never evaluated. Filed as
[substrate#593](https://github.com/scttfrdmn/substrate/issues/593), and the first cut
of this module was scoped honestly around the gap rather than around the property.

**Fixed upstream in v0.95.0.** `test/integration/broker_test.go` now pins that
version and tests the real property: a signed IAM user (not the unauthenticated
`test`/`test` credentials, which substrate never checks against a trust policy —
"existence in state is the opt-in") succeeds against a vendor role with the correct
`sts:ExternalId`, fails with none, and fails against a role trusting a different
account. `broker.Assume`'s wire-format correctness against a real STS-shaped server
is still covered (`TestBrokerAssumeIsRejectedForAnUnknownRole`'s real HTTP-level
`NoSuchEntityException`), the same class of bug a fake cannot have since it never
parses a response off the wire. See `docs/testing-strategy.md` for the full history.

Constraints, both non-negotiable and both from CLAUDE.md's testing section:

- **Separate module** at `test/integration/go.mod`, its own `make integration`
  target, never in the default `make test` gate. The emulator's `go` directive is
  ahead of automat's floor, and a floor propagates to `go install` regardless of
  which files import it.
- **`internal/awsfake` stays.** The emulator tests that automat's requests are
  well-formed and authorized; the fakes test automat's reaction to state moving
  mid-call. `broker` gets both, and the ensure-semantics packages keep only the
  fakes until an emulator can express a call that succeeds against state that
  changed underneath it.

Upstream gaps are filed and behavior-framed rather than as endpoint lists:
[substrate#577](https://github.com/scttfrdmn/substrate/issues/577) (root has no
stable identity — a live bug the probe found, worth an AUDIT-2 note as evidence the
probe paid for itself independent of the migration decision),
[#578](https://github.com/scttfrdmn/substrate/issues/578) (Organizations: OU tree,
policy lifecycle, placement, tagging — 17 operations plus the nine behaviors the
ensure layer depends on), [#579](https://github.com/scttfrdmn/substrate/issues/579)
(`SimulatePrincipalPolicy`, which `preflight` is built on),
[#580](https://github.com/scttfrdmn/substrate/issues/580) (AWS Config: no plugin, so
`baseline` has nothing to run against). Keep the behavior-first framing on any
further filings. `preflight`, `org`, and `baseline` are blocked on #578–580 and are
not migration candidates until they land.
[#593](https://github.com/scttfrdmn/substrate/issues/593) (`AssumeRole` did not
evaluate a role's trust policy or an `sts:ExternalId` condition — found while
building this section, above) is **closed**, fixed in substrate v0.95.0; the
resolution is why `broker`'s emulator tests now cover the real property rather than
a documented gap around it.

## Phase 4 — Verify + union hardening
- **`verify` SHIPPED, scoped to the policy and freshness layers.** DESIGN §12 names four layers (policy, detective, procedural, freshness); the detective layer (Config recorder, conformance pack) and the procedural layer (attestation stubs) both check something DESIGN §7 step 5 — `internal/baseline` — was meant to install, and that package still does not exist, so there is nothing in a vended account for either layer to check against. `automat verify --account <id>` says so in its own output rather than staying silent about the gap, the same discipline `vend` follows for the identical shortfall (docs/cli-surface.md D3). `--ou <id>` from DESIGN §12's literal flag text is not offered: baseline-protection (compiled into every vend, never optional) exempts automat's in-account automation role by ARN, which embeds the account id, so `compilesets.Pack` cannot render the expected policy set for an OU with no account in hand.
  - Policy layer: `internal/verify.CheckPolicy` recompiles the expected policy set (`compilesets.Pack`) and compares it against what is attached (`awsapi.OrgVerifyAPI`, a new read-only sibling of `OrgPolicyAPI` carrying no write method) using `org.SameDocument` — the exact structural comparator `vend`'s own idempotent re-runs already use for drift detection. Reports per-policy attached/matches/owned, plus orphans (automat-owned policies no longer named by the current compile, which nothing can remove since no write interface holds `DetachPolicy`).
  - Freshness layer: `internal/verify.CheckFreshness` warns, never fails, when the environment profile's `review_by` has passed (DESIGN §11a).
  - **`verify`'s result is a structured value** (`internal/verify.PolicyReport`/`FreshnessStatus`); the printed report renders from it, not the reverse — `assess` (below) is meant to consume this later.
  - Writes an `evidence.OpVerify` record per run.
- **Union semantics, Config-rule half SHIPPED**: dedupe by rule identifier (within one artifact and across artifacts), parameter resolution via `artifact.RuleParameter.Resolve` (previously built, never called from production code until now), conflicts surfaced as a first-class `*compilesets.ConflictReport` value, override files (`--override` on `vend`/`verify`, D6) resolving a conflict to an explicit value, and Q1's carried `blockedPort1`-`blockedPort5` re-slotting caveat closed. Property tests (idempotent/commutative/associative) mirror the existing SCP-half suite; monotonicity is inherited from `RuleParameter.Resolve`'s own property tests rather than re-asserted, since this layer adds no behavior beyond dedupe and re-slotting. **Crosswalk dedupe SHIPPED as a primitive with no consumer yet.** `compilesets.DedupeAttestations` groups procedural controls transitively by shared `Crosswalk` entries into practices, refusing (as an `*AttestationConflict`) when two controls sharing an entry disagree about the attestation's template, frequency, guidance, or crosswalk mapping. It renders no stub — no attestation-stub generator exists at all; that is DESIGN §7 step 5's in-child baseline work (`internal/baseline`, absent — D3) — so the grouping is built and tested ahead of the renderer that will consume it, the same "write the code behind an interface, keep going" discipline CLAUDE.md's working style names. `cmd/automat/vend.go`'s own `attestationIDs` still lists every procedural control undeduped, because its only job today is a boolean disclosure check, not a stub's content.
- **`list` SHIPPED, without tag-based filtering.** `automat list --ou <id> --evidence-dir <dir>` walks the OU tree via a new `org.WalkTree` (`internal/org/tree.go`) and separately scans local evidence manifests for parked accounts (`evidence.Dir.ListAccountIDs`, `Manifest.Parked`). Every account under the walked OU is listed regardless of tag: `awsapi.OrgVendAPI` has no `ListTagsForResource` for account resources, and the published vendor-role bundle does not grant it — the same absence docs/open-questions.md Q19 already documents for a different reason. See docs/cli-surface.md D5.

### Assessment reporting (`assess`) — approved scope, staged within this phase

Design authority: `docs/assessment-reporting.md`. Read it before writing any of this; the invariants below are summaries of arguments made there. Both frameworks automat ships catalogs for define a self-assessment process with an expected output, and a tool that produces baselines but nothing an assessor can read leaves the last mile to a spreadsheet.

- **Obligation profiles are the second axis, and they are already built.** A catalog answers *which controls*; it does not answer under what instrument, assessed how, signed by whom, with gaps deferrable or not. `schema/obligation-profile-v1.schema.json` plus `cmmc-l1`, `dfars-7012`, `nih-cadr-dua` in `catalogs/obligations/` — **data and schema only, no Go types, no `assess`**. The axis has to be separate because the same catalog is assessed under incompatible rules: `dfars-7012` and `nih-cadr-dua` both read 800-171 and agree on almost nothing else, and CMMC L1 forbids the POA&M both of them permit. Profiles are **data — no profile-specific branching in Go**, since a regime encoded as a `switch` cannot be corrected without a release. Two consequences to honor when `assess` is written: (a) `applicability` is prose plus bounded non-exhaustive hints and **never evaluable** — an automated "this obligation applies to you" is the most dangerous output this tool could produce; (b) under `nih-cadr-dua` the 800-171 revision is **not pinned by NIH**, so it is an operator determination hashed into the evidence chain, and **`assess` must refuse to run without one rather than default**. `FAR Case 2017-016` is deliberately not shipped: still a proposed rule, and it excludes COTS and fundamental research at universities.
- **`automat assess --account <id> --profile cmmc-l1|dfars-7012|nih-cadr-dua --determinations <file> --out <dir>`.** Read-only against AWS, so no `--yes`. `--profile` rather than `--framework`: the profile determines the determination vocabulary, whether a POA&M is renderable, and whether there is a score at all, and it names the catalog. Consumes `verify`'s structured results, attestation state, and an operator-determinations file. A separate verb rather than a `verify` flag: `verify` asks "does reality still match the artifact", `assess` asks "what can be claimed about this account", and `assess` writes an evidence record while `verify` does not. Needs ratification; §13 gains it when it ships.
- **Three invariants, each a test rather than a paragraph:**
  1. **Every rendered page carries `DRAFT — NOT A SUBMISSION`, and no output may resemble a signable affirmation** — no signature line, no "affirm"/"certify"/"under penalty", no submission framing. Hard invariant, same class as `TestREADMEMakesTheBlastRadiusArgument`, checked across every renderer the way `TestEveryRendererIsReachable` checks the bundle. A generated document that *looks* like a CMMC L1 affirmation is a document someone can sign without having done the assessment.
  2. **automat's proposals may only ever understate compliance.** `MET`/`SATISFIED` comes from the determinations file or from nowhere; `NOT MET` automat may write. Being wrong in that direction costs a review; the other direction is what an enforcement action is built on. Per objective the report labels evidence class **`machine`** vs **`operator`**, mirroring the existing `aws-mapping`/`curated` split — so a reader can audit the operator's assertions separately from automat's observations. **The profile parameterizes this rather than bolting onto it:** `determinations.understatement_value` names which member of the regime's own closed set automat may write, and the invariant is asserted as a **property over the profile set**, not per profile (`TestTheUnderstatementAsymmetryHoldsUnderEveryProfile`) — it must hold for profiles nobody has written yet.
  3. **At CMMC L1, an objective with neither machine evidence nor a determination renders NOT MET**, not "in progress". L1 has no partial credit and permits no POA&M, so "in progress" would invent a state the framework lacks — and the comfortable one. The L1 summary must also state that any NOT MET practice means no affirmation can be made this year.
- **New schema (needs pre-approval per rule 6):** (a) `assessment-result-v1` — canonical, hashed, referenceable from an evidence manifest record; every human-facing form renders from it and none is authored independently. (b) `operator-determinations-v1` — per determination: id, objective(s) satisfied, statement, date, responsible party; **content-hashed into the evidence chain like a catalog**, so a reader can tell which human assertions were in force and an assertion cannot be revised after the fact without the hash moving.
- **New catalog data, vendored + hashed like all sources:** 800-171A objectives from NIST CPRT (`SP_800_171A`), plus DFARS per-requirement weights from the DoD Assessment Methodology document **recorded with its title, version, and hash — the weights are load-bearing and must never be inferred**. Also a practice→objective crosswalk, which is not the existing practice→requirement crosswalk and fans out further.
- **Q10 is decided: the weight table is hand-transcribed TWICE, independently, and the two passes diffed before commit** — the second pass fresh from the source document without consulting the first, with a committed note recording that they agreed; a disagreement anywhere goes to review rather than being resolved by picking one. Redundancy at the point of entry is the only control available against a false input to correct arithmetic: a hash detects a value that *changed*, never one that was wrong when first written down, and a wrong weight is confidently wrong in the same direction on every regeneration. `catalogs/obligations/dfars-7012.json` carries the reference with an all-zero hash today, and `TestNoUnresolvedHashInARenderableProfile` stops the placeholder becoming load-bearing. Deliberately **not** pre-filled with plausible weights: a plausible wrong weight is worse than an obviously absent one, because it produces output.
- **The policy caveat and the DRAFT marking are different claims, and every `assess` output carries both.** DRAFT says *this document is not finished*; the caveat says *this document is not a legal conclusion* — and a finished document can still not be a legal conclusion, which is the case that matters. Canonical wording and the phrase-by-phrase substance test in `docs/policy-caveat.md`.
- **Standing audit scope, now in CLAUDE.md's ritual:** at every phase gate, re-verify each obligation profile's citations and effective dates against the primary source, and confirm every claim automat renders into a human-facing document traces to a hashed source. **A stale legal citation is a finding ranked no lower than medium.**
- **SPRS output is the computed score plus per-requirement worked arithmetic** for human entry: which requirements counted, at what weight, which weight table by hash, what is unscored for want of evidence. No submission formatting, no affirmation text.
- **Staged, so the L1 path is not blocked by the 800-171 path:** (0) obligation profiles — **done**, data and schema only; (1) objectives catalog + weight table, data-only; (2) 800-171A worksheet + scoring; (3) CMMC L1 MET/NOT MET summary with the no-POA&M rule enforced. L1 needs no weight table, so (3) does not depend on Q10. Stage 1 also vendors the profiles' own citations, since nothing may render from a profile whose sources are unresolved.
- **SSP generation is out of scope for v1** — noted as future in the design page. An SSP is mostly about things outside the AWS account, and a partial SSP that looks complete is invariant 1's hazard in another form.
- **Accept:** golden reports for a fully-evidenced account, a partially-evidenced one, and one with no machine evidence at all; the DRAFT marking asserted across every renderer and the signature-affordance list asserted absent; no generated document contains a `MET`/`SATISFIED` automat wrote. The three L1 practices with no AWS surface (media disposal, both physical-access practices) must render NOT MET absent a determination — that is the acceptance test for invariants 2 and 3 together, not an edge case.

- **Accept (phase):** property suite green; **`verify` golden reports SHIPPED** for compliant / drifted / freshness-lapsed scenarios (`cmd/automat/verify_golden_test.go`) — reinterpreted from this line's original "findings-only" third scenario, which has no referent in what `verify` checks (D4: no detective layer, so no "findings" as DESIGN §12 uses the term); `assess` acceptance above.

## Phase 5 — Polish + lifecycle
- `reclaim` design + implementation (closure rate limits, plan/apply, `--yes`).
- KMS signer for evidence manifests.
- Docs site content: conventions.md, security-review.md ("the 60-line review" for central IT), beyond.md.
- Manual smoke-test runbook against a sandbox org; capture answers to `docs/open-questions.md` (delegation visibility, quota edges).
- **Re-verify `docs/vs-control-tower.md` against the implemented feature set before v1.** That page is human-owned positioning: its judgments stand as written, but every factual claim it makes about what automat does must be traced to shipped code and corrected if the implementation diverged. A positioning claim that outruns the code is the one kind of inaccuracy this project cannot afford.
- **Accept:** a stranger with a standalone AWS account can go README → init → vend → verify without asking a human anything.

## Deferred / explicitly out of scope for v1
- **Signature verification, trust-policy loading, and any form of registry** (DESIGN §11a). The *fields* exist and are recordable; nothing reads them. Verification without a trust model is theatre, and a trust model automat ships is a trust model automat owns. v2's intended mechanism is keyless OIDC-identity signing distributed over ordinary git or an OCI registry, so an institution never has to run a key ceremony — automat proposes a format and must never become a registry, a signing service, or a standards owner.
- Approval-per-vend request queue.
- Continuous monitoring, dashboards, agents.
- HIPAA / 800-53 catalogs (pipeline should make them data-only additions; pick the blessed HIPAA crosswalk before generating).
