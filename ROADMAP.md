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

Upstream gaps were filed and behavior-framed rather than as endpoint lists, and most of
the Organizations blocker has since closed:

**Closed.** [substrate#577](https://github.com/scttfrdmn/substrate/issues/577) (root had
no stable identity) and [#578](https://github.com/scttfrdmn/substrate/issues/578)
(Organizations: OU tree, policy lifecycle, placement, tagging) closed in **v0.97.0**
(2026-08-09). [#593](https://github.com/scttfrdmn/substrate/issues/593) (`AssumeRole` did
not evaluate a role's trust policy or an `sts:ExternalId` condition) closed in **v0.95.0**.
[#619](https://github.com/scttfrdmn/substrate/issues/619) (resource-policy plugin),
[#623](https://github.com/scttfrdmn/substrate/issues/623) (member accounts saw their own
private organization instead of the one they belong to — the actual blocker on Q5), and
[#624](https://github.com/scttfrdmn/substrate/issues/624) (Service Quotas requests filed
under a placeholder account) closed across **v0.98.0–v0.99.0** (2026-08-14).
[#629](https://github.com/scttfrdmn/substrate/issues/629) (the Account Management API —
`ListRegions`/`EnableRegion`/`DisableRegion`/`GetRegionOptStatus`,
`internal/baseline.EnsureRegions`'s own surface, filed by this project) and
[#625](https://github.com/scttfrdmn/substrate/issues/625) (`CloseAccount`, `reclaim`'s own
surface, including the `L-E619E033` quota interaction this project confirmed live) both
closed in **v0.99.0** too.

**Closed.** [#579](https://github.com/scttfrdmn/substrate/issues/579)
(`SimulatePrincipalPolicy`/`SimulateCustomPolicy`, which `preflight` is built on) closed in
**v0.100.0** (2026-08-14) — runs the same evaluator substrate's own request gate enforces
with, reports the three-way allowed/explicitDeny/implicitDeny distinction `preflight`'s own
`Certainty` field is built around, and deliberately does not evaluate SCPs, matching
exactly the caveat `preflight`'s own doc comment states about real IAM.

**Closed, and with it every substrate gap this project ever tracked.**
[#580](https://github.com/scttfrdmn/substrate/issues/580) (AWS Config: recorder, delivery
channel, Config rules, conformance packs — 25 operations) closed in **v0.101.0**
(2026-08-15), modeling the identical "created but not started" trap
`EnsureConfigRecorder`'s own doc comment already names, and computing
`EnsureDeliveryChannel`'s S3 refusals from real bucket-policy state in the same emulator.
`internal/org`, `internal/preflight`, and `internal/baseline` are now all migration
candidates — `docs/testing-strategy.md`'s "Substrate v0.95.0 → v0.101.0" section has the
full account of what landed across all six releases and what each change means for a
migration evaluation; a newly-emulatable operation is not automatically a faithful model
of the undocumented behavior `docs/open-questions.md`'s Q5/Q8/Q9/Q13/Q24 are actually
asking about, so evaluate before assuming either way. Keep the behavior-first framing on
any further filings, should a new gap surface.

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
- **`automat assess --account <id> --profile cmmc-l1 --scope-statement <text> [--determinations <file>] [--evidence-dir <dir>] --out <dir>` SHIPPED, Stage 3 only.** `--profile` accepts only `cmmc-l1` today — `dfars-7012` and `nih-cadr-dua` need Stages 1-2 (the 800-171A worksheet, DFARS scoring), not built in this pass. Read-only against AWS beyond one `sts:GetCallerIdentity` call for evidence attribution, so no `--yes`. `--profile` rather than `--framework`: the profile determines the determination vocabulary, whether a POA&M is renderable, and whether there is a score at all, and it names the catalog. `--scope-statement` is required: whether the account equals the system boundary is the operator's assertion, never automat's inference. `--evidence-dir` (default `evidence`, AUDIT-5) exists because `assess` has no `--environment-profile` to read `baseline.evidence.local_dir` out of — the account is named directly, the same reason `list` has its own `--evidence-dir` — so an account vended under a profile that customized the directory needs the same value replayed here, or the `OpAssess` record lands in a second, disconnected manifest instead of the account's real chain. A separate verb rather than a `verify` flag: `verify` asks "does reality still match the artifact", `assess` asks "what can be claimed about this account", and `assess` writes an `evidence.OpAssess` record while `verify` does not. §13 gained it (docs/cli-surface.md D7, D8). **This build's honest limit:** `catalogs/cmmc-l1.json` carries no SCP fragments and no AWS Config read interface exists in `internal/awsapi`, so `assess` contributes zero machine evidence for any of the fifteen L1 practices — `internal/assess.SummarizeL1` marks every objective's evidence class `operator`, and `docs/assessment-reporting.md`'s "What automat can and cannot contribute" table is accurate as written, not aspirational.
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
- **Staged, so the L1 path is not blocked by the 800-171 path:** (0) obligation profiles — **done**, data and schema only; (1) objectives catalog + weight table, data-only — **not done**; (2) 800-171A worksheet + scoring — **not done**; (3) CMMC L1 MET/NOT MET summary with the no-POA&M rule enforced — **SHIPPED** (`internal/assess`, `cmd/automat/assess.go`). L1 needs no weight table, so (3) did not depend on Q10. Stage 1 also vendors the profiles' own citations, since nothing may render from a profile whose sources are unresolved — still true, and still blocking Stages 1-2.
- **SSP generation is out of scope for v1** — noted as future in the design page. An SSP is mostly about things outside the AWS account, and a partial SSP that looks complete is invariant 1's hazard in another form.
- **Accept (Stage 3):** golden reports for a fully-evidenced account (every practice MET via a determinations file) and one with no determinations file at all (every practice NOT MET); the DRAFT marking and no-signature-affordance list asserted across the renderer registry the same way `internal/bundle`'s own registry is checked; no generated document contains a `MET` automat wrote itself (`TestSummarizeL1NeverWritesMETItself`). The three L1 practices with no AWS surface (`MP.L1-b.1.vii` media disposal, `PE.L1-b.1.viii`/`ix` physical access) render NOT MET absent a determination — covered as part of the all-silent scenario, not a separate case, since this build has no machine evidence for any practice. **Not accepted, deferred to Stages 1-2:** a "fully-evidenced account" scenario carrying `machine`-class evidence — no such evidence exists to render yet.

- **Accept (phase):** property suite green; **`verify` golden reports SHIPPED** for compliant / drifted / freshness-lapsed scenarios (`cmd/automat/verify_golden_test.go`) — reinterpreted from this line's original "findings-only" third scenario, which has no referent in what `verify` checks (D4: no detective layer, so no "findings" as DESIGN §12 uses the term); `assess` acceptance above.

## Phase 5 — Polish + lifecycle
- **`reclaim` SHIPPED**: `automat reclaim --account <id> [--dry-run] --yes [--evidence-dir <dir>]`. Design settled first in `docs/reclaim-design.md` — durable-by-default, `--yes` unconditional (every apply is destructive; no gated-only-on-one-step nuance the way `init` has), detach-then-close ordering (a failed close leaves a known, resumable state; the reverse could not). `DetachPolicy`/`CloseAccount` moved off `TestNoWriteInterfaceCanDestroy`'s forbidden list onto a new, narrowly-scoped `awsapi.OrgReclaimAPI` — exactly the fix that test's own comment described in advance. No AWS-side closure-rate-limit pre-check exists (no Service Quotas code exposes the rate); a rejection is reported with the actual AWS-documented limit named. **Known gap, disclosed rather than hidden**: the onboarding bundle's vendor role does not yet grant `organizations:CloseAccount`, so `reclaim` in the MEMBER state will be denied until the bundle is widened (`docs/security-review.md`).
- **KMS signer SHIPPED**: `evidence.KMSSigner`/`KMSVerifier` over a new narrow `awsapi.KMSAPI` (Sign, Verify only). No schema change was needed — `AlgKMSRSAPSS256`/`AlgKMSECDSA256` were already in the closed algorithm enum and `key_id` already used the wider `round_trip_ref` pattern, both landed ahead of time for exactly this. Wired in as two config fields (`evidence_kms_key_id`/`evidence_kms_algorithm`, both-or-neither) rather than a per-command flag — operator infrastructure, the same standing as `vendor_role_arn`. Opt-in: absent config means unsigned records, unchanged from before this shipped.
- **Docs site content SHIPPED**: `docs/conventions.md` (extracted from DESIGN §14, corrected against shipped code — the S3 manifest-mirror convention DESIGN §14 named has no implementation anywhere), `docs/security-review.md` (the 60-line review, verified line-by-line against `internal/bundle`'s golden fixtures — found the claimed "~60 lines" is actually ~300 today), `docs/beyond.md` (capability-phrased, no product names, per DESIGN §15).
- **`docs/vs-control-tower.md` re-verified against Phase 5's feature set.** Fixed a four-phases-stale "as of Phase 1" framing and three drifted claims: automat does not yet deploy detective controls or baseline via a provisioning role (`internal/baseline` doesn't exist — stated as the largest capability gap, not claimed as parity); `verify` does not render a per-control "N of M enforceable" breakdown (only which control sets a compile drew from); evidence manifests are not "signed" by default (signing is optional and config-only, most manifests today are unsigned). The "~60 lines" reviewable-trust-surface claim is corrected to the measured ~300.
- **README quickstart SHIPPED**: `login` → `preflight` → `init` → `vend` → `verify`, exact flag names, a minimal environment profile verified to actually load and validate (caught one drafting mistake: `placement.target_ou` needs an OU id, not a name). This is the phase's accept criterion, below.
- **Manual smoke-test runbook: still not automated, unchanged from Phase 1's disclosure** — `make smoke` runs zero tests today (no file carries the `smoke` build tag). `docs/smoke.md`'s checklist gained an eighth, last entry (**Q24**, `docs/open-questions.md`): whether `reclaim`'s detach-then-close sequence behaves against a real org the way its design assumes (real `CloseAccount` is asynchronous; the fake is not) — ordered last because it is the only entry that destroys the account it tests. **This item is explicitly handed off, not executed by this pass**: it requires a human with real AWS credentials against a named sandbox organization and `AUTOMAT_SMOKE_PROFILE` set, which no agent run can supply. Capturing answers to Q5, Q7, Q8, Q9, Q12, Q13, Q24 remains open.
- **Accept:** a stranger with a standalone AWS account can go README → init → vend → verify without asking a human anything — **met** by the README quickstart above; the environment profile in it is verified to load, and every flag name in the walkthrough is copy-pasted from the built binary's own `--help` output rather than paraphrased.

## Backlog — research complete, awaiting implementation

Everything below came out of a 2026-08-10/11 research pass (9 parallel agents studying every
open item in `docs/open-questions.md` plus the largest gaps in `docs/beyond.md`). Five findings
that needed no schema change and no live-AWS infrastructure were implemented immediately and are
folded into the phases above (Q20's validation gap, Q21's birth-certificate print, Q22's
disclosure warning, `verify`'s structural-honesty breakdown, and `internal/baseline`'s slice 1
interfaces). Everything else is organized below by track, with full technical detail; the
**phase order** that sequences these tracks against each other — which can start now, which wait
on a maintainer decision, which must not run in the same parallel batch because they'd touch the
same files — is a separate scheduling layer, given first since it's what a future session reads
before dispatching anything.

### Phase order across tracks

**Phase 0 — one consolidated pre-approval ask. APPROVED 2026-08-11.** Three tracks each needed a
rule-6 schema decision: Q23's `OpRotate` operation + `rotation` block; assessment's
`worksheet_summary`/`score` sibling fields plus two new schema files (objectives catalog, weight
table); and, only if later evaluation showed it was needed, a cross-account-role field for the
evidence mirror. The evidence-mirror slice 1 work (Phase 1) confirmed the existing
`Region`/`Profile` config fields are sufficient — no cross-account-role field is needed, so that
third item is moot. **The maintainer approved items 1 and 2** (Q23's rotation addition and
assessment's schema additions, including `schema/objectives-catalog-v1.schema.json`, which now
exists ratified rather than draft — see `schema/CHANGELOG.md`). Phase 2's schema-gated work may
proceed.

**Phase 1 — start now, five tracks, no schema change, no cross-track file conflict:**
1. `internal/baseline` package skeleton + slice 2 (`EnsureAutomationRole`) — see below. The one
   track that creates the new package; everything else in the baseline track depends on this
   landing first, alone (not concurrently with slice 6, which would otherwise risk two agents
   scaffolding the same new package differently).
2. Evidence mirror slice 1 (write-only upload) — see below.
3. Assessment's `800-171r2` control artifact — see below. Independent of every other track.
4. **Done.** Assessment's `800-171A` objectives catalog — sequenced right after track 3 landed
   (needed `800-171r2`'s real requirement ids to cross-reference against). See "Assessment
   Stages 1-2" below for detail.
5. Q20's live-IAM smoke subtest — see below. Small, `internal/smoke`-only, needs nothing else.

Running in parallel with all five, but not as agent work — human-paced, started now, blocking
nothing else: the **DFARS weight table's dual-transcription** (Q10's already-decided procedure —
**done, 2026-08-12**; see "Assessment Stages 1-2" below) and the **Q5/Q8/Q9/Q13 cluster's manual
AWS setup** (second permanent sandbox account, bundle deployment, CFN apply, delegation-policy
apply — still outstanding).

**Phase 2 — depends on Phase 1's baseline skeleton; schema-gated items depend on Phase 0's answer:**
1. `internal/baseline` slices 3, 5, 6 — parallel-safe against each other (disjoint `Ensure*`
   methods, no shared new state), built against Phase 1's skeleton.
2. `internal/baseline` slice 4 — can run alongside 3/5/6; no longer gated on Q22's review timing
   (Q22 already shipped).
3. Q23's rotation — starts once Phase 0 approves it. Do **not** run in the same parallel batch as
   evidence-mirror slice 2 (item 4 below) — both touch `internal/evidence`, real merge-conflict
   risk even under worktree isolation. Sequence one after the other.
4. Evidence mirror slice 2 (read-and-diff in `verify`) — depends only on mirror slice 1 (Phase
   1), not on baseline. Sequence against Q23's rotation per the note above.
5. Q5/Q8/Q9/Q13 cluster's brokered-credential harness code — starts once the manual AWS
   deployment (running since Phase 1) has actually completed. Q13's subtest specifically also
   needs baseline slice 2 (Phase 1) to exist — it will, by this point.

**Phase 3 — depends on Phase 2's baseline slices, and on assessment's human-paced inputs:**
1. `internal/baseline` slice 7 (evidence/manifest wiring) — needs to know what slices 3/4/5/6
   actually produced.
2. Assessment Stage 1 (worksheet) — needs the `800-171r2` catalog + objectives catalog (both
   Phase 1) and Phase 0's schema approval. `nih-cadr-dua`'s worksheet first (no weight-table
   dependency), then `dfars-7012`'s.

**Phase 4 — final pieces, each with its own late dependency:**
1. Assessment Stage 2 (DFARS scoring) — needs Stage 1 (Phase 3) and the weight table, which has
   been transcribing since Phase 1 on its own timeline; check its status well before this phase
   starts, since it's the likeliest long pole in the whole backlog.
2. **Done.** `internal/baseline` slice 9 (wire `verify`'s detective/procedural layers).
3. `internal/baseline` slice 8 (`disable_org_access_role_after_vend`) — smallest, most
   speculative; could be deferred past this plan entirely.

### `internal/baseline`, slices 2-9

Slice 1 (`awsapi.ConfigAPI`/`AccountAPI` + fakes, no behavior) is done. Remaining slices, in the
research plan's own order:

2. **`EnsureAutomationRole`**, wired into `runVendSteps` **before** SCP attachment. This is the
   one genuine surprise worth a PR-description callout per CLAUDE.md rule 2: DESIGN §7 lists
   baseline work as step 5, after the SCP-attachment step it lists as step 4 — but the automation
   role must be created and fully permissioned *before* `baseline-protection` attaches, or the
   protecting SCP denies the very `PutRolePolicy` call that permissions the role (Q13's ordering
   constraint). The two steps must run in the reverse of DESIGN's listed order, not the order the
   numbering implies. Also implements the Q13 parked-on-re-permission-denial handling for
   re-vends after the SCP is already attached.
3. **`EnsureConfigRecorder` + `EnsureDeliveryChannel`.** Scope-cut: v1 requires
   `delivery_bucket` to be a pre-existing, operator-named bucket; automat does not provision S3
   buckets with their own lifecycle/encryption/public-access-block policy in this pass.
4. **`EnsureConformancePack`**, the first production consumer of
   `compilesets.Merged.SortedConfigRules()`. This is the exact point where Q22's now-inert
   override-disclosure warning starts mattering in production — schedule after Q22's disclosure
   has had a chance to be reviewed against real conformance-pack content, not concurrently.
5. **`EnsureRegions`** — independent of 3/4, can land in parallel with either.
6. **`EnsureAttestationStubs`**, the first consumer of `compilesets.DedupeAttestations`. No AWS
   call at all (pure local-filesystem work through `internal/safeio`) — cheapest slice, could
   land first regardless of numbering.
7. **Evidence/manifest wiring**: replace `recordBaselineIsMissing` with real `OpBaselineApply`
   records populating `Enforcement.ConformancePackARN`/`ConfigRuleNames`/`RegionSet`/`AttestationIDs`
   (all four fields already exist on `evidence.Enforcement`, unused today).
8. **`disable_org_access_role_after_vend`** — design settled, 2026-08-12
   (`docs/disable-org-access-role-design.md`): a deny-all inline permissions policy on
   `OrganizationAccountAccessRole` via `iam:PutRolePolicy`, the same call/create-or-replace shape
   `EnsureAutomationRole` already uses for its own role. An SCP is structurally impossible (SCPs
   never bind the management account, which is who calls `AssumeRole` on this role) and
   `DeleteRole` is eliminated on recoverability grounds (a recreated role has a different
   identity). Must run LAST in `runVendSteps`, after the SCP set attaches — the mirror image of
   `EnsureAutomationRole`'s own "must run first" constraint, both for the identical reason
   (`BP.IAM-1` denies mutating either named role once baseline-protection is attached). No schema
   change, no new `evidence.Operation`, no new `org.Verb`, no CLI flag needed — not yet built.
9. **Done.** Wired `verify`'s detective and procedural layers against what step 5 now installs —
   DESIGN §12's own next increment once baseline existed. `internal/verify.CheckDetective`
   (detective.go) reuses `internal/baseline`'s own exported comparators (`SameRecorderConfig`,
   `SameInputParameters`) through a new read-only `awsapi.ConfigVerifyAPI`, so "matches" means
   exactly what it means to the `Ensure*` method that would correct a drift.
   `internal/verify.CheckProcedural` (procedural.go) reads the local attestation-stub directory,
   read-only, no AWS call. Both follow the "opt-in, and not opted into" discipline the evidence-
   mirror layer established. `cmd/automat/verify.go` wires both in, with a detective/procedural
   check that could not complete at all (assumption failure, denied read, unreadable stub
   directory) landing at `exitVerifyUnknown`, never `exitVerifyDrift`.

### Assessment Stages 1-2 (800-171A worksheet + DFARS scoring)

Strict prerequisite chain, not parallelizable at the start:

1. **Done.** The `800-171r2` control artifact — `catalogs/800-171r2.json`, 110 requirements
   across 14 families, retrieved from NIST CPRT `SP_800_171_2_0_0`, vendored + hashed, compiled
   via a new `compileFrom171r2` target in `gen/catalog` — now exists, so
   `catalogs/obligations/dfars-7012.json`'s `control_catalogs[].artifact_id: "800-171r2"` is a
   resolvable reference rather than a forward one. Every requirement compiles `procedural`
   with a per-family attestation stub: no AWS-side mapping is joined (docs/open-questions.md
   Q4 step 3, Security Hub's 800-171 Rev 2 standard and Audit Manager's 800-171 Rev 2
   framework, remains deferred future work, not attempted in this pass).
2. **Done (2026-08-12).** The DFARS weight table — Q10's dual-transcription procedure, carried
   out for real: two independent passes against the DoD's *NIST SP 800-171 DoD Assessment
   Methodology, Version 1.2.1*, zero disagreements across all 110 requirements, source currency
   separately confirmed against the operative DFARS 252.204-7019/7020 clauses. Vendored at
   `gen/sources/dfars-800-171r2-weights.json`, hashed, and named by that hash in
   `catalogs/obligations/dfars-7012.json`'s `scoring.weight_table` (no longer the all-zero
   placeholder). `TestWeightTableHashMatchesTheFileOnDisk`
   (`internal/artifact/obligation_profile_test.go`) is the new sibling test keeping this hash
   from drifting, since the existing `TestProfileSourceHashesMatchTheFilesOnDisk` only walks
   `p.Sources`, not `scoring.weight_table`. **Three requirements (`3.5.3`, `3.13.11`, `3.12.4`)
   have no single scalar weight in the source itself** — recorded as `docs/open-questions.md`
   Q25, a real scoring-model design question Stage 2 (item 5, below) will need to answer, not a
   transcription gap either pass could have resolved.
3. **Done.** The 800-171A objectives catalog (single-pass retrieval + hash, unlike the weight
   table — don't conflate the two transcription disciplines) — `catalogs/objectives/
   800-171a-objectives.json`, 320 assessment-objective determination statements across the same
   110 requirements `800-171r2` names, retrieved from NIST CPRT `SP_800_171A_1_0_0`, vendored +
   hashed, compiled via a new `compileFromObjectives` target in `gen/catalog` into
   `internal/assess.ObjectivesCatalog` — a NEW, STANDALONE Go type and schema
   (`schema/objectives-catalog-v1.schema.json`), not a field on `control-artifact-v1`. Retrieval
   endpoint found by the same discovery discipline `800-171r2`'s Q4 entry used: the documented
   shape, with `sp_800_171_2_0_0` substituted for `sp_800_171a_1_0_0`, worked on the first try —
   no third-party reference lookup was needed this time. **The schema file is DRAFT, not
   ratified** — this line item's own text below already says the two new schema files (this one
   and the weight table's) are "needs pre-approval per rule 6, not yet asked", so
   `schema/objectives-catalog-v1.schema.json` carries an explicit `$comment_draft_status` saying
   so and is not to be treated as approved. Cross-referenced against `catalogs/800-171r2.json` at
   compile time (`ObjectivesCatalog.CrossReferenceControlArtifact`): the two datasets' requirement
   id sets are exactly equal, no orphan either direction.
4. **Stage 1 (worksheet)** — `nih-cadr-dua` first (no weight-table dependency, `scoring.method:
   "none"`), then `dfars-7012`'s worksheet half. Must also wire the `nih-cadr-dua`
   revision-determination refusal (`--profile nih-cadr-dua` with no `--determinations` file must
   refuse, not silently render every objective NOT MET) — the mechanism already exists in
   `Determinations.ValidateAgainst`, it's just never called from a path that requires it.
5. **Stage 2 (DFARS scoring)** — strictly after 2 and 4.

**Approved by the maintainer 2026-08-11 (Phase 0, above).** A `worksheet_summary` sibling field
and a `score` sibling field on `assessment-result-v1` are cleared to build when Stage 1/2 code is
written (item 4/5 above); `schema/objectives-catalog-v1.schema.json` is ratified (item 3 above,
already built and merged). The weight-table schema remains undrafted, but is cleared to build —
the DFARS weight table itself (item 2) is now done (2026-08-12), so there's real, ratified data
to shape a schema around whenever Stage 2 code is written.

### Remote evidence mirror

Two independent slices:

1. **Write-only upload.** New `awsapi.S3MirrorAPI` (`PutObject`/`GetObject`, no `DeleteObject` —
   automat never administers or deletes a mirror copy). New `evidence.Mirror` interface + one
   `S3Mirror` implementation, following `Signer`/`KMSSigner`'s existing shape. Reads the bucket
   name from the **already-existing, already-schema-legal**
   `envprofile.OutputTargets.InAccountBucket`/`ManagementMirrorBucket` fields — no new config
   surface needed for this slice. Recommend management-account bucket as the default (a vended
   account's own admin has no access to it unless separately granted); the in-account bucket's
   tamper-resistance is weaker until `internal/baseline` can protect it with an SCP, and should be
   documented as such rather than presented as equivalent.
2. **Read-and-diff in `verify`.** The half that actually closes (not just narrows) Q21's residual:
   `verify` fetches the mirrored copy and compares `Meta` + `records[0]` against the local file,
   flagging drift as a new finding class. Needs a second interface method (kept separate from
   `Mirror`, mirroring `Signer`/`Verifier`'s existing split — a writer never needs read access).

Flag as needs-pre-approval only if a cross-account-role config field turns out to be needed (not
certain — the research found the existing `Region`/`Profile` fields on `config.Context` may be
sufficient).

### Q23 — evidence manifest rotation

Reuse `Custody.SuccessorManifestID` (already schema-legal, currently unused) via a new
`OpRotate` operation and `rotation` schema block, generalizing the existing terminal-record
check (`IsCustodyTransfer`) to cover both terminal kinds. **Approved by the maintainer 2026-08-11
(Phase 0, above)** — widens the operation enum, cleared to build. Trigger: automatic, at a
2,000-record threshold (well under the
~8,971-record ceiling `MaxManifestBytes` implies), but visibly logged, not silent — matches this
project's preference for explicit, disclosed behavior over implicit magic. A `Meta.PredecessorSHA`
field for cryptographically (not just nominally) linking rotated manifests is a distinct, later,
also-needs-pre-approval ask — don't bundle the two.

### Q5/Q8/Q9/Q13 live-org test cluster

One shared, corrected prerequisite: the vendor role deploys into the **management** account, not
the member account (the member only needs an identity matching the bundle's trust policy — the
earlier framing of "deploy the bundle into the member account" was wrong). Needs a second,
*permanently-kept* AWS account under the sandbox org (not vended-and-reclaimed like every other
smoke-test account) playing "member," plus the onboarding bundle actually deployed: `automat setup
--request`, a manual CFN deploy of the vendor-role template into the management account, and a
manual `organizations:PutResourcePolicy` applying the delegation policy. Sized ~half a day manual
AWS setup + ~1 day of Go work for a new brokered-credential harness path in `internal/smoke`
(constructing a client via `internal/broker.Assume` rather than only ever native credentials).
Once deployed: Q8's move-of-an-untagged-account check becomes a real assertion (not just a
recorded `Finding`) under the *actual* restricted vendor role; Q9 gets tested against the real
3-ARN resource list; Q5 gets tested from the member account's own point of view against a
delegation policy that now actually exists. **Q13 stays blocked on `internal/baseline` regardless**
— no amount of bundle deployment creates the automation role Q13 needs to test against.

### Q20's live-IAM behavioral test

Once the validation-gap fix (already shipped) is in place, add a new `internal/smoke` subtest:
construct a control-character-bearing SCP resource/action directly against `compilesets.Pack`
(bypassing automat's own — now-fixed — validation, which is exactly the "arrived another way"
case Q20's remaining open half is about), `CreatePolicy`/`AttachPolicy` it against the sandbox OU,
and observe whether AWS refuses it, preserves it literally (silent no-op Deny), or normalizes it
into something else. Cheap and low-risk relative to the rest of the smoke checklist — no account
needs to be vended, just a throwaway policy create/attach/detach. Needs its own cleanup path since
`OrgReclaimAPI` deliberately has no `DeletePolicy` (`internal/smoke` may reach past the narrow
interface to the harness's own concrete client, the same way `Harness.OrgClient` already does).

## Deferred / explicitly out of scope for v1
- **Signature verification, trust-policy loading, and any form of registry** (DESIGN §11a). The *fields* exist and are recordable; nothing reads them. Verification without a trust model is theatre, and a trust model automat ships is a trust model automat owns. v2's intended mechanism is keyless OIDC-identity signing distributed over ordinary git or an OCI registry, so an institution never has to run a key ceremony — automat proposes a format and must never become a registry, a signing service, or a standards owner.
- Approval-per-vend request queue.
- Continuous monitoring, dashboards, agents.
- HIPAA / 800-53 catalogs (pipeline should make them data-only additions; pick the blessed HIPAA crosswalk before generating).
