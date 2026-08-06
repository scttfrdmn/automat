# Open questions

Uncertainties recorded rather than guessed at, per CLAUDE.md's working style: write
the code behind an interface, note what only a live org (or a maintainer decision) can
answer, and keep going.

Each entry says what is unknown, what the code currently assumes, and what would settle
it. Delete an entry when it is answered; do not silently reinterpret one.

---

## Phase 0

### ~~Q1 — Set-valued conformance-pack parameters have no union order~~ — RESOLVED

**Resolved** at the Phase 0 review. The schema gained `set-union` and `set-intersect`
orders plus an optional `set_separator` (default `,`), before publication, so no version
bump; both changes are recorded in `schema/CHANGELOG.md`. Deny-shaped sets
(`blockedActionsPatterns`, `blockedPort1`–`blockedPort5`) are `set-union`; the allow-shaped
`authorizedTcpPorts` is `set-intersect`. `internal/artifact/order.go` implements
resolution, with monotonicity and the semilattice laws as property tests.

**One thing Phase 4 still has to handle**, carried forward rather than left implicit:
`blockedPort1`–`blockedPort5` are one prohibited-port set spread across five slots, and
`RESTRICTED_INCOMING_TRAFFIC` types each as a single integer. Per-slot `set-union` is
correct, but the artifact-level union must **re-slot** the unioned ports across the five
parameters and hard-error above five, rather than emit a joined value the rule would
reject. Also recorded in `gen/MAPPING-NOTES.md` and at the declaration in
`gen/catalog/enforcement.go`.

### ~~Q2 — DESIGN §8's example control ID uses CMMC 1.0-era numbering~~ — RESOLVED

**Resolved** at the Phase 0 review: the human confirmed the catalog is right and DESIGN
§8's example was the error. §8 now shows `"id": "AC.L1-b.1.i"` with a pointer to
32 CFR 170.14(c)(1), and its `config_rules` sketch carries `provenance` and the five-value
`order` enum. The legacy AWS-side identifier remains addressable in
`crosswalk.aws_config_mapping_id`.

### ~~Q3 — AWS's mapping of identification (3.5.1) to logging rules~~ — RESOLVED

**Resolved** at the Phase 0 review: `IA.L1-b.1.v` **stays as-is** under the aws-mapping
layer. AWS maps nine logging rules (CloudTrail, ELB, RDS, S3, API Gateway, WAF) to
`IA.L1-3.5.1` / `IA.L1-b.1.v`, on the reading that identification is evidenced by
attributable logs. That reading is defensible, and second-guessing a mapping AWS does
publish is a different kind of act from filling a gap it leaves — the curated layer exists
for the latter only. Recorded in the assignment table in `gen/MAPPING-NOTES.md`.

### ~~Q4 — No OSCAL catalog exists upstream for 800-171 Rev 2~~ — RESOLVED, build deferred

**Resolved.** The premise was right but incomplete: `usnistgov/oscal-content` publishes an
OSCAL catalog for Rev 3 only, **but NIST's CPRT holds a complete legacy Rev 2 dataset**, so
no PDF extraction is needed. Verified during the Phase 0 review:

- Framework `SP_800_171`, version identifier `SP_800_171_2_0_0`, labeled "Revision 2",
  `frameworkVersionId` 10, status Production.
- `…/nudp/framework/version/SP_800_171_2_0_0/type/requirement/elements` returns HTTP 200
  and **exactly 110 requirements with full text and no empty entries**, across 14 families.
- `…/type/family/elements` returns the family titles (3.1 "ACCESS CONTROL" … 3.10
  "PHYSICAL PROTECTION").

The endpoints are the undocumented REST API behind the CPRT web UI, discovered from
`csrc.nist.gov/extensions/nudppublic/main.js`. Undocumented means unstable, which is fine
here: the retrieved JSON is hashed into `artifact.sources` and vendored, so the compile does
not depend on the endpoint staying up. **Rev 2 is withdrawn and will never change**, so the
extraction is frozen once reviewed — a one-time acquisition, not a refresh cycle.

**Plan for the `800-171r2` build (not started; explicitly out of scope for this session).**

1. Retrieve the CPRT requirement and family element sets; record each response's sha256,
   `retrieved_at`, and URI in `artifact.sources` as `catalog` entries.
2. Emit a reviewable `gen/` intermediate — the 110 requirements with family, number, and
   verbatim text — for hand review before it becomes a catalog. Same shape as the curated
   FAR source: a committed file a human has read, not a live fetch.
3. AWS mappings come from two API-retrievable sources, recorded as `mapping` entries: the
   **Security Hub NIST 800-171 Rev 2 standard** (control set + rule associations) and the
   **Audit Manager 800-171 Rev 2 framework** (control-to-evidence-source mappings). Both
   are richer and more current than a conformance pack, and both can be captured to a
   vendored file the same way.
4. Everything unmapped stays `procedural` with an attestation stub (ROADMAP Phase 0), and
   the same orphan check applies: a mapping AWS publishes that no requirement claims fails
   the compile.
5. Expect the r2 catalog to bind the same parameterized rules as `cmmc-l1`
   (`iam-password-policy`, `restricted-common-ports`, `vpc-sg-open-only-to-authorized-ports`).
   That is the first real exercise of the union orders resolved in Q1, and where the
   `blockedPort` re-slotting caveat will first matter.

Adjacent CPRT datasets found while checking, potentially useful later:
`SP-800-171-Rev-2-to-SP-800-171-Rev-3`, `NIST SP 800-171 r2 to CMMC L1`,
`NIST SP 800-171 r2 to CMMC L2`, `NIST SP 800-171 R2 to NIST SP 800-53 R5`, and
`SP_800_171A` (1.0.0 and 3.0.0).

---

## Awaiting a live org

Nothing here can be answered from fakes; all of it is Phase 1+ and DESIGN §16 already
names most of it. The checklist is `docs/smoke.md`, which orders these by when a first
live run reaches them and says what each run must capture. Answering one of these means
editing this file — deleting an entry or narrowing it — not reporting that a test
passed.

One of them is worth knowing about before reading the rest: **Q8's bad case is the only
one here that is silent.** Q9 and Q7 fail visibly, Q5 and Q6 are questions about
capability and headroom. A tag condition that does not bind looks exactly like one that
does.

### Q5 — What can `preflight` actually detect about delegation from the member side?

DESIGN §4 says preflight should report delegated-admin status "via `DescribeResourcePolicy`
effects where visible". Whether a member account can read the delegation policy that grants
it policy-management rights is unverified. If it cannot, preflight must be told rather than
detect, and the onboarding bundle needs to carry that fact.

### Q6 — SCP quota edges under union output — **RE-MEASURED AGAINST REAL STATEMENTS; HEADROOM IS AMPLE**

DESIGN §16 names the quotas (5 SCPs per target, 5120 characters each). What was unverified was
how close a real union of `cmmc-l1` + a profile's allowlists + a campus baseline comes to them,
and therefore how aggressive the packer must be about merging Action lists.

This entry previously said the question was blocked on catalog content, because no shipped
artifact had an `scp` block. That was the wrong diagnosis: the packer's real subject was always
`baseline-protection`, and it was a missing Phase 0 deliverable rather than a coverage gap.
`catalogs/baseline-protection.json` now ships (DESIGN §10 as data, compiled from
`gen/sources/baseline-protection.json`), so the numbers below are from real statements.

**Measured, against the shipped set.** Seven protection controls, of which four share the
`baseline-automation` exemption and therefore merge into one 11-action statement:

| input | statements | policies | first policy | of 5120 |
| --- | --- | --- | --- | --- |
| `baseline-protection` alone | 4 | 1 | 1069 | 20% |
| `baseline-protection` + `cmmc-l1` | 4 | 1 | 1069 | 20% |
| + a profile's allowlists (2 regions, 15 services) | 6 | 1 | 2397 | 46% |
| + 60 allowlisted services | 6 | 1 | 2882 | 56% |
| + 200 allowlisted services | 6 | 1 | 4422 | 86% (warns) |

`cmmc-l1` adds nothing because its SCP count is permanently zero by design
(`TestEnforcementBreakdownIsPinned`). The realistic shipped configuration lands at 46% of one
of three usable policies, so **the 80% warning does not fire on any realistic input** — the
first thing that trips it is an allowlist of roughly 200 services, which is most of AWS and
therefore not an allowlist. The synthetic figure this entry used to quote (~28 statements per
policy) was indeed optimistic per statement: a real merged protection statement is about 700
characters against a synthetic one's ~170. It was pessimistic per *artifact*, because the merge
collapses far more than the synthetic fixtures let it.

**The re-measurement found a live packer defect**, which is the part worth recording. Scaling
the protection set by replicating it (renaming ids, Sids, and actions so the merger cannot
collapse the copies) produced, at 14 copies, a single merged statement of 5036 characters —
larger than any policy can hold. The merge groups actions by exemption set, so a catalog whose
controls share one exemption yields one statement carrying all of their actions, and that is
unbounded. The old error told the operator to "split the control's action list across several
statements in the catalog", which cannot be done: the catalog *had* split them, across seven
controls, and the merge joined them. `renderFitting` now splits an oversize Deny by halving its
action list, which cannot widen (a Deny's action list is a disjunction, so parts over halves
deny exactly the union) and explicitly refuses to do the same to an allowlist, where a
`NotAction` list is a conjunction and halving would deny everything. Post-fix thresholds, from
the same replication sweep: 10 copies → 2 policies, 19 → 3, 28 → slot overflow with the
actionable error.

**What remains open** is narrower than before and does not block anything:

- Whether a Phase 4 conformance-pack-derived SCP is shaped like the protection statements
  measured here. Those are hand-authored and dense; a generated one may carry longer action
  lists and more conditions per statement.
- Whether a campus baseline SCP attached in the reserved institutional slot leaves the three
  usable ones intact in practice, which is a live-org question about who attaches what.

Re-measure when `gen/catalog` emits SCP blocks from a conformance pack, and treat a real union
landing above ~2 of the 3 usable slots as a signal that the merger needs to be more aggressive
about action lists than the normal form is.

### Q7 — Does `MoveAccount` reliably succeed immediately after `CreateAccount`?

DESIGN §5 documents the cosmetic race and requires treating create-without-move as an error
state with a `parked` outcome. The retry policy that is actually needed — how long, how many
attempts — is an empirical question.

### Q8 — Does `MoveAccount` honor `aws:ResourceTag` on the account being moved?

AUDIT-1 added `aws:ResourceTag/automat:vended-by` to the vendor role's `MoveAccount`
statement (`internal/bundle/role.go`). The reasoning: `MoveAccount` authorizes against both
the destination parent and the account being moved, and an Organizations account ARN encodes
the organization rather than the OU, so `account/<org>/*` is org-wide and the condition is
the only thing confining which account may be moved. Without it the role can move any
account in the organization into the delegated OU — and out from under whatever SCPs bound
it before, since an account has exactly one parent.

What is unverified is whether Organizations evaluates `aws:ResourceTag` against the account
resource for this action, or only against the destination OU. Two failure modes:

- **The condition is ignored for the account.** Then the confinement does not exist and the
  bullet the generated README makes about it is false. This is the bad case, and it cannot
  be detected from fakes.
- **The condition is evaluated against the destination OU too.** Then `MoveAccount` fails
  for a legitimate vend, because automat's OUs are tagged `automat:managed-by` rather than
  `automat:vended-by`. Fails closed and shows up on the first smoke run.

The second is self-announcing; the first is not, so the Phase 5 smoke runbook must test it
directly: attempt to move an untagged account, from the vendor role, into the delegated OU,
and confirm `AccessDenied`. A smoke test that only proves the happy path proves nothing here.

If it turns out `MoveAccount` cannot be conditioned on the account at all, the fallback is
`organizations:MoveAccount` scoped by a permissions boundary that `preflight` verifies, or —
better — dropping the org-wide account resource and accepting that automat must be told each
account's ARN, which it knows, since it created it.

### Q9 — Does `MoveAccount` authorize against the *source* parent as well as the destination?

Q8's neighbor, same statement, opposite direction. The `MoveAccountsIntoTheDelegatedSubtreeOnly`
statement in both generated templates (`internal/bundle/role.go`, CFN and TF) lists three
resources: `account/<org>/*` and the two OU ARNs — the target OU and its `/*` descendants.
**It does not list the organization root.** That is deliberate: naming the root would let the
role move accounts to the root, which is the confinement the whole statement exists to create,
and the generated README says so ("An attempt to move an account into any other OU, or to the
root, is denied by IAM").

The unverified part is whether `MoveAccount` requires authorization on `SourceParentId` in
addition to `DestinationParentId`. If it does, the first vend fails: a newly created account
lands at the organization root (DESIGN §5's cosmetic race), so the source parent is the root
ARN, which is not in the resource list. Every vend fails the same way, on the move, after the
account exists — the `parked` outcome Q7 describes, for a reason that has nothing to do with
timing.

This **fails closed and is self-announcing**, unlike Q8's bad case, which is why AUDIT-1
accepted it rather than adding the root ARN speculatively: adding it to fix a failure that may
not exist would widen the grant to include the exact move the statement is designed to
prevent, and would do so silently, in the direction that cannot be caught later. A denied
first smoke vend is recoverable in an afternoon; a role that can quietly park any account at
the root is not.

**Phase 5 smoke runbook: `docs/smoke.md`, first item on the checklist.** The Phase 1 review
made the acceptance conditional on that tie being explicit ("first sandbox run answers Q9
empirically"), so the procedure — vend one account, let it fail, read whether the denial names
the *source* parent, record the error text rather than a paraphrase — lives there rather than
here. This is the first thing the first vend tests. If the move is denied
with the source parent named in the error, the fix is a fourth resource entry — the root ARN,
restricted to a statement that permits it only as a source, if IAM allows that distinction
(`organizations:MoveAccount` does not appear to expose separate source/destination condition
keys, which is itself part of the question). If it does not, the honest resolution is a
`DestinationParentId`-only grant plus documenting that the delegate can move an account it
created back to the root, and saying so in the README's blast-radius section.

### Q12 — Does `MoveAccount` into the account's *current* parent succeed or return `DuplicateAccountException`?

Q9's neighbour again, and the one `vend --resume` turns on. A resumed vend re-runs the move
against an account that is already exactly where it belongs, which is the *success* path of
resumption, not an edge case: it happens every time an operator re-runs a `vend` that got as
far as the move.

The AWS documentation does not say. `DuplicateAccountException` is defined as "that account is
already present in the specified destination", which reads like the answer, but the same
exception is listed on operations where "already present" means something else, and a no-op
move is plausibly treated as a no-op.

It is not resolvable from fakes, so **both readings are producible**:
`awsfake.OrgState.MoveToSamePlaceErrors` switches between them and
`TestBothReadingsOfAMoveToWhereTheAccountAlreadyIsAreReachable` exercises both. That test
deliberately asserts the knob works rather than which reading is right — asserting the latter
would be claiming an answer only a live org has, and CLAUDE.md rule 2 makes that a finding.

The consequence for `internal/org` is that ensure-semantics must pass **either way**, which
means: read the parent first (`ListParents`), skip the move when it already matches, and
*also* treat `DuplicateAccountException` as success if the move is attempted anyway. Both, not
one — the read-first path is the correct one, and the exception tolerance is what covers the
TOCTOU window between the read and the move. Neither alone is enough, and code written against
only one reading of this question would have exactly one of them.

Note the secondary wrinkle the fake also reproduces: `SourceParentId` is mandatory, so a
resumed vend cannot replay the call it made the first time — the source it recorded is stale
precisely because the move succeeded.

**Phase 5 smoke runbook, alongside Q9:** after the first successful vend, re-run the move with
the destination equal to the current parent and record the exact result.

### Q13 — `BP.IAM-1` protects the baseline roles from automat as well, so what is the vend ordering?

`gen/sources/baseline-protection.json`'s `BP.IAM-1` denies
`iam:Attach*/Delete*/Detach*/Put*/Update*` on `OrganizationAccountAccessRole` and
`automat-automation`, and it deliberately carries **no exemption** — not even for automat's own
automation role. The reasoning is in the control's `extends_design` and it stands: a role
exempted from a Deny on its own permissions can rewrite them, which is a standing
privilege-escalation path, and exempting the management-assumable role is not even expressible
(an exemption may name only a literal role ARN, and a shipped catalog does not know the account
id yet).

The consequence is an ordering constraint the vend path has to respect, and the part that is
genuinely unverified is where the boundary of that Deny falls:

- **Ordering.** The automation role must be created *and* fully permissioned before the
  protection policy is attached at the OU. Once it is attached, `PutRolePolicy` against that
  role is denied to every principal in the account, automat included. Note what is *not*
  denied: `iam:CreateRole` and `iam:TagRole` are absent from the list, so creating the role is
  fine and only re-permissioning it is blocked. A vend that attaches first and permissions
  second parks on an `AccessDenied` that reads like a missing grant rather than automat's own
  control.
- **Re-running a vend against an account whose role policy must change.** Idempotent
  re-vending is fine while the desired role policy matches what is there. If a later version of
  automat needs a *different* automation-role policy, the ensure step cannot write it: the
  operator has to detach the protection policy from the OU first, which is a delegated
  policy-admin action and lands in the evidence chain. That is the intended trade, but it means
  an automation-role policy change is a migration, not an upgrade, and Phase 5 has to say so
  where an operator will read it.
- **The live question.** Whether an SCP attached at the parent OU governs a call made by a role
  in the child account *at the moment automat is establishing that same role* is the ordering
  above answered empirically — SCPs are evaluated on the principal's account, so it should, but
  the attach/propagation timing is exactly the kind of thing DESIGN §3 warns about. There is
  also no documented propagation delay for SCP attachment, so an attach-then-immediately-write
  sequence may succeed once and fail later, which is the worst version of this.

**What the code assumes now:** nothing yet — no vend path exists. Task #13 must order
role establishment before policy attachment, and must not treat an `AccessDenied` on
`PutRolePolicy` against a baseline role as a permissions problem to report as a missing grant
(CLAUDE.md rule 7's remediation text would send the operator to add a grant that cannot help).

**Phase 5 smoke runbook:** after a successful vend, attempt `PutRolePolicy` on
`automat-automation` from the automation role itself and record the result; then re-run the
full vend and confirm it is a no-op rather than a denied write.

---

## Decided by the maintainer

Not live-org questions and not code questions: questions about source data whose authority
matters more than its availability, plus the places where the design and the schema
disagree and only the maintainer can say which is right. `docs/smoke.md` does not cover
these, because no sandbox run answers them. Kept here rather than deleted once decided —
the reasoning is the part that has to survive, since the decision looks like unnecessary
ceremony to anyone who has not read why.

### Q10 — Where do the DFARS per-requirement assessment weights come from, authoritatively? — **DECIDED**

Phase 4's score computation (`docs/assessment-reporting.md`) needs the DoD assessment
methodology's per-requirement weights: 5, 3, or 1 subtracted from 110 for each
unimplemented 800-171 requirement. The weights are published in the DoD *NIST SP 800-171
Assessment Methodology* document, which is **not machine-readable** — unlike every other
source in `artifact.sources`, which is retrieved and hashed.

What makes this a recorded question rather than an afternoon of transcription: the output
is a number posted to SPRS under a senior official's affirmation. A transcription error in
one weight produces a score that is confidently wrong and looks exactly like a score that
is right, and it would be wrong in the same direction every time it is regenerated. There
is no test that catches it — the arithmetic would be correct and the input would be
false.

Three options were on the table: hand-transcribe and hash; find a machine-readable
publication with real authority behind it (a third-party spreadsheet does not qualify); or
decline to compute a score at all and emit only the worksheet.

**Decision: hand-transcribe, vendor, hash, and name the table by hash in the report — with
the transcription performed TWICE, independently, and the two passes diffed before the
table is committed.** The second pass is done fresh from the source document without
consulting the first. Both the table and a note recording that the two passes agreed are
committed. If the two passes disagree anywhere, the disagreement is surfaced for review
rather than resolved by picking one.

The reason the dual pass is the decision rather than a nicety is the paragraph above:
**redundancy at the point of entry is the only control available against a false input to
correct arithmetic.** Every other provenance mechanism in this repository detects
*change* — a hash catches a file that was edited after review, a golden file catches a
renderer that started emitting something different. None of them catch a value that was
wrong when it was first written down. A hash over a mistyped weight is a perfectly valid
hash over a wrong number, computed identically forever. So the check has to happen before
the value enters the tree at all, and the only check that works there is doing the work
twice and comparing.

What gets recorded with the table:

- The source document's **title, version or date designation, and hash** — in
  `hashed_reference` form, so the version an operator names in a review is the version the
  score was computed from. `retrieved_at` is not a substitute: a methodology document has a
  version, and a score is defended by version, not by download date.
- The **provenance stated as `curated`**, not dressed up as a retrieval — the same posture
  as `gen/sources/far-52.204-21.json`, which is also a file a human read rather than a
  fetch.
- The **note that both transcription passes agreed**, with what was compared.

And the renderer states which weight table it used, by hash, in the report — so a wrong
weight is discoverable from the output rather than only from the source tree.

**Status: decided, not yet done.** The transcription is a Phase 4 deliverable.
`catalogs/obligations/dfars-7012.json` carries the weight-table reference with a
deliberately all-zero hash and a note saying so; `TestNoUnresolvedHashInARenderableProfile`
asserts no profile automat may render holds an unresolved hash, so the placeholder cannot
quietly become load-bearing. The table is deliberately **not** pre-filled with plausible
weights: a plausible wrong weight is worse than an obvious absent one, because it produces
output.

Note that **CMMC Level 1 needs none of this**: L1 is MET/NOT MET with no scoring, so Q10
gates only the 800-171 renderer and must not be allowed to hold up the L1 path.

### Q11 — Does FAR Case 2017-016 become a fourth obligation profile? — **NOT YET; ASK AGAIN IF FINALIZED**

The proposed FAR CUI rule (FAR Case 2017-016, with its proposed clause set and the
standard-form CUI marking requirements) would put a CUI obligation on civilian-agency
awards, not just DoD contracts — which is most of what a university actually holds. If it
is finalized it is plausibly the most broadly applicable profile in the set.

It is deliberately **not** shipped. A proposed rule creates no obligation, and a selectable
profile invites an operator to adopt one that does not exist. The schema's `status` enum
does include `"proposed"`, but only so that the *description* can say why nothing uses it:
a shipped profile carrying that value would make the dangerous thing reachable in order to
save a docs paragraph. The rule's current home is prose —
`docs/assessment-reporting.md` — where it can be read but not selected.

`TestTheShippedProfileSetIsTheOneThatWasApproved` pins the set at exactly three
(`cmmc-l1`, `dfars-7012`, `nih-cadr-dua`) and names this question in its failure message.
That is the mechanism: adding a fourth profile fails a test, so it becomes a deliberate
decision with a maintainer behind it rather than a plausible-looking file that appears in
`catalogs/obligations/` and starts being used.

**Revisit when, and only when, the final rule publishes** — at which point the profile's
citations get effective dates from the final rule, not the proposal, and the phase-gate
citation re-verification (CLAUDE.md's audit ritual) covers it from then on. Until then the
answer to "should we get ahead of this?" is no.

### ~~Q14 — DESIGN §7 says the profile resolves to a region set and a service set; `profile-v1` has no field for either~~ — **DECIDED: reading 2, plus a rename**

**Decision (maintainer, Q14).** DESIGN §7 is correct and the schema gains the fields —
**reading 2**, the sets carried on the document and composed by **intersection** with what
the control sets require. And first, a rename: `profile/v1` is now
**`environment-profile/v1`**, because "profile" named three unrelated documents and evidence
records name one of them by id and content hash, which made that field ambiguous to exactly
the auditor it exists for. See DESIGN §7a for the four senses (the fourth, the AWS credential
profile, is why `vend`'s flag is `--environment-profile` and `--profile` stays reserved), and
`schema/CHANGELOG.md` for the rename's field-by-field record.

What the decision requires beyond "add two fields", each of which is a constraint rather
than a nicety:

- **Both sets are ALLOWLISTS**, enforced by `aws:RequestedRegion` / service deny SCPs, and
  each carries its **exemption list as catalog DATA, never hardcoded** — the same pattern as
  `exempt_principals`. The global services (IAM, STS, Organizations, Route 53, Support,
  billing/Cost Explorer, Health, …) must be exempt from a region deny; getting that list
  wrong bricks the account.
- **Opt-in region *enablement* stays a separate field from the SCP allowlist.** One is a
  boundary (what a principal may call), the other an account-level Account Management API
  action at baseline time. An operator can legitimately want a region enabled but not
  permitted, or permitted-in-policy while never enabled. `baseline.regions.{home,enable,
  disable}` already is that separate field; it is not the allowlist and must not become it.
- **The narrowing invariant.** The environment profile may only ever *narrow* relative to
  what the control sets require. Union of controls, intersection of permitted behavior —
  the union law again. The packer's can-any-merge-widen property coverage gains region and
  service **sets** as subjects, not only statements.
- **The empty-set guard.** AUDIT-0's H5 found the empty set is the absorbing element of the
  meet; here the consequence is concrete — an empty allowlist denies everything and bricks a
  freshly vended account *after* create and move have already succeeded. So `minItems: 1` at
  the schema layer **and** an intersection that evaluates to empty is a hard error at
  **plan** time, naming which inputs produced the emptiness. Never a silent deny-all, never
  discovered at apply. Golden-tested.
- **`verify` must be able to check it** (Phase 4): the shape has to be checkable against
  attached region/service SCPs, not merely emittable.
- The schema also gains the environment profile's references to obligation profile ids, a
  classification level once item C lands, and the operator determinations DESIGN requires be
  recorded and hashed — these are what the manifest's environment-profile record points at.

Reading 1 was what the code implemented and is now superseded; the analysis of all three
readings is kept below because the decision is only legible against the alternatives.

Flagged rather than resolved, per CLAUDE.md: "when design and code disagree, stop and flag it".

DESIGN §7 step 1 is "resolve profile → compiled control artifact (§8) + region set + service
set", and step 4 attaches "control SCPs + region SCP + service SCP + baseline-protection SCP".
The packer emits all four shapes and `catalogs/baseline-protection.json` now supplies the
fourth. The region and service SCPs, though, are generated from `scp.region_allowlist` and
`scp.service_allowlist`, which live on the **control artifact**, not on the profile.
`schema/environment-profile-v1.schema.json` (then `profile-v1`) has `baseline.regions.{home,enable,disable}` — opt-in region
*enablement* via the Account Management API, which is step 5's in-child work — and its own
description already says "the region allowlist is enforced separately by SCP". So a profile
today cannot express either set, and §7's step 1 has nothing to resolve them from.

Three readings, and they are not equivalent:

1. **The design means the artifact.** "Resolve profile → artifact + region set + service set" is
   one resolution, not three: the profile names control sets, and their allowlists intersect
   into the sets §7 mentions. Nothing to change but §7's wording. This is the reading the code
   currently implements, and it is the strictest — an institution cannot widen its own region
   posture by editing a profile, only by choosing different control sets. It is also the least
   usable: "this account is us-east-1 and us-west-2 only" is a per-account decision at most
   institutions, and expressing it would mean authoring a control set per region combination.
2. **The profile carries the sets, intersected with the artifact's.** Two new profile fields,
   folded into the same `set-intersect` the merge already applies. Safe in the widening
   direction *if* intersected rather than replacing, which is the only version worth
   considering. This needs an `environment-profile/v1` schema change — an addition, but a restructuring of
   where authority for a preventive control lives, so rule 6's "ask first" applies rather than
   the audit-driven tightening exception.
3. **A shipped example control set carries them.** No schema change; the region and service
   allowlist shapes get exercised and shipped, and a campus forks the example. Cheap, and it
   dodges the question rather than answering it — the fork is the profile field, done by hand.

**What the code assumes now:** reading 1, because it is what the schema permits and no code
guesses at the others. The packer is fully implemented for all three — `regionStatement` and
`serviceStatement` render from whatever `Merged` holds, and where the allowlists came from does
not reach them — so this decision changes the profile schema and the vend path's step 1, not
the packer.

**Asked and answered before task #13's step 4 was written**, since step 4 is where the absence
becomes visible: a vend that attaches "control SCPs + baseline-protection" and silently attaches
no region or service SCP is a vend that does three quarters of what §7 says it does.

### Q15 — `obligation-profile/v1` does not say what its content hash covers

**Blocks nothing today; blocks the check it was written for.** An environment profile's
obligation reference carries a required `content_sha256`, and
`envprofile.CheckObligations` compares it against the profile's actual hash — the
second of its three checks, and the reason the field exists at all: an obligation
profile is a reading of policy that moves, so a reference naming only an id has a
subject that can be rewritten underneath it.

The comparison does not happen. `ObligationFacts.ContentSHA256` is left empty by
`internal/catalog`, and `CheckObligations` reads empty as *unknown* rather than as
*matches* (`TestAResolverWithNoHashDoesNotSilentlyPassTheHashCheck`), so a reference's
hash is checked for well-formedness by `Validate` and against nothing else.

The reason is that there is no value to compare against. The other two document types
define a hashed payload explicitly — `control-artifact/v1` hashes
`{controls, region_deny_exempt_services}`, and `environment-profile/v1` names its
covered and excluded fields in `internal/envprofile/canonical.go` — while the
obligation profile's schema describes `signatures[].content_sha256` as "the document
content hash" and never says which bytes that is. At least three answers are defensible:

1. **Raw file bytes.** Simplest, and checkable with `sha256sum`. But it makes
   reformatting the file a hash change, and the vendored profiles are hand-maintained
   JSON that a maintainer will reformat.
2. **Canonicalized whole document.** Stable under reformatting, and the
   `CanonicalJSON` the maintainer already ratified one of ("one canonicalization is
   the point"). Requires deciding whether `signatures` is inside its own hash, which
   the other two schemas answer by excluding it.
3. **A canonicalized payload excluding `signatures`, `status`, and `review_by`** — the
   fields that change when a profile is re-reviewed but its policy reading does not.
   Most useful for the check's actual purpose, and the most opinionated.

**What the code assumes now:** nothing, deliberately. The resolver reports the hash as
unknown and `TestResolveObligationsReportsTheHashAsUnknown` pins that, with a note to
delete the test once the check exists. Reporting a hash computed some plausible way
would be worse than reporting none: `CheckObligations` would then compare every
reference in every environment profile against a definition nobody ratified, and a
reference that verified against the wrong definition looks checked while a reference
that verified against nothing does not.

**Settled by a maintainer decision, not by a live org.** It is a schema question:
answering it adds "the hash covers X" language to
`schema/obligation-profile-v1.schema.json`, which is a published contract, so rule 6's
"ask first" applies. Worth answering before Phase 4's `assess`, which will want to
quote the same hash.

### Q16 — DESIGN §14's SCP naming convention is not what the packer emits

DESIGN §14: "SCP names: `automat-<artifact-id>-<class>` (e.g.
`automat-cmmc-l1-baseline-protection`), each SCP tagged with the artifact hash."
`internal/org/policy.go`'s `PolicySpec.Name` doc repeats it. `compilesets.Pack` emits
`fmt.Sprintf("%s-%d", opts.NamePrefix, i+1)`, and the golden files are
`automat-test-1.json` … — a caller-supplied prefix and an ordinal, with no artifact id
and no class.

Flagged rather than reconciled, per CLAUDE.md: "when design and code disagree, stop and
flag it — do not silently reinterpret the design." Which one is right is not obvious,
because §14's shape may not be expressible:

- **A packed policy has no single artifact id.** Union is the whole point — a vend
  compiling `cmmc-l1` + `baseline-protection` + a campus set produces statements from
  all three, and the packer bin-packs them by size rather than by origin. `<artifact-id>`
  presumes one artifact per policy; the merge presumes the opposite.
- **Nor a single class.** The packer emits control, region, service, and
  baseline-protection statement shapes and packs whatever fits, so a policy is
  `<class>` only if the packer is required to keep classes in separate policies —
  which spends slots out of a per-target budget of five, of which two are already
  reserved.
- **Organizations enforces name uniqueness**, which the ordinal handles and
  `automat-<artifact-id>-<class>` does not: two vends against the same OU with
  different profiles would collide on a name that names neither profile.

Three readings, and the first two are not the same change:

1. **§14 describes the intent and the packer's names are the implementation.** Then §14
   is stale prose and should say `automat-<environment-profile-id>-<n>` or similar —
   the profile id being the one id a packed policy actually has one of. Cheapest, and
   it loses the readability §14 was reaching for: an operator looking at five attached
   policies in the console learns nothing from an ordinal.
2. **§14 is the requirement and the packer must pack by class.** Names become
   meaningful, `verify` can find the policy it means to check by name rather than by
   tag, and the slot budget tightens: four classes into three available slots fails
   whenever more than three are non-empty, which a region+service+control+protection
   vend is.
3. **Names stay ordinal and the TAGS carry the meaning.** §14 already requires the
   artifact hash as a tag; extend that to artifact ids and class. `verify` reads tags,
   which it must anyway (a console-renamed policy is still the policy). §14's example
   name becomes an illustration rather than a contract.

**What the code assumes now:** reading 1 by default, since `NamePrefix` is
caller-supplied and no caller exists yet. `vend` is the first caller and has to pass
something, so this needs an answer at task #13 — but the answer is a one-line change
at the call site under any reading, which is why the packer was not held up for it.

**Relevant to `verify` (Phase 4)** more than to `vend`: whatever `vend` names a policy,
`verify` has to find it again, and finding it by name means the name is a contract.
