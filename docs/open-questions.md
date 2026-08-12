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

### ~~Q4 — No OSCAL catalog exists upstream for 800-171 Rev 2~~ — RESOLVED, steps 1-2 built, 3-5 deferred

**Resolved.** The premise was right but incomplete: `usnistgov/oscal-content` publishes an
OSCAL catalog for Rev 3 only, **but NIST's CPRT holds a complete legacy Rev 2 dataset**, so
no PDF extraction is needed. Verified during the Phase 0 review:

- Framework `SP_800_171`, version identifier `SP_800_171_2_0_0`, labeled "Revision 2",
  `frameworkVersionId` 10, status Production.
- `…/nudp/framework/version/SP_800_171_2_0_0/type/requirement/elements` returns HTTP 200
  and **exactly 110 requirements with full text and no empty entries**, across 14 families.
- `…/type/family/elements` returns the family titles (3.1 "ACCESS CONTROL" … 3.10
  "PHYSICAL PROTECTION").

**The endpoint path above 404s as written; the working path is different, and this is worth
flagging rather than silently reconciling.** The actual retrieval (2026-08-11) used
`csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/sp_800_171_2_0_0/export/json?element=all`
— note `nudp` not `nudppublic`, `services` not `service`, and one combined `export/json`
endpoint rather than separate `type/requirement/elements` and `type/family/elements` calls.
Confirmed by fetching the CURRENT `csrc.nist.gov/extensions/nudppublic/main.js` directly: it
contains only the `service/rest/json/nudp/framework/version/{id}/type/{type}/elements` path
shape this entry originally described, and every variation of that shape returns HTTP 404
from this environment (tried with and without a session cookie, with browser-like headers, and
via the `services.nvd.nist.gov` redirect target `main.js` names as `getContentServerName`'s
resolution target). The working URL was instead found by searching public code for prior
extractions of this exact framework version (`nealfennimore/cmmc`, a public GitHub repo doing
the same CPRT extraction independently) rather than by re-deriving it from `main.js` a second
time — so either the endpoint shape genuinely changed since this entry was first written, or
this entry's original discovery process recorded the wrong path from the start. Not resolved
which; noted here so a future re-derivation does not waste time re-trying the documented path.
The response's shape also differs from what this entry implied: one JSON document containing
`families`, `requirement_type`, `requirement`, and `discussion` elements together (236 elements
total: 14 families + 110 requirements + 110 discussions + 2 requirement types), not two
separately-fetched element-type lists.

The endpoint is undocumented, discovered via a third party's already-published reverse
engineering rather than via this project's own retracing of `main.js` this time. Undocumented
means unstable, which is fine here: the retrieved JSON is hashed into `artifact.sources` and
vendored, so the compile does not depend on the endpoint staying up. **Rev 2 is withdrawn and
will never change**, so the extraction is frozen once reviewed — a one-time acquisition, not a
refresh cycle.

**Plan for the `800-171r2` build.**

1. **Done (2026-08-11).** Retrieved the CPRT export in one call; response sha256
   `7e4bae9b7df6ea0724416057a2ea1b972c03475c9fef066e0cb0568a9436597a`, retrieved_at
   `2026-08-11T16:34:31Z`, recorded in `gen/sources/800-171r2.json`'s `source` block and
   carried into `catalogs/800-171r2.json`'s `artifact.sources` as a `catalog` entry.
2. **Done.** `gen/sources/800-171r2.json` is the reviewable intermediate — all 110
   requirements with family, number, and verbatim text, plus the 14 family titles — in the
   same shape as the curated FAR source: a committed file a human has read, not a live fetch.
   Compiled via a new `compileFrom171r2` target in `gen/catalog` into `catalogs/800-171r2.json`
   (golden-tested, deterministic, verified against `schema/control-artifact-v1.schema.json`
   unchanged).
3. **Not done, still deferred.** AWS mappings come from two API-retrievable sources, recorded
   as `mapping` entries: the **Security Hub NIST 800-171 Rev 2 standard** (control set + rule
   associations) and the **Audit Manager 800-171 Rev 2 framework** (control-to-evidence-source
   mappings). Both are richer and more current than a conformance pack, and both can be
   captured to a vendored file the same way.
4. **Done, vacuously.** With no mapping compiled (step 3 deferred), every one of the 110
   requirements is `procedural` with an attestation stub (ROADMAP Phase 0) — one stub per
   family (14), not per requirement, since nothing in this pass distinguishes a requirement's
   evidentiary shape from its family's siblings. The orphan check step 3 will need — a mapping
   AWS publishes that no requirement claims fails the compile — has no work to do until a
   mapping exists, so it is not yet exercised for this catalog.
5. **Not done, follows from 3.** Expect the r2 catalog to bind the same parameterized rules as
   `cmmc-l1` (`iam-password-policy`, `restricted-common-ports`,
   `vpc-sg-open-only-to-authorized-ports`). That is the first real exercise of the union orders
   resolved in Q1, and where the `blockedPort` re-slotting caveat will first matter.

Adjacent CPRT datasets found while checking, potentially useful later:
`SP-800-171-Rev-2-to-SP-800-171-Rev-3`, `NIST SP 800-171 r2 to CMMC L1`,
`NIST SP 800-171 r2 to CMMC L2`, `NIST SP 800-171 R2 to NIST SP 800-53 R5`, and
`SP_800_171A` (1.0.0 and 3.0.0). **`SP_800_171A` version 1.0.0 retrieved (2026-08-11).** Unlike
`800-171r2`'s own retrieval, the documented endpoint shape worked on the first attempt —
substituting `sp_800_171a_1_0_0` for the working `sp_800_171_2_0_0` reused the same URL shape with
no third-party reference-implementation lookup needed. 320 assessment-objective determination
statements across the same 110 requirements, vendored as `gen/sources/800-171a-objectives.json`
and compiled to `catalogs/objectives/800-171a-objectives.json` via a new, standalone
`schema/objectives-catalog-v1.schema.json` (DRAFT, not yet ratified — see that schema's own
`$comment_draft_status` and `schema/CHANGELOG.md`'s `objectives-catalog/v1` entry) and
`internal/assess.ObjectivesCatalog`. Cross-referenced against `catalogs/800-171r2.json`'s
requirement id set at compile time: exact equality, no orphan either direction. Version 3.0.0
(pairs with Rev 3) remains unretrieved and out of scope.

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

**First live sandbox run (2026-08-10): partial, and from the wrong side.** `DescribeResourcePolicy`
against this sandbox — which has never had a delegation policy created (no `setup` has run
against it) — returned `ResourcePolicyNotFoundException: No resource-based policy found`, not
`AccessDenied`. That is a readable, informative response about *absence*, called from the
**management account**. The actual question is about the **member account's** visibility into
a delegation policy that *does* exist, which this run cannot test: no member account exists in
this sandbox yet (nothing has been vended and kept — every vended account this run went
straight to `reclaim`), and no delegation policy has ever been created here. Needs a follow-up
run: create a delegation policy, vend a member account, and call `DescribeResourcePolicy` from
inside it.

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

### Q7 — Does `MoveAccount` reliably succeed immediately after `CreateAccount`? — **ANSWERED**

DESIGN §5 documents the cosmetic race and requires treating create-without-move as an error
state with a `parked` outcome. The retry policy that is actually needed — how long, how many
attempts — is an empirical question.

**First live sandbox run (2026-08-10, `internal/smoke`, two vends):** `DescribeCreateAccountStatus`
polling reached `SUCCEEDED` after ~10.4s both times (10.40s, 10.41s) at 5s poll intervals — i.e.
the very first or second poll after issuing `CreateAccount`. Once `SUCCEEDED`, `MoveAccount`
itself completed in ~0.35s both times, with no delay or retry needed — the cosmetic race DESIGN
§5 warns about did not manifest in either run. A ~15s total budget (poll `CreateAccount` to
completion, then move once) comfortably covers both observations; this is not enough runs to
rule out a slow tail, but gives no evidence one exists.

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

**First live sandbox run (2026-08-10): still open.** `internal/smoke`'s `Q8_ResourceTagHonored`
moved a deliberately untagged account and it succeeded (not denied) — but this is expected and
uninformative under this run's *native* management-account credentials, which carry no
resource-tag restriction at all. The real test — the same move attempted under the *brokered
vendor role*, which does carry the condition — needs the onboarding bundle deployed into a
member account first, which this run did not do (no bundle has been deployed into any sandbox
account yet). Still the one entry on this list whose bad case is silent; still needs that
follow-up run before it can be closed.

**Disclosed gap (AUDIT-7 M3): the tag-*write* audit `docs/smoke.md` requires was not run
either.** That page's own standing rule (carried from the Phase 1 review) requires testing,
in the same run, that the delegate cannot apply `automat:vended-by` to an account or policy
outside its namespace — "a condition that binds correctly while the principal can write the
tag it reads is not a control." No `TagResource` call was attempted by either live run.
Building that check for real needs the same prerequisite as the read-side re-test above: the
onboarding bundle deployed into a sandbox member account, so the write attempt can be made
under the brokered vendor role rather than this suite's unrestricted native credentials.

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

**First live sandbox run (2026-08-10): still open, same reason as Q8.** `internal/smoke`'s
`Q9_MoveAccountSourceParent` moved a freshly created account from the root into the delegated
OU and it succeeded immediately (~0.35s, no denial) — but this run's credentials are the
management account's own native admin session, which has no IAM resource restriction at all
and was never going to be denied regardless of what the *vendor role's* three-entry resource
list would do in the same position. This is exactly the case `docs/smoke.md`'s own text warns
about: the question is about the **restricted vendor role's** authorization, not automat's own
management-account access, and answering it for real needs the onboarding bundle deployed and
the move attempted through the brokered vendor role — not done in this run. Confirmed instead:
`CreateAccount` really does land a new account at the organization root (source parent was the
root ARN both times), which is the premise the whole question rests on.

### Q12 — Does `MoveAccount` into the account's *current* parent succeed or return `DuplicateAccountException`? — **ANSWERED**

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

**First live sandbox run (2026-08-10), both vends: `DuplicateAccountException`, not a silent
success.** Exact message both times: `"That account is already present at the specified
destination."` This confirms the reading `internal/org/account.go`'s `isCode(err,
"DuplicateAccountException")` branch already assumes and treats as success — the code's
tolerance for this exception, combined with reading the parent first via `ListParents` before
attempting the move at all, is the right (and now confirmed necessary) pair. Native
credentials were sufficient to answer this one fully; unlike Q8/Q9 there is no restricted-role
angle this result depends on.

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

**First live sandbox run (2026-08-10): not reached.** `internal/smoke`'s `Q13_BaselineRolesProtected`
called `GetRole("automat-automation")` and got `NoSuchEntity` — expected and uninformative:
`internal/baseline` does not exist yet, so no vend path has ever created that role anywhere,
including in this sandbox, and the call ran against the management account rather than a
child. This question cannot be answered empirically until `internal/baseline` exists to create
the role in a member account and the smoke suite can assume into that child to attempt
`PutRolePolicy` against it post-attach. Still fully open.

### Q24 — Does `reclaim`'s detach-then-close sequence behave against a real organization the way `docs/reclaim-design.md` assumes?

`internal/org.Reclaimer` and `cmd/automat/reclaim.go` (Phase 5) are built and tested against
`awsfake.OrgReclaim`, whose `CloseAccount` is a synchronous state flip
(`ACTIVE`→`SUSPENDED`) and whose `DetachPolicy` has no propagation delay. Real
`organizations:CloseAccount` is explicitly asynchronous (the SDK's own doc comment: a
successful response can return while the account is still `PENDING_CLOSURE`), and nothing
verifies against a live org:

- Whether `DetachPolicy` on an SCP just attached, or about to be relied on by
  `baseline-protection`, has the same "no documented propagation delay" risk Q13 already
  flags for attach — the same worry in the opposite direction, for a call `reclaim` makes
  rather than `vend`.
- Whether the closure rate-limit rejection (`ConstraintViolationException` with reason
  `CLOSE_ACCOUNT_QUOTA_EXCEEDED` or `CLOSE_ACCOUNT_REQUESTS_LIMIT_EXCEEDED`) is actually the
  shape AWS returns today — the reason codes are read from the SDK's own generated types,
  never observed against a real rejection, so the remediation text `Reclaimer.CloseAccount`
  prints is unverified prose about an error nobody has seen fire.
- What `DescribeAccount` reports for an account mid-`PENDING_CLOSURE` if `reclaim` (or any
  other command) reads it in that window — no code path handles that status today because
  no live account has ever been in it.

**What the code assumes now:** `CloseAccount`'s response can be trusted as a request
accepted, full stop — `Reclaimer.CloseAccount` reports `Applied: true` on any `nil` error,
with no poll loop the way `vend`'s account-creation step has one for
`DescribeCreateAccountStatus`. If closure needs the same asynchronous-completion handling
account creation does, that is undiscovered work, not a decided design.

**Phase 5 smoke runbook:** vend a throwaway account in the sandbox org, `reclaim --yes` it,
and record: how long `DescribeAccount` took to report `SUSPENDED`, whether `DetachPolicy`
succeeded immediately after the SCP's own attach (a fresh attach followed by an immediate
detach in the same run), and — only if the sandbox org's history permits reaching it
without risking a real account — the exact shape of a closure-quota rejection.

**First live sandbox run (2026-08-10): partially answered, and revealed a gap in `reclaim`
itself.**

- `DetachOwnedPolicies` (detaching the tag-owned SCP from the account's OU) completed in
  ~0.35s both runs, immediately, no propagation delay observed — the SCP had been attached to
  the OU (not the account) well before either close attempt, so this does not test an
  immediate attach-then-detach sequence; it tests detach against a policy that has been in
  place for a while, which is the more common case anyway.
- `CloseAccount` itself returned in ~0.2s both times, `nil` error — a request accepted, exactly
  what `Reclaimer.CloseAccount`'s current "trust a nil error as Applied: true" assumption
  expects.
- **`DescribeAccount` did NOT report `SUSPENDED` within 10 minutes for either account.** Run 1:
  killed by `go test`'s own binary-wide timeout before the poll finished (a harness bug, since
  fixed — see below). Run 2, with that fixed: the account was still `ACTIVE` at the 10-minute
  mark and only reported `SUSPENDED` sometime shortly after (confirmed by a manual
  `describe-account` a few minutes later). **This means real `CloseAccount` completion — full
  propagation to `DescribeAccount`, not just request acceptance — can take longer than 10
  minutes.** `Reclaimer.CloseAccount`'s assumption that a `nil` error means done is validated
  for "request accepted"; it is not validated, and is now known to be wrong, for "the account
  is actually closed" if any caller relies on `DescribeAccount` reporting `SUSPENDED` promptly
  afterward (nothing in `cmd/automat/reclaim.go` currently polls for it, so this has not yet
  caused a user-visible bug — but it is a real gap between what closure "returning" means and
  what an operator watching the account would see).
- Closure-quota rejection: not reached — only two accounts were ever closed in this org's
  history, far under any rate limit.
- Separately, this run's own harness (not `reclaim` itself) had a real bug: its `t.Cleanup`
  reclaim path called `ListPoliciesForTarget` without the required `Filter` field and failed
  outright, and `go test`'s default 10-minute *whole-binary* timeout killed the process mid-poll
  on the first attempt before `t.Cleanup` could even run — both fixed
  (`internal/smoke/harness.go`, `Makefile`'s `-timeout=30m`), and both required a hand-run
  `automat reclaim --yes` afterward to close the accounts these bugs left `ACTIVE`. Neither
  bug is evidence about production `reclaim` itself, only about the smoke harness's own
  fidelity to it.

---

## Decided by the maintainer

Not live-org questions and not code questions: questions about source data whose authority
matters more than its availability, plus the places where the design and the schema
disagree and only the maintainer can say which is right. `docs/smoke.md` does not cover
these, because no sandbox run answers them. Kept here rather than deleted once decided —
the reasoning is the part that has to survive, since the decision looks like unnecessary
ceremony to anyone who has not read why.

### Q10 — Where do the DFARS per-requirement assessment weights come from, authoritatively? — **DECIDED AND DONE (2026-08-12)**

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

**Status: done.** The dual-pass transcription was carried out 2026-08-12 against the DoD's
own *NIST SP 800-171 DoD Assessment Methodology, Version 1.2.1 (June 24, 2020)*
(`www.acq.osd.mil`), with the two passes produced in genuinely independent order — the
second pass was fully constructed from the source before the first pass was ever opened,
not checked against it line by line, which is the distinction that makes agreement between
them real evidence rather than a proofreading pass over one document. **Result: zero
disagreements across all 110 requirements.** The currency of the source was separately
confirmed the same day: the current DFARS 252.204-7019/7020 clauses (`acquisition.gov`)
still name this exact Version 1.2.1 document and URL as the operative methodology; DoD's
Rev 3 preparation work is not a superseding edition of this scoring methodology.

Vendored at `gen/sources/dfars-800-171r2-weights.json`, hashed, and named by that hash in
`catalogs/obligations/dfars-7012.json`'s `scoring.weight_table` (no longer the all-zero
placeholder). `TestWeightTableHashMatchesTheFileOnDisk`
(`internal/artifact/obligation_profile_test.go`) keeps the profile's cited hash from
drifting from the vendored file's real bytes, the same discipline
`TestProfileSourceHashesMatchTheFilesOnDisk` already applies to `p.Sources` — that older
test does not cover `scoring.weight_table` (a bare identifier, not a `gen/`-prefixed path),
which is why this is a new, sibling test rather than an extension of the old one.

**Three requirements have no single scalar weight in the source itself: see Q25, below.**
This is not a transcription gap — both independent passes reproduced the same three
non-scalar entries, because the DoD document itself assigns them a conditional or
non-numeric value. No Stage 2 scoring code exists yet to decide how to model them.

Note that **CMMC Level 1 needs none of this**: L1 is MET/NOT MET with no scoring, so Q10
never gated the L1 path.

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

### Q15 — `obligation-profile/v1` does not say what its content hash covers. DECIDED (scope only)

**Resolved by the maintainer: option 2, the canonicalized whole document minus
`schema_version` and `signatures`** — see `schema/CHANGELOG.md`'s obligation-profile/v1
entry for the field list and the reasoning, matching `classification-profile/v1`'s
precedent for the same choice. Stated as a schema `$comment` rather than implemented,
because ROADMAP's Phase 4 stage 0 keeps this document type "data and schema only, no Go
types" until `assess` is written — the comment defines the contract a future
canonicalizer must satisfy, and `TestObligationProfileHashScopeCommentNamesEveryField‑
ExactlyOnce` pins it against the schema's own field list so the two cannot silently
drift apart before the code exists to compare against.

**What is still open, and what this decision does not change.** `internal/catalog.‑
ObligationFacts.ContentSHA256` remains empty, and `envprofile.CheckObligations`
continues to report the comparison as unknown — this decides *what* the hash will
cover, not when it starts being computed. That is Phase 4's work, when `assess` needs
the same hash and a canonicalizer is written at last.

The reasoning below is kept as the record of what the three candidate answers were and
why option 2 was chosen over the other two.

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

### Q16 — DESIGN §14's SCP naming convention is not what the packer emits. DECIDED

**Resolved by the maintainer: reading 1 — §14 amended to match what ships.** DESIGN §14 now
states the ordinal naming (`automat-<environment-profile-id>-<n>`) as the convention, with
the reasoning kept alongside it. Artifact-hash tagging (reading 3) remains genuinely absent
— `internal/org` has no artifact-hash tagging on any SCP today — and stays a real gap rather
than a decided one; it is not blocked on this decision and can be added independently
whenever `internal/org` gains tagging for the account-tag work `docs/cli-surface.md` D3
already names. The reasoning below is kept as the record of why the other two readings were
not chosen.

DESIGN §14 previously read: "SCP names: `automat-<artifact-id>-<class>` (e.g.
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

**Task #13 has now made the call-site choice, which narrows the question without
answering it.** `vend` passes `NamePrefix: "automat-" + p.Meta.ID`, so a packed policy is
`automat-<environment-profile-id>-<n>` — reading 1, chosen because it is the only reading
`vend` could implement without the packer changing, and because the profile id is the one
id a packed policy has exactly one of. Two consequences worth recording before AUDIT-2
re-opens this:

- **Reading 2 is now more expensive than it looks.** `vend` orders the packed set with the
  baseline-protection-carrying policies last (Q13), which is an ordering over policies the
  packer produced. Packing by class would make that ordering structural rather than a sort,
  and the slot arithmetic in reading 2 above becomes a refusal `vend` has to render.
- **Reading 3 is untouched and still cheap.** `vend` writes no tags onto the policies it
  creates — see the account-tag gap in `docs/cli-surface.md` D3, which is the same missing
  capability in `internal/org`. Whoever implements tagging can satisfy reading 3 in the same
  pass, and reading 1's ordinal names stay as they are.

### Q17 — `evidence-manifest/v1`'s `artifact` admits one document, but a vend compiles a union

`Record.artifact` is a single `DocRef` (id + sha256). A vend resolves *several* control
sets — at minimum a control artifact plus `baseline-protection`, and the union is the
design's whole premise (DESIGN §9) — so there is no one artifact a vend's records are
"the" artifact of.

**What the code assumes now:** `cmd/automat/vend.go`'s `artifactRef` fills the field only
when the union is unambiguous, meaning exactly one non-baseline artifact, and leaves it
absent otherwise. Absent is honest and checkable; naming one member of a union as though
it were the artifact would not be. But it means the field is present on simple vends and
missing on exactly the composed ones an auditor is most likely to be reading, which is a
poor property for an evidence field.

Three answers, and the first is what the shape of the data suggests:

1. **A repeated block.** `artifacts[]` of `DocRef`, one per resolved set, which is what a
   vend actually has. Restructures a published contract, so rule 6's "ask first" applies,
   and it is a versioning event if any manifest exists in the wild.
2. **A compiled-set hash.** One `DocRef` whose id names the merged set and whose hash is
   over the canonicalized merge. Keeps the shape, and is arguably the *more* useful claim —
   "vended under this exact compiled union" rather than a list of inputs. Needs a
   definition of the merged canonical form, which `internal/compilesets` does not expose,
   and inherits Q15's question of which bytes.
3. **Leave it, and let the environment-profile record carry the provenance.** The
   environment profile names its control sets and is already hashed in its own record, so
   the inputs are recoverable one hop away. Cheapest, and it concedes that `artifact` is a
   field the manifest does not really have.

**Settled by a maintainer decision, not a live org**, and the same shape of question as
Q15 — both are "what does this hash cover", and answering them together is likely cheaper
than answering either alone. Wanted before Phase 4's `verify`, which has to decide what it
is verifying an account *against*.

**Still open after `verify` shipped, because `verify` worked around it rather than
needing an answer.** `cmd/automat/verify.go` takes the same environment profile path
`vend` did — reload it, recompile via `compilesets.Pack` — and compares the fresh
compile against what is attached, rather than reading a prior evidence record's
`artifact` field to learn what to check against. Its own written `OpVerify` record
leaves `Artifact` unset entirely — it names the environment profile checked
(`EnvProfile`, which is unambiguous) but not any of the resolved control sets, which
is a narrower answer than `vend`'s "fill it when the union is unambiguous" and avoids
the question rather than answering it. It stays open for a reader of an existing
manifest who wants to know what a past record's `artifact` field means for a union.

### Q18 — `classification-profile/v1` has no way to record a citation it could not retrieve. DECIDED

**Resolved by the maintainer: option 1, a fourth `date_basis` value.** `not-retrieved` is
implemented — see `schema/CHANGELOG.md`, "Pre-publication change to
classification-profile/v1: `date_basis: not-retrieved`" — and `catalogs/classification/
uc-protection-levels.json`'s BFB-IS-3 citation now carries it, with `source_id` removed and
its `interpreted-by` attestation re-signed over the new content hash. The reasoning below is
kept as the record of why, and why the other two options were not chosen.

`citation.date_basis` had three values, and all three describe a document that WAS
retrieved: `published-effective-date` and `last-updated-in-document` name where in the
bytes the date was read from, and `retrieved-only` means "retrieved, and it bears no date
at all." There is no value for *never retrieved*.

The UC profile has such a citation. `BFB-IS-3` is the parent policy the Classification
Standard says drives it, retrieval was attempted and failed with a TLS error, and the
profile records it because a reader needs to know it exists and that this profile has not
read it. Its note says NOT RETRIEVED in the first two words. But the machine-readable
fields say something else:

- `date_basis: retrieved-only` — which, per its own schema description, asserts the
  document was retrieved and found dateless.
- `source_id: uc-classification-standard` — the Classification Standard, i.e. a
  DIFFERENT document. The schema defines `source_id` as "the `sources[]` entry holding the
  retrieved bytes of this citation," and those bytes are not IS-3's.

The validator requires a `source_id` when the basis is `retrieved-only`, precisely because
that basis means the retrieval record is the only dating available — so the profile was
pushed into naming *some* source, and the only hashed source it has is the other document.
Reasonable under the shapes available, and wrong in the field a tool reads. A future
consumer filtering on `date_basis` gets IS-3 in the retrieved set, and one resolving
`source_id` gets a hash that verifies against a document IS-3 is not.

**Why this is not fixed in the audit that found it (AUDIT-2 F5).** Every repair needs
either a new enum value or a relaxed `source_id` rule, and rule 6 reserves both: a fourth
`date_basis` value loosens a published enum, and dropping the `source_id` requirement
loosens a validator constraint that exists for a good reason. Three candidate answers:

1. **A fourth `date_basis`: `not-retrieved`.** Forbids `effective_date` like
   `retrieved-only` does, and forbids `source_id` rather than requiring it — the absence
   then MEANS unretrieved, checkably, instead of being inferable only from prose. Most
   honest, and it makes the state a first-class one a renderer can mark, the way
   `envprofile.ObligationFacts.UnresolvedSources` now marks the obligation profiles'
   zero-hash placeholders (F1). Costs a schema version bump and a migration note.
2. **A separate `unretrieved_references[]` block.** Keeps `citations[]` meaning "documents
   this profile read" with no exceptions, and puts the acknowledged-but-unread elsewhere.
   Cleaner conceptually; more schema surface, and it splits one reader-facing list in two.
3. **Drop the citation.** Cheapest and the worst of the three: the reader loses the fact
   that IS-3 governs the scheme, which is true and load-bearing whether or not automat
   fetched it. A profile that omits its own parent policy reads as complete.

**Settled by a maintainer decision.** Wanted before a second derived profile ships, since
whatever shape is chosen will be copied by every profile after it, and unretrieved parent
policy is the normal case rather than the exception — institutional policy pages routinely
reference PDFs behind broken links.

Until then the state is disclosed in the profile's own citation note, which is where a
human reads it, and this question is the record that a machine still cannot.

### Q19 — the vendor-role bundle cannot read `automat:vended-by`, so `vend` cannot prove an account is its own

`vend` adopts an existing account when one already holds the root email the environment
profile resolves to, rather than creating a second one. It has to: an address belongs to
exactly one AWS account anywhere in AWS (DESIGN §3, fact 11), so a re-run of an
interrupted vend finds the account it made, and CLAUDE.md rule 4 makes that re-run safe.

Email uniqueness makes the address identify **one** account. It does not make that account
automat's. AUDIT-2 found that any account in the search containers holding that address was
adopted: the profile's service control policies attached to it, a birth certificate written
for it, and — sitting under the organization root, which is both where a fresh account
lands and where an account nobody has organized most plausibly sits — a `MoveAccount` into
the destination OU. An account has exactly one parent, so that move takes it out from under
every policy attached where it was. This is the same harm `--resume` was hardened against
earlier in the same audit, reached without typing anything: the attacker supplies no id,
only an email pattern that happens to collide.

**`automat:vended-by` is the tag that would settle it, and it exists for this.** It is
applied at `CreateAccount` through `aws:RequestTag` precisely so a vended account is
distinguishable from every other account in the organization. automat cannot read it:

- `awsapi.OrgVendAPI` has no `ListTagsForResource` (the reason is recorded in
  `internal/org/doc.go` — an account tag *ensure* that cannot read would be a blind write
  dressed as a comparison, so the interface omits the read as well as the write);
- `DescribeAccount`, which the role *does* grant, does not return tags;
- so the check needs `organizations:ListTagsForResource` on account resources in the
  published `vendor-role.cfn.yaml` and `vendor-role.tf`, which they do not contain.

**Why the audit did not just add it.** Widening the bundle changes what an institution's
central IT approved, and the bundle's whole argument is that a reviewer can read it and
enumerate the blast radius (`TestREADMEMakesTheBlastRadiusArgument`). A new read action is
small but it is not automat's to grant itself, and every deployed bundle would need
redeploying before the check could be relied on — a check that silently degrades to nothing
on an older bundle is worse than a documented gap. Three shapes:

1. **Add `organizations:ListTagsForResource` for account resources to the bundle**, and
   refuse to adopt an account not carrying `automat:vended-by` = the vending account. The
   authoritative answer. Costs a bundle version, a redeploy, and a decision about what to
   do on the older bundles: refuse to adopt at all (safe, breaks rule 4 for anyone who has
   not redeployed) or fall back to the corroboration below (safe by default, and the
   fallback is then the thing that ships forever).
2. **Adopt only accounts automat's own evidence manifests record it as having vended.**
   Needs no new grant, and it is a weaker guarantee than it sounds: the manifest is local
   state, an operator vending from a second workstation legitimately has none, and rule 4's
   re-run would then create a second account.
3. **Require an explicit `--adopt <account-id>` for any adoption at all.** Strongest and
   loudest, and it makes the ordinary interrupted re-run interactive, which is the case
   rule 4 exists to keep boring.

**Settled by a maintainer decision**, because (1) alters the published bundle and (3)
alters the CLI surface — both reserved by CLAUDE.md's "ask before".

**What ships in the meantime.** `findAccountByEmail` requires the account NAME to match
the name the vend was asked for, and refuses to adopt otherwise. It is strictly tighter
than what it replaced and free — `ListAccountsForParent` already returns the name — and it
is a corroboration, not a proof: an account coinciding on both the address and the name is
still adopted. `TestVendWillNotAdoptAnAccountItWasNotAskedToVend` asserts both halves,
including the still-adopted case, so the check cannot be read as the guarantee this
question is about.

### Q20 — what does real IAM do with a control character in an ARN inside an attached SCP?

AUDIT-2's accepted finding L4. An adversarial pass constructed a resource ARN carrying a
`\u0001` byte and asked what happens when a policy containing it is *attached* to an OU.
Three outcomes are all plausible and they differ in the direction that matters:

1. `AttachPolicy` refuses the document, and the vend fails loudly at a point where the plan
   has already printed. Fine.
2. The document attaches and the byte is preserved literally, so the statement matches
   nothing and a guard silently does not apply — a Deny that never fires reads in the console
   exactly like one that does.
3. The document attaches and something normalizes or strips the byte, so the statement
   matches something **other** than what the catalog wrote.

Only (1) is safe, (2) and (3) are both silent, and no fake can tell them apart: `awsfake`
answers whatever it was written to answer, which would be my guess about IAM rather than IAM.
CLAUDE.md rule 1 forbids finding out in CI, and a live answer needs an org where attaching a
deliberately malformed policy is acceptable — the sandbox `make smoke` names.

**Not currently reachable through automat.** Rule 8's character-class patterns refuse the
value at both the JSON Schema and the Go validator, so no automat-authored path produces such
an ARN. What is unverified is what would happen if one arrived another way: a hand-edited
catalog loaded with `SkipValidate`, or a future artifact field that grows a resource list
without inheriting the pattern.

**Why it is not fixed rather than asked.** The only available fix is to guess IAM's behavior
and code to the guess, and a guess wearing a defense's clothing is worse than the open
question — it would be indistinguishable from a verified control to the next reader. So this
follows CLAUDE.md's working-style rule: note the uncertainty, keep the validator, keep going.

**A second, related item parked here rather than in its own question.** Nothing shipped today
can point `internal/catalog.Options.FS` at an attacker-controlled tree — every caller passes
the embedded FS. If **vendored-only is load-bearing** rather than incidental, it should be
written down as a control with a test, not left as a property of the current call sites. A
field whose safety depends on who happens to call it is one refactor from not being safe.

**2026-08-10 — the "not currently reachable" claim above was wrong for `action`/`resource`.**
AUDIT-2 L4 accepted the assumption that rule 8's character-class pattern was applied to every
round-trip field, `scp_statement.action`/`.resource` among them, on the strength of
`ExemptPrincipal.Reason` carrying `reNoControlBytes` at both layers. A closer look found that
`checkStatementList` in `internal/artifact/validate.go` — the function backing both fields —
only ever enforced `minLength:1` and `uniqueItems`; it never applied `reNoControlBytes` or any
other pattern. The published schema matched it exactly: `scp_statement.action.items` and
`.resource.items` carried `"minLength": 1` and nothing else. So a resource or action ARN
carrying a literal `\x01` byte passed `artifact.Validate()` with zero bypass needed — not
through `SkipValidate`, not through a hand-edited catalog, through the ordinary path. Fixed by
adding the `reNoControlBytes` check to `checkStatementList` (mirroring the `Reason` check's
wording, adapted to say "action"/"resource") and adding
`"pattern": "^[^\\x00-\\x1f\\x7f]+$"` to both schema items, alongside their existing
`minLength: 1`. This is a strictly-tightening schema change under CLAUDE.md rule 6: no
document that previously failed validation now passes, and every document that now fails
contains a control character in `action` or `resource` that the schema and validator had
missed. The live-AWS behavioral half of this question — what `AttachPolicy` actually does with
such a byte if one reaches it another way — is unaffected and remains open: automat's own
validation now refuses the value on the ordinary path, but what happens via `SkipValidate` or a
future field that doesn't inherit the pattern is still unverified, per the "not currently
reachable" paragraph above, which is now accurate again rather than merely assumed.

**2026-08-11 — a smoke subtest now exists to answer this empirically.**
`internal/smoke.q20ControlCharacterInResourceARN` (`Q20_ControlCharacterInResourceARN` in
`TestSmokeChecklist`, see `docs/smoke.md`) constructs the deliberately malformed statement
directly as `compilesets` input — bypassing `artifact.Validate` on purpose, the same bypass this
question is about — packs it, and calls `CreatePolicy`/`AttachPolicy`/`DescribePolicy` against a
real sandbox, recording which of the three outcomes above occurred as a `Finding`. Writing this
test does **not** answer Q20: nothing in this tree has ever run it against real AWS, and per
CLAUDE.md rule 1 nothing will until an operator runs `make smoke` against a sandbox org with
`AUTOMAT_SMOKE_SCRATCH_OU` set. This paragraph should be replaced with the observed outcome after
that first run, not left standing beside it.

### Q21 — `manifest.genesis_sha256` does not defend against a rewrite that edits the header too

Added at H3's resolution (see `schema/CHANGELOG.md`, "Pre-publication change to
evidence-manifest/v1: `manifest.genesis_sha256`"). The field catches head truncation when
the header is left unedited — the ordinary case, since dropping `records[0]` and
recomputing the anchor to match takes one extra step an editor motivated to remove
evidence has every reason to take once they know the field exists.

**Why this is not fixed rather than disclosed.** Closing it needs the header itself to be
checkable — a manifest-level attestation over canonicalized `Meta`, comparable to a
second copy, or a signature that covers the header the way `record_sha256` covers a
record. Every shape considered collides with the same constraint H4 already ran into:
covering `Meta` inside a hash that also gates the chain's validity would make correcting
a typo in `created_at` an event that invalidates evidence, which is a worse failure mode
than the one being closed. And it collides with a decision already made: automat ships no
trust anchor and cosigning is optional, so a scheme that only works when every manifest
carries a header signature is a scheme most manifests will not have.

**What already narrows this.** DESIGN §11's external anchor — the vended account's own S3
copy, a management-side mirror — remains the compensating control: two copies of the
header that disagree are noticeable to whoever holds both, even though neither one is
internally invalid on its own. `TestPrefixTruncationIsRefused`'s fourth part
(`internal/evidence/header_binding_test.go`) demonstrates the residual directly rather
than describing it, so the claim stays checkable rather than asserted.

**Not blocking anything today.** No shipped command relies on `genesis_sha256` alone to
detect tampering; `vend`'s birth certificate and the external mirror are the load-bearing
pieces DESIGN §11 already names. Recorded so the next audit does not re-discover the
residual and re-file it as though the anchor were meant to close the whole finding.

**Update: the birth certificate now actually prints the anchor.** Until this fix,
`renderBirthCertificate` (`cmd/automat/vend.go`) never printed `Meta.GenesisSHA` — the
compensating control this entry and `internal/evidence/validate.go`'s own comments
claimed existed was aspirational for any unsigned manifest, since the birth certificate
is the only second copy of the header an operator without an external mirror ever sees.
`writeVendEvidence` now returns the genesis anchor alongside the manifest path, and
`renderBirthCertificate` prints it as a `genesis anchor` line. This narrows the residual
for the unsigned case — the operator's terminal transcript is now a real second copy of
`genesis_sha256` to diff against a manifest handed back later — but does not close it:
an editor who rewrites both the header and the birth certificate's saved transcript
together is still internally consistent, for the same reason DESIGN §11's external
mirror only narrows rather than closes. The signed-manifest case needed no such fix and
was already fully closed before this change, per `TestPrefixTruncationIsRefused`'s third
part (`internal/evidence/header_binding_test.go`): a signed chain, prefix-truncated with
its header rewritten to match, is still refused — the link-and-signature check catches
it independently of the anchor.

**Update: the read-and-diff half of the external mirror now exists (ROADMAP.md's "Remote
evidence mirror" slice 2), and closes this residual FOR ACCOUNTS WITH A MIRROR
CONFIGURED.** Everything above described the compensating control as something a human
holding two copies had to notice by hand — "two copies of the header that disagree are
noticeable to whoever holds both" was true but did nothing automated. `verify` now fetches
the mirrored copy (`evidence.MirrorReader.Fetch`, `S3Mirror`'s second interface,
`internal/awsapi.S3MirrorAPI`'s already-present `GetObject`) and compares it against the
local manifest — `Meta` in full, `GenesisSHA` specifically named — via
`evidence.MirrorDrift`, before this run's own record is appended (so the comparison is
against the mirror's state as of the START of this run, not a copy this same run already
overwrote). A rewrite that truncates records and recomputes `genesis_sha256` to match is
internally consistent, exactly as described above — but it is no longer internally
consistent WITH THE MIRROR unless the same rewrite was also applied there, and an editor
who can rewrite the local file typically cannot also rewrite an S3 object in a bucket they
were never granted `s3:PutObject` on twice, once for each copy, without the second write
being independently detectable. `TestVerifyReportsDriftWhenMirrorBytesDiffer`
(`cmd/automat/verify_mirror_test.go`) and `TestMirrorDriftDisagreement`
(`internal/evidence/mirrordrift_test.go`) demonstrate the closure directly.

This closes the residual only when a mirror is configured — `baseline.evidence.in_account_bucket`
or `management_mirror_bucket`, still optional per DESIGN §11 and envprofile's schema — so
the entry stays open, now narrowed: **for an account with no mirror bucket named in its
environment profile, the residual described above is unchanged and this entry remains the
correct description of it.** `verify` reports this state explicitly too — a
"could not verify" mirror-drift finding when a mirror is configured but unreachable is
kept distinct from both "no mirror configured" (the section is omitted entirely) and
"checked, clean", so an operator reading a report can always tell which of the three
states applies, rather than three states quietly collapsing into "no news".

### Q22 — May an override widen a Config-rule parameter past what every input artifact permitted?

Raised at AUDIT-4's L1. `internal/compilesets.Overrides.apply` returns an override's value
verbatim, with no comparison against the conflicting values it is resolving — an override
naming `ami-1,ami-2,ami-3,ami-4,ami-EVERYTHING` for a `set-intersect` conflict between
`ami-1,ami-2` and `ami-3,ami-4` returns exactly that, a member neither input permitted.
DESIGN §9's governing law is monotonicity: the resolved value must never permit behavior
either input forbade. `artifact.RuleParameter.Permits` exists precisely so that law is a
checkable predicate, and the override path bypasses it entirely.

**What the code assumes now:** the override is trusted absolutely, on the reasoning
`Override`'s own doc comment states — DESIGN §9 asks for "the value you intend", and an
operator resolving a genuine three-way conflict may need a value none of the three inputs
holds; clamping to the meet of the conflicting values would forbid exactly the case that
reasoning was written for.

**Why this is not decided yet.** It is a real design question with two defensible
answers — trust the override completely (current behavior) or clamp it to what
monotonicity would allow — and AUDIT-4 surfaced it under the ritual's own rule not to
decide a design question mid-audit.

**Why it is inert today and will not stay that way.** Nothing deployed reads the merged
Config-rule map: `cmd/automat/vend.go`'s `configRuleNames` walks raw per-control
`ConfigRules`, not the union, and no conformance pack is deployed because
`internal/baseline` does not exist. An override's widened value reaches a disclosure
sentence and nothing else. **The first change that deploys a conformance pack turns an
unbounded operator-supplied value into a parameter of a live detective control** — decide
this question as part of that work, not after it ships.

**Decision (confirmed correct): trust-the-override stays.** Re-examined and settled —
clamping the override to `artifact.RuleParameter.Permits` is mechanically incapable of
resolving either conflict shape that reaches this code path (an `exact` mismatch, or a
disjoint `set-intersect`, `ami-1,ami-2` against `ami-3,ami-4`): the meet of what every
input permits is provably empty in both cases, so clamping would convert "resolve a real
conflict" into "always refuse," which defeats the mechanism `Override`'s own doc comment
was written for. No behavior change was made.

**What was added instead: a disclosure, not a gate.** `internal/compilesets` now computes,
at the two points where `Overrides.apply` resolves a real conflict
(`addOneConfigRule`/`combineConfigRules` in `configrules.go`), whether the override's
resolved value is permitted by *either* conflicting side (`current.Permits`/
`incoming.Permits`, `order.go`). For a scalar order (`exact`/`min`/`max`), permitted-by-
neither is reported as a widening; a non-numeric override under `min`/`max` (`Permits`'
`meaningful=false`) is reported as its own, distinct case, since nothing was actually
compared. For a set order (`set-union`/`set-intersect`), each member of the resolved value
is checked independently and only the members permitted by neither side are named — so the
worked example above now warns about `ami-EVERYTHING` specifically, not the whole
five-member value. A second, narrower gap in the same code path was closed alongside it: an
override naming a `(rule, parameter)` with no actual conflict at that spot used to be a
silent no-op with no trace in the compile output; it now warns that the entry was never
applied. Both surface through a new `Merged.Warnings []string` field, following
`Narrowed.Warnings`'s existing shape, carried forward by `Narrow` into `Narrowed.Warnings`
so `cmd/automat/vend.go`'s existing `renderVendWarnings` prints them with no changes to that
function. This is a Go-only addition: no schema changed, and warnings are ephemeral
compile-time text, not a field of any persisted document.

**This remains genuinely inert in production until a conformance pack is deployed.**
Confirmed again with the disclosure landed: `configRuleNames` in `cmd/automat/vend.go`
still walks each control's raw `ConfigRules`, never the union `Merge`/`Narrow` produce, and
no code path attaches `Merged.ConfigRules` to a live AWS Config conformance pack —
`internal/baseline` does not exist yet. The new warning is visible in a compile plan today
if an operator writes an overrides file that widens past both inputs, but nothing an
operator sees today changes as a result of this fix; it is groundwork for when
`internal/baseline` starts deploying conformance packs and an override's value becomes a
parameter of a live detective control, at which point this warning is the operator's only
present-day signal that it might be worth a second look before that day arrives.

### Q23 — `verify`'s evidence manifest has no rotation, and an hourly cron reaches the size ceiling in about a year — **DECIDED AND DONE (2026-08-12)**

Raised at AUDIT-4's M3. `writeVerifyEvidence` appends a record on every run, success or
drift, with no pruning — the same unconditional-append shape `vend` uses, but `vend` runs
once per account while `verify` is meant to run repeatedly against the same account
(DESIGN §12's cron/CI framing). At roughly 935 bytes per record and `evidence
.MaxManifestBytes`'s 8 MiB ceiling, an hourly cron reaches the ceiling in about a year, at
which point every later run fails closed (`Write` refuses a manifest over the limit).

**What the code assumed before this landed:** the manifest grows forever and something
else (an operator, a future command) prunes it before that matters.

**Decision (pre-approved by the maintainer 2026-08-11, Phase 0 — see ROADMAP.md): rotate,
via a new terminal record kind, at a 2,000-record threshold.** Reusing
`Custody.SuccessorManifestID`'s already-schema-legal shape was considered and rejected —
`Custody` requires `transferee`/`reason` fields that answer "who has it now and from when",
which rotation has no answer to, since nobody's custody changes when a manifest fills up.
Instead: a new `OpRotate` operation, widening the closed `operation` enum, and a new
`RotationInfo` type/`rotation` schema block (`successor_manifest_id`, `reason`,
`record_count`) — the same pairing discipline `custody_transfer` already follows, at both
the schema and the Go-validator layers.

The existing terminal-record check (`Record.IsCustodyTransfer`) generalized to
`Record.IsTerminal`, returning true for either terminal kind, with exactly one check used
everywhere `Append`'s and `VerifyChain`'s "nothing may follow this" rule is enforced —
there is no separate, divergent second check. `Manifest.Rotate` appends the terminal
`rotate` record through the existing `Append` machinery (no duplicated hashing or linking)
and constructs a fresh successor `*Manifest` via `NewManifest`. The successor's
`Meta.GenesisSHA` is computed normally, the ordinary way, when its own first record is
later appended — no `Meta.PredecessorSHA` or any other cross-manifest hash link was built.
That remains a **distinct, later, also-needs-pre-approval ask**, named but explicitly not
bundled with this one.

Wired into both `verify` (`cmd/automat/verify.go`'s `writeVerifyEvidence` — the exact
command this question is about) and, defensively, `vend` (`cmd/automat/vend.go`'s
`writeVendEvidence` — far less likely to reach the threshold in one run, but cheap to
guard against a heavily-resumed one). A shared `cmd/automat/evidencerotate.go` holds the
naming scheme (`<accountID>-2.json`, `-3`, ... — the first name not already on disk) and
the write sequence (write the record; if the threshold is crossed, close the manifest with
the terminal record, rewrite it, and print an explicit, non-silent notice — "Rotated
evidence manifest: `<path>` is now closed (N records); continuing at `<path>`" — never
implicit magic). The next run for that account resolves the live file by following the
rotation pointer (`openActiveManifest`) rather than assuming the account-named file is
still current; a custody-transferred manifest's successor is deliberately NOT followed the
same way, since custody having left automat's hands means automat has no further business
writing to whatever continues it.

**Status: done.** `schema/evidence-manifest-v1.schema.json` gained the `rotate` operation
and `rotation` block (RATIFIED, not draft — schema/CHANGELOG.md's entry), `internal
/evidence` gained the Go types, validation, `Manifest.Rotate`, and a golden fixture ending
in a rotate record, and both write paths are wired. `Meta.PredecessorSHA` remains the
recorded, separate, not-yet-approved residual.

### Q25 — three of the 110 DFARS SPRS weights are not a single scalar in the DoD's own source

Raised while transcribing the weight table Q10 already decided the sourcing procedure for
(pass 1, 2026-08-11, against the DoD's own "NIST SP 800-171 DoD Assessment Methodology,
Version 1.2.1, June 24, 2020" — `www.acq.osd.mil`). 107 of the 110 requirements have a
fixed weight (5, 3, or 1) that subtracts cleanly from the starting score of 110. Three do
not, and the source itself — not a transcription ambiguity — is why:

- **3.5.3** (multifactor authentication): the DoD document assigns **5** if MFA is not
  implemented at all, **3** if MFA is implemented for privileged/remote access but not for
  general network access — a conditional value depending on a fact automat's own scoring
  arithmetic (`docs/open-questions.md`'s "Assessment Stages 1-2" backlog track, ROADMAP.md)
  has nowhere to read from a plain operator determination of "satisfied" or "not satisfied".
- **3.13.11** (FIPS-validated cryptography): the same 5-or-3 shape — 5 if no cryptography is
  employed at all, 3 if cryptography is employed but not FIPS-validated.
- **3.12.4** (system security plan): the source does not assign a point value at all. It is
  marked **NA** — the absence of an SSP is documented as blocking the assessment from
  proceeding, not as a deduction alongside the other 109.

**What the code assumes now:** nothing yet — no scoring code exists (`internal/assess`
Stage 2 is not built; see ROADMAP.md's "Assessment Stages 1-2" backlog track). The weight
table itself, as a document, has three entries that cannot be a bare integer the way the
other 107 are.

**Why this is not decided here.** It is a real design question about what `assess`'s
determination vocabulary and scoring arithmetic need to express, not a transcription
question — a perfect, disagreement-free second pass through the same DoD document
reproduces exactly these three non-scalar entries, because the ambiguity is the source's,
not the transcriber's. Two shapes are visible without having picked one: (a) model these
three as a small, closed sub-vocabulary the operator determination selects among (e.g.
`3.5.3` admits `not-implemented` (weight 5), `partial` (weight 3), or `satisfied` (weight
0) rather than the binary satisfied/not-satisfied every other requirement uses), or (b)
treat `3.12.4`'s NA specifically as a hard precondition — no SSP, no score at all, distinct
from every other requirement's ordinary deduction — while resolving `3.5.3`/`3.13.11` as
(a). Whichever is chosen has to be decided before Stage 2's scoring code is written, not
discovered partway through it.

**Not blocking anything today.** No scoring code exists yet to get this wrong. Recorded
now, ahead of Stage 2, so the weight table's own schema/type (still to be drafted; see
ROADMAP.md, "Assessment Stages 1-2," items 2 and 5) is designed to hold these three
correctly from the start rather than retrofitted once a `null`/scalar mismatch surfaces in
code.

### Q26 — does a closed account's slot against the account-count quota free up at exactly the 90-day mark, or on some other, opaque schedule?

Confirmed live (2026-08-13), not inferred: a sandbox org with one `ACTIVE` account and four
`SUSPENDED` ones (all four closed by earlier `reclaim` runs, well within AWS's documented
90-day reinstatement window) refused a sixth `CreateAccount` with
`ConstraintViolationException`/`ACCOUNT_NUMBER_LIMIT_EXCEEDED` — five accounts, every
status counted, already at the ceiling. `docs/reclaim-design.md`'s new "A closed account
still counts against the account-count quota" section records the confirmed fact:
`reclaim` changes an account's *status*, not whether it occupies a slot against
`L-E619E033` ("Maximum number of accounts").

**Correction (2026-08-12):** this entry originally theorized that the account's
`GetServiceQuota` call failing with `NoSuchResourceException` meant a brand-new payer
account might not expose its account-count quota via Service Quotas at all, carrying a
temporary, unpublished ceiling below the standard default. That theory was wrong. The
failure was caused by automat itself using `L-29A0C5DF`, a quota code that has never
existed for the `organizations` service — confirmed by listing every quota AWS actually
publishes for the service. The real code, `L-E619E033`, was readable and CLI-adjustable
the whole time, and its value (5.0) exactly matched the observed ceiling: this was always
the ordinary default, not a special new-payer throttle. See
`docs/reclaim-design.md`'s "A closed account still counts against the account-count quota"
section for the full correction. The temporal question below is unaffected by this
correction and remains open.

**What is not confirmed, and cannot be from one observation:** whether that slot frees
exactly when the 90-day grace window (during which AWS can reinstate a closed account on
request) elapses, sometime after via a separate, undocumented purge process, or on some
other schedule AWS does not publish. The inference that it tracks the 90-day window is
reasonable — a still-reinstatable account has to remain a real, addressable entity in the
org, which is consistent with it still counting — but AWS's own `CloseAccount` and account-
status documentation does not state a quota-release timeline anywhere this project has
found, so this is exactly the class of live-org fact `docs/smoke.md`'s checklist exists to
answer and is not yet on that checklist.

**What would settle it:** a sandbox account closed on a known date, with the account-count
quota polled periodically afterward (`aws organizations list-accounts` plus
`aws service-quotas get-service-quota --service-code organizations --quota-code
L-E619E033`) until the slot is observed to free — or a definitive answer from AWS Support,
if a quota-increase case is filed for the same org in the meantime (see the "A closed
account still counts" section for the CLI command that opens one; no support case is
strictly required to raise the ceiling itself, only to learn the exact release schedule).

**Not blocking anything today** beyond the immediate, already-hit inconvenience: this
sandbox org cannot create another account until either the quota is raised or enough
existing `SUSPENDED` accounts age out, whichever happens first. Recorded so the next
person to hit this — in this sandbox or another — has the confirmed fact (closed accounts
count) and the open question (for how long, exactly) in one place, rather than
rediscovering the first and guessing at the second.

**See also `docs/hold-design.md`'s "Explicit interaction with Q26 and the quota finding":**
`automat hold` (keeping an account `ACTIVE` under a tightened SCP instead of closing it) does
not free or avoid consuming this quota either — an active held account counts exactly like
any other active account. `hold` and `reclaim` are not alternative quota-management
strategies; neither one moves this number.

**Partial mitigation landed:** `preflight`'s `checkQuota` now also reads the current account
count via `organizations:ListAccounts` (every status, since this is exactly the fact this
question is about) and reports it alongside the quota value whenever either is readable
(`internal/preflight/preflight.go`). An operator can now see "9 of 10, one more vend is fine"
versus "10 of 10, the next vend fails outright" before running `vend`, rather than finding out
mid-vend — but this only reports the count, not how long a `SUSPENDED` account keeps occupying
its slot, so the question above is unaffected.
