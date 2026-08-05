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

### Q6 — SCP quota edges under union output

DESIGN §16 names the quotas (5 SCPs per target, 5120 characters each). What is unverified is
how close a real union of `cmmc-l1` + `800-171r2` + a campus baseline comes to them, and
therefore how aggressive the packer must be about merging Action lists.

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

---

## Decided by the maintainer

Not live-org questions and not code questions: questions about source data whose authority
matters more than its availability. `docs/smoke.md` does not cover these, because no
sandbox run answers them. Kept here rather than deleted once decided — the reasoning is
the part that has to survive, since the decision looks like unnecessary ceremony to anyone
who has not read why.

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
