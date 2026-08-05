# Assessment reporting — Phase 4 scope proposal

**Status: approved as scope, staged inside ROADMAP Phase 4. No implementation before
Phase 4.** This page is the design authority; ROADMAP.md carries the deliverables. Two
consequences land on Phase 4's `verify` work itself — see "What this requires of
`verify`" — and that part should be read before `verify` is written, because retrofitting
it means two code paths computing one compliance claim.

> automat encodes a technical reading of published policy. It is not legal advice and not a
> compliance determination. The agreement, award terms, or contract clause your institution
> signed governs; your sponsored programs office, contracts office, or counsel decides what
> applies and which revision. Where policy is ambiguous — for example the NIH 800-171
> revision question — automat records the operator's declaration rather than resolving it.
> Policy citations carry effective dates and change; verify against the primary source
> before relying on them. (`docs/policy-caveat.md`.)

Both frameworks automat ships catalogs for define a **self-assessment process with an
expected output**, and neither is satisfied by a tool printing "compliant". This page
records what those processes require, what automat can honestly contribute, and the
invariants that keep the second from overstating the first.

**Amended after the review that approved this scope:** the original proposal assumed one
assessment regime per control catalog. It needs a second axis, and everything below reads
against it — see "The second axis" immediately following.

## The second axis: obligation profiles

A catalog answers **which controls**. It does not answer *under what instrument, assessed
how, signed by whom, with gaps deferrable or not.* Those are a separate axis, and the
reason they cannot be fields on the catalog is that **the same control catalog is assessed
under incompatible rules by different regimes**:

| | Catalog | Determinations | POA&M | Score | Signed by |
|---|---|---|---|---|---|
| `cmmc-l1` | CMMC 2.0 L1 (15 practices) | MET / NOT MET | **forbidden** | none | senior official |
| `dfars-7012` | 800-171 **Rev 2**, pinned by class deviation | SATISFIED / OTHER THAN SATISFIED | permitted, dated | 110-weighted → SPRS | authorized rep |
| `nih-cadr-dua` | 800-171, **revision not pinned** | SATISFIED / OTHER THAN SATISFIED | permitted, dated | none | PI + IT contact + signing official |

The bottom two rows read the *same* control catalog and agree on almost nothing else. The
same objective with no evidence is a blocking NOT MET under the first, and an
OTHER-THAN-SATISFIED with an eligible POA&M line under the third. Same fact, two legitimate
renderings.

`nih-cadr-dua` is the case that matters most for this project's users and the one that
breaks a CMMC-shaped model outright, in three ways:

- **The trigger is the data source, not a marking or a clause.** The obligation arrives via
  a **Data Use Agreement** with a listed controlled-access repository. An institution can
  be entirely outside DFARS and squarely inside this.
- **The scope is wider than a contract's.** It binds Approved Users *and* developers
  building or testing platforms, pipelines, tools, or interfaces that touch the data, and it
  reaches institutional systems, third-party IT, and cloud providers.
- **The revision is not pinned.** NIH's notices align expectations with 800-171 without
  naming a revision, and institutions have split. So the revision is an **operator
  determination** — recorded with who determined it and when, hashed into the evidence chain
  like any other determination — and **automat ships no default and refuses to proceed
  without one**. "Most institutions use Rev N" is not a default; it is not even a hint,
  because a default here silently picks an institution's compliance posture for it.

Profiles live in `catalogs/obligations/` against
`schema/obligation-profile-v1.schema.json`, and are **data**: there is no
profile-specific branching in Go. A regime encoded as a `switch` on profile id cannot be
corrected without a release, and policy moves faster than this tool will.

**Applicability is never evaluable.** A profile's `applicability.trigger` is prose for a
human plus at most a bounded, explicitly non-exhaustive `hints` list. There is no expression
language and no predicate, because an automated "this obligation applies to you" is the most
dangerous output this tool could produce: wrong in the permissive direction it tells an
institution it is unregulated, and it would be believed, because it came from a tool that is
right about everything else. The operator declares which profiles apply.

`FAR Case 2017-016` — the governmentwide civilian CUI rule — is deliberately **not shipped
as a profile**. It is still a proposed rule, and it excludes COTS items and fundamental
research at colleges, universities, and laboratories, which is most of what this project's
users do. The schema's `status: proposed` exists so it *can* be recorded without being
modeled as binding; shipping it today would imply requirements institutions do not have.

## The processes, and their expected artifacts

**NIST SP 800-171 self-assessment** is defined by **SP 800-171A**, the companion
assessment-procedures publication. It is structured data, not guidance: each requirement
decomposes into numbered **assessment objectives** — 3.1.1 becomes 3.1.1[a] through
3.1.1[e] — and each objective is determined **SATISFIED** or **OTHER THAN SATISFIED**
using three method classes (EXAMINE, INTERVIEW, TEST). The expected artifacts are a
**System Security Plan** describing how each requirement is met (800-171 §3.12.4) and a
**Plan of Action and Milestones** for anything not satisfied.

For DoD contractors, **DFARS 252.204-7019/7020** adds a scoring methodology: begin at
110, subtract a per-requirement weight of 5, 3, or 1 for each unimplemented requirement,
and post the resulting score with a target completion date to **SPRS**. That score is the
output with contractual consequences.

**CMMC 2.0 Level 1** is the simpler case and the one automat already has a catalog for.
Fifteen practices — exactly the fifteen in `catalogs/cmmc-l1.json` — assessed annually by
the contractor itself, each **MET** or **NOT MET**. Two properties drive the L1 renderer:
there is **no partial credit**, and **no POA&M is permitted at Level 1**, so a single NOT
MET practice means there is nothing to affirm. The process concludes with an **annual
affirmation by a senior official** submitted in SPRS. No third-party assessor is involved
at L1.

## Invariant 1: every output is a draft, and nothing resembles a submission

**Every rendered page carries a `DRAFT — NOT A SUBMISSION` marking, and no output may
resemble a signable affirmation.** This is a hard invariant with a test, in the same class
as `TestREADMEMakesTheBlastRadiusArgument` — a claim about generated output that a future
refactor could quietly drop, so it is asserted rather than documented.

The reason is the CMMC L1 affirmation. An annual affirmation is a named senior official
personally attesting to a compliance posture, with False Claims Act exposure behind it. A
generated document that *reads* like that affirmation — official-looking, signature line,
determination fields filled — is a document someone can sign without having done the
assessment. The tool would have manufactured the appearance of diligence, which is worse
than producing nothing, because the appearance is what survives being forwarded.

Concretely, the test must assert:

- The `DRAFT — NOT A SUBMISSION` marking appears in **every** renderer's output, checked
  the way `TestEveryRendererIsReachable` checks the bundle: a renderer added later and
  omitted from the list is itself a failure.
- **No signature affordance** anywhere: no signature line, no `_________`, no "signed",
  "affirm", "affirmation", "I certify", "under penalty", no date-signed field. The
  forbidden-phrase list is the mechanism, the way `TestNoProductOrVendorReference` is.
- **No submission framing**: no "submit this", no SPRS submission instructions beyond
  "enter this score", no form numbers.

automat generates the packet the affirming official *reads*, never the thing they sign.

## Invariant 2: automat writes no determination that overstates

A determination is a claim a named human signs. automat may never write one that says a
requirement is met.

It **may** write one that says a requirement is not met — and at CMMC L1 it must. That
asymmetry is the whole rule, and it is worth stating as direction rather than as
prohibition:

> automat's proposals may only ever understate compliance. `MET` / `SATISFIED` comes from
> the operator's determinations file or from nowhere. `NOT MET` may be written by automat,
> because being wrong in that direction costs an afternoon of review, while being wrong in
> the other direction is what an enforcement action is built on.

So the report carries two layers, and labels which is which per objective:

| Layer | Vocabulary | Written by |
|---|---|---|
| **Machine evidence** | automat's observations: resource configured, rule evaluation, timestamp, artifact hash | automat, mechanically |
| **Operator determination** | The standard's closed set — `SATISFIED`/`OTHER THAN SATISFIED`, `MET`/`NOT MET` | The operator, in the determinations file |

Per objective, the report labels its evidence class **`machine`** or **`operator`**,
mirroring the existing `aws-mapping`/`curated` provenance split on config-rule bindings.
The precedent matters: that field exists so a reader can audit automat's judgment
separately from AWS's, and this one exists so a reader can audit the operator's assertions
separately from automat's observations. An assessment where every objective is `operator`
is a spreadsheet with extra steps, and the report should make that visible.

automat does **not** invent a third value inside the standard's vocabulary. 800-171A has
exactly two determinations; adding a "NOT DETERMINED" beside them would produce a
worksheet that is not an 800-171A worksheet. Undetermined lives in automat's layer, as the
absence of an operator determination — which at L1 renders NOT MET (below) and at
800-171r2 renders as an unscored requirement in the arithmetic.

**The profile parameterizes this asymmetry; it does not bolt onto it.** Each regime spells
its own values, so `determinations.understatement_value` in the profile names which member
of that closed set automat is permitted to write on its own — `NOT MET` for `cmmc-l1`,
`OTHER THAN SATISFIED` for the other two. That is the *only* value automat writes; the
satisfied value comes from the determinations file or from nowhere.

Because a profile can carry that field, a profile could in principle invert the invariant
while validating perfectly against the schema. So it is asserted as a **property over the
profile set** rather than per profile
(`TestTheUnderstatementAsymmetryHoldsUnderEveryProfile`): the check has to hold for profiles
nobody has written yet, which is precisely what a per-profile assertion cannot do.

## Invariant 3: the L1 wrinkle — no partial credit, no POA&M, so silence is NOT MET

At CMMC Level 1 an objective with **neither machine evidence nor an operator
determination** renders as **NOT MET** in the draft. Not "in progress", not "pending", not
blank.

This follows from the framework rather than from taste. L1 permits no POA&M, so there is
no legitimate place for a practice to sit partially done; and it has no partial credit, so
a practice is one of two things. A renderer that emitted "in progress" would be inventing
a state the framework does not have, and — worse — inventing the *comfortable* one. An
operator reading fifteen practices where four say "in progress" concludes they are nearly
there. The same four saying NOT MET tells them the truth: there is nothing to affirm this
year until those four are done.

Note this is Invariant 2 working, not an exception to it. NOT MET understates; that is the
permitted direction.

The L1 summary must also state the consequence rather than leaving it to be inferred: with
any practice NOT MET, the annual affirmation cannot be made. A count of 11/15 is not a
score at L1 — it is a fail with a work list.

## What automat can and cannot contribute

The honest accounting against the shipped catalog. Of the fifteen L1 practices, twelve
carry `config-rule` and six carry `procedural` (some carry both):

| automat can assert (`machine`) | Only the operator can assert (`operator`) |
|---|---|
| Per-objective evidence for detective controls: which Config rule, evaluation status and timestamp, the artifact id and `content_sha256` it came from | That the AWS account **is** the system boundary |
| That a preventive control is attached and its content hash matches the artifact | That the boundary contains no other systems processing the same data |
| That an attestation stub exists and is not stale against its declared frequency | That the attested process actually happens |
| A provenance chain per claim, back through the evidence manifest to the compile sources | Anything about physical or media controls |

Three L1 practices — `MP.L1-b.1.vii` (media disposal) and `PE.L1-b.1.viii`/`ix` (physical
access) — have essentially no AWS surface. They can only ever be `operator`, and with no
determination they render NOT MET. That is not a gap in the tool; it is the tool's scope
stated per-objective instead of once in a README.

### Scope is an input, not an inference

Every report states its scope in its own header: *this report covers AWS account `<id>` as
configured by artifact `<id>@<sha256>`*. Whether that equals the system boundary the
assessment concerns is the operator's assertion, captured as an input and reproduced in the
output. If the boundary includes laptops, a datacenter, and three SaaS applications, most
objectives are not automat's to speak to, and the report must say so in a way that survives
being forwarded without its cover note.

## Inputs

`automat assess` consumes three things and reaches AWS read-only:

1. **`verify` results** — the structured value, not its printed form. See below.
2. **Attestation state** — which stubs exist, and their staleness against declared
   frequency. Already computed by `verify`'s procedural layer (DESIGN §12).
3. **An operator-determinations file** — the operator's own assertions, as data.

The determinations file is the mechanism that makes Invariant 2 enforceable. Without it,
`SATISFIED` would have to be typed into a generated document, which is exactly the
signable-artifact shape Invariant 1 forbids. As a file it is reviewable, diffable, and
**content-hashed into the evidence chain like a catalog** — so a later reader can tell
which human assertions were in force when a report was generated, and an assertion cannot
be revised after the fact without the hash moving.

Per determination: an **id**, the **objective(s)** it satisfies, a **statement** of the
basis, a **date**, and a **responsible party**. The responsible party is not decoration —
it is the field that makes an assertion attributable, and an assessment where every
determination names the same person who also ran the tool is a fact a reviewer should be
able to see.

## Outputs

A canonical JSON **assessment-result** document is the primary artifact — hashed and
canonicalized like every other document in `schema/`, referenceable from an evidence
manifest record. Human-facing forms render *from* it and are never authored independently:

- **800-171A objective worksheet** — one row per objective: automat's observation, its
  evidence class (`machine`/`operator`), the evidence pointer, and the determination from
  the determinations file (or its absence).
- **CMMC L1 MET/NOT MET summary** — fifteen practices, the no-POA&M rule enforced per
  Invariant 3, and an explicit statement of whether an affirmation is possible at all.
- **POA&M seed** — one entry per objective with no satisfying determination. At L1 this
  exists only as a work list, and the L1 renderer must say so rather than emit a document
  implying a POA&M is permitted.
- **SPRS score computation** — the score plus **per-requirement worked arithmetic**: which
  requirements were counted, at what weight, which weight table by hash, and what remains
  unscored for want of evidence. No submission formatting, no affirmation text. A bare
  number is not usable; the operator has to key it in and defend it.

**Generating an assessment appends an evidence record.** A self-assessment is a claim made
at a point in time against a specific artifact hash and a specific set of operator
determinations, which is what the manifest chain exists to hold. It also lets a later
reader tell whether a report predates a baseline change.

**SPRS has no documented ingest format.** Scores are entered through its web application;
there is no published submission schema to target. So "the expected format" splits: the
800-171A worksheet, the L1 summary, and the POA&M seed are genuinely generatable, while
SPRS means computing the score correctly and showing the work.

**SSP generation is out of scope for v1.** Noted as future: an SSP is a system-boundary
document, and most of its content is about things outside the AWS account — network
diagrams, personnel, physical facilities. automat could pre-fill the requirement sections
it configured, which is a real contribution but a small fraction of the document, and a
partial SSP that looks complete is the Invariant 1 hazard in another form. Revisit once
the worksheet and scoring paths have been used against a real assessment.

## What this requires of `verify`

The part that cannot be deferred within Phase 4.

**`verify`'s result must be a structured value; the printed report renders from it.** If
`verify` prints text and returns an exit code, `assess` has to re-derive every evaluation —
a second code path computing the same compliance claims, which is how two parts of one tool
start disagreeing about whether an account is compliant.

Per control, that value needs: the enforcement classes exercised, the resource actually
observed (SCP ARN, rule name, attestation path), the observation timestamp, and the
artifact id and `content_sha256` checked against. Nothing here requires the assessment
schema to exist — only that `verify` not throw its evidence away.

## Staged deliverables

Ordered so each stage is independently useful and the L1 path is not blocked by the
800-171 path:

0. **Obligation profiles.** **Done** — `schema/obligation-profile-v1.schema.json` plus
   `cmmc-l1`, `dfars-7012`, `nih-cadr-dua` in `catalogs/obligations/`. Data and schema only.
   First because every stage below renders under a profile, and the citations still need
   vendoring before anything may render from them
   (`TestNoUnresolvedHashInARenderableProfile`).
1. **Objectives catalog + weight table.** 800-171A objectives from NIST CPRT
   (`SP_800_171A`), vendored and hashed into `artifact.sources` like every other source.
   DFARS weights from the DoD Assessment Methodology document, **recorded with its title,
   version, and hash** — the weights are load-bearing and must never be inferred.

   Q10 is **decided**: the weight table is **hand-transcribed twice, independently, and the
   two passes diffed before commit**, the second pass done fresh from the source document
   without consulting the first, with a note recording that they agreed. If they disagree
   anywhere, the diff goes to review rather than being resolved by picking one. The reason is
   that redundancy at the point of entry is the only control available against a false input
   to correct arithmetic: a hash detects a value that *changed*, never one that was wrong
   when first written down, and a wrong weight is confidently wrong in the same direction on
   every regeneration. See `docs/open-questions.md` Q10. Data-only; lands before any
   renderer.
2. **Worksheet + scoring.** The 800-171A objective worksheet and the SPRS score with worked
   arithmetic.
3. **L1 MET/NOT MET summary**, with the no-POA&M rule and Invariant 3 enforced.

CMMC L1 needs no weight table, so stage 3 does not depend on Q10 being settled.

## Schema and surface, for ratification when built

Both need pre-approval; recorded here as the thing to ask about, not as a decision taken.

- **`schema/assessment-result-v1.schema.json`** — the canonical result document.
- **`schema/operator-determinations-v1.schema.json`** — id, objectives, statement, date,
  responsible party; content-hashed into the evidence chain. Also carries the **revision
  determination** where a profile leaves the revision open, with who determined it and when.
- **`schema/obligation-profile-v1.schema.json`** — **already written**, listed in
  `schema/CHANGELOG.md` for ratification, with three profiles shipped in
  `catalogs/obligations/`. Data and schema only; no Go types and no `assess`.

```
automat assess --account <id> --profile cmmc-l1|dfars-7012|nih-cadr-dua \
               --determinations <file> --out <dir>
```

`--profile` names an obligation profile, not a catalog: the profile is what determines the
determination vocabulary, whether a POA&M is renderable, and whether there is a score at
all, and it names the catalog it is assessed against. Under a profile whose revision is
operator-determined, `assess` **refuses to run** without the operator's recorded revision
determination — it does not pick one.

A separate verb rather than a `verify` flag: the two answer different questions — `verify`
asks "does reality still match the artifact", `assess` asks "what can be claimed about this
account against a framework" — and `assess` writes an evidence record while `verify` does
not. Read-only against AWS, so no `--yes`.

DESIGN §13 does not list `assess`. Per the Phase 1 review's ratification condition a
command absent from §13 is an addition rather than a contradiction, but §13 should gain it
when it ships, so the design stays the source of truth.
