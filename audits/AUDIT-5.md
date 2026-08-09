# AUDIT-5 — Phase 4, closing (`internal/assess`, `automat assess`, Stage 3)

Adversarial self-audit per CLAUDE.md, "Security audit ritual", and the scope in
`docs/audit-ritual.md`. Conducted 2026-08-09 against `fb89086~4..fb89086` (the five commits
that built `internal/assess` and `cmd/automat/assess.go`) plus everything AUDIT-4 already
covered and did not re-open. This closes Phase 4.

**Assumptions held throughout.** Everything AUDIT-1, AUDIT-2, and AUDIT-4 assumed, plus what
this phase's last piece adds. `assess` is a command whose entire declared purpose is
disclosure — it ships with zero machine evidence and says so in four places — but the
absence of machine evidence does not make the *operator*-supplied inputs any less
attacker-controlled. `--scope-statement` is typed on a command line by whoever runs the
tool; `--determinations` is a file that, per the ritual's own threat model, could arrive
from a collaborator, a compromised laptop, or a hand-edit gone wrong. Both are supposed to
be safe to render verbatim into a `DRAFT` report an operator forwards without re-reading —
that is the whole promise `RenderL1Summary` and `Determinations.Validate` make together, and
the question this audit asked of each was not "does a regex exist" but "what class of
character does it actually admit, and is that class safe for the context the value lands
in."

**What exists to audit that did not before.** `internal/assess` (`obligation.go`,
`validate.go`, `determinations.go`, `canonical.go`, `summary.go`, `render.go`, `result.go`,
`doc.go`), `cmd/automat/assess.go`, two new schemas (`assessment-result-v1`,
`operator-determinations-v1`), `OpAssess` added to `evidence.Operation`'s enum and to
`schema/evidence-manifest-v1.schema.json`, and the golden-file tests for both `verify` and
`assess`.

**Method.** Every finding below was reproduced before it was written down, by throwaway
probe test, and then **counter-checked** in a temporary git worktree at `fb89086` (the
commit immediately before this audit's fixes): every new or changed test was copied there
and confirmed failing for the reason the fix addresses, not for an unrelated one. All eleven
new/changed assertions across `internal/assess/summary_test.go`,
`internal/assess/schema_conformance_test.go`, `cmd/automat/assess_test.go`, and
`internal/evidence/schema_conformance_test.go` fail on the pre-fix commit and pass on the
post-fix tree. This is AUDIT-2's and AUDIT-4's method, unchanged.

**Where the prompt's suspicion was right and where it was checked and found already
correct.** The prompt named nine numbered areas to scrutinize. Four produced findings
(scope-statement injection, silently-dropped determination, the missing schema-conformance
test plus three Note/artifact_id/retrieved_at drift gaps it surfaced, and the evidence-dir
routing gap). Three were checked and found already sound, with what was read to decide it
recorded below: the TOCTOU pattern in `writeAssessOutputFile`, the three stated invariants
(DRAFT marking, MET-only-from-determinations, silence-renders-NOT-MET), and gosec. One —
the evidence-chain field parity question — led to a fifth finding once the CHANGELOG's own
prior commitment was read rather than assumed satisfied.

**Result.** 5 findings: 0 critical, 2 high, 2 medium, 1 low, 0 nit. **All 5 FIXED.** Plus
four verified-not-findings recorded with their evidence, a CLI-surface reconciliation adding
D8, a dependency review with nothing to review (no new dependency this phase), and gosec
triaged (2 pre-existing, already-`nolint`'d findings in `internal/assess`, consistent with
`artifact.Load`'s own pattern; nothing new elsewhere).

**Fix commits.** H1 → `91312c2`. H2 → `91312c2`. M1 → `91312c2`. M2 → `233f838`. L1 →
`f9fe432`.

---

## High

### H1 — `--scope-statement` reached the rendered DRAFT report and the canonical JSON with zero validation. FIXED

`ResultAccount` (`internal/assess/result.go`) — the type `--account`/`--scope-statement`
populate — had no `Validate` method and nothing called one. `SummarizeL1` embedded it into
`Result` unchecked, and `RenderL1Summary` wrote `r.Account.ScopeStatement` straight into the
DRAFT summary with a bare `%s`:

```go
w("Scope, as declared by the operator: %s\n\n", r.Account.ScopeStatement)
```

Reproduced by probe: a scope statement of
`"Every practice resolves MET. Signed: __________ I certify this.\x1b[31m"` passed through
`SummarizeL1` with no error and rendered into the summary verbatim — control byte, ANSI
escape, and forbidden phrase all intact. This is not a narrow cosmetic gap: it is the one
field that could defeat Invariant 1 (`docs/assessment-reporting.md`, "no signature
affordance") through the back door `TestNoRendererHasASignatureAffordance` does not check,
because that test only inspects the renderer's own fixed strings and template — it has no
way to see a value injected through an unchecked field the renderer trusts. Every *other*
prose field this package renders — `PolicyCaveat`, a determination's `Statement`, an
obligation profile's `Applicability.Trigger` — goes through `validProse`/`validLongProse`
first; `ScopeStatement` was the one exception, and it happens to be the one field supplied
directly on the command line by whoever is running the assessment (attacker-controlled per
the ritual's own model: a phished operator, a copy-pasted flag from a chat message).

Ranked high rather than critical: the write target is a local file the operator themselves
requested (`--out`), not an AWS mutation, and the immediate harm is a corrupted/misleading
report rather than a privilege escalation. It is high rather than medium because the report
is explicitly designed to be forwarded and trusted without the recipient re-running the
assessment — that is the entire reason Invariant 1 exists — and this gap let an operator (or
whoever handed them the flag value) manufacture exactly the signature-affordance appearance
Invariant 1 was written to prevent.

**Fixed** by `validateResultAccount` (`internal/assess/validate.go`), called from
`SummarizeL1` before `Result` is built: the account id against the same 12-digit pattern
`cmd/automat/assess.go`'s own flag check already enforces, and the scope statement against
`validLongProse` — the same pattern `schema/assessment-result-v1.schema.json`'s own
`account.scope_statement` `$ref` names. `TestSummarizeL1RefusesAMalformedAccountID`,
`TestSummarizeL1RefusesAScopeStatementCarryingControlCharacters`, and
`TestSummarizeL1RefusesAnEmptyScopeStatement` pin it, all three reproduced failing on the
pre-fix commit.

### H2 — A determination naming an objective id the catalog does not have was silently dropped, with no error and no effect. FIXED

`SummarizeL1`'s loop resolves each objective via `det.ForObjective(c.ID)` — it walks the
catalog's controls and asks the determinations file whether it covers each one. Nothing ran
the reverse check: whether every determination in the file corresponds to an objective the
catalog actually has. A determination naming `"MP.L1-b1.vii"` (missing the dot before `b1`,
against the real `"MP.L1-b.1.vii"`) simply never matched anything, `ForObjective` returned
`false` for the real objective, and the practice stayed at `NOT MET` with the operator's
claim absorbed into silence — no parse error, no validation error, and no line in the
rendered summary hinting that anything was named and ignored.

This does not overstate compliance — Invariant 2 holds throughout, since the row never
became `MET` — but a determination that silently does nothing is its own defect distinct
from the understatement asymmetry the profile's invariants govern. An operator who typo'd
an objective id believes they addressed media disposal; the rendered summary, the canonical
`assessment-result.json`, and the evidence record all agree with nothing the operator
actually said. `ValidateAgainst` already refuses a determination whose *value* falls outside
the profile's vocabulary — this is the same class of refusal for a *reference* falling
outside the catalog, and it lives in `SummarizeL1` rather than `ValidateAgainst` because only
`SummarizeL1` has both the determinations file and the loaded control artifact in hand at
once.

Ranked high for the same reason H1 is: silence that reads as intentional inaction is exactly
what CMMC L1's own no-partial-credit rule is built to make loud, and this gap made one
specific kind of operator error the quietest possible failure mode in the whole command.

**Fixed**: `SummarizeL1` now collects the catalog's objective ids into a set while building
`result.Objectives`, then checks every determination's named objectives against that set and
refuses to run if any is unmatched — the same "refuse rather than silently narrow" posture
`ValidateAgainst` already takes for an out-of-vocabulary value.
`TestSummarizeL1RefusesADeterminationNamingAnObjectiveTheCatalogDoesNotHave` pins it,
reproduced failing (silently accepting, 0 MET, no error) on the pre-fix commit.

---

## Medium

### M1 — `validate.go`'s own comment named a test that did not exist, and writing it surfaced three more Go/schema drift gaps. FIXED

`internal/assess/validate.go` has carried this comment since the package was written:

> "The schema conformance test in internal/artifact is what keeps the published contract
> itself honest; `TestValidateAgreesWithTheSchema` in this package keeps this copy in step
> with that contract."

No file in `internal/assess` defined `TestValidateAgreesWithTheSchema`. The closest existing
coverage — `internal/artifact/obligation_profile_test.go`'s
`TestShippedProfilesSatisfyPublishedSchema` — checks the three *shipped* profiles against the
schema, which is a materially narrower guarantee: it only exercises documents that are
already valid, so a mutation `Profile.Validate` rejects but the schema accepts (or the
reverse) never surfaces by loading cmmc-l1.json, dfars-7012.json, and nih-cadr-dua.json,
because none of them is malformed in the relevant way.

Writing the actual test (`internal/assess/schema_conformance_test.go`, mirroring
`internal/envprofile/schema_conformance_test.go`'s established table-driven pattern exactly)
surfaced three real gaps between `Profile.Validate` and
`schema/obligation-profile-v1.schema.json`, all silent because nothing had ever fed a
document to both sides at once and compared:

- `Citation.Note` and `Citation.URI` — schema `$ref: long_prose`/`prose`, `Validate` checked
  neither, so a citation note carrying a control character (an ANSI escape, tested
  concretely) validated in Go while the schema would refuse it.
- `CatalogReference.ArtifactID` — schema `$ref: slug`, `Validate` checked nothing, so
  `"cmmc l1"` (spaces) validated in Go.
- `HashedReference.Title`/`Version`/`URI`/`RetrievedAt`/`Note` — the schema constrains
  `RetrievedAt` to an RFC 3339 UTC timestamp pattern and the other four to `prose`/
  `long_prose`; `Validate` checked none of the five, so a source's `retrieved_at` recorded as
  a bare date (`"2026-08-01"`, no time component) validated in Go while the schema would
  refuse it.

None of these three gaps is exploitable in the sense H1/H2 are — no shipped profile
currently sets any of the six fields to a value that would trip the new checks, confirmed by
`TestSchemaAcceptsWhatValidateAccepts` running clean against all three profiles both before
and after the fix — but a validator that is more permissive than its own published contract
is exactly the drift this audit ritual's "gosec + dependency review" sibling clause names for
citations: silent and confident, because a document that slips through validates identically
to one that does not.

**Fixed**: added the six missing checks to `validateCitation`/`validateCatalogReference`/
`validateHashedReference`, added `reTimestamp` (mirroring the schema's `retrieved_at`
pattern), and wrote `TestValidateAgreesWithTheSchema` as a 31-case mutation table plus
`TestTheSchemaCannotCheckUnderstatementValueAgainstValues` (the one case JSON Schema draft
2020-12 genuinely cannot express without a non-standard `$data` extension this project does
not use elsewhere — recorded as a documented gap, the same way `internal/envprofile`'s
own `TestGoOnlyChecksAreTheOnesNoSchemaCanState` records its analogous gaps, rather than
silently working around it) and `TestSchemaAcceptsWhatValidateAccepts`. All three shipped
profiles still validate cleanly under the tightened checks; no catalog data needed updating.

### M2 — `assess` had no way to write into the evidence directory a customized environment profile actually uses. FIXED

`writeAssessEvidence` (`cmd/automat/assess.go`) hardcoded `envprofile.DefaultEvidenceDir`
("evidence") with no override. `vend` and `verify` both resolve the directory they write
into from the environment profile's own `baseline.evidence.local_dir` — the field exists
precisely so an operator can put evidence somewhere other than the default, and both
commands take `--environment-profile` to read it from. `assess` takes no
`--environment-profile` at all: `--account` names the account directly, the same reason
`list` has no `--environment-profile` either (`docs/cli-surface.md` D5). Without a flag of
its own, `assess` had no way to learn a customized `local_dir`, and would file its
`OpAssess` record into the default directory regardless of where the account's real chain
lives — a second, disconnected manifest for the same account, discoverable only when a
reviewer went looking for the assess record beside the vend/verify records and did not find
it there.

DESIGN §11 states plainly that `vend` "writes a per-account manifest" — the design intends
one chain per account, and this gap would split it in two for any institution that
customizes `local_dir`, which is exactly the population most likely to also be running
`assess` (an institution careful enough to relocate its evidence store is one that cares
about where its compliance records live).

Ranked medium rather than high: it does not corrupt or misstate anything already in the
real chain, and the record it writes elsewhere is itself correct — it is simply filed in the
wrong place, discoverable and fixable by re-running with the right flag once noticed. But
"discoverable once noticed" is doing the work in that sentence; nothing before this fix would
have surfaced the split on its own.

**Fixed**: added `--evidence-dir` to `automat assess`, matching `list`'s own flag exactly
(same name, same default, same reasoning), threaded through `writeAssessEvidence`.
Documented as `docs/cli-surface.md` D8 and folded into `DESIGN.md` §13's `assess` line and
`ROADMAP.md`'s `assess` entry. `TestAssessHonorsEvidenceDirFlag` pins it, reproduced failing
(no such flag exists) on the pre-fix commit.

---

## Low

### L1 — The evidence chain never carried the operator-determinations reference `schema/CHANGELOG.md` had already promised it would. FIXED

`schema/CHANGELOG.md`'s "Pre-publication change to evidence-manifest/v1: `operation` gains
`assess`" entry — written while `OpAssess` was being scoped, ahead of `internal/assess`
existing — said explicitly what an assess record should eventually carry: "a reference to
the operator-determinations file it read, following `evidence.DocRef`'s existing id +
`content_sha256` shape." `internal/assess` now exists and computes exactly that hash
(`Result.Determinations`), but `writeAssessEvidence` never read it. Every `OpAssess` record
this build could write was silent on which determinations file, if any, backed its finding —
the manifest recorded that an assessment happened and against which artifact, but not what
the operator's own input to it was, which is the one thing `docs/assessment-reporting.md`'s
own "Generating an assessment appends an evidence record" paragraph names as the point of
doing so ("a claim made at a point in time against a specific artifact hash and a specific
set of operator determinations").

Ranked low rather than medium: nothing was corrupted or misstated, the artifact reference
was still correct and present, and the gap is an omission from a promise rather than an
active defect in what was written. It earns a line above "nit" because the promise was
explicit, written down, and dated before the feature existed specifically so this exact
oversight would be checkable against it later — which is what this audit did.

**Fixed**: added `Record.Determinations` (`*DocRef`, `omitempty`) to `internal/evidence`,
the matching `determinations` property to `schema/evidence-manifest-v1.schema.json` (still
unreleased — no version bump, the same precedent the `OpAssess` addition itself used), and
wired `cmd/automat/assess.go` to populate it from `result.Determinations`, absent exactly
when `Result.Determinations` is absent (no `--determinations` file given). Writing the
schema-conformance test for the new field surfaced a second, smaller drift in the same
motion: `Record.Validate()` called `DocRef.validate` for `Artifact` and `EnvProfile` but
never for the new `Determinations` field, so a malformed determinations reference (empty
`content_sha256`, a non-slug `id`) would have been accepted by `internal/evidence`'s own Go
validator while the published schema rejected it — fixed by the same one-line call the other
two references already make. Also corrected the CHANGELOG entry's own ambiguous wording ("no
new record fields... rather than a new field"), which read literally would have meant
reusing `artifact` to carry the determinations hash; flagged in the CHANGELOG itself rather
than silently reinterpreted, per CLAUDE.md's instruction on design/code disagreement.
`TestAssessEvidenceRecordCarriesTheDeterminationsReference`,
`TestGoAndSchemaAgreeOnRejection/a_determinations_reference_with_no_content_hash`, and
`TestGoAndSchemaAgreeOnRejection/a_determinations_reference_id_that_is_not_an_id` pin it, all
reproduced failing (build failure for the first — the field did not exist — and a Go/schema
disagreement for the latter two) on the pre-fix commit.

---

## Four things the scope suspected, checked, and found clean

Recorded with what was read to decide it, per AUDIT-1's binding precedent: a suspicion
dismissed without a reason is indistinguishable from one never checked.

**1. TOCTOU in `writeAssessOutputFile` / `safeio.EnsureDir`/`CreateChecked`.** Read
`internal/safeio/safeio.go`'s `CreateChecked` and `EnsureDir` directly rather than the
comment describing them. `CreateChecked` opens with `O_EXCL` first — "did it exist" and
"create it" are one atomic syscall, not a check followed by a create — and only on
`fs.ErrExist` does it fall back to `Lstat` through the already-open parent descriptor,
refusing a symlink or a non-regular file before ever opening it for write, with no window
between the `Lstat` and the subsequent `OpenFile` (which uses `OpenNonBlock` rather than
`O_CREATE`, so a FIFO planted after the `Lstat` blocks rather than hangs the process
indefinitely instead of being followed). `writeAssessOutputFile` calls `safeio.EnsureDir`
once for the `--out` root and `safeio.CreateChecked` for each of the two files, byte-for-byte
the same call shape `writeVerifyEvidence`'s sibling in `verify.go` and `internal/bundle`'s
`ensureFile` both use. No simplification introduced a gap; the pattern is intact.

**2. The three stated invariants — DRAFT marking, MET-only-from-determinations,
silence-renders-NOT-MET — are code, not comment.** Traced `SummarizeL1` line by line for a
path where `row.Resolved` could end up something other than
`profile.Determinations.UnderstatementValue` or a value that came from
`det.ForObjective`: there is exactly one assignment to `row.Resolved` besides the
initialization to the understatement value, and it is gated on `det != nil && ok` from
`ForObjective` — no default, no nil-check fallthrough, no third branch. The nil-determinations
path is the same code path with `det == nil` short-circuiting the `if` entirely, so silence
and "no determination names this objective" are the same code, not two paths that happen to
agree today. For the DRAFT-marking/no-signature-affordance half: `RenderL1Summary` is the
only entry in the `renderers` table (`renderersCount = 1`, asserted by
`TestEveryRendererIsReachable`) and `cmd/automat/assess.go` calls `assess.RenderL1Summary`
directly rather than iterating the registry — so today there is exactly one rendering path
and it is the audited one. This is a formality rather than a live gap only because a second
renderer does not exist yet; the moment one is added, whether `assess.go` routes through the
registry or calls a second function directly becomes load-bearing, and is worth a note for
whoever adds Stage 1 or 2's renderer next.

**3. gosec.** Ran `gosec ./...` (wired into `golangci-lint run ./...` per `.golangci.yml`,
confirmed both ways agree: 0 issues from the linter, 2 from gosec run standalone across the
whole tree, both pre-existing and already `//nolint:gosec`-annotated with a stated reason —
`internal/assess/obligation.go:177` and `internal/assess/determinations.go:54`, both G304
"potential file inclusion via variable," both the same accepted shape `internal/artifact.Load`
and `internal/envprofile.Load` already carry: the path is operator-supplied by design, same
trust level as every other document loader in the tree. Nothing new introduced by this
phase's fixes triggered a finding.

**4. Dependency review.** No new dependency this phase — `internal/assess` and
`cmd/automat/assess.go` import only what the rest of the tree already depends on
(`encoding/json`, `internal/artifact`, `internal/evidence`, `internal/safeio`,
`github.com/aws/aws-sdk-go-v2/service/sts`, `github.com/spf13/cobra`), plus
`github.com/santhosh-tekuri/jsonschema/v6` for the two new schema-conformance test files,
which was already a dependency (`go.mod` line 16, used by every other package's own
`schema_conformance_test.go`). Nothing to ratify.

---

## The other findings AUDIT-4 left as ACCEPTED, re-checked against this phase's addition

Per the task's own instruction: re-verify anything AUDIT-4 marked ACCEPTED that this phase's
new code might have invalidated.

**AUDIT-4's L1 (an override can widen a Config-rule parameter past what either input
permitted)** — untouched by this phase. `internal/assess` does not read `internal/compilesets`
or any override file; `assess` computes a determination-based summary from a control
artifact and an obligation profile, not a packed policy set. AUDIT-4's own reasoning for
accepting it (reachable but inert until a Config-read path or `internal/baseline` exists)
is unchanged by anything built here — `assess` does not become that consumer, and none of
Phase 4's new work creates one either. Still accepted, same reason.

**AUDIT-4's M3 (`verify` appends unconditionally, and the per-account manifest has a hard
~8971-record ceiling)** — this phase adds a third writer (`assess`, alongside `vend` and
`verify`) to the same per-account manifest, so the growth-rate math is worth re-running
rather than assumed unaffected. Measured (throwaway probe, mirroring AUDIT-4's own method):
an `OpAssess` record with no determinations reference canonicalizes to 442 bytes; with one,
576 bytes — smaller than `verify`'s own ~935-byte record either way, so `assess` reaching the
8 MiB ceiling on its own would take *longer* than `verify` does (roughly 14,563–18,978
records at `assess`'s size, versus `verify`'s already-measured ~8,971). But `assess` is a
**third** writer on the same manifest, not a replacement for either existing one, so the
ceiling is reached by the *sum* of all three operations' append rates, not by any one of
them in isolation — three writers each appending at their own cadence exhaust the same
8 MiB budget faster than two did, even though `assess`'s own per-record cost is the smallest
of the three. `assess` has no cron-shaped reason to run unconditionally the way `verify`
does (a human decides when to render an assessment; there is no "assess on every account
every 15 minutes" use case analogous to `verify`'s), so in practice its contribution to the
sum is likely to be `vend`-shaped (append-on-event) rather than `verify`-shaped
(append-unconditionally-on-a-timer) — but that is an assumption about how institutions will
actually use the command, not a guarantee the code enforces. AUDIT-4's own three reasons for
accepting M3 rather than fixing it (the ceiling is a safety limit, not a budget to be dodged;
every plausible fix is a policy decision about what the manifest means, not a tuning knob;
a clean record is itself standing evidence, not nothing) all still hold and are not weakened
by a third writer whose own footprint is smaller than the existing two's. **Still accepted,
same reasons, with the sum now measured rather than assumed** — worth a line in whichever
audit eventually revisits M3's rotation/append-on-change-of-finding policy question, since
three writers sharing one ceiling is the shape that question will actually have to answer
for.

No other AUDIT-4 ACCEPTED item touches anything `internal/assess` or `cmd/automat/assess.go`
reads or writes.

---

## CLI surface vs. DESIGN §13

`--account`, `--profile`, `--scope-statement`, `--determinations`, `--out` all match
`docs/assessment-reporting.md`'s own `automat assess` invocation and D7's description
exactly. `--profile`'s "only cmmc-l1 today" restriction is enforced by an exact string
equality (`profileID != "cmmc-l1"`) rather than a prefix or case-insensitive match, so a
typo'd or near-miss profile id (`"CMMC-L1"`, `"cmmc-l1 "`, `"cmmc_l1"`) is refused rather than
silently accepted — checked concretely by tracing the one comparison in
`cmd/automat/assess.go`; there is no second code path that could disagree with it.

**One addition this audit made**: `--evidence-dir` (M2 above), not present when this phase
shipped and not named in `docs/assessment-reporting.md`'s own invocation sketch. Documented
as `docs/cli-surface.md` D8, following the same ratification pattern D2–D7 already
established (a flag §13/the design authority does not enumerate is an addition, not a
contradiction, per the Phase 1 review's standing condition) — folded into `DESIGN.md` §13's
`assess` line and `ROADMAP.md`'s `assess` entry so the addition is visible without diffing
two audits.

---

## For the human

Nothing requires a decision beyond reviewing the five fixes above. No ratification request
this time — M1's added checks strictly tighten `Profile.Validate` (rule 6 already permits an
audit-driven tightening without pre-approval, listed here for ratification per that rule),
and the schema fields themselves did not change, only which Go values now enforce them. L1's
schema addition (`determinations` on an evidence-manifest record) is worth a look since
`evidence-manifest-v1` remains unreleased and this is exactly the kind of pre-publication
change the maintainer has wanted visibility into (schema/CHANGELOG.md's own precedent for
the `OpAssess` addition itself).

**One item flagged for whoever next touches the renderer registry** (clean item 2 above):
`cmd/automat/assess.go` calls `RenderL1Summary` directly rather than iterating
`internal/assess`'s `renderers` table. Harmless today because there is exactly one entry in
it. The day a second renderer (the 800-171A worksheet, Stage 1/2) is added, whichever
function `assess.go` — or its Stage-1/2 sibling command — calls needs to actually route
through the registry, or the DRAFT-marking/no-signature-affordance tests that iterate
`renderers` stop covering what ships.
