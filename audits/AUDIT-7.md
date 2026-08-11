# AUDIT-7 — Phase 5 closing, first live-org smoke run (`internal/smoke`)

Adversarial self-audit per CLAUDE.md, "Security audit ritual," and the scope in
`docs/audit-ritual.md`. Conducted 2026-08-10 against the tip of `main` (`a838d69`) —
everything shipped since AUDIT-6: `internal/smoke` (`doc.go`, `findings.go`, `harness.go`,
`smoke_test.go`), the `Makefile`'s `smoke` target, `docs/smoke.md`, `docs/testing-strategy.md`,
and this session's additions to `docs/open-questions.md` recording the first two real runs of
`TestSmokeChecklist` against a live sandbox organization. Renewed scrutiny also fell on
`internal/org/reclaim.go` (`Reclaimer.CloseAccount`, `DetachOwnedPolicies`) and
`cmd/automat/reclaim.go`, in light of what the live run actually observed rather than what
AUDIT-6 assumed: `DescribeAccount` did **not** report `SUSPENDED` within 10 minutes of a
successful `CloseAccount` call, in either of the two real runs.

**Assumptions held throughout.** Everything AUDIT-1 through AUDIT-6 assumed, plus what this
package adds: `internal/smoke` is the first code in this tree that calls real AWS with real
credentials, creating and closing real accounts. It is exempted from CLAUDE.md rule 1 only
because rule 1 exempts it by name (`make smoke`, manual, gated on `AUTOMAT_SMOKE_PROFILE`) —
every line in the package is still held to the same "attacker-controlled input, phished
operator, unreliable network" threat model as everything else, and the history already
includes two real bugs found by running it (a missing `ListPoliciesForTarget` `Filter` field
that broke the harness's own cleanup path, and a `go test` default whole-binary timeout that
killed the suite mid-poll before `t.Cleanup` could run), both of which left real AWS accounts
`ACTIVE`/orphaned and had to be closed by hand. That history is the reason this audit assumed
there would be more, rather than treating two fixed bugs as the end of the list.

## What exists to audit that did not before

`internal/smoke/doc.go`, `internal/smoke/findings.go` (`Finding`, `recordFinding`,
`findingsPath`), `internal/smoke/harness.go` (`Harness`, `newHarness`, `TrackVendedAccount`,
`reclaimAllTrackedAccounts`, `reclaimAccount`), `internal/smoke/smoke_test.go`
(`TestSmokeChecklist` and its eight subtests: Q9, Q12, Q8, Q5, Q6, Q13, Q24), the `Makefile`'s
`smoke` target (env-var gating, `-timeout=30m`), `docs/smoke.md`'s "Status: runnable" section,
and roughly 95 lines of new prose in `docs/open-questions.md` recording what two real runs
against sandbox org `o-mfugj2jrha` actually showed for Q5, Q7, Q8, Q9, Q12, Q13, and Q24.

## Method

This audit did **not** use the worktree-counter-check method AUDIT-2, AUDIT-4, AUDIT-5, and
AUDIT-6 describe (reproduce each finding with a throwaway probe, fix it, then counter-check the
fix in a temporary worktree at the pre-fix commit). That method exists to verify a fix actually
addresses the finding it claims to; this audit is not applying any fix as part of itself —
findings below are reported for the maintainer to triage as FIXED or ACCEPTED, per the standing
ritual, and none has yet been fixed under this audit's own hand. Every finding was independently
re-derived by reading the cited file and line directly (not trusting the dimension reviews' line
numbers or characterizations at face value) and, where a review's claim was refuted by a
verification pass, re-checked here a third time against the literal text before being excluded.
H1's absence of a sibling check and M1's operator-visible text were additionally spot-checked
directly against the source in this pass.

## Result

7 findings survive independent verification: 1 high, 3 medium, 2 low, 1 nit. **0 FIXED, 0
ACCEPTED — all 7 are open, pending the maintainer's disposition**, since this audit did not
apply fixes. One additional claim from the dimension reviews (a characterization of Q9's
`docs/open-questions.md` text as overclaiming) was checked directly against the actual prose and
found not to match — excluded, not reported. Dependency review: no new dependency (see below).
CLI-surface reconciliation: not applicable — no new CLI surface was added by this work;
`internal/smoke` is a test-only package gated behind the `smoke` build tag and is not part of
`cmd/automat`.

---

## High

### H1 — The smoke harness's own cleanup path re-implements `reclaim`'s detach-then-close without the sibling-active-account check AUDIT-6 added specifically to prevent stripping a live account's guardrails

`internal/smoke/harness.go:169-222`, `Harness.reclaimAccount`. This is the function
`reclaimAllTrackedAccounts` (called from `newHarness`'s `t.Cleanup`, `harness.go:138`) uses to
detach and close every account the suite vends. It resolves the account's parent OU (`target`,
line 178), lists every SCP attached to `target`, and unconditionally detaches every one tagged
`automat:managed-by=automat` (lines 189-208) — with no analog to
`internal/org.Reclaimer.DetachOwnedPolicies`'s `activeSiblings` check
(`internal/org/reclaim.go:220-258`), the fix AUDIT-6 C1 landed for exactly this failure mode: an
SCP is attached at the OU, not the account (DESIGN §5, §8), so more than one account can share
it, and detaching it to reclaim one strips guardrails from every other account still sitting
under that OU.

**Failure scenario:** `smoke_test.go` moves both the Q9 account (line 118, into `ou`) and the Q8
"deliberately untagged" account (line 194, into the same `ou`) into `AUTOMAT_SMOKE_OU`. Both are
tracked via `h.TrackVendedAccount` (lines 109, 189) and cleaned up only through
`reclaimAllTrackedAccounts` → `reclaimAccount`. If a real sandbox operator's `AUTOMAT_SMOKE_OU`
is ever the same OU (or a parent of an OU) that holds another, non-throwaway account — plausible
in a sandbox org that is not freshly created for each run, which is exactly the kind of org an
operator re-uses across sessions rather than tearing down — `reclaimAccount`'s cleanup for one
tracked account silently detaches the shared SCP and strips that other, live account's
guardrails, with no warning printed and nothing recorded beyond a generic `t.Logf` on
`reclaimAllTrackedAccounts`'s own error path (which does not even fire here, since detach and
close both report `nil` error in this scenario — the sibling losing its SCP is not an error at
all from this function's point of view). Compare to production's `VerbUnchanged` reporting
(`reclaim.go:174-186`), which names the live sibling and refuses the detach outright; the smoke
harness has neither the refusal nor the disclosure.

**Recommended fix:** either give `Harness.reclaimAccount` its own sibling check mirroring
`activeSiblings`, or — simpler, and consistent with the harness's own doc comment's reasoning
for not reusing `org.Reclaimer` (it must "always apply" without a plan/apply gate) — have it call
`org.Reclaimer.DetachOwnedPolicies` directly in `ModeApply` rather than re-implementing
detach-then-close by hand; the plan/apply distinction the doc comment objects to is orthogonal to
the sibling check, which `Reclaimer` performs regardless of mode.

---

## Medium

### M1 — `Reclaimer.CloseAccount`'s own success text, and every downstream consumer of it, claims an AWS closure timeline the live run has now falsified

`internal/org/reclaim.go:283-285`. The literal string stored in `Action.Detail` on a successful
`CloseAccount` call is: *"close requested. AWS closes accounts asynchronously — it may report
SUSPENDED only after a few minutes."* `Action.String()` includes `Detail` verbatim in its
rendering, and `cmd/automat/reclaim.go:179` prints this text to the operator on every successful
apply via `renderActions(out, "\nApplied:", apply.Actions())` — confirmed directly against the
source in this pass.

**Failure scenario:** an operator runs `reclaim --yes`, reads "may report SUSPENDED only after a
few minutes," and — reasonably, since this is the tool's own claim — checks `DescribeAccount` a
few minutes later, or scripts a follow-up check on that timeline. This session's own live run
(`docs/open-questions.md` Q24) recorded the account still `ACTIVE` at the 10-minute mark in both
runs, reaching `SUSPENDED` only "sometime shortly after" that, confirmed by a manual check
minutes later still. The tool's own printed claim is now known to be wrong by at least an order
of magnitude for at least one real organization, and nothing about `CloseAccount`'s
implementation changed in response — the text an operator reads on every successful reclaim is
unchanged.

**Recommended fix:** widen the printed detail to something that does not name a duration
contradicted by observation — e.g. "AWS closes accounts asynchronously; propagation to SUSPENDED
has been observed to take longer than 10 minutes" — or drop the specific timeframe entirely and
point at `docs/reclaim-design.md`/`docs/open-questions.md` Q24 for what is actually known.

### M2 — The persisted `OpReclaim` evidence record cannot distinguish "AWS accepted the close request" from "the account is actually closed," and the doc that justifies the record's shape asserts the stronger claim as its premise

`cmd/automat/reclaim.go:300-365`, `writeReclaimEvidence`. `applyErr == nil` (i.e., `CloseAccount`
returned without error) unconditionally produces `Outcome: evidence.OutcomeSuccess`; there is no
field in `evidence.Record` available on the success path to carry a caveat distinguishing
"request accepted" from "closure confirmed" — the only free-text field for qualifying an outcome,
`RecordError`, is populated only in the `applyErr != nil` branch. The distinction exists only as
a Go source comment, never serialized into what the schema
(`schema/evidence-manifest-v1.schema.json`) actually persists. `docs/reclaim-design.md` states as
a premise, at exactly the call site that justifies not closing the manifest chain: *"the subject
the manifest is about no longer exists in AWS."* The live run shows the account was still
`ACTIVE` for 10+ minutes past that exact call — the doc's stated premise is empirically false at
the moment it is invoked to justify the record shape.

**Failure scenario:** an auditor reads an `OpReclaim` / `OutcomeSuccess` record months later and,
per DESIGN §11's own chain-of-custody purpose, takes it as evidence the account was closed at the
recorded timestamp. For a window of at least ten-plus minutes after that timestamp, the account
was still `ACTIVE` in AWS — a compliance claim ("this account no longer exists") is being made
about a state the tool never actually observed, only requested.

**Recommended fix:** either add a field to `RecordError`-adjacent structure (or a new optional
field on `Record`/`Target`) that can carry "request accepted, closure not confirmed" on the
success path too, not only the failure path; or have `reclaim` poll `DescribeAccount` for
`SUSPENDED` (bounded, with a timeout) before writing the success record, and write a distinctly
different, still-honest record ("close requested, not yet confirmed by AWS") if the poll times
out rather than treating that as equivalent to a confirmed close.

### M3 — `docs/smoke.md`'s Phase-1-review-mandated Q8 tag-write audit was never implemented, and nothing in the session's Q8 findings discloses that the write-side check is still missing

`docs/smoke.md` states, as a standing requirement carried from the Phase 1 review: *"When Q8 is
tested, test the write side in the same run: confirm from the sandbox that the delegate cannot
apply `automat:vended-by` to an account or policy outside its namespace."* Grepping
`internal/smoke/*.go` and `docs/open-questions.md` for `TagResource` returns nothing.
`Q8_ResourceTagHonored` (`smoke_test.go`) and the Q8 entry in `docs/open-questions.md` discuss
only `MoveAccount`'s read-side condition (whether the move is denied); neither the test nor the
documentation mentions attempting a `TagResource` call at all.

**Failure scenario:** a maintainer reading `docs/open-questions.md`'s Q8 entry after this
session's run reasonably believes "the smoke run tested what `docs/smoke.md` says to test" — but
the specific write-side check `docs/smoke.md` calls out by name (and which Phase 1's own review
made a condition, per that same rule: "a condition that binds correctly while the principal can
write the tag it reads is not a control") never ran and is not disclosed as skipped. Q8 remains
marked "still open" for the read side, but the write side isn't even tracked as a remaining gap —
it has silently fallen out of the record entirely.

**Recommended fix:** either implement the `TagResource` write-side check as its own smoke subtest
(under the brokered vendor-role credential, same prerequisite Q8's read-side check already names
as blocking), or add an explicit line to the Q8 entry in `docs/open-questions.md` disclosing that
the write-side half of `docs/smoke.md`'s own rule was not exercised this run.

---

## Low

### L1 — `Harness.reclaimAccount`'s pagination loops have no page cap or duplicate-token guard, unlike every other pagination loop in `internal/org`

`internal/smoke/harness.go:180-214` (the `ListPoliciesForTarget` loop) is a bare `for {}` whose
only exit condition is an empty `NextToken`. The inline `ListTagsForResource` call is worse: it
is not paginated at all — exactly one call, no loop, no `NextToken` read. Contrast every
equivalent loop in `internal/org/reclaim.go`: `attachedPolicies`, `activeSiblings`, and
`policyOwnership` all bound iteration with `listPageCap` (`internal/org/ensure.go`, 500) and track
`seen[token]` to error loudly on a repeated token rather than loop forever.

**Failure scenario:** this loop runs inside `t.Cleanup`, which `go test` waits on before the
process can exit. A pathological or misbehaving `NextToken` sequence (AWS-side bug, or a very
large number of policies on a long-lived shared OU) hangs cleanup with nothing bounding it except
the `Makefile`'s blunt process-level `-timeout=30m` — which kills the whole suite, not just this
loop, and does so without running any of the cleanup for accounts later in `h.vendedAccounts`.
Separately, the un-paginated `ListTagsForResource` call means a tag landing on an unread second
page (if `ListTagsForResource` for a heavily tagged policy is ever paginated by AWS) would make
`owned` come back false for a genuinely automat-owned policy, leaving it attached — the opposite
of the hang risk, but the same root cause.

**Recommended fix:** apply the same `listPageCap` + `seen`-token pattern already established in
`internal/org/reclaim.go` to both loops in `harness.go`, and add the missing pagination loop
around `ListTagsForResource`.

### L2 — `recordFinding`'s errors are silently discarded at every call site, with no upfront writability check, so a real run can complete with zero recorded findings and no diagnostic

`internal/smoke/findings.go:67-82`, `recordFinding`, returns an `error` from `os.OpenFile`/
`file.Write`. Every one of its eleven call sites in `smoke_test.go` discards that error
(`_ = recordFinding(...)`), and nothing in `newHarness` probes `findingsPath()` for writability
before the run starts.

**Failure scenario:** `AUTOMAT_SMOKE_FINDINGS` points at a path in a directory that does not
exist, or that the running user cannot write to (a typo, a stale path from a previous
environment, a read-only mount) — every `recordFinding` call fails silently, `t.Logf` never fires
for it, and the entire point of the run (per `docs/smoke.md` rule 4: "the output of a smoke run
is an edit to `docs/open-questions.md`... a run that only reports pass/fail has wasted the one
thing a live org provides") is lost without a single diagnostic printed. Given that every account
this suite vends is real and gets closed by the end of the run, this is a real AWS org mutated
for observations that then evaporate unnoticed.

**Recommended fix:** either log the discarded error via `t.Logf` at each call site, or — more
robust to the "eleven call sites" problem — probe `findingsPath()`'s writability once in
`newHarness` and fail fast if it is not writable, the same "check the precondition once, up
front" pattern the harness already applies to `AUTOMAT_SMOKE_PROFILE`/`AUTOMAT_SMOKE_ORG`.

---

## Nit

### N1 — `TestMakefileSmokeClaimIsStillTrue` checks that the smoke tag exists and that a fixed sentence is absent from the Makefile, but never checks that the Makefile's `-run 'Smoke'` regex actually matches an exported test name in the tagged files

`internal/artifact/smoke_claim_test.go`. The test walks the tree for `//go:build smoke`
(confirming at least one file carries the tag) and greps the `Makefile` for the literal sentence
"No test in this tree carries the smoke build tag" (confirming that sentence's presence/absence
tracks the tag's presence/absence). It never parses the Makefile's `-run 'Smoke'` flag and
confirms that pattern actually matches an exported `Test*` function name in a smoke-tagged file.

**Failure scenario:** `TestSmokeChecklist` is renamed to, say, `TestLiveOrgChecklist` (a change
that would keep the `//go:build smoke` tag present, so `TestMakefileSmokeClaimIsStillTrue` would
still pass) — `make smoke`'s `-run 'Smoke'` then matches zero tests, `go test` exits 0, and the
target silently runs nothing again, which is the exact class of defect this test was written to
prevent. The test currently guards against the tag disappearing but not against the run-pattern
and the actual test name drifting apart while the tag stays present.

**Recommended fix:** extend the test to also extract exported `Test*` function names from every
smoke-tagged file and assert at least one matches the Makefile's `-run` pattern (a regex match
against `'Smoke'`, mirroring what `go test -run` does).

---

## Checked and found clean

**1. The Q9 live-run text's framing.** One dimension review characterized the Q9 entry
(`docs/open-questions.md`) as overclaiming a "new discovery." Read directly: the actual sentence
is *"Confirmed instead: `CreateAccount` really does land a new account at the organization
root... which is the premise the whole question rests on"* — this explicitly frames the
observation as verifying an existing premise, not announcing a new one. The review's
characterization does not match the text as written; not reported as a finding.

**2. AWS's own `AccountAlreadyClosedException` handling (AUDIT-6 M1) under the light of this
run.** This fix is unrelated to the timing gap M1 (this audit) reports — it addresses re-running
`reclaim` against an account already reported closed by AWS, a distinct concern from whether
`DescribeAccount` promptly reflects a fresh close. No interaction found between the two.

**3. `docs/testing-strategy.md`'s claims about `internal/smoke`.** Traced the page's description
of the package against the actual gating (`AUTOMAT_SMOKE_PROFILE`/`AUTOMAT_SMOKE_ORG` required,
never in CI) and found it accurate — no drift between what the doc claims `make smoke` does and
what the Makefile/`newHarness` actually enforce.

**4. `KMSSigner`/evidence-signing interaction with `reclaim`.** `writeReclaimEvidence`'s signer
plumbing is unchanged from AUDIT-6's audited shape; nothing in this session's smoke work touches
it, and no new call site was found.

**5. Dependency review.** No new dependency introduced by `internal/smoke`, the Makefile change,
or any doc change this session. `internal/smoke` imports only `github.com/aws/aws-sdk-go-v2`
service packages already pre-approved under CLAUDE.md's blanket ratification (AUDIT-1), plus
`testing` and stdlib. Nothing new.

---

## CLI surface

Not applicable. No new CLI surface was added by this work — `internal/smoke` is a test-only
package behind the `smoke` build tag, invoked only via `make smoke`/`go test -tags=smoke`, never
through `cmd/automat`. `docs/cli-surface.md` requires no reconciliation this audit.

---

## For the human

Seven open findings, none fixed by this audit (by design — this was a report-only pass, not a
fix-and-counter-check one). Ranked by what's most load-bearing to decide first:

- **H1** is the one with the sharpest blast radius if a real operator's sandbox ever has more
  than one account under the smoke OU — recommend fixing before the next live run rather than
  accepting, since the harness's own doc comment already explains why it diverges from
  `org.Reclaimer` and the sibling check is orthogonal to that reasoning.
- **M1 and M2** are two faces of the same underlying gap (`CloseAccount`'s "done" claim is weaker
  than what's printed/recorded) — worth deciding together, since the fix for one likely informs
  the fix for the other (a bounded poll would address both).
- **M3** is a process gap (a Phase-1-review-mandated check that never got built) rather than a
  code defect — worth a maintainer decision on whether to build the write-side check now or
  explicitly re-scope Q8 to disclose it's still missing.
- **L1, L2, N1** are all "this code doesn't hold itself to the standard the rest of the tree
  already established" — straightforward to fix, low urgency given the package's own gating.
