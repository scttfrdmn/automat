# ROADMAP — automat

Phases are ordered so the compatibility contract (schema) exists before anything consumes it, and so every phase ends with something demonstrable. Each phase = tagged milestone.

## Phase 0 — Contract first: schema + catalogs
- JSON Schemas: control artifact, profile, evidence manifest (`schema/`), with Go types, canonicalization, content hashing, round-trip tests.
- `gen/`: compile CMMC L1 catalog from NIST/FAR OSCAL sources joined with the AWS Config CMMC L1 conformance-pack mapping; record source hashes. Vendor output to `catalogs/cmmc-l1.json`.
- Same pipeline for `800-171r2` and `800-171r3` (enforcement mappings may be partial — mark unmapped controls `procedural` with a TODO provenance note rather than dropping them).
- Baseline-protection control set as data (`catalogs/baseline-protection.json`).
- **Accept:** `automat compile --sets cmmc-l1 --out a.json` validates, hashes deterministically; golden files for all three catalogs.

## Phase 1 — Preflight + onboarding bundle
- `login` (SSO device flow via ssooidc + credential chain), `preflight` (three-state machine, quota + permission report with SCP-caveat wording), `setup --request` (onboarding bundle: delegation policy, vendor role CFN + TF, README).
- **Accept:** golden-file tests for bundle output; fake-backed preflight covers all three states and the "member with vendor role" variant.

## Phase 2 — Vend (management + standalone paths)
- `init` (CreateOrganization ALL + research OU), `vend` end-to-end in MANAGEMENT state: create → poll → move → SCP ensure (control + region + service + baseline-protection) → assume into child → recorder/delivery channel/conformance pack → attestation stubs → evidence manifest.
- SCP packer: quota-aware (5-per-target, size limits), deterministic output, golden-tested.
- Resumable requests (`--resume`), parked-account handling.
- **Accept:** full vend pipeline runs against fakes with every step idempotent (run twice = no diff); manifest chain validates.

## Phase 3 — Brokered vend (the university path)
- `broker/`: vendor-role assumption with ExternalId; vend flow in MEMBER state mixing brokered (create/move/OU) and delegated (policy) credentials.
- `setup` (MANAGEMENT side): apply delegation policy + create vendor role for a named member account.
- Nested OU creation within depth limits.
- **Accept:** fake-backed MEMBER vend; failure modes (unassumable role, missing delegation) produce actionable remediation text naming the exact missing grant.

## Phase 4 — Verify + union hardening
- `verify` per DESIGN §12 (policy/detective/procedural layers, findings vs drift distinction, enforcement-class breakdown, cron-friendly exit codes).
- **`verify`'s result is a structured value; the printed report renders from it.** Per control: enforcement classes exercised, the resource actually observed (SCP ARN, rule name, attestation path), observation timestamp, and the artifact id + `content_sha256` checked against. `assess` (below) consumes this rather than re-deriving it — two code paths computing the same compliance claim is how one tool starts disagreeing with itself. See `docs/assessment-reporting.md`, "What this requires of `verify`"; nothing here needs the assessment schema to exist, only for `verify` not to throw its evidence away.
- Union semantics complete: crosswalk dedupe, parameter partial orders, conflict reports + override files; property tests (idempotent/commutative/associative/monotone).
- `list` (tag-driven inventory incl. parked accounts).

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

- **Accept (phase):** property suite green; `verify` golden reports for compliant / drifted / findings-only scenarios; `assess` acceptance above.

## Phase 5 — Polish + lifecycle
- `reclaim` design + implementation (closure rate limits, plan/apply, `--yes`).
- KMS signer for evidence manifests.
- Docs site content: conventions.md, security-review.md ("the 60-line review" for central IT), beyond.md.
- Manual smoke-test runbook against a sandbox org; capture answers to `docs/open-questions.md` (delegation visibility, quota edges).
- **Re-verify `docs/vs-control-tower.md` against the implemented feature set before v1.** That page is human-owned positioning: its judgments stand as written, but every factual claim it makes about what automat does must be traced to shipped code and corrected if the implementation diverged. A positioning claim that outruns the code is the one kind of inaccuracy this project cannot afford.
- **Accept:** a stranger with a standalone AWS account can go README → init → vend → verify without asking a human anything.

## Deferred / explicitly out of scope for v1
- Approval-per-vend request queue.
- Continuous monitoring, dashboards, agents.
- HIPAA / 800-53 catalogs (pipeline should make them data-only additions; pick the blessed HIPAA crosswalk before generating).
