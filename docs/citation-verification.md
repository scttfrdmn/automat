# Citation verification queue

A standing list of claims automat renders into human-facing documents that no
test over vendored bytes can check, because they are claims about what an
external authority *currently* says. This is not automat's own record of a
point-in-time finding — it is a queue, meant to survive from one audit to the
next, and to be extended as new profiles ship.

**On this list's provenance.** AUDIT-2 (`audits/AUDIT-2.md`) ran a citation
re-verification pass and reported finding 28 such items, referencing "the
citation pass's output" three times. That output was never committed — it
lived only in the pass's own transcript — and it cannot be reproduced
faithfully after the fact. **This list is a re-derivation, not a recovery.**
It was built on 2026-08 by walking every `citations[]` entry, every
`effective_date`, every revision pin, and every `sources[].uri` across the
five catalogs shipped at that time. That method produced **17** items, not
28. The discrepancy is reported rather than papered over: forcing this list
to 28 to match AUDIT-2's count would be inventing evidence, which is the
exact failure mode AUDIT-2's own F4 finding was about (two independent
transcriptions of the same wrong date agreeing is not correctness).

**Item numbers below do not correspond to whatever the original 28 were.**
Carry an item by the authority and instrument it names, never by number —
AUDIT-2's own numbering note makes the same argument about its own findings.

`TestEveryShippedCitationIsInTheVerificationQueue` (`internal/artifact/
citation_queue_test.go`) asserts every citation in every shipped catalog
appears below by its `id`. A citation that ships without an entry here is a
claim nobody queued for a human to check — the failure mode AUDIT-2's F1
found in `envprofile.ObligationFacts.UnresolvedSources` (a map literal
tracking sources by hand, silently wrong the moment a new one was added).

---

## 1 — DoD class deviation 2024-O0013 pinning NIST SP 800-171 Revision 2

**Highest priority.** This is the *sole* basis, across every profile that
depends on it, for pinning 800-171 **Revision 2** rather than the current
Revision 3.

- **Claim:** the class deviation "notwithstanding 800-171's own revision to
  Rev 3," pinning Rev 2 for DFARS purposes, remains in effect as of the date
  a profile citing it is rendered.
- **Document / field:** `catalogs/obligations/dfars-7012.json`, citation id
  `DoD class deviation 2024-O0013`, `effective_date: 2024-05-02`.
- **Authority:** DoD, Office of the Under Secretary of Defense for
  Acquisition and Sustainment.
- **What would falsify it:** a superseding class deviation, an expiration
  date reached, or a DFARS rule change that adopts Rev 3 directly and
  withdraws the deviation.
- **Why it matters beyond this one document:** if it has lapsed, every
  profile pinned to r2 cites a superseded standard while rendering exactly as
  confidently as a current one — per `docs/audit-ritual.md`'s standing rule,
  that is a medium finding *at minimum*, and it would be one in every
  document that inherits this pin.
- **Last verified by a human:** not yet.

## 2 — 48 CFR 252.204-7021 clause heading and effective date

- **Claim:** the current clause text is set by 90 FR 43560 (DFARS Case
  2019-D041), with an effective date of 2025-11-10.
- **Document / field:** `catalogs/obligations/cmmc-l1.json` and
  `catalogs/obligations/dfars-7012.json`, citation id
  `48 CFR 252.204-7021`, `effective_date: 2025-11-10`.
- **Authority:** Federal Register / DFARS.
- **What would falsify it:** a further DFARS case amending the clause, or an
  effective-date correction in a later Federal Register notice.
- **Note:** this field previously carried the 32 CFR 170 program rule's date
  (2024-12-16) rather than its own — AUDIT-2 F4. The current date is the
  corrected one; re-verification confirms the correction, not the original
  error.
- **Last verified by a human:** not yet.

## 3 — 32 CFR Part 170 (CMMC Program rule) effective date and paragraph split

- **Claim:** 170.14(c)(2) enumerates the Level 1 requirements by reference to
  48 CFR 52.204-21(b)(1)(i)–(xv); 170.14(c)(1) is a numbering convention, not
  a second, different set of requirements. Effective 2024-12-16.
- **Document / field:** `catalogs/obligations/cmmc-l1.json`, citation id
  `32 CFR Part 170`.
- **Authority:** Federal Register.
- **What would falsify it:** an amendment splitting or renumbering
  170.14(c), or a phase-in date superseding 2024-12-16.
- **Note:** this citation exists because an earlier reading conflated the two
  paragraphs into one requirement (AUDIT-2 F2, partly wrong as originally
  reported — see the audit for the correction history).
- **Last verified by a human:** not yet.

## 4 — FAR 52.204-21 current revision date

- **Claim:** the current clause heading reads (NOV 2021), set by 86 FR
  [Federal Register citation in the note], effective 2021-12-06 — not either
  of the two dates a prior draft of this catalog carried.
- **Document / field:** `catalogs/obligations/cmmc-l1.json`, citation id
  `FAR 52.204-21`, `effective_date: 2021-12-06`.
- **Authority:** Federal Register / FAR.
- **What would falsify it:** a further FAR case amending 52.204-21.
- **Last verified by a human:** not yet.

## 5 — DFARS 252.204-7012 full-implementation date

- **Claim:** the full-implementation date for NIST SP 800-171 under this
  clause is 2017-12-31.
- **Document / field:** `catalogs/obligations/dfars-7012.json`, citation id
  `DFARS 252.204-7012`, `effective_date: 2017-12-31`.
- **Authority:** DFARS.
- **What would falsify it:** a superseding DFARS case changing the
  implementation deadline (none is known to exist, but this list does not
  take that on faith).
- **Last verified by a human:** not yet.

## 6 — DFARS 252.204-7019 / -7020 assessment currency window

- **Claim:** a current assessment (within three years) posted in SPRS is a
  condition of award consideration, per both clauses, dated 2020-11-30.
- **Document / field:** `catalogs/obligations/dfars-7012.json`, citation ids
  `DFARS 252.204-7019` and `DFARS 252.204-7020`.
- **Authority:** DFARS.
- **What would falsify it:** a rule change to the three-year window, or a
  restructuring of the assessment tiers.
- **Last verified by a human:** not yet.

## 7 — NIH controlled-access data notices, dates and tranches

- **Claim:** NOT-OD-24-157 is effective 2025-01-25; NOT-OD-25-159 is
  effective 2025-09-24 in three tranches; the stipulation date in
  NOT-OD-24-157 for new/renewed agreements is 2026-02-25; NOT-OD-25-081 is
  effective 2025-03-28.
- **Document / field:** `catalogs/obligations/nih-cadr-dua.json`, citation
  ids `NOT-OD-24-157`, `NOT-OD-25-159`,
  `NOT-OD-24-157 (agreement stipulation date)`, `NOT-OD-25-081`.
- **Authority:** NIH.
- **What would falsify it:** a superseding NOT- notice, or a tranche
  schedule amendment.
- **Last verified by a human:** not yet.

## 8 — NIH Security Best Practices document is silent on 800-171 revision

- **Claim:** the NIH Security Best Practices document states an alignment
  with NIST SP 800-171 but does not state *which revision* — which is why
  this profile does not pin one either (`nih-cadr-dua`'s whole reason for
  existing per its own note).
- **Document / field:** `catalogs/obligations/nih-cadr-dua.json`, citation id
  `NIH Security Best Practices for Users of Controlled-Access Data`.
- **Authority:** NIH.
- **What would falsify it:** a revision to the document that names a
  specific 800-171 revision, which would turn this profile's deliberate
  silence into a stale omission.
- **Last verified by a human:** not yet.

## 9 — Stanford Risk Classifications page has no version or effective date

- **Claim:** the page is a living document with no version, no revision
  history, and no effective date — which is why `date_basis` is
  `retrieved-only` rather than any dated basis.
- **Document / field:** `catalogs/classification/stanford-risk-‑
  classifications.json`, citation id `Risk Classifications`.
- **Authority:** Stanford University IT.
- **What would falsify it:** the page gaining a stated version or effective
  date, which would make `retrieved-only` the wrong basis.
- **Last verified by a human:** not yet.

## 10 — Stanford Minimum Security Standards page states its own instability

- **Claim:** the page states of itself that the standards "will be" revised,
  i.e. it discloses its own volatility; `date_basis` is `retrieved-only` for
  the same reason as item 9.
- **Document / field:** `catalogs/classification/stanford-risk-‑
  classifications.json`, citation id `Minimum Security Standards`.
- **Authority:** Stanford University IT.
- **What would falsify it:** the page being replaced by a dated,
  versioned standard.
- **Last verified by a human:** not yet.

## 11 — UC Classification Standard "Last Updated" date

- **Claim:** the UC Institutional Information and IT Resource Classification
  Standard carries "Last Updated: 8/21/2019" and that is the correct
  `effective_date` basis (`last-updated-in-document`).
- **Document / field:** `catalogs/classification/uc-protection-levels.json`,
  citation id `SC-0002`, `effective_date: 2019-08-21`.
- **Authority:** UC Office of the President.
- **What would falsify it:** a newer "Last Updated" stamp on the same page.
- **Last verified by a human:** not yet.

## 12 — BFB-IS-3 (UC Electronic Information Security) was never retrieved

- **Claim:** BFB-IS-3 is the parent policy the Classification Standard says
  drives it; automat has not retrieved it (retrieval was attempted and
  failed with a TLS error), and the profile records it as unread rather than
  omitting it or guessing its content.
- **Document / field:** `catalogs/classification/uc-protection-levels.json`,
  citation id `BFB-IS-3`.
- **Authority:** UC Office of the President.
- **What would falsify it:** nothing falsifies "unread" — this item's
  disposition is to actually retrieve BFB-IS-3. The citation now carries
  `date_basis: not-retrieved` (F5/Q18, resolved), so the schema has a field
  to record it correctly once that happens; retrieval itself remains
  outstanding.
- **Last verified by a human:** not yet.

---

## Method, stated so the next pass can repeat or extend it

1. For each file in `catalogs/obligations/*.json` and
   `catalogs/classification/*.json`, load `citations[]`.
2. For each citation, record its `id`, `effective_date` (or `date_basis` for
   classification profiles, which use a different dating model), the source
   document and field it lives in, and enough of its `note` to state what is
   being claimed and who the authority is.
3. Do not collapse two citations of the same instrument across different
   files into one entry — `48 CFR 252.204-7021` appears in two catalogs
   (item 2) and is listed once here with both files named, because the claim
   and the falsification condition are identical; a genuinely distinct claim
   about the same instrument would get its own entry.
4. `TestEveryShippedCitationIsInTheVerificationQueue` keeps this list from
   silently falling behind what ships: it fails if a shipped catalog gains a
   citation `id` this document does not mention.
