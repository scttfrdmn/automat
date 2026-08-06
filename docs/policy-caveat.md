# The policy caveat

This page holds the canonical wording of one paragraph. It is short, and it is the most
load-bearing prose in the repository.

## Why it is a test, not a convention

automat encodes readings of published policy — notice numbers, clause numbers, effective
dates, which determination values a regime permits, whether a POA&M is allowed. Those
readings are technical, they are made by engineers, and they are made at a point in time
against documents that change. A tool that renders them into a document an institution
acts on has to say what kind of claim it is making, every time, in the rendered output —
because the rendered output is what gets forwarded, printed, and attached to an
agreement, usually without whatever page explained the caveat.

So the caveat is held the same way the onboarding bundle's blast-radius argument is held
(`TestREADMEMakesTheBlastRadiusArgument`): as rendered words, asserted by a test. A
caveat that lives in a contributor's memory is one a refactor drops silently, and the
failure is invisible — the document still renders, still looks authoritative, and no
longer says what it is.

## Canonical wording

> automat encodes a technical reading of published policy. It is not legal advice and not
> a compliance determination. The agreement, award terms, or contract clause your
> institution signed governs; your sponsored programs office, contracts office, or counsel
> decides what applies and which revision. Where policy is ambiguous — for example the NIH
> 800-171 revision question — automat records the operator's declaration rather than
> resolving it. Policy citations carry effective dates and change; verify against the
> primary source before relying on them.

## Where it must appear

- `README.md` and `DESIGN.md`, prominently.
- **Every obligation profile** (`schema/obligation-profile-v1.schema.json` makes the field
  required, so a profile without one is not a valid profile).
- **Every `assess` output**, alongside the `DRAFT — NOT A SUBMISSION` marking
  (`docs/assessment-reporting.md`, invariant 1). The two are different claims and neither
  substitutes for the other: DRAFT says *this document is not finished*, the caveat says
  *this document is not a legal conclusion*. A finished document can still not be a legal
  conclusion, which is exactly the case that matters.
- **Every classification profile.** `schema/classification-profile-v1.schema.json` makes
  the field required for the same reason: a classification profile is a reading of an
  institution's own published policy, which moves at least as fast as federal policy and
  is not versioned by anybody. Held by `requiredCaveatSubstance` in
  `internal/classprofile/catalog_test.go`.

"In substance" rather than verbatim: renderers wrap text differently and a worksheet cell
is not a prose paragraph. What is asserted is the substance, as a phrase list — see
`requiredCaveatSubstance` in `internal/artifact/obligation_profile_test.go`, restated in
`internal/classprofile/catalog_test.go` for the profiles that package owns. Each phrase in
that list is there because dropping it changes what the paragraph claims:

| Phrase | What is lost without it |
|---|---|
| `not legal advice` | The reader may treat an engineering reading as counsel's |
| `not a compliance determination` | The document reads as the determination it is an input to |
| `governs` (of the signed instrument) | automat's model appears to outrank the actual agreement |
| `sponsored programs` / `counsel` | No named human owns the decision, so the tool implicitly does |
| `records the operator's declaration` | Ambiguity looks resolved rather than deferred |
| `verify against the primary source` | A citation's staleness becomes the reader's surprise |

## What the caveat does NOT cover, and what does

The caveat says a citation may be stale. It does not say a citation was never checked
against bytes, and those are different claims — the first is a warning about time
passing, the second is about a claim nobody has verified at all.

An obligation profile records its provenance in `sources[]`, and an all-zero `sha256`
there means "recorded from the published identifier, not from a retrieved copy." That
fact reaches the rendered output: `envprofile.ObligationFacts.UnresolvedSources` carries
it from the resolver to whatever renders, and `vend` marks the citation on the birth
certificate. AUDIT-2 found the discipline previously held by a map literal inside a test
function, which no renderer could consult and which could not fail — so two profiles were
being cited by hash on a document an operator files, with nothing saying their own
citations were unretrieved.

## Standing obligation

At every phase gate, each obligation profile's citations and effective dates are
re-verified against the primary source, and every claim automat renders into a
human-facing document is traced to a hashed source. **A stale legal citation is an audit
finding, ranked no lower than medium.** In CLAUDE.md's audit ritual, so it recurs rather
than depending on someone remembering this page exists.
