# Institutional classification profiles

**Status: implemented as a document type. `schema/classification-profile-v1.schema.json`,
`internal/classprofile`, and two derived examples in `catalogs/classification/`.** The
environment profile's reference *to* a level is deliberately not built yet — see "What is
not here yet". This page is the argument for the format; ROADMAP.md carries the
deliverables and `schema/CHANGELOG.md` carries the field-by-field reasoning.

> automat encodes a technical reading of published policy. It is not legal advice and not a
> compliance determination. The agreement, award terms, or contract clause your institution
> signed governs; your sponsored programs office, contracts office, or counsel decides what
> applies and which revision. Where policy is ambiguous — for example the NIH 800-171
> revision question — automat records the operator's declaration rather than resolving it.
> Policy citations carry effective dates and change; verify against the primary source
> before relying on them. (`docs/policy-caveat.md`.)

## The sentence this exists to make true

> *This account is rated for P4 – High.*

That is the sentence `vend` is ultimately built to print, and it is not automat's idiom —
it is the one institutions already use. Harvard's FASRC rates Cannon for DSL1–2 and routes
DSL3 work to FASSE, and has no DSL5 systems at all. Stanford's Yen is Low/Moderate, with
other systems for High. A researcher asking "where can I put this data" is asking which
resources are rated for their level, and the answer is a property of the resource,
published in advance, by the institution.

A tool that vends accounts is producing exactly that kind of resource, so it needs the
vocabulary. **The vocabulary is the whole deliverable.** Everything else on this page is
about the ways a tool can get that vocabulary wrong.

## Why this is publishable rather than a local convention

The honest starting point is a negative result. HEISC's *Data Classification Toolkit*
(EDUCAUSE/Internet2) is a compiled reading list, **last reviewed July 2015** — a set of
pointers to member institutions' own policies, not a normative model. There is no
community-consensus level scheme to defer to.

That absence is the justification. A generalized model is worth publishing precisely
because nothing occupies the slot, and because the alternative to a published format is
what already exists: every institution's scheme legible only to itself, and every tool
that wants to be portable across them either hardcoding one or assuming four levels.

The adjacent groups are live even though the toolkit is not. The EDUCAUSE HEISC 800-171
Compliance Community Group (~600 members) has published a NIST SP 800-171 Toolkit. The
Regulated Research Community of Practice runs SSP workshops and tracks NSPM-33. HECVAT is
the governance precedent worth studying — EDUCAUSE + Internet2 + REN-ISAC, 2016, unified
into a single framework in 2025, replacing scattered per-institution spreadsheets with one
artifact everybody fills in once. And data classification is openly acknowledged as an
unfinished community problem; the UW-Madison survey and peer-policy gap analysis in
*EDUCAUSE Review* (2025) is the current statement of that.

**These context claims are not hashed sources, and that distinction is load-bearing.**
They are recorded here as this project's understanding of the landscape, gathered while
scoping the work. The two *documents automat ships readings of* carry retrieval dates and
sha256 hashes over the exact bytes read, because a profile makes claims about what a policy
says. This section makes claims about what a community is doing, which is a weaker kind of
claim, and marking it as such is cheaper than dressing it up. If any of it turns out to be
wrong, the correction is a paragraph here; if a *citation in a profile* turns out to be
wrong, that is an audit finding ranked no lower than medium (`docs/audit-ritual.md`).

## The six-institution sample

The model was not designed and then validated. It was derived from six published schemes,
and every requirement below exists because at least one of them would break a simpler
model.

| Institution | Levels | Names | Notable |
|---|---|---|---|
| **UC** (IS-3 / SC-0002) | 4 | P1–P4, numeric **ascending** | 350+ controls, in a *different document*; a separate Availability axis A1–A4; determination by Proprietors with Security SMEs and Unit Information Security Leads |
| **Harvard** | 5 | DSL 1–5, ascending | **Two layered policies** — enterprise HEISP plus a research overlay HRDSP — sharing one classification table |
| **Stanford** | 3 | Low / Moderate / High | Each level has its own Minimum Security Standards, split by endpoints / servers / applications |
| **U-M** | 4 | Restricted / High / Moderate / Low — **the top is first and the names run downward** | Mapped onto NIST directly (Restricted ≈ NIST Moderate), with per-data-type templates (FISMA, HIPAA, CUI) |
| **MIT** | 3 | Low / Medium / High | |
| **Georgia Tech** (SGA IT Board) | 5 | adopted wholesale from Harvard | Forking is already happening in the wild, without a format |

Two of these are shipped as derived profiles (UC and Stanford, with hashed sources); the
other four are recorded here as the research that shaped the schema. **U-M and Harvard are
also both Go test fixtures**, for one specific reason given below.

Georgia Tech is the row that most argues for a format. An institution adopting another's
scheme verbatim is the exact operation a format makes reviewable and an ad-hoc copy makes
invisible — and it happened before anybody offered them a format.

## The model, and the test that holds each part

Every requirement is a test rather than a paragraph. The paragraph is here; the test is
what survives a refactor.

### Level count varies. Never assume four.

3, 4, and 5 all occur in the sample, and there is no reason to think 6 will not.
`TestLevelCountVariesAcrossTheSample` asserts the fixture set spans all three, and
`TestTheSampleSpansTheLevelCountsAndBothNamingDirections` asserts the two *shipped*
documents differ in count. A model validated only against four-level schemes would have
looked complete.

### Ordering is an explicit required integer rank. Never inferred from labels.

`rank` is required, integer, and must form a **dense run starting at 1** — no gaps, no
duplicates, no implicit ordering from array position or from the label. Sorted by label,
U-M's scheme reads High, Low, Moderate, Restricted: the second-most-protective level sorts
to the top of the list and the most protective sorts to the bottom. Harvard's DSL1–5 sorts
correctly by label and would make any label-derived ordering look like it worked.

So both are fixtures, and `TestLabelOrderIsNotRankOrder` asserts the *disagreement*
directly: U-M's label order must not equal its rank order, and Harvard's must. A test that
only checked Harvard would pass on a broken implementation.
`TestRankMustBeExplicitAndDense` covers the four ways a rank set goes wrong (absent,
duplicated, gapped, starting above 1), and `TestHighestReadsRanksRatherThanPosition` pins
that `Highest()` reads ranks rather than taking the last element.

Dense-and-from-1 is stricter than the sample strictly requires, and it is the right
strictness: a gap means either a level was dropped in transcription or the scheme has a
level the profile is not stating, and both are things to fix rather than encode.

### Highest water mark, which is the union law on a different lattice

Every scheme in the sample shares one composition rule. An element meeting two definitions
takes the higher; a dataset takes the highest level of any element it contains; deliberate
over-classification is permitted and documented.

DESIGN §9 states the same principle for control sets. Written out as one line — the
sentence `CompositionRuleAssociates` exports so a reader meets it at the point of use:

> union of controls · intersection of permitted behavior · join of classification levels

Three operations, one law: **the stricter reading wins, so composing inputs can never
relax what any single input required.** `compile` holds idempotence, commutativity,
associativity, and monotonicity as property tests over control sets; `Join` holds the same
four over levels, in `TestJoinHoldsTheUnionLaws`, across all three fixture shapes. It is
the same algebra on a total order, and saying so is not decoration — a reader who has
already understood the control-set law should not have to work out that this is not a
second, possibly-inconsistent one.

`Join` refuses a cross-institution comparison rather than answering it
(`UnknownLevelError`, `TestJoinRefusesACrossInstitutionComparison`). P3 and Moderate are
not comparable, there is no correct answer, and the wrong kind of helpfulness here is a
crosswalk automat invented.

### Institutional schemes route to external obligations; they do not replace them

U-M maps its levels onto NIST. Stanford's High Risk standards say "Implement PCI DSS,
HIPAA, FISMA, or export controls **as applicable**."

That "as applicable" is the entire modeling problem. The source names a regime; it does not
say the regime applies to you. So `external_obligations[]` carries a single relation value
— `informational-reference` — and a required `declared_by_operator` flag, and there is **no
automatic composition** with an obligation profile. The operator declares which obligations
apply. Anything else is automat concluding that a regime binds an institution on the
strength of a policy page listing it as an example.

The UC profile shows the other half of the same discipline. Its P4 examples name protected
health information, credit card data, and CUI — and they are recorded as `examples`,
because that is what the source calls them, and **not** as external obligations. Reading a
routing rule out of an example list would convert "UC lists this as a kind of P4 data" into
"UC states that this regime applies at P4".

### Profile-to-profile inheritance within one issuer

Harvard's enterprise policy and its research overlay share one classification table. That
is `inherits{profile_id, issuer_id, relation}`, with `relation` closed to `overlays` and
`shares-levels-with`, and validated to require the **same issuer**: an overlay is an
institution layering its own policy, not an institution inheriting another's. Cross-issuer
adoption — the Georgia Tech case — is a fork, which is a different and more honest
operation: you copy the document, put your own name on it, and attest to it yourself.

### automat never classifies data

There is no matcher, no trigger expression, and no evaluable form anywhere in this document
type. `determination.automat_determines` exists as a field and is pinned `false` at both
layers, so a profile cannot opt into the tool deciding. Determination is a human role the
profile *names* — UC's Proprietors, Security SMEs, and Unit Information Security Leads;
Stanford's data owner — together with the process, cited.

The absence is enforced structurally rather than by review.
`TestNoShippedProfileCarriesAMatcherOrTriggerExpression` walks every key and every scalar
in the raw JSON of every shipped document, refusing predicate syntax (`&&`, `==`, `=~`,
`${`, `{{`, `regex:`, …) and about twenty-six field names a match language would plausibly
arrive under (`matcher`, `pattern`, `trigger`, `predicate`, `classify`, `detect`,
`infer`, …). Its failure message says what to do: **if a match language is taking shape
here, stop and flag it.**

The reason is not squeamishness. An automated "this dataset is Level 4" would be wrong in
the *permissive* direction exactly when it matters most — the hard cases are hard — and it
would be believed, because it came from a tool that is right about everything else. Level
selection for a vended account is an operator determination, recorded and hashed like any
other.

`levels[].examples` is a bounded reading aid for a person, exactly as an obligation
profile's `applicability.hints` are: capped, prose, and never consulted by code.

### Unmodeled axes are disclosed, not omitted

UC classifies on two independent axes: Protection (P1–P4) and Availability (A1–A4). This
document type models one, because a Protection Level is what an account is rated for. So
the UC profile carries an `unmodeled_axes` entry saying so, cited.

Recording the omission matters more than it looks. To a reader who knows the Standard, four
levels and no availability axis reads as an incomplete transcription; to a reader who does
not, it reads as though UC classifies on one axis. And the two axes are *not* parallel in
the place it matters: a Proprietor may not lower a Protection Level outside the named
exception process, but the Standard says explicitly that a Proprietor **may** select a
lower Availability Level than the guide specifies. An implementation that treated
availability as another instance of this axis would carry that permission across and be
wrong in the permissive direction.

## Provenance: automat is the interpreter, never the author

**The provenance honesty is the point of shipping derived profiles at all.** A profile in
`catalogs/classification/` is automat's reading of somebody else's published policy. The
institution has authored nothing, reviewed nothing, and endorsed nothing.

Four mechanisms, each test-guarded:

**1. Every claim traces to a cited section of a hashed source.** Every level, control,
composition rule, obligation reference, and unmodeled axis carries a `CitationRef` naming a
`source_id` that must resolve to an entry in `sources[]`, each of which carries a title,
retrieval timestamp, and sha256 over the bytes actually read. `TestEveryShippedClaimTracesToACitedSection`
additionally requires the `section` to name a *locator* — a number, a structural word, or a
heading plus a sub-locator — and rejects generic gestures like "the policy" or "see above".

**2. Where the source is silent, the profile is silent.** The UC profile states **zero
controls at every level**, and that is not an unfinished transcription. SC-0002 defines the
levels and the classification process and defers the controls to BFB-IS-3 — a document
automat has not retrieved (retrieval was attempted and failed on a TLS error) and therefore
makes no claim about. The sample row above says UC has 350+ controls; they exist, and they
are not in the document that was read.

Filling those empty lists with sensible-looking controls would silently convert "UC's
policy says" into "automat thinks UC should say", and that is a finding, not a nice touch.
`TestWhereTheShippedSourceIsSilentTheShippedProfileIsSilent` names it as the most tempting
mistake available in this package and fails if anyone makes it. The same test fails if
Stanford's 75 controls are ever dropped, because Stanford is the only shipped example of
controls that genuinely came from the source.

`levels[].controls` therefore rejects a present-but-empty array at both layers. `[]` claims
the source was consulted and stated no controls; an absent field declines to claim
anything; the two render identically to a reader, so only one of them is allowed to be
written.

**3. The non-endorsement statement is required and asserted in substance.**

> This is automat's interpretation of a published policy. It was not authored, reviewed, or
> endorsed by \<institution\>. The institution's own policy governs; verify against it.

`TestNonEndorsementIsGuardedInSubstanceAndNamesTheInstitution` asserts the substance rather
than the bytes — a hard wrap is not a defect — and asserts that the institution is **named**
rather than referred to generically. A disclaimer that says "the institution" leaves the
reader to fill in which one, and they will fill in the one whose name is on the document.

**4. A derived profile may claim only `interpreted-by`, and may not claim to be
maintained.** `authorship: derived-interpretation` constrains `signatures[]` to the
`interpreted-by` role, and both shipped profiles carry `maintenance: example-and-forkable`.
`TestADerivedProfileMayOnlyBeInterpreted` and `TestEveryShippedProfileIsMarkedAsAnExample`
hold both. The shipped set is pinned by filename, at exactly two, by
`TestTheShippedProfileSetIsTheOneThatWasApproved` — so a third arriving is a decision
somebody makes rather than a file somebody drops in a directory.

## The trust model, and why cosigning is the mechanism for adoption

DESIGN §11a governs all three profile document types, and it says a signature attests
**provenance and nothing else** — never correctness, never applicability to a particular
institution, never approval for a particular use. Each attestation carries a role from a
closed five-value vocabulary (`authored-by`, `adopted-by`, `reviewed-by`, `interpreted-by`,
`format-validated-by`) plus a **required statement in the attester's own words**, over the
document's content hash.

The vocabulary is the whole design. "automat interpreted this", "the institution wrote
this", and "an institution adopted this for its own use" are three different claims, and a
reader shown one undifferentiated checkmark will infer the strongest available. A bare
signature is refused for the same reason: it invites the reader to supply the claim, and
they supply the most flattering one.

On this document type that distinction is not hypothetical, because it is exactly the
adoption path:

| Who | Role | What it means |
|---|---|---|
| automat maintainers | `interpreted-by` | We read the published document and this is our reading of it. Nothing more. |
| The issuing institution | `authored-by` | This is our scheme, stated by us. Retires the derived reading entirely. |
| Another institution | `adopted-by` | We took this document and adopted it for our own use — the Georgia Tech operation, made reviewable |
| A tool or CI | `format-validated-by` | The bytes satisfy the schema. Says nothing about the content. |

The content hash is scoped so a fork is possible without the fork being a forgery.
`Issuer`, `Authorship`, `Maintenance`, `Interpretation`, `Determination`, `Levels`,
`Composition`, `Inherits`, `UnmodeledAxes`, `Citations`, `PolicyCaveat`, and `Sources` are
covered; `classification_profile.id` and `.title` are not. **So a department that forks a
profile and retitles it does not invalidate the interpreter's attestation over the reading
itself — but `issuer` is covered, so the fork can be retitled and not reattributed.**
Which fields are covered is asserted by reflection over the struct
(`TestHashCoverageIsADecisionNotADefault`), so a new field is a decision about hash
coverage rather than a default.

**Trust is an operator determination.** Whether any identity in `signatures[]` counts for
anything is decided by the operator, against a trust policy the operator maintains.
**automat ships no trust anchor and no default accepted identity, implements no
verification, and loads no trust policy in v1.** A document nobody has cosigned is valid
and always will be — that is the normal case.

`review_by` is required with no default, sits inside the content hash the attestations
cover (so extending it is a change no earlier attestation vouches for), and `verify` warns
when it lapses. **Signed does not mean current**, and a durable, signed, stale reading of
policy is worse than an unsigned one: it carries the authority without the accuracy. That
matters more here than for the other document types, because institutional policy is
published as *living web pages*. Stanford's two pages carry no version and no effective
date and are revised in place, which is why every Stanford citation is dated by retrieval
and the sha256 in `sources[]` is the only fixed reference to what was read. The schema's
`date_basis` is three-valued for exactly this reason —
`published-effective-date` / `last-updated-in-document` / `retrieved-only` — so that "we
have no basis for a date" is a recorded answer rather than an invented one.

## automat proposes a format, never a governance body

This page is written so it could be taken to the HEISC 800-171 Compliance Community Group
or to RRCoP. If it is, the ask is narrow: **use the format, or tell us what is wrong with
it.** Not "adopt automat", and not "register with us".

Four things automat must never become, stated so the boundary is checkable rather than
tonal:

- **Not a registry.** No canonical list of institutional profiles, no namespace to claim, no
  index anybody has to appear in. `inherits` resolves within one issuer; there is no global
  resolution step and nowhere for one to live.
- **Not a standards owner.** The published schema is a versioned contract, and an
  institution disagreeing with a field is a reason to change the field, not a
  nonconformance.
- **Not a signing service and no trust anchor.** Per §11a, and it is the same boundary: a
  default accepted identity is a registry with one entry.
- **Not the upstream for anybody's scheme.** Both derived profiles are marked
  `example-and-forkable`. The intended lifecycle for one is that an institution forks it,
  corrects automat's reading against its own reading, publishes it under its own name with
  an `authored-by` attestation, and never speaks to this project again. **That is success,
  not attrition.**

The version of this that goes wrong is easy to picture and worth naming: automat
accumulates institutional profiles, becomes the place people look them up, and the
convenience of being looked-up turns into a claim to be authoritative about other people's
policies. The two-document cap, the `example-and-forkable` marking, and the absence of any
resolution mechanism are the structural answers to that, and they are answers precisely
because they are inconvenient.

## Reading the format if you are evaluating it

The two shipped documents are the fastest way in, and they are deliberately unalike:

- **`catalogs/classification/uc-protection-levels.json`** — 4 ascending alphanumeric codes,
  no controls anywhere, one unmodeled axis, one hashed PDF source and one explicitly
  unretrieved document. The example of a scheme whose *levels* and *controls* live in
  different places.
- **`catalogs/classification/stanford-risk-classifications.json`** — 3 word-named levels,
  75 controls across three `applies_to` groups, four external obligations at the top level,
  two undated living web pages as sources. The example of a scheme that states its controls
  inline.

Three word-named levels against four ascending codes is the pairing that stresses the model
hardest. **Any implementation that assumed four levels, or that derived order from a label,
works on one of these and silently fails on the other** — and
`TestTheSampleSpansTheLevelCountsAndBothNamingDirections` asserts that it is the
*disagreement* between them that is load-bearing: UC's ids happen to sort into rank order,
Stanford's do not, and the test fails if that stops being true.

Neither document enforces anything today. Every Stanford control carries
`automat_enforces: no`, which is accurate: they are patch windows, inventory registration,
and physical-security requirements, and a tool that vends AWS accounts does not do them.
Stating that per control is the same structural honesty `verify` prints per control set.

## What is not here yet

- **The environment profile does not reference a classification level.** Deliberately a
  separate change, so this document type could be reviewed on its own terms before anything
  depended on it. What the reference will need already exists: `LevelByID` resolves a level
  within a profile, and `ContentHash` gives the reference a subject that cannot be rewritten
  underneath it.
- **`vend` does not print the rating sentence** — the sentence at the top of this page. It
  needs the reference above first.
- **No verification of attestations, and no trust policy.** Per §11a, and not a v1 gap to be
  closed quietly: the v2 intent is keyless OIDC identity signing, so that an institution
  never has to run a key ceremony, with documents distributed over ordinary git or an OCI
  registry. `signature.format` names that form now so adopting it is not a schema version
  event.
- **Four of the six sampled institutions have no shipped profile**, by decision. Two was the
  approved number and the cap is pinned by a test.

## Standing obligation

`docs/audit-ritual.md` requires every profile's citations and dates to be re-verified
against the primary source at each phase gate, and a stale citation is a finding ranked no
lower than medium. Two things about this document type make that obligation sharper than it
is for the obligation profiles:

1. **Institutional policy is published as living web pages** that are revised in place with
   no version bump. A retrieval hash detects that a page changed; nothing detects that it
   changed *meaningfully* except reading it again.
2. **A derived profile is forked.** If automat's reading is wrong, the fork an institution
   publishes under its own name inherits the defect — and inherits it with the
   institution's authority attached rather than automat's.
