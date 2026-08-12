# Schema changelog

The files in `schema/` are versioned compatibility contracts. Any change to a
published schema bumps the version and adds a migration note here.

Versioning: the `schema_version` field carries plain semver. A **major** bump
means consumers must reject documents they do not understand; a **minor** bump
adds optional fields; a **patch** bump is documentation or constraint
clarification that does not change which documents validate.

## control-artifact/v1 — 1.0.0 (unreleased, Phase 0)

Initial definition per DESIGN.md §8. No migration.

Notes on choices that constrain future changes:

- `enforcement` is always an **array**, never a bare string. DESIGN.md §8 notes a
  control may be both SCP-enforced and Config-monitored; encoding that as a
  scalar-or-array union would make canonicalization ambiguous, so the array form
  is the only form.
- `artifact.sources[]` requires `sha256` on every entry and uses `oneOf` over
  `catalog` / `mapping` / `artifact` so a union artifact's provenance is
  structurally distinguishable from a compile from upstream sources.
- `config_rule_parameter.order` is **required**. Union resolves overlapping
  parameters by this declared order; a missing order is a hard error at compile
  time (DESIGN.md §9), so it must not be omissible in the artifact.
- `config_rule.provenance` is **required**, with values `aws-mapping` and
  `curated`. Added before publication (see the two notes below), so no version
  bump: 1.0.0 has never shipped.
- `config_rule_parameter.order` enumerates five values, not the three sketched in
  DESIGN.md §8. See below.
- `scp_statement.exempt_principals` is a list of principals with reasons, not a
  boolean. See the pre-publication change below; the field began as
  `exempt_automation_role: true|false`.
- `compiled_at` and all timestamps are constrained to second-precision UTC with
  a `Z` suffix. Sub-second or offset forms would break deterministic hashing.
- `content_sha256` covers a canonicalized **content payload** object, not
  `controls[]` alone. DESIGN.md §8 said `controls[]` and this section originally
  said nothing at all; see "Pre-publication change to control-artifact/v1: the
  content hash covers a payload" below for what the payload is and why leaving the
  definition implicit was the defect.

### Pre-publication changes to 1.0.0

Changes 1 and 2 landed during Phase 0 review; changes 3–5 landed as AUDIT-0
fixes. All of them predate publication of `1.0.0`, so there is **no version
bump**: there is no consumer of the earlier shape to migrate. Every one of them
tightens what validates, so after publication each would have been a major bump.
`audits/AUDIT-0.md` records the findings that motivated 3–5.

**1. `config_rule.provenance` (required) and `config_rule.rationale`.**

Each config-rule binding now records who asserts that the rule enforces the
control:

- `aws-mapping` — the binding comes from a published AWS mapping recorded in
  `artifact.sources`. Bindings of this kind are mechanically generated from that
  mapping and are never hand-edited; the mapping's `sha256` in `sources` is what
  vouches for them.
- `curated` — the binding is this project's own judgment. A curated binding
  **must** carry `rationale` (enforced by an `if`/`then` in the schema, and by
  the Go validator).

The distinction is for review, not decoration. Without it, a reader of a catalog
cannot tell which associations came from AWS and which came from us, so they
cannot audit our judgment separately from AWS's — and a regeneration could
silently overwrite a hand-added binding. Keeping the two layers structurally
distinct is what makes "the aws-mapping layer is mechanically generated" a
checkable property rather than a convention.

**2. `config_rule_parameter.order` gains `set-union` and `set-intersect`, plus
`set_separator`.**

DESIGN.md §8 sketched `min | max | exact`. Several AWS Config managed rule
parameters are separator-joined *sets*, not scalars, and no scalar order is
monotone over them — `exact` would make two catalogs that both restrict ports
irreconcilable, while `min`/`max` on the joined string is meaningless. The two
set orders resolve them in the direction that is stricter, which is what union
requires (DESIGN.md §9):

- `set-union` — the value is a set of **prohibited** items (blocked ports,
  blocked action patterns). Prohibiting more is stricter, so union.
- `set-intersect` — the value is a set of **permitted** items (authorized
  ports). Permitting fewer is stricter, so intersect.

`set_separator` (default `,`) splits the value into members. It is forbidden on
`min`/`max`/`exact`, where the value has no members. Set-valued parameters
canonicalize to trimmed, deduplicated, sorted, separator-joined members so two
spellings of the same set produce the same content hash; an explicit separator
equal to the default is dropped for the same reason.

**3. `scp_statement.not_action` removed (AUDIT-0 H3).**

The field is gone from the schema and from the Go type, so both decoders reject
it as an unknown field. A `Deny` over `NotAction` denies everything it does *not*
name, so two such fragments concatenate into a deny-all: the union of two control
sets that each permitted something would permit nothing. That destroys the
safe-concatenation property union relies on (DESIGN.md §9), and it fails closed
in the worst way — a vended account that cannot function.

The legitimate uses of that shape are region and service allowlists, which are
already their own fields (`scp.region_allowlist`, `scp.service_allowlist`) with
`set-intersect`-style semantics. The SCP packer emits the `NotAction` form from
those fields; a catalog author never writes it directly.

**4. `scp_statement.effect` is now `const: "Deny"` (AUDIT-0 H4).**

Previously the schema enumerated `Deny` and `Allow` while the Go validator merely
discouraged `Allow` — drift a consumer would have discovered the hard way. An
`Allow` in an SCP does not grant anything; it only widens what a parent SCP
already permits, so it does not compose under union: the union of control sets
must be an *intersection* of permitted behavior. Permission is expressed through
the two allowlist fields, which are intersected rather than concatenated.

**5. A set-valued `config_rule_parameter` must carry at least one member
(AUDIT-0 H5).**

`value` may no longer be empty or whitespace-only when `order` is `set-union` or
`set-intersect`; with the default separator the schema also rejects a value made
entirely of separators. An empty set is not a stricter set. AWS Config rejects
the parameter outright, and under `set-intersect` an empty set is the absorbing
element: resolving anything against it yields empty forever, so a single
malformed catalog would empty every authorized-ports list it unioned with.

The Go validator is authoritative on member splitting, because it honors a
non-default `set_separator`; the schema catches the default-separator case
directly. Both reject the same documents (`TestGoAndSchemaAgreeOnRejection`).

**6. `scp_statement.exempt_automation_role` (boolean) becomes
`exempt_principals` (a list with reasons).** Phase 1 review item 9(b), landed
pre-publication for the same reason as change 5: after publication this would be
a major bump, since the field's type changes.

The old field was a single boolean meaning "the packer should exempt automat's
own automation role". Two problems, and the second is the one that matters.

The first is expressiveness. A real deployment has more than one legitimate hole
in a baseline-protection `Deny` — a break-glass role, a central-IT audit role —
and DESIGN.md §10's whole premise is that the deny list is *data*, extensible per
catalog, "so L2-minded users can extend" it. A one-role boolean makes the
exemption list the one part of that data a catalog author cannot extend, which
pushes them to weaken the `Deny` itself instead. That is strictly worse: a
`Deny` narrowed to accommodate a role is invisible in review, whereas a named
exemption is a line a reviewer can object to.

The second is that **an exemption is the only thing in a catalog that widens a
policy**, and the boolean gave that fact nowhere to live. Every other field can
only make a `Deny` stricter. Consequences now encoded in the schema rather than
left to the packer:

- **Union intersects these lists; it does not concatenate them.** Denies
  concatenate and allowlists intersect (DESIGN.md §9) because both directions
  make the merge stricter. Concatenating exemptions would invert that: adding a
  control set could widen the result, breaking the monotonicity property union is
  tested against. An exemption therefore survives a union only if every input
  control set constraining that statement agrees to it. This is the rule the
  Phase 2 SCP packer must implement, and it is the reason this change is worth
  making before the packer exists rather than after.
- **No wildcards, and roles only.** `exempt_principal_ref` admits exactly two
  forms: the symbolic `automat:automation-role` placeholder (the ARN is unknown
  until vend time, so the packer materializes it) or a fully qualified IAM role
  ARN. Not `arn:aws:iam::*:root`, not `arn:aws:iam::<id>:root`, not a trailing
  `*`, not a user. Without that restriction one exemption entry could undo the
  root-user `Deny` §10 requires — a catalog file is attacker-controlled input in
  this project's threat model, and an exemption is the highest-value thing to
  smuggle into one. The ARN pattern is partition-agnostic (`aws[a-z-]*`), so
  GovCloud and China ARNs are not rejected in the environments most likely to
  need this catalog.
- **A reason is required, and it is inside the content hash.** An unexplained
  exemption is indistinguishable from an escape hatch, and the reason is the half
  of the entry a reviewer actually evaluates. Hashing it means the stated
  justification for a hole in a `Deny` cannot be rewritten under a signature that
  still verifies. Reasons are capped at 512 bytes and forbid control characters:
  they are echoed in validation reports, where a newline forges a line.
- **At most eight per statement.** Each entry is a hole in a preventive control,
  and the list is rendered into an IAM condition against the 5120-character SCP
  quota (DESIGN.md §16). A statement needing more than a handful of exemptions is
  a `Deny` that does not hold; a hard error beats a policy that silently stops
  fitting.

No published catalog required rehashing: nothing had shipped with the boolean and
no file in `catalogs/` carries an exemption. The sample-artifact content hash in
`TestContentHashIsStable` moved, which is the pin following its fixture rather
than canonicalization drifting — the distinction that test exists to make.

## profile/v1 — 1.0.0 (unreleased, Phase 0)

> **Superseded in part** — see "The rename: `profile/v1` becomes
> `environment-profile/v1`" below. This schema is now
> `schema/environment-profile-v1.schema.json` with `$id`
> `automat.dev/schema/environment-profile/v1`, and its top-level `profile` member
> is `environment_profile`. Every constraint recorded in this section still holds;
> only the names moved. The section stands as written because a changelog records
> what was said at the time; this marker is here so a reader does not take the old
> names at face value.

Initial definition per DESIGN.md §7 and §13. No migration.

- `account.tags` forbids keys matching `^automat:` — automat's conventional tags
  (DESIGN.md §14) are applied by the tool and must not be overridable by a
  profile, since they are what `list` and `verify` key off.
- `placement.ou_path` is capped at five entries, mirroring the OU nesting limit
  (DESIGN.md §3, fact 10).
- `review_by` (required) and `signatures[]` (optional) were added
  pre-publication; see the shared section below.

## obligation-profile/v1 — 1.0.0 (unreleased, Phase 4 scope)

New schema, added at the Phase 1 review's request alongside the Phase 4
assessment-reporting scope (`docs/assessment-reporting.md`). **Listed here for
maintainer ratification** under rule 6: it is a new contract rather than a change
to a published one, so nothing is bumped and nothing migrates, but a new file in
`schema/` is a new promise and belongs in the changelog on the way in.

**Why it exists: a catalog answers "which controls" and nothing else.** It does
not answer under what instrument, assessed how, signed by whom, or with gaps
deferrable or not. Those are a second axis, and the reason it has to be a
separate axis rather than a field on the catalog is that **the same control
catalog is assessed under incompatible rules by different regimes**. NIST SP
800-171 is the clearest case: under DFARS a shortfall may carry a plan of action
with a target date and the aggregate is a weighted score; under NIH's
controlled-access data expectations a plan is also permitted but there is no
score at all; and at CMMC Level 1 — a different catalog, but the same shape of
question — no plan is permitted whatsoever, so a single unmet practice means
there is nothing to affirm. One catalog, three sets of rules about what a
determination *means*.

**Profiles are data. There is no profile-specific branching in Go.** A regime
encoded as a `switch` on profile id is a regime that cannot be corrected without
a release, and policy changes faster than this tool will. Everything a renderer
needs to behave correctly under a regime is a field here.

Notes on the choices that constrain future changes:

- **`determinations.understatement_value` parameterizes the honesty asymmetry
  rather than bolting onto it.** The invariant is directional: automat's own
  proposals may only ever *understate* compliance. The satisfied value comes from
  the operator's determinations file or from nowhere; the unmet value automat may
  write itself, because being wrong in that direction costs an afternoon of
  review while being wrong in the other direction is what an enforcement action
  is built on. Since each regime spells its own values (`MET`/`NOT MET`,
  `SATISFIED`/`OTHER THAN SATISFIED`), the field names which member of that
  closed set automat is permitted to write. `determinations.values` is likewise
  the regime's own spellings and automat does not add to it: a worksheet carrying
  a value the standard does not define is not a worksheet for that standard.

  The invariant is asserted as a **property over the profile set**, not per
  profile — `TestTheUnderstatementAsymmetryHoldsUnderEveryProfile`. A per-profile
  assertion would pass forever while a fourth profile added later pointed the
  field at its satisfied value and validated perfectly against this schema. The
  test also rejects the substring trap: `OTHER THAN SATISFIED` contains
  `SATISFIED` and is the opposite claim.

- **`applicability` is prose, and deliberately not evaluable.** There is no
  expression language, no predicate, and no match form — `trigger` is prose
  written for a sponsored programs officer, `hints` is capped at 32 and is
  explicitly non-exhaustive, and `declared_by_operator` is `const: true` so a
  profile cannot opt into automatic applicability.

  An automated "this obligation applies to you" is the most dangerous output this
  tool could produce. Wrong in the permissive direction it tells an institution
  it is unregulated, and it would be *believed*, because it came from a tool that
  is right about everything else. The `const: true` is there so a reader of a
  profile sees the rule rather than having to know it, and
  `TestApplicabilityIsNeverEvaluable` fails on predicate syntax in any
  applicability text — a match language arrives one plausible entry at a time,
  and the entry that starts it looks harmless.

- **`revision_policy: operator-determined` FORBIDS the `revision` field.** Not
  "makes it optional" — forbids it. NIH's notices align expectations with 800-171
  without naming a revision, and institutions have split between Rev 2 and Rev 3.
  automat ships no default, because a default here would silently pick an
  institution's compliance posture for it and route around the one person — the
  sponsored programs officer reading the actual agreement — best placed to
  decide. A revision sitting in an operator-determined profile is a default
  wearing a different hat, which is why the schema will not hold one.
  `TestAnOperatorDeterminedRevisionShipsNoDefault` also rejects a revision named
  in `hints`, since "most institutions use rN" is not a default and not even a
  hint.

- **`scoring.weight_table` is required iff `method` is not `none`, and forbidden
  otherwise.** A scoring method with no weight table would compute a number from
  weights that came from nowhere, and that is the one output this project cannot
  produce: the result is posted under a senior official's affirmation. See
  `docs/open-questions.md` Q10 for the decision on where the weights come from
  (hand-transcribed twice, independently, and diffed before commit — no test
  catches a false input to correct arithmetic).

- **`submission.automat_may_format` defaults false and is expected to stay
  false.** A document formatted for submission is a document that can be
  submitted, and automat generates the packet a human reads, never the instrument
  they sign (`docs/assessment-reporting.md` invariant 1).
  `TestNoProfileFormatsForSubmission` fails if any shipped profile sets it, so
  turning it on is a reviewed decision rather than a data change.

- **`policy_caveat` is required.** A profile is where automat's reading of policy
  is most concentrated, so a profile that does not say what kind of claim it is
  making is not a valid profile. The substance is asserted phrase by phrase
  (`docs/policy-caveat.md`, `TestEveryProfileCarriesThePolicyCaveatInSubstance`),
  in substance rather than verbatim, since renderers wrap differently.

- **`citations[].effective_date` is required.** An undated policy claim cannot be
  checked for staleness, which is the entire point of recording citations rather
  than describing them. A stale legal citation is an audit finding ranked no
  lower than medium (`docs/policy-caveat.md`, and CLAUDE.md's audit ritual).

- **`status` includes `proposed` and `phased`.** `proposed` exists so a proposed
  rule can be recorded without being modeled as binding — FAR Case 2017-016 is
  still proposed, and a tool that treated it as in force would impose
  requirements on institutions that do not have them. `phased` covers an
  instrument whose applicability turns on a date inside the phase-in, where two
  operators can legitimately be under different rules on the same day.

Three profiles ship in `catalogs/obligations/`: `cmmc-l1`, `dfars-7012`, and
`nih-cadr-dua`. The set is pinned by
`TestTheShippedProfileSetIsTheOneThatWasApproved` — adding a profile is a policy
decision, not a data change, since a fourth profile shipped quietly is a fourth
obligation automat implies an institution might be under.

**No Go types.** The profiles were added as design-and-data ahead of `assess`,
and a struct would be building what that decision said not to build. Every
constraint above is tested against the published schema from raw JSON
(`internal/artifact/obligation_profile_test.go`), each verified to fire by
deleting it and confirming the covering case fails.

## evidence-manifest/v1 — 1.0.0 (unreleased, Phase 0)

Initial definition per DESIGN.md §11. No migration.

- `records[]` is append-only and hash-chained: `previous_sha256` of the first
  record is 64 zeros. `record_sha256` covers the canonicalized record with
  `record_sha256` and `signature` themselves omitted, so a record can be signed
  after it is hashed without invalidating the chain.
- `signature` is optional at the schema level so an unsigned local manifest is
  still a valid document; whether signatures are required is a policy decision
  above the schema.
- `error.remediation` exists because permission failures must state which action,
  which resource, and what grant would fix it (CLAUDE.md rule 7) — that text is
  part of the evidence record, not just log output.

### Pre-publication change to 1.0.0: the `custody-transfer` terminal record

Landed at the Phase 1 review's request (item 9a), before publication and before
any Go implementation, so there is **no version bump**: nothing has emitted or
consumed a 1.0.0 manifest. Added now rather than in Phase 2 for one reason —
after publication this would be a **major** bump, because it changes what a
complete chain looks like. A consumer written against a schema with no terminal
record has no way to distinguish a chain that ended deliberately from one that
was truncated, and would be right to treat the new form as corrupt.

**What it is.** `operation` gains `custody-transfer`, and a record with that
operation must carry a `custody_transfer` object: `transferee`,
`effective_date`, `reason`, `final_artifact` (id + `content_sha256`), plus an
optional `successor_manifest_id`.

**Why a chain needs a way to end.** The manifest is the chain of custody behind
a "born compliant" claim, and it is append-only. Without a terminal record,
every chain that stops — the account is handed to central IT, the grant is
revoked, the project ends, automat stops being the tool — stops in the same way
a tampered chain stops: at a record, with nothing after it. The reader cannot
tell those apart, so *no* silent ending can be trusted, which weakens every
chain rather than just the abandoned ones. A terminal record makes the ordinary
case say so, and thereby restores the meaning of a chain that ends without one:
a chain with records missing from the end and no `custody-transfer` is now
positively suspicious, which is the property that makes the evidence worth
keeping.

**Why each field.** `transferee` and `reason` are what a successor auditor needs
and what nothing else in the chain records; a chain that ends with no stated
recipient or reason is not meaningfully different from one that just stops.
`effective_date` is a **date, not a timestamp**, and deliberately distinct from
the record's `timestamp`: custody passing is a policy fact usually agreed before
or recorded after the moment it takes effect, and collapsing the two would make
the record claim the transfer happened when the command ran. `final_artifact`
gives the successor a stated baseline to inherit instead of one they must infer
by replaying the whole chain — the same id-plus-content-hash pair the rest of
the manifest uses, so it is verifiable against a catalog rather than a
description. `successor_manifest_id` is optional on purpose: a transfer out of
automat's scope entirely has no successor manifest, and requiring the field
would force an operator to invent a false claim of continuity.

**Constraints, and which of them the schema can actually enforce.**

- `custody_transfer` is **required on** a `custody-transfer` record and
  **forbidden on** every other kind. The negative half matters as much as the
  positive: without it, a transfer could ride along on an ordinary
  `account-move` record, ending the chain in a place no reader looks for an
  ending.
- A `custody-transfer` record may not also carry `artifact` or `enforcement`. A
  transfer enforces nothing, and two artifact references in one record leave the
  reader to guess which is the baseline being handed over.
- `outcome` must be `success`. A transfer that failed did not transfer anything,
  so it cannot be what a chain ends on; record the failure as the operation that
  failed and let the chain continue.
- **At most one** `custody-transfer` record per manifest. A second one means
  either the first was false or the chain was reopened after it closed.
- `transferee` and `reason` are prose fields, so they forbid control characters:
  they are printed back in reports, and a newline in either can forge a line of
  one.

The one thing the schema **cannot** say is that a `custody-transfer` record is
the *last* record: JSON Schema cannot refer to an array's final position. The
"at most one" rule is the half that is expressible; terminality is a chain-level
invariant the Phase 2 chain validator must enforce alongside the hash links.
That gap is recorded in the schema's own `records` description and pinned by
`TestTheSchemaCannotSayCustodyTransferIsLast`, which asserts the document the
schema lets through so the Go-side obligation cannot be quietly dropped.

No Go types were added: the review asked for the schema and the reasoning while
schemas are still soft, explicitly without implementation. The constraints are
tested against the published schema from raw JSON
(`internal/artifact/evidence_schema_test.go`), each one verified to fire by
deleting it and confirming the covering case fails.

> **Superseded in part** — see "The Go implementation of evidence-manifest/v1"
> below. `internal/evidence` now implements this schema, and the terminality gap
> named in the paragraph above is enforced in Go. The statement stands as written
> because a changelog records what was said at the time; this marker is here so a
> reader does not take it at face value.

## Pre-publication change to three schemas: cosigning and freshness

Landed before `internal/evidence` writes its first record, and that timing is the
whole reason it landed now rather than in Phase 4 where the fields are first
*read*. Three schemas change together — `profile/v1`, `obligation-profile/v1`, and
`evidence-manifest/v1` — because the manifest field only makes sense if the
profile field exists to be recorded. **No version bumps**: all three are 1.0.0
unreleased, nothing has emitted or consumed one, and there is no earlier shape to
migrate.

**Listed here for maintainer ratification.** Under rule 6 an audit-driven change
that strictly *tightens* validation may land without asking; this is not that.
`review_by` is a new required property, which tightens, but `signatures[]` and the
manifest's `profile` are new structure. Ratify or reject the structure; the
reasoning is below rather than in a commit message so there is something to
reject.

**Why before the first manifest record exists.** Retrofitting the *record* shape
after records exist in the wild is a versioning event, not a changelog line — and
a worse one than the custody-transfer case, because a consumer reading a chain
would have no way to tell a record written before the field existed from a record
whose profile provenance was omitted. Adding the field now means every record
automat has ever written carries it.

### `review_by` — required on both profile document types

A date, no default, on every `profile/v1` and `obligation-profile/v1` document. The
date by which the document must be re-read against its sources; Phase 4's `verify`
**warns** once it has lapsed (DESIGN.md §11a, §12).

**Signed does not mean current, and this is the more dangerous failure of the
two.** A profile is a reading of policy that an institution acts on, and policy
moves: notices are superseded, phase-in dates arrive, a class deviation pinning a
revision expires. The failure mode is silent and confident — **a superseded
citation renders exactly as well as a current one**. Adding signatures without
adding this field would make the problem worse rather than better: a durable,
signed, stale artifact carries the authority without the accuracy, which is worse
than an unsigned one because it discourages the reader from checking. The
citation-freshness rule in CLAUDE.md's audit ritual ("a stale legal citation is a
finding, ranked no lower than medium") is a rule about a human process; this field
is the same rule expressed as data, so the process has something to check against.

Required rather than optional, and with no default, for the reason the rest of
this file keeps arriving at: an optional freshness date is absent from exactly the
documents whose freshness nobody thought about. It sits **inside** the content hash
the attestations cover, so extending it is a change no earlier attestation vouches
for — which is the intended friction. A field a stale document could quietly bump
would be worse than no field.

Warn rather than fail (DESIGN.md §12). A lapsed review date says nothing about the
account, which is exactly as compliant as it was the day before; what has expired
is anyone's assurance that the document describing it still reads policy
correctly. A hard failure would also make `verify` unusable in the cron job it is
meant for, and an unusable check gets disabled.

The three shipped obligation profiles carry `2026-11-10` (`cmmc-l1`,
`dfars-7012`) and `2027-02-26` (`nih-cadr-dua`). Neither date is arbitrary: both
are dates already cited *inside* those profiles as the moments their own reading
changes — CMMC Phase 2 begins 2026-11-10, and NIH's expectations are stipulated in
new or renewed agreements from 2026-02-26, one year before the review date chosen
here. A review date later than the phase-in it knows about would be a profile
scheduling its own re-reading for after the change it predicts.

### `signatures[]` — optional attestations, provenance only

An optional array on both profile document types. Each entry is an **attestation
predicate over the document's content hash**: a `role`, an `identity`, a required
`statement`, the `content_sha256` it is over, an `attested_at` date, and an
*optional* `signature` block carrying the cryptographic material when there is
any.

**A signature attests PROVENANCE ONLY** — never correctness, never applicability
to a particular institution, never approval for a particular use. That sentence is
in the schema, in DESIGN §11a, and here, because it is the claim the whole
mechanism will be misread as making.

**The five roles exist so the claims cannot collapse into one checkmark.**
`authored-by`, `adopted-by`, `reviewed-by`, `interpreted-by`,
`format-validated-by`. "X wrote this", "Y adopted it for its own use", "Z read
it", and "the format validated" are four unrelated claims of wildly different
weight, and the last is a statement about *syntax*. A reader shown a single
undifferentiated green tick learns nothing and will infer the strongest available
claim, which is how "the JSON parsed" becomes "the university approved this". No
role means approved, certified, or compliant, and none may be added that does: the
vocabulary's entire value is that the weakest claim cannot be read as the
strongest. `interpreted-by` is the one that carries a *negative*: it says this
document is someone's reading of a third party's published policy, and that the
third party has neither reviewed nor endorsed it.

**`statement` is required, and it is why these are attestations rather than
signatures.** The identity says in its own words what it is claiming, so the
reader evaluates a sentence instead of a tick. A bare signature invites the reader
to supply the claim themselves, and they supply the most flattering one available.
It is `long_prose`, hashed with the rest of the document, so a statement cannot be
rewritten under material that still verifies.

**The `signature` block is optional and deliberately subordinate.** The claim is
the attestation; the bytes are evidence for it, never the other way round. An
entry with no signature is still a recordable attestation — an institution
asserting authorship of a file it publishes itself — while bytes with no role and
no statement are *not expressible at all*. Two formats are named now so adopting
the second is not a version event: `detached-ed25519` (raw signature over the
content hash, key obtained out of band) and `oidc-identity-bundle`, the intended
v2 mechanism. The `if`/`then`/`else` pairs each with the field that makes it
meaningful and forbids the other's: `key_id` is required on the detached form,
because a detached signature nobody can locate a key for is unverifiable in a way
that *looks* verifiable; `identity_issuer` is required on the keyless form and
forbidden on the detached one, because in the keyless model the issuer is the whole
of what the identity means — "signed by security@example.edu" is a different claim
depending on who vouched for that address.

**Trust is an OPERATOR DETERMINATION. automat ships no trust anchor.** No default
accepted identity, no bundled key, no implied issuer. Whether an identity counts
for anything is decided by the operator against a trust policy file they maintain,
naming accepted identities per role. The intended v2 mechanism is keyless
OIDC-identity signing so an institution never has to run a key ceremony, with
documents distributed over ordinary git or an OCI registry — infrastructure that
already exists at every institution automat targets. **automat is not and must
never become a registry, a signing service, or a standards owner.** It proposes a
format; a format has no members and no revocation list.

**v1 implements no verification and loads no trust policy.** The fields are
recordable and nothing reads them. That is deliberate: verification without a
trust model is theatre, and a trust model automat ships is a trust model automat
owns.

`maxItems: 16` on the array and `uniqueItems: true`. Sixteen because an attestation
list long enough to skim past is one nobody reads, and the useful case is a
handful — an author, an adopting institution, maybe a reviewer.

### `evidence_manifest.record.profile` — what the vend recorded

> **Superseded in part** — the field is now `record.environment_profile` and the
> `$def` is `environment_profile_reference`. See the rename section at the end of
> this file. Everything below still describes the field's shape and reasoning.

An optional `profile` object on a record: `id`, `content_sha256`,
`verified_signatures[]` (all three required *within* the object), plus optional
`schema_version` and `review_by`.

Optional on the record because not every record has a profile behind it — `init`
predates one — and **forbidden on a `custody-transfer` record** for the same reason
`artifact` and `enforcement` already are: a transfer deploys nothing, and a second
document reference beside `custody_transfer.final_artifact` leaves the reader to
guess which one is the baseline being handed over. Every record a `vend` writes
carries it.

`content_sha256` is what makes "vended under this profile" checkable rather than a
label: a record naming only the profile id is a record whose subject can be edited
afterwards. `review_by` is *copied* into the record rather than looked up, because
an evidence record has to be readable years later without its inputs — an auditor
should be able to see that the profile behind an account was already six months
past review when it was vended, without needing the file.

**`verified_signatures` is required, and an empty array is the normal value.**
v1 verifies nothing, so it records the empty set. Required rather than optional so
that an absent field cannot be read as "unknown": the difference between "nothing
was verified" and "the question was never asked" is precisely the distinction an
evidence record must not blur, and the reader tells which one an empty set means
from the record's own `tool_version`. Each entry is an identity *and* a role — the
role required alongside the identity so the field cannot degrade into a bare list
of names, which a reader would take for approval. Attestations present in the
profile but unverified are deliberately **not** copied here: a record listing
signatures it did not check would manufacture assurance out of a document's own
claims about itself, which is the exact failure the role vocabulary exists to
prevent.

### What the schemas cannot enforce, and what a validator must

- **That `attestation.content_sha256` is the hash of the document containing it.**
  A schema cannot compute a hash, so an attestation could name any hash at all —
  including one lifted from a different document. Recording the hash is still
  right (an attestation whose subject is implicit can be moved silently), but Phase
  4's verifier must recompute and compare. Pinned by
  `TestTheSchemaCannotCheckAnAttestationsOwnHash`.
- **That the roles do not multiply.** The five-value enum is enforceable; the
  reason it is five is not. `TestTheAttestationRoleVocabularyIsClosed` pins the
  set and the reasoning, so a sixth role is a reviewed decision.
- **That an attestation was verified before being recorded in a manifest.** The
  manifest schema cannot distinguish a `verified_signatures` entry automat checked
  from one written by hand. That is a Go-side obligation of whatever writes
  records, asserted by `TestVerifiedSignaturesAreEmptyUntilVerificationExists`.
- **That `review_by` is in the future.** A schema has no clock, and one that
  rejected a past date would make every archived document invalid. Lapse is a
  `verify` warning, not a validation error.

**No Go types were added**, and no verification, trust-policy loading, or registry
was implemented — that scope was explicitly excluded. Every constraint above is
tested against the published schemas from raw JSON
(`internal/artifact/cosign_schema_test.go`), each verified to fire by deleting it
and confirming the covering case fails.

> **Superseded in part** — see "The Go implementation of evidence-manifest/v1"
> below. The manifest half now has Go types, and the Go-side obligation named
> above ("that an attestation was verified before being recorded in a manifest")
> is discharged at the writer. Verification, trust-policy loading, and the
> registry remain unimplemented, so the substance of this paragraph still holds.
> The statement stands as written; this marker is here so a reader does not take
> it at face value.

## Pre-publication change to evidence-manifest/v1: `request_id` is patterned

Landed with `internal/evidence` (Phase 2, task #12), before publication, so there
is **no version bump** — nothing has emitted or consumed a 1.0.0 manifest. After
publication this would be a **major** bump: it narrows what validates, and a
consumer written against the looser shape would be right to consider a rejection
a breaking change.

`records[].request_id` was `{"type": "string", "minLength": 1}` and is now
`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`.

The old constraint was inherited from "it is a non-empty string" thinking, and it
was the only id in the file with no pattern while `manifest.id`, `artifact.id`,
`profile.id`, `account_id`, `ou_id`, and `organization_id` all had one. What
makes this one worth tightening rather than merely tidying is where the value
goes: the request id is the single field in a record that a **human copies back
onto a command line**, as `automat vend --resume <request-id>`. A parked record
exists precisely so an operator can read it weeks later and re-run that command.

Under the old pattern, `req-123; aws organizations close-account …` was a valid
request id. automat would never construct one, but automat is not the only writer
of these files — a manifest is a document institutions store, merge, and
sometimes hand-edit, and `--resume` takes whatever the record says. A record that
prints an id an operator will retype is a record that must not be able to suggest
a different command than the one it appears to. Whitespace is refused for a
duller version of the same reason: an id containing a space cannot be selected by
double-click, so the operator retypes it by hand and gets it wrong.

This is not injection *prevention* — argument construction is the CLI's problem
and stays the CLI's problem. It is refusing to write down a value whose whole
purpose is to be read back by a person and acted on. Enforced identically by the
Go validator (`reRequestID`) and pinned in both directions by
`evidence.TestGoAndSchemaAgreeOnRejection`.

## The Go implementation of evidence-manifest/v1 (Phase 2, task #12)

Two sections above state "No Go types were added". That was true when written and
is no longer: `internal/evidence` now implements the manifest — types, validator,
hash chain, signer, and store. The statements stand as a record of what those
reviews scoped, and this section records which of the Go-side obligations they
named are now discharged, and by what:

- **Terminality** — that a `custody-transfer` record is the *last* record, which
  JSON Schema structurally cannot say. Enforced by `evidence.validateChain` and
  by `Append`, which refuses to extend a closed chain. The two halves of the
  invariant are now pinned from both sides:
  `artifact.TestTheSchemaCannotSayCustodyTransferIsLast` asserts the schema lets
  the document through, and
  `evidence.TestTheSchemaStillCannotSayCustodyTransferIsLast` asserts the Go
  validator catches it. If JSON Schema ever gains the ability, the first test
  fails and points at the second.
- **That an attestation was verified before being recorded.** Discharged at the
  writer: `Append` refuses any record whose `profile.verified_signatures` is
  non-empty, because v1 verifies nothing and therefore has nothing true to put
  there. Tested by `evidence.TestAppendRefusesUnverifiedSignatures`; the refusal
  message says automat verifies nothing in this version, loads no trust policy,
  and ships no trust anchor, so a caller who hits it is not left guessing whether
  the field is broken or the feature is absent. This is the obligation the
  cosigning section named as "a Go-side obligation of whatever writes records",
  and it is now stated as a test rather than as a paragraph.
- **That `review_by` being past is a warning, not an error.** The Go validator
  accepts a lapsed date; `evidence.TestTheSchemaAcceptsWhatGoAccepts` pins it,
  including the case with no `review_by` at all.

Two obligations remain undischarged and are still Phase 4's:
recomputing `attestation.content_sha256` against the document containing it, and
any verification at all. Neither is implemented, and `verified_signatures` stays
empty until they are.

**The Go validator and the published schema are now held against each other in
both directions** by `internal/evidence/schema_conformance_test.go`, mirroring
`internal/artifact/schema_conformance_test.go`: every way of breaking a manifest
must be rejected by both, and every valid manifest accepted by both. A case only
one side catches is drift, and the failure message says which side is missing the
check. The vocabularies (`operation`, `outcome`, attestation `role`, signature
`algorithm`) are compared as *sets read out of the schema file*, not case by
case, because a case-by-case test cannot catch a value the schema gained and Go
did not.

Writing that test found two divergences, both fixed rather than accepted:

1. The Go validator checked only `scp_arns` for empty members and checked none of
   the five enforcement arrays for duplicates, while the schema declares
   `uniqueItems` and `minLength: 1` on all of them. `Append` canonicalizes —
   sorting and deduping — so a manifest automat wrote was never affected, but a
   manifest read off disk went through no such thing. An enforcement list is the
   part of a record an auditor counts: "three SCPs attached" and "two SCPs, one
   listed twice" are different claims. This tightens only the Go validator; no
   `schema/` file changed.
2. `request_id` had no pattern, per the section above.

Both strictly tighten validation, so rule 6 permitted them without pre-approval
and required them to be ratified. **Both ratified at the task #12 review**, and
the `request_id` reasoning was elevated into a standing rule rather than left as
a note about one field: **CLAUDE.md rule 8** now requires a character-class
pattern at both the schema and Go layers on any value automat writes that is
designed to be read back by a person and typed onto a command line, and the audit
ritual must *enumerate* those fields rather than spot-check them. The
generalization is the point — `request_id` survived Phase 0 unpatterned because
"non-empty string" is what a round-trip field looks like from inside the writer,
and nothing had asked which fields were round-trip fields.

Carried in ROADMAP's Phase 2 AUDIT-2 list until `audits/AUDIT-2.md` is written,
so the audit records the decision rather than rediscovering the change.

### The rule 8 sweep, run immediately on this schema

Rule 8 requires audits to *enumerate* round-trip fields rather than spot-check
them, so the sweep was run on this schema at once instead of being deferred to
AUDIT-2 — a rule generalized from a finding and then not applied to the file the
finding came from is a rule that has already failed. It found three more, all
pre-publication, all strictly tightening, and all now sharing two new `$defs`:

- **`$defs/round_trip_id`** — for identities automat mints. `manifest.id` and
  `custody_transfer.successor_manifest_id` join `records[].request_id` here. Both
  were `minLength: 1`. `successor_manifest_id` is the one with the longest fuse:
  the person who follows that pointer is a successor auditor years later holding
  nothing but the record, and a pointer they cannot type is not a pointer.
- **`$defs/round_trip_ref`** — for identities automat does **not** mint and so
  cannot reduce to a plain id. `signature.key_id` was `minLength: 1` and may be a
  KMS key ARN or an alias, so it needs colons and slashes. It is also the field
  with the sharpest claim on rule 8: a key-id mismatch is *refused* rather than
  reported as a bad signature, and the refusal text tells the operator to supply
  the key the record names — automat has actively instructed a person to retype
  this value, which makes an untypeable one a defect in the remediation, not in
  the field.

The two `$defs` are separate because collapsing them would force a choice between
rejecting every ARN and admitting whitespace. `round_trip_ref` is bounded at 256
rather than the 2048 an ARN may formally reach: Go's regexp engine caps a repeat
count at 1000, and **a bound the Go validator cannot express is one this schema
must not express either** — rule 8 is only meaningful if both layers state the
same thing, so the tighter, mutually expressible bound wins over the formally
correct one. Every real key reference clears it with room to spare.

Both directions are pinned by `evidence.TestGoAndSchemaAgreeOnRejection`, and the
accept side keeps a KMS key ARN and a bare `alias/...` valid so the distinction
between the two `$defs` cannot be quietly collapsed later.

One rule 7 defect surfaced in the same pass and is fixed: the Go validator's
`successor_manifest_id` problem carried an **empty `Fix` string** — a validation
failure with nowhere to go, which rule 7 exists to forbid.

## The rename: `profile/v1` becomes `environment-profile/v1`

Pre-publication, and a rename only — **no constraint changes, no version bump**.
Nothing has emitted or consumed a `profile/v1` document, so there is nothing to
migrate. Landed at the maintainer's direction on Q14.

| before | after |
| --- | --- |
| `schema/profile-v1.schema.json` | `schema/environment-profile-v1.schema.json` |
| `$id automat.dev/schema/profile/v1` | `$id automat.dev/schema/environment-profile/v1` |
| top-level member `profile` | `environment_profile` |
| `evidence-manifest` `record.profile` | `record.environment_profile` |
| `evidence-manifest` `$defs/profile_reference` | `$defs/environment_profile_reference` |
| Go `evidence.ProfileRef` / `Record.Profile` | `evidence.EnvProfileRef` / `Record.EnvProfile` |

**Why a rename is worth a changelog section.** "Profile" named three unrelated
documents — the per-vend input (DESIGN §7), obligation profiles (`cmmc-l1`,
`dfars-7012`, `nih-cadr-dua`), and the institutional classification profiles not
yet built — and there is a fourth sense the tool cannot rename, the **AWS
credential profile** (`config.toml`'s `profile`, `login --profile`). An evidence
record's whole job is to name the document it ran under by id and content hash. A
field called `profile` in that record is ambiguous to exactly the auditor it exists
for, and DESIGN §7 further spelled the vend input `--profile` — the same flag name
as the credential profile, in the same tool. `vend`'s input flag is now
`--environment-profile`; `--profile` stays reserved for the AWS sense, because that
is what it means in every other tool the operator uses.

"Environment" rather than some new coinage because it is the idiom already in use
for a resource rated to hold data at a level, and because it names the right thing:
obligation and classification profiles are **policy** artifacts, while the
environment profile is the thing being **built**. It is also the document `vend`,
`verify`, and later `assess` all consume.

**This moved every record hash.** The manifest field name is inside the record
hash, so `internal/evidence/testdata/golden/manifest.json` was regenerated and its
diff is exactly the rename: the field name, then the `record_sha256`,
`previous_sha256`, and signature values that must follow it. Nothing else changed —
which is what the golden file exists to make visible. Canonicalization itself did
not change, so this is not the release-note-breaks-every-manifest-on-disk case that
test's failure message warns about; there are no manifests on disk to break.

## Pre-publication change to control-artifact/v1: `region_deny_exempt_services`, and the content hash covers a payload

Landed with E1–E7 (Phase 2), before publication, so there is **no version bump** —
nothing has consumed a 1.0.0 artifact. After publication the new field would be a
**minor** bump on its own (a new optional property), but the hash-definition change
would be **major**: it changes what `content_sha256` means, so a consumer computing
the old hash would reject every artifact automat writes.

**Directed by the maintainer** as part of E1/E3: the global-service exemption list
is catalog data, never compiled into the binary. The hash restructuring is not part
of that direction — it fell out of it, and it **restructures rather than strictly
tightens**, which under CLAUDE.md rule 6 makes it something to surface rather than
assume. It is recorded here for ratification with the reasoning below; the
alternative was an unhashed security-relevant field, which was not a real option.

### The new field

`region_deny_exempt_services` — a **top-level** array (sibling of `schema_version`,
`artifact`, `controls`), `minItems: 1`, `uniqueItems: true`, entries matching
`^[a-z0-9-]+$`. It names the globally addressed service namespaces (IAM, STS,
Organizations, Route 53, Support, billing, Health, …) that a region or service
allowlist Deny must not cover.

**Data, not code**, for the same reason `exempt_principals` is: getting this list
wrong bricks an account, and a list only the binary knows is a control whose scope
cannot be reviewed or corrected without a release. The packer therefore has **no
fallback** — a fallback is the compiled-in list with extra steps, and it would
silently paper over a control set that forgot to state the fact.

**Top-level rather than per control**, and this was decided by a test rather than by
taste. Three reasons, in the order they became apparent:

1. On a control it made an SCP block that carries no statement. An exemption list
   prevents nothing, and `TestEveryBaselineControlIsBaselineProtectionClass`
   rejected the synthetic control that held it with "carries no SCP statement, so it
   prevents nothing" — which is the right answer.
2. Its scope *is* the artifact. Two controls in one document carrying different
   lists would have no coherent reading.
3. It is not required alongside `region_allowlist`, and cannot be: the control set
   stating the AWS fact need not be the one restricting regions. `baseline-protection`
   supplies the list and constrains no regions. The pairing is therefore a
   **plan-time** invariant in `internal/compilesets`, not a schema one.

Under union it **intersects**, which is forced rather than chosen: a Deny over
`NotAction: [a:*]` alongside a Deny over `NotAction: [b:*]` denies everything except
what both spare, so a merge that unioned the lists would describe something the
rendered policy does not do. `nil` and empty mean different failures at plan time —
nothing supplied a list, versus two inputs supplied lists that agree on nothing —
and both are refused with messages naming the inputs. Those messages are
golden-tested under `internal/compilesets/testdata/refusals/`, because in the case
they cover the message is the whole of what automat delivers.

### The hash now covers a payload

`content_sha256` was defined (DESIGN.md §8) as the hash of canonicalized
`controls[]`. A top-level field beside `controls` would have sat **outside** it.

That is not a tidiness problem. This is the one field in the artifact whose
corruption both bricks an account and silently widens a Deny: an edit adding `s3` to
the list opens `s3:*` in every region the allowlist excludes, and under the old
definition it would have passed `VerifyContentHash` and every signature over the
artifact unremarked. So the hash input is now an explicit object:

```jsonc
{ "controls": [...], "region_deny_exempt_services": [...] }   // omitted when absent
```

Excluded: `schema_version`, and the whole `artifact` block — which carries the hash
itself, and whose `sources[]` entries are each vouched for by their own `sha256`.
`internal/artifact` names both groups (`HashCoveredFields`, `HashExcludedFields`) and
a reflection test requires every field of `Artifact` to appear in exactly one, so
adding a field is now a **decision about hash coverage that fails the build until it
is written down**. That mechanism is the actual fix; the payload object is just this
instance of it.

**Every artifact hash moved**, including `cmmc-l1`'s, which gained no field — the
payload is a wrapping object where it used to be a bare array. Both vendored
catalogs were regenerated and `TestContentHashIsStable`'s pin was updated with the
reason. This cost nothing, because nothing is published and no catalog has shipped;
the same change after publication would have been a migration.

The hash does **not** distinguish an empty `region_deny_exempt_services` from an
absent one (`omitempty` collapses them), and that is deliberate: no valid document
can carry `[]`, since both `minItems: 1` and the Go validator reject it. Two earlier
attempts to preserve the distinction in the payload were reverted. The place that
must not launder empty into absent is **canonicalization**, which runs before
`Write` validates — hence `sortedUniqueKeepEmpty` there, and
`TestCanonicalizeKeepsAnEmptyExemptListDistinguishableFromAbsent`.

### Both validators, both directions

The Go validator enforces the pattern, `uniqueItems`, and the present-but-empty
rejection; `TestGoAndSchemaAgreeOnRejection` pins the pair. Two gaps surfaced in
writing it, and both were real rather than fixture artifacts on inspection:

- **`uniqueItems` was missing from the Go validator.** Added. "Three namespaces
  exempted" and "two namespaces, one listed twice" are different claims to someone
  counting them — the same reasoning the maintainer ratified for the enforcement
  sets.
- **The present-but-empty case could not be expressed in the shared table**, which
  marshals a Go struct and so drops `[]` before the schema ever sees it. Moved to
  `TestBothValidatorsRejectAnEmptyExemptListOnDisk`, which feeds both validators the
  on-disk form directly. This one *was* a fixture limitation, and the fix was a
  better fixture rather than a weaker claim.

## Pre-publication change to environment-profile/v1: five tightenings, found by writing the drift detector

Pre-publication, **no version bump** — nothing has emitted or consumed an
environment profile. All five **strictly tighten** validation, so they land under
rule 6's audit-driven clause and are listed in `ROADMAP.md` for AUDIT-2 to ratify.
Every one was found the same way: by writing `internal/envprofile`'s
`TestGoAndSchemaAgreeOnRejection` and having to decide, field by field, what the two
layers each claim. The Go validator was written from DESIGN §7 and the schema from
the same source, and where they disagreed the schema was the looser of the two in
every case.

That direction is worth stating, because it is the direction that matters for this
document type. A control artifact is machine-generated by `gen/`; an environment
profile is **hand-written by an operator**, and the schema is what their editor
validates against while they write it. A constraint only the Go layer has means an
operator is told their document is fine by the one of the two things that checks it
they are actually looking at, and finds out otherwise from `vend`.

| field | was | now |
| --- | --- | --- |
| `environment_profile.title` / `.description` | `minLength: 1` / unbounded | `$defs/prose` / `$defs/long_prose` |
| `placement.ou_path[]` | `minLength: 1`, `maxLength: 128` | `$defs/ou_name` |
| `account.email_pattern` | `^[^@\s]+@[^@\s]+$` | explicit charset, `maxLength: 254` |
| `account.tags` | `{"type": "string"}` values, `not: ^automat:` keys | `$defs/tag_key` / `$defs/tag_value`, `maxProperties: 48` |
| `baseline.{attestations,evidence}.local_dir` | `minLength: 1` | `$defs/local_dir` |

**Why each, briefly, since the pattern is not the point in any of them:**

- **`title` and `description` are rendered into the birth certificate `vend`
  prints**, and into every report about the account afterwards. A newline in a title
  forges a row of that output. The obligation profile's title was already `prose`
  for exactly this reason, and the two documents sit side by side in the same table
  — so this was a *gap between two schemas*, not a new idea.
- **`email_pattern`'s negated character class admitted control bytes.**
  `^[^@\s]+@[^@\s]+$` refuses `@` and whitespace and nothing else: an escape byte,
  a `\x7f`, a 4KB address all passed. This value reaches `CreateAccount` and is
  echoed into the birth certificate, the onboarding bundle, and every error message
  about the vend. The explicit charset admits `{` and `}` **only** because the
  `{name}` placeholder needs them; whether the substitution is well-formed is a
  claim about structure that no schema can make, and `validateEmailPattern` makes it.
- **`tag_key` was half a defense.** The `^automat:` refusal was already there —
  that is AUDIT-1's C1 — but the **value** was any string of any length, and there
  was no cap on the number of tags. AWS caps tags per resource and automat applies
  its own conventional tags on top, so a profile at the cap makes a vend fail
  *after* the account exists.
- **`local_dir` is the one field in an environment profile naming somewhere automat
  WRITES.** `minLength: 1` admitted `/etc`, `../../..`, and `~/`. The document is
  attacker-controlled input in the threat model — an operator may have received it
  from a central IT office or forked an example — so an absolute path would let the
  profile choose the destination of every attestation stub and evidence manifest a
  vend produces. Four escape shapes are pinned in the agreement table.
- **`ou_name`** is not a traversal defense; nothing resolves an OU name as a path.
  It is bounded because the name is rendered into the plan `vend` prints **before it
  acts**, and a plan whose lines can be forged is not a plan an operator can
  approve. Interior spaces are admitted deliberately: `Research CUI` is what an
  operator actually names an OU, and refusing it pushes them to a name they mistype.

**`..` and `^automat:` are stated as sibling `not` clauses rather than folded into
the `pattern`,** for the reason the rule 8 sweep gave above: Go's regexp engine has
no lookahead, and a bound the Go validator cannot express is one this schema must
not express either. Rule 8 is only meaningful if both layers state the same thing.

### Three asymmetries are recorded as tests rather than closed

`TestGoAndSchemaAgreeOnRejection` is a drift detector, so anything it *cannot* cover
has to be visible somewhere. Each of these is asserted to **remain** asymmetric —
the test checks both that Go refuses the document and that the schema does not, so
the day a case moves it fails and has to be reclassified rather than silently
double-covered:

- **The schema cannot reject an unsupported major version.** A published contract
  that refused `2.0.0` would make every v2 document *invalid against v1* rather than
  merely unreadable by a v1 build, and would retroactively malform archived
  documents the day v2 ships. Which majors a *build* understands is Go's question,
  and `Validate` answers it with `"not supported by this build"`.
- **The schema cannot state a cross-field rule.** Six are Go-only: an OU path with
  `create_intermediate_ous: false`, the `{name}` placeholder count, a delivery
  bucket with the recorder off, a region in both `enable` and `disable`, a
  management mirror on the attestations block, two obligation references to one
  profile carrying different hashes.
- **The schema cannot compute a hash**, so it cannot check that an attestation names
  *this* document. `VerifyAttestationSubjects` does, and it is a separate call from
  `Validate` so that a caller who only wanted a syntax check cannot silently skip it.

### `[]`-versus-absent is a claim, and `omitempty` erases it

The agreement table marshals a mutated Go struct, so a present-but-empty
`permitted.regions` becomes **absent** on the way out and the schema correctly
accepts it — the disagreement would be in the fixture rather than in the contract.
Those cases feed both validators the **on-disk bytes** directly
(`TestBothValidatorsRejectAPresentButEmptyPermittedSetOnDisk`), which is what a
hand-edited profile actually is and the only form in which the empty list exists.
Same shape as `control-artifact/v1`'s `TestBothValidatorsRejectAnEmptyExemptListOnDisk`
and the same conclusion: a better fixture, not a weaker claim.

### One production defect, found by the same set of tests

`CanonicalContentJSON` reads `Permitted` off the **original** rather than the clone,
because the clone round-trips through JSON and `omitempty` would drop a
present-but-empty set — a deny-all document would otherwise hash as one that
constrained nothing. That override was correct and **too broad**: it also
resurrected a `permitted` block that `Canonicalize` deliberately drops, so `{}` and
absent hashed differently.

Those two distinctions look alike and point opposite ways:

- an empty permitted **set** is a deny-all, and *must* hash differently from absent;
- an empty permitted **block** asserts nothing, and *must* hash identically to absent.

Fixed by guarding the override on `Regions != nil || Services != nil`. The failure
mode it removes is the one this project's hash tests exist for: two documents a
reviewer reads as identical carrying different content hashes, which would make
`verify` report drift on a profile nobody touched — and an operator who saw that once
would stop believing the next report.

## classification-profile/v1 — 1.0.0 (unreleased, item C)

New schema, added for ROADMAP item C (institutional classification profiles).
**Listed here for AUDIT-2 ratification** under rule 6: it is a new contract rather
than a change to a published one, so nothing is bumped and nothing migrates, but a
new file in `schema/` is a new promise and belongs in the changelog on the way in.

**Why it exists, and why it is a sibling of `obligation-profile/v1` rather than a
variant of it.** An obligation profile answers *under what instrument, assessed
how*. A classification profile answers *which of this institution's levels is this
environment rated for* — a question every research university already has a
published answer to, and which no federal clause answers. The two axes are
independent: DFARS 7012 says nothing about whether a dataset is UC P4 or Stanford
High Risk, and UC's Protection Level 4 says nothing about which award clause
applies. An account is **rated for** a level; the rating is an operator
determination, recorded and hashed like every other one.

**automat never classifies data.** There is deliberately no matcher, no trigger
expression, and no evaluable form anywhere in this document. `determination` names
the human roles the institution's own policy makes responsible, `automat_determines`
is pinned `const false`, and level `examples` are a bounded reading aid for a person
in exactly the way an obligation profile's `applicability.hints` are. The reasoning
is the same and it is worth restating because this document type is where the
temptation is strongest: a tool that concluded "this dataset is Level 4" would be
*believed*, because it came from a tool that is right about everything else, and
wrong in the permissive direction it tells an institution its regulated data is
unregulated. `TestNoShippedProfileCarriesAMatcherOrTriggerExpression` walks the raw
JSON of every shipped document for predicate syntax and for two dozen field names a
match language would arrive under, because a match language arrives one plausible
entry at a time.

Notes on the choices that constrain future changes:

- **`rank` is a required explicit integer, and order comes from nowhere else.** Not
  from array position, not from the id, and above all not from the label. The
  published schemes run three levels (Stanford, MIT), four (UC, U-M), and five
  (Harvard, Georgia Tech) — so any code that indexed a fixed count would be correct
  on a third of the sample. Worse, the labels sort *opposite* between institutions:
  U-M's run Restricted / High / Moderate / Low downward, Harvard's DSL 1–5 upward.
  Sorting by label orders one correctly and the other exactly backwards, which is
  what makes label-sorting look right to anyone who tests one scheme. Both
  directions are fixtures for that reason, and `TestLabelOrderIsNotRankOrder`
  asserts they still disagree — if it ever passes trivially the fixtures stopped
  covering the case.
- **Ranks must be a dense run 1..N, which the schema cannot state.** It bounds a
  rank to 1..64; only the Go validator can see the sequence. Four entries ranked 1,
  2, 4, and 5 read as a complete four-level scheme, and nothing in the rendering
  says the third one is missing.
- **`composition.rule` is pinned `const "highest-water-mark"`.** Not an enum with
  one member for later expansion: a lattice with two joins is not a lattice. This is
  DESIGN §9's union law on a different lattice — *union of controls, intersection of
  permitted behavior, join of classification levels* — and all three say the
  stricter reading wins, so composing can never relax anything. `Join` is asserted
  idempotent, commutative, associative, and monotone over all three fixture widths,
  because a principle claimed in a doc comment and asserted nowhere is a claim about
  intent. Adding a second rule is a major version event, not an enum member.
- **`Join` refuses a level id from another institution's scheme** rather than
  answering. UC's P3 and Stanford's Moderate are not comparable, and a tool that
  ranked them would be publishing an equivalence neither institution stated.
  `UnknownLevelError` lists the profile's own ids least-protective-first, because the
  likeliest cause is a value typed from the other document.
- **`authorship` and `maintenance` are separate fields, and a derived profile may
  only be `example-and-forkable`.** Every institutional profile automat ships is
  automat's *reading* of somebody else's published policy. `authorship:
  derived-interpretation` then requires the `interpretation` block, and
  `maintenance: shipped-and-maintained` is refused outright — automat is not the
  upstream for anybody's data classification policy, and a document claiming
  maintenance implies a promise to track policy revisions that nobody made.
- **On a derived profile the only admissible attestation role is `interpreted-by`.**
  Pinned in the schema by an `if`/`then` and in Go. The *weaker* roles are the
  danger rather than the stronger ones: one inference from `reviewed-by` is "the
  institution reviewed this", which is the single claim a derived profile must never
  support. The vocabulary itself is unchanged — `evidence.Role`'s five values, shared
  with the other two document types, and `AllSignatureFormats` is asserted to match
  the environment profile's so that two documents cannot become two trust models.
- **The non-endorsement statement is checked in substance AND must name the
  institution.** Four phrases are required, each because dropping it changes what
  the paragraph claims; all three verbs in "not authored, reviewed, or endorsed"
  matter, because a reader who sees only "not authored" concludes the institution
  reviewed it. The name check is the half a phrase list alone would miss: "It was
  not authored, reviewed, or endorsed by the institution" is a grammatically
  complete disclaimer that disclaims nobody, and a reader will attach it to
  whichever institution they had in mind. Substance rather than verbatim, for the
  reason the policy caveat is: a check that failed on a hard wrap would be enforcing
  formatting while claiming to enforce meaning.
- **Every control cites a section of a hashed source, and where the source is silent
  the profile is silent.** The Go validator resolves *every* `citation_ref.source_id`
  in the document against `sources[]` — eleven distinct reference sites, each with
  its own case in `TestEveryCitationMustResolveToAHashedSource`, because a new
  citation field added without a corresponding line is a claim whose provenance
  nobody checks. Filling a gap with a sensible-looking control converts "this
  institution's policy says" into "automat thinks this institution should say".
- **`citation.date_basis` is three-valued rather than a required effective date.**
  Institutional policy is published in two forms that differ exactly here: a
  versioned standard carries an approval date, and a living web page carries nothing
  at all. Both shipped Stanford sources are dateless pages. An invented effective
  date on one of those would be automat's own fabrication sitting in the field a
  reader checks for staleness, so `retrieved-only` says so and requires a
  `source_id`, since the retrieval record is then the only thing dating the claim.
  `last-updated-in-document` is the third value because the UC PDF's footer date is
  printed *in* the document without necessarily being when the policy took effect.
- **`unmodeled_axes` makes an omission a disclosure.** UC is why the field exists:
  IS-3 classifies on two independent axes, Protection (P1–P4) and Availability
  (A1–A4), and automat models the protection axis alone because that is what an
  account is rated for. Silently omitting the other one would read to someone who
  knows IS-3 as an incomplete transcription and to someone who does not as though UC
  had one axis. The shipped entry additionally records that the two axes are *not
  parallel* — a Proprietor may select a lower Availability Level but may not lower a
  Protection Level outside the exception process — so an implementation that treated
  them as one axis would be wrong in the permissive direction.
- **`inherits` is within one issuer.** `issuer_id` must equal the profile's own, and
  `profile_id` must not. An enterprise policy and its research overlay sharing one
  classification table is the case the field exists for, and both belong to the same
  institution; across institutions it would assert something about somebody else's
  policy in a document attributed to this one.
- **Rule 8 applies to `$defs/level_id` and `$defs/slug`,** at both layers.
  `level_id` is the most-typed value in the model — an operator reads a level id off
  a rating and types it onto a command line — and it is patterned more tightly than
  the general slug (32 characters rather than 64) because it is short by nature in
  every published scheme: `p3`, `dsl4`, `high`. Issuer ids are patterned for the
  same reason plus one more: `inherits.issuer_id` is compared against `issuer.id`, so
  a value that differed only in whitespace would read as a match.
- **`status: superseded` is recordable rather than deletable.** An account rated
  years ago was rated under whatever was current then, and an evidence record naming
  a superseded profile is still a true record of what was believed.

### Four constraints were added while writing the drift detector

Found the way `environment-profile/v1`'s five were: by writing
`TestGoAndSchemaAgreeOnRejection` and `TestBothValidatorsRejectAPresentButEmptyArrayOnDisk`
and having to decide, field by field, what each layer claims. All four **strictly
tighten**, so they land under rule 6's audit-driven clause; pre-publication, no
version bump.

| field | was | now |
| --- | --- | --- |
| `levels[].controls` | `maxItems: 256` | `minItems: 1`, `maxItems: 256` |
| `levels[].examples` | `maxItems: 32` | `minItems: 1`, `maxItems: 32` |
| `levels[].external_obligations` | `maxItems: 32` | `minItems: 1`, `maxItems: 32` |
| `unmodeled_axes` | `maxItems: 8` | `minItems: 1`, `maxItems: 8` |

All four are the same defect and it is gate 4's: **`[]` and absent are different
claims, and they render identically to a reader.** An empty `controls` array says
the cited source was consulted and states no controls at this level. An absent one
declines to claim anything. The Go validator already refused the empty form on all
four ("present but empty"); the schema accepted it, so an institution editing a
fork against the published contract would have been told the ambiguous document was
fine.

The asymmetry between the two shipped documents is exactly this distinction in
practice, which is why it is tested rather than described: the UC Standard defines
four Protection Levels and defers controls to BFB-IS-3, so **no level in the UC
profile has a `controls` key at all**; Stanford's Minimum Security Standards *are* a
retrieved source, so every level there states controls (15 / 26 / 34, cumulative).
`TestWhereTheShippedSourceIsSilentTheShippedProfileIsSilent` asserts both halves,
because the tempting mistake available in this package is filling UC's empty control
lists in from a document automat has not retrieved.

### Four asymmetries are recorded as tests rather than closed

Each is asserted to **remain** asymmetric — the test checks both that Go refuses the
document and that the schema does not — so the day a case moves it fails and has to
be reclassified rather than silently double-covered:

- **The schema cannot reject an unsupported major version**, for the reason it
  cannot on the other two document types: a published contract that refused `2.0.0`
  would make every v2 document invalid against v1 rather than unreadable by a v1
  build.
- **The schema cannot state a cross-field rule.** Fourteen are Go-only and each has
  its own case in `TestGoOnlyChecksAreTheOnesNoSchemaCanState`: unresolved
  `source_id`s, duplicate level ranks / ids / labels, the dense-run check, the
  non-endorsement name and substance checks, `inherits` pointing at another issuer or
  at itself, duplicate source / citation / control ids, `only-by-exception` with no
  exception process, and `retrieved-only` with no source.
- **The schema cannot compute a hash**, so it cannot check that an attestation names
  *this* document. This matters more here than on an environment profile: a fork
  inherits automat's `interpreted-by` attestation, and if nothing recomputed the
  subject, automat's signature would appear to vouch for the institution's edits.
- **The schema cannot see whether `Join` implements the rule it declares.** Pinning
  `composition.rule` means the *document* declares highest-water-mark; nothing in a
  schema can assert that the code behaves. The four union laws are asserted in
  `TestJoinHoldsTheUnionLaws`, and `TestTheSchemaCannotSeeTheJoinLaws` records that
  the schema's agreement is about the declaration rather than the behaviour.

### The two shipped documents are pinned by name

`catalogs/classification/` holds exactly two profiles and
`TestTheShippedProfileSetIsTheOneThatWasApproved` names them. Adding a third is not
a data change: each of these states, under an institution's name, what that
institution requires, and the cost of being wrong is borne by an institution that
never agreed to be represented. The pair was chosen to maximally stress the model —
four ascending alphanumeric codes (UC P1–P4) against three word names (Stanford
Low / Moderate / High), so id-sorting works on one and fails on the other.

One rule-3 note, since a vendored catalog file is data automat ships: the Stanford
Minimum Security Standards name specific tools in nearly every control row, and the
transcription records the **obligation** rather than the tool ("Enable whole-disk
encryption using the platform's native facility"). Rule 3 requires that anyway, and
there is an independent second reason: the source marks most named tools as
*recommended*, so transcribing one as the requirement would misstate the policy in
the stricter direction. `TestNoShippedProfileNamesAVendorProduct` pins the specific
names this transcription had the opportunity to get wrong.

The model, the six published schemes it was derived from, the trust model for
cosigning a derived profile, and the four things automat must never become as a
result of publishing this format: `docs/institutional-profiles.md`.

## Pre-publication change to classification-profile/v1: `date_basis: not-retrieved`

No version bump — `classification-profile/v1` has not been published, so this lands
as part of the still-unreleased 1.0.0 rather than as a migration. After publication
this would be a **minor** bump: it adds an enum value and two `allOf` constraints,
and every document that validated before still validates unchanged.

**Listed for the record under rule 6 anyway**, since it is new structure rather than
a pure tightening: `date_basis` gained a fourth value, `not-retrieved`, and
`source_id` is now conditionally forbidden where it was previously required. Decided
by the maintainer following AUDIT-2's F5 finding and Q18.

**The gap.** All three prior `date_basis` values describe a document that WAS
retrieved: `published-effective-date` and `last-updated-in-document` name where the
date came from, and `retrieved-only` means "retrieved, and it bears no date." There
was no value for *never retrieved* — and a citation needs one, because a profile
legitimately names a governing document it has not read: BFB-IS-3 is the parent
policy UC's own Classification Standard says drives it, and a reader of the profile
needs to know it exists and governs even though automat has not fetched it (retrieval
was attempted and failed with a TLS error).

**What shipped instead, and why it was wrong in the machine-readable direction.**
The only value available that forbade `effective_date` was `retrieved-only`, so the
citation used it — asserting retrieved bytes that do not exist. The validator then
*required* `source_id` on that basis (with no published date, the retrieval record is
the only dating available), so the citation named the Classification Standard's
`source_id` instead — a different document, whose hash does not cover BFB-IS-3's
bytes at all. The prose note said "NOT RETRIEVED" in its first two words; the two
fields a tool actually reads asserted the opposite. Reasonable under the shapes
available, and wrong in the field that matters.

**The fix.** `date_basis: not-retrieved` forbids both `effective_date` and
`source_id` — unlike `retrieved-only`, which forbids only the former. Their absence
now means exactly what the prose says: nothing was read, so there is no date and no
hash to point at. A future reader filtering `citations[]` by `date_basis` gets an
honest partition instead of a `retrieved-only` entry that lies about being read.

Two shapes rule 6 also reserved were not chosen, and the reasoning is worth keeping
even though it is not the change: a separate `unretrieved_references[]` block would
keep `citations[]` meaning strictly "documents this profile read," at the cost of
splitting one reader-facing list into two; dropping the citation entirely was graded
worst of the three, because the reader would then lose the fact that BFB-IS-3 governs
the scheme at all — true and load-bearing whether or not automat has fetched it.

**Consequence for `catalogs/classification/uc-protection-levels.json`.** The BFB-IS-3
citation now carries `date_basis: not-retrieved` with no `source_id`. `citations[]`
is inside the content hash, so this moved the document's `content_sha256`, and its
`interpreted-by` attestation was re-signed over the new hash —
`TestTheShippedAttestationsAreAboutTheShippedContent` is what would have caught it
otherwise. The claim about the policy itself did not change: BFB-IS-3 still governs
and is still unread, and every checkable claim in this profile still traces to the
Classification Standard, the only document actually hashed.

`internal/classprofile/schema_conformance_test.go` gained accept cases for a bare
`not-retrieved` citation and reject cases for one carrying either forbidden field, so
both validators agree on the new value the same way they agree on the other three.

## Pre-publication change to evidence-manifest/v1: `manifest.genesis_sha256`

No version bump — `evidence-manifest/v1` has not been published, so this lands as
part of the still-unreleased 1.0.0 rather than as a migration. After publication
this would be a **major** bump: it is a new REQUIRED field on `manifest`, and
`additionalProperties: false` there means every document valid before it existed
still validates against the old shape but not against this one — a consumer
written against the old shape would correctly consider the addition breaking.

**Listed for the record under rule 6 anyway** for the same reason as
classification-profile's `not-retrieved` above: this is new structure, not a pure
tightening. Decided by the maintainer following AUDIT-2's H3 finding.

**The gap.** AUDIT-2 found that removing records from the FRONT of a manifest —
dropping `records[0..k]` and re-anchoring the new first record to `ZeroHash` —
leaves a chain that passes every chain-level check: sequence density, links, and
terminality can all be recomputed after the drop. `meta.created_at` was tried as
an anchor and rejected: after the truncation it still precedes the surviving
first record, so the bound is satisfied by construction. Nothing in the schema
bound the header to which record actually started the chain.

**The fix.** `manifest.genesis_sha256` is `records[0].record_sha256`, set once by
`Append` when the first record lands and compared against the current
`records[0]` on every load (`validateHeaderAgainstRecords`). A head-truncated
chain whose header is left unedited no longer matches: re-anchoring the
survivor recomputes its hash, since `previous_sha256` is inside `record_sha256`.

**Required, not optional.** An optional anchor is a field an attacker can simply
omit, which is cheaper than the truncation it exists to catch — the same failure
mode the package already documents for signatures (an unsigned record's absence
is not flagged by `VerifyChain`, which is why `SignatureCoverage` exists to let a
reader ask). Required is available now for the same reason the field itself is:
nothing has emitted a 1.0.0 manifest yet.

**What this does NOT close, stated as plainly as the rest of the package's
disclosures.** `genesis_sha256` sits OUTSIDE every `record_sha256`, for the same
reason `meta.created_at` and `meta.account_id` do: covering the header in the
record hash would let a typo in `created_at` invalidate the whole chain, which
`internal/evidence/validate.go`'s H4 comment already rejected as the wrong fix
for a different finding. So a rewriter who edits the header ALONGSIDE the
truncation — recomputing `genesis_sha256` to match the new `records[0]` — produces
a document that is internally consistent again. What remains is exactly what
remained before this field existed: detectable only by a reader holding a SECOND
copy of the header, e.g. the management-side mirror DESIGN §11 describes. This
converts head truncation from *undetectable from the local copy alone* to
*detectable by any holder of a second copy of the header* — real and bounded,
not closed. The residual is `docs/open-questions.md` Q21.

**Consequence for the golden manifest.** `internal/evidence/testdata/golden/
manifest.json` gained the field on regeneration (`AUTOMAT_UPDATE_GOLDEN=1`); no
`record_sha256` changed, which is the empirical proof that `Meta` sits outside
every record hash — the same check M5 made with a content hash elsewhere.

`TestPrefixTruncationIsRefused` (`internal/evidence/header_binding_test.go`) now
has four parts instead of three: header-unchanged truncation refused (new),
`created_at` still not sufficient on its own (kept, now explicitly *not* the
mechanism), the residual — header rewritten alongside the truncation still loads
(the open part that remains) — and the signed case, isolated from the anchor by
rewriting it too, so the link-and-signature mechanism is shown to work
independently of `genesis_sha256`.

## Pre-publication change to obligation-profile/v1: the content-hash scope, stated in a `$comment`

No version bump — `obligation-profile/v1` has not been published, and this adds a
`$comment` rather than a constraint, so it changes nothing about which documents
validate. Listed anyway under rule 6, since it answers a question the schema
previously left open and any answer to it is a decision worth a maintainer's
ratification, not only a code change.

**The gap.** `signatures[].content_sha256` was described as "the document content
hash" without saying which bytes. The other two document types with a content hash
define the payload explicitly — `control-artifact/v1` in its canonicalizer,
`environment-profile/v1` likewise, `classification-profile/v1`'s `HashCoveredFields`
— but nothing said so here.

**The fix — a comment, not a canonicalizer.** ROADMAP's Phase 4 stage 0 keeps
`obligation-profile/v1` "data and schema only, no Go types, no `assess`" until that
phase is written, and a canonicalizer is a Go type. So the scope is stated as a
`$comment` on the schema: everything except `schema_version` and `signatures` is
covered — `profile`, `citations`, `control_catalogs`, `assessment`,
`determinations`, `poam`, `scoring`, `submission`, `applicability`, `status`,
`review_by`, `policy_caveat`, `sources`. This defines the contract; nothing
enforces it yet. `internal/catalog.ObligationFacts.ContentSHA256` stays empty and
`envprofile.CheckObligations` continues to report the comparison as unknown, per
Q15's own note, until a canonicalizer implementing exactly this scope is written.

**Why the coverage is wide, following `classification-profile/v1`'s precedent for
the same choice.** An obligation profile, like a classification profile and unlike
an environment profile, builds nothing — its entire content is a set of claims
about a published instrument, and there is no field here whose alteration leaves
the claims intact. `status` and `review_by` are covered rather than excluded as
administrative, because a profile re-marked `superseded` or given a new
`review_by` is a different claim about the state of the world. `profile.id` and
`profile.title` are covered too, unlike `classification-profile/v1`'s excluded
identity block — an obligation profile is not forked-and-retitled the way a
derived institutional profile is, so there is no fork-without-reattestation case
to protect.

`TestObligationProfileHashScopeCommentNamesEveryFieldExactlyOnce`
(`internal/artifact/obligation_profile_test.go`) pins the comment against the
schema's own top-level property list, so a future field addition that forgets to
update the comment fails loudly rather than leaving a scope note that quietly
stops matching what it describes.

## Pre-publication change to evidence-manifest/v1: `operation` gains `assess`

Landed while scoping Phase 4's `assess` (Stage 3, the CMMC L1 MET/NOT MET
summary). No version bump: `evidence-manifest/v1` remains unreleased, and this
is the same shape as the `custody-transfer` addition above — a value added to
the closed `operation` enum before any consumer of the 1.0.0 shape exists.

**What it is.** `operation` gains `"assess"`, alongside the Go
`evidence.OpAssess` constant. `assess` writes nothing to AWS — it is read-only,
the same as `verify` — but a self-assessment is a claim made at a point in time
against a specific artifact hash and a specific set of operator determinations,
and the manifest chain is what lets a later reader tell whether a report
predates a baseline change (`docs/assessment-reporting.md`, "Outputs"). So it
gets the same treatment `verify` already has: worth recording that it ran, not
worth a dedicated object the way `custody-transfer` needed one.

No new record fields: an `assess` record uses the existing `artifact` and
`environment_profile` reference shapes for the same purpose `verify` puts them
to, plus (once `internal/assess` exists) a reference to the operator-
determinations file it read, following `evidence.DocRef`'s existing id +
`content_sha256` shape rather than a new field — the determinations file is
content-hashed into the chain "like a catalog"
(`docs/assessment-reporting.md`, "Inputs"), and a catalog is already how
`DocRef` is used.

**Landed (AUDIT-5).** `internal/assess` now exists, and `writeAssessEvidence`
(`cmd/automat/assess.go`) writes exactly this reference: `record.determinations`
(Go: `Record.Determinations`, a `*DocRef`), present when `--determinations`
named a file and absent otherwise — the same absent-is-honest convention
`Result.Determinations` follows. **Correction to this entry's own wording**:
the paragraph above says "rather than a new field", which read literally
would mean reusing `artifact` or `environment_profile` to carry the
determinations hash — neither is the right subject, and doing that would
make one field's meaning depend on which operation wrote the record. What
shipped, and what this paragraph most likely meant, is a new field
(`determinations`) built from the *existing* `DocRef` shape rather than a
new bespoke object type — the same relationship `artifact` already has to
that shape. Recorded here rather than silently reinterpreted, per CLAUDE.md's
instruction to flag rather than reinterpret when design and code disagree.

## assessment-result/v1 — 1.0.0 (unreleased, Phase 4 assess Stage 3)

New schema. **Listed here for maintainer ratification** under rule 6: a new
contract rather than a change to a published one, so nothing is bumped and
nothing migrates, but a new file in `schema/` is a new promise and belongs in
the changelog on the way in — the same footing `obligation-profile/v1` was
ratified on.

**Why it exists.** `docs/assessment-reporting.md`'s own requirement: "Every
rendered form renders FROM [the canonical result], and none is authored
independently." Without a canonical document, the CMMC L1 summary (Stage 3)
and the later 800-171A worksheet and SPRS score (Stages 1-2) would each compute
their own answer to "is this account compliant", which is exactly how two parts
of one tool start disagreeing with each other.

Notes on the choices that constrain future changes:

- **`objectives[].evidence_class` mirrors `config_rule.provenance`'s
  `aws-mapping`/`curated` split, on purpose.** That field exists so a reader can
  audit automat's own judgment separately from AWS's; this one exists so a
  reader can audit the operator's assertions separately from automat's
  observations (`docs/assessment-reporting.md`, Invariant 2's two-layer table).
  An assessment where every objective is `operator` is a spreadsheet with extra
  steps, and the schema makes that visible rather than optional.
- **As of Stage 3, `evidence_pointer` is absent on every objective this schema
  will actually see.** `cmmc-l1`'s catalog carries no SCP fragments, and no AWS
  Config read interface exists yet, so there is no machine evidence for any of
  the fifteen L1 practices in this build. The field stays in the schema because
  Stage 3's shape must not need to change once a Config-read path or
  `internal/baseline` exist — they would only start populating it, not require
  a new document version.
- **`l1_summary` is a Stage-3-specific sibling field, not a polymorphic
  "summary" object.** A later regime's own rollup (an SPRS score, say) gets its
  own field rather than overloading this one, so a reader can tell from the
  document's own shape which regime it was rendered under without inspecting
  `profile.id` first.
- **`account.scope_statement` is required and is the operator's own words,
  never automat's inference.** `docs/assessment-reporting.md`, "Scope is an
  input, not an inference": whether the AWS account equals the system boundary
  the assessment concerns is the operator's assertion, and the schema requires
  it be stated rather than left implicit in a cover note that does not survive
  being forwarded.
- **`determinations` is optional, not required-but-nullable.** A result
  rendered with no determinations file at all (every objective silently
  NOT MET) is a real, legitimate state — the honest "nothing has been
  determined yet" case — and an absent field says that plainly, where an empty
  reference object would read as "a determinations file existed and asserted
  nothing," a different and false claim.
- **Content hash is out-of-band**, the same convention `environment-profile/v1`
  and `control-artifact/v1` use: no self-referential hash field inside the
  document, recorded instead in the evidence manifest record that references it
  and in `operator-determinations-v1`'s own `determinations` back-reference.

## operator-determinations/v1 — 1.0.0 (unreleased, Phase 4 assess Stage 3)

New schema, ratified alongside `assessment-result-v1` for the same reason.

**Why it exists.** The mechanism that makes Invariant 2 enforceable at all:
"automat's proposals may only ever understate compliance... `MET`/`SATISFIED`
comes from the operator's determinations file or from nowhere"
(`docs/assessment-reporting.md`). Without this file as a separate document, a
satisfied value would have to be typed directly into a generated report, which
is exactly the signable-artifact shape Invariant 1 forbids. As a file it is
reviewable, diffable, and content-hashed into the evidence chain like a
catalog, so a later reader can tell which human assertions were in force when
a report was generated, and no assertion can be revised after the fact without
the hash moving.

Notes on the choices that constrain future changes:

- **`determinations[].value` is validated against the named obligation
  profile's `determinations.values` at load time, not against a hardcoded
  enum in this schema.** Each regime spells its own vocabulary
  (`MET`/`NOT MET` vs. `SATISFIED`/`OTHER THAN SATISFIED`), and a schema-level
  enum here would either have to union every regime's spellings — letting a
  CMMC determination carry an 800-171 value undetected — or be regime-specific,
  which a shared document type cannot be. The profile is the source of truth
  for its own vocabulary; this schema only requires *some* prose value be
  given.
- **`determinations[].id` is round-trip patterned (CLAUDE.md rule 8) as
  `$defs/round_trip_id`**, not `$defs/prose`: `assessment-result-v1`'s
  per-objective `determination` field points back to this id, so an operator
  reviewing a rendered result may need to find this exact entry again by eye or
  by search in the source file. A value carrying a space or a quote would
  break both.
- **`revision_determination` is a top-level, optional field — not nested under
  a specific determination.** It answers a different question than the
  per-objective determinations do (which revision of a control catalog applies
  at all, not whether a specific practice is met) and it is required by
  `assess`'s own refusal-to-run rule only when the named obligation profile
  leaves its `control_catalogs[].revision_policy` as `operator-determined`
  (`nih-cadr-dua` is the shipped case). The schema cannot express "required
  only under a condition read from a different document," so that refusal is
  enforced in Go, in `automat assess` itself, before this file is even fully
  consulted — the schema states the shape the determination takes when it is
  given, not when it must be.
- **Content hash is out-of-band**, matching `assessment-result-v1` and every
  other document in `schema/`.

## objectives-catalog/v1 — 1.0.0 (RATIFIED 2026-08-11)

New schema file, added while retrieving the NIST SP 800-171A objectives catalog
(ROADMAP.md, "Backlog — research complete" › "Assessment Stages 1-2", item 3).
**Approved by the maintainer 2026-08-11**, as part of the Phase 0 consolidated pre-approval ask
ROADMAP.md's backlog section described: this schema file, the not-yet-built weight-table schema
file, and `assessment-result-v1`'s proposed `worksheet_summary`/`score` sibling fields were
presented together and approved together. This file and the sibling fields are ratified; the
weight-table schema remains to be drafted and is not yet built (see ROADMAP.md's "Assessment
Stages 1-2" item 2 — the DFARS weight table itself is still mid-transcription).

**Why it is a NEW, STANDALONE document type rather than a field on `control-artifact-v1`'s
`Control` object.** `control-artifact-v1.schema.json` is shared by every compiled catalog this
project ships — `cmmc-l1`, `800-171r2`, `baseline-protection` — and only the 800-171 family has
an assessment-objective decomposition to carry. Adding an `objectives` field to `Control` would
be a schema change reaching every one of those catalogs for a shape only one of them needs; a
sibling document that references a control catalog's ids without redefining them costs nothing
to the schema every other catalog validates against.

**Shape.** `catalog` (id, title, the `control_catalog_id` it decomposes, provenance `sources[]`,
`compiled_at`, `content_sha256` — the same fields `control-artifact-v1`'s `artifact` block carries,
minus the `artifact`-union source member, since an objectives catalog is never itself a union) and
`requirements[]`, each a requirement id plus its `objectives[]` (id, statement, and a reserved,
currently-unpopulated `method_class`) and one `assessment_methods` triple (`examine`, `interview`,
`test`) recorded **per requirement, not per objective** — NIST's own CPRT data model attaches one
triple of candidate evidence sources to the requirement as a whole, not to each lettered
determination statement, so this schema follows that shape rather than inventing a finer one the
source does not support.

**`requirements[].id` must equal an id present in the named `control_catalog_id` catalog's
`controls[]`, and the schema cannot state that.** JSON Schema cannot look inside a second document,
so this is a Go-side obligation: `internal/assess.ObjectivesCatalog.CrossReferenceControlArtifact`
checks both directions — every objective's requirement id exists in the control artifact, and
every control artifact requirement has at least one objectives entry — and `gen/catalog`'s
`compileFromObjectives` refuses to compile if either direction has an orphan. For the shipped
`800-171a-objectives` catalog against `800-171r2`, the two requirement-id sets are exactly equal:
no orphan either direction, confirmed by set equality at curation time as well as at compile time.

**No Go worksheet or scoring code was added, and none should read this until Stage 1 is scoped.**
`internal/assess.ObjectivesCatalog`, `RequirementObjectives`, and `Objective` are load-bearing
types with a loader (`LoadObjectivesCatalog`/`LoadObjectivesCatalogFS`), a validator, and the
cross-reference check above — but nothing in `internal/assess` yet renders a worksheet, scores
anything, or wires a CLI flag to this catalog. That is Stage 1 (ROADMAP.md, "Assessment Stages
1-2", item 4), a separate, later task gated on this schema's actual ratification.

**Vendored under `catalogs/objectives/`, not the top level.** The top level of `catalogs/` is
implicitly reserved for `control-artifact-v1` documents: `internal/compilesets`'s
`TestTheModelUnderstandsEveryOperatorTheCatalogsUse` globs `catalogs/*.json` and loads every match
as a control artifact, so a document of a different schema at that level fails that load rather
than being silently skipped by it. `catalogs/embed.go`'s `//go:embed` directive was widened to
include `objectives/*.json` alongside the existing `obligations/*.json` and
`classification/*.json` subdirectory globs.

Retrieval: NIST CPRT, framework `SP_800_171A`, version `1.0.0` (the version that pairs with Rev 2,
which is what `800-171r2` compiles — version `3.0.0` pairs with Rev 3 and is out of scope). The
documented endpoint shape worked on the first attempt, substituting `sp_800_171a_1_0_0` for
`800-171r2`'s working `sp_800_171_2_0_0` — no third-party reference-implementation lookup was
needed this time, unlike `800-171r2`'s own retrieval (docs/open-questions.md Q4).

## evidence-manifest/v1 — `rotate` operation and `rotation` block (RATIFIED 2026-08-11)

Widens the closed `operation` enum with a new terminal kind, closing Q23 (docs/open-questions.md
— "`verify`'s evidence manifest has no rotation, and an hourly cron reaches the size ceiling in
about a year"). **Approved by the maintainer 2026-08-11**, as part of the same Phase 0
consolidated pre-approval ask that ratified `objectives-catalog/v1` above (ROADMAP.md's Phase 0
section) — a rule-6 schema decision, not a draft.

**Why a new operation and a new object, not a reuse of `custody_transfer`.**
`custody_transfer.successor_manifest_id` is already schema-legal and, before this change,
unused — reusing that shape for rotation was the first thing considered. It does not fit:
`custody_transfer` requires `transferee`, `effective_date`, and `reason` fields that answer "who
holds the chain now and from when", and rotation has no answer to that question. Nobody's
custody changes when a manifest reaches its record-count threshold; the file is simply full and a
fresh one continues it. A rotate record carrying an empty `transferee` would read as a transfer
to nobody, which is not what happened. So `rotation` is a **separate** object
(`successor_manifest_id`, `reason`, `record_count`), mirroring `custody_transfer`'s pairing
discipline rather than its fields: required on a `rotate` record and forbidden on every other
kind (the same `if`/`then`/`else` shape as `custody_transfer`'s own rule), and — unlike
`custody_transfer.successor_manifest_id`, which is optional because a transfer may leave
automat's scope entirely — `rotation.successor_manifest_id` is **required**: a rotation is
automat's own housekeeping and always produces a successor.

**The terminal-record rule generalizes to cover both kinds.** `records[]`'s "at most one, and it
must be last" invariant — the half JSON Schema can state (`not`/`contains`/`minContains`) plus the
half it structurally cannot (an array's final position, enforced only by
`internal/evidence`'s chain validator, per the existing `custody_transfer` entry below) — now
applies to `rotate` records too, via a new `is_rotate` `$def` mirroring `is_custody_transfer` and
an added `allOf` clause. `internal/evidence.Record.IsCustodyTransfer` is renamed
`IsTerminal` and returns true for either kind, with every call site (`chain.go`'s `Append`,
`validate.go`'s chain-order check) updated to the one generalized check — there is no second,
divergent "is this the end of the chain" test living alongside it.

**Trigger: automatic, at a 2,000-record threshold** (`evidence.RotateThresholdRecords`), well
under the ~8,971-record ceiling `MaxManifestBytes` implies at roughly 935 bytes per record —
rotation is meant to happen long before a manifest is at risk of refusing a write, not as a
last-resort recovery from one. Wired into `verify` (the command Q23 is actually about — a `verify`
run on an hourly cron against one account is the shape that reaches the ceiling) and,
defensively, into `vend` (far less likely to reach the threshold in one run, but cheap to guard).
Neither rotates silently: both print an explicit notice ("Rotated evidence manifest: `<path>` is
now closed (N records); continuing at `<path>`") — this project's stated preference for explicit,
disclosed behavior over implicit magic (ROADMAP.md's Q23 entry).

**`Meta.PredecessorSHA` — a cryptographic link between the closed manifest and its successor — is
explicitly NOT part of this change.** ROADMAP.md's Q23 entry names it as "a distinct, later,
also-needs-pre-approval ask" and is explicit that the two must not be bundled. This change
connects the two manifests only by the named pointer (`rotation.successor_manifest_id`); the
successor's own `genesis_sha256` is computed the ordinary way, by `Append`, when its first record
lands — nothing here seeds it from the predecessor's final hash.

No migration: every manifest written before this change has no `rotate` records and remains
valid, since the new operation and block are additive to the closed sets they widen.
