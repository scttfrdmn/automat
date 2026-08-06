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
