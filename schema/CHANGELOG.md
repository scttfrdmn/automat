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
- `scp_statement.exempt_automation_role` is a boolean marker rather than a
  literal ARN, because the in-account automation role ARN is not known until
  vend time. The SCP packer materializes the condition.
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

## profile/v1 — 1.0.0 (unreleased, Phase 0)

Initial definition per DESIGN.md §7 and §13. No migration.

- `account.tags` forbids keys matching `^automat:` — automat's conventional tags
  (DESIGN.md §14) are applied by the tool and must not be overridable by a
  profile, since they are what `list` and `verify` key off.
- `placement.ou_path` is capped at five entries, mirroring the OU nesting limit
  (DESIGN.md §3, fact 10).

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
