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

Both landed during Phase 0 review, before `1.0.0` was published. **No version
bump**, because there is no consumer of the earlier shape to migrate; if either
change were made after publication it would be a major bump, since both tighten
what validates.

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
