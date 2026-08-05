# Open questions

Uncertainties recorded rather than guessed at, per CLAUDE.md's working style: write
the code behind an interface, note what only a live org (or a maintainer decision) can
answer, and keep going.

Each entry says what is unknown, what the code currently assumes, and what would settle
it. Delete an entry when it is answered; do not silently reinterpret one.

---

## Phase 0

### ~~Q1 — Set-valued conformance-pack parameters have no union order~~ — RESOLVED

**Resolved** at the Phase 0 review. The schema gained `set-union` and `set-intersect`
orders plus an optional `set_separator` (default `,`), before publication, so no version
bump; both changes are recorded in `schema/CHANGELOG.md`. Deny-shaped sets
(`blockedActionsPatterns`, `blockedPort1`–`blockedPort5`) are `set-union`; the allow-shaped
`authorizedTcpPorts` is `set-intersect`. `internal/artifact/order.go` implements
resolution, with monotonicity and the semilattice laws as property tests.

**One thing Phase 4 still has to handle**, carried forward rather than left implicit:
`blockedPort1`–`blockedPort5` are one prohibited-port set spread across five slots, and
`RESTRICTED_INCOMING_TRAFFIC` types each as a single integer. Per-slot `set-union` is
correct, but the artifact-level union must **re-slot** the unioned ports across the five
parameters and hard-error above five, rather than emit a joined value the rule would
reject. Also recorded in `gen/MAPPING-NOTES.md` and at the declaration in
`gen/catalog/enforcement.go`.

### ~~Q2 — DESIGN §8's example control ID uses CMMC 1.0-era numbering~~ — RESOLVED

**Resolved** at the Phase 0 review: the human confirmed the catalog is right and DESIGN
§8's example was the error. §8 now shows `"id": "AC.L1-b.1.i"` with a pointer to
32 CFR 170.14(c)(1), and its `config_rules` sketch carries `provenance` and the five-value
`order` enum. The legacy AWS-side identifier remains addressable in
`crosswalk.aws_config_mapping_id`.

### ~~Q3 — AWS's mapping of identification (3.5.1) to logging rules~~ — RESOLVED

**Resolved** at the Phase 0 review: `IA.L1-b.1.v` **stays as-is** under the aws-mapping
layer. AWS maps nine logging rules (CloudTrail, ELB, RDS, S3, API Gateway, WAF) to
`IA.L1-3.5.1` / `IA.L1-b.1.v`, on the reading that identification is evidenced by
attributable logs. That reading is defensible, and second-guessing a mapping AWS does
publish is a different kind of act from filling a gap it leaves — the curated layer exists
for the latter only. Recorded in the assignment table in `gen/MAPPING-NOTES.md`.

### ~~Q4 — No OSCAL catalog exists upstream for 800-171 Rev 2~~ — RESOLVED, build deferred

**Resolved.** The premise was right but incomplete: `usnistgov/oscal-content` publishes an
OSCAL catalog for Rev 3 only, **but NIST's CPRT holds a complete legacy Rev 2 dataset**, so
no PDF extraction is needed. Verified during the Phase 0 review:

- Framework `SP_800_171`, version identifier `SP_800_171_2_0_0`, labeled "Revision 2",
  `frameworkVersionId` 10, status Production.
- `…/nudp/framework/version/SP_800_171_2_0_0/type/requirement/elements` returns HTTP 200
  and **exactly 110 requirements with full text and no empty entries**, across 14 families.
- `…/type/family/elements` returns the family titles (3.1 "ACCESS CONTROL" … 3.10
  "PHYSICAL PROTECTION").

The endpoints are the undocumented REST API behind the CPRT web UI, discovered from
`csrc.nist.gov/extensions/nudppublic/main.js`. Undocumented means unstable, which is fine
here: the retrieved JSON is hashed into `artifact.sources` and vendored, so the compile does
not depend on the endpoint staying up. **Rev 2 is withdrawn and will never change**, so the
extraction is frozen once reviewed — a one-time acquisition, not a refresh cycle.

**Plan for the `800-171r2` build (not started; explicitly out of scope for this session).**

1. Retrieve the CPRT requirement and family element sets; record each response's sha256,
   `retrieved_at`, and URI in `artifact.sources` as `catalog` entries.
2. Emit a reviewable `gen/` intermediate — the 110 requirements with family, number, and
   verbatim text — for hand review before it becomes a catalog. Same shape as the curated
   FAR source: a committed file a human has read, not a live fetch.
3. AWS mappings come from two API-retrievable sources, recorded as `mapping` entries: the
   **Security Hub NIST 800-171 Rev 2 standard** (control set + rule associations) and the
   **Audit Manager 800-171 Rev 2 framework** (control-to-evidence-source mappings). Both
   are richer and more current than a conformance pack, and both can be captured to a
   vendored file the same way.
4. Everything unmapped stays `procedural` with an attestation stub (ROADMAP Phase 0), and
   the same orphan check applies: a mapping AWS publishes that no requirement claims fails
   the compile.
5. Expect the r2 catalog to bind the same parameterized rules as `cmmc-l1`
   (`iam-password-policy`, `restricted-common-ports`, `vpc-sg-open-only-to-authorized-ports`).
   That is the first real exercise of the union orders resolved in Q1, and where the
   `blockedPort` re-slotting caveat will first matter.

Adjacent CPRT datasets found while checking, potentially useful later:
`SP-800-171-Rev-2-to-SP-800-171-Rev-3`, `NIST SP 800-171 r2 to CMMC L1`,
`NIST SP 800-171 r2 to CMMC L2`, `NIST SP 800-171 R2 to NIST SP 800-53 R5`, and
`SP_800_171A` (1.0.0 and 3.0.0).

---

## Awaiting a live org

Nothing here can be answered from fakes; all of it is Phase 1+ and DESIGN §16 already
names most of it. Listed so the smoke-test runbook (Phase 5) has a checklist.

### Q5 — What can `preflight` actually detect about delegation from the member side?

DESIGN §4 says preflight should report delegated-admin status "via `DescribeResourcePolicy`
effects where visible". Whether a member account can read the delegation policy that grants
it policy-management rights is unverified. If it cannot, preflight must be told rather than
detect, and the onboarding bundle needs to carry that fact.

### Q6 — SCP quota edges under union output

DESIGN §16 names the quotas (5 SCPs per target, 5120 characters each). What is unverified is
how close a real union of `cmmc-l1` + `800-171r2` + a campus baseline comes to them, and
therefore how aggressive the packer must be about merging Action lists.

### Q7 — Does `MoveAccount` reliably succeed immediately after `CreateAccount`?

DESIGN §5 documents the cosmetic race and requires treating create-without-move as an error
state with a `parked` outcome. The retry policy that is actually needed — how long, how many
attempts — is an empirical question.
