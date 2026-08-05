# Open questions

Uncertainties recorded rather than guessed at, per CLAUDE.md's working style: write
the code behind an interface, note what only a live org (or a maintainer decision) can
answer, and keep going.

Each entry says what is unknown, what the code currently assumes, and what would settle
it. Delete an entry when it is answered; do not silently reinterpret one.

---

## Phase 0

### Q1 — Set-valued conformance-pack parameters have no union order

**Unknown.** Several AWS Config rule parameters are conceptually sets encoded as
comma-separated strings: `blockedActionsPatterns` (`kms:Decrypt,kms:ReEncryptFrom`),
`authorizedTcpPorts` (`443`), and `blockedPort1`–`blockedPort5`. Semantically, blocked
items should **union** and authorized items should **intersect** when two control sets
bind the same parameter — both of which tighten behavior, which is what DESIGN §9 wants.

**Current assumption.** All are declared `exact`, so two control sets binding the same
one with different values is a hard error demanding an explicit override. That is
conservative and never silently loosens a control, but it will produce spurious conflicts
once a second catalog (800-171r2) binds the same rules.

**What would settle it.** A maintainer decision on whether the schema should model
set-valued parameters as a first-class kind — e.g. `order: "union" | "intersect"` with a
declared separator — rather than as opaque strings. **This is a schema change**, so per
CLAUDE.md it needs a human decision, a version bump, and a `schema/CHANGELOG.md` note.
Deferred to Phase 4 (union hardening), where the conflict actually bites.

### Q2 — DESIGN §8's example control ID uses CMMC 1.0-era numbering

**Unknown.** Nothing, strictly — this is a resolved design/code divergence, recorded so
it is not rediscovered as a bug.

**Current state.** DESIGN §8's sketch shows `"id": "AC.L1-3.1.1"`. That form is
CMMC 1.0-era; 32 CFR 170.14(c)(1) assigns Level 1 requirements identifiers of the form
`AC.L1-b.1.i`. `catalogs/cmmc-l1.json` uses the final-rule IDs, with the legacy AWS-side
identifier preserved in `crosswalk.aws_config_mapping_id`.

**What would settle it.** Updating the example in DESIGN §8 so the source of truth and
the code agree. Flagged rather than edited: DESIGN.md is the human's document.

### Q3 — AWS's mapping of identification (3.5.1) to logging rules

**Unknown.** Whether AWS's reading is one automat should adopt unchanged. AWS maps nine
**logging** rules (CloudTrail, ELB, RDS, S3, API Gateway, WAF) to
`IA.L1-3.5.1` / `IA.L1-b.1.v`, "identify users, processes, or devices" — the reading being
that identification is evidenced by attributable logs. Defensible, but not the only
reading; a stricter one would look at identity configuration rather than log emission.

**Current assumption.** AWS's mapping is used as published. The alternative is automat
inventing its own mapping, which is a larger commitment than Phase 0 should make.

**What would settle it.** Human review of the assignment table in `gen/MAPPING-NOTES.md`.

### Q4 — No OSCAL catalog exists upstream for 800-171 Rev 2

**Unknown.** What the authoritative machine-readable source for Rev 2 control text should
be. `usnistgov/oscal-content` publishes an OSCAL catalog for **Rev 3** only. Rev 2 is what
CMMC Level 2 is assessed against today (DoD class deviation, DESIGN §8), so the catalog
automat most needs has no OSCAL form.

**Current state.** Not yet relevant — Phase 0's remaining catalogs (`800-171r2`,
`800-171r3`, `baseline-protection`) were explicitly out of scope for the first session.

**What would settle it.** A maintainer decision between deriving Rev 2 text from the
NIST PDF/CSV, deriving it from the Rev 3 OSCAL catalog plus the published Rev 2↔Rev 3
mapping, or hand-curating it as was done for FAR 52.204-21.

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
