# SESSION — Phase 0, part 1

Scope was Phase 0 only, stopping at a review checkpoint. `make build test lint` is green;
126 tests pass; `golangci-lint` reports 0 issues.

## What exists

| Deliverable | State |
|---|---|
| Repo scaffolding (module, Go 1.24, Apache-2.0, `.gitignore`, `.golangci.yml`, Makefile) | done |
| `schema/` — control artifact, environment profile, evidence manifest + CHANGELOG | done |
| `internal/artifact` — Go types, canonicalize, content hash, load/validate, round-trip tests | done |
| `gen/` compiler + `catalogs/cmmc-l1.json` + golden test | done |
| `gen/MAPPING-NOTES.md` — 15 enforcement rationales **for your review** | done |
| Stub cobra root (`automat`, `automat version`) | done |
| `800-171r2`, `800-171r3`, `baseline-protection` catalogs | **not started** (out of scope) |
| Union code, `automat compile` and every other subcommand | **not started** (out of scope) |

No AWS SDK dependency exists yet, and nothing in this tree makes a network call at build,
test, or run time.

`catalogs/cmmc-l1.json` — 15 controls, `content_sha256`
`5721c6d1eb2a68a284cdd6656b5a33f964a369e5c24188f064fa59f35ce04f57`, 9 `config-rule` /
6 `procedural` / 0 `scp` / 0 `baseline-protection`.

## The thing to review first

**`gen/MAPPING-NOTES.md`** — the fifteen enforcement-class assignments, as you asked.

The short version: I did not exercise judgment about what *could* be automated. A control
is `config-rule` iff AWS's published conformance-pack mapping associates rules with it, and
`procedural` otherwise. That rule produced 9/6 with no discretion left over, which is why
the notes read as provenance rather than opinion.

Three procedural assignments are the ones I'd expect you to push back on — `AC.L1-b.1.iv`
(public content), `SC.L1-b.1.xi` (subnetwork separation), `SI.L1-b.1.xiv` (malicious-code
updates). Rules exist in the pack that bear on all three, but AWS maps them to *other*
requirements. Reusing them would mean automat asserting an enforcement AWS does not claim,
in an artifact whose hash goes into an evidence manifest. `candidateForEnforcement` in
`gen/catalog/enforcement.go` records the argument for each; none is acted on.

Also worth your eye: **`IA.L1-b.1.v`** (identification) carries nine *logging* rules,
because AWS's reading is that identification is evidenced by attributable logs. Defensible,
not the only reading. Recorded as Q3 in `docs/open-questions.md`.

## Decisions made

**Control IDs use the CFR final-rule form** (`AC.L1-b.1.i` … `SI.L1-b.1.xv`) per
32 CFR 170.14(c)(1) — your call when I raised it. The legacy AWS-style identifier survives
in `crosswalk.aws_config_mapping_id`, which is also what makes the join auditable.

**DESIGN §8's example ID is now stale** — it shows `AC.L1-3.1.1`, CMMC 1.0-era numbering.
Flagging rather than editing, per CLAUDE.md; recorded as Q2.

**The content hash covers `controls[]` only.** Recompiling the same controls at a different
timestamp must not change the hash, or every account tag, SCP tag, and manifest record that
references it becomes meaningless. Pinned as a regression constant in
`canonical_test.go`, independently corroborated against `shasum -a 256`.

**`compiled_at` is derived from the sources, not the clock** — the newest `retrieved_at`
across the curated inputs. Without this, `make catalogs` would rewrite the file on every
run and the golden test would be noise instead of signal.

**Two provenance layers per source.** Each `artifact.sources` entry carries the hash of the
curated file the compiler actually read *and*, in its `note`, the hash and URI of the
upstream publication it was derived from. A reviewer can verify the chain without trusting
the compiler.

**Undeclared rule parameters are a hard error**, not a defaulted order. A wrong default
either loosens a control or manufactures a spurious union conflict. All 8 parameterized
rules in the pack have declared orders; a 9th appearing upstream stops the compile.

**`schema/` gets its own validator in tests.** `internal/artifact.Validate()` stays the
hand-written runtime path (no dependency in the vend path); `santhosh-tekuri/jsonschema/v6`
validates fixtures against the published schema in tests, so schema↔Go drift fails loudly
in both directions. I verified the detector is not vacuous by deleting a schema constraint
and observing the precise expected failure.

**`make golden` uses `AUTOMAT_UPDATE_GOLDEN=1`, not a `-update` flag.** A flag defined in
one package's tests makes `go test ./...` fail in every other package.

## Corrections to things I told you earlier

- I said `santhosh-tekuri/jsonschema/v6` had no transitive dependencies. It pulls
  `golang.org/x/text`. (`github.com/dlclark/regexp2` turned out not to be required after
  `go mod tidy`.) Adding cobra brought `spf13/pflag` and `inconshreveable/mousetrap`. Full
  dependency set is now 5 modules, 2 direct.

## Deviations from the brief

- **Commit granularity.** The brief asked for conventional commits from the first commit.
  There is currently **one** commit (`3c162c0`), not one per deliverable: my first commit
  swept the pre-existing markdown in under a scaffolding-only message, and the cleanest fix
  (`git update-ref -d HEAD`) was correctly refused as destructive, so I amended into one
  accurate multi-section message instead. Everything from this session is **uncommitted** —
  you can slice it into per-deliverable commits during review, which is probably better than
  me guessing your preferred boundaries.

## Open questions

Written up in `docs/open-questions.md`. The two that need *you*, not a live AWS org:

- **Q1 — set-valued rule parameters.** `blockedActionsPatterns`, `authorizedTcpPorts`,
  `blockedPort1`–`5` are sets encoded as comma-separated strings. Semantically blocked items
  should union and authorized items should intersect. All are currently `exact`, which is
  safe but will produce spurious conflicts as soon as `800-171r2` binds the same rules.
  Modeling them properly is a **schema change** — your decision, a version bump, and a
  CHANGELOG note. Deferred to Phase 4 where the conflict actually bites.
- **Q4 — no OSCAL catalog exists for 800-171 Rev 2.** `usnistgov/oscal-content` ships Rev 3
  only, and Rev 2 is what CMMC L2 is assessed against today. Blocks the `800-171r2` catalog:
  derive from the NIST PDF/CSV, derive from Rev 3 plus the published mapping, or hand-curate
  as I did for FAR 52.204-21.

Q5–Q7 (delegation visibility from the member side, SCP quota headroom under union, and
`MoveAccount`-after-`CreateAccount` retry policy) need a live org and are Phase 1+.

## Where I'd go next, once you've reviewed the mapping

Finish Phase 0: resolve Q4, then `800-171r2` / `800-171r3` / `baseline-protection` through
the same compiler, then `automat compile` so the ROADMAP Phase 0 accept criterion can run
as written.
