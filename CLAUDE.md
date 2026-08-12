# CLAUDE.md — automat

Read `DESIGN.md` first; it is the source of truth. `ROADMAP.md` sequences the work. When design and code disagree, stop and flag it — do not silently reinterpret the design.

## Project facts

- Module: `github.com/scttfrdmn/automat` (may later move to an org — keep the module path referenced only via the module root; no vanity imports yet).
- Go ≥ 1.24, single static binary, `CGO_ENABLED=0`. No daemons, no databases.
- License: Apache-2.0 (add LICENSE + SPDX headers).
- CLI: `spf13/cobra` + `viper`-free config (plain TOML via `BurntSushi/toml`); keep the dependency tree small and boring.
- AWS: `aws-sdk-go-v2` only. All AWS calls go through narrow, hand-written interfaces (one per service concern: `OrgAPI`, `STSAPI`, `ConfigAPI`, `AccountAPI`, `IAMAPI`) so everything is testable with fakes. No mocking frameworks; hand-rolled fakes in `internal/awsfake`.
- **The `aws-sdk-go-v2` module family is pre-approved** — core, `config`, `credentials`, and any per-service module. Ratified at AUDIT-1 so the "ask before adding a dependency" rule does not recur once per service. Every new service module still needs its own narrow interface and fake, and a dependency-review line in the phase audit.

## Hard rules

1. **Never call real AWS in tests or CI.** Unit + fake-based tests only. `make smoke` (documented, manual, requires explicit `AUTOMAT_SMOKE_PROFILE`) is for live testing; read-only except in an explicitly named sandbox org. An emulator is not real AWS and is not covered by this rule — see `docs/testing-strategy.md`.
2. **The load-bearing AWS facts in DESIGN.md §3 are constraints, not suggestions.** If SDK behavior seems to contradict one, surface it in the PR description rather than coding around it.
3. **No product/vendor references** other than AWS anywhere in code, docs, schema, tags, or CLI output (DESIGN.md §15).
4. **Idempotency everywhere.** Every mutating command must be safely re-runnable; `vend` is resumable by request id. Prefer "ensure" semantics (create-or-verify) over "create".
5. **Destructive operations** (anything that closes accounts, detaches policies, deletes) require `--yes` and print a plan first. Phase 5 concern mostly, but the plumbing (plan/apply split) should exist from Phase 2.
6. **Schema stability:** `schema/` files are versioned contracts. Any change bumps the version and adds a migration note in `schema/CHANGELOG.md`. Audit-driven changes that **strictly tighten** validation may be made without pre-approval, but must be listed in the audit file for ratification. Anything that loosens or restructures still requires asking first.
7. **Errors are values with remediation text:** every permission failure must say *which* action, *which* resource, and *what grant would fix it* — that reporting is a headline feature, not logging.
8. **Round-trip fields carry a character-class pattern at both layers.** Any value automat *writes* that is designed to be read back by a person and typed onto a command line — request ids, account aliases, OU names, profile ids, resume tokens — must be patterned in the JSON Schema **and** in the Go validator. This is **not injection prevention**: argument construction remains the CLI's problem and stays there. It is refusing to *record* a value whose whole purpose is to travel through human hands into a shell. Two failure modes, and the duller one is not the lesser: a value carrying a quote or metacharacter is a record that suggests a different command than the one it appears to, and a value carrying whitespace cannot be selected by double-click, so the operator retypes it and gets it wrong.
9. **Any AWS resource id, quota code, service-quota code, or ARN pattern hand-written into this codebase must be confirmed against a live AWS CLI `list-*`/`describe-*`/`get-*` call, or the service's own current documentation, before it is trusted or written down as fact.** Never guess, carry one forward from memory, or invent one that merely looks plausible. This rule exists because `internal/preflight`'s account-count quota check used `L-29A0C5DF` — a code that has never existed for the `organizations` service — for the entire life of the project. Every `GetServiceQuota` call against it failed with `NoSuchResourceException`, which was misread as an AWS-side "new-payer-account throttle" and written into `docs/reclaim-design.md` and `docs/open-questions.md` Q26 as if it were a confirmed AWS behavior, rather than recognized as a wrong constant in automat's own code. The real code (`L-E619E033`) was found only by listing every quota AWS actually publishes for the service and was readable and CLI-adjustable the whole time. When a live AWS call returns an error that doesn't match documented, expected behavior, treat "the code I'm using might be wrong" as at least as likely as "AWS is behaving unusually" — verify against the live source before writing either conclusion down.

## Quality bar

- `golangci-lint` clean (config in repo: govet, staticcheck, errcheck, gosec, revive).
- Table-driven tests; property tests (rapid or gopter) for union semantics — idempotence, commutativity, associativity, monotonicity (DESIGN.md §9).
- Golden-file tests for: onboarding bundle output, compiled artifacts, evidence manifests, SCP packer output.
- Every package has a doc comment explaining its role in the vend pipeline.
- `make build test lint` green before any commit. Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Testing strategy — fakes vs. emulator, and which tests belong where: `docs/testing-strategy.md`.

## Security audit ritual

At the end of every phase, and before any tagged milestone, perform an adversarial
self-audit as a hostile, unimpressible security auditor. Output `audits/AUDIT-<phase>.md`
with findings ranked critical/high/medium/low/nit, each FIXED (with commit) or ACCEPTED
(with a written reason). No finding may be dismissed without one.

**Full scope and the reasoning behind each item: `docs/audit-ritual.md`.** Read it before
starting an audit — the tag-authorization, round-trip-field, and citation-re-verification
items each exist because something got missed once.

## Layout

```
cmd/automat/            # cobra main
internal/
  preflight/            # three-state machine (DESIGN §4)
  org/                  # Organizations ops via OrgAPI (create/move/OU/SCP ensure)
  broker/               # vendor-role assumption, ExternalId handling (Phase 3, task 1 of 4;
                        # not yet wired into vend's MEMBER-state flow — see ROADMAP.md)
  baseline/             # NOT YET BUILT (Phase 3): in-child work — config recorder, conformance pack, regions, roles
  artifact/             # control-artifact schema types, load/validate/canonicalize/hash
  envprofile/           # environment-profile document type (vend's per-vend input, DESIGN §7a)
  classprofile/         # classification-profile document type (institutional data levels)
  compilesets/          # union semantics + SCP packer
  evidence/             # hash-chained manifests, signer interface (local key now, KMS later)
  bundle/               # onboarding bundle generation (CFN/TF/README templates)
  catalog/              # resolves an environment profile's ids to the documents they name
  config/               # on-disk configuration
  login/                # AWS SSO device authorization grant
  safeio/               # confined file reads/writes (no symlink/hardlink/FIFO substitution)
  version/              # build identity
  awsfake/              # hand-rolled fakes for all service interfaces
schema/                 # JSON Schemas + CHANGELOG (versioned contracts)
catalogs/               # vendored compiled artifacts: cmmc-l1, baseline-protection, 800-171r2
                        # (110 requirements, all procedural — no AWS mapping joined yet, see
                        # docs/open-questions.md Q4), plus obligations/ (dfars-7012,
                        # nih-cadr-dua), classification/ (uc-protection-levels,
                        # stanford-risk-classifications), and objectives/ (800-171a-objectives —
                        # a DIFFERENT, DRAFT schema, schema/objectives-catalog-v1.schema.json, not
                        # yet ratified per rule 6; see schema/CHANGELOG.md's objectives-catalog/v1
                        # entry). 800-171r3 remains Phase 0 scope, not yet compiled.
gen/                    # maintainer tooling: OSCAL + conformance-pack → catalog compiler
docs/                   # conventions.md, reclaim-design.md now written (Phase 5); see
                        # docs/cli-surface.md, docs/audit-ritual.md, docs/open-questions.md,
                        # and the rest of docs/ for what exists today.
test/integration/       # SEPARATE Go module (its own go.mod, go 1.26) — emulator-backed
                        # tests, run only via `make integration`, never `make test`. See
                        # docs/testing-strategy.md.
```

## Working style

- Small PR-sized commits per ROADMAP task; each phase ends with a tagged milestone and an updated `docs/` page.
- When an AWS behavior is uncertain (delegation-policy visibility, SCP quota edge cases), write the code behind an interface, note the uncertainty in `docs/open-questions.md`, and keep going — don't block on what only a live org can answer.
- Ask the human before: adding any dependency beyond the ones named here, changing the schema, or altering CLI surface/flags.
