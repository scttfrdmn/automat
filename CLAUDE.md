# CLAUDE.md — automat

Read `DESIGN.md` first; it is the source of truth. `ROADMAP.md` sequences the work. When design and code disagree, stop and flag it — do not silently reinterpret the design.

## Project facts

- Module: `github.com/scttfrdmn/automat` (may later move to an org — keep the module path referenced only via the module root; no vanity imports yet).
- Go ≥ 1.24, single static binary, `CGO_ENABLED=0`. No daemons, no databases.
- License: Apache-2.0 (add LICENSE + SPDX headers).
- CLI: `spf13/cobra` + `viper`-free config (plain TOML via `BurntSushi/toml`); keep the dependency tree small and boring.
- AWS: `aws-sdk-go-v2` only. All AWS calls go through narrow, hand-written interfaces (one per service concern: `OrgAPI`, `STSAPI`, `ConfigAPI`, `AccountAPI`, `IAMAPI`) so everything is testable with fakes. No mocking frameworks; hand-rolled fakes in `internal/awsfake`.

## Hard rules

1. **Never call real AWS in tests or CI.** Unit + fake-based tests only. Provide a separate `make smoke` target (documented, manual, requires explicit `AUTOMAT_SMOKE_PROFILE`) for live testing; it must be read-only except in an explicitly named sandbox org.
2. **The load-bearing AWS facts in DESIGN.md §3 are constraints, not suggestions.** If SDK behavior seems to contradict one, surface it in the PR description rather than coding around it.
3. **No product/vendor references** other than AWS anywhere in code, docs, schema, tags, or CLI output (DESIGN.md §15).
4. **Idempotency everywhere.** Every mutating command must be safely re-runnable; `vend` is resumable by request id. Prefer "ensure" semantics (create-or-verify) over "create".
5. **Destructive operations** (anything that closes accounts, detaches policies, deletes) require `--yes` and print a plan first. Phase 5 concern mostly, but the plumbing (plan/apply split) should exist from Phase 2.
6. **Schema stability:** `schema/` files are versioned contracts. Any change to a published schema bumps the version and adds a migration note in `schema/CHANGELOG.md`.
7. Errors are values with remediation text: every permission failure must say *which* action, *which* resource, and *what grant would fix it* — that reporting is a headline feature, not logging.

## Quality bar

- `golangci-lint` clean (config in repo: govet, staticcheck, errcheck, gosec, revive).
- Table-driven tests; property tests (rapid or gopter) for union semantics — idempotence, commutativity, associativity, monotonicity (DESIGN.md §9).
- Golden-file tests for: onboarding bundle output, compiled artifacts, evidence manifests, SCP packer output.
- Every package has a doc comment explaining its role in the vend pipeline.
- `make build test lint` green before any commit. Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

## Layout

```
cmd/automat/            # cobra main
internal/
  preflight/            # three-state machine (DESIGN §4)
  org/                  # Organizations ops via OrgAPI (create/move/OU/SCP ensure)
  broker/               # vendor-role assumption, ExternalId handling
  baseline/             # in-child work: config recorder, conformance pack, regions, roles
  artifact/             # schema types, load/validate/canonicalize/hash
  compilesets/          # union semantics + SCP packer
  evidence/             # hash-chained manifests, signer interface (local key now, KMS later)
  bundle/               # onboarding bundle generation (CFN/TF/README templates)
  awsfake/              # hand-rolled fakes for all service interfaces
schema/                 # JSON Schemas + CHANGELOG (versioned contracts)
catalogs/               # vendored compiled artifacts (cmmc-l1, 800-171r2, 800-171r3)
gen/                    # maintainer tooling: OSCAL + conformance-pack → catalog compiler
docs/                   # conventions.md, security-review.md (the 60-line pitch), beyond.md
```

## Working style

- Small PR-sized commits per ROADMAP task; each phase ends with a tagged milestone and an updated `docs/` page.
- When an AWS behavior is uncertain (delegation-policy visibility, SCP quota edge cases), write the code behind an interface, note the uncertainty in `docs/open-questions.md`, and keep going — don't block on what only a live org can answer.
- Ask the human before: adding any dependency beyond the ones named here, changing the schema, or altering CLI surface/flags.
