# CLAUDE.md — automat

Read `DESIGN.md` first; it is the source of truth. `ROADMAP.md` sequences the work. When design and code disagree, stop and flag it — do not silently reinterpret the design.

## Project facts

- Module: `github.com/scttfrdmn/automat` (may later move to an org — keep the module path referenced only via the module root; no vanity imports yet).
- Go ≥ 1.24, single static binary, `CGO_ENABLED=0`. No daemons, no databases.
- License: Apache-2.0 (add LICENSE + SPDX headers).
- CLI: `spf13/cobra` + `viper`-free config (plain TOML via `BurntSushi/toml`); keep the dependency tree small and boring.
- AWS: `aws-sdk-go-v2` only. All AWS calls go through narrow, hand-written interfaces (one per service concern: `OrgAPI`, `STSAPI`, `ConfigAPI`, `AccountAPI`, `IAMAPI`) so everything is testable with fakes. No mocking frameworks; hand-rolled fakes in `internal/awsfake`.
- **The `aws-sdk-go-v2` module family is pre-approved** — the core module, `config`, `credentials`, and any per-service module (`service/organizations`, `service/iam`, …). Ratified at the AUDIT-1 review so the "ask before adding a dependency" rule does not recur once per service. `config` in particular *is* DESIGN §13's credential chain; hand-rolling credential resolution to avoid the import would be strictly worse security. Every new service module still needs its own narrow interface and fake per the rule above, and still gets a dependency-review line in the phase audit.

## Hard rules

1. **Never call real AWS in tests or CI.** Unit + fake-based tests only. Provide a separate `make smoke` target (documented, manual, requires explicit `AUTOMAT_SMOKE_PROFILE`) for live testing; it must be read-only except in an explicitly named sandbox org.
2. **The load-bearing AWS facts in DESIGN.md §3 are constraints, not suggestions.** If SDK behavior seems to contradict one, surface it in the PR description rather than coding around it.
3. **No product/vendor references** other than AWS anywhere in code, docs, schema, tags, or CLI output (DESIGN.md §15).
4. **Idempotency everywhere.** Every mutating command must be safely re-runnable; `vend` is resumable by request id. Prefer "ensure" semantics (create-or-verify) over "create".
5. **Destructive operations** (anything that closes accounts, detaches policies, deletes) require `--yes` and print a plan first. Phase 5 concern mostly, but the plumbing (plan/apply split) should exist from Phase 2.
6. **Schema stability:** `schema/` files are versioned contracts. Any change to a published schema bumps the version and adds a migration note in `schema/CHANGELOG.md`. Audit-driven changes that **strictly tighten** validation may be made without pre-approval, but must be listed in the audit file for ratification. Anything that loosens or restructures still requires asking first.
7. Errors are values with remediation text: every permission failure must say *which* action, *which* resource, and *what grant would fix it* — that reporting is a headline feature, not logging.

## Quality bar

- `golangci-lint` clean (config in repo: govet, staticcheck, errcheck, gosec, revive).
- Table-driven tests; property tests (rapid or gopter) for union semantics — idempotence, commutativity, associativity, monotonicity (DESIGN.md §9).
- Golden-file tests for: onboarding bundle output, compiled artifacts, evidence manifests, SCP packer output.
- Every package has a doc comment explaining its role in the vend pipeline.
- `make build test lint` green before any commit. Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

## Security audit ritual

At the end of every phase, and before any tagged milestone, perform an adversarial self-audit in the persona of a hostile, unimpressible security auditor reviewing this codebase for the first time. The auditor assumes: all user input is attacker-controlled (account names, emails, OU ids, catalog files, config), the operator will be phished, the network is unreliable, and every claim in the docs is false until traced to code. Scope each audit to at least:

- Every IAM policy string and template: least privilege, missing conditions, confused-deputy paths, ExternalId handling.
- **Tag-based authorization, both directions.** Every `aws:ResourceTag` / `aws:RequestTag` condition must be paired with an audit of which principals can *write* that tag at the same scope. **Wherever tag-reading gates access, tag-writing is a privilege boundary.** A condition that reads a tag any grant in the same bundle can apply is not a condition. Audit the pair even when the two halves live in different files or different templates — AUDIT-1's C1 was exactly this defect, and each half was unremarkable alone. State the invariant as a test, not as a paragraph: enumerate the keys the policies read and assert no grant can write one.
- Injection surfaces: any user-supplied value that reaches a template (CFN/TF/JSON/markdown), a shell, a path, or an ARN.
- TOCTOU between preflight checks and mutating actions.
- Error and log paths: credential/ARN/email leakage.
- The evidence chain: canonicalization ambiguity, hash inputs, signature coverage, whether a record can be silently replaced.
- The SCP packer (once it exists): can any merge WIDEN permissions.
- **Every obligation profile's citations and effective dates, re-verified against the primary source.** Confirm every claim automat renders into a human-facing document traces to a hashed source. **A stale legal citation is a finding, ranked no lower than medium** — it is not a documentation nit. A profile is a reading of policy that an institution acts on, and policy moves: notices are superseded, phase-in dates arrive, a class deviation pinning a revision expires. The failure mode is silent and confident, since a superseded citation renders exactly as well as a current one. Also confirm the policy caveat still appears where `docs/policy-caveat.md` requires it, and that the understatement asymmetry still holds across the whole profile set rather than per profile.
- gosec + dependency review, with every finding triaged in writing.
- **The CLI surface against DESIGN §13.** List the flags each command actually has and reconcile them with §13. A flag §13 does not enumerate is an addition and fine; a flag that *contradicts* §13 — or a §13 command whose implemented behavior differs — is its own line item in the audit, not a footnote. Ratified at the AUDIT-1 review on this condition.

Output: `audits/AUDIT-<phase>.md` — findings ranked critical/high/medium/low/nit, each resolved as FIXED (with commit) or ACCEPTED (with a reason a crabby auditor would begrudgingly sign). No finding may be dismissed without a written reason. The audit file is committed; the human reviews ACCEPTED items.

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
