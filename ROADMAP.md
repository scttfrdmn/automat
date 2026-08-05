# ROADMAP — automat

Phases are ordered so the compatibility contract (schema) exists before anything consumes it, and so every phase ends with something demonstrable. Each phase = tagged milestone.

## Phase 0 — Contract first: schema + catalogs
- JSON Schemas: control artifact, profile, evidence manifest (`schema/`), with Go types, canonicalization, content hashing, round-trip tests.
- `gen/`: compile CMMC L1 catalog from NIST/FAR OSCAL sources joined with the AWS Config CMMC L1 conformance-pack mapping; record source hashes. Vendor output to `catalogs/cmmc-l1.json`.
- Same pipeline for `800-171r2` and `800-171r3` (enforcement mappings may be partial — mark unmapped controls `procedural` with a TODO provenance note rather than dropping them).
- Baseline-protection control set as data (`catalogs/baseline-protection.json`).
- **Accept:** `automat compile --sets cmmc-l1 --out a.json` validates, hashes deterministically; golden files for all three catalogs.

## Phase 1 — Preflight + onboarding bundle
- `login` (SSO device flow via ssooidc + credential chain), `preflight` (three-state machine, quota + permission report with SCP-caveat wording), `setup --request` (onboarding bundle: delegation policy, vendor role CFN + TF, README).
- **Accept:** golden-file tests for bundle output; fake-backed preflight covers all three states and the "member with vendor role" variant.

## Phase 2 — Vend (management + standalone paths)
- `init` (CreateOrganization ALL + research OU), `vend` end-to-end in MANAGEMENT state: create → poll → move → SCP ensure (control + region + service + baseline-protection) → assume into child → recorder/delivery channel/conformance pack → attestation stubs → evidence manifest.
- SCP packer: quota-aware (5-per-target, size limits), deterministic output, golden-tested.
- Resumable requests (`--resume`), parked-account handling.
- **Accept:** full vend pipeline runs against fakes with every step idempotent (run twice = no diff); manifest chain validates.

## Phase 3 — Brokered vend (the university path)
- `broker/`: vendor-role assumption with ExternalId; vend flow in MEMBER state mixing brokered (create/move/OU) and delegated (policy) credentials.
- `setup` (MANAGEMENT side): apply delegation policy + create vendor role for a named member account.
- Nested OU creation within depth limits.
- **Accept:** fake-backed MEMBER vend; failure modes (unassumable role, missing delegation) produce actionable remediation text naming the exact missing grant.

## Phase 4 — Verify + union hardening
- `verify` per DESIGN §12 (policy/detective/procedural layers, findings vs drift distinction, enforcement-class breakdown, cron-friendly exit codes).
- Union semantics complete: crosswalk dedupe, parameter partial orders, conflict reports + override files; property tests (idempotent/commutative/associative/monotone).
- `list` (tag-driven inventory incl. parked accounts).
- **Accept:** property suite green; `verify` golden reports for compliant / drifted / findings-only scenarios.

## Phase 5 — Polish + lifecycle
- `reclaim` design + implementation (closure rate limits, plan/apply, `--yes`).
- KMS signer for evidence manifests.
- Docs site content: conventions.md, security-review.md ("the 60-line review" for central IT), beyond.md.
- Manual smoke-test runbook against a sandbox org; capture answers to `docs/open-questions.md` (delegation visibility, quota edges).
- **Accept:** a stranger with a standalone AWS account can go README → init → vend → verify without asking a human anything.

## Deferred / explicitly out of scope for v1
- Approval-per-vend request queue.
- Continuous monitoring, dashboards, agents.
- HIPAA / 800-53 catalogs (pipeline should make them data-only additions; pick the blessed HIPAA crosswalk before generating).
