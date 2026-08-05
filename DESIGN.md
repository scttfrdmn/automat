# automat — Design

**Repo:** `github.com/scttfrdmn/automat` · **Language:** Go · **License:** Apache-2.0
**One-liner:** A standalone CLI that lets an AWS account vend compliant sub-accounts — CMMC 2 Level 1 and NIST 800-171 baselines attached at birth — without Control Tower.

---

## 1. Problem and audience

University research organizations need AWS accounts with compliance controls (CMMC 2 L1 today; 800-171, and eventually L2/L3, HIPAA, 800-53). Central IT holds the org management ("master payer") account and typically will not run Account Factory for researchers, and AWS Control Tower is too heavy a deployment for them to accept. Research computing groups need a *delegated, OU-scoped* vending capability: central IT approves a small, reviewable grant once; the research org vends thereafter without further involvement.

automat is a **distributed control tower**: the create/move/baseline ceremony of Account Factory, with the baseline reduced to an explicit, auditable control file, and the trust structure matching how universities actually govern (federated; the center sets boundaries, the units operate).

Secondary audience: a fully standalone account (no org at all) — e.g., a lab with its own AWS account — which automat can bootstrap into the management account of its own new organization.

## 2. Non-goals

- No Control Tower dependency, ever. No landing-zone opinions beyond the control file.
- No long-running service, no dashboard, no database. Single static binary; state lives in AWS (tags, SCPs, manifests) and in files.
- No continuous monitoring / evidence collection agents. `verify` is point-in-time. (See §12 — the tool states its own limits.)
- Not a compliance program. Procedural controls produce attestation stubs, not magic.

## 3. Hard AWS facts the design is built on

These are load-bearing; do not "improve" them away without re-verifying against AWS docs:

1. `organizations:CreateAccount` runs **only** in the management account. It is **not** delegable via resource-based delegation policies.
2. `organizations:CreateOrganizationalUnit` is likewise **not** a supported action in delegation policies (API rejects it: "unsupported action").
3. Organizations **policy management** (create/update/delete/attach/detach SCPs etc.) **is** delegable to a member account via a resource-based delegation policy, and can be **scoped to a specific OU** and its accounts via Resource ARNs.
4. New accounts always materialize under the **root**, then must be `MoveAccount`-ed to a target OU. `CreateAccount` cannot be OU-constrained; `MoveAccount` can be resource-scoped (destination OU ARN).
5. `CreateAccount` accepts **tags**; IAM `aws:RequestTag` conditions can force mandatory tags at creation time.
6. Every vended account gets `OrganizationAccountAccessRole` (name configurable at create) that the management-side caller can assume — this is the door for in-account baselining.
7. SCPs bind **all principals in member accounts, including root users**. SCPs do not bind the management account. Delegated-admin accounts *are* subject to SCPs.
8. SCPs require the org to be in `ALL` feature set (not consolidated-billing-only). `CreateOrganization` must pass `FeatureSet=ALL`.
9. `iam:SimulatePrincipalPolicy` does **not** evaluate SCPs — permission preflight from a member account is best-effort and must be labeled as such.
10. OU nesting depth: max five levels of OU under the root.
11. Practical quotas: default accounts-per-org quota is low (raiseable via Service Quotas); account closure is rate-limited (~10% of member accounts per rolling 30 days); each account needs a globally unique email.
12. Standalone accounts can call `CreateOrganization` and become the management account of a fresh org. Member accounts cannot leave an org without management-account cooperation.

## 4. The three org states (preflight state machine)

`automat preflight` classifies the caller's account and drives everything else:

| State | Detection | Capability | automat behavior |
|---|---|---|---|
| **STANDALONE** | `DescribeOrganization` → not in an org | Can become its own management account | Offer `automat init` → `CreateOrganization(FeatureSet=ALL)`, create root-level research OU, then vend freely |
| **MANAGEMENT** | `DescribeOrganization` + caller account == management account | Full | Vend directly; also can emit delegation bundles for other member accounts |
| **MEMBER** | In an org, not management | Cannot create accounts/OUs natively; may hold delegated policy admin and/or an assumable vendor role | If vendor role configured & assumable → vend via broker. Else → generate the **onboarding bundle** (§6) addressed to central IT |

Preflight also reports: org feature set, delegated-admin status (via `DescribeResourcePolicy` effects where visible / documented config), presence and assumability of the configured vendor role, relevant service quotas (accounts per org), and permission simulation results — with the explicit caveat that SCP effects are not simulatable from a member account.

## 5. The delegation model (MEMBER state, the university case)

Two halves with different mechanisms:

**Policy half — native delegation.** Central IT applies a resource-based delegation policy statement allowing the research account to create/update/delete/attach/detach SCPs, scoped to the research OU subtree and to policies automat creates. Plus the standard read/navigate actions (`Describe*`, `List*`).

**Vending half — brokered role.** Central IT creates one IAM role in the management account (`automat-vendor`, name configurable):

- **Trust:** only the research account (ideally a specific role ARN) may assume, with `sts:ExternalId` required.
- **Permissions:** `organizations:CreateAccount` (with `aws:RequestTag` condition requiring `automat:vended-by` and `automat:ou` tags), `DescribeCreateAccountStatus`, `MoveAccount` restricted to the research OU (and its descendants) as destination, `CreateOrganizationalUnit` restricted to the research OU subtree as parent, `TagResource`, and read actions.
- Nothing else. No policy actions here — those flow through delegation, which keeps the role reviewable in ~60 lines.

The CLI transparently: assumes `automat-vendor` for create/move/OU operations; uses the caller's own (delegated) credentials for policy operations; assumes `OrganizationAccountAccessRole` in the child for baselining.

**Known cosmetic race:** a created account sits in root until `MoveAccount` succeeds. automat must treat create-without-successful-move as an error state — retry the move, and if still failing, record the account as **parked** in the local/remote manifest and surface it loudly. Document for central IT that transient root-landing is expected.

## 6. The onboarding bundle (failure → artifact)

When preflight lands in MEMBER without grants, `automat setup --request` emits a directory:

```
automat-onboarding/
  README.md                   # cover note for central IT: what, why, blast radius
  delegation-policy.json      # the resource-based delegation policy statement(s)
  vendor-role.cfn.yaml        # CloudFormation for the automat-vendor role
  vendor-role.tf              # equivalent Terraform
  ou.md                       # instructions: create OU, note its ID, fill placeholders
```

The README must explain the blast-radius argument in CISO-legible terms: the role can only place accounts into the named OU; the delegation only touches policies on that OU; SCPs central IT attaches **above** the OU still bind everything below — the delegate can add restrictions but never loosen the institutional floor.

## 7. Vend flow

`automat vend --profile <profile.json> --name <acct> --email <addr>` (email may come from a configured pattern, e.g. `research-admin+{name}@dept.edu`):

1. Resolve profile → compiled control artifact (§8) + region set + service set.
2. Broker/native `CreateAccount` with mandatory tags; poll `DescribeCreateAccountStatus`.
3. `MoveAccount` into the target OU (creating intermediate OUs if the profile says so, within depth limits).
4. Ensure OU-level SCPs match the artifact (idempotent create/attach via delegated permissions): control SCPs + region SCP + service SCP + **baseline-protection SCP** (§10).
5. Assume `OrganizationAccountAccessRole` into the child:
   - Enable/disable opt-in regions per profile (Account Management API).
   - Deploy detective baseline: Config recorder, delivery channel, conformance pack from the artifact's config-rule set.
   - Create attestation stubs for procedural controls (local `compliance/` output + optional S3 in-account).
   - Create the automat automation role in-account (least privilege for future `verify`), then optionally disable further use of `OrganizationAccountAccessRole` per profile.
6. Write the **evidence manifest** (§11) and print a birth certificate: account ID, OU, control artifact hash, enforcement summary.

Ordering matters: controls attach before the account is handed to anyone — "born compliant" is a claim the manifest can back.

Idempotency: every step must be safely re-runnable (`vend --resume <request-id>`).

## 8. Control artifact (the schema is the product)

The artifact is a compiled, frozen JSON document — automat interprets it; it never interprets raw OSCAL at vend time. The schema is defined **in this repo** (`schema/`), versioned (`automat.dev/schema/control-artifact/v1` style `$id`; plain semver field is fine pre-domain), and is the compatibility contract for any future tooling. Design it as a strict subset of OSCAL component-definition concepts so upstream suites can adopt it; **do not** reference any external product in the schema, field names, or docs.

Sketch (Claude Code: formalize as JSON Schema + Go types with round-trip tests):

```jsonc
{
  "schema_version": "1.0.0",
  "artifact": {
    "id": "cmmc-l1",                 // or a union artifact id
    "title": "CMMC 2.0 Level 1",
    "sources": [                      // provenance of the compile
      { "catalog": "FAR 52.204-21", "version": "…", "oscal_sha256": "…" },
      { "mapping": "aws-config-conformance-pack-cmmc-l1", "sha256": "…" }
    ],
    "compiled_at": "2026-08-04T00:00:00Z",
    "content_sha256": "…"            // hash of canonicalized controls[]
  },
  "controls": [
    {
      "id": "AC.L1-3.1.1",
      "title": "…",
      "crosswalk": { "far": "52.204-21(b)(1)(i)", "800-171r2": "3.1.1", "800-171r3": "03.01.01" },
      "enforcement": "scp | config-rule | procedural | baseline-protection",
      "scp": { /* statement fragment(s), deny-style preferred */ },
      "config_rules": [ { "identifier": "…", "parameters": { "k": {"value": "v", "order": "min|max|exact"} } } ],
      "attestation": { "template": "…md", "frequency": "annual" }
    }
  ]
}
```

Notes:
- `enforcement` may be a list (a control can have both an SCP fragment and config rules).
- `order` on parameters encodes the per-parameter partial order used by union (§9).
- `crosswalk` is what lets union dedupe the same practice across frameworks.

**Catalog generation** (`gen/` tooling, run by maintainers, output vendored into `catalogs/`):
- `cmmc-l1` — the 15 FAR 52.204-21 requirements (CMMC 2.0 final rule, 32 CFR 170).
- `800-171r2` — 110 requirements. **This is what CMMC L2 assesses against today** (DoD class deviation; Rev 2 remains the baseline until rulemaking completes).
- `800-171r3` — 97 requirements + ODPs. Current NIST publication; relevant now for some civilian-agency contracts, and the CMMC transition target (rulemaking in flight as of mid-2026).
- Ship r2 **and** r3, clearly tagged; never present r3 as "the CMMC one."
- Inputs: NIST OSCAL catalogs (authoritative control text) joined with AWS-side mappings (AWS Config conformance packs for CMMC L1 / 800-171; optionally Audit Manager framework API). Record source hashes in `artifact.sources`.

## 9. Union semantics (`automat compile`)

`automat compile --sets cmmc-l1,800-171r2,campus-base --out artifact.json`

Governing law: **union of controls = intersection of permitted behavior.** The operation is a meet on a semilattice of control sets:

- **Deny SCP fragments:** concatenate (always safe; dedupe identical statements; respect SCP size limits by merging Action lists where semantics allow).
- **Allowlists** (regions, services): **intersect**. Union of "us-east-1,us-west-2" and "US regions" = the two regions.
- **Config rules:** set-union deduped by rule identifier; overlapping parameters resolve by the declared per-parameter `order` (min/max). If two sets bind the same parameter with `exact` and different values, or no order is declared: **hard error** with a conflict report demanding explicit resolution (an override file). Never guess.
- **Procedural controls:** dedupe via `crosswalk` so one practice is attested once, not once per framework ID; the stub lists all satisfied IDs.
- Output is itself a first-class artifact (new id, sources = the input artifacts, fresh content hash) — unions compose.

Property tests Claude Code should write: idempotence (A∪A=A), commutativity, associativity, and monotonicity (the union never permits behavior any input forbade).

## 10. Baseline-protection meta-control

A control set that guards the guards, attached at the OU with every vend, extensible per catalog. Deny (with a Condition exempting only the automat automation role ARN):

- `config:DeleteConfigurationRecorder`, `config:StopConfigurationRecorder`, `config:DeleteDeliveryChannel`, conformance-pack delete/modify
- `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail` (scoped to the baseline trail if one is deployed)
- `organizations:LeaveOrganization`
- IAM mutation (`iam:Update*/Delete*/Put*/Attach*/Detach*` on) of `OrganizationAccountAccessRole` and the automat automation role
- Root-user usage deny (`aws:PrincipalArn` = `arn:aws:iam::*:root`) — standard hygiene, and it maps onto AC-family practices

Represent as `enforcement: baseline-protection` entries in the artifact, not hardcoded, so L2-minded users can extend the deny list.

## 11. Evidence manifests

Every mutating operation appends a record; `vend` writes a per-account manifest:

- Content: timestamp, operator principal, operation, account/OU IDs, control artifact id + `content_sha256`, SCP ARNs attached, conformance pack ARN, region/service sets, tool version.
- Canonical JSON, hash-chained (each record includes previous record's hash), signed (start with a local key; design the signer as an interface so KMS signing is a drop-in).
- Stored: in-account S3 (created at vend) and/or the vending account; local copy always.
- Purpose: the "born compliant" chain of custody. The format lives in `schema/` beside the control artifact and is deliberately simple, append-only, and ingestible by future systems. (Internal note, not for docs: shaped so an evidence kernel can adopt it later. No external product named anywhere.)

## 12. `verify`

`automat verify --account <id> | --ou <id>`: re-walk the artifact against reality.

- Policy layer: attached SCPs still match the artifact (by name + content hash tag).
- Detective layer: recorder on, delivery channel intact, conformance pack present and its rule set matches; then report current compliance findings (resource noncompliance is *signal*, not drift — present it as findings, distinct from baseline drift).
- Procedural layer: attestation stubs present; staleness vs. declared frequency.
- Structural honesty: for each control set, print the enforcement-class breakdown ("X of Y controls enforced/monitored by this tool; N require documented process; M require continuous evidence collection outside this tool's scope"). Computed from the artifact — this is also how the tool states its limits for L2+ catalogs without ever pitching anything.

Exit codes suitable for cron/CI.

## 13. CLI surface (cobra)

```
automat login        # SSO device flow (ssooidc) or standard credential chain; profile-aware
automat preflight    # three-state classification + permission report
automat init         # STANDALONE only: CreateOrganization(ALL) + research OU
automat setup        # MANAGEMENT: apply delegation + create vendor role for a member acct
automat setup --request   # MEMBER: emit onboarding bundle (§6)
automat compile      # union/compile control sets → artifact (§9)
automat vend         # §7
automat verify       # §12
automat list         # vended accounts (by tags), parked accounts, OUs
automat reclaim      # LATER (Phase 5): close/park accounts; respect closure rate limits
```

Config: `~/.config/automat/config.toml` + per-org context (vendor role ARN, ExternalId ref, OU id, email pattern). Never store secrets; lean on the AWS credential chain and OS keychain if anything must persist.

## 14. Conventions (the adoption contract)

These are automat's own, documented publicly in `docs/conventions.md`; external systems may adopt them, automat depends on nothing external:

- Tags on vended accounts: `automat:vended-by`, `automat:ou`, `automat:artifact-id`, `automat:artifact-sha256`, `automat:version`. Enable as cost-allocation tags where possible (chargeback matters as much as compliance to this audience).
- SCP names: `automat-<artifact-id>-<class>` (e.g. `automat-cmmc-l1-baseline-protection`), each SCP tagged with the artifact hash.
- Manifest locations: `s3://automat-evidence-<acct>/manifests/…` and management-side mirror.
- OU marker tag on automat-managed OUs.

## 15. Branding rule (hard requirement)

No references to any commercial suite, company, or upstream product in code, docs, tags, schema, or output. automat is complete for its stated scope. The only forward pointer permitted is capability-phrased (§12's enforcement-class statement) plus, at most, a single neutral `docs/beyond.md` page. Dependency direction: others may build on automat's published conventions; automat imports nothing from them.

## 16. Known risks / open questions for the human

- Approval-per-vend: some central ITs will demand a human in the loop. v1 is standing-delegation only; a request/approve queue is explicitly out of scope (note in README).
- `reclaim` semantics (ephemeral vs durable accounts) deferred to Phase 5; design vend so nothing precludes it.
- SCP count/size quotas per target (5 SCPs directly attached per target; 5120-char SCP size) will constrain how union output is packed into policies — the SCP packer needs to be quota-aware and is a real piece of work, not a serialization detail.
- Delegation-policy visibility from the member side (what preflight can actually detect vs. must be told) needs empirical testing against a real org.
