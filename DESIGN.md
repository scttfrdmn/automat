# automat — Design

**Repo:** `github.com/scttfrdmn/automat` · **Language:** Go · **License:** Apache-2.0
**One-liner:** A standalone CLI that lets an AWS account vend compliant sub-accounts — CMMC 2 Level 1 and NIST 800-171 baselines attached at birth — without Control Tower.

---

> **automat encodes a technical reading of published policy. It is not legal advice and not
> a compliance determination.** The agreement, award terms, or contract clause your
> institution signed governs; your sponsored programs office, contracts office, or counsel
> decides what applies and which revision. Where policy is ambiguous — for example the NIH
> 800-171 revision question — automat records the operator's declaration rather than
> resolving it. Policy citations carry effective dates and change; verify against the
> primary source before relying on them.
>
> This paragraph is canonical (`docs/policy-caveat.md`) and held by a test, not by
> convention: it must appear in this document, in every obligation profile, and in every
> `assess` output. It is a different claim from the `DRAFT — NOT A SUBMISSION` marking, and
> neither substitutes for the other.

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
11. Practical quotas: default accounts-per-org quota is low (raiseable via Service Quotas); account closure is rate-limited (the higher of 250 or 20% of member accounts per rolling 30 days, up to 1,000 — verified directly against the `CloseAccount` API's own documentation, correcting an earlier approximation of "~10%"); each account needs a globally unique email.
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

### 7a. The three profiles, and why the vend input is the *environment* profile

"Profile" named three unrelated documents, and evidence records name one of them by
id and content hash (§11) — which makes that field ambiguous to exactly the auditor
it exists for. The vend input is therefore the **environment profile**
(`environment-profile/v1`):

| document | schema | what it is |
| --- | --- | --- |
| **environment profile** | `environment-profile/v1` | the per-vend input below: control sets, regions, services, placement, baseline. The thing being *built*. |
| obligation profile | `obligation-profile/v1` | `cmmc-l1`, `dfars-7012`, `nih-cadr-dua` — under what instrument an obligation applies. A *policy* artifact. |
| classification profile | (not yet built) | an institution's own data levels. A *policy* artifact. |

"Environment" is the higher-ed idiom already in use for a resource rated to hold data
at a level, and it is the document `vend`, `verify`, and later `assess` all consume.
There is also a fourth, unrenameable sense: the **AWS credential profile**
(`config.toml`'s `profile`, and `login --profile`). `--profile` stays reserved for
that, because it is AWS-standard everywhere else an operator works.

`automat vend --environment-profile <file.json> --name <acct> --email <addr>` (email may come from a configured pattern, e.g. `research-admin+{name}@dept.edu`):

1. Resolve the environment profile → compiled control artifact (§8) + region set + service set.
2. Broker/native `CreateAccount` with mandatory tags; poll `DescribeCreateAccountStatus`.
3. `MoveAccount` into the target OU (creating intermediate OUs if the environment profile says so, within depth limits).
4. Ensure OU-level SCPs match the artifact (idempotent create/attach via delegated permissions): control SCPs + region SCP + service SCP + **baseline-protection SCP** (§10).
5. Assume `OrganizationAccountAccessRole` into the child:
   - Enable/disable opt-in regions per the environment profile (Account Management API).
   - Deploy detective baseline: Config recorder, delivery channel, conformance pack from the artifact's config-rule set.
   - Create attestation stubs for procedural controls (local `compliance/` output + optional S3 in-account).
   - Create the automat automation role in-account (least privilege for future `verify`), then optionally disable further use of `OrganizationAccountAccessRole` per the environment profile.
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
    "content_sha256": "…"            // hash of the canonicalized content payload — see below
  },
  "controls": [
    {
      "id": "AC.L1-b.1.i",         // final-rule id per 32 CFR 170.14(c)(1)
      "title": "…",
      "crosswalk": { "far": "52.204-21(b)(1)(i)", "800-171r2": "3.1.1", "800-171r3": "03.01.01" },
      "enforcement": "scp | config-rule | procedural | baseline-protection",
      "scp": { /* statement fragment(s), deny-style preferred */ },
      "config_rules": [ { "identifier": "…", "provenance": "aws-mapping | curated",
                          "parameters": { "k": {"value": "v",
                                                "order": "min|max|exact|set-union|set-intersect"} } } ],
      "attestation": { "template": "…md", "frequency": "annual" }
    }
  ]
}
```

Notes:
- `content_sha256` covers a **content payload**, not the `controls[]` array alone. This paragraph
  originally said "hash of canonicalized `controls[]`", and that stopped being true when
  `region_deny_exempt_services` moved to the top level (see below): a field beside `controls` would
  have sat outside the hash, so an edit adding a namespace to it — *widening the holes in a region
  Deny* — would have passed `VerifyContentHash` and every signature over the artifact unremarked.
  The payload is `{controls, region_deny_exempt_services}`, canonicalized, and `internal/artifact`
  enumerates the covered and excluded field names so adding a field to the artifact is a decision
  about hash coverage that fails the build until it is written down. Excluded: `schema_version` and
  the whole `artifact` block, whose `sources` entries carry their own per-source hashes.
- `region_deny_exempt_services` is a **top-level** array of the globally addressed service
  namespaces (IAM, STS, Organizations, Route 53, Support, billing, Health, …) that a region or
  service allowlist Deny must not cover. It is catalog **data**, never compiled into the binary,
  for the same reason `exempt_principals` is: getting it wrong bricks an account, and a list only
  the binary knows is a control whose scope cannot be reviewed or corrected without a release.
  Top-level rather than per control because its scope *is* the artifact — two controls carrying
  different lists would have no coherent reading — and because on a control it made an SCP block
  that denies nothing, which a `baseline-protection` control is not allowed to be. Under union it
  **intersects**, which is forced rather than chosen: a Deny over `NotAction: [a:*]` alongside a
  Deny over `NotAction: [b:*]` denies everything except what both spare, so a merge that unioned
  the lists would describe something the rendered policy does not do.
- `enforcement` may be a list (a control can have both an SCP fragment and config rules).
- `order` on parameters encodes the per-parameter partial order used by union (§9). Set-valued parameters (comma-joined port and action lists) take `set-union` when the members are *prohibited* and `set-intersect` when they are *permitted*; both directions are the stricter one, which is what monotonicity requires. A `set_separator` field overrides the default `,`.
- `provenance` on each config-rule binding records who asserts it. `aws-mapping` bindings come from a published AWS mapping recorded in `artifact.sources` and are mechanically generated — never hand-edited. `curated` bindings are automat's own judgment and must carry a `rationale`. The split exists so a reviewer can audit automat's claims separately from AWS's, and so regenerating a catalog cannot silently overwrite a reviewed binding.
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
- **Allowlists** (regions, services): **intersect**. Union of "us-east-1,us-west-2" and "US regions" = the two regions. So does `region_deny_exempt_services` (§8), for the reason recorded there.
- **An allowlist intersection that evaluates to empty is a hard error at plan time**, naming which inputs produced the emptiness. AUDIT-0's H5 observed that the empty set is the absorbing element of the meet; the consequence here is concrete, because an empty region or service allowlist renders as an SCP denying every call in the account — including automat's own baseline work and the operator's attempt to undo it — and it would be discovered *after* create and move had already succeeded. `minItems: 1` in the schema stops the one-document case; the plan-time refusal stops the intersection case. Never a silent deny-all, never discovered at apply. The refusal messages are golden-tested, because in the case they cover the message is the whole of what automat delivers.
- **A control set that restricts regions or services and supplies no `region_deny_exempt_services` is refused**, with no fallback to a built-in list — a fallback is the compiled-in list with extra steps.
- **Config rules:** set-union deduped by rule identifier; overlapping parameters resolve by the declared per-parameter `order` (min/max). If two sets bind the same parameter with `exact` and different values, or no order is declared: **hard error** with a conflict report demanding explicit resolution (an override file). Never guess.
- **Procedural controls:** dedupe via `crosswalk` so one practice is attested once, not once per framework ID; the stub lists all satisfied IDs.
- Output is itself a first-class artifact (new id, sources = the input artifacts, fresh content hash) — unions compose.

Property tests Claude Code should write: idempotence (A∪A=A), commutativity, associativity, and monotonicity (the union never permits behavior any input forbade). Monotonicity is asserted with the region, service, and exemption **sets** as subjects and not only the statements, and over the **packed policy documents** as well as the merged values: an allowlist is not a statement until the packer renders it, so a statement-level property cannot see it, and a renderer that intersected the members correctly could still emit a document permitting more than either input's.

The allowlist shape must be **checkable, not merely emittable**: `verify` (§12) has to say which region or service moved, so `internal/compilesets` reads region and service restrictions back off attached policy documents as AWS returns them, and a property test round-trips everything the packer emits. A shape automat can render but cannot recover would leave `verify` diffing whole documents and reporting "different" for a reordered key.

## 10. Baseline-protection meta-control

A control set that guards the guards, attached at the OU with every vend, extensible per catalog. Deny, with a Condition exempting the principals the statement names — `scp_statement.exempt_principals`, each with a required reason (Phase 1 review item 9b; see `schema/CHANGELOG.md`). This paragraph originally said "exempting only the automat automation role ARN"; the list generalizes that, because a deployment has other legitimate holes (break-glass, a central-IT audit role) and a catalog that cannot name them forces the operator to weaken the Deny itself instead. Under union these lists are **intersected**, never concatenated: an exemption is the only thing in a catalog that widens a policy, so concatenation would let adding a control set widen the merge, which §9's monotonicity property forbids. Only `automat:automation-role` (materialized by the packer at vend time) or a fully qualified IAM role ARN — no wildcards, no root, no users, so no exemption entry can undo the root-user Deny below.

The deny list itself:

- `config:DeleteConfigurationRecorder`, `config:StopConfigurationRecorder`, `config:DeleteDeliveryChannel`, conformance-pack delete/modify
- `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail` (scoped to the baseline trail if one is deployed)
- `organizations:LeaveOrganization`
- IAM mutation (`iam:Update*/Delete*/Put*/Attach*/Detach*` on) of `OrganizationAccountAccessRole` and the automat automation role
- Root-user usage deny (`aws:PrincipalArn` = `arn:aws:iam::*:root`) — standard hygiene, and it maps onto AC-family practices

Represent as `enforcement: baseline-protection` entries in the artifact, not hardcoded, so L2-minded users can extend the deny list.

## 11. Evidence manifests

Every mutating operation appends a record; `vend` writes a per-account manifest:

- Content: timestamp, operator principal, operation, account/OU IDs, control artifact id + `content_sha256`, the environment profile id + `content_sha256` + the attestations over it that verified, SCP ARNs attached, conformance pack ARN, region/service sets, tool version.
- Canonical JSON, hash-chained (each record includes previous record's hash), signed (start with a local key; design the signer as an interface so KMS signing is a drop-in).
- Stored: in-account S3 (created at vend) and/or the vending account; local copy always.
- Purpose: the "born compliant" chain of custody. The format lives in `schema/` beside the control artifact and is deliberately simple, append-only, and ingestible by future systems. (Internal note, not for docs: shaped so an evidence kernel can adopt it later. No external product named anywhere.)

### 11a. Cosigning and freshness — provenance only

Profile documents (both `environment-profile/v1` and `obligation-profile/v1`) may carry an optional
`signatures[]` array, and must carry a required `review_by` date. Both exist because a
profile is a *reading of policy an institution acts on*, and the two ways such a
document goes wrong are that nobody will say where it came from, and that it silently
stops being current.

**A signature attests provenance and nothing else.** Never correctness, never
applicability to a particular institution, never approval for a particular use. Each
entry is an attestation predicate over the document's content hash and carries a
**role** plus a **statement in the attester's own words** — never a bare signature. The
roles are `authored-by`, `adopted-by`, `reviewed-by`, `interpreted-by`, and
`format-validated-by`. The vocabulary is the point: "X wrote this", "Y adopted it for
its own use", "Z read it", and "the format validated" are four different claims, and a
reader shown one undifferentiated checkmark will infer the strongest of them. The
statement is required for the same reason — a bare signature invites the reader to
supply the claim, and they supply the most flattering one available.

**Trust is an operator determination.** Whether any identity in `signatures[]` counts
for anything is decided by the operator, against a trust policy file the operator
maintains naming accepted identities per role. **automat ships no trust anchor and no
default accepted identity**, and it must never become a registry, a signing service, or
a standards owner. The intended v2 mechanism is keyless
OIDC-identity signing so that an institution never has to run a key ceremony, with
documents and their attestations distributed over ordinary git or an OCI registry;
`signature.format` names that form now so adopting it is not a schema version event.
**v1 implements no verification and loads no trust policy.**

**Freshness is the other half, because signed does not mean current.** A superseded
citation renders exactly as well as a live one, and a durable, signed, stale artifact is
worse than an unsigned one: it carries the authority without the accuracy. `review_by`
is therefore required with no default, sits inside the content hash the attestations
cover (so extending it is a change no earlier attestation vouches for), and `verify`
**warns** when it has lapsed — warns, rather than fails, because a lapsed review date is
a statement about the document, not about the account.

At vend time the evidence record names the environment profile by id and content hash, its
`review_by`, and the set of attestations that **verified** — identity and role. Not the
attestations merely *present in the file*: copying those would be manufacturing
assurance out of a document's own claims about itself. In v1 that set is always empty,
and the field is required rather than optional precisely so an empty set is a recorded
answer rather than an absent question.

## 12. `verify`

`automat verify --account <id>`: re-walk the artifact against reality.

**Implemented (Phase 4): the policy and freshness layers only** — see
`docs/cli-surface.md` D4 for why `--ou` is not a separate accepted form (baseline-
protection's automation-role exemption embeds the account id, so the expected policy
set cannot be compiled for an OU with no account in hand) and why the detective and
procedural layers are not checked (both check what DESIGN §7 step 5 —
`internal/baseline` — would install, and that package does not exist yet).

- Policy layer: attached SCPs compared against a fresh compile of the same environment
  profile, by structural document comparison (`org.SameDocument`) — not by a content-hash
  tag, since automat writes no such tag on any SCP today (also D4).
- Detective layer: recorder on, delivery channel intact, conformance pack present and its rule set matches; then report current compliance findings (resource noncompliance is *signal*, not drift — present it as findings, distinct from baseline drift). **Not yet checkable — see D4.**
- Procedural layer: attestation stubs present; staleness vs. declared frequency. **Not yet checkable — see D4.**
- Freshness layer: **warn** when the environment profile's `review_by` date has lapsed (§11a). A warning, not a failure — the account is exactly as compliant as it was yesterday; what has expired is anyone's assurance that the document describing it is still a correct reading of policy.
- Structural honesty: for each control set, print the enforcement-class breakdown ("X of Y controls enforced/monitored by this tool; N require documented process; M require continuous evidence collection outside this tool's scope"). Computed from the artifact — this is also how the tool states its limits for L2+ catalogs without ever pitching anything. **Not yet implemented**; the shipped report lists the control sets compiled rather than a per-control breakdown.

Exit codes suitable for cron/CI.

## 13. CLI surface (cobra)

```
automat login        # SSO device flow (ssooidc) or standard credential chain; credential-profile-aware
automat preflight    # three-state classification + permission report
automat init         # STANDALONE or MANAGEMENT: CreateOrganization(ALL) + research OU, or adopt an
                      # organization already created outside automat (enable SCPs, ensure the OU).
                      # Refuses MEMBER, which has neither authority and is pointed at `setup --request`.
automat setup        # MANAGEMENT: apply delegation + create vendor role for a member acct
automat setup --request   # MEMBER: emit onboarding bundle (§6)
automat vend         # §7 steps 1-4 and 6 (compile control set, create account, move, attach SCPs,
                      # write evidence + birth certificate). --override resolves a Config-rule
                      # parameter conflict the union could not settle on its own (§9, D6). Step 5,
                      # the in-child baseline (Config recorder, conformance pack, opt-in regions,
                      # automation role), is NOT YET IMPLEMENTED — see docs/cli-surface.md D3. A
                      # vended account's preventive controls are real; nothing in it is being
                      # watched yet, and `vend` says so in its plan, its evidence manifest, and
                      # its birth certificate rather than staying silent about the gap.
automat verify       # §12: policy + freshness layers only (detective/procedural NOT YET
                      # IMPLEMENTED — see docs/cli-surface.md D4). --override must match the one
                      # `vend` used (D6), or the recompiled expectation will not be the one
                      # actually attached.
automat list         # accounts and OUs under --ou (or the config `ou`, or the org root),
                      # plus parked accounts from local evidence manifests under
                      # --evidence-dir. No tag-based filtering — see docs/cli-surface.md D5
automat assess       # docs/assessment-reporting.md, Stage 3 only: CMMC L1 MET/NOT MET
                      # summary against --profile cmmc-l1 and an optional
                      # --determinations file. Read-only beyond one
                      # sts:GetCallerIdentity call; writes an OpAssess evidence record
                      # under --evidence-dir (default "evidence" — must match the
                      # environment profile's baseline.evidence.local_dir that vended
                      # the account, since assess has no --environment-profile of its
                      # own to read that override from; see docs/cli-surface.md D8).
                      # Stages 1-2 (800-171A worksheet, DFARS scoring) NOT YET
                      # IMPLEMENTED — see docs/cli-surface.md D7. This build contributes
                      # zero machine evidence for any CMMC L1 practice (no SCP fragments
                      # in the catalog, no AWS Config read path), and the rendered
                      # summary discloses that rather than staying silent.
automat reclaim      # LATER (Phase 5): close/park accounts; respect closure rate limits
```

`automat assess` is an addition to this list, not a contradiction of it: per the Phase 1
review's ratification condition, a command absent from an earlier revision of §13 could be
added once its scope was approved (docs/assessment-reporting.md), and it now appears here as
that approval's implementation lands.

There is no `automat compile` subcommand. Union/compile control sets → artifact (§9) is
maintainer tooling, `gen/catalog`, run against curated sources in `gen/sources` and vendored
into `catalogs/` for the CLI to read — never run against attacker-supplied input, and never
exposed as an end-user command. An operator does not compile a control set; they choose one by
id in an environment profile.

Config: `~/.config/automat/config.toml` + per-org context (vendor role ARN, ExternalId ref, OU id, email pattern). Never store secrets; lean on the AWS credential chain and OS keychain if anything must persist.

## 14. Conventions (the adoption contract)

These are automat's own, documented publicly in `docs/conventions.md`; external systems may adopt them, automat depends on nothing external:

- Tags on vended accounts: `automat:vended-by`, `automat:ou`, `automat:artifact-id`, `automat:artifact-sha256`, `automat:version`. Enable as cost-allocation tags where possible (chargeback matters as much as compliance to this audience).
- SCP names: `automat-<environment-profile-id>-<n>` (e.g. `automat-research-cui-1`), an ordinal
  over the packed policy set rather than one name per artifact or class. A vend unions
  multiple control sets into a shared pool of statements (§9) and packs them by size against
  a five-SCP-per-target quota, so a single attached policy has no one artifact id and no one
  class to name — the environment profile id is the one id a packed policy always has exactly
  one of, and Organizations enforces name uniqueness in a way an ordinal satisfies and a
  per-artifact name would not (two vends against one OU under different profiles would collide
  on a name naming neither). `verify` (§12) finds and distinguishes packed policies by their
  tags, not by parsing the name.

- SCPs are NOT tagged with the artifact hash today; that remains open (Q16 in
  `docs/open-questions.md`, `internal/org` has no artifact-hash tagging on any SCP yet).
- Manifest locations: `s3://automat-evidence-<acct>/manifests/…` and management-side mirror.
- OU marker tag on automat-managed OUs.

## 15. Branding rule (hard requirement)

No references to any commercial suite, company, or upstream product in code, docs, tags, schema, or output. automat is complete for its stated scope. The only forward pointer permitted is capability-phrased (§12's enforcement-class statement) plus, at most, a single neutral `docs/beyond.md` page. Dependency direction: others may build on automat's published conventions; automat imports nothing from them.

## 16. Known risks / open questions for the human

- Approval-per-vend: some central ITs will demand a human in the loop. v1 is standing-delegation only; a request/approve queue is explicitly out of scope (note in README).
- `reclaim` semantics — **resolved**: durable by default (`docs/reclaim-design.md`), settled before implementation the same way `docs/assessment-reporting.md` settled `assess`'s scope.
- SCP count/size quotas per target (5 SCPs directly attached per target; 5120-char SCP size) will constrain how union output is packed into policies — the SCP packer needs to be quota-aware and is a real piece of work, not a serialization detail.
- Delegation-policy visibility from the member side (what preflight can actually detect vs. must be told) needs empirical testing against a real org.
