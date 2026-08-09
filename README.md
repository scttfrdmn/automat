# automat

A single static binary that vends AWS member accounts with compliance controls attached at
birth — driven by a compiled control artifact rather than a landing-zone deployment.

Built for university research computing: central IT holds the organization's management
account and typically will not run an account factory for researchers. automat splits the
ceremony so central IT approves one small, reviewable grant, and the research group vends
thereafter without further involvement.

---

> **automat encodes a technical reading of published policy. It is not legal advice and not
> a compliance determination.** The agreement, award terms, or contract clause your
> institution signed governs; your sponsored programs office, contracts office, or counsel
> decides what applies and which revision. Where policy is ambiguous — for example the NIH
> 800-171 revision question — automat records the operator's declaration rather than
> resolving it. Policy citations carry effective dates and change; verify against the
> primary source before relying on them.

See [`docs/policy-caveat.md`](docs/policy-caveat.md). That paragraph is canonical and held
by a test rather than by convention, because the rendered output is what gets forwarded and
attached to an agreement, usually without whatever page explained the caveat.

---

## What works today

This is a **Phase 2 build in progress**. The list below is what you can actually run;
everything else in the design is marked as not shipping yet, in this file and in
`automat --help`.

| Command | Does | Landed |
|---|---|---|
| `automat preflight` | Classifies where you stand — standalone, management, or member — and reports every capability automat needs, with the exact grant that would fix anything missing | Phase 1 |
| `automat init` | Prepares an organization to vend into: creates one with all features if this account is not in one, enables the service control policy type on the root, and ensures an OU below it. Prints a plan first; every step is create-or-verify, so a second run writes nothing | Phase 2 |
| `automat vend` | Creates one member account from an environment profile, moves it into the target OU, and ensures the OU's service control policies from the compiled control sets — controls attached before the account is handed to anyone. Writes a hash-chained evidence manifest and prints a birth certificate. **Preventive controls only:** it performs no in-child baseline work, and says so in every plan and every manifest (see below) | Phase 2 |
| `automat setup --request` | Generates the onboarding bundle a member account sends to whoever runs the organization: delegation policy, vendor role as CloudFormation and Terraform, and a cover note stating the blast radius. Writes five files; makes no AWS call | Phase 1 |
| `automat setup` (no `--request`) | Applies the delegation policy and creates the vendor role directly, from the management account. Requires a real target OU (`--ou`) and an ExternalId reference (`--external-id-ref`) — no template parameter to defer either to, and automat does not generate an ExternalId. Ensure-semantics: a second run corrects drift | Phase 3 |
| `automat verify` | Re-checks one account's attached service control policies against a fresh compile of the environment profile that vended it, and warns if the profile's `review_by` date has passed. Read-only; checks the policy and freshness layers only — the detective and procedural layers have nothing to check against until the in-child baseline exists (see below) | Phase 4 |
| `automat list` | Inventories the organizational units and accounts under the configured OU (or the root), plus every account a local evidence manifest records as parked. Makes no write call, but is not read-only by construction the way `verify` is — the tree walk travels the same client `vend` uses and assumes the vendor role in the MEMBER state. Tag-based filtering is not available — see below | Phase 4 |
| `automat assess` | Renders a CMMC Level 1 MET/NOT MET summary — the fifteen practices in `catalogs/cmmc-l1.json` against an optional operator-determinations file. Read-only beyond one `sts:GetCallerIdentity` call for evidence attribution. **This build contributes zero machine evidence**: the catalog carries no SCP fragments and no AWS Config read path exists yet, so every practice is an operator determination or, absent one, a NOT MET the renderer states rather than leaves silent — CMMC L1 permits no partial credit and no plan of action. The 800-171A worksheet and DFARS scoring (Stages 1–2) are not built; `--profile` accepts only `cmmc-l1` — see [`docs/assessment-reporting.md`](docs/assessment-reporting.md) | Phase 4 |
| `automat reclaim` | Closes a vended account: detaches automat's own service control policies from its OU placement, then calls `CloseAccount`. A vended account is durable by default — this is the one destructive command in the tree, and `--yes` is required unconditionally to apply, not gated on one step the way `init`'s org-creation gate is. Writes an evidence record; see [`docs/reclaim-design.md`](docs/reclaim-design.md) | Phase 5 |
| `automat login` | Signs in through AWS SSO and caches the token where every AWS tool reads it | Phase 1 |
| `automat version` | Prints the version stamped into generated artifacts | Phase 1 |

Read preflight's **certainty column**. A permission check is evidence, not authorization:
`iam:SimulatePrincipalPolicy` does not evaluate service control policies, so from a member
account a call reported as allowed can still be denied by an SCP above you. A check
reliably tells you a grant is *missing*; it cannot promise a call will succeed.

## Not in this version

Named because leaving them out would read as an oversight, and naming them as though they
worked would be worse. Each is in [`ROADMAP.md`](ROADMAP.md) with a phase.

- **The in-child baseline** — the half of vending that works *inside* the new account: the
  Config recorder and delivery channel, the conformance pack compiled from the control sets'
  Config rules, opt-in region enablement, attestation stubs for the procedural controls, and
  the in-account automation role. Phase 2, in progress. Vending itself works (see the table
  above) and what it attaches is real, but it attaches only **preventive** controls. A
  vended account therefore has no detective baseline: nothing in it is being *watched*.
  Singled out here rather than left as a footnote because a vended account looks finished —
  so the plan reports the step as not performed, and the evidence manifest carries a
  **parked** `baseline-apply` record. That record is what stops a manifest which is merely
  silent about the baseline from reading as a baseline that succeeded.
- **`list`'s tag-based filtering** — DESIGN §13 describes it as inventorying "vended
  accounts (by tags)". The vendor role bundle grants no
  `organizations:ListTagsForResource` on account resources
  ([`docs/open-questions.md`](docs/open-questions.md) Q19), so an account's
  `automat:vended-by`/`automat:ou` tags cannot be read back through this client — `list`
  shows every account under the walked OU regardless of tag.
- **Assessment reporting Stages 1 and 2** — the 800-171A objective worksheet and DFARS
  score arithmetic. Both need a hand-transcribed-twice weight table
  ([`docs/open-questions.md`](docs/open-questions.md) Q10), real off-computer work rather
  than code. Stage 3, the CMMC L1 summary, ships today (see the table above).
- **`automat compile`** — union of control sets. The compiler exists as maintainer tooling
  in `gen/catalog`, not as a subcommand; see [`docs/cli-surface.md`](docs/cli-surface.md).

## What is data, not code

Four kinds of file are versioned contracts rather than implementation, which is most of
why this tool is reviewable at all:

- **`schema/`** — JSON Schemas with a [changelog](schema/CHANGELOG.md). A change to a
  published schema bumps a version and adds a migration note.
- **`catalogs/`** — compiled control artifacts. `cmmc-l1.json` is the fifteen CMMC 2.0
  Level 1 practices, each control naming how it is enforced (preventive SCP, detective
  Config rule, or procedural attestation) and where the binding came from.
- **`catalogs/obligations/`** — obligation profiles. A catalog answers *which controls*; a
  profile answers under what instrument, assessed how, signed by whom, and whether gaps may
  be deferred. Three ship: `cmmc-l1`, `dfars-7012`, `nih-cadr-dua`. Profiles are data with
  no code behind them yet — `assess` is Phase 4.
- **`catalogs/classification/`** — institutional classification profiles: one university's
  data levels, what each means, and what its published policy requires there, so that "this
  account is rated for P4 – High" is a sentence with a citation behind it. Two ship as
  **examples to fork, not maintained documents** — automat is the interpreter and the
  institution has endorsed nothing. See
  [`docs/institutional-profiles.md`](docs/institutional-profiles.md).

## Building

```
make build test lint
```

Go ≥ 1.24, `CGO_ENABLED=0`, no daemons and no database. **No test or CI run touches real
AWS**; everything is fake-backed. `make smoke` is the separate, manual, opt-in path for
live testing — see [`docs/smoke.md`](docs/smoke.md).

## Reading further

- [`DESIGN.md`](DESIGN.md) — the source of truth, including the AWS facts the whole design
  rests on.
- [`ROADMAP.md`](ROADMAP.md) — what lands when.
- [`docs/cli-surface.md`](docs/cli-surface.md) — every flag reconciled against the design's
  CLI section, read from the built binary rather than from the design.
- [`docs/institutional-profiles.md`](docs/institutional-profiles.md) — the classification
  model, the six universities it was derived from, and why automat proposes a format and
  never a governance body.
- [`audits/`](audits/) — the adversarial self-audit at the end of each phase, findings
  ranked and each one resolved or accepted in writing.
- [`docs/open-questions.md`](docs/open-questions.md) — what is genuinely unresolved,
  including what only a live organization can answer.

Apache-2.0.
