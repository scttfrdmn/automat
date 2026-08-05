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

This is a **Phase 1 build**. The list below is what you can actually run; everything else
in the design is marked as not shipping yet, in this file and in `automat --help`.

| Command | Does | Landed |
|---|---|---|
| `automat preflight` | Classifies where you stand — standalone, management, or member — and reports every capability automat needs, with the exact grant that would fix anything missing | Phase 1 |
| `automat setup --request` | Generates the onboarding bundle a member account sends to whoever runs the organization: delegation policy, vendor role as CloudFormation and Terraform, and a cover note stating the blast radius. Writes five files; makes no AWS call | Phase 1 |
| `automat login` | Signs in through AWS SSO and caches the token where every AWS tool reads it | Phase 1 |
| `automat version` | Prints the version stamped into generated artifacts | Phase 1 |

Read preflight's **certainty column**. A permission check is evidence, not authorization:
`iam:SimulatePrincipalPolicy` does not evaluate service control policies, so from a member
account a call reported as allowed can still be denied by an SCP above you. A check
reliably tells you a grant is *missing*; it cannot promise a call will succeed.

## Not in this version

Named because leaving them out would read as an oversight, and naming them as though they
worked would be worse. Each is in [`ROADMAP.md`](ROADMAP.md) with a phase.

- **`automat init` and `automat vend`** — creating and baselining accounts. Phase 2. This
  is the point of the tool, and it does not exist yet.
- **`automat setup` without `--request`** — applying the delegation directly from a
  management account. Phase 3. The command refuses and names the phase.
- **`automat verify`** — re-reading what is actually attached to an account. Phase 4. Worth
  singling out: the delegation automat asks for includes `organizations:DetachPolicy` on
  automat's own policies, so the controls a vended account is born with are **not
  permanent** against the account that vended it, and `verify` is the answer to that. The
  onboarding bundle's cover note says so, including that `verify` does not ship yet.
- **`automat list`** — tag-driven inventory. Phase 4.
- **`automat assess`** — assessment reporting: 800-171A objective worksheets, CMMC L1
  MET/NOT MET summaries, DFARS score arithmetic. Phase 4, scope approved in
  [`docs/assessment-reporting.md`](docs/assessment-reporting.md).
- **`automat reclaim`** — account closure. Phase 5.
- **`automat compile`** — union of control sets. The compiler exists as maintainer tooling
  in `gen/catalog`, not as a subcommand; see [`docs/cli-surface.md`](docs/cli-surface.md).

## What is data, not code

Three kinds of file are versioned contracts rather than implementation, which is most of
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
- [`audits/`](audits/) — the adversarial self-audit at the end of each phase, findings
  ranked and each one resolved or accepted in writing.
- [`docs/open-questions.md`](docs/open-questions.md) — what is genuinely unresolved,
  including what only a live organization can answer.

Apache-2.0.
