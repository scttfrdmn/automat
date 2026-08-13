# Vitrine — a web GUI shell over automat

**Status: architecture recommendation for a separate, not-yet-started side-project.**
Not built, not scheduled, not part of automat's own codebase or ROADMAP.md. This page
records the research and the decisions that should shape that project's first commit,
the same way `docs/billing-conductor-design.md` and `docs/hold-design.md` settle a
design before code exists for a capability that IS automat's own. This one is different
in one respect worth stating plainly: **nothing in this document proposes changing
automat.** It exists in `docs/` because the question "would automat need to change to
support this" is a question about automat, and its answer belongs where automat's other
design decisions live — not because the GUI project itself is going to be built here.

## What Vitrine is

A web-based GUI — its own repository, its own backend, its own frontend — that lets an
admin drive automat's read-only capabilities from a browser instead of a terminal. Named
for the glass display case in a real automat: the compartments where the food is visible
but the machinery behind them stays out of sight. Vitrine is the glass, not the kitchen —
it shows what automat already knows and does, through the same narrow interface a CLI
already gives every other caller (an operator typing commands), rather than reimplementing
or reaching around any part of automat itself.

## The governing decision

**automat does not need to change for Vitrine to exist.** Every capability in scope for
a first version — `preflight`, `list`, `verify`, `assess` — is reachable today by shelling
out to the compiled `automat` binary and parsing its output. This is confirmed, not
assumed: see "Integration path" below for why the alternative (importing automat's
internals as a Go library) is not merely undesirable but blocked by the Go compiler
itself, and "What automat could optionally gain" for the one narrow addition worth
raising with automat's own maintainer later — as an ask, never a plan Vitrine is entitled
to expect.

Mutating capability — `vend`, `reclaim`, `init`, `setup` — is **explicitly out of scope
for a first version**, for reasons "Build order" makes concrete: automat's plan/apply
discipline and evidence-chain attribution model both carry real, sharp implications for a
GUI that a read-only dashboard never has to resolve, and resolving them badly on day one
would cost more than deferring them until a read-only Vitrine has taught the team
something real about how admins actually use it.

## Integration path: subprocess, not library

Go enforces `internal/` import visibility at the compiler level: any package path
containing an `internal/` segment is importable only from code sharing the same module
root. `github.com/scttfrdmn/automat/internal/evidence`, `internal/org`, every package
automat is built from — none of it is importable from a separate module in a separate
repository, regardless of whether an identifier is exported. This is not a project
convention Vitrine could ask automat's maintainer to waive; it is a `go build` failure,
unconditionally, for any importer outside `github.com/scttfrdmn/automat/...`.

So there are exactly two integration paths, not three:

1. **Shell out to the compiled `automat` binary**, parse stdout/stderr and the exit code.
   Available today. Needs nothing from automat's maintainer. This is Vitrine's path.
2. **automat exposes a new, deliberately public, non-`internal` API package** a separate
   module could import directly. This is a much bigger and more permanent commitment than
   a CLI-surface or schema change — a second, indefinite public contract sitting beside
   the ones CLAUDE.md already gates behind asking first — and it cuts against automat's
   own "single static binary, no daemon" design in spirit, since the natural next step
   after "import automat as a library" is "call AWS directly instead of forking a
   process," which erodes the boundary between automat and whatever consumes it. Not
   proposed here. Flagged only as a theoretical future direction if the subprocess
   boundary ever becomes a genuine, demonstrated bottleneck — and even then, something
   only automat's own maintainer decides to build, not something Vitrine designs and
   hands over.

## Async operations: `--resume` already solves this

`vend` can take minutes (`CreateAccount` polling, conformance-pack deployment, opt-in
region enablement). A web request cannot block for that long. automat already has the
mechanism a backend needs, and it needs nothing new: every step `vend` performs is
create-or-verify, and a run that's interrupted mid-flight parks with a resume token
(`vend --resume <request-id>`) that a bare re-run or a later `--resume` call continues
safely — no double-create, no lost account. A backend can invoke `vend` with a bounded
timeout, and on timeout treat the parked evidence record (or the printed resume hint) as
its own poll target, re-invoking `--resume` on a schedule, rather than needing automat to
stream progress or hold a connection open. This generalizes to `reclaim` (no `--resume`
flag exists, but a bare re-run of `reclaim --yes` continues a partial detach-then-close
by the same idempotent design) and needs no invention on Vitrine's side beyond "poll by
re-invoking, don't hold a process open."

One real gap, worth naming and not fixing: `vend`'s in-child baseline steps (automation
role, regions, conformance pack, Config recorder) run and poll *within* one apply pass,
with no per-substep resume token — only the whole-vend request id. A backend gets no
live sub-step progress today, only "still running" until the whole pass returns or is
killed. Irrelevant to a read-only first version; relevant only once a later version wants
a progress bar for `vend` itself.

## Auth model: one fixed backend identity to start, not per-admin brokering

automat holds no credential of its own — it resolves whatever the OS-level AWS config
chain hands it (profile, env var, SSO cache), the same way the AWS CLI does, by design
(`internal/login`'s own doc comment: "An automat-owned token store would be a second copy
of a credential"). A CLI run has a natural 1:1 relationship between the human at the
terminal and the AWS identity that acts. A web backend serving many admins does not have
that for free, and the two ways to get it are not equivalent:

- **One fixed, narrowly-scoped backend operator identity**, used for every action
  regardless of which admin clicked in the browser. Simple: one set of credentials to
  hold and refresh, one IAM principal for central IT to review. Cost: automat's evidence
  manifests record `Operator.ARN` from `sts:GetCallerIdentity` at the top of every
  mutating command — if the backend always presents the same identity, every evidence
  record's operator field says "the backend," not "which admin approved this." The
  chain-of-custody claim DESIGN §11 makes for the evidence manifest is about the AWS
  principal that acted, and that claim stays literally true either way — it is the
  *implicit* expectation a reader might bring (that the manifest tracks the human) that
  quietly stops holding. Individual-admin attribution would then live only in Vitrine's
  own session log, a system with none of the evidence chain's hash-linking or signing
  guarantees. That is a real, disclosable limitation to document in Vitrine's own docs,
  not a defect in automat — automat's `Operator` type never claimed to identify a human,
  only an AWS principal.
- **Per-admin SSO session brokering** — the backend runs each admin's own device-flow
  login and holds their short-lived credentials server-side, invoking automat under each
  admin's real identity per request. Evidence attribution becomes fully faithful, at the
  cost of managing N live credential sets concurrently (a mixing bug here is a
  privilege-escalation bug) and extending central IT's blast-radius review to as many
  principals as there are Vitrine admins.

**Decision: start with one fixed backend identity.** It's the right tradeoff for a
read-only first version, where the operator-attribution question barely bites (`verify`
and `assess` write at most a local evidence record; `preflight` and `list` write nothing
at all). Revisit per-admin brokering only if and when a later version adds `vend` or
`reclaim`, where an evidence-chain reader's expectation about who acted actually matters
to the audience automat is built for — a CMMC assessor, a central-IT reviewer reading the
manifest months later.

## Evidence and file outputs: colocate first, mirror-as-source-of-truth later

`vend`/`verify`/`reclaim`/`assess` write local evidence manifests unconditionally and
optionally mirror them to S3, best-effort, after the local write (DESIGN §11's "local
copy always"). Two deployment shapes follow from this, and they are not interchangeable:

- **Colocated backend** — same filesystem as wherever `automat` runs, reading local
  evidence/output files directly. Zero new AWS grants, zero extra network round trip,
  works in every org state. Constrains the backend to a persistent host or volume rather
  than a fully stateless deployment.
- **S3-mirror-as-source-of-truth** — a stateless backend (container, function) with no
  durable local disk would need to pull the evidence tree from the mirror bucket before
  every automat invocation and push it back after, since automat's own mirror path is
  one-way except for `verify`'s read-back. Workable, but real plumbing, and only earns
  its cost once Vitrine needs to run with no durable local disk at all.

**Decision: colocate for a first version.** It matches the read-only scope's needs
exactly — `preflight`/`list` write nothing, `verify`/`assess` write small local files a
colocated backend reads directly with no new grants — and defers the mirror-as-source
shape to whatever later version actually needs a fully stateless, horizontally-scaled
deployment (a multi-institution hosted version, if that is ever a goal; not assumed here).

## Plan/apply drift: a GUI's own responsibility, sharper than the CLI's

Every mutating automat command plans and applies as two separate, live reads against AWS
within one process, seconds apart — never a cached prediction replayed later. Nothing in
automat locks a resource or takes a concurrency token between the two; that's a real gap
in AWS Organizations' own API surface, not something a flag on automat could close. A CLI
operator's plan-then-apply happens within one command, at the terminal, seconds apart. A
GUI's "preview, then click confirm" can have arbitrary human-scale time in between — an
admin can tab away for ten minutes, long enough for a quota to fill or another operator to
have moved the same account.

**This is Vitrine's problem to solve, not automat's.** On confirm, Vitrine must re-run
`--dry-run` fresh, immediately before the real apply, and diff the new plan against what
the admin actually saw and approved — refusing or re-prompting on a material difference
rather than trusting a plan that's already stale. automat gives Vitrine everything needed
to build that diff (the same struct-backed plan data both the shown-preview run and the
fresh pre-apply run produce); it does not need to grow a plan-caching or plan-diffing
feature of its own to make this possible. This becomes relevant only once a later version
adds `vend`/`reclaim` — not a concern for the read-only first version, where nothing is
ever applied.

## What automat could optionally gain — an ask, not a plan

No change is required to build a read-only Vitrine. If, later, prose-parsing `preflight`'s
and `verify`'s report text turns out to be a genuine, ongoing maintenance cost (rather
than a hypothetical one), the single highest-leverage addition would be a `--json` flag
on those two commands specifically — a serialized form of the `Report`/`PolicyReport`/
`FreshnessStatus`/`StructuralHonestyReport` structs they already build internally before
rendering prose, not new data. `assess` already emits real JSON (`assessment-result.json`),
so it needs nothing further.

This is flagged here exactly as CLAUDE.md requires: a CLI-surface change, needing
automat's maintainer's sign-off first, not something Vitrine's own team decides and
implements. It is explicitly **not** proposed for `vend`/`reclaim`/`init`/`setup` — those
commands' output is inseparable from a plan/apply narrative (birth certificates, parked-
resume hints) that would need a much larger, more deliberate schema-design pass than
serializing a verify report, and should wait until a concrete, motivated need exists
rather than being asked for speculatively now.

Exit codes are uneven across commands today (`preflight`/`verify` have a real
clean/problem/undetermined taxonomy; `list`/`assess`/`login` return plain 0/1) but this
is not worth asking to standardize before Vitrine has hit a real problem from it — a
read-only first version needs only "succeeded" vs. "failed, show stderr" for the commands
without a richer taxonomy, which a plain non-zero exit already gives it.

## Proposed architecture

- **Language: Go.** The backend's job is almost entirely "invoke a subprocess, capture
  output, serve JSON to a browser." A Go backend can also validate against automat's own
  `schema/` JSON Schemas (the cross-language contract, unlike anything under `internal/`)
  before ever shelling out, and share tooling/skill with anyone who already knows automat.
- **Wire shape: subprocess-per-action, not a long-lived wrapper process.** automat is
  explicitly single-binary, no-daemon, with no expensive per-invocation cost (no
  connection pool, no warm state) to amortize by staying resident. Each Vitrine action
  becomes: build flags/input files, run the binary with a bounded timeout, capture
  stdout/stderr/exit code, parse, respond.
- **Deployment: colocated** with the automat binary and its evidence directory, per the
  evidence-output decision above.
- **Backend identity: one fixed, narrowly-scoped operator role**, per the auth-model
  decision above.

## Build order

**Version 1 — read-only dashboard.** `preflight` (org-state/readiness), `list`
(account/OU inventory, parked accounts), `verify` (drift/freshness for one account),
`assess` (render the CMMC L1 summary — the easiest to wire well, since it already emits
real JSON). No `--yes` anywhere in this version. No plan/apply-drift handling needed (v1
never applies anything). No credential-brokering complexity beyond one fixed identity.
No automat change of any kind required to ship it. This version's real purpose, beyond
its own utility, is to test the subprocess-integration approach cheaply before committing
to anything harder.

**Version 2 — guarded mutation, `vend` only.** Built strictly around "preview, confirm,
re-plan fresh, apply" — the first version where the plan/apply-drift discipline above
actually matters, and the first point at which per-admin credential brokering is worth
reconsidering, if attribution in the evidence chain has started to matter to Vitrine's
actual users by then.

**Version 3 — `reclaim`.** Follows, not leads, `vend` — more destructive (an unconditional
`--yes` gate, a 90-day-then-permanent point of no return per `docs/reclaim-design.md`) and
should wait for real operational confidence in how Vitrine handles `vend`'s plan/apply/
resume lifecycle first.

**Deferred, unscoped:** `init`/`setup` — rare, high-consequence, once-per-org actions
plausibly better left CLI-only, performed deliberately by whoever bootstraps an org rather
than exposed as a GUI button; and live sub-step progress for `vend`'s in-child baseline
work, which needs a per-substep resume token automat does not have today (see "Async
operations" above) and is not worth asking for until a version actually wants that UI.

## What this document does not do

It does not commit automat's maintainer to the optional `--json` ask above, or to
anything else — every "automat could" in this document is a future ask, not a queued
task, and none of it appears in automat's own ROADMAP.md. It does not revisit whether
Vitrine should exist at all; that was settled by the research this document records, not
re-litigated here.

Everything from here down IS meant to be specific enough to hand to a coding agent (or a
person) and have version 1 built directly, with no further design discussion needed for
the four read-only commands in scope. If reality disagrees with something stated below
(an exact flag name, an exact JSON field), the running `automat --help` / `automat
<command> --help` against the actual binary is authoritative, not this document.

## Repository and module

New, separate repository — not a directory inside `automat`. Suggested layout, a single
Go module with the frontend built as static assets the backend serves (no separate
frontend toolchain deployment to coordinate for v1):

```
vitrine/
  go.mod                  # module github.com/scttfrdmn/vitrine (or an org path later)
  cmd/vitrine/
    main.go               # http.Server bootstrap, flag/env parsing, graceful shutdown
  internal/
    runner/                # subprocess invocation: build args, run with timeout, capture
      runner.go
      runner_test.go
    parse/                 # turn automat's stdout/exit code into Vitrine's own JSON types
      preflight.go
      list.go
      verify.go
      assess.go
      parse_test.go
    api/                   # HTTP handlers, one file per endpoint group
      preflight.go
      list.go
      verify.go
      assess.go
      health.go
    config/                 # Vitrine's OWN config: path to the automat binary, working
      config.go            # directory, default --context, timeouts — separate from
                             # automat's own ~/.config/automat/config.toml, never edits it
  web/                      # static frontend (plain HTML/CSS/JS, or a small framework —
                             # a v1 frontend choice, not specified further here)
  Makefile
  README.md
```

Nothing here reuses automat's Go packages (blocked by `internal/` visibility, confirmed
above) — Vitrine reads automat's config only insofar as automat itself does, by
inheriting the same `--context`/`AWS_PROFILE`/environment that the automat binary
resolves on its own. Vitrine's `config.go` fields, settled:

- `automat_bin` — path to the `automat` binary.
- `work_dir` — the working directory to run it in, so relative `--evidence-dir` paths
  resolve the same way they would for a human running the CLI from that directory.
- `automat_config` — optional passthrough to automat's own `--config <path>` global flag,
  when a deployment needs to point at a specific `config.toml` rather than automat's
  default `~/.config/automat/config.toml`. Vitrine never reads or edits that file itself
  — it only ever passes the path through as a flag value, the same way it passes
  `--context`.
- `default_context` — passed as `--context` when a request doesn't name one.
- `evidence_dir` — default for `list`'s `--evidence-dir`; must match the real deployment's
  evidence directory.
- `profiles_dir`, `determinations_dir` — the two confined-path roots (see "Filesystem
  paths accepted from HTTP requests" below).
- `assess_out_root` — the directory `assess` responses are written under (see the assess
  endpoint's lifecycle decision below).
- `listen_addr` — defaults to a loopback address (see "Authentication on Vitrine's own
  HTTP surface" below).
- `timeout` — per-invocation subprocess timeout.
- `max_concurrent_invocations` — the global cap on in-flight automat subprocesses (see
  "Concurrent evidence writes" below).

Vitrine never reads or writes automat's own `~/.config/automat/config.toml` directly —
only ever names its path via `--config` when `automat_config` is set.

## API surface: the exact four endpoints, and the exact automat invocation behind each

Every endpoint is a thin wrapper: build an argument list, run the binary via
`internal/runner`, parse stdout/exit code via `internal/parse`, respond with JSON. No
endpoint takes a request body shaped like automat's own internal types — each takes only
the handful of scalar parameters a human would otherwise type as flags.

### `GET /api/v1/preflight`

Invokes `automat preflight [--context <ctx>]` and nothing else — the command takes no
other flags today (confirmed via `automat preflight --help`). Parses **prose stdout**;
there is no `--json` mode yet (see "What automat could optionally gain" above). Exit code
`0` = clean, `2` = not ready (at least one check failed), `3` = unknown (a check could not
complete) — these are automat's real, stable exit codes (`exitPreflightNotReady = 2`,
`exitPreflightUnknown = 3` in `cmd/automat/preflight.go`).

Response shape (Vitrine's own type, built by `internal/parse/preflight.go` from the report
text — parse defensively, and if a line doesn't match an expected pattern, surface it
under `raw_output` rather than dropping it):

```json
{
  "status": "clean | not_ready | unknown",
  "exit_code": 0,
  "state": "STANDALONE | MANAGEMENT | MEMBER",
  "can_vend": true,
  "can_vend_via": "directly",
  "checks": [
    {"name": "vendor role", "result": "pass | fail | unknown",
     "certainty": "observed | simulated | undetermined",
     "detail": "...", "grant": ""}
  ],
  "raw_output": "the full, unparsed report text — always included, so a parsing gap in\nVitrine never hides information the operator could get from the CLI directly"
}
```

`internal/preflight.Report`'s real fields (`internal/preflight/preflight.go`, `type
Report struct`) are `State`, `AccountID`, `CallerARN`, `OrgID`, `ManagementAccountID`,
`FeatureSet`, `TargetOU`, `OUFound`, `VendorRoleARN`, `VendorRoleAssumable`,
`VendorRoleExternalID`, `AccountQuota`, `AccountQuotaKnown`, `AccountCount`,
`AccountCountKnown`, `DelegationVisible`, `Checks []Check`, `CanVend`, `CanVendVia` — a
`Check` carries `Name`, `Result`, `Certainty`, `Detail`, `Grant`. **Verified against the
real binary: `Report.String()` prints far less of this struct than the fields above
suggest** — only `state:`, `account:`, `caller:`, an optional `org:` line, the `Checks`
block (name/result/certainty/detail/grant, one per check), an optional simulated-results
caveat line, and a trailing `vend: yes|no — <via>` line. `TargetOU`, `OUFound`,
`VendorRoleARN`, `AccountQuota`, `AccountCount`, `DelegationVisible` are NOT printed as
their own lines — they appear, if at all, only incidentally inside some check's `Detail`
string. So `internal/parse/preflight.go` can reliably recover `state`, `account_id`,
`caller_arn`, `org` (when present), `checks[]` (name/result/certainty/detail/grant),
`can_vend`, `can_vend_via` — roughly six-to-eight fields, not the whole struct — and
should not attempt to reconstruct the rest by scraping check details; that is exactly the
gap `raw_output` exists to cover, not something the parser should get clever about
extracting. `internal/parse/preflight.go`'s job is to recover exactly that subset,
always keeping `raw_output` as the fallback. **Always include `raw_output` in every
parsed response, for every endpoint** — this is the load-bearing convention that makes
fragile prose-parsing an acceptable v1 choice: a parsing miss degrades to "show the raw
text," never to "hide the answer."

Updated response shape, reflecting the fields that are actually recoverable:

```json
{
  "status": "clean | not_ready | unknown",
  "exit_code": 0,
  "state": "STANDALONE | MANAGEMENT | MEMBER",
  "account_id": "111111111111",
  "caller_arn": "arn:aws:sts::111111111111:assumed-role/.../automat",
  "org_id": "o-example (omitted when STANDALONE)",
  "can_vend": true,
  "can_vend_via": "directly",
  "checks": [
    {"name": "vendor role", "result": "pass | fail | unknown",
     "certainty": "observed | simulated | undetermined",
     "detail": "...", "grant": ""}
  ],
  "raw_output": "the full, unparsed report text"
}
```

### `GET /api/v1/list?ou=<id>`

Invokes `automat list [--ou <id>] [--evidence-dir <dir>] [--context <ctx>]`. `--ou` is
optional (confirmed via `automat list --help`; omitting it uses the config file's `ou` or
the organization root). Vitrine's own `--evidence-dir` default should match automat's own
default, `"evidence"` (`envprofile.DefaultEvidenceDir`, confirmed via the `--help` output
above), and must be configurable in Vitrine's own config since it has to match whatever
directory the real evidence manifests live in for this deployment. No exit-code taxonomy
beyond plain 0/1 — `list` has none today.

This is the easiest command to parse reliably, not the hardest: `renderListReport`
deliberately `%q`-quotes every variable field (AUDIT-4 M2's own discipline — a name
carrying whitespace or a quote must not be ambiguous in the report), so
`"ou-x" "name" (under "parent")`-shaped lines are unambiguous even against adversarial
OU/account names.

Response shape:

```json
{
  "ous": [{"id": "ou-...", "name": "...", "parent_id": "..."}],
  "accounts": [{"id": "...", "name": "...", "email": "...", "parent_ou_id": "..."}],
  "parked_accounts": [{"account_id": "...", "operation": "...", "timestamp": "...", "detail": "..."}],
  "raw_output": "..."
}
```

### `GET /api/v1/verify?account=<id>&profile=<path>`

Invokes `automat verify --account <id> --environment-profile <path> [--override <path>]
[--context <ctx>]`. Both `--account` and `--environment-profile` are **required** by
automat itself (confirmed via `--help`; automat refuses and prints a specific error if
either is missing — do not let Vitrine's own request validation duplicate that message,
just pass the flags and surface automat's own error text if they're missing). `--account`
must match `^[0-9]{12}$` — validate this in Vitrine before shelling out, to fail fast with
a clear message rather than let automat's own regex refusal round-trip through a
subprocess unnecessarily. `--environment-profile` is a path **on the machine automat
runs on** — since Vitrine is colocated with automat (see "Evidence and file outputs"
above), this is a real, existing file path the backend's own filesystem can also see; a
future version might accept an uploaded profile document instead, but v1 does not — profile
selection is by path, matching how a CLI operator would invoke it. There is **no
`--evidence-dir` flag on `verify`** (unlike `list`/`assess`) — it reads the evidence
directory from the environment profile's own `baseline.evidence.local_dir`, so Vitrine
must not offer a `--evidence-dir` override for this endpoint; the profile is the only
source of that path here.

Exit codes: `0` clean, `2` = `exitVerifyDrift` (policy or mirror drift found), `3` =
`exitVerifyUnknown` (nothing found wrong, but a check could not complete — e.g. a
lapsed `review_by` freshness date, or an unreachable mirror). These are real, stable
constants in `cmd/automat/verify.go`.

**Real report shape, confirmed against `cmd/automat/testdata/golden/verify/*.txt` and
`internal/verify`'s source, not assumed:** `Account <id> (OU/root "<target>")`, then a
`Policy layer:` section, a `Freshness layer:` section, a `Structural honesty:` section,
and — only when at least one mirror bucket is configured for this profile — an
`Evidence mirror layer:` section (its absence, not an empty section, means "no mirror
configured"; its presence with all-clean lines means "checked, found nothing," per the
design doc's own "opt-in, and not opted into" distinction). Then an `Evidence: <path>`
line, then a trailing `automat <version>` line. Mirror drift pushes the exit code to 2
alongside policy drift; an unreachable mirror pushes it to 3 alongside an unparseable
freshness date — both already covered by the exit-code taxonomy above, so no exit-code
change is needed to add this section, only a parser addition.

- **Policy layer has four distinct per-policy states, not a three-boolean combination:**
  not attached; attached but not carrying automat's owner tag (an explicit name
  collision, NOT automat's own drift — render this distinctly from a real mismatch, not
  as a variant of "differs"); attached with content differing from a fresh compile;
  matches. Plus a distinct empty case ("no preventive controls in this compile; nothing
  to attach") when the compile produced zero policies — render this as "nothing to
  check," not as an empty, ambiguous array.
- **Freshness has exactly three forms** (`internal/verify/freshness.go`), each carrying a
  subject and a date: current ("has not yet passed"), lapsed ("has passed... re-read..."),
  or unparseable (`review_by "<value>" is not a YYYY-MM-DD date`). Maps cleanly to
  `status: current|lapsed|unparseable` plus the `review_by` date value.
- **Structural honesty carries a fifth field the original response shape omitted:**
  `compiled from: <control-set-ids>` (e.g. `baseline-protection, cmmc-l1`) precedes the
  four counts — include it as `compiled_from: []string`.
- **Detective/procedural layers**: as of this document, `verify --help` still states
  these are not checked (a separate automat backlog slice may close this later). Do not
  invent fields for them now; extend the parser only once automat's real output changes.

Updated response shape, reflecting the verified report structure:

```json
{
  "status": "clean | drift | unknown",
  "exit_code": 0,
  "account_id": "222222222222",
  "target": "ou-exam-research1",
  "policy_layer": [
    {"name": "automat-cmmc-l1-0",
     "state": "not_attached | name_collision | content_differs | matches",
     "detail": "..."}
  ],
  "no_preventive_controls": false,
  "orphans": ["automat-old-profile-0 (p-xxxx)"],
  "freshness": {"status": "current | lapsed | unparseable", "review_by": "2027-01-01", "detail": "..."},
  "structural_honesty": {
    "compiled_from": ["baseline-protection", "cmmc-l1"],
    "total": 22, "enforced": 7, "documented": 6, "continuous": 9
  },
  "evidence_mirror": [
    {"bucket": "...", "checked": true, "drifted": false, "detail": "matches the local manifest"}
  ],
  "evidence_path": "evidence/222222222222.json",
  "tool_version": "...",
  "raw_output": "..."
}
```

`evidence_mirror` is `null`/omitted, not an empty array, when no mirror is configured for
this profile — the same "absent means not opted into, empty-but-present means checked
and clean" distinction the report text itself draws.

### `POST /api/v1/assess`

The one endpoint that's a `POST` rather than a `GET`, because `assess` takes enough
required parameters (an account id, a profile id, a scope statement, an output directory,
optionally a determinations file) that query-string encoding would be unwieldy, and
because it **writes local files** (`assessment-result.json`, `l1-summary.txt` under
`--out`, plus an evidence record) even though it makes no other AWS mutation — this is
"read-only against AWS," not "makes no local write," and `POST` reflects that honestly
even though nothing in AWS itself changes.

Invokes `automat assess --account <id> --profile cmmc-l1 --scope-statement "<text>" --out
<dir> [--determinations <path>] [--evidence-dir <dir>] [--context <ctx>]`. `--profile`
accepts only `"cmmc-l1"` today (confirmed via `--help`) — Vitrine's own request validation
should refuse any other value with a clear message rather than let it round-trip through
a failed subprocess call. `--out` should be a Vitrine-managed directory, never a path the
caller supplies directly, since automat writes real files there and Vitrine should own
where those land on its own filesystem. **Lifecycle decision: write to
`<config.out_root>/<account_id>/<RFC3339-timestamp>/` and keep every run — do not prune.**
These files are the deliverable a CMMC assessor eventually reads; silent deletion is the
wrong default, and retention policy (if ever needed) is a manual, documented operator
step to add later, not something v1 builds speculatively.

Request body:

```json
{
  "account_id": "222222222222",
  "scope_statement": "this account is the sole compute environment for project X",
  "determinations_path": "optional/name/under/config.determinations_dir.json"
}
```

`determinations_path` resolves under a configured root the same way `--environment-profile`
does for `verify` — see "Filesystem paths accepted from HTTP requests" below; it is never
an absolute or caller-controlled path.

Response shape: automat's own `assessment-result.json` is real, stable JSON
(`internal/assess/result.go`'s `Result` type — `schema_version`, `rendered_at`,
`tool_version`, `account`, `profile`, `artifact`, `determinations`, `objectives[]`,
`l1_summary`, `policy_caveat`) — **Vitrine should return this file's content directly**,
parsed as JSON and re-served, not re-derived from prose, since it already IS the
structured wire format this whole document argues for everywhere else. Read it from the
file `--out` wrote (`<out-dir>/assessment-result.json`), not from stdout — stdout's own
shape is simply `<outDir>\n`, then the full rendered summary text, then
`\nEvidence: <path>\n`, so `summary_text` and `evidence_path` are both trivially
parseable from stdout, but `result` should come from the JSON file directly rather than
being re-derived from anything printed:

```json
{
  "result": { "...": "the parsed contents of assessment-result.json, verbatim" },
  "summary_text": "the contents of l1-summary.txt",
  "evidence_path": "...",
  "raw_output": "..."
}
```

## Authentication on Vitrine's own HTTP surface

This document settled AWS-side auth thoroughly (see "Auth model" above) but did not
originally settle how a human admin authenticates to Vitrine's own HTTP surface — a real
gap, since an unauthenticated port that can enumerate an AWS org is not a default to pick
silently.

**Decision for v1: bind `127.0.0.1` only, by default, with no login of Vitrine's own.**
An admin reaches it via an SSH tunnel to the host Vitrine runs on. The bind address is
configurable (`config.listen_addr`), and Vitrine prints (and, if practical, refuses to
start without an explicit override flag for) a loud startup warning if configured to bind
to anything other than a loopback address — non-loopback is an explicit, deliberate
choice an operator has to opt into, not something that happens by leaving a default in
place. This defers real multi-user authentication (a shared bearer token, or trusting a
reverse-proxy-injected identity header) to whenever Vitrine actually needs to be
network-reachable — not built speculatively now, and not a decision this document makes
on behalf of that later need.

## Filesystem paths accepted from HTTP requests

`verify`'s `profile` parameter and `assess`'s `determinations_path` both name a file on
the host Vitrine runs on. Accepting an arbitrary caller-supplied path here is an
arbitrary-file-read probe surface on anything with a browser in front of it — a
materially different risk posture than a CLI flag, which only ever comes from an operator
who already has a shell on the machine.

**Decision: two configured root directories — `config.profiles_dir` and
`config.determinations_dir`.** The API accepts only a bare name or a relative path that
resolves under the configured root; both `..`-style traversal and a symlink that escapes
the root are rejected before the path is ever handed to automat as a flag value. This is
the same posture automat's own `internal/safeio` package holds for confined reads on its
own side of the boundary — applied here on Vitrine's side of an HTTP-facing boundary,
where the calling party is far less trusted than an operator's own shell. This is
slightly less flexible than the CLI (an operator can no longer point at an arbitrary path
anywhere on disk), which is the correct trade for something reachable over HTTP.

## Concurrent evidence writes

`verify` and `assess` each append to a hash-chained, per-account evidence manifest.
automat's own design assumes one operator, one invocation at a time; a web backend can
receive two simultaneous requests against the same account (two browser tabs, two admins,
a double-click). Two concurrent `verify` runs against the same account risk interleaving
writes to the same manifest file.

**Decision: a per-account-id mutex held around every evidence-writing invocation**
(`verify`, `assess` — not `preflight`/`list`, which write no evidence), plus a global cap
on the number of concurrent automat subprocesses Vitrine will run at once. Cheap
insurance, worth building in v1 rather than deferred — the failure mode it prevents
(a corrupted or misordered hash chain) is exactly the kind of durable-audit-trail damage
this whole tool exists to avoid, and the fix is a straightforward `sync.Mutex` keyed by
account id, not a redesign.

## `internal/runner`: the one piece every endpoint shares

A single function, roughly:

```go
type Invocation struct {
    Args    []string      // e.g. []string{"preflight", "--context", "sandbox"}
    Timeout time.Duration  // bounded; see per-command guidance below
}

type Result struct {
    ExitCode int
    Stdout   string
    Stderr   string
    TimedOut bool
}

func Run(ctx context.Context, binPath, workDir string, inv Invocation) (*Result, error)
```

Implementation notes:

- Use `exec.CommandContext` with a `context.WithTimeout` derived from `Invocation.Timeout`
  — never an unbounded run. Suggested starting timeouts: `preflight`/`list`/`verify` 30s
  (all read-only, bounded AWS calls); `assess` 30s (one STS call plus local rendering).
  None of v1's four commands ever calls the multi-minute-latency operations (`CreateAccount`
  polling, conformance-pack deployment) that motivated the `--resume` discussion above —
  that discussion matters starting in version 2, when `vend` enters scope, not for v1.
- Capture stdout and stderr **separately**. automat's own convention (confirmed across
  every command read above) is: the report/plan goes to stdout, warnings and `evidence:
  ...` confirmation lines also go to stdout for some commands, actual errors go to stderr
  via cobra's own error path. Preserve both in the response (`raw_output` above should be
  stdout; surface stderr as a distinct field on any error response) rather than merging
  them, so a caller can distinguish "here is the report, with a warning" from "here is why
  it failed."
- Never pass `AWS_PROFILE`, region, or any credential material as a command-line
  argument. automat resolves credentials from its own environment/config the same way the
  AWS CLI does; Vitrine's job is to make sure the **process environment** the subprocess
  inherits already carries whatever `AWS_PROFILE`/`AWS_REGION`/SSO cache location it
  needs (per the "one fixed backend identity" decision above), not to smuggle a secret
  through argv, where it would be visible to anything that can read `/proc/<pid>/cmdline`
  or an OS process listing.
- On a non-zero exit, still parse what's on stdout (some commands print a full report
  and then return a nonzero exit purely to encode "drift found," not "the command
  crashed" — `verify`'s exit 2 is exactly this shape) — do not treat "exit code != 0" as
  synonymous with "no usable output."

## Health/readiness endpoint

`GET /api/v1/health` — Vitrine's own liveness check, not an automat wrapper: confirms the
configured `automat` binary path exists and is executable (e.g. `automat version` runs
and returns 0), and that the configured working directory is readable. This is the first
thing to build and the first thing a coding agent should get green before wiring any of
the four real endpoints — it validates the whole subprocess-invocation plumbing against
the simplest possible case.

## Frontend (v1)

**Settled: no framework, no build step.** A single `index.html`, one vanilla-JS file, one
CSS file, `go:embed`-ed directly into the `vitrine` binary — four tabbed panels, one per
endpoint. Each panel is a simple form (where an endpoint takes parameters) plus a
rendered response: structured fields where parsed successfully, `raw_output` shown
verbatim underneath always, so nothing is ever hidden by a parsing gap. No npm, no
separate frontend deployment artifact — the whole thing ships as part of the one Go
binary.

## Verification limits for v1's handoff

There is no live AWS sandbox org available to whoever builds this. **This is an accepted
limit for v1, not a blocker**, for the same reason automat's own CLAUDE.md rule 1 draws a
hard line against live AWS calls in ordinary tests: handing a second, unaudited codebase
live credentials against a real org would extend that org's blast radius for no good
reason at this stage. The bar for v1's own test suite: `internal/runner` tested against a
fake executable (never the real `automat` binary in a unit test); `internal/parse` tested
against automat's own real golden fixtures
(`cmd/automat/testdata/golden/verify/*.txt` and equivalent captured output for the other
three commands) and against `Report.String()`/`renderListReport`'s actual source, not
hand-invented sample text; `/api/v1/health` proven against a real, locally-built
`automat` binary (`go build ./cmd/automat`), since that needs no AWS credentials at all.
A live end-to-end pass against a real sandbox org is a separate, manual, later step —
matching the same deferred shape automat's own `docs/smoke.md`/`make smoke` checklist
takes for automat itself — not something v1's build or its automated tests need to cover.

## Version control

`git init` the repository at the start, and commit incrementally as each build-checklist
step below lands — conventional-commit style (`feat:`, `fix:`, `test:`, `docs:`),
matching automat's own convention, so anyone moving between the two repos reads a
consistent history.

## Build checklist for a first implementer (human or agent)

In order, each step buildable and testable before the next:

1. Scaffold the repo per "Repository and module" above. `go.mod`, empty `cmd/vitrine/main.go`
   that starts an `http.Server` with only `/api/v1/health` wired. First commit.
2. Build `internal/runner` per its section above, with unit tests using a **fake
   executable** (a tiny shell script or Go test-helper binary standing in for `automat`)
   rather than the real binary — mirrors automat's own "hand-rolled fakes, no live calls in
   tests" discipline (CLAUDE.md rule 1), applied here to Vitrine's own test suite.
3. Wire `/api/v1/health` for real against a configured automat binary path; confirm it
   returns healthy against a real, locally built `automat` binary (`go build ./cmd/automat`
   in the automat repo, point Vitrine's config at the resulting binary). This is the one
   piece of "verification limits" above that IS provable without a sandbox org — prove it.
4. Build the confined-path helper (see "Filesystem paths accepted from HTTP requests")
   and the per-account mutex/concurrency cap (see "Concurrent evidence writes") as
   shared, independently-tested pieces before wiring them into any endpoint — both are
   used by more than one endpoint and are easiest to get right in isolation.
5. Build `internal/parse/preflight.go` and `GET /api/v1/preflight`, tested against
   **real captured `automat preflight` output** or hand-written fixture text matching the
   real report format confirmed in this document's own "Full current CLI surface"
   verification — not against invented sample text.
6. Repeat step 5 for `list`, `verify`, `assess` in that order — `assess` last since its
   response is the simplest (re-serve real JSON, no prose parsing at all) and benefits
   from having the runner/parse patterns already proven on the harder three. Wire the
   per-account mutex from step 4 into `verify` and `assess` specifically (the two
   evidence-writing endpoints), and the confined-path helper into `verify`'s `profile`
   parameter and `assess`'s `determinations_path`.
7. Build the four frontend panels (`go:embed`-ed, per "Frontend (v1)" above) against the
   now-working API.
8. Add the loopback-only bind default and the non-loopback startup warning (see
   "Authentication on Vitrine's own HTTP surface").
9. Write a top-level `README.md` stating plainly, for anyone who finds this repo without
   this design doc: what Vitrine is, that it shells out to a separately-installed
   `automat` binary rather than vendoring or reimplementing any of it, and a link back to
   this document (`automat`'s own `docs/vitrine-design.md`) as the design record.

## What this document does not do (restated for version 2+)

It does not design version 2 (`vend`) or version 3 (`reclaim`) in this level of detail —
"Build order" above states their sequencing and the two open design questions (plan/apply
re-diffing, per-admin credential brokering) they'll need to resolve, but the exact
endpoint/request shapes for mutating actions should be designed against version 1's real
experience, not speculated now.
