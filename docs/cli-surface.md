# CLI surface vs. DESIGN §13

The Phase 1 review ratified the CLI surface AUDIT-1 listed **on the condition that it
matches DESIGN §13**, and asked that any deviation be flagged as its own line item, now
and in future audits. This page is that reconciliation. It is kept current per phase;
an audit that says "the surface matches §13" without this page behind it is a claim
outrunning its evidence.

Everything below was read from the built binary (`automat <cmd> --help`) and from
`internal/config`'s struct tags, not from the design document or from AUDIT-1's list.
That direction matters: checking §13 against a summary of the code would find nothing.

## Commands

§13 lists eleven command forms. Phase 1 shipped three plus two cobra built-ins; Phase 2
adds `init` and `vend`.

| §13 command | State | Where |
|---|---|---|
| `automat login` | **Shipped** | `cmd/automat/login.go` |
| `automat preflight` | **Shipped** | `cmd/automat/preflight.go` |
| `automat setup --request` | **Shipped** | `cmd/automat/setup.go` |
| `automat setup` (MANAGEMENT) | **Shipped** | `cmd/automat/setup.go`'s `runSetupApply` |
| `automat init` | **Shipped** — see D2 | `cmd/automat/init.go` |
| `automat vend` | **Shipped** — steps 1–4 and 6 only; see D3 | `cmd/automat/vend.go` |
| `automat compile` | **Not a subcommand — see below** | `gen/catalog`, maintainer tooling |
| `automat verify` | **Shipped** — policy, freshness, and structural-honesty layers only, `--account` not `--account \| --ou`; see D4 | `cmd/automat/verify.go` |
| `automat list` | **Shipped** — no tag-based filtering; see D5 | `cmd/automat/list.go` |
| `automat reclaim` | **Shipped** — `--account`/`--dry-run`/`--yes`, unconditional `--yes`; see D9 | `cmd/automat/reclaim.go` |

Also present and not in §13: `version`, `help`, `completion`. `version` is a
deliberate addition (a tool that stamps its version into generated artifacts must be
able to state it); `help` and `completion` are cobra's, registered automatically.
None takes a flag with security meaning.

**No command in §13 is missing for a reason other than not being built yet, and no
shipped command is absent from §13.**

## Flags

| Scope | Flags | In §13? |
|---|---|---|
| Persistent | `--config`, `--context` | Implied by §13's config paragraph |
| `login` | `--start-url`, `--sso-region` | Implied by "credential-profile-aware" / SSO |
| `preflight` | none | — |
| `setup` | `--request`, `--dry-run`, `--force`, `--out`, `--org`, `--ou`, `--ou-name`, `--management-account`, `--member-account`, `--member-role-arn`, `--vendor-role-name`, `--contact` | §13 names none of these |
| `init` | `--ou-name`, `--dry-run`, `--yes` | §13 names none of these |
| `vend` | `--environment-profile`, `--name`, `--email`, `--ou`, `--resume`, `--override`, `--dry-run` | §13 line 100 names `--profile`; see the naming note below and D6 for `--override` |
| `verify` | `--account`, `--environment-profile`, `--override` | §13 names `--account \| --ou`; see D4 and D6 |
| `list` | `--ou`, `--evidence-dir` | §13 names none of these; see D5 |

§13 specifies commands, not flags, so a flag cannot contradict it by existing. The two
with security semantics remain the ones AUDIT-1 flagged: `--force` (discards a hand
edit — the mechanism an operator uses to apply a correction central IT asked for) and
`--out` (a path, hence the control-byte refusal and the `os.Root` work in
`internal/bundle/write.go`).

`init --yes` joins them, and it is the CLAUDE.md rule 5 plumbing rather than a
convenience: creating an organization is the only act in this command AWS provides no
call to undo, so it is the only step gated. The gate is keyed off the **printed plan**
(`plansOrgCreation`) rather than off a boolean threaded out of the step function, so the
gate and the operator read the same list — a gate consulting a different source could
refuse for a reason the plan does not mention, or wave through something it does. Every
other step is create-or-verify, so `--yes` is not required for them and an operator does
not learn to pass it reflexively.

### One flag was removed since AUDIT-1: `--external-id`

AUDIT-1's ratified list included `setup --external-id`. It is gone, as part of
inverting ExternalId generation (Phase 1 review item 6). **This is not a §13
deviation, in either direction:**

- §13's command list does not mention it, so removing it cannot diverge from the list.
- §13's config paragraph says *"Never store secrets; lean on the AWS credential chain
  and OS keychain if anything must persist."* The flag existed to put a secret into a
  generated file. Removing it moves the code toward that sentence, not away from it.

Recorded here rather than left as a silent shrinkage of a ratified surface: the review
ratified a list that has since changed, and the change should be visible without
diffing two audits.

## Config keys

§13 names four per-org context keys. All four exist, with these TOML names
(`internal/config/config.go`):

| §13 | Key |
|---|---|
| vendor role ARN | `vendor_role_arn` |
| ExternalId ref | `external_id_ref` |
| OU id | `ou` |
| email pattern | `email_pattern` |

Plus `org`, `region`, `profile`, `sso_start_url`, `sso_region`, and the top-level
`context` / `default_context`. Additions, not substitutions — `region` and `profile`
are what "credential-profile-aware" in §13's `login` line requires, and the two `sso_*`
keys are what let `login` work without re-typing a start URL.

**`profile` here is the AWS credential profile and nothing else.** It is the fourth
sense of the word DESIGN §7a enumerates, and the one that cannot be renamed because it
is AWS-standard in every other tool the operator uses. `vend`'s input document is the
**environment profile**, reached by `--environment-profile`; the two must never share a
flag name. §13 line 100 originally spelled the vend input `--profile`, which would have
put both meanings on one flag in one tool — DESIGN §7a now resolves that, and this row
is the CLI-side half of the same fix.

**§13's "never store secrets" holds literally.** `external_id_ref` stores a *reference*
(`env:VAR`, `file:/path`), resolved at assume time by `config.ResolveExternalID` and
never written back. No config key holds a credential. This is asserted, not just
intended: `TestPreflightNeverPrintsTheExternalID` covers the CLI's output paths.

## Deviations

Three. D1 was found by writing this page; D2 was found by building `init` and is a
deviation automat is keeping; D3 was found by building `vend` and is a shortfall
automat is disclosing rather than keeping.

### D1 — The CLI named the wrong phase for `setup` without `--request`. FIXED

`automat setup` in a management account is not implemented, and the error told the
operator it "arrives in Phase 2". ROADMAP.md schedules it in **Phase 3**: *"`setup`
(MANAGEMENT side): apply delegation policy + create vendor role for a named member
account."* Phase 2 is `init` and `vend`.

Not a cosmetic slip. That string is a promise made to an operator who is blocked, in
the one place they will look — and it named a release that will not contain what they
are waiting for. It appeared in three operator-facing spots (the `Long` help, the
refusal message, the command's doc comment) plus `docs/phase-1.md`, all fixed, with
the test now asserting the phase *number* rather than the word "Phase" so the next
drift fails loudly. CLAUDE.md's rule — when design and code disagree, flag it rather
than reinterpret — puts ROADMAP as the sequencing authority, so the code was wrong.

### D2 — `automat init` runs in MANAGEMENT as well as STANDALONE. RESOLVED — §13 amended

§13 wrote the command as **"STANDALONE only: CreateOrganization(ALL) + research OU"**.
As built, `init` permits STANDALONE **and** MANAGEMENT, and refuses MEMBER. **Resolved by
amending §13's line** rather than by re-ratifying the deviation — DESIGN.md now names both
states `init` permits and states the MEMBER refusal, so §13 and the shipped command agree.
This section stays as the reasoning behind that line, since DESIGN.md states the decision
but not why.

Two reasons, and the second is a security argument rather than an ergonomic one.

**"STANDALONE only" and CLAUDE.md rule 4 cannot both hold literally.** Rule 4 requires
every mutating command to be safely re-runnable. After `init` succeeds the account is no
longer standalone — it is the management account of the organization it just created — so
the idempotent second run is *necessarily* from MANAGEMENT. A command that refused it
would be a mutating command with no safe second run. `TestInitRunsTwiceWithNoSecondChange`
is that second run, and it passes no `--yes`, because by then nothing irreversible is left
in the plan.

**An operator who created their organization in the console was never STANDALONE to
automat, and is the operator most likely to need this command.** Their root may have the
service control policy type DISABLED — the state where `CreatePolicy` succeeds,
`AttachPolicy` succeeds, and nothing is enforced (DESIGN §3 fact 8). `init` is what fixes
that. Refusing to run it there would send exactly that operator to the console for the one
call deciding whether every control automat later attaches enforces anything.
`TestInitAdoptsAnOrganizationCreatedInTheConsole` fixes that shape — all features on, root
reporting no policy types — and asserts `init` enables it and calls `CreateOrganization`
zero times.

**MEMBER is refused, and it is the state §13's "only" is really about.** A member account
cannot create an organization, cannot enable a policy type on a root it does not own, and
cannot create a root-level OU; AWS delegates none of the three. The refusal says all of
that and points at `automat setup --request`, and it arrives having mutated nothing —
`EnsureOrganization` reads before it writes and creates only when the account is in no
organization at all, so the check is reached with nothing done.

Also worth stating because it is invisible from the flag list: **step order inside `init`
is load-bearing.** The policy type is enabled *before* the OU is created, so a half-failed
init leaves a root that enforces policy and no OU, rather than an OU that policies attach
to and silently do not enforce. Of the two partial states, the second is the one that looks
finished. `TestInitReportsWhatItDidBeforeFailing` drives exactly that half-failure and
asserts the partial-progress report names the step that did succeed.

### D3 — `automat vend` performs DESIGN §7 steps 1–4 and 6, not step 5. RESOLVED — §13 amended, step 5 deferred

§13 writes the command as vending an account with its baseline applied. As built, `vend`
does step 1 (resolve the environment profile to a compiled control set), step 2 (create
the account), step 3 (move it into the target OU), step 4 (ensure the OU's service
control policies), and step 6 (write the evidence manifest and print the birth
certificate). It does **not** do step 5, the in-child baseline work: no Config recorder
or delivery channel, no conformance pack, no opt-in region enablement, no attestation
stubs, and no in-account automation role.

The reason is capability, not scheduling: there is no `internal/baseline` package and no
Config, Account Management, or IAM-write interface in `internal/awsapi`, so this binary
cannot assume into a vended account at all.

**Listed as a deviation rather than as ROADMAP progress because a vended account looks
finished.** Its preventive controls are real and attached; nothing in it is being
watched. An operator reading only a green run would have no way to tell. So the shortfall
is stated in three places the operator cannot miss, and each is asserted by a test:

- the **plan and the applied output** carry two `RecordUnknown` lines naming what was
  not performed and why re-running will not change it;
- the **evidence manifest** carries a `baseline-apply` record with outcome `parked` — the
  accurate outcome, since the work is genuinely outstanding. A manifest that was merely
  silent would read as a baseline that succeeded, which is the single most damaging thing
  a compliance artifact can do;
- the **birth certificate** prints `detective baseline: NOT APPLIED`.

Two smaller shortfalls of the same kind, both reported the same way rather than dropped:

- **Three of DESIGN §14's five account tags are not written.** `automat:vended-by` and
  `automat:ou` are set at creation, which is the only moment they can be — a tag a
  condition reads must not be writable by the principal the condition constrains. The
  other three (`automat:artifact-id`, `automat:artifact-sha256`, `automat:version`) are
  the post-create mutable set, and nothing in `internal/org` tags an account after
  creation.

  **`automat:ou` names the delegated OU, not the OU the account is placed in.** The two
  are the same value until an environment profile sets `placement.ou_path`, and DESIGN
  §14's one-line tag list does not say which one is meant — so it is said here. The
  vendor role's `CreateAccount` grant renders the condition as a literal
  (`StringEquals aws:RequestTag/automat:ou: '<target_ou>'`), fixed when the bundle was
  generated, and the grant cannot be widened to the subtree: OU ids are opaque, so no
  `StringLike` pattern expresses "below this OU". The tag would also be *wrong* as a
  placement record — it is immutable after creation while `MoveAccount` is permitted
  anywhere in the subtree, so a value naming the leaf OU is stale after the first
  permitted move. It answers "under which delegation was this vended"; `ListParents`
  answers "where is it now", and where the account actually landed is on the birth
  certificate and in the evidence manifest. AUDIT-2 found vend tagging with the resolved
  placement OU, which is `AccessDeniedException` in a real organization.
- **`account.role_name` and `account.iam_user_access_to_billing` in the environment
  profile do not reach AWS.** `org.EnsureAccount` sends only `AccountName`, `Email`, and
  `Tags`. Two document fields that validate and then have no effect, which is worth an
  audit line of its own.

**Resolved by amending §13's line**, not by shipping step 5 or by re-ratifying: DESIGN.md's
`vend` line now names steps 1–4 and 6 explicitly and states that step 5 is not yet
implemented, pointing here for the shortfall's disclosure. The instruction this resolution
honors is the one AUDIT-2 wrote — step 5 not shipping must not quietly become the
*definition* of vending, so the amendment says "not yet implemented," not "vend does not
include this." Everything above about how the shortfall is disclosed and the two smaller
ones alongside it is unchanged by the resolution.

### D4 — `automat verify` takes `--account`, not `--account | --ou`. Checks all four layers as of ROADMAP.md's "internal/baseline, slices 2-9" item 9. RESOLVED — §13 amended

§12 and §13 both write the flag as `--account <id> | --ou <id>` and describe four
verification layers: policy, detective, procedural, freshness. `verify` accepts only
`--account <id>`, for a reason that does not go away as the tool grows; the layer
count, on the other hand, was a temporary capability gap and is now closed.

**The flag cannot be built as written, and this half of D4 is permanent.**
Baseline-protection — compiled into every vend, never optional — exempts automat's
in-account automation role from its Deny statements, and that exemption is
rendered as the role's ARN (`internal/compilesets`'s `renderCondition`), which
embeds the account id. An OU with no account in hand has no ARN to render, so
`compilesets.Pack` cannot produce the expected policy set for an OU-only check.
`--account` resolves its own parent OU via `ListParents` and checks the policies
attached there; a bare `--ou` flag is not offered rather than offered and silently
wrong.

**The two-layers-not-four half is now closed.** When this page was first written,
the detective layer (Config recorder, conformance pack) and the procedural layer
(attestation stubs) both checked something DESIGN §7 step 5 — `internal/baseline`
— was meant to install, and that package did not exist yet, so `verify` disclosed
the gap in its own output rather than claiming to check a recorder that was never
created. `internal/baseline` now exists in full (its own package doc), and
`internal/verify.CheckDetective`/`CheckProcedural` (ROADMAP.md's "internal/
baseline, slices 2-9" item 9) check exactly what it installs: the recorder's
presence, recording state, and configuration; the delivery channel's bucket; the
conformance pack's deployed parameters; and each attestation stub's presence,
emptiness, and staleness against its declared frequency. Both layers still follow
the "opt-in, and not opted into" discipline the mirror layer established: a
profile that never asked for a piece reports it as not configured, not as a
failure. A detective/procedural check that cannot complete at all (the in-child
session cannot be assumed, or a read is denied) is reported as unknown, landing
`verify`'s exit code at `exitVerifyUnknown`, never `exitVerifyDrift` — a denial is
not evidence that the account drifted.

Explicitly NOT built by this closure: per-resource compliance findings from the
conformance pack's own AWS Config evaluation (DESIGN §12's "report current
compliance findings... present it as findings, distinct from baseline drift").
This slice checks that the pack is deployed and its parameters match a fresh
compile — it does not read what AWS Config's own rule evaluations currently say
about individual resources. That remains a larger, unscoped increment.

**Resolved by amending §13's line** to read all four layers again now that all
four are checkable, and by updating this page rather than leaving the "not yet
implemented" framing in place after the gap it described had closed.

### D5 — `automat list` has no tag-based filtering, and its two flags are not in §13. RESOLVED — §13 amended

§13 describes `list` as "vended accounts (by tags), parked accounts, OUs" and names no
flags. As built, `list` walks the OU tree rooted at `--ou` (or the config file's `ou`, or
the organization root if neither is set) and lists every account under it regardless of
tag, plus every account a local evidence manifest under `--evidence-dir` records as
parked.

**`list` is not read-only by construction the way `verify` is (AUDIT-4 H3).** The tree walk
travels `awsapi.OrgVendAPI` — `vend`'s own write-carrying client — brokered through the
vendor role in the MEMBER state, because an inventory read through a different credential
than `vend` uses would see a different view. `OrgVendAPI` carries `CreateAccount`,
`MoveAccount`, `CreateOrganizationalUnit`, and `TagResource`; `list` calls none of them, but
nothing in the type system stops it the way `OrgVerifyAPI`'s absence of a write method stops
`verify`. A narrow read-only, MEMBER-brokered walk interface is the correct fix and is not
yet built (AUDIT-4 H3's recommended follow-up); `list --help` states the gap honestly in the
meantime.

**Tag-based filtering is not available because the read grant does not exist.**
`awsapi.OrgVendAPI` has no `ListTagsForResource` for account resources — the same
absence `docs/open-questions.md` Q19 already documents, there for a different reason
(adopting an account by email cannot be corroborated by its `automat:vended-by` tag).
The published `vendor-role.cfn.yaml`/`vendor-role.tf` do not grant
`organizations:ListTagsForResource` on account ARNs, so even a native (MANAGEMENT-state)
caller reading through the same interface a MEMBER-state caller would use gets no tags
back — widening the interface for one state and not the other would mean `list` behaves
differently depending on where it runs, which is worse than the gap it would close. The
fix is the same one Q19 names for its own problem: widen the bundle, which is a version
event for a published, reviewed document and is not done casually.

**`--ou` and `--evidence-dir` exist because `list` has no other way to find its two data
sources.** `--ou` matches `vend`'s own override pattern (config file default, CLI
override) for the traversal root. `--evidence-dir` exists because `list` has no
`--environment-profile` — unlike `vend` and `verify`, which read a single profile's
`baseline.evidence.local_dir`, `list` inventories accounts as a group and needs a
directory to scan before it knows which profiles, if any, vended what is in it.

**Resolved by amending §13's line**: DESIGN.md's `list` line now names `--ou` and
`--evidence-dir` and states that tag-based filtering is not available, pointing here for
the reasoning.

### D6 — `vend` and `verify` gain `--override`, not named in §13. RESOLVED — §13 amended

§9 states the remedy for a Config-rule parameter conflict the union cannot resolve on its
own: "hard error with a conflict report demanding explicit resolution (an override file)."
It names the mechanism without naming a flag, a file format, or which commands read one.

**`--override <file>` on both `vend` and `verify`**, a JSON document naming each resolved
`{rule, parameter, value}` triple (`internal/compilesets.Overrides`/`LoadOverrides`).
Unpublished — no `schema/` entry, per rule 6's proportionality: this is a small,
operator-local file with no cross-institution provenance requirement, unlike an
environment profile or a control artifact. `MergeWithOverrides`/`CombineWithOverrides`/
`FromArtifactWithOverrides` are new entry points beside `Merge`/`Combine`/`FromArtifact`
rather than a fourth parameter on the existing ones, which had already changed shape once
this phase (gaining an error return) and every caller — production and test — had just
been updated for that.

`verify` needs the same flag as `vend` for the same reason it needs `--environment-profile`
at all: it recompiles the expected policy set from scratch rather than reading a prior
evidence record, so an account vended with an override needs the same override replayed at
verify time or the recompiled expectation will not be the one actually attached — a false
drift report, not a missing feature.

**Resolved by amending §13's line**: DESIGN.md's `vend` and `verify` lines both now name
`--override`, pointing here for the reasoning.

### D7 — `automat assess` is not in an earlier revision of §13. RESOLVED — §13 amended

`docs/assessment-reporting.md` is the design authority for `assess`, approved as scope
before any of it was built, and its own closing section names §13 as needing the addition
"when it ships" — the same ratification condition the Phase 1 review already established
for a command absent from an earlier revision of the list (D2, D3, D4, D5, D6 above all
follow it). This is that addition landing.

**Only Stage 3 ships**: `--profile` accepts only `cmmc-l1`. Stages 1 and 2 — the 800-171A
objective worksheet and DFARS score arithmetic — need a weight table transcribed twice,
independently, and diffed before commit (`docs/open-questions.md` Q10); that is real
off-computer work, not a coding task, and is not attempted here.

**Read-only beyond one `sts:GetCallerIdentity` call**, the same shape `verify` has: no
`--yes`, because `assess` mutates nothing in AWS. It writes locally — the
`assessment-result-v1` document and its rendered summary into `--out`, and an `OpAssess`
evidence record — which is why it needs a client at all despite reading nothing else from
the account.

**This build's honest limit, stated in the command's own `--help` and in every rendered
summary**: `catalogs/cmmc-l1.json` carries no SCP fragments, and no AWS Config read
interface exists anywhere in `internal/awsapi`. So `assess` contributes zero machine
evidence for any of the fifteen L1 practices today — every objective's evidence class is
`operator`, and with no `--determinations` file, every practice renders NOT MET rather
than staying silent (CMMC Level 1 permits no partial credit and no plan of action, so
silence is a fail with a work list, not a pending state). The rendered summary states this
disclosure once, at the document level, rather than leaving a reader to infer it from an
all-`operator` table.

**Resolved by amending §13's line**: DESIGN.md's `automat assess` line names the flag
surface and the current scope limit, pointing here for the reasoning.

### D8 — `automat assess` gains `--evidence-dir`, not named when it shipped. RESOLVED — §13 amended

AUDIT-5 found `writeAssessEvidence` hardcoded `envprofile.DefaultEvidenceDir` ("evidence")
with no way to override it. `vend` and `verify` both resolve the directory they write into
from the environment profile's own `baseline.evidence.local_dir` — the field exists
precisely so an operator can put evidence somewhere other than the default. `assess` takes
no `--environment-profile` at all (the account is named directly by `--account`, the same
reason `list` has no `--environment-profile` either, D5 above), so it had no way to learn a
customized directory and would file its `OpAssess` record into the default one regardless —
a second, disconnected manifest for an account whose real chain lives elsewhere, discovered
only when a reviewer went looking for the assess record beside the vend and verify records
and did not find it.

**`--evidence-dir`, matching `list`'s own flag exactly**: same name, same default
(`envprofile.DefaultEvidenceDir`), same reasoning — a command with no profile to read
`local_dir` out of needs the directory named directly. An operator running `assess` against
an account vended under a profile that customized `baseline.evidence.local_dir` must pass
the same value here, or the OpAssess record lands in the wrong file.

**Resolved by amending §13's line**: DESIGN.md's `automat assess` line now names
`--evidence-dir` alongside its other flags, pointing here for the reasoning.

### D9 — `automat reclaim` is not in an earlier revision of §13, and needs `--evidence-dir` from day one. RESOLVED — §13 amended

`docs/reclaim-design.md` is the design authority, settled before any code was written the
same way `docs/assessment-reporting.md` settled `assess`'s scope, and its own closing
section named §13 as needing the addition when it shipped — the same ratification
condition D2 through D8 above all follow.

**`--account`, `--dry-run`, `--yes`, `--evidence-dir`.** `--evidence-dir` is present from
the first commit rather than added after an audit found it missing the way D8 had to for
`assess`: `reclaim` takes no `--environment-profile` either (the account is named directly,
same reasoning D5 gives for `list`), so it has no way to learn a customized
`baseline.evidence.local_dir` and needs the flag to avoid filing its `OpReclaim` record into
a manifest disconnected from the one `vend` and `verify` already wrote to.

**`--yes` is unconditional**, not gated on one step within the plan the way `init`'s
org-creation gate is (`plansOrgCreation`). Every `reclaim` apply closes an account; there is
no non-destructive half of this command to distinguish.

**Resolved by amending §13's line**: DESIGN.md's `automat reclaim` line now names all four
flags and the unconditional-`--yes` decision, pointing here for the reasoning.

### `automat compile`. RESOLVED — §13 and ROADMAP amended, `gen/catalog` is not a deviation

§13 listed `automat compile`, and ROADMAP Phase 0's accept criterion wrote it as
`automat compile --sets cmmc-l1 --out a.json`. What exists is `gen/catalog`, a separate
maintainer-time binary with `-out`, `-sources`, and `-check`.

**Resolved by amending §13 and ROADMAP** rather than by shipping a subcommand: DESIGN.md's
§13 now states plainly that there is no `automat compile` subcommand and that union/compile
is maintainer tooling, run against curated sources and vendored into `catalogs/` for the CLI
to read. This section stays as the reasoning behind that line.

The compiler that produces the vendored catalogs is maintainer tooling by design —
`gen/catalog/doc.go` states that it is "the only thing that ever reads an upstream catalog
format", running at maintainer time while automat itself reads only the compiled output.
Phase 0 is about the compiled artifact being a versioned contract, not about exposing the
compiler to an operator. Whether an operator-facing `compile` is ever wanted (composing a
control set from vendored catalogs, using §9's union semantics directly) is a real question
this resolution does not foreclose — it says nothing ships one *today*, not that nothing
ever will. Shipping one later is a CLI surface change and needs its own ask.

ROADMAP.md's Phase 0 accept criterion, which named `automat compile --sets cmmc-l1 --out
a.json`, is amended to name `gen/catalog`'s actual invocation instead, so the accept
criterion states what running it produces rather than a command that does not exist.
