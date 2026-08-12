# `automat hold` — design

**Status: design authority for a Phase 5 capability. Not yet built.** Settled the same way
`docs/reclaim-design.md` settled `reclaim` before any code was written: this page follows
that page's structure and rigor, because `hold` is being added into the exact space
`reclaim`'s own design left open — a third lifecycle state, not a variant of the second.

## The lifecycle decision

A vended account has, as of this design, **three** lifecycle states rather than two:

1. **Durable-active** — the ordinary, default state `docs/reclaim-design.md` already
   describes: a long-lived, audited research-computing asset, governed by whatever the
   compiled artifact attaches, with no expectation that anything about it is temporary.
2. **Reclaimed-closed** — `reclaim`'s own state: the account has been closed via
   `CloseAccount`, is `SUSPENDED`, reinstatable only through AWS Support inside a 90-day
   grace window, and is understood to be permanently done once that window elapses.
3. **Held** — this design's new state: the account stays **ACTIVE**, fully billable, and
   fully data-intact, but is deliberately locked down — its own SCP tightened to deny
   everything but a narrow read/inspect allowlist, with no exemptions to speak of — for a
   stated compliance reason. automat **never calls `CloseAccount`** on a held account. It is
   a live, reachable, audit-ready account that nobody is meant to actively use.

**Why a third state rather than a mode of `reclaim` or a flag on `vend`.** The maintainer's
own framing, taken as the settled premise here: "letting automat 'hold' accounts if they
need to for compliance reasons is better than closing them." Followed to its structured
choice: **hold = explicitly NOT reclaimed, kept ACTIVE with tightened SCPs.** The alternative
that was offered and explicitly *not* chosen — hold as a pure evidence-side marker with no
AWS-side change — is not this design. What ships is an AWS-side lockdown: a deny-all-but-read
SCP attached, and (per the analysis two sections down) no reachable way to revoke in-account
IAM user access from outside the account, so the SCP is the entire mechanism.

**What `hold` is for, stated as plainly as the maintainer's own framing allows.** `hold` exists
for the case a `reclaim` cannot serve: an account that must remain *intact and reachable* for
a compliance, audit, or legal-hold reason — the opposite of "we are done with this account."
`reclaim` answers "this account is permanently done and its data may go away with AWS's own
90-day-then-gone lifecycle." `hold` answers "this account's data and access must remain
exactly as they are, inspectable, for as long as the compliance reason lasts, and closing it
is not an option because closing risks exactly the loss `hold` exists to prevent." These are
not two ways of answering the same question. An operator who reaches for `hold` because they
want to reduce cost, free a quota slot, or "pause" an account nobody is using right now is
using the wrong command — see the mandatory quota section below for why, in detail.

**This does not change `reclaim`'s own model.** `reclaim` stays durable-by-default,
`--yes` unconditional, no ephemeral mode, detach-then-close ordering, no bulk operation —
every decision `docs/reclaim-design.md` already made stands untouched. `hold` is additive: a
new command, a new verb, a new evidence operation, sitting beside `reclaim` rather than
inside it or in front of it. Nothing about `reclaim`'s own gate, ordering, or scope changes
because `hold` now exists. An account may be held and later reclaimed (an operator decides
the compliance reason has lapsed and the account should finally close) — that is an ordinary
sequence of two independent commands, not a state transition either command has to know
about specially.

## What `hold` does, in order

### 1. Attach a hold-lockdown SCP, layered on top of what is already attached

**Authored as a new, distinct catalog, through the same catalog/compile pipeline every other
control set uses — not a hand-built one-off statement `internal/org` constructs directly.**
Weighed against `baseline-protection`'s own precedent and `reclaim`'s: `reclaim`'s
`DetachOwnedPolicies` needs no catalog because it detaches policies that already exist, using
metadata (`OwnerTagKey`) that has nothing to do with a policy's *content* — there is no new
Deny statement for `reclaim` to author, so there is nothing for a catalog entry to describe.
`hold` is the opposite case: it needs a genuinely new Deny statement — "deny everything except
a narrow read/inspect allowlist" — and that is exactly the kind of content
`catalogs/baseline-protection.json` and `cmmc-l1.json` already hold, authored the same way:
a curated JSON source under `gen/sources/`, compiled by a new `gen/catalog` target
(`compileHold`, alongside `compileBaseline`), producing a new vendored artifact — call it
`catalogs/hold-lockdown.json` — with the same `_comment`/`design_basis`/`extends_design`
discipline `baseline-protection` already enforces. Reasons this fits automat's architecture
better than a hand-built statement:

- **Reviewability.** A deny-all-but-read lockdown is exactly the kind of control a reviewer
  needs to be able to read in a diff, the same argument that put `baseline-protection`'s deny
  list in `gen/sources/baseline-protection.json` rather than in Go. A hand-built statement
  living inside `internal/org/hold.go` would be a control nobody outside this repository's Go
  source can review — the opposite of what a compliance-retention control should be.
- **Extensibility.** DESIGN §10's own reasoning for `baseline-protection` — "so L2-minded users
  can extend the deny list" — applies at least as strongly here: an institution may have its
  own idea of what "narrow read allowlist" should include (a specific audit role that must
  retain read access, say), and a catalog entry is the reviewable place to add that, the same
  way `exempt_principals` is for every other control set.
- **It is not `reclaim`'s shape.** `reclaim` detaches existing, already-reviewed policies; it
  never authors new Deny content, so it never needed the pipeline. `hold` authors new Deny
  content, so it needs exactly the pipeline that content-authoring already goes through.

**Layered on top of what is already attached — a new SCP added, nothing existing detached
first.** The task description flags the union-semantics angle and asks that it be checked
against `internal/compilesets`' actual monotonicity guarantees rather than merely asserted;
having done that:

- `internal/compilesets.Merge`'s governing law (DESIGN §9, restated in `compilesets/doc.go`)
  is *union of controls = intersection of permitted behavior*, and it is proven for
  concatenation of Deny statements without limit: "concatenation is inherently monotone and
  needs no argument" — adding a Deny statement to a policy can only deny more. A hold-lockdown
  Deny is exactly one more Deny statement narrowing what is already denied. It cannot widen
  anything `baseline-protection`, `cmmc-l1`, or an environment profile's own control sets
  already forbid, because Deny concatenation is monotone in that direction by construction.
- The narrower question — does `hold`'s statement, once *packed* alongside what is already
  attached, actually shrink what is permitted rather than accidentally *replacing* a
  stricter existing Deny with a looser merged one — is the packer's own job to get right, and
  it already has to: `mergeStatements` groups actions by their exemption-intersection value
  (`E(guard, action)`), so a hold statement carrying **no exemptions at all** on an action an
  existing statement already denies with no exemptions either simply lands in the same group
  and changes nothing observable; a hold statement adding a **new** action nothing else denies
  creates a new group, denying that action outright. Neither case can widen anything, because
  the merge only ever computes an intersection of exemption sets — adding a statement with an
  empty exemption set to any group can only shrink that group's permitted exemptions toward
  empty, never grow it.
- **Consequence for the attach step itself: this is `EnsurePolicySet`/`EnsurePolicy`, called
  with hold's SCP as one more entry in the specs slice — not a detach-then-replace.** No
  existing policy is detached. `reclaim`'s detach-then-close ordering has nothing to say here
  because nothing is being closed; `hold` is `vend`'s own `EnsurePolicySet` pattern, run once
  more, after the fact, against an account already vended: read the target's currently
  attached policies, ensure the hold policy exists with the right content, attach it if not
  already attached. This is exactly `internal/org.Ensurer`'s existing shape, not a new one.

**A quota consequence worth stating up front rather than discovering it at attach time.**
`compilesets.ReservedPolicySlots` already reserves two of the five per-target SCP slots (one
for central IT's own institutional policy, one for AWS's `FullAWSAccess`), leaving
`AvailablePolicySlots = 3` for everything automat attaches. A hold lockdown consumes one more
of those three. `hold`'s own plan step must read what is currently attached at the target
(the same `ListPoliciesForTarget` read `Reclaimer.attachedPolicies` already performs) and
refuse — at plan time, not at `AttachPolicy` time with the account already mid-lockdown — if
attaching one more automat-owned policy would exceed the target's slot budget, naming which
policies already occupy the other slots, the same discipline `attachmentQuota`
(`internal/org/policy.go`) already renders for the ordinary vend path.

### 2. In-account IAM lockout: investigated and rejected as unreachable from outside the account, so the SCP is the whole mechanism

The task's own framing asks whether "revoke user access" needs something beyond an SCP —
disabling console/API access for specific principals — and whether `internal/baseline`'s
`EnsureAutomationRole` pattern (an in-child action reached by assuming
`OrganizationAccountAccessRole`) is a usable template for it. Investigated and the answer is:
**no additional in-child step is added in this design**, for two independent reasons that
each would be sufficient alone:

- **An SCP already achieves "no principal in this account may act" without needing to touch
  IAM users or roles individually.** A Deny with no exemptions, condition-free, naming `"*"`
  as both action and resource, binds *every principal in the account, including the root
  user* (DESIGN §3 fact 7: "SCPs bind all principals in member accounts, including root
  users"). There is no IAM user, role, or federated identity an SCP of this shape does not
  already stop — deleting login profiles or detaching user policies one at a time would be
  strictly weaker than the SCP already in place (it would miss any credential — an access key,
  an assumed role from outside the account — the per-user approach did not enumerate) and
  strictly more invasive (it destroys IAM state inside the account that a later, legitimate
  reason to look at the account, or to release the hold, would then have to reconstruct).
  "Revoke user access" as an *outcome* is already what the SCP produces; there is no
  additional in-child action that produces more of that outcome without producing a worse
  side effect.
- **`EnsureAutomationRole`'s own pattern is unavailable for exactly the reason it is not
  wanted here.** That pattern reaches into the account by assuming
  `OrganizationAccountAccessRole` and calling in-child IAM (`iam:CreateRole`, `PutRolePolicy`,
  and so on) — but every one of those calls is itself a principal acting *inside* the account,
  which is precisely what a hold's own SCP, once attached, would deny to everyone including
  automat's own automation role (the same ordering hazard `internal/baseline`'s own doc
  comment already documents for `BP.IAM-1`, Q13). Sequencing an in-child IAM lockout *before*
  attaching the SCP would work mechanically, but it would mean `hold` needs its own assumed
  session into the child account, its own ordering constraint, and its own explanation for why
  it is safe to run — for a step that (per the point above) adds no denial the SCP was not
  already going to apply. The complexity is not worth a capability the SCP does not lack.

**Conclusion: an SCP alone suffices. No `internal/baseline`-style in-child step is added for
`hold`.** If a future, narrower need arises — say, an institution wants a hold to also
*revoke standing IAM credentials* rather than merely deny their use, for a reason specific to
some regulatory regime that requires credential rotation/deactivation rather than an access
denial — that is a distinct, separately-scoped addition (see "what this design deliberately
does not cover," below), not part of this pass.

### Idempotency: what "already held, matches" vs. "needs re-locking" means

Follows `EnsurePolicy`'s own read-then-compare shape exactly, because `hold`'s attach step
*is* `EnsurePolicy`/`EnsurePolicyAttachment`, not a new primitive:

- **Already held, matches.** The hold-lockdown policy (found by name and automat's owner tag,
  the same `OwnerTagKey`/`OwnerTagValue` convention every other automat-owned policy carries)
  is attached to the target and its document structurally matches (`org.SameDocument`) what
  this build would render. Reported `VerbUnchanged`, no write issued — a second `automat hold`
  against an already-held account is the safe, boring re-run CLAUDE.md rule 4 requires.
- **Needs re-locking.** The policy exists but its content has drifted from what this build
  would render (a catalog update narrowed the read allowlist further, say) — `VerbUpdate`,
  the same `UpdatePolicy` path `EnsurePolicy` already takes for drift on any other automat-
  owned policy.
- **Not yet held.** No automat-owned hold policy is attached — `VerbCreate` then `VerbAttach`,
  the ordinary two-step `EnsurePolicy`/`EnsurePolicyAttachment` sequence every other policy
  spec already goes through in `EnsurePolicySet`.

**Un-holding (release) is explicitly out of scope for v1** — see the closing section for the
reasoning. Because release is out of scope, this design does not need to define what
"idempotent release" looks like; only the forward direction (attach-if-not-already, matching
`EnsurePolicy`'s existing idempotence) is built.

## Interface shape (`internal/awsapi`)

**No new interface.** `hold`'s AWS-side surface is exactly one action:
`organizations:AttachPolicy` (plus the same read-before-write triad every ensure operation
already uses: `ListPoliciesForTarget`, `ListTagsForResource`, and — for the same reason
`EnsurePolicy` needs it — `CreatePolicy`/`UpdatePolicy` for the policy document itself). Every
one of those methods already lives on `awsapi.OrgPolicyAPI`
(`internal/awsapi/api.go`), which is delegable at the Organizations level (DESIGN §3 fact 3)
and already carries the identical credential shape `reclaim`'s own `Policy` field uses: native
in MANAGEMENT, the caller's own delegated identity in MEMBER, never brokered. `hold` needs
no `CloseAccount`, no `DetachPolicy`, and (per the section above) no `IAMRoleAPI` surface —
so it is strictly narrower than what `Reclaimer` needs, and `OrgPolicyAPI` alone is
sufficient. Introducing a `OrgHoldAPI` carrying a subset of methods `OrgPolicyAPI` already
exposes would not narrow anything real; it would just be a second name for the same grant,
which the guardrail comment in `internal/awsapi/api.go` ("a granted-but-unreachable action
costs nothing" — stated in the other direction, an unreachable-but-needed method is the thing
worth avoiding) argues against introducing without a reason. **Decision: `hold` is built as a
new type in `internal/org` (see below) carrying an `awsapi.OrgPolicyAPI` field, the same field
`Ensurer.Policy` already is.**

## New `org.Verb`?

**Yes, one: `VerbHold`.** Following `docs/reclaim-design.md`'s own precedent of adding
exactly one verb (`VerbClose`) for its own new capability, rather than reusing an existing
one that would blur what happened:

```go
// VerbHold means a hold-lockdown service control policy was attached to an
// account that is being deliberately retained rather than closed, or would
// be. Distinct from VerbAttach, the same way VerbClose is distinct from
// VerbDetach: an operator reading a plan or an evidence record needs to see
// at a glance that this attachment is a hold action, not an ordinary vend's
// policy-set attachment.
VerbHold Verb = "hold"
```

Reusing `VerbAttach` was considered and rejected: `VerbAttach` already means "one of the
compiled artifact's ordinary control-set policies was attached during a vend," and an
operator scanning `list`'s output or an evidence manifest for hold actions specifically
(the way `Manifest.Parked()` already scans for a specific verb/outcome combination) needs a
verb that means only "this was a hold," the same reason `VerbClose` was not folded into
`VerbDetach`+something-else.

**No `VerbRelease` in this pass.** Un-holding is out of scope for v1 (see the closing
section), so there is nothing for a release verb to name yet. Adding it speculatively, ahead
of the command that would produce it, risks exactly the kind of unused, unreachable surface
`TestNoWriteInterfaceCanDestroy`'s guardrail comment already warns against for interface
methods — a verb nothing ever emits is a verb a future reader has to guess the meaning of
from its name alone.

A new, small `Holder` type (mirroring `Reclaimer`'s own reasoning for being a separate type
from `Ensurer` rather than one more method on it) is **not** obviously warranted the same way
`Reclaimer` was: `Reclaimer` exists apart from `Ensurer` because it is destructive
(`CloseAccount`, `DetachPolicy` — actions `TestNoWriteInterfaceCanDestroy` singles out) and
`Ensurer`'s own fields have never touched a destructive action in four phases. `hold`'s single
action, `AttachPolicy`, is not destructive in that sense — it is the *identical* write
`EnsurePolicyAttachment` already performs for every ordinary vend, on a policy authored for a
different purpose. **Decision: `hold` is a new method, `EnsureHold`, on the existing
`Ensurer` type**, taking the target OU and the rendered hold-lockdown `PolicySpec`, and
internally calling `EnsurePolicy`/`EnsurePolicyAttachment` exactly as `EnsurePolicySet` already
does — but recording its own actions with `VerbHold` in place of `VerbAttach`/`VerbCreate` at
the one point that matters to a reader (the attachment step), so the plan and the evidence
record both say "hold" rather than "an ordinary policy-set attach happened, for reasons you'll
have to infer." Concretely: `EnsureHold` calls `EnsurePolicy` (verb unchanged: `VerbCreate`/
`VerbUpdate`/`VerbUnchanged` are the right verbs for the policy *document* existing or
matching, exactly as they are for every other policy), then a hold-specific thin wrapper
around `EnsurePolicyAttachment` that re-labels only the attachment action's `Verb` field to
`VerbHold` when a real attach happens (and leaves `VerbUnchanged` alone — an already-held
account reports "unchanged," not "held," on a second run, the same way an already-attached
ordinary policy reports "unchanged" rather than re-announcing "attached").

## Command surface

```
automat hold --account <id> --reason <text> [--dry-run] --yes
```

Justified against the task's own open questions:

- **No `--release`/`--unhold` in v1.** Explicitly scoped out — see the closing section. The
  command surface therefore has no flag or subcommand implying release exists; adding one
  later, once release is designed, is a pure CLI addition (a new flag or a new
  `automat hold --release`) rather than a change to what `hold --yes` already means, so
  scoping it out now costs nothing forward-compatible.
- **`--yes` required unconditionally, following `reclaim`'s own gating precedent, not
  `init`'s conditional one.** `hold` is a real, blast-radius-bearing lockdown of a live
  account: after it applies, nobody (automat's own automation role included, since the hold
  statement is deliberately built with no exemption — a narrow read allowlist is not an
  exemption for a role, it is the allowlist itself) can act in the account until it is
  released, and release is not built in this pass. That is at least as consequential as
  `reclaim`'s "closes an account, no undo call" framing, if not more so in one respect: a
  reclaimed account is *understood* to be gone, while a held account looks, from the outside,
  exactly like an ordinary active account that has quietly stopped being usable — the kind of
  surprise CLAUDE.md rule 5's "print a plan first" exists to prevent.
- **`--dry-run` prints the plan and stops**, the same convention every other command
  (`init`/`vend`/`reclaim`) already follows.
- **`--reason` is required, not optional.** See the evidence section below for why it is a
  required, schema-patterned field rather than a nicety.
- **No `--ou`.** Following `reclaim`'s own reasoning exactly: `hold` targets one already-
  vended account, resolved to its current parent OU the same way `reclaim`'s
  `verifyParentOf` already does (`cmd/automat/reclaim.go`), not a subtree. There is no
  "hold everything under this OU" bulk mode — see the closing section.
- **`--evidence-dir` defaults the same way every other account-scoped command's does**
  (`envprofile.DefaultEvidenceDir`), matching `reclaim --evidence-dir`'s own flag exactly, for
  the identical reason: `hold` names an account directly and has no `--environment-profile`
  to read a customized evidence directory out of.

Plan-then-apply structure mirrors `reclaim` line for line: build a `Mode: org.ModePlan` pass
first, render it, stop on `--dry-run`, otherwise require `--yes`, then build a
`Mode: org.ModeApply` pass and apply it — the same real-code-in-plan-mode discipline that
keeps `reclaim`'s plan from ever drifting from what it applies.

## Evidence-manifest impact

**A new `evidence.Operation` value, `OpHold`.** `evidence.Operation`'s actual current enum
(`internal/evidence/types.go`) is:

```go
OpInit, OpSetup, OpAccountCreate, OpAccountMove, OpOUEnsure, OpSCPEnsure,
OpBaselineApply, OpAttestationWrite, OpVerify, OpAssess, OpReclaim, OpCustodyTransfer
```

`OpReclaim` is already there, added ahead of `reclaim`'s own code the same way this task's
prompt anticipated finding it. There is no `OpHold` slot pre-added the way `OpReclaim` was —
confirmed directly against the enum above rather than assumed — so this design proposes
adding one now, following the identical closed-enum discipline: a new `const OpHold
Operation = "hold"` in the Go enum, appended to `AllOperations`, and the matching enum value
added to `schema/evidence-manifest-v1.schema.json`'s `operation` field. This is a **schema
change** (CLAUDE.md rule 6: adding an enum member is not the audit-driven "strictly tightens
validation" exception — it is new surface, not a tightening — so it needs asking first,
which this design doc is). It should be requested alongside implementation, with a
`schema/CHANGELOG.md` entry the same shape as `OpReclaim`'s own addition.

**Record shape: a plain `OpHold` record, using the fields `Record` already has — no new
field on `Record` and no schema restructuring**, mirroring `reclaim`'s own "Task 6 not
needed" conclusion exactly:

- `Target.AccountID`/`Target.OUID` name what was held and where.
- `Outcome` is `success` (the attach was accepted or was already true) or `failure` (an
  `AccessDenied`, a quota refusal, or similar — `RecordError`'s existing shape, with the same
  action/resource/remediation triad CLAUDE.md rule 7 requires everywhere else).
- `Enforcement.SCPARNs` carries the hold policy's ARN — the exact field `reclaim` already
  reuses for what it detached, used here for what was attached, which is consistent with what
  the field already means ("what was actually attached or deployed," per its own doc comment)
  rather than a new meaning.
- The **compliance reason itself is new prose that has no existing field to live in.**
  `RecordError.Message` is wrong (it is reserved for a *failure's* message, and a hold's
  reason is not an error). `Custody.Reason` is the wrong field too — it is `custody_transfer`-
  specific and schema-forbidden on every other operation (`custody_transfer` is `required`
  when `operation` is `custody-transfer` and explicitly `not required` otherwise, per the
  schema's own `if`/`then`/`else` block). **Decision: a new field on `Record`, `Reason
  string`, `json:"reason,omitempty"`**, populated only on `OpHold` records (and, for symmetry
  if a future release command is added, on whatever operation that becomes) — a second,
  narrow, purpose-built field rather than overloading an existing one that already carries a
  different, load-bearing meaning elsewhere in the same document.

**The reason field's own discipline, proposed as the same round-trip/human-typed pattern
CLAUDE.md rule 8 and `catalogs/baseline-protection.json`'s `exempt_principals[].reason`
already establish.** `exempt_principal.reason`
(`schema/control-artifact-v1.schema.json`) is `minLength: 1`, `maxLength: 512`, pattern
`^[^\x00-\x1f\x7f]+$` — "an unexplained exemption is indistinguishable from one added to
create an escape hatch." A hold's reason carries the identical justificatory weight: an
unexplained hold, six months later, is indistinguishable from an account somebody forgot they
had locked down for no stated purpose, and the evidence record is the only place that
justification survives once the operator who typed it has moved on. The evidence schema
already has the right primitive for this — `$defs/prose`
(`schema/evidence-manifest-v1.schema.json`): `minLength: 1`, `maxLength: 1024`, the identical
control-byte pattern, already used for `custody_transfer.reason`. **`Record.reason` should be
typed as `$ref: "#/$defs/prose"`**, reusing the existing definition rather than inventing a
sibling pattern — the same discipline, the same primitive, no new regex to keep in sync with
the one `custody_transfer.reason` already uses. (Note this is `prose`, not `round_trip_id`/
`round_trip_ref`: a compliance reason is read by a human, not retyped onto a command line, so
the narrower round-trip character class rule 8 describes for ids/tokens does not apply here —
the applicable discipline is `prose`'s control-byte-refusal for the reporting-forgery reason
its own schema comment states, not the round-trip reason. This distinction matters because
rule 8 names specific examples — "request ids, account aliases, OU names, profile ids, resume
tokens" — and a compliance reason is not among them.)

## Explicit interaction with Q26 and the quota finding

**This is stated plainly and separately because the task that produced this design flagged
it as a real risk of two people talking past each other, and it deserves the same
prominence here.**

**Holding an account does NOT free, avoid consuming, or otherwise interact with any AWS
account-count quota slot.** An account that is `ACTIVE` and held counts against
`L-29A0C5DF` (accounts-per-organization) exactly the same as any other `ACTIVE` account —
there is no distinct AWS account status for "held," because AWS itself has no concept of
`hold` at all; from AWS's point of view a held account is simply an ordinary `ACTIVE` account
whose attached SCPs happen to deny almost everything. A `RECLAIMED` (closed, `SUSPENDED`)
account *also* continues to count against the same quota, confirmed live
(`docs/reclaim-design.md`'s "A closed account still counts against the account-count quota"
section, and Q26 in `docs/open-questions.md`), for at least the 90-day reinstatement window
and possibly longer — Q26 leaves exactly how much longer as an open, unconfirmed question.

**The consequence stated as bluntly as possible: choosing `hold` over `reclaim` for a given
account changes nothing about that account's quota cost, in either direction.** The account
was already consuming a slot against `L-29A0C5DF` before anyone decided whether to hold or
reclaim it — that decision happens no earlier than account creation, by which point the slot
is already spent. `hold` does not return the slot (the account stays `ACTIVE`, unambiguously
counted). `reclaim` does not return the slot either, at least not promptly (the newly
confirmed fact above). Neither operation is a lever an operator can pull to manage headroom
against the account-count ceiling. An operator who reaches for `hold` believing it is a
"pause an account without spending its slot" tool, or who reaches for `reclaim` believing it
is a "get this slot back right away" tool, is wrong about both, in the same direction: AWS's
bookkeeping does not distinguish "SCP-locked-down-but-active" or "closed-within-90-days" from
"ordinary active account" for the purpose of this one quota.

**What `hold` and `reclaim` actually answer are two unrelated questions, not two strategies
for the same one.** `reclaim`: is this account's operational life permanently over, such that
closing it (with AWS's own eventual, opaque data-retention lifecycle taking over from there)
is the correct disposition? `hold`: must this account's data and access remain exactly as they
are right now — intact, inspectable, administratively reachable if a legitimate need to look
at it arises — for a stated compliance, audit, or legal reason, making closure specifically
the wrong disposition regardless of whether anyone is actively using the account? An account
can need `hold`'s answer while its quota cost is identical to an account that would have
gotten `reclaim`'s answer instead, or to an account nobody has made any lifecycle decision
about at all. The three are simply not comparable on the quota axis, because the axis does not
move for either decision.

**Recommended cross-references, to be added once this document exists (see the Commit
section for what was actually done).** `docs/reclaim-design.md`'s "A closed account still
counts against the account-count quota" section, and `docs/open-questions.md`'s Q26 entry,
should each gain a short pointer at this document's "Explicit interaction with Q26 and the
quota finding" section, so a future reader who arrives at either page already holding the
"maybe hold/reclaim manage the quota" hypothesis lands on the correction rather than having
to independently rediscover it.

## What this design deliberately does NOT cover

- **Automatic or triggered holds.** `hold` is an explicit, operator-invoked, reasoned
  decision, exactly matching `reclaim`'s own "rare, deliberate event, not routine teardown"
  framing. Nothing in automat watches an account and decides on its own that it should be
  held — there is no continuous monitoring anywhere in this tool (a non-goal DESIGN.md §2
  already states), and a hold triggered by, say, a `verify` finding or an assessment score
  would be exactly the kind of automated compliance action this project has never built and
  should not start with the one command whose entire point is deliberateness.
- **Releasing a held account back to normal (`--release`/`--unhold`).** Scoped out of v1.
  This is the one item in this list worth arguing rather than just stating, because it is the
  most obviously useful next step: a hold that can never be lifted is not a retention tool,
  it is a slower `reclaim`. It is left for a future, separately-scoped addition rather than
  built alongside `hold` itself for three reasons. First, release is a strictly different
  shape of decision than hold: holding is "lock this down, we have a reason," but releasing is
  "the compliance reason has lapsed, AND nothing about this account's current state should
  block returning it to ordinary use" — the second half of that sentence is a real
  determination (has anything else changed underneath the lockdown that a plain policy-detach
  would now expose?) that this design has not analyzed and should not improvise an answer to
  under the same task that settled hold's own shape. Second, `EnsurePolicySet`'s existing
  machinery already gives a path to release without new code, once someone has thought
  through what should happen: an operator can `automat verify`/re-vend to re-attach the
  ordinary control set, and a future explicit `DetachPolicy`-based release command (using the
  same delegable, native-in-MANAGEMENT/never-brokered credential shape `reclaim`'s own detach
  step already established) is additive on top of what exists rather than something `hold`'s
  own design has to pre-build a slot for. Third, matching `reclaim`'s own "no ephemeral mode"
  caution: building release speculatively, before a real operational need has clarified what
  "safe to release" actually requires checking, risks exactly the "a flag bolted onto the
  default path" pattern `docs/reclaim-design.md` explicitly declined for reclaim's own
  ephemeral-account question.
- **Batch/bulk hold** (multiple accounts in one invocation). Not built, mirroring `reclaim`'s
  identical exclusion. `hold --account <id>` targets one account per invocation.
- **Automatic re-evaluation of whether a hold is still justified.** Once held, an account
  stays held until an operator (or, later, whatever institutional process decides holds
  should lapse) acts — automat does not track review dates, does not expire holds, and does
  not remind anyone. This is an operator/institutional-policy process, not automat's job,
  matching the project's own "no continuous monitoring" non-goal exactly. (If a future need
  for a review-by date on a hold emerges, it is the same shape of addition
  `environment-profile/v1`'s own `review_by` field already is elsewhere in this schema family
  — a candidate for that future work, not a gap in this one.)
- **In-account credential revocation/rotation** (deactivating access keys, deleting login
  profiles, disabling MFA devices) as a supplement to the SCP. Investigated above and found
  unnecessary: the SCP already denies every principal in the account, including the root
  user, so there is no gap for a credential-level action to close. If a specific regulatory
  regime is ever found to require *deactivation* rather than *denial* of credentials
  specifically (a real distinction some frameworks draw), that is new information this design
  does not have and would need its own scoped addition, not a default assumption baked in now.
- **A hold-lockdown catalog that varies per environment profile or institution beyond the
  ordinary catalog-extension mechanism.** `hold`'s SCP is authored once, as one more catalog
  (`catalogs/hold-lockdown.json`, by analogy with `baseline-protection.json`), extensible the
  same way every other catalog is — via its own data, reviewed and compiled through
  `gen/catalog`. This design does not propose a mechanism for an institution to swap in an
  entirely different hold posture per account; that is the same "extend rather than replace"
  discipline DESIGN §10 already states for `baseline-protection`, carried over rather than
  reinvented.
