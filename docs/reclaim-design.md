# `automat reclaim` — design

**Status: design authority for Phase 5's `reclaim` task. Not yet built.** ROADMAP.md
schedules the implementation; this page settles the decisions DESIGN §16 explicitly
deferred ("`reclaim` semantics (ephemeral vs durable accounts) deferred to Phase 5") before
any code is written, the same way `docs/assessment-reporting.md` did for `assess`.

## The lifecycle decision

**A vended account is durable by default.** It is a long-lived, audited research-computing
asset, not a disposable one. `reclaim` is therefore a rare, heavily-gated event rather than
routine teardown:

- `--yes` is **required unconditionally** to apply, not gated on one particularly dangerous
  step the way `init`'s org-creation gate is (`plansOrgCreation`). Every `reclaim --apply`
  closes an AWS account; there is no "safe half" of this command the way `init` has
  OU-ensure alongside org-creation.
- `--dry-run` prints the plan and stops, following `init`/`vend`'s own convention exactly.
- No ephemeral/lighter-weight mode is built in this pass. If a future need for
  routinely-disposable accounts (e.g. CI sandboxes) emerges, that is a separate,
  explicitly-scoped addition — not a flag bolted onto this command's default path.

## What `reclaim` does, in order

Two AWS-side actions, sequenced deliberately:

1. **Detach automat's own service control policies** from the account's OU placement,
   via the delegated `OrgPolicyAPI`-class credential (native in MANAGEMENT, the caller's
   own delegated identity in MEMBER — never brokered, since `DetachPolicy` at the
   Organizations level **is** delegable, DESIGN §3 fact 3). Ownership is checked the same
   way `EnsurePolicyAttachment`/`policyOwnership` already do: only a policy carrying
   `automat:managed-by=automat` is touched. A policy present but not automat's is left
   alone and reported, not silently skipped — the same "ownership before content"
   discipline `EnsurePolicy` already follows.
2. **Close the account**, via `organizations:CloseAccount` — a brand-new,
   management-account-only, non-delegable call (absent from every delegable-action list
   DESIGN §3 documents, same class as `CreateAccount`/`CreateOrganizationalUnit`). This
   means the exact MANAGEMENT/MEMBER-brokered split `vend`'s `vendOrgClient`/
   `g.brokeredOrgVendClient` already implements, reused rather than reinvented: native
   credentials in MANAGEMENT, the vendor role assumed in MEMBER.

**Detach before close, not the reverse.** Two reasons: (a) `CloseAccount` is asynchronous
and can leave an account in `PENDING_CLOSURE` for minutes — attempting to detach a policy
from an account already mid-closure is an unforced complication with no benefit, since the
account is being destroyed either way; (b) if closure itself is denied (rate limit, a
missing grant, an org-level constraint), the account is left in a **known, previously-ensured
state** (no automat SCPs, but otherwise intact and reachable) rather than a half-torn-down
one. The failure mode of "detach succeeded, close failed" is a plain, resumable state —
the operator re-runs `reclaim` and the detach step reports `unchanged`. The failure mode
of "close succeeded, detach failed" cannot happen, because `CloseAccount` does not fail in
a way that leaves an ambiguous account state — either it accepts the request or it refuses
outright.

**A policy is attached at the OU, not the account (DESIGN §5, §8) — so step 1 checks for a
live sibling before detaching anything (AUDIT-6 C1).** An OU can hold more than one account:
two vends against the same `target_ou` land two accounts under one OU sharing one
automat-owned SCP, the ordinary shape `docs/cli-surface.md` D5's `list` tree walk already
depends on existing. `DetachOwnedPolicies` resolves the account being reclaimed's parent OU
(`target`, from `ListParents`, same as `verify`) and would, without a check, detach that
policy from `target` regardless of what else sits under it — stripping a still-ACTIVE
sibling's guardrails as an unannounced side effect of reclaiming a *different* account.
Fixed by a read before the detach: `ListAccountsForParent` against `target`, excluding the
account being reclaimed itself, refusing to detach an automat-owned policy while any other
account under `target` reports `ACTIVE`. The policy is reported `unchanged` with the
sibling's account id named, not silently skipped — the same "report what nothing here may
touch" discipline the not-automat's-policy branch already follows. `ListAccountsForParent`
is already in the delegation policy's `readActions` (`internal/bundle/policy.go`), scoped to
the same OU ARNs the attach/detach statement already names, so no bundle change was needed —
the read this fix needs was already granted, just never called from this path.

## The rate limit

AWS's own `CloseAccount` doc comment (verified directly against the SDK source, not
inferred): *"Within a rolling 30-day period you can close the higher of either 250 or 20%
of the member accounts in your organization, up to a maximum of 1,000."* This **updates**
DESIGN §3 fact 11's "~10% per rolling 30 days" — the actual AWS quota is more generous
(the higher of 250 or 20%) and is documented directly in the SDK's operation comment. DESIGN
§3 should be corrected to cite the accurate figure rather than the rounder approximation
carried forward from an earlier note (flagged for a separate, tightly-scoped DESIGN.md
fix alongside this page, since a fact section is a place approximation should not persist
once the primary source is in hand).

**`reclaim` does not attempt to compute this quota client-side before acting.** There is no
`servicequotas` code covering the close-account limit the way `preflight.checkQuota`
covers `L-29A0C5DF` (accounts-per-organization) — Service Quotas does not expose
"close-account rate" as a queryable quota code at all, only the account-count ceiling.
Inventing a client-side counter (tracking closures against a rolling window from local
evidence manifests) would be assuming the quota's exact shape from prose and enforcing a
guess. Instead, `reclaim` calls `CloseAccount` and handles the AWS-side rejection
gracefully: a `ConstraintViolationException` with reason
`CLOSE_ACCOUNT_QUOTA_EXCEEDED` or `CLOSE_ACCOUNT_REQUESTS_LIMIT_EXCEEDED` (both real,
named reasons in the SDK's `ConstraintViolationExceptionReason` enum) is reported with
remediation text naming the actual AWS-documented limit and pointing at *Quotas for
Organizations* — CLAUDE.md rule 7's discipline (every failure says which action, which
resource, what would fix it), applied to a limit this tool cannot pre-check rather than
one it can.

## Evidence-record shape

**A plain `OpReclaim` record, not a variant of custody-transfer.** `evidence.OpReclaim` is
already in the closed `Operation` enum (landed ahead of time when the enum was drafted).
Custody-transfer is reserved for the case DESIGN §11 built it for: custody of the *manifest
itself* passing to a different system or owner, with the chain deliberately ending
(`Manifest.Closed()`/`ErrClosed`). Closing the AWS account is a different fact — the
subject the manifest is about no longer exists in AWS — but the manifest itself is not
being handed to anyone; it is the terminal record of what happened to *this* account,
staying exactly where every other account's evidence directory already keeps it.

**The manifest chain does not close.** Two reasons: (1) AWS itself keeps a closed account
in `SUSPENDED` status for a 90-day grace window during which it can be **reinstated** by
contacting AWS Support (verified in the SDK's own `CloseAccount` doc comment) — a
permanently-closed manifest chain would have no way to record a reinstatement if one
happened, and `Append`'s `ErrClosed` refusal exists specifically for the case where nothing
should ever follow (a genuine custody transfer), not this one. (2) `list`'s existing
parked-account convention already distinguishes "this account needs attention" from "this
chain is closed" — `OutcomeParked`/`Manifest.Parked()` is the shape for the former, and no
new chain-closing mechanism should be introduced for what is really a status the record
itself carries.

**No new field on `Record`.** The existing shape is sufficient: `Target.AccountID` names
what was closed, `Outcome` reports `success` or `failure` (a `CLOSE_ACCOUNT_QUOTA_EXCEEDED`
rejection is a `failure` with `RecordError`'s remediation text, matching how `vend` records
a parked step today), and `Enforcement.SCPARNs` (already on `Record`, populated by `vend`
today for what was attached) is reused to record which of automat's policies were detached
before closure — an empty slice if none were automat's to detach. **Conclusion: Task 6
(the conditional schema-change task in the approved plan) is not needed.** No field is
added to `schema/evidence-manifest-v1.schema.json`.

## Interface shape (`internal/awsapi`)

A single new interface, `OrgReclaimAPI`, carrying exactly the three methods the
`api.go` guardrail comment already names together (`DetachPolicy`, `DeletePolicy`,
`CloseAccount`) plus the read method needed to find which policies are automat's
(`ListPoliciesForTarget`, mirroring `OrgPolicyAPI`'s own read-before-write pattern per
`TestEveryWriteInterfaceCanReadBackWhatItWrote`'s existing requirement) and
`ListTagsForResource` (to check ownership, exactly as `OrgPolicyAPI` does today).
`DeletePolicy` is included even though the detach step above does not delete the policy
document itself (a fair question: should reclaim also delete the now-unattached SCP, or
leave it for potential reattachment/audit trail?) — **decision: reclaim detaches but does
NOT delete.** An orphaned-but-undeleted policy is inert (attached nowhere, so it enforces
nothing) and remains inspectable evidence of what the account was governed by; deleting it
destroys that trail for no operational benefit, and `DeletePolicy` was only ever
provisionally listed in the api.go guardrail's "bundle already requests it" note, not a
requirement of this design. `DeletePolicy` is **not** added to `OrgReclaimAPI` — narrower
than the bundle's current grant, which is the safe direction (a granted-but-unreachable
action costs nothing, per the guardrail's own stated policy).

This keeps `TestNoWriteInterfaceCanDestroy`'s `destructive` map accurate: `DetachPolicy`
and `CloseAccount` move off that "must stay absent from every interface" list and onto
`OrgReclaimAPI`'s own explicit, gated surface; `DeletePolicy` stays listed as absent,
since this design does not use it.

## Plan/apply vocabulary

Reuses `internal/org`'s existing `Mode`/`Verb`/`Action` types exactly, adding one new verb:

```go
// VerbClose means an account was closed, or would be.
VerbClose Verb = "close"
```

A new `Reclaimer` type (not a method added to `Ensurer`, to keep the destructive surface
visibly separate — mirroring the interface-level separation above) with its own `Policy
awsapi.OrgReclaimAPI` field, `Plan`/`Apply` methods following `Ensurer.EnsurePolicy`'s
existing plan/no-write vs. apply/write branching shape (`e.planning()`), and its own
`Actions()` accumulator for the printed plan and the evidence record.

## Command surface

```
automat reclaim --account <id> [--dry-run] --yes
```

No `--ou` (reclaim always targets one already-placed account, not a subtree — there is no
"reclaim everything under this OU" bulk mode in this pass). `--yes` has no default and
`reclaim --apply`-without-`--yes` refuses outright, the same message shape `init` uses when
`--yes` is missing for org-creation, but unconditional here rather than conditional on plan
contents.

## What this design deliberately does not cover

- **Bulk/batch reclaim** (multiple accounts in one invocation) — not built; `reclaim`
  targets one account per invocation, matching `verify`'s own single-`--account` scope.
- **Programmatic rate-limit tracking** — explicitly rejected above; AWS's own rejection is
  the source of truth, reported with remediation text.
- **Reinstatement tooling** — AWS's 90-day grace-window reinstatement is a Support
  interaction (per the SDK doc comment), not an API `automat` can drive; out of scope.
- **A widened vendor-role bundle for `CloseAccount`** — the onboarding bundle's current
  CFN/TF templates do not yet grant it (only `DetachPolicy`/`DeletePolicy` are requested
  today, per `internal/bundle/policy.go`, for `verify`'s own detach capability plus the
  `reclaim` scaffolding this design settles). Widening the bundle to add `CloseAccount` for
  the MEMBER-brokered vendor role is implementation work for the `cmd/automat/reclaim.go`
  task, not a design question — noted here so it is not missed.
