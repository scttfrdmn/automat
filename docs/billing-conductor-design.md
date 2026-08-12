# Billing Conductor enrollment — design

**Status: design authority for a not-yet-scheduled vend-time capability. Not yet built.**
This page settles the decisions before any code is written, the same way
`docs/reclaim-design.md` did for `automat reclaim`. Two things came out of the research
pass that produced this page and are treated as settled premises, not re-litigated here:
AWS Organizations consolidated billing has no native "sub-root payer" — one org, one real
payer, always the management account — and AWS Billing Conductor's billing groups are a
reporting/allocation layer over that one real invoice, never a second payer.

## The governing decision

**Enrollment belongs in automat. Enforcement does not, ever.**

Enrolling a newly vended account into an institution's existing Billing Conductor billing
group is a one-shot, at-creation, idempotent administrative act — structurally identical to
attaching SCPs or tagging an account, both of which automat already does at vend time. It
names a resource (a billing group) that already exists, by an id the environment profile
carries, the same way `Placement.TargetOU` names an OU that already exists. automat creates
neither the billing group nor the pricing plan behind it, exactly as it attaches SCPs to an
OU it does not create.

Ongoing spending controls — budget thresholds, alerts, freeze actions — do **not** belong in
automat, and this is not a scope note to revisit later; it is the same non-goal that already
rules out a standing agent. Enforcing a budget threshold requires re-evaluating account
spend against a lagging billing pipeline on some cadence no operator invocation drives, which
is precisely the class of thing CLAUDE.md's "no daemons, no databases" project fact and
DESIGN's "no continuous monitoring / evidence collection agents" non-goal already exclude.
A tool that vends an account once and is done with it cannot also be the tool watching that
account's spend every day afterward without becoming the daemon this project has structurally
refused to be. If an institution needs budget alerting, that is Billing Conductor's own
budget feature (or AWS Budgets), configured and owned outside automat — automat's job ends at
naming the account into the group that feature reads from.

## Delegability: brokered, like account creation — not native like SCPs, and not hard-restricted like `CloseAccount`

DESIGN §3 states two shapes for a management-account-adjacent action: facts 1–2
(`CreateAccount`, `CreateOrganizationalUnit` — hard-restricted to the management account, no
resource-based delegation policy accepts them at all) versus fact 3 (SCP management —
delegable to a member account via an Organizations resource-based delegation policy, scoped
by resource ARN). Billing Conductor's `AssociateAccounts` is **neither** shape cleanly, and
getting this wrong would either block the MEMBER-state case entirely or design a delegation
mechanism Billing Conductor does not have.

**What the research established, cited directly:**

1. **No hard, AWS-side caller restriction exists for `AssociateAccounts`.** Its own API
   reference (`docs.aws.amazon.com/billingconductor/latest/APIReference/API_AssociateAccounts.html`)
   lists `AccessDeniedException` ("You do not have sufficient access to perform this
   action") as the only authorization-related error — the same generic IAM-denial shape
   every ordinary, identity-policy-gated action uses. Contrast this directly against
   `CreateAccount`'s own doc, which states the management-account restriction as prose, not
   as a permission a policy could ever grant around. `AssociateAccounts` carries no
   equivalent sentence anywhere in AWS's Billing Conductor documentation set fetched during
   this research pass (API reference, user guide "What is AWS Billing Conductor?", "Identity
   and access management for AWS Billing Conductor", "How AWS Billing Conductor works with
   IAM", "Quotas and restrictions").
2. **Billing Conductor explicitly documents cross-account role use as supported**, which is
   the fact that actually answers the question. "How AWS Billing Conductor works with IAM"
   (`docs.aws.amazon.com/billingconductor/latest/userguide/security_iam_service-with-iam.html`),
   under "Using temporary credentials with Billing Conductor": *"You can use temporary
   credentials to sign in with federation, assume an IAM role, or to assume a cross-account
   role. You obtain temporary security credentials by calling AWS STS API operations such as
   AssumeRole... Billing Conductor supports using temporary credentials."* This is the
   opposite of `CreateAccount`'s documented behavior, where no amount of role assumption
   reaches it from anywhere but the management account itself.
3. **There is no Billing-Conductor-specific delegation mechanism analogous to
   Organizations' resource policy.** The full 32-operation surface of
   `github.com/aws/aws-sdk-go-v2/service/billingconductor` has no `PutResourcePolicy` or
   `DescribeResourcePolicy` equivalent — nothing plays the role
   `organizations:PutResourcePolicy` plays for fact 3's delegated SCP management. So this is
   not "delegable the way SCPs are" (there is no resource-based delegation policy to write),
   but it also is not "restricted the way `CreateAccount` is" (ordinary IAM identity policies
   on an assumed role work, per point 2).

**Conclusion: `AssociateAccounts` is reached exactly the way `CreateAccount` and
`MoveAccount` already are, not the way `AttachPolicy` is.** A billing group's ARN is
namespaced to the payer/management account
(`arn:aws:billingconductor::{management-account-id}:billinggroup/{id}`, confirmed in the
`AssociateAccounts`/`CreateBillingGroup` API reference's own `Arn` parameter pattern), so the
permission to call it has to live on a principal reachable from that account. In MANAGEMENT,
that is the caller's own identity, same as `OrgVendAPI`. In MEMBER, that is the **same
brokered vendor role** `vendOrgClient` already assumes for `CreateAccount`/`MoveAccount` —
this design widens that role's policy with a `billingconductor:AssociateAccounts` (and
`billingconductor:ListAccountAssociations`) statement scoped to the one billing-group ARN the
environment profile names, rather than inventing a second broker. The MANAGEMENT/MEMBER split
this needs is `OrgVendAPI`'s own split, reused, not `OrgPolicyAPI`'s. This means the feature
works in **both** of automat's operating states, contrary to a plausible worst case (a
Billing-Conductor-only capability unreachable from MEMBER the way `CloseAccount` is) — but it
reaches MEMBER through the vendor-role bundle widening the same way `CreateAccount` does, not
through central IT's delegation-policy statement.

## What enrollment does, in order

One AWS-side action, called once per vend, after the account exists:

1. **Read current association.** `billingconductor:ListAccountAssociations`, filtered to the
   one account id being vended (`Filters.AccountId`), to learn whether this account is
   already in a billing group and which one. Ensure-semantics needs this read before the
   write for the same reason `OrgPolicyAPI.ListPoliciesForTarget` precedes
   `AttachPolicy` — a second run of `vend` must not blindly re-call `AssociateAccounts`
   against an account already correctly enrolled.
2. **Enroll, or confirm, or refuse — never migrate.** `AssociateAccounts`'s own description
   states the constraint directly: account ids passed to it "must... not already [be]
   associated with another billing group." This is the fact that settles the "can an account
   be reassigned directly" question this design had to answer before writing any ensure
   logic: **no** — `AssociateAccounts` itself refuses an account already in a different
   billing group; moving one requires `DisassociateAccounts` from the old group first. Given
   that, the read from step 1 sorts into exactly three outcomes:
   - **Absent from any billing group** (Billing Conductor's own `UNMONITORED` state) →
     `AssociateAccounts` runs. This is the ordinary case: a freshly created account, vended
     moments earlier, has never been in any billing group.
   - **Already associated with the billing group this environment profile names** → no call;
     the plan reports this account already in place, the same "unchanged" shape every other
     ensure in this codebase reports.
   - **Already associated with a *different* billing group** → refused, not resolved. See
     below for why this is not automat's decision to make silently.

**Why the third case is a refusal rather than a disassociate-then-associate.** A freshly
vended account has no history: it was created moments before this step runs, so the only way
it can already sit in a *different* billing group is out-of-band action between account
creation and this step (a partially-completed prior `vend` run whose environment profile
named a different group before an operator edited it, or a human/other tool acting on the
account directly). Automatically disassociating and reassociating would be automat silently
correcting a possibly-deliberate placement it has no way to distinguish from a mistake, and
`DisassociateAccounts` is a write against *another* billing group's membership — the same
"do not touch what this operation was not asked to touch" discipline
`docs/reclaim-design.md`'s sibling-account check applies to a different OU's SCP. This design
therefore does not give the interface a `DisassociateAccounts` method at all (see interface
shape, below); reassignment is out of scope, named explicitly in the closing section.

## Where this runs in the vend pipeline

**Independent of OU placement and SCP attachment, confirmed rather than assumed.** Billing
Conductor's `AccountGrouping.LinkedAccountIds` (the field `CreateBillingGroup` takes, and the
shape `AssociateAccounts` extends) is a flat array of 12-digit account ids with no OU,
region, or policy semantics anywhere in the API — nothing in the service's data model
references an Organizations OU. So the only real ordering dependency this step has is the one
every vend step after account creation shares: it needs the account id, which exists only
once `CreateAccount` has been called and (per DESIGN §7 step 2) `DescribeCreateAccountStatus`
has confirmed it. It has no dependency on `MoveAccount` succeeding, no dependency on SCP
attachment, and no dependency on the in-child baseline work.

Concretely, in DESIGN §7's numbered flow (resolve profile → create account → move into OU →
ensure SCPs → in-child baseline → evidence + birth certificate), billing-group enrollment
slots in **right after step 2's `CreateAccount`/poll succeeds**, before step 3's `MoveAccount`
— matching the account-tagging behavior `CreateAccount` itself already performs at the same
point (tags are written at creation, before placement is known to have succeeded). Running it
this early means an account that later ends up **parked** (DESIGN §5's known root-landing
race, `MoveAccount` failing) is still correctly enrolled in its billing group — parking is a
placement/governance problem, not a billing one, and there is no reason the two should be
coupled.

**A failure here must not block the rest of vend.** Billing-group enrollment is a reporting
concern, never a security control, so a denial (say, the vendor-role bundle was never widened
for `billingconductor:AssociateAccounts` in a MEMBER-state org) is recorded and reported the
same way DESIGN §7 step 5's absence is reported today — a named, non-fatal gap in the birth
certificate — rather than treated as a reason to abort SCP attachment or the in-child
baseline. Coupling a compliance-relevant step's success to a billing-reporting step's success
would let a Billing Conductor outage or a missing grant block an account from ever getting
its guardrails, which is exactly backwards from CLAUDE.md's own priorities.

## Interface shape (`internal/awsapi`)

A new interface, `BillingConductorAPI`, in its own file backed by the new (pre-approved per
CLAUDE.md's standing dependency ratification) `github.com/aws/aws-sdk-go-v2/service/billingconductor`
module — a new per-service module still needs its own dependency-review line in whichever
phase audit lands the implementation, per that same rule.

```go
// BillingConductorAPI is vend-time enrollment into an institution's own,
// already-existing Billing Conductor billing group
// (docs/billing-conductor-design.md). Not delegable via any Organizations-style
// resource policy (Billing Conductor has none) but not management-account-only
// the unconditional way CreateAccount is either: AssociateAccounts is an
// ordinary IAM-gated action Billing Conductor's own docs confirm works under
// an assumed cross-account role, so this interface is reached the same way
// OrgVendAPI is — the caller's own credentials in MANAGEMENT, the brokered
// vendor role in MEMBER — never OrgPolicyAPI's delegation-policy path, which
// Billing Conductor has no equivalent of.
//
// ListAccountAssociations is the read-before-write half: an ensure operation
// must know whether the account is already enrolled, and where, before ever
// calling AssociateAccounts — the same discipline OrgPolicyAPI's
// ListPoliciesForTarget already holds for AttachPolicy.
//
// # What is deliberately absent
//
// CreateBillingGroup, DeleteBillingGroup, UpdateBillingGroup, and every
// pricing-plan/pricing-rule/custom-line-item call: automat enrolls INTO an
// existing, institution-managed billing group; it does not create or
// administer billing groups or their pricing, mirroring exactly how
// OrgReclaimAPI detaches a service control policy but never deletes the
// policy document, and how OrgPolicyAPI never gets a DeletePolicy method.
//
// DisassociateAccounts is absent on purpose, not merely unused: this design's
// ensure-semantics never move an account OUT of a billing group it is already
// in, including a different one than the environment profile names — see
// docs/billing-conductor-design.md's "why the third case is a refusal"
// paragraph. Adding it would make reassignment reachable from a code path
// this design explicitly declined to write logic for.
//
// ListBillingGroups is absent: the environment profile names the billing
// group by its ARN directly (the same shape Placement.TargetOU names an OU
// by id, not by a friendly name automat would have to resolve), so nothing
// in this pipeline ever needs to discover or enumerate billing groups.
type BillingConductorAPI interface {
	AssociateAccounts(ctx context.Context, in *billingconductor.AssociateAccountsInput,
		optFns ...func(*billingconductor.Options)) (*billingconductor.AssociateAccountsOutput, error)

	ListAccountAssociations(ctx context.Context, in *billingconductor.ListAccountAssociationsInput,
		optFns ...func(*billingconductor.Options)) (*billingconductor.ListAccountAssociationsOutput, error)
}
```

Added to the compile-time assertion block alongside the others:

```go
_ BillingConductorAPI = (*billingconductor.Client)(nil)
```

Reached via `vendOrgClient`'s exact MANAGEMENT/MEMBER split (native credentials one place,
`g.brokeredOrgVendClient`'s assumed role the other) — no third client-construction path is
needed, since this interface's credential shape is `OrgVendAPI`'s, not a new one.

## New environment-profile field — **schema change, not pre-approved**

The natural home is `envprofile.Account` (`internal/envprofile/types.go`), not `Baseline`:
`Account` already carries `IAMUserAccessToBilling`, a billing-adjacent `CreateAccount`
parameter, right alongside `RoleName` and `Tags` — enrollment is an account-level
administrative fact decided at vend time, not in-child work performed after assuming into
the child the way every `Baseline` field is.

Proposed field, following `RoleName`'s exact shape (a plain optional string, empty means the
step is skipped entirely — no billing-group management is the default, matching how
signing and mirroring are both opt-in-only):

```go
// BillingGroupARN, when set, enrolls this account into an existing AWS Billing
// Conductor billing group at vend time (docs/billing-conductor-design.md).
// Empty means the step is skipped: no billing-group enrollment is the default,
// and automat never creates or administers the billing group itself.
BillingGroupARN string `json:"billing_group_arn,omitempty"`
```

JSON path: `.account.billing_group_arn`. This is a round-trip field under CLAUDE.md rule 8 —
an operator writes it into the profile, and it is echoed back in plan output and the evidence
record, the same way `Placement.TargetOU` is — so both layers need a character-class pattern.
AWS's own `AssociateAccounts`/`CreateBillingGroup` API reference documents the ARN's pattern
as `(arn:aws(-cn)?:billingconductor::[0-9]{12}:billinggroup/)?[a-zA-Z0-9]{10,12}` (the ARN
prefix is optional in AWS's own grammar, which would let a bare id through); this design
proposes automat's schema and Go validator both **require** the full `arn:aws(-cn)?:` prefix
—narrower than what the AWS API itself accepts, the same direction `docs/reclaim-design.md`
takes when it narrows `OrgReclaimAPI` below the bundle's existing grant — so a profile field
never holds an ambiguous bare id that reads differently depending on which AWS account
resolves it.

**This is a schema change requiring pre-approval per CLAUDE.md rule 6.** It is proposed here,
not assumed. It adds an optional field, which per `schema/CHANGELOG.md`'s own versioning
convention is a **minor** bump to `environment-profile/v1`, not a major one — but the human
still has to say yes before `schema/environment-profile-v1.schema.json` or
`internal/envprofile/types.go` changes.

## Plan/apply vocabulary

**No new verb.** `org.Verb`'s existing vocabulary already covers every outcome this design
produces:

- **Absent → enroll**: `VerbAttach` ("a policy was attached to a target") — reused rather
  than duplicated, since "an account was attached to a billing group" is the same shape of
  fact as "a policy was attached to an OU": something that already existed on both sides was
  connected. `Action.Kind` disambiguates ("billing group association" vs. "service control
  policy"), the same way `Action.Kind` already disambiguates every other verb's subject.
- **Already correct → no-op**: `VerbUnchanged`, same as everywhere else.
- **Already enrolled elsewhere**: not a verb at all. This is the plan-time refusal described
  above under "what enrollment does" — a hard error naming the account, the profile's named
  billing group, and the billing group the account is actually in, the same shape `Permitted`
  producing an empty intersection is a plan-time hard error rather than a silently-emitted
  `VerbUnknown`.

No `Reclaimer`-style dedicated type is needed either: this is an ordinary ensure, not a
destructive operation requiring its own visibly-separate surface — it belongs on `Ensurer`
itself, alongside `EnsurePolicy` and the account/OU ensures, with its own
`BillingConductor awsapi.BillingConductorAPI` field.

## Evidence-record shape

**A new `Operation` value, not a fact folded into `OpAccountCreate`.** Following
`evidence.OpReclaim`'s own precedent — landed in the closed enum ahead of the code that
produces it — this design proposes `evidence.OpBillingGroupEnsure`, added to `AllOperations`
alongside the other `*Ensure`-shaped values (it sits with `OpSCPEnsure`, not with
`OpAccountCreate`). The reasoning is the same "what claim is this record actually making"
discipline `docs/reclaim-design.md`'s own evidence section applies: `OpAccountCreate` is
specifically the claim that `CreateAccount` succeeded, an atomic, once-per-account fact.
Billing-group enrollment is a **separate, independently-idempotent, independently-retryable**
API call that can fail on its own (a MEMBER-state org whose vendor-role bundle was never
widened for `billingconductor:AssociateAccounts`) without account creation having failed —
exactly the reasoning that already keeps `OpSCPEnsure` a distinct record from
`OpAccountCreate` rather than a note buried inside it.

**The fact itself lands on `Enforcement`, a new field.** `Enforcement` already carries
one-time "this was attached/deployed at vend" facts (`SCPARNs`, `ConformancePackARN`); a
`BillingGroupARN string` field follows the identical shape — present when enrollment ran and
succeeded, absent (via `omitempty`, matching every other field on `Enforcement`) when it did
not apply or was skipped because the profile named none.

**This is also a schema change requiring pre-approval per CLAUDE.md rule 6** — both the new
`operation` enum value in `schema/evidence-manifest-v1.schema.json` and the new
`enforcement.billing_group_arn` field. Both are additive (a new enum member, a new optional
property), which is a **minor** bump under `schema/CHANGELOG.md`'s own convention, matching
the environment-profile change above — but, as with that field, this page proposes rather
than assumes the approval.

## What this design deliberately does not cover

- **Creating or administering billing groups, pricing plans, pricing rules, or custom line
  items.** Entirely the institution's own responsibility, configured out-of-band through the
  Billing Conductor console or API directly — the same boundary `docs/reclaim-design.md`
  draws around SCP documents it detaches but never deletes.
- **Any spending-threshold, alert, or freeze mechanism.** Explicitly and permanently out of
  scope per the governing decision above, not a gap to fill later: continuous budget
  enforcement requires polling a lagging billing pipeline on a cadence no operator invocation
  drives, which is exactly the standing daemon this project has structurally rejected
  (CLAUDE.md's "no daemons, no databases," DESIGN's non-goal on continuous monitoring
  agents). An institution that wants this runs a separate, external tool built for it —
  Billing Conductor's own budget feature, or AWS Budgets, reading the billing group automat
  enrolled the account into.
- **Re-enrollment or migration between billing groups**, if an institution's org structure or
  chargeback model changes later. `AssociateAccounts` itself refuses a currently-associated
  account (see "what enrollment does," above), so a real migration tool would need
  `DisassociateAccounts` plus a decision about who authorizes moving an account's costs into
  a different chargeback bucket after the fact — a real future question, not solved here, the
  same way `docs/reclaim-design.md` notes AWS's own 90-day account-reinstatement window as
  Support-mediated tooling out of scope for that design.
- **Any UI or reporting on the billing group's own cost data.** Pro-forma cost analysis,
  margin reports, and Cost and Usage Report configuration for a billing group are Billing
  Conductor's own console and API surface; automat's only interaction with a billing group,
  ever, is naming an account into it once.
- **Widening the onboarding bundle's vendor-role policy** for
  `billingconductor:AssociateAccounts`/`ListAccountAssociations` in the MEMBER-state case —
  this design settles that the vendor role is the right instrument (see "Delegability,"
  above) but the actual CFN/TF template change in `internal/bundle/policy.go` is
  implementation work for whichever task builds this, not a design question, noted here so
  it is not missed the same way `docs/reclaim-design.md` flags its own bundle-widening gap.
