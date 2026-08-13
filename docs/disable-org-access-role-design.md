# `disable_org_access_role_after_vend` — design

**Status: design authority for ROADMAP's `internal/baseline` slice 8, the one remaining
piece of DESIGN §7 step 5. Not yet built.** Follows the structure and rigor
`docs/hold-design.md` and `docs/billing-conductor-design.md` already established for a
contested design question in this codebase: settle the mechanism, confirm the AWS facts
against a live call or AWS's own current documentation, and name every schema/CLI
surface implication explicitly rather than let it surface later as a surprise.

## 0. Where this sits, and why it was deferred

`envprofile.Baseline.DisableOrgAccessRoleAfterVend` (`internal/envprofile/types.go`) already
exists as a schema field and a Go field — it has existed since the environment-profile
schema was first written. Every other piece of DESIGN §7 step 5 is built:
`EnsureAutomationRole`, `EnsureConfigRecorder`/`EnsureDeliveryChannel`, `EnsureConformancePack`,
`EnsureRegions`, `EnsureAttestationStubs` (`internal/baseline/*.go`). `cmd/automat/vend.go`'s
`stepFiveMissingPieces` names exactly one remaining gap — "disabling further use of
`OrganizationAccountAccessRole`" — and `recordStepFiveIsMissing` writes it into every plan and
every evidence manifest as `RecordUnknown("in-child baseline (DESIGN §7 step 5)", "NOT
PERFORMED by this build: ...")`. ROADMAP.md calls it "the smallest, most speculative" piece
because "the actual mechanism (a deny policy vs. narrowing assumability) is a real open design
question DESIGN §7 does not settle" — this document settles it.

DESIGN §7 step 5's own text: "Create the automat automation role in-account (least privilege
for future `verify`), then **optionally** disable further use of `OrganizationAccountAccessRole`
per the environment profile." DESIGN names the *intent* — a profile may ask for this — but not
the mechanism, which is exactly the gap ROADMAP flags and this document resolves.

## 1. The setting's own name assumes a mechanism it needs to make good on

`disable_org_access_role_after_vend` says "disable... the role," not "deny it" or "delete it."
That word is a real constraint on the answer, not just a label: whatever this builds has to be
something a reasonable reader would call "disabling the role," and — per §2 below — has to be
something an operator can walk back if the decision turns out to be wrong, the same
reversibility bar `docs/hold-design.md`'s SCP-layering answer met for a similarly shaped
question ("lock down without destroying").

## 2. What `OrganizationAccountAccessRole` actually is, confirmed against AWS's own current documentation

**Confirmed via AWS's own current documentation** (this environment has AWS CLI access and
valid credentials, but rule 1 forbids calling real AWS in anything read as a test; the facts
below are the kind rule 9 requires confirming against a live `describe`/`get` call OR the
service's own current documentation — here, documentation, because there is no running org to
query and no code drafted yet to test):

- **Automatic creation.** "When you create an account in your organization, in addition to the
  root user, AWS Organizations automatically creates an IAM role that is by default named
  `OrganizationAccountAccessRole`." (AWS Organizations User Guide, "Accessing member accounts in
  an organization with AWS Organizations.") `automat`'s own code already states this fact
  correctly: `envprofile.DefaultOrgAccessRole = "OrganizationAccountAccessRole"`, and
  `org.EnsureAccount` does not send `CreateAccountInput.RoleName`
  (`docs/cli-surface.md`'s D3), so the role that exists to assume, in every account `vend`
  creates, is always AWS's own default under AWS's own default name — never automat's chosen
  name, regardless of what an environment profile's `account.role_name` says.
- **Permissions.** "This role has full administrative permissions in the member account." (Same
  page, "Accessing a member account that has OrganizationAccountAccessRole with AWS
  Organizations.") It is not a narrow role; it is `AdministratorAccess`-equivalent, attached as
  the role's permissions policy at creation.
- **Trust.** "The scope of access for this role includes all principals in the management
  account, such that the role is configured to grant that access to the organization's
  management account." `internal/baseline.TrustPolicyJSON`'s own doc comment states the same
  thing for the *automation* role it renders, citing this exact behavior as precedent: "Trust is
  placed on the management ACCOUNT (a root-principal ARN), not on one role's ARN inside it,
  matching the shape AWS itself gives `OrganizationAccountAccessRole` by default (DESIGN §3 fact
  6)." That is: the default trust policy's `Principal` is
  `arn:aws:iam::<management-account-id>:root`, not a specific IAM user or role — any principal
  that can get management-account credentials, and has been separately granted `sts:AssumeRole`
  on this specific role ARN by its own account's IAM policy, may assume it.
- **Not deletable by the member account in any way that matters here.** Nothing in AWS's
  documentation states the member account can rename, remove, or otherwise alter the role's
  relationship to the management account without the management account's own cooperation
  (consistent with DESIGN §3 fact 12: "Member accounts cannot leave an org without management-
  account cooperation" — the same asymmetry).

## 3. The load-bearing fact that eliminates one whole candidate mechanism: SCPs cannot touch this at all

DESIGN §3 fact 7 states plainly: **"SCPs bind all principals in member accounts, including root
users. SCPs do not bind the management account."** AWS's own current documentation says the
identical thing in three places, confirmed by direct fetch of AWS's live documentation pages
during this design's research (not carried forward from memory, per rule 9):

- "SCPs don't affect users or roles in the management account. They affect only the member
  accounts in your organization." (Organizations User Guide, "Service control policies (SCPs).")
- "SCPs affect only *member* accounts in the organization. They have no effect on users or
  roles in the management account." (Same page, "SCP effects on permissions.")
- "You **can't** use SCPs to restrict the following tasks: Any action performed by the
  management account." (Same page, "Tasks and entities not restricted by SCPs.")

**Consequence, stated as bluntly as `docs/hold-design.md`'s own quota section states its
finding:** the whole point of `OrganizationAccountAccessRole` is that the calling principal for
an ordinary post-vend re-entry (a support case, a later automat feature, `automat`'s own future
operations if it ever needed this door) is a principal *in the management account*, assuming a
role whose trust is to the management account's root. Any SCP attached to the vended member
account's OU denies things to principals *in that member account* — it has no jurisdiction at
all over the calling side of a cross-account `sts:AssumeRole` where the caller is the management
account. Attaching a Deny-on-this-role SCP at the OU does not, and structurally cannot, stop the
management account from assuming `OrganizationAccountAccessRole`, because the request being
evaluated belongs to the management account's own permission universe, which is precisely the
one SCPs are documented to exclude.

This is not a subtle timing question the way Q13's ordering concern is (`docs/open-questions.md`
Q13, `internal/baseline/doc.go`'s own "ordering surprise" section) — it is a structural
impossibility, confirmed by AWS's own documentation stated three separate times on the same
page. **Candidate mechanism (c) from the task — "an SCP scoped to just this role's ARN,
analogous to `hold`'s design" — is eliminated outright, not merely disfavored.** `hold`'s own SCP
answer works for a completely different reason: `hold` denies *in-account* principals from
acting, and every principal `hold` needs to stop (an in-account IAM user, a role, even the root
user) is bound by the account's own SCPs. This task denies a principal *outside* the account
(the management account) from reaching *in*, which is exactly the direction DESIGN §3 fact 7 and
AWS's own documentation say SCPs cannot reach. Reusing `hold`'s precedent here would be applying
a pattern past the boundary where its own justification held.

## 4. The remaining candidates, confirmed against AWS's own current API documentation

With (c) eliminated, three candidates remain from the task's list. All four underlying API calls
were confirmed live via `aws iam <command> help` in this environment (AWS CLI 2.36.21, run
read-only, no state-changing call made against any account) — the CLI's bundled help text is
generated from the same API model AWS ships for the SDK, so this counts as a live confirmation
of the call's existence and current shape, not documentation carried forward from memory:

- **`aws iam update-assume-role-policy --role-name <value> --policy-document <value>`** exists
  today, described as: "Updates the policy that grants an IAM entity permission to assume a
  role. This is typically referred to as the 'role trust policy'." This is candidate (b) —
  rewriting the trust policy itself.
- **`aws iam delete-role --role-name <value>`** exists today. Its own help text warns: "Unlike
  the AWS Management Console, when you delete a role programmatically, you must delete the items
  attached to the role manually, or the deletion fails" (inline policies via `DeleteRolePolicy`,
  attached managed policies via `DetachRolePolicy`, any instance profile). This is candidate (d).
- **`aws iam put-role-permissions-boundary --role-name <value> --permissions-boundary <value>`**
  exists today. This is one reading of candidate (a).
- **`aws iam put-role-policy`** (inline permissions policy, already the exact call
  `internal/baseline.EnsureAutomationRole` and `internal/org.EnsureVendorRole` both use for their
  own roles) is the other reading of candidate (a): a deny-all inline policy written to the role.

**A fifth fact, confirmed against AWS's own IAM documentation, rules out one of these two
readings of (a) outright:** a permissions boundary does not affect whether a role **can be
assumed**. "A permissions boundary is an advanced feature for using a managed policy to set the
maximum permissions that an identity-based policy can grant to an IAM entity." (IAM User Guide,
"Permissions boundaries for IAM entities.") The evaluation-logic page states the same thing from
the enforcement side: a permissions boundary participates in evaluating *what an entity's
identity-based policies may grant it*, intersected with those policies — it is not consulted when
deciding whether an `AssumeRole` call against the role succeeds in the first place. The trust
policy (a resource-based policy, distinct from a permissions boundary) is what governs
`AssumeRole`; nothing in AWS's boundary documentation, and nothing in `PutRolePermissionsBoundary`'s
own help text, mentions the assume-role decision at all. **`PutRolePermissionsBoundary` is not a
usable mechanism for this task and is eliminated.** It would leave the role fully assumable and
only cap what the resulting session's own identity-based policies could grant — the opposite of
what "disable further use of" means, and in fact a strictly weaker lockdown than doing nothing,
because a permissions boundary is easy to mistake for "the role now does less" when it changes
nothing about who can get into it.

**That leaves three real candidates: (a-inline) a deny-all inline policy on the role's
*permissions*, (b) rewriting the role's *trust policy*, and (d) deleting the role outright.**

### 4a. Does a deny-all permissions policy actually stop the role from being *used*, or only from being *assumed*?

These are different claims and the task's own phrasing ("restricts further use of") does not
disambiguate them. AWS's documentation on revoking temporary credentials is direct on the
distinction and answers this decisively: "Temporary security credentials are valid until they
expire... Permissions assigned to temporary security credentials are evaluated **each time they
are used** to make an AWS request. Once you remove all permissions from the credentials, AWS
requests that use them fail." And, specifically for a deny-all rewrite of an existing
identity-based policy: "When you update the policy, the changes affect the permissions of all
temporary security credentials associated with the role, **including credentials that were
issued before you changed the role's permissions policy**." (IAM User Guide, "Disabling
permissions for temporary security credentials.")

So a deny-all inline policy on `OrganizationAccountAccessRole`'s *permissions* does two things at
once, confirmed by AWS's own documentation rather than assumed: it stops the role from doing
anything useful once assumed (every action inside the session evaluates against the new deny-all
policy, retroactively covering sessions already in flight), **and** it leaves `sts:AssumeRole`
itself untouched — the trust policy is a separate document, and nothing about rewriting the
permissions policy changes who may assume the role. An operator (or an attacker who had somehow
obtained management-account credentials) could still successfully call `AssumeRole` against this
role and receive valid temporary credentials; those credentials would simply be able to do
nothing, because every subsequent call fails against the deny-all policy.

This matters for how a reader is meant to describe the outcome. "Disable further use of
`OrganizationAccountAccessRole`" is satisfied by this reading in the sense that matters
practically — nothing can be *done* through the role anymore — but it is not satisfied in the
sense the setting's name most naturally suggests to an operator who has not read this document:
the assumption itself still succeeds, and would show up as a successful `AssumeRole` in
CloudTrail even though it accomplishes nothing.

### 4b. Trust-policy rewrite: removes assumability itself, but is a resource-based-policy change, not a Deny

Candidate (b) attacks the other half: `UpdateAssumeRolePolicy`, replacing the trust policy's
`Allow`-the-management-account-root statement with an empty statement list (a trust policy
document requires at least one statement; the narrowest form is a statement that allows nothing
by naming no matching principal, or naming a same-account principal that never calls). Unlike a
Deny in an identity-based policy, an empty or non-matching trust policy does not "deny" the
`AssumeRole` call in the sense of an explicit-deny override — it simply removes the only `Allow`
that ever let it succeed, and IAM's default is deny-by-default, so `AssumeRole` fails with
`AccessDenied` exactly as if no trust relationship had ever existed. IAM documentation confirms
`Effect: "Deny"` is syntactically valid anywhere a JSON policy statement appears, including a
trust policy, but AWS's own procedure for narrowing who may assume a role
("Update a role trust policy") only ever shows rewriting the `Principal` list under `Allow` — the
documented pattern is remove-the-allow, not add-a-deny, and remove-the-allow is sufficient
because there is nothing else in the account's evaluation chain that would otherwise grant the
assumption.

This candidate stops the assumption at the door, which (a-inline) does not.

### 4c. Deletion: irreversible in a way neither of the others is, and the role's own doc comments in this codebase already treat this class of action with extreme caution

`DeleteRole`'s own help text requires clearing every attached item first (inline policies via
`DeleteRolePolicy`, managed-policy attachments via `DetachRolePolicy`) — a multi-call sequence
with more surface for a partially-completed apply than either (a-inline) or (b), which are each
one call. Once deleted, the role — and its identity (`AROA...` unique id, referenced by any
existing IAM condition or CloudTrail record) — is gone; recreating a role with the same name
produces a **different** role with a **different** unique id, which is a fact the trust-policy
and inline-policy candidates never force into being true. `internal/org.EnsureVendorRole`'s own
doc comment states the reasoning this codebase already applies elsewhere for a sibling role: "No
DeleteRole, no DetachRolePolicy: nothing in Phase 3 removes a vendor role" — deletion has never
been this codebase's answer for a role AWS itself expects to persist as a stable identity.

## 5. Recoverability — none of the three real candidates is a one-way door in the same sense, but they differ sharply in cost

Per the task's own framing (CLAUDE.md rules 4 and 8, `docs/hold-design.md`'s "layering, not
detach-then-replace" precedent): if a `vend` disabled this role and something later needs the
management account to reach back into the child — a support case, a later automat feature,
disaster recovery when the automation role itself is somehow unusable — what is the path back?

- **(a-inline) deny-all permissions policy: fully recoverable, and cheaply.** `PutRolePolicy`
  with a new document overwrites the old one; the role's identity, its unique id, and its trust
  relationship to the management account all persist untouched throughout. Recovery is a second
  `PutRolePolicy` call carrying whatever permissions policy is wanted back — the exact same
  create-or-replace semantics `internal/baseline.EnsureAutomationRole` and
  `internal/org.EnsureVendorRole` already rely on for their own inline policies. This is the
  cheapest possible reversal: one idempotent write, no coordination with anything else in the
  account, no risk of a `DeleteRole` sequence failing partway through.
- **(b) trust-policy rewrite: fully recoverable, one call, but the FIX is a call this same role's
  door was just closed against making easily.** `UpdateAssumeRolePolicy` restoring the original
  `Allow`-the-management-account-root statement reopens exactly what was closed. The asymmetry
  worth naming: whoever restores it must already be calling as a principal who can reach the
  account by SOME other door (the automat automation role, if it is still assumable and still
  permissioned for `iam:UpdateAssumeRolePolicy` on this specific role — which BP.IAM-1 denies to
  every principal once baseline-protection is attached, per §7 below — or a human with console
  access some other way). This is not a one-way door in the technical sense (the call exists and
  is idempotent), but it is a door whose key is not automat's own automation role once
  baseline-protection has attached, for the same Q13-shaped reason `internal/baseline`'s own
  package doc already documents for that role's *permissions* policy.
- **(d) deletion: NOT reversible in the sense that matters.** `CreateRole` under the same name
  produces a role with a new, different unique identifier. Any resource-based policy, SCP
  condition, or CloudTrail-derived audit trail that referenced the old role's ARN by its
  underlying identity (rather than by the reusable name string) would not "reconnect" to the
  recreated role the way it would to a role whose trust or permissions policy was merely edited
  and restored. This is the one candidate genuinely eligible for "one-way door" in the practical
  sense CLAUDE.md rule 4's idempotency bar cares about, even though the individual API call
  itself is not the load-bearing irreversibility — the identity discontinuity is.

**This section's conclusion: (a-inline) and (b) are both cleanly reversible by a second call of
the same shape; (d) is not, in the identity-continuity sense that matters for an audit trail and
for any future automat feature that might want to name this role by ARN rather than rediscover
it.** Deletion is eliminated on recoverability grounds alone, independent of the "is it even the
right verb for 'disable'" question §4c also raises.

## 6. Interaction with the vendor role / broker path, and with automat's own ongoing operations — confirmed clean

The task asks this directly: does disabling `OrganizationAccountAccessRole` risk accidentally
touching automat's own control-plane credentials for ongoing operations (`verify`, `reclaim`, a
future re-vend)?

**Confirmed clean, by reading every caller.** `cmd/automat/verify.go` and `cmd/automat/reclaim.go`
were grepped directly for `OrganizationAccountAccessRole`, `DefaultOrgAccessRole`,
`childIAMRoleClient`, `childAccountClient`, and `childConfigClient` — the only names anywhere in
this codebase that route a session through this role. **Neither file references any of them.**
`verify` reads OU placement via the plain, native-or-delegated `awsapi.OrgAPI` (never brokered —
`verifyParentOf`'s own doc comment: "a read every state can make with its own credentials") and
checks attached policies via `awsapi.OrgVerifyAPI`; neither ever assumes into the child account at
all. `reclaim` detaches SCPs via the delegable `awsapi.OrgPolicyAPI`-shaped client and closes the
account via either the native or brokered vendor-role path (`reclaimOrgClients`) — again never
touching `OrganizationAccountAccessRole`.

The only three call sites in the entire tree that ever build a session through this role are
`cmd/automat/vend.go`'s own `childIAMRole`/`childAccount`/`childConfig` closures, feeding
`vendAutomationRoleStep`, `vendRegionsStep`, and `vendConformancePackStep`/`vendConfigRecorderStep`
— all four run **once, during the vend that creates the account**, before this feature would ever
fire (§7 below settles exactly when it fires, and it is necessarily after all four). Once a vend
completes, nothing in `verify`, `reclaim`, or a later re-vend's SCP-attachment/policy-check steps
reaches through `OrganizationAccountAccessRole` again. **automat's own control plane for ongoing
operations against a vended account is the automation role (`automat-automation`) plus the
delegated/native Organizations credentials — never the generic AWS backdoor role.** Disabling
`OrganizationAccountAccessRole` after a vend completes cannot break any command this codebase
ships today, because none of them use it after that point.

One live nuance worth stating precisely rather than glossing: in the **MEMBER** state,
`childIAMRoleClient` still calls `g.stsClient` — the caller's own native credentials, built from
whatever the ambient AWS credential chain resolves (`awsConfig`/`LoadDefaultConfig`), **not** the
brokered vendor-role session `vendOrgClient` builds for account/OU operations in that same state.
This is correct rather than an oversight: `OrganizationAccountAccessRole`'s trust policy names the
whole management account root as principal, and DESIGN §5 places the calling operator for a
MEMBER-state vend as a principal *inside* that management account (running `automat vend` with
their own management-account credentials, which is what makes them able to reach the vendor
role's trust in the first place) — so the assumption succeeds on the caller's own identity, no
broker required, matching `internal/baseline`'s own `TrustPolicyJSON` doc comment: "Trust is
placed on the management ACCOUNT... not on one role's ARN inside it... so a later caller may
assume this role later without a second grant naming a role that may not even exist yet." The
same reasoning applies to `OrganizationAccountAccessRole` itself, which is AWS's own instance of
exactly this shape.

## 7. Ordering: this runs LAST, after everything else in the baseline stage, for the same Q13-shaped reason `EnsureAutomationRole` runs FIRST

`internal/baseline`'s package doc already documents an ordering hazard for the opposite end of
this same problem: the automation role must be created and permissioned **before**
baseline-protection attaches, because once attached, BP.IAM-1 denies `iam:Update*/Delete*/Put*/
Attach*/Detach*` on `OrganizationAccountAccessRole` and the automation role, to every principal in
the account, with **no exemption at all** — not even automat's own automation role
(`catalogs/baseline-protection.json`'s own control text, confirmed present: `"arn:aws*:iam::*:role/
OrganizationAccountAccessRole"` and the automation role both appear as `Resource` entries under
that exact action list).

This feature sits on the far side of that same fence. Disabling `OrganizationAccountAccessRole` —
whichever of (a-inline) or (b) is chosen — means calling `iam:PutRolePolicy` or
`iam:UpdateAssumeRolePolicy` against `OrganizationAccountAccessRole` itself. **If baseline-
protection is already attached to the OU by the time this step would run, that exact call is
denied by BP.IAM-1, to automat's own automation-role session and to any other principal in the
account alike, with no exemption to grant around it.** This is not a hypothetical timing risk the
way Q13's original propagation-delay concern was — it is the same control, read plainly, applied
to the other named role in its `Resource` list.

**Consequence for where this step must run in `runVendSteps`: strictly LAST, after
`e.EnsurePolicySet` attaches the OU's policy set (`vend.go` line ~868), never alongside
`vendAutomationRoleStep`/`vendRegionsStep`/`vendConformancePackStep`/`vendConfigRecorderStep`, which
all run BEFORE the SCP set for the reason `internal/baseline`'s own doc comment gives.** This is
the reverse of the automation role's own ordering constraint, and for the identical underlying
control: the automation role must be permissioned before baseline-protection attaches because
baseline-protection would then block permissioning it; this feature must run before
baseline-protection attaches for the same reason, because baseline-protection would then block
disabling `OrganizationAccountAccessRole` at all. Both facts are really one fact — BP.IAM-1 denies
mutating either named role, unconditionally, once attached — read from its two opposite
consequences.

This has a real, disclosable effect on what "disable further use of the role" can mean by the
time it runs: the automation role, region enablement, the conformance pack, and the Config
recorder/delivery channel (all four of `vendAutomationRoleStep`'s siblings) have ALREADY used
`OrganizationAccountAccessRole` earlier in the same vend, by design — this step is not first, it
is second-to-last, running immediately before `EnsurePolicySet`. There is no ordering that lets
"disable the role" run first without breaking the four baseline steps that legitimately need it.
**The re-vend/idempotency case that follows directly from this ordering: a later `vend --resume`
or plain re-run against an account whose `OrganizationAccountAccessRole` is already disabled must
not need to re-enable it to redo any of the four earlier baseline steps.** Since all four already
carry their own read-first idempotence (`EnsureAutomationRole`'s `GetRole`-then-compare,
`EnsureConfigRecorder`'s `DescribeConfigurationRecorders`-then-compare, and so on) and report
`VerbUnchanged` when nothing has drifted, an ordinary re-run against an unchanged profile issues
no write at all through any of them — so it never needs to call through the now-disabled role a
second time. The genuinely hard case — a re-vend that needs to CHANGE something the earlier steps
established, against an account whose door is now closed — is symmetric with Q13's own "an
automation-role policy change is a migration, not an upgrade" conclusion, and gets the identical
answer: re-opening `OrganizationAccountAccessRole` (§8's `EnsureOrgAccessRoleDisabled`, called with
the desired state flipped back to "enabled" via a profile edit) is itself an ordinary,
idempotent, reversible operation per §5 above, available to an operator who needs to redo earlier
baseline work against an account this feature already locked down.

## 8. Decision: candidate (a-inline), with (b) named as the natural v2 escalation, never (c) or (d)

**Recommendation: v1 implements candidate (a-inline) — a deny-all inline permissions policy
written to `OrganizationAccountAccessRole` via `iam:PutRolePolicy`, the same call and the same
create-or-replace semantics `EnsureAutomationRole` and `EnsureVendorRole` already use for their
own roles.** Rationale, weighed against the alternatives settled above:

- **It actually satisfies "disable further use of" in the sense that matters for a compliance
  posture.** Nobody assuming this role again can do anything with the resulting session — every
  subsequent call evaluates against the deny-all policy, confirmed by AWS's own documentation to
  apply retroactively to any session already in flight, not merely to future assumptions. That is
  a strictly stronger practical guarantee than (b) provides on its own: (b) stops new
  `AssumeRole` calls but does nothing about a session obtained a moment before the trust policy
  changed (that session's temporary credentials remain fully privileged, per AWS's own
  distinction between "who may assume" and "what an assumed session may do," until they expire —
  up to 12 hours later under this role's default duration settings). (a-inline) closes that gap;
  (b) alone does not.
- **It is the cheapest, cleanest reversal (§5).** One `PutRolePolicy` call restores the prior
  permissions policy exactly, no role-identity discontinuity, matching the "ensure" semantics
  CLAUDE.md rule 4 requires everywhere in this codebase and the same reasoning
  `docs/hold-design.md` gives for choosing SCP-layering over "detach-then-replace" in a
  differently-shaped but analogous "lock down without destroying" decision.
- **It reuses machinery this package already has, rather than inventing a new one.** Every method
  in `internal/baseline` that touches a role's policy — `EnsureAutomationRole`'s
  `createAutomationRole`/`updateAutomationRole` — already does exactly this shape of read-then-
  write against `PutRolePolicy`, with the identical Q13-aware remediation-text branching
  `updateAutomationRole` already carries for a denial that might be BP.IAM-1 rather than an
  ordinary missing grant. The new method is a sibling, not a new pattern.
- **(b) is named as the natural v2 escalation, not rejected outright.** If a future audit or
  regulatory reading demands that `AssumeRole` itself fail — not merely that the resulting
  session be powerless — (b)'s trust-policy rewrite is the correct next step, and nothing about
  building (a-inline) first forecloses it: the two are independent axes (permissions vs. trust),
  and a v2 could apply both, in the same "layer, don't replace" spirit `hold`'s SCP answer
  already established for this codebase. This document does not build (b) now because
  (a-inline) already delivers the practical guarantee the setting's own doc comment describes
  ("restricts further use of"), and adding a second IAM call (`UpdateAssumeRolePolicy`) to every
  vend that opts into this is added surface — an added failure mode, an added remediation-text
  branch, an added idempotency check — for a marginal gain (closing the brief already-in-flight-
  session gap) that is real but narrow, and better justified by an actual future requirement than
  built speculatively now. Should a future revision add (b), it composes: apply (a-inline) first,
  then (b), in that order, since (b) removes the very assumability that let (a-inline) get
  written in the first place — reversing that order would mean the deny-all write itself needed
  a door that had already been closed one step earlier.
- **(c) is not merely disfavored — it is eliminated per §3.** An SCP cannot bind the management
  account under any framing; there is no version of this feature built on an SCP that could work.
- **(d) is eliminated per §4c and §5** on both "is deletion even 'disabling'" grounds and
  recoverability grounds: it is the one candidate that is not cleanly reversible in the sense
  that matters (role-identity discontinuity), for no compensating benefit over (a-inline) or (b).

## 9. What `EnsureOrgAccessRoleDisabled` (or the fitting name) needs to plan/report/verify, following the existing six methods' shape

Naming convention: the existing six methods are all `Ensure<Noun>` — `EnsureAutomationRole`,
`EnsureConfigRecorder`, `EnsureDeliveryChannel`, `EnsureConformancePack`, `EnsureRegions`,
`EnsureAttestationStubs`. Following that pattern exactly: **`EnsureOrgAccessRoleDisabled`** (not
`EnsureOrgAccessRoleDisable` — the field this method serves,
`DisableOrgAccessRoleAfterVend`, is a boolean *state* the profile wants ensured, matching how
`EnsureConfigRecorder` ensures a recorder's *state* — enabled, configured, recording — rather than
performing a bare verb).

**Shape, in prose, mirroring `EnsureAutomationRole`'s own read-first/plan-vs-apply/Q13-aware
structure:**

- **Signature**, matching the existing methods' pattern of taking an already-assumed client
  (never constructing one itself, per `internal/baseline/doc.go`'s "what this package does not
  construct" section): `EnsureOrgAccessRoleDisabled(ctx, roleName string) (actions []org.Action,
  err error)`. Takes `e.Role` (the same `awsapi.IAMRoleAPI` field `EnsureAutomationRole` already
  uses) built against a session assumed into the child via `OrganizationAccountAccessRole`
  itself — the same session `vendAutomationRoleStep` already builds via `childIAMRole`, reused
  rather than a second assumption, since this step must run through that exact role to reach it
  (assuming a role in order to disable itself is fine; the disabling write is the last thing that
  session ever does).
- **Read-first.** `GetRolePolicy` for a known, fixed inline-policy name (parallel to
  `AutomationRolePolicyName`; call it `OrgAccessRoleDisablePolicyName`, e.g.
  `"automat-org-access-disabled"`) to learn whether the deny-all policy is already written and,
  if so, whether it matches what this build would render. `org.SameDocument` for the structural
  comparison, the same helper `updateAutomationRole` already uses.
- **Three outcomes, matching `EnsureAutomationRole`'s and every other `Ensure*` method's own three-
  way branch:**
  - **Not yet disabled** (no such inline policy, or an inline policy present but not the
    deny-all shape this build renders) → `VerbCreate` (if this is a genuinely new state — the
    permissions policy has never been touched by automat before) or `VerbUpdate` (if some
    other automat-owned inline policy already existed under a name that must now be replaced,
    though in practice a fresh deny-all write on a role that has only ever carried
    `AdministratorAccess`-equivalent-by-omission is always the create case): write, record
    `Applied: true`.
  - **Already disabled, matches** → `VerbUnchanged`, no write — the ordinary re-vend case,
    matching every other method's idempotence.
  - **Plan mode** → report what would happen without calling `PutRolePolicy`, the identical
    `e.planning()` branch every other method in this package already takes.
- **Q13-aware remediation text on a denial**, the exact shape `updateAutomationRole` already uses
  for its own `PutRolePolicy` calls, adapted to name `OrganizationAccountAccessRole` rather than
  the automation role: an `AccessDenied` here, if baseline-protection is already attached, states
  BOTH readings — "if baseline-protection is attached to this OU, BP.IAM-1 denies `iam:Put*` on
  this role to every principal in the account, with no exemption — detach it, apply, re-attach;
  if NOT attached, grant `iam:PutRolePolicy` on this role's ARN to [principal] instead." This is
  not speculative reuse — it is the SAME control (`BP.IAM-1`'s `Resource` list already names
  `OrganizationAccountAccessRole` explicitly, confirmed in §7) producing the identical failure
  mode for the identical reason, so the identical dual-reading remediation text is correct here
  for the same reason it is correct in `updateAutomationRole`.
- **No poll loop.** `PutRolePolicy` is synchronous (the same reasoning every other inline-policy
  write in this package already relies on — `EnsureAutomationRole` never polls after
  `PutRolePolicy` either), so this method needs none of `Ensurer`'s `PollInterval`/`MaxPolls`/
  `Sleep` machinery.
- **A no-op branch when the profile does not ask for this**, matching `vendAutomationRoleStep`'s
  own first branch ("A no-op when the profile says not to create one... `ShouldCreate()` reports
  false"): `vendOrgAccessRoleDisableStep` (the `cmd/automat/vend.go`-side wrapper, matching the
  naming of `vendAutomationRoleStep`/`vendRegionsStep`/etc.) checks
  `in.Profile.Baseline.DisableOrgAccessRoleAfterVend` and returns immediately if false — the
  field already exists and already defaults to `false` (schema default, confirmed in
  `schema/environment-profile-v1.schema.json`), so an environment profile that says nothing gets
  exactly today's behavior: the role stays open, matching AWS's own default.
- **Where it plugs into `runVendSteps` (`vend.go`):** as the very last baseline action, after
  `e.EnsurePolicySet` (per §7's ordering argument) and therefore after `recordStepFiveIsMissing`'s
  current unconditional `RecordUnknown` call is narrowed to stop firing when this feature is
  built and requested (see §10 for the required code-side follow-up to that function once this
  ships).

## 10. Schema and CLI-surface implications — the pre-approval list this document owes per CLAUDE.md

Per CLAUDE.md's own rule: "Ask the human before: adding any dependency beyond the ones named
here, changing the schema, or altering CLI surface/flags." Named precisely, as this task
requires, rather than left to surface later:

- **No new environment-profile field.** `Baseline.DisableOrgAccessRoleAfterVend bool` already
  exists, already has a schema entry
  (`schema/environment-profile-v1.schema.json`'s `disable_org_access_role_after_vend`, `type:
  boolean`, `default: false`), and this design's recommended mechanism (a-inline) needs no
  further input from the profile — no policy-content override, no "which role" (the role is
  always `OrganizationAccountAccessRole`, per §2's confirmation that automat cannot even choose a
  different name today), no reason string the way `hold`'s design needed one. **Nothing to ask
  for here.**
- **No new `evidence.Operation` enum value.** Unlike `hold` (which needed `OpHold` because it is
  a new, separately-invoked command with its own evidence semantics), this feature is one more
  action inside the SAME `vend` operation `OpBaselineApply`/`OpSCPEnsure` already cover. The right
  evidence shape is a plain `org.Action` (`VerbCreate`/`VerbUpdate`/`VerbUnchanged`, `Kind:
  "management-assumable role"` or similar) folded into the existing baseline-apply action stream
  the same way `EnsureAutomationRole`'s own actions already are — **no schema change, no new
  operation value.** This should be double-checked against whatever slice 7 (evidence/manifest
  wiring, ROADMAP's "internal/baseline" item 7 — replacing `recordBaselineIsMissing` with real
  `OpBaselineApply` records) actually lands as, since that slice is listed ahead of this one and
  this document assumes its `Enforcement` fields (`ConformancePackARN`,
  `ConfigRuleNames`, etc.) are the model to extend from, not replace.
- **No new `org.Verb`.** Every outcome this method produces (create/update/unchanged the inline
  policy) is already covered by `VerbCreate`/`VerbUpdate`/`VerbUnchanged` — unlike `hold`, which
  needed `VerbHold` because attaching a hold-lockdown SCP is observably different from an ordinary
  vend's policy-set attach and a reader needs to see that at a glance. Disabling this role's
  permissions is not a different KIND of action from what `EnsureAutomationRole` already does to a
  different role — it is the identical operation (write an inline policy to a role) aimed at a
  different target, so it does not need a vocabulary word of its own the way `hold`'s SCP-attach
  did.
- **No CLI flag change.** This is driven entirely by the existing environment-profile field, read
  during the existing `vend` command's existing flow — no new `vend` flag, no new subcommand.
  **Nothing to ask for here either.**
- **One narrowing of existing, already-shipped disclosure text that DOES need to happen once this
  ships, named so it is not missed:** `cmd/automat/vend.go`'s `stepFiveMissingPieces` and
  `recordStepFiveIsMissing` currently report this as unconditionally missing whenever a profile
  sets `disable_org_access_role_after_vend: true`. Once `EnsureOrgAccessRoleDisabled` exists and is
  wired into `runVendSteps`, `stepFiveMissingPieces` must stop naming this piece — the function's
  own doc comment already anticipates exactly this: "Only slice 8... remains... a later build
  will [change that]." This is a code change inside the existing `vend` command's existing
  behavior, not a schema or CLI-surface change, but it is called out here because
  `TestVendBirthCertificateReportsThePartlyAppliedCaseForDisableOrgAccessRole`
  (`cmd/automat/vend_test.go`) currently asserts the OLD, "not performed" behavior by name and
  must be rewritten to assert the NEW, "performed" behavior instead — a test whose current passing
  state would otherwise silently start asserting a stale claim once the feature ships under it.

## 11. What this design deliberately does not cover

- **Re-enabling the role (an `--yes`-gated "undo").** Per §5, restoring the prior permissions
  policy is a plain, idempotent `PutRolePolicy` call — but there is no `vend`-side plumbing today
  for "re-vend with `disable_org_access_role_after_vend: false` against an account where it was
  previously `true`" to actually issue that write, versus merely reporting `VerbUnchanged`-shaped
  silence because the profile no longer names the setting at all (the "no-op branch" in §9 returns
  early on `false`, and a profile that flips from `true` to `false` hits that same early return —
  it does not know to actively RESTORE a permissions policy it never wrote in the first place,
  because the desired-state model here is "ensure disabled," not "ensure disabled OR restore on
  request"). If an operator needs the restore path, today's shape gives them the raw call
  (`aws iam put-role-policy` with the desired permissions document, run by hand, same as any
  manual IAM remediation), not a first-class `automat` command. Whether that gap is acceptable for
  v1 or needs its own explicit `vend --restore-org-access-role`-shaped follow-up is a question this
  document raises but does not answer, matching `hold`'s own precedent of explicitly scoping
  "release" out rather than improvising an answer under a different task's own settlement.
- **Trust-policy rewrite (candidate (b)) as a v1 feature.** Named in §8 as the natural v2
  escalation, not built now.
- **Any mechanism for an institution to customize what "disabled" means** (a narrower deny than
  deny-all, an allowlist of a few read-only actions the way `hold`'s lockdown SCP allows a narrow
  read/inspect allowlist). `hold`'s catalog-driven, reviewable-content answer fits its own
  problem because `hold`'s Deny statement is genuinely new control CONTENT that belongs in a
  catalog for the reasons `docs/hold-design.md` §1 gives. This feature's deny-all inline policy is
  not control content in that sense — it does not enforce a compliance practice against every
  vended account the way `baseline-protection` or a hold-lockdown catalog does; it is a per-role,
  per-account operational lockdown triggered by one boolean, and does not need — and per §10
  should not acquire — a catalog entry of its own. If a future need for a narrower-than-deny-all
  posture emerges, that is new information this design does not have, matching
  `docs/hold-design.md`'s own closing-section discipline for scoping additions it cannot yet
  justify.

## 12. Summary table

| Candidate | What it touches | Assumability after? | Reversible? | Verdict |
|---|---|---|---|---|
| (a-inline) deny-all inline permissions policy | Role's identity-based (permissions) policy | Yes — `AssumeRole` still succeeds, session is powerless | Yes — one `PutRolePolicy` call restores prior policy exactly | **Recommended for v1** |
| (b) trust-policy rewrite | Role's resource-based (trust) policy | No — `AssumeRole` itself fails | Yes — one `UpdateAssumeRolePolicy` call restores prior trust statement | Named as v2 escalation, not built now |
| (c) SCP on the role's ARN | An OU-level policy | No effect at all — SCPs cannot bind the management account (DESIGN §3 fact 7, confirmed against AWS's own documentation) | N/A | **Eliminated — structurally impossible, not merely disfavored** |
| (d) `DeleteRole` | The role's existence | N/A — role no longer exists | No — recreated role has a new, different identity | **Eliminated — not "disabling," and not reversible in the sense that matters** |

## 13. Confirmation ledger — what is live-confirmed, what is documentation-confirmed, what remains unconfirmed

Per CLAUDE.md rule 9 and the task's own request to be explicit about the difference:

- **Live-confirmed in this environment** (AWS CLI 2.36.21, `aws iam <command> help`, no
  state-changing call made): `update-assume-role-policy`, `delete-role`,
  `put-role-permissions-boundary`, and `put-role-policy` all exist today under exactly these
  names and parameter shapes.
- **Documentation-confirmed** (direct fetch of AWS's own current, live documentation pages during
  this design's research, quoted verbatim above rather than recalled from memory): every fact in
  §2 (role creation, permissions, trust default), §3 (SCPs never bind the management account, in
  three separate statements on AWS's own page), §4a (permissions-boundary evaluation does not
  gate `AssumeRole`; deny-all permissions-policy changes apply retroactively to already-issued
  sessions), and §4b (trust-policy Deny is syntactically valid but AWS's own documented procedure
  is remove-the-allow).
- **Not live-confirmed against a real organization, and stated as such rather than guessed:**
  whether `PutRolePolicy` against `OrganizationAccountAccessRole` from within a session assumed
  through that SAME role (as opposed to from the automation role, which is what Q13's own
  live-sandbox note says has "not [yet] reached" this exact test) behaves exactly as documented
  once baseline-protection is attached in a live org — this is the identical unresolved half of
  Q13 (`docs/open-questions.md`'s own "First live sandbox run (2026-08-10): not reached" note),
  now inherited by this feature rather than newly introduced by it. **What would confirm it:**
  the same smoke-runbook shape Q13 already names — after a live vend with
  `disable_org_access_role_after_vend: true` completes and baseline-protection is attached, attempt
  `aws iam put-role-policy` against `OrganizationAccountAccessRole` from the automation role's own
  assumed session and confirm the denial reads as BP.IAM-1's Deny rather than an ordinary missing
  grant; separately, attempt `aws sts assume-role` against `OrganizationAccountAccessRole` from
  management-account credentials post-disable and confirm the deny-all inline policy actually
  renders the resulting session powerless against a representative read call (e.g.
  `iam:ListRoles`), per §4a's documented-but-not-yet-observed claim about retroactive session
  effect.
