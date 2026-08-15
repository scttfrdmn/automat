# Testing against AWS: three tools, none replacing the others

Referenced by `CLAUDE.md`. `internal/awsfake`, an AWS emulator, and `internal/smoke`'s
live-AWS suite each test a different thing, and a package moves to a heavier tier only
when that tier can express what the package's tests actually assert.

## The fakes test automat's REACTION to adversarial state transitions

`OrgState`'s `Before` hook exists because ensure semantics must survive the organization
moving underneath a call that has already been decided on — read-first-and-tolerate is
built entirely on that TOCTOU window (`docs/open-questions.md` Q12). Expressing it requires
a call to **succeed** against state that changed mid-flight. A fault controller that fails
calls cannot host those tests; failing a call is the one thing the window is not.

## The emulator tests that automat's REQUESTS are well-formed and IAM-enforced

Against a real authorization path — that a policy document is accepted, that a condition
key actually gates the call, that a trust policy admits the principal automat assumes.
Hand-rolled fakes say yes because they were written to say yes.

## `internal/smoke` tests what neither a fake nor the emulator can: undocumented real-AWS behavior

`docs/smoke.md`'s checklist — `MoveAccount`'s source-parent authorization, the timing
between `CreateAccount` and a move that can follow it, whether an `aws:ResourceTag`
condition actually binds — are not questions about automat's own code, and not questions
about IAM enforcement an emulator's auth controller can answer either, because the
emulator's own behavior on these points is itself an assumption, not a fact borrowed from
AWS. Only a real organization settles them. `internal/smoke` (every file `//go:build
smoke`) is gated identically to CLAUDE.md rule 1's carve-out: never in CI, never on
ambient credentials, read-only except against a sandbox verified at runtime. See
`docs/smoke.md` for how to run it and what it can and cannot yet answer on its own
(a few of the checklist's questions need `internal/baseline` or a deployed onboarding
bundle to answer for real, and the corresponding subtests say so rather than guessing).

## Keep all three

Do not migrate a package to the emulator because the emulator exists, and do not reach
for `internal/smoke` for something a fake or the emulator can already express. Migrate
when a tier's tests' subject is expressible there, and say in the commit which of the
three things the moved or added tests were testing.

## Emulator integration lives in a SEPARATE GO MODULE

`test/integration/go.mod`, run from its own make target (`make integration`) and never from
the default `make test` gate. Not a style preference: a dependency's `go` directive floor
propagates to everyone who runs `go install` on the main module, regardless of which files
import it — so test-only *in intent* is not test-only *in effect* within one module.
automat's floor stays at 1.24 and the emulator ([`scttfrdmn/substrate`](https://github.com/scttfrdmn/substrate))
stays out of automat's dependency graph.

## `internal/broker` is the first (and so far only) package that migrated

`test/integration/broker_test.go` exercises `broker.Assume` against a real running
substrate server (`emulator.StartTestServer`) rather than `awsfake.STS` — the wire-format
correctness (HTTP, XML marshaling, response parsing) a hand-rolled fake cannot get wrong
by construction, because it never parses anything off a wire.

**It now also tests the property Task 4 was originally scoped to test, and did not at
first.** ROADMAP.md's justification for reaching for an emulator here was that substrate's
auth controller enforces a role's trust policy — including the `sts:ExternalId` condition —
on `AssumeRole`. Substrate v0.94.0 did not do this: `AssumeRole` verified only that the
named role existed, never reading `AssumeRolePolicyDocument` or evaluating an `ExternalId`
against it. Filed as [substrate#593](https://github.com/scttfrdmn/substrate/issues/593);
fixed in **v0.95.0**, which this module now pins.

Trust-policy enforcement needs a **signed, real principal** — substrate's own testing guide:
"existence in state is the opt-in", and an unauthenticated caller (the `test`/`test`
credentials this module still uses for setup calls like `CreateRole` and `CreateUser`) is
never evaluated against anything, trust policies included. `signedMemberCaller` mints a
real IAM user and access key for exactly this reason.

- `TestBrokerAssumeSucceedsWithTheRightExternalId` and `TestBrokerAssumeFailsWithNoExternalId`
  are the confused-deputy defense itself: a signed caller the trust policy's `Principal`
  admits, with and without the correct `sts:ExternalId`.
- `TestBrokerAssumeFailsForAnUntrustedPrincipal` is the other half: correct `ExternalId`,
  wrong account.
- `TestBrokerAssumeIsRejectedForAnUnknownRole` is unrelated to trust-policy enforcement — a
  role absent from state entirely, refused with a real HTTP-level `NoSuchEntityException`,
  which is the class of thing a fake cannot get wrong by construction because it never
  parses an error off the wire.

## Substrate v0.95.0 → v0.101.0 (2026-08-09 to 2026-08-15): every tracked gap closed

`test/integration` now pins **v0.101.0**. Across six releases in seven days, substrate's
Organizations, Account Management, Service Quotas, IAM, and Config plugins went from
"describes an organization, cannot say whether a call is allowed, has no detective
controls at all" to covering every AWS surface `internal/org`, `internal/preflight`, and
`internal/baseline` depend on — which changes what belongs in this tier's scope, not
merely what version number is in `go.mod`. Every substrate gap this project ever filed or
tracked (#577, #578, #579, #580, #619, #623, #624, #625, #629) is now **closed**.

**What v0.96.0–v0.99.0 actually added, in order:**

- **v0.96.0**: `iam:UpdateAssumeRolePolicy` (trust-policy tightening in place, the CDK/
  Terraform shape); every service's `AccessDenied*` code now follows its real wire
  protocol instead of one generic string (a **breaking** change for any test asserting
  `AccessDeniedException` against an XML-protocol service — `automat`'s own tests assert
  no such literal, confirmed by grep before upgrading, so this cost nothing here); the
  configured event-store backend actually persists.
- **v0.97.0**: the OU tree, asynchronous account vending (`CreateAccount` now genuinely
  returns `IN_PROGRESS` with a real `car-` request id, matching what `internal/org`'s own
  poll loop already assumes), the full SCP lifecycle including `EnablePolicyType`/
  `DisablePolicyType` and the "SCPs disabled on the root" trap DESIGN §3 fact 8 exists
  because of, resource tagging with `aws:ResourceTag`/`aws:RequestTag` condition-key
  enforcement (Q8/Q9's own open questions), and a stable root identity.
- **v0.98.0**: the organization's resource policy (`PutResourcePolicy`/
  `DescribeResourcePolicy`/`DeleteResourcePolicy`), and the `organizations` Service Quotas
  entries including `L-E619E033` ("Maximum number of accounts") seeded at the value
  substrate's own plugin enforces.
- **v0.99.0**: the fix that made v0.98.0's resource-policy plugin actually answer Q5 —
  substrate previously keyed all Organizations state by the caller's own account with no
  member→management index, so a member account calling any Organizations operation was
  silently handed a brand-new organization of its own rather than the one it actually
  belongs to (substrate#623). Also added: the **Account Management Region opt-in API**
  (`ListRegions`/`GetRegionOptStatus`/`EnableRegion`/`DisableRegion`, closing
  [substrate#629](https://github.com/scttfrdmn/substrate/issues/629), filed by this
  project) and **`CloseAccount`** (closing substrate#625's item 2, including the exact
  `L-E619E033` quota interaction this project confirmed live and recorded in
  `docs/reclaim-design.md` — a closed account keeps its place in the org, stays in
  `ListAccounts`, and keeps counting against the quota). Also fixed: Service Quotas
  increase requests now file under the real caller's account rather than a placeholder
  `000000000000` (substrate#624).
- **v0.100.0**: `SimulatePrincipalPolicy` and `SimulateCustomPolicy` (closing
  [substrate#579](https://github.com/scttfrdmn/substrate/issues/579)) — running the
  **same evaluator the request gate itself enforces with**, so a simulated answer cannot
  disagree with what an actual call would do. Reports `allowed`/`explicitDeny`/
  `implicitDeny` as three distinct outcomes, `MatchedStatements` (which policy decided),
  and `MissingContextValues` — everything `preflight`'s own simulated-permission check
  reads. Explicitly, correctly, does **not** evaluate SCPs (substrate stores them but
  `CheckAccess` never consults them either), so a simulated allow here carries the exact
  same caveat `preflight`'s own doc comment already states about real IAM: SCP effects
  are invisible to simulation, full stop, on both AWS and substrate. Also added IAM group
  support (a prerequisite for a correct simulation, not an extra) and `GetPolicyVersion`/
  `ListPolicyVersions`, which is what makes a simulated `implicitDeny` checkable — the
  caller can now read the policy that failed to grant it.
- **v0.101.0**: AWS Config, taken whole (closing
  [substrate#580](https://github.com/scttfrdmn/substrate/issues/580)) — 25 operations
  covering the recorder, delivery channel, Config rules, and conformance packs, exactly
  the surface `internal/baseline`'s `EnsureConfigRecorder`/`EnsureDeliveryChannel`/
  `EnsureConformancePack` drive. Models the identical "created but not started" trap
  those three methods' own doc comments already name as the reason they read-then-branch
  twice rather than once: `PutConfigurationRecorder` leaves `recording: false`, only
  `StartConfigurationRecorder` flips it, and the two are genuinely separate wire calls
  with genuinely separate refusal shapes (`NoAvailableDeliveryChannelException` for one
  ordering mistake, `NoAvailableConfigurationRecorderException` for the other). Every
  state key carries the Region, matching `EnsureRegions`' own region-scoped baseline
  model. `PutDeliveryChannel`'s S3 refusals are computed from real S3 bucket-policy
  state in the same emulator, which is the kind of cross-service check a hand-rolled fake
  cannot express by construction. Compliance is seeded, never computed — an unevaluated
  rule reports `INSUFFICIENT_DATA`, matching real AWS, not a free `COMPLIANT` — so a test
  asserting on compliance state must seed it explicitly rather than rely on emulator
  inference.

**What this means for `docs/open-questions.md`'s live-org-only entries.** Several of the
questions this project's own `docs/smoke.md` runbook lists as needing a real organization
are now expressible against a deterministic emulator — not a replacement for the live-org
answer (an emulator's own behavior is a model of AWS, not AWS), but a way to develop and
regression-test the *code path* against a realistic authorization surface before ever
touching a sandbox org:

- **Q5** — now genuinely testable for the first time: substrate v0.99.0's member→
  management index means a member account's `DescribeResourcePolicy` call resolves against
  the organization it actually belongs to, with three distinguishable answers ("nothing
  delegated", "something delegated but unreadable", "readable"). Worth a migration
  evaluation before spending live-org headroom on this question.
- **Q8/Q9** (`MoveAccount`'s `aws:ResourceTag` condition, source-vs-destination-parent
  authorization) — substrate v0.97.0's tag-condition enforcement and OU/root modeling are
  exactly the mechanism these two questions are about. Worth a migration pass, with the
  same caution as always: check whether substrate's `MoveAccount` implementation is
  answering from AWS's own documented behavior or from an assumption its authors made,
  before treating an emulator result as the live-org answer (this file's "Keep all three"
  section).
- **Q13** (`BP.IAM-1`'s ordering constraint) — substrate v0.96.0's `UpdateAssumeRolePolicy`
  plus its real authorization path can now express "can a Deny SCP actually block a
  `PutRolePolicy` call once attached", the mechanical half of Q13. The *timing* half (how
  long after `AttachPolicy` a Deny becomes effective) is still real-AWS-only — an emulator
  has no propagation delay unless it deliberately models one.
- **Q24** (`reclaim`'s detach-then-close timing assumptions) — substrate v0.99.0's
  `CloseAccount` resolves `PENDING_CLOSURE` → `SUSPENDED` on first observation (no
  wall-clock dependence), which can exercise `reclaim`'s own poll/park logic against a
  believable async shape, though not the *real* propagation-delay timing Q24 is ultimately
  asking about.

**`preflight`'s simulated-permission check is now migratable.** `internal/preflight`'s
`checkPermissions` (DESIGN §4/§13) calls `iam:SimulatePrincipalPolicy` and reports
`Certainty: Simulated` precisely because a simulated allow does not account for SCPs —
substrate v0.100.0's own implementation makes that exact same disclosure for the exact
same reason, so an emulator-tier test of this check would be validating automat's own
Simulated/Observed distinction against a real (if not real-AWS) evaluator rather than a
fake that was written to say yes. Worth a migration evaluation.

**`internal/baseline`'s Config-backed slices are now migratable too.** Substrate v0.101.0
models the identical "created but not started" trap `EnsureConfigRecorder`'s own doc
comment already names as the reason it read-then-branches twice — a real emulator-tier
test can now exercise the exact two-write sequence and its two distinct refusal shapes
rather than only a hand-rolled fake's idea of them. `EnsureDeliveryChannel`'s S3-bucket-
policy validation is a genuine cross-service check (substrate computes the refusal from
real S3 bucket-policy state in the same emulator), which is precisely the class of thing
an emulator is suited for and a fake cannot express by construction. Compliance state is
seeded, never computed, on both sides — `internal/baseline` never reads Config compliance
today, so this doesn't change what it can test, only confirms the emulator won't silently
invent a compliance answer if that ever changes.

**Every substrate gap this project ever tracked is now closed.** There is nothing left in
this list. Future gaps, if any surface, get filed and tracked the same way these were.

**The discipline stays the same regardless of how much of AWS substrate now covers**:
migrate a package's tests to the emulator only when the emulator can express what those
tests actually assert, and say in the commit which of the three tiers (`internal/awsfake`,
the emulator, `internal/smoke`) the moved or added tests are testing. A newly-emulatable
operation is an invitation to evaluate a migration, not a mandate to perform one — and a
migration evaluation across `internal/org`, `internal/preflight`, and `internal/baseline`
is now, for the first time, possible to actually carry out rather than blocked before it
starts.
