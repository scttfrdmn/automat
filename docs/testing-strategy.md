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

## Substrate v0.98.0 (2026-08-14): Organizations went from unusable to load-bearing

`test/integration` now pins **v0.98.0** (was v0.95.0). Between those two releases,
substrate's Organizations plugin went from 5 read-only operations to 30 — it can now build
an organization, not just describe one — which changes what belongs in this tier's scope,
not merely what version number is in `go.mod`.

**What v0.96.0–v0.98.0 actually added, in order:**

- **v0.96.0**: `iam:UpdateAssumeRolePolicy` (trust-policy tightening in place, the CDK/
  Terraform shape); every service's `AccessDenied*` code now follows its real wire
  protocol instead of one generic string (a **breaking** change for any test asserting
  `AccessDeniedException` against an XML-protocol service — `automat`'s own tests assert
  no such literal, confirmed by grep before upgrading, so this cost nothing here); the
  configured event-store backend actually persists (`RecordEvent` now flushes; previously
  had zero callers despite being fully documented and config-tested).
- **v0.97.0**: the OU tree, asynchronous account vending (`CreateAccount` now genuinely
  returns `IN_PROGRESS` with a real `car-` request id, matching what `internal/org`'s own
  poll loop already assumes), the full SCP lifecycle including `EnablePolicyType`/
  `DisablePolicyType` and the "SCPs disabled on the root" trap DESIGN §3 fact 8 exists
  because of, resource tagging with `aws:ResourceTag`/`aws:RequestTag` condition-key
  enforcement (Q8/Q9's own open questions — see below), and a stable root identity (fixes
  a real determinism defect: `ListRoots` used to mint a fresh id per call).
- **v0.98.0**: the organization's resource policy (`PutResourcePolicy`/
  `DescribeResourcePolicy`/`DeleteResourcePolicy` — Q5's own question, delegation
  visibility), and the `organizations` Service Quotas entries including `L-E619E033`
  ("Maximum number of accounts") seeded at the value substrate's own plugin enforces.

**What this means for `docs/open-questions.md`'s live-org-only entries.** Several of the
questions this project's own `docs/smoke.md` runbook lists as needing a real organization
are now, for the first time, expressible against a deterministic emulator instead — not a
replacement for the live-org answer (an emulator's own behavior is a model of AWS, not
AWS), but a way to develop and regression-test the *code path* against a realistic
authorization surface before ever touching a sandbox org, and to catch what an emulator
can catch (a malformed request, a condition key that doesn't gate the way the code
assumes) without spending sandbox headroom on it:

- **Q8/Q9** (`MoveAccount`'s `aws:ResourceTag` condition, source-vs-destination-parent
  authorization) — substrate v0.97.0's tag-condition enforcement and OU/root modeling are
  exactly the mechanism these two questions are about. Worth a migration pass: does
  substrate's `MoveAccount` implementation happen to answer either question, or does it
  model AWS's own undocumented behavior as an assumption substrate's authors made — the
  same distinction this file's own "Keep all three" section draws. Check substrate's own
  issue tracker and source before treating an emulator result as the live-org answer.
- **Q13** (`BP.IAM-1`'s ordering constraint) — substrate v0.96.0's `UpdateAssumeRolePolicy`
  plus its real authorization path can now express "can a Deny SCP actually block a
  `PutRolePolicy` call once attached", which is the mechanical half of Q13. The *timing*
  half (how long after `AttachPolicy` a Deny becomes effective) is still real-AWS-only —
  an emulator has no propagation delay to observe unless it deliberately models one.
- **Q5** — substrate v0.98.0's resource-policy plugin is scoped to the caller's own
  organization only (substrate's own tracked gap, issue #623 — no member→organization
  reverse index yet), so it cannot yet answer Q5's actual question (what a *member*
  account sees). Not migratable until that lands upstream.

**Not yet migratable at all, tracked upstream, not automat's own gap to build around:**

- **AWS Config** (recorder, delivery channel, conformance pack) — no plugin exists.
  Filed and tracked as [substrate#580](https://github.com/scttfrdmn/substrate/issues/580).
  Blocks any emulator-tier test of `internal/baseline`'s `EnsureConfigRecorder`/
  `EnsureDeliveryChannel`/`EnsureConformancePack`.
- **`iam:SimulatePrincipalPolicy`** — no plugin support. Filed and tracked as
  [substrate#579](https://github.com/scttfrdmn/substrate/issues/579). Blocks any
  emulator-tier test of `internal/preflight`'s simulated-permission checks.
- **The Account Management API** (`ListRegions`/`EnableRegion`/`DisableRegion`/
  `GetRegionOptStatus`) — no plugin exists at all, and none was tracked until this
  project filed [substrate#629](https://github.com/scttfrdmn/substrate/issues/629).
  Blocks any emulator-tier test of `internal/baseline.EnsureRegions`.
- **`CloseAccount`** — absent from substrate entirely, including the quota interaction
  with `L-E619E033` this project confirmed live and recorded in
  `docs/reclaim-design.md`. Tracked as item 2 of
  [substrate#625](https://github.com/scttfrdmn/substrate/issues/625). Blocks any
  emulator-tier test of `reclaim`.

**The discipline stays the same regardless of how much of Organizations substrate now
covers**: migrate a package's tests to the emulator only when the emulator can express
what those tests actually assert, and say in the commit which of the three tiers
(`internal/awsfake`, the emulator, `internal/smoke`) the moved or added tests are testing.
A newly-emulatable operation is an invitation to evaluate a migration, not a mandate to
perform one.
