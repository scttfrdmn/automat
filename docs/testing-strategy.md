# Testing against AWS: two tools, neither replacing the other

Referenced by `CLAUDE.md`. `internal/awsfake` and an AWS emulator test different things,
and a package moves to the emulator only when the emulator can express what that package's
tests actually assert.

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

## Keep both

Do not migrate a package to the emulator because the emulator exists; migrate when its
tests' subject is expressible there, and say in the commit which of the two things the
moved tests were testing.

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
