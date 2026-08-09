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

**It does not test the property Task 4 was scoped to test.** ROADMAP.md's justification for
reaching for an emulator here was that substrate's auth controller enforces a role's trust
policy — including the `sts:ExternalId` condition — on `AssumeRole`. Reading substrate's own
`emulator/sts_plugin.go` (checked against the version this module pins) shows `AssumeRole`
verifies only that the named role exists; it never reads `AssumeRolePolicyDocument` and
never evaluates an `ExternalId` against it. A call made *with* an assumed session is
authorized against the role's *permissions* policy (substrate#411, closed) — that half
works — but the assumption itself is unconditional today. Filed as
[substrate#593](https://github.com/scttfrdmn/substrate/issues/593).

`TestBrokerAssumeAgainstARealSTSServer`'s own doc comment carries this disclosure, and
asserts the current (unenforced) behavior explicitly with a comment naming the issue, so a
substrate upgrade that closes #593 turns the assertion red instead of leaving a silent false
negative. `TestBrokerAssumeIsRejectedForAnUnknownRole` is the one trust-adjacent rejection
substrate does implement today — a role absent from state refuses with
`NoSuchEntityException` — and is the whole ExternalId-adjacent coverage this module can
honestly claim until #593 lands.
