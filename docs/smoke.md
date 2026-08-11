# Smoke runbook (manual, live AWS)

`make smoke` is the only thing in this repository that talks to real AWS. Everything
else is fake-backed by rule (CLAUDE.md rule 1), which is why this file exists: the
questions in `docs/open-questions.md` under "Awaiting a live org" cannot be answered by
a green test suite, and a green suite is not evidence about them.

This page is the runbook the Makefile points at. It is written now, in Phase 1, because
the Phase 1 review made one acceptance conditional on it (item 4: *"Tie it to the Phase
5 smoke runbook explicitly: first sandbox run answers Q9 empirically"*). An acceptance
whose remedy lives in a document nobody has written is an acceptance with no remedy.

**Status: runnable.** `internal/smoke` (package `smoke`, every file tagged `//go:build
smoke`) automates this checklist as `TestSmokeChecklist`, with one subtest per question
below, sharing the accounts earlier subtests vend the same way the manual checklist
always required. `make smoke` runs it. This section used to say the runbook was
specified but not automated — `TestMakefileSmokeClaimIsStillTrue`
(`internal/artifact/smoke_claim_test.go`) is what keeps this claim from silently going
stale again in either direction.

**This automation has never run against real AWS.** It was written and typechecked
against the tag, but no agent building it has AWS credentials — the first real run is
what will tell you whether the call shapes actually hold. Expect the first attempt to
surface a small fix (an SDK field name, a pagination edge, a missing permission) rather
than a clean pass, the same as any code meeting its real target for the first time.

## Running it

```
export AUTOMAT_SMOKE_PROFILE=my-sandbox-profile   # AWS credential profile
export AUTOMAT_SMOKE_ORG=o-xxxxxxxxxx              # the sandbox org id, verified at runtime
export AUTOMAT_SMOKE_OU=ou-xxxx-xxxxxxxx           # where throwaway accounts land
export AUTOMAT_SMOKE_EMAIL_PATTERN='you+automat-smoke-{name}@example.edu'  # {name} required
export AUTOMAT_SMOKE_FINDINGS=/path/to/findings.jsonl  # optional; defaults under the OS temp dir
export AUTOMAT_SMOKE_REGION=us-east-1              # optional
make smoke
```

`AUTOMAT_SMOKE_PROFILE` and `AUTOMAT_SMOKE_ORG` are both required and checked in that
order; `AUTOMAT_SMOKE_ORG` is verified against a real `DescribeOrganization` call before
anything else runs — a mismatch refuses the whole suite rather than running the wrong
account's questions.

**The findings file is not the deliverable.** It is JSON lines, one `smoke.Finding` per
observation (a latency, an exception's exact text, which of several already-handled
outcomes occurred) — read it after the run, and use it to edit `docs/open-questions.md`
by hand: narrow or delete the entry a finding answers. The test itself never touches that
file. Rule 4 below still governs; automation changed how the observation is captured, not
who acts on it.

## Rules

These are not negotiable and the target enforces the first two:

1. **`AUTOMAT_SMOKE_PROFILE` must be set explicitly.** No default, no fallback to the
   ambient credential chain. A smoke target that runs against whatever profile happens
   to be active is one that eventually runs against production.
2. **Read-only except in an explicitly named sandbox organization.** Anything mutating
   is gated on the sandbox org id, checked at run time against the org the credentials
   actually resolve to — not against a flag saying it is the sandbox. `AUTOMAT_SMOKE_ORG`
   plus `internal/smoke.newHarness`'s own `DescribeOrganization` check is what enforces
   this now, in code rather than only in this paragraph.
3. **Never in CI.** The tag exists so `go test ./...` cannot reach these.
4. **Record what you observed, not what passed.** The output of a smoke run is an edit
   to `docs/open-questions.md`: an entry deleted, or an entry narrowed. A run that only
   reports pass/fail has wasted the one thing a live org provides. `internal/smoke`'s
   `Finding`s are what make this possible without hand-transcribing terminal output —
   see "Running it," above.

## Q9 is the first thing the first vend tests

Phase 1 review item 4, verbatim: *"H1 (MoveAccount source-parent) acceptance approved —
fails closed and visibly beats silently widening the grant. Tie it to the Phase 5 smoke
runbook explicitly: first sandbox run answers Q9 empirically."*

**The question** (`docs/open-questions.md` Q9): does `organizations:MoveAccount`
authorize against `SourceParentId` as well as `DestinationParentId`? The vendor role's
`MoveAccountsIntoTheDelegatedSubtreeOnly` statement deliberately omits the organization
root from its resource list, because naming the root would permit the exact move the
statement exists to prevent. A newly created account lands at the root, so if
`MoveAccount` needs source-parent authorization, **every first vend fails on the move,
after the account exists.**

**Why it is first, and why it is safe to have shipped unanswered:** it fails closed and
announces itself. The bad outcome is a denied move and a parked account, recoverable in
an afternoon. The alternative — adding the root ARN speculatively — would have widened
the grant silently, in the direction that cannot be caught later.

**Procedure for the first sandbox vend:**

1. Vend one account into the delegated OU using the brokered path, and let it fail if
   it fails. Do not pre-emptively add the root ARN to the role.
2. Read the denial. The distinguishing evidence is whether the error names the *source*
   parent (the root) or the destination. Capture the full error, including the
   `AccessDeniedException` message and any resource ARN in it — this is the empirical
   answer, and a paraphrase is not.
3. Check the account's actual parent afterward. A denial that still moved the account,
   or a success that left it at the root, means the question was posed wrong.
4. Then resolve, per Q9's own recorded options: a fourth resource entry restricted to
   source-only if IAM exposes that distinction (it appears not to, which is part of the
   question), or a `DestinationParentId`-only grant with the widened capability
   disclosed in the README's blast-radius section. **The disclosure is not optional in
   that branch** — it is a grant the delegate has, so the bundle must say so.
5. Delete or narrow Q9 in `docs/open-questions.md`, and record the observed error text.

If the move succeeds on the first try, Q9 is answered in the good direction and the
entry is deleted — but record the AWS response anyway, because "it worked" without the
observation is the same weak evidence this runbook exists to replace.

## The rest of the checklist

In the order a first live run reaches them. Each is an entry in
`docs/open-questions.md` with its own recorded reasoning; this is the sequence, not a
restatement.

| Order | Question | What the run must capture |
|---|---|---|
| 1 | **Q9** — `MoveAccount` source parent | The denial text, or the success (above) |
| 2 | **Q7** — `MoveAccount` timing after `CreateAccount` | Actual latency distribution, enough to set a retry policy rather than guess one |
| 3 | **Q8** — does `MoveAccount` honor `aws:ResourceTag` on the account? | Whether the condition binds. This one does **not** fail closed: if the tag condition is ignored, the role can move *any* account in the organization into the delegated OU, and nothing announces it. Test it directly with a deliberately untagged account. |
| 4 | **Q12** — `MoveAccount` into the parent the account already has | Success, or the exact exception. Immediately after order 1 succeeds, re-run the same move: it costs one API call and it is the behavior every `vend --resume` depends on |
| 5 | **Q5** — what `preflight` can detect about delegation from the member side | Whether `DescribeResourcePolicy` is readable from the member account at all; if not, preflight must be told rather than detect, and the bundle must carry that fact |
| 6 | **Q6** — SCP quota edges under real union output | Now largely answered offline against `catalogs/baseline-protection.json`: the shipped set plus a profile's allowlists packs into **one** policy at 46% of the limit. What a live run still adds is what a *campus* baseline in the reserved institutional slot looks like, and whether the three usable slots survive contact with one |
| 7 | **Q13** — `BP.IAM-1` denies re-permissioning the baseline roles, automat included | Whether the protection SCP governs automat's own `PutRolePolicy` on `automat-automation` once attached, and how long after `AttachPolicy` that becomes true. Attempt the write from the automation role and record the result, then re-run the full vend and confirm it is a no-op rather than a denied write |
| 8 | **Q24** — does `reclaim`'s detach-then-close sequence behave the way `docs/reclaim-design.md` assumes | Vend a throwaway account, `reclaim --yes` it, and record: how long `DescribeAccount` took to report `SUSPENDED`, whether `DetachPolicy` on a just-attached SCP succeeded immediately, and — only if the sandbox org's own history permits reaching it safely — the exact shape of a closure-quota rejection |

**`TestSmokeChecklist`'s Q8 subtest is a partial answer.** It runs under this suite's own
native credentials, which carry no resource-tag restriction at all — so a real run of it
is expected to succeed regardless of whether the *vendor role's* condition would bind.
The subtest still records what it observed as a `Finding`, but answering Q8 for real
means running the same untagged-account move under the *brokered* vendor role, which
requires the onboarding bundle already deployed into the sandbox — not something this
suite does on your behalf. Likewise `TestSmokeChecklist`'s Q13 subtest can only reach
`GetRole` against its own account; the actual live question (whether the protection SCP
denies `PutRolePolicy` to every principal in the *child* account, `automat-automation`
included) needs `internal/baseline` to exist so a suite can assume into the child and
test it — recorded as a disclosed gap in the Finding, not fabricated.

Q8 deserves the emphasis it has above: it is the one on this list whose bad case is
silent. Q9 fails visibly, Q7 fails visibly, Q5 and Q6 are questions about capability
and headroom. A tag condition that does not bind looks exactly like a tag condition
that does.

Q13 is the near miss: its bad case fails visibly but *late*. If SCP attachment has a
propagation delay, an attach-then-write sequence succeeds on the run that establishes it
and fails on some later run, which is why the run must attempt the denied write
deliberately rather than conclude from a vend that happened to work.

Q24 is last on purpose: it is the only entry that destroys the account it tests against,
so it should run after every other question on this list has already been answered
using accounts this same sandbox run vends — reclaiming early would remove the very
account the earlier questions still need.

## Phase 1 review item 7 applies here too

The standing change from the Phase 1 review: *"every tag-based authorization condition
(`aws:ResourceTag` / `aws:RequestTag`) must be paired with an audit of which principals
can WRITE those tags at the same scope."*

That is a code-audit rule, but Q8 is its live-org counterpart and the smoke run is
where it becomes observable. When Q8 is tested, test the write side in the same run:
confirm from the sandbox that the delegate cannot apply `automat:vended-by` to an
account or policy outside its namespace. A condition that binds correctly while the
principal can write the tag it reads is not a control.
