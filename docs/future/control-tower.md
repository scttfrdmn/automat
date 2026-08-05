# Interaction with AWS Control Tower: parked scenario analysis

**Status: parked. No implementation, no schema, no CLI surface.** This page records
an analysis the Phase 1 review asked to be written down while it was fresh, so that
whoever implements it does not have to re-derive it. Nothing here is a commitment,
and nothing here has been verified against a live Control Tower deployment — every
claim about Control Tower's behavior below is marked with how confident it is and
what would confirm it.

Read `docs/vs-control-tower.md` first for the positioning question ("which tool
should I use"). This page is the narrower engineering question: **what happens when
both are present in one organization**, in either order. That situation arises
whether or not automat wants it, because central IT adopting Control Tower is a
decision made above the delegate.

`docs/vs-control-tower.md` is the only page permitted to compare the two tools
(DESIGN §15 caps the comparison surface). This page names Control Tower because it
must describe an interaction with it, not to position against it; it makes no
comparative claim.

## Why this needs an answer at all

automat's whole premise is a delegated, OU-scoped vend from a member account
(DESIGN §5). Control Tower governs OUs from the management account. Both attach
SCPs at OU scope and both baseline accounts by assuming a role inside them. Two
tools writing to the same OU with no shared notion of ownership is the setup for
the failure automat exists to prevent: an account that *looks* baselined and is
not.

The concrete hazard is not conflict — SCPs compose by intersection, so two sets of
Denies over one account is strictly safer than one. The hazard is **automat
reporting a baseline it does not own.** If Control Tower enrolls an account after
automat vended it, enrollment re-baselines the account: it can replace the Config
recorder, retarget the delivery channel, and attach its own guardrails. automat's
`verify` would then be checking an artifact hash against a baseline that a
different system is now the author of, and every outcome it could print is wrong:
"compliant" claims custody automat lost, "drifted" blames an operator for
something they did deliberately.

That is the whole problem. Everything below follows from it.

## The two orderings converge

**Ordering A — Control Tower first, then automat.** The OU is already enrolled.
automat's `preflight` runs in MEMBER state, finds the delegated grant, and could
vend into that OU.

**Ordering B — automat first, then Control Tower.** automat vended accounts into
its OU; central IT later enrolls that OU (or registers it), which enrolls the
accounts under it.

Both end in the same place: **an account whose detective baseline is authored by
Control Tower and whose SCP set includes guardrails automat did not attach.** So
they need one state, not two, and the name for it is `CT_MANAGED` — a fourth
value alongside DESIGN §4's `STANDALONE` / `MANAGEMENT` / `MEMBER`.

Some care about where that value lives. §4's three states classify **the caller's
own position in the organization**, and the comment on `preflight.State` says there
is deliberately no fourth value for "cannot determine". `CT_MANAGED` is a different
kind of fact: it describes **the target OU**, not the caller, and a caller can be
MEMBER while its target OU is managed. Two defensible shapes:

1. A separate field on the preflight report (`TargetOU.Governance`), leaving
   `State` a three-value type. Preserves the meaning of `State`; costs every
   consumer an extra branch.
2. A fourth `State`. Simpler for callers, at the price of conflating "where I
   stand" with "what the OU is".

**Recommendation: (1).** The states are load-bearing for `vend`'s dispatch and the
existing type comment argues against widening them. But this is exactly the kind of
decision that should be made when the code is in front of someone, not here.

## The one hard rule: never enroll-after-vend

**automat must never treat a vended account as safe to enroll, and must never
help.** This is the rule the rest of the design hangs off, and it is a rule about
what automat *refuses*, which is why it can be stated now, without implementation.

An automat-vended account carries a claim: an artifact with a content hash, an
evidence manifest chain recording what was attached and by whom, and account tags
(`automat:artifact-sha256`, DESIGN §14) that `verify` keys off. Enrollment
invalidates the parts of that claim automat can no longer see, but leaves the tags
and the manifest chain in place, saying exactly what they said before. The account
now asserts a lineage that is no longer true, and nothing in the account records
the moment it stopped being true.

Note which direction this is asymmetric in. Enroll-then-vend (Ordering A) is
recoverable: automat can inspect first and decline, or vend knowing the OU is
managed. Vend-then-enroll is not, because the damage is to evidence already
written and distributed. That asymmetry is the argument for the rule being
absolute rather than a warning.

Practical consequences, if this is ever built:

- `verify` must **detect** the managed case and report it as its own outcome, not
  as compliant and not as drift. Something nearer "custody: not held" — a third
  answer, the same way `preflight` needed `Undetermined` rather than folding
  unknowable into fail.
- The detection must not be a tag automat wrote. A tag automat wrote is a tag
  automat's own bug can write wrongly; enrollment is observable in the
  organization (an enrolled OU, an enrolled account) and should be read from
  there. **Unverified: whether a member account with only automat's delegated
  grant can observe that.** This is a Q5-shaped question, and it should join
  `docs/open-questions.md` when the work starts rather than now.
- Vending into an OU already known to be managed should be refused by default, not
  warned about. If it is ever allowed, it must be an explicit flag and the
  evidence record must say the account was vended into a co-managed OU — because
  that is a record whose meaning a later reader has to know to discount.

## Graceful handoff (verb sketch, not a spec)

If an account genuinely should move from automat's custody to Control Tower's, the
answer is not to prevent it — it is to make the transition a recorded event rather
than a silent overwrite. That is precisely what the `custody-transfer` evidence
record exists for (`schema/CHANGELOG.md`, evidence-manifest pre-publication
change): a terminal record naming the transferee, the effective date, the reason,
and the final artifact hash, after which the chain validly ends.

So the sketch is thin on purpose, because the schema already carries the hard part:

```
automat handoff --account <id> --to <transferee> --reason <text> [--yes]
```

- **Plan first, then apply**, and `--yes` required: this ends an evidence chain,
  which CLAUDE.md rule 5's plan/apply split exists for. The plan prints what the
  final artifact hash is, what the account currently claims, and what the
  transferee will be recorded as.
- **Writes a `custody-transfer` record and nothing else.** It does not detach
  SCPs, does not stop the recorder, does not touch the account. Tearing down a
  baseline as part of a handoff would leave a window where the account is governed
  by neither tool, and the transferee is the one who should decide what replaces
  what. The verb says "automat is no longer the author of this account's
  compliance claim" — that is a statement about custody, not a change to the
  account.
- **Idempotent** (CLAUDE.md rule 4), and it is the one command where that is
  subtle: the schema permits at most one `custody-transfer` per manifest, so
  re-running must recognize the existing terminal record and succeed without
  appending a second. A second record means either the first was false or the
  chain was reopened after it closed.
- **Removing the `automat:` tags is a separate decision** and probably belongs to
  whatever `reclaim` becomes (ROADMAP Phase 5). Leaving them means the account
  still advertises a lineage that has ended; removing them means the tags no
  longer point at the manifest that explains what happened. The manifest is the
  authority either way, so a tag pointing at a manifest whose last record is a
  transfer is not actually misleading — a reader who follows it learns the truth.
  Weak preference for leaving them and letting `verify` read the terminal record.

The reverse direction — handoff *to* automat from Control Tower — is not sketched,
because automat cannot honestly claim a baseline it did not attach. It would vend
nothing and verify nothing; the operator would run a normal vend against a fresh
account instead.

## What is not decided here

- Whether any of this ships. It is not in ROADMAP.md.
- Whether `CT_MANAGED` is a state or a field (recommendation above; decide with
  code in hand).
- Whether the managed case is even **observable** from a member account holding
  only automat's grant. If it is not, the rule above still holds, but automat can
  only enforce it by being told, and the onboarding bundle's README would need to
  ask central IT to say so — the same shape as Q5's fallback.
- Whether `handoff` is its own verb or a mode of `reclaim`. It is a CLI-surface
  question, so it needs asking before it is written (CLAUDE.md working style).
