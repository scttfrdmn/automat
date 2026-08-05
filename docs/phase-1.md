# Phase 1 — preflight and the onboarding bundle

What shipped at `v0.1.0-phase1`, what it deliberately does not do, and where to look
when it is wrong. Read `DESIGN.md` for the design; this page records the state of the
implementation at the end of Phase 1.

**`vend` does not exist yet.** Phase 1 answers "can automat work here, and if not,
what exactly is missing" — nothing in it mutates AWS.

## The three commands

### `automat login`

SSO device flow via `ssooidc`, writing the token to the same cache location and
filename the AWS CLI uses (the SHA-1 of the start URL — interop, not integrity), so
one sign-in serves every AWS tool on the machine. Flags: `--start-url`,
`--sso-region`. Everything else comes from the credential chain, per DESIGN §13:
automat stores no secret of its own.

### `automat preflight`

The three-state machine of DESIGN §4. It reports which of three positions you are in
— management account, delegated member with a vendor role, or standalone — and for
each check, **what kind of evidence it has**.

That last part is the load-bearing design decision, and it is in the type system
rather than in a footnote. DESIGN §3 fact 9: `iam:SimulatePrincipalPolicy` does not
evaluate service control policies. So from a member account, a *simulated* allow may
be shadowed by exactly the SCPs that matter, while a simulated *deny* is reliable.
`preflight` therefore distinguishes `Simulated` from `Observed` results and prints the
caveat whenever any check was simulated. A preflight pass is evidence, not
authorization.

Exit codes are meant for scripts, and the third one is the whole point: `0` ready,
`2` not-ready (something failed and is named), `3` undetermined (nothing failed, but a
check could not be completed). "I could not tell" must not exit the same as "no".

Every failure names the action, the resource, and the grant that would fix it —
CLAUDE.md rule 7 — and names *who must act*, since the fix is usually in someone
else's account.

### `automat setup --request`

Writes five files into `--out` (default `automat-onboarding/`) and makes **no AWS
call**:

| File | For |
|---|---|
| `README.md` | The person who approves the delegation. The blast-radius section is the point. |
| `delegation-policy.json` | Organizations resource policy, attached by central IT. |
| `vendor-role.cfn.yaml` | The role in the management account. Deploy this **or** the TF. |
| `vendor-role.tf` | Same role, Terraform. Deploy one, not both. |
| `ou.md` | Only meaningful when the target OU does not exist yet. |

`--dry-run` prints what would be written and stops. `--force` overwrites files edited
by hand.

Without `--request`, `setup` applies the delegation directly from a management
account — Phase 2.

## What the bundle is, as a security artifact

The bundle asks someone to grant a standing capability in their management account.
Two consequences shaped the implementation:

**The templates are executed, not read.** A forged line in a CFN template becomes a
grant. So no operator-supplied value reaches a template unvalidated: every field is
pattern-checked (no field admits a structural byte — no newline, quote, or brace), every
renderer validates before writing a byte and returns *no bytes* alongside an error, and
every value rendered into YAML goes through one quoting helper. The rendered YAML is
then re-parsed in tests and each value asserted to still be a **string**, because
type confusion is the other half of injection: a role name that YAML reads as a
boolean is a template whose `RoleName` is not a string.

**The safety argument is made of tag conditions, so tag-writing is the attack.** The
delegation permits policy modification only on resources already tagged
`automat:managed-by=automat`. That holds only if the delegate cannot apply that tag to
someone else's policy. AUDIT-1's C1 was exactly this defect, and its two halves lived
in different files — each unremarkable alone. The invariant is now a test
(`TestNoConditionReadsATagTheBundleLetsTheDelegateWrite`) that enumerates every
condition key the policies *read* and asserts no grant in either file can *write* one.
It is cross-file because the defect was, and because a reviewer reads one file at a
time.

**The bundle contains a live `sts:ExternalId`,** which makes it a sensitive file. The
generated README says so and says not to commit it publicly. The alternative — a
placeholder each side invents — is worse, since both sides must configure the *same*
value.

## Limits, stated because the tool states its own limits

- **No mutating AWS call exists in Phase 1.** `TestPreflightIssuesNoMutatingCall`
  asserts it against the fakes rather than trusting the reading.
- **`automat verify` does not exist** (DESIGN §12, Phase 4). This matters for one
  disclosure the README makes: the delegate can detach the controls automat itself
  attached, and the honest remedy is re-reading state, which is `verify`. Until it
  ships, "automat attached a control once" is a claim with no standing evidence, and
  the generated README says that in those terms.
- **The delegate can fill the delegated OU's five SCP slots.** It weakens nothing —
  a policy at a parent OU or the root still binds — but it can lock central IT out of
  attaching one *there*. Disclosed, with the remedy: attach yours first, or one level
  up.
- **Every claim about live AWS behavior rests on documentation, not observation.**
  `docs/open-questions.md` Q5–Q9 is the honest list. Fakes cannot falsify them and a
  green suite here is not evidence about them. Q9 in particular could make the first
  vend fail — it fails closed, which is why it was accepted rather than guessed at.

## Testing shape

Never AWS: hand-rolled fakes in `internal/awsfake` only (CLAUDE.md rule 1). Beyond
the ordinary table-driven tests, three kinds are worth knowing about:

- **Golden files** for all five generated files in both OU variants —
  `member-existing-ou` and `member-new-ou`, under `internal/bundle/testdata/golden/`.
  Regenerate with `make golden` and **read the diff**: that is the review, not the
  regeneration.
- **The escalation suite** (`internal/bundle/escalation_test.go`) asks privilege
  questions of the generated policies directly: can the role touch a policy, move an
  account it did not vend, tag outside its namespace, attach outside the OU.
- **Tests that hold the README to the code.** `TestREADMEDescribesTheGrantThatIsActuallyGenerated`
  and `TestREADMEDisclosesWhatTheDelegateCanDoToAutomatsOwnControls` key their
  assertions to the actions the policy actually grants, so a doc claim cannot outrun
  the grant and a removed grant retires its disclosure requirement instead of leaving
  a paragraph describing a permission that is gone.

`make build test lint` is the gate; `golangci-lint` is clean and `govulncheck` reports
nothing. `make smoke` remains the only path that touches real AWS, is manual, and
requires `AUTOMAT_SMOKE_PROFILE`.

## The audit

`audits/AUDIT-1.md`: 17 findings (1 critical, 4 high, 6 medium, 3 low, 3 nits), 15
fixed and 2 accepted with written reasons. It also records where the audit is weaker
than it looks — two overlapping defenses no jam could isolate, two tests that
initially overstated what they pinned, and one adversarial-agent finding that was
simply wrong, kept with the reason. The ACCEPTED items and three ratification requests
are the human's to review.
