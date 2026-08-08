# Security audit ritual

Referenced by `CLAUDE.md`. At the end of every phase, and before any tagged milestone,
perform an adversarial self-audit in the persona of a hostile, unimpressible security
auditor reviewing this codebase for the first time. The auditor assumes: all user input is
attacker-controlled (account names, emails, OU ids, catalog files, config), the operator
will be phished, the network is unreliable, and every claim in the docs is false until
traced to code.

Output: `audits/AUDIT-<phase>.md` — findings ranked critical/high/medium/low/nit, each
resolved as FIXED (with commit) or ACCEPTED (with a reason a crabby auditor would
begrudgingly sign). No finding may be dismissed without a written reason. The audit file is
committed; the human reviews ACCEPTED items.

## Scope, at minimum

**Every IAM policy string and template** — least privilege, missing conditions,
confused-deputy paths, ExternalId handling.

**Tag-based authorization, both directions.** Every `aws:ResourceTag` / `aws:RequestTag`
condition must be paired with an audit of which principals can *write* that tag at the same
scope. **Wherever tag-reading gates access, tag-writing is a privilege boundary.** A
condition that reads a tag any grant in the same bundle can apply is not a condition. Audit
the pair even when the two halves live in different files or different templates —
AUDIT-1's C1 was exactly this defect, and each half was unremarkable alone. State the
invariant as a test, not as a paragraph: enumerate the keys the policies read and assert no
grant can write one.

**Injection surfaces** — any user-supplied value that reaches a template (CFN/TF/JSON/
markdown), a shell, a path, or an ARN.

**Round-trip fields, enumerated rather than spot-checked (rule 8).** List every value
automat writes that a person is expected to read back and type — request ids, account
aliases, OU names, profile ids, resume tokens, anything a remediation string tells the
operator to retype — and confirm each is patterned in both the schema and the Go validator.
Enumeration is the point: the failure mode is a field nobody classified as a round-trip
field, which is how `request_id` survived Phase 0 unpatterned while every other id in the
same file had a pattern. A field newly *printed* in a remediation message becomes a
round-trip field at that moment even though its schema did not change, so the sweep runs
over what the CLI and error paths emit, not only over `schema/`.

**TOCTOU** between preflight checks and mutating actions.

**Error and log paths** — credential/ARN/email leakage.

**The evidence chain** — canonicalization ambiguity, hash inputs, signature coverage,
whether a record can be silently replaced.

**The SCP packer** — can any merge WIDEN permissions.

**Every obligation profile's citations and effective dates, re-verified against the primary
source.** Confirm every claim automat renders into a human-facing document traces to a
hashed source. **A stale legal citation is a finding, ranked no lower than medium** — it is
not a documentation nit. A profile is a reading of policy that an institution acts on, and
policy moves: notices are superseded, phase-in dates arrive, a class deviation pinning a
revision expires. The failure mode is silent and confident, since a superseded citation
renders exactly as well as a current one. Also confirm the policy caveat still appears
where `docs/policy-caveat.md` requires it, and that the understatement asymmetry — the
`determinations.understatement_value` guarantee `TestTheUnderstatementAsymmetryHoldsUnder‑
EveryProfile` enforces — still holds across every **obligation** profile rather than per
profile. The classification profiles are a separate document type with no understatement
value to check: what they owe instead is that automat never decides a level
(`TestNoShippedProfileClaimsAutomatDecides`) and that a source's silence is not filled in
(`TestWhereTheShippedSourceIsSilentTheShippedProfileIsSilent`) — confirm both hold across
every shipped classification profile, for the same reason: a guarantee checked against one
document and assumed for the rest is a guarantee that erodes the first time a second document
disagrees with it.

**gosec + dependency review**, with every finding triaged in writing.

**The CLI surface against DESIGN §13.** List the flags each command actually has and
reconcile them with §13. A flag §13 does not enumerate is an addition and fine; a flag that
*contradicts* §13 — or a §13 command whose implemented behavior differs — is its own line
item in the audit, not a footnote. Ratified at the AUDIT-1 review on this condition.
