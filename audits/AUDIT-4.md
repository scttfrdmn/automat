# AUDIT-4 — Phase 4, partial (`verify`, `list`, the Config-rule union, override files, crosswalk dedupe)

Adversarial self-audit per CLAUDE.md, "Security audit ritual", and the scope in
`docs/audit-ritual.md`. Conducted 2026-08-07/08 against `e32825d~1..330780b` — seven
commits, 52 files, +4410/−144.

**Assumptions held throughout.** Everything AUDIT-1 and AUDIT-2 assumed, plus what this
phase added. Every document automat *reads* is attacker-supplied, and this phase added a
new one: the override file, which is unpublished and therefore has exactly one validation
layer instead of two. Every value automat *writes* into a human-facing document is a claim
that will be forwarded or typed onto a command line by someone who did not run the
command. **And one new assumption, which is this phase's whole character:** `verify` is a
command whose entire output is a *claim about what is true in AWS*, so every way it can
overstate what it checked is a security defect and not a documentation defect. `list` is
the same shape. AUDIT-2's assumptions were about a command that changes things; these are
about commands that *report*, where the failure mode is a reader trusting a narrower check
than they think they got.

**What exists to audit that did not before.** `internal/verify` (the policy and freshness
layers), `awsapi.OrgVerifyAPI` and its fake, `cmd/automat/verify.go` with the 0/2/3 exit
taxonomy, `org.SameDocument`/`CanonicalizeDocument` newly exported, `cmd/automat/list.go`,
`org.WalkTree`, `evidence.Dir.ListAccountIDs`, `awsfake.Org.Accounts` plus
`OrgState.LookupParent`/`SetPolicyContent`, `internal/compilesets/configrules.go` (union
dedupe, per-parameter resolution, conflict reports, the Q1 blockedPort re-slotting),
`conflicts.go`, `overrides.go` with `--override` on `vend` and `verify`, and
`crosswalk.go`. Also changed: the delegation README's `automat verify` paragraph, and the
deletion of the test assertion that guarded it.

**Method.** Every finding below was reproduced before it was written down — three by
throwaway probe tests (the override duplicate-key decode, the forged conflict-report line,
the override widening a disjoint intersect), one by a size measurement, the rest by reading
the call path a claim rests on rather than the comment that makes it. Fixes were
**counter-checked** in a throwaway git worktree at the previous commit: each new or changed
assertion was copied there and run, confirmed failing, with `git diff --numstat` proving only
`_test.go` files changed. All five fail there — the four new tests plus M4's replaced
assertion. This is AUDIT-2's method, unchanged, and it is the only thing that distinguishes
a test that pins a fix from a test that passes for an unrelated reason.

**Where the prompt's suspicion was right and where it was wrong, both recorded.** The
scope handed to this audit named nine specific worries. Four were real (§H1, §H2, §H3,
§M1). Five were checked and found not to be defects, and each is recorded below **with what
was read to decide it**, per AUDIT-1's binding precedent — a suspicion dismissed without a
reason is indistinguishable from one never checked. Two of the five were the ones flagged
as potentially the largest ("does `awsfake.Org.Accounts` change a production path — if it
does, that's a bigger finding"; "can `reSlotBlockedPorts` DROP a port"), and both are
clean. The largest finding this audit actually produced was in neither list.

**Result.** 12 findings: 0 critical, 3 high, 4 medium, 4 low, 1 nit. **6 FIXED, 6
ACCEPTED, each with a written reason.** Plus 5 verified-not-findings recorded with their
evidence, a §13 CLI reconciliation confirming D4/D5/D6 accurate, a dependency review with
nothing to review, and gosec triaged.

**Fix commits.** H1 → `7874637`. M1 → `b2d91d0`. H3, M2 (list half) → `7c1c9ca`.
H2, M2 (verify half) → `128bd51`. M4 → `a4660e9`. M3, L1–L4, and N1 carry no fix commit —
each is ACCEPTED with its reason in place.

**For the human: 6 accepted findings, 1 ratification request, and 1 recommended follow-up
that is an interface change rather than a fix — in the sections at the end.** The
ratification request is H1's: it strictly tightens a read path, per rule 6.

---

## Critical

None. Stated rather than omitted: the shape that would have been critical is a widening
one, and §H4-that-isn't (the override widening, filed as L1) is genuinely reachable but
touches nothing that is deployed today. If `crosswalk.go`'s or the merged Config-rule map's
first production consumer lands without closing L1, that finding becomes critical at that
moment and not before.

---

## High

### H1 — An override file naming a key twice resolved to the value the operator did not write. FIXED

`LoadOverrides` set `DisallowUnknownFields` and called that the read discipline. It is not:
**`DisallowUnknownFields` does not fire on a key that is known twice.** Given

```json
{"overrides":[{"rule":"X","parameter":"Y","value":"14","value":"6"}]}
```

`encoding/json` takes the last occurrence silently. Reproduced: the loaded entry carried
`Value: "6"`. The same holds for a duplicated `rule` (probe: `Rule: "Z"`, the second) and
for a duplicated top-level `overrides` array (probe: the second array entirely).

This is AUDIT-2 H8 exactly, on a file H8's fix did not reach. What makes it high rather
than a repeat of a solved problem is *which* file: an override file's entire content is a
value a human decided on after reading a conflict report, and the parameter it resolves is
a Config-rule parameter — `MinimumPasswordLength: 14` versus `6`. The operator reviewing
the file, or the reviewer approving the pull request that adds it, reads the first
occurrence. The compile takes the second. There is no diff between what was approved and
what was applied, because the same bytes produce both readings.

`artifact.RejectDuplicateKeys` now runs before the decode. Fixed in `7874637`.

**Unpublished is not exempt, and that is the general lesson.** `docs/cli-surface.md` D6
resolved that the override file gets no `schema/` entry, on proportionality grounds this
audit does not reopen. But the decision has a consequence nobody wrote down at the time:
with no JSON Schema, the Go read path is not one of two layers, it is the *only* layer. A
document with one validation layer needs that layer to carry what two would have carried.
Recorded as a ratification request — the change strictly tightens validation, which rule 6
permits without pre-approval and requires be listed here.

### H2 — `verify` recorded `"outcome": "success"` on a run that found drift and exited 2. FIXED

`writeVerifyEvidence` set `Outcome: evidence.OutcomeSuccess` unconditionally. The
`RunE` body then reached its exit switch and returned `&exitError{code: exitVerifyDrift}`.
So a run that named a differing policy on stdout and exited 2 appended a record saying it
succeeded.

The exit code lives for as long as the shell that read it. The manifest is the artifact
DESIGN §11 exists for — read months later by someone reconstructing what happened, with no
scrollback. **A reader counting successful verify records was counting the drifted ones**,
and the drift was the only thing in the run worth recording. `evidence.OutcomeSuccess`'s
own vocabulary made the gap harder to see, not easier: `success` reads as "the command
worked", and the command did work. What failed was the check.

Worse in one specific way: `validateOutcomePairing` refuses a `failure` or `parked` record
with no error block, precisely so a reader is never shown an operation that stopped without
being told why. A drifted run marked `success` sails past that check, so the one guard in
the package aimed at "this record withholds what happened" could not fire.

Fixed in `128bd51`: a drifted run is `OutcomeFailure` with a `RecordError` naming each
finding by class — not attached, content differs, name collision, orphan — and a
remediation per class. **`failure`, not `parked`:** parked means real AWS state was left
behind for `vend --resume` to find (`OutcomeParked`'s own doc comment), and verify wrote
nothing to resume. **Freshness deliberately excluded:** a lapsed `review_by` is a warning
that changes no exit code (DESIGN §11a, §12), and a record marked failure for a date would
say the account drifted when nothing about it moved.

### H3 — `automat list --help` claimed a read-only grant the command does not hold. FIXED

The help text said, verbatim:

> Read-only: this command holds no write grant on anything it inspects.

`listTree` obtains its client through `vendOrgClient` — `vend`'s own constructor — which
returns `awsapi.OrgVendAPI`: `CreateAccount`, `MoveAccount`, `CreateOrganizationalUnit`,
`TagResource`. In the MEMBER state it gets there by **assuming the vendor role**, so
running `automat list` performs an `sts:AssumeRole` into the management account.

The sentence is not a rounding error, because `automat verify`'s identical sentence *is*
true — `awsapi.OrgVerifyAPI` carries no write method, and `globals.orgVerifyClient` returns
it. Two commands print the same claim; one is enforced by the type system and the other is
enforced by nobody. An operator comparing them, or an approver asked whether `list` is safe
to hand to a student, has no way to tell which kind they are reading. **Nothing tested it**
— `cmd/automat/list_test.go` asserts output shape and the `--ou` refusal, and
`TestNoWriteInterfaceCanDestroy` checks for destructive actions, which none of these four
are.

Fixed in `7c1c9ca`: the help text now says the command makes no write call and states
plainly that it is not read-only by construction the way `verify` is, naming the four
methods it carries and the assume-role.

**Not fixed by narrowing the interface, and this is the honest half.** The right fix is a
read-only walk interface in `api.go` with its own fake and its own doc comment. It was not
made here because it is not a small change: the walk needs `ListAccountsForParent` and
`ListOrganizationalUnitsForParent` **through the same credential `vend` uses**, since in the
MEMBER state a read on the caller's own identity sees a different view than the brokered
one, and an inventory that disagrees with what `vend` sees is the wrong inventory. So the
new interface has to be brokered too, which means a second brokered constructor and a
second fake, and the audit ritual's own rule is not to make risky changes under audit. The
doc text now matches the code, and the interface work is carried below as a recommended
follow-up. `docs/audit-ritual.md`'s wording applies exactly: *"State the invariant as a
test, not as a paragraph"* — this fix downgrades a false paragraph to a true one, and the
test still does not exist.

---

## Medium

### M1 — A conflict report printed its origins unescaped, so a control id could forge a line of it. FIXED

`ConflictReport.Error()` quotes `Rule`, `Parameter`, and every member of `Values` through
`safe()`. `Origins` went through `strings.Join` raw.

An origin is `artifactID + ":" + controlID`. `Control.ID` is checked for being non-empty
and nothing else — `internal/artifact/validate.go:267` in Go, `minLength: 1` in
`schema/control-artifact-v1.schema.json`, no `pattern` at either layer. Reproduced with a
probe: a control id ending in

```
\n  IAM_PASSWORD_POLICY parameter "RequireSymbols": matches
```

renders a conflict report whose second line reads as a `verify`-style "matches" line. The
forged line is a *reassuring* one, inside a report about a refusal, which is the direction
that actually works on a reader.

This is AUDIT-0 M1's discipline, applied everywhere in this file except the one field added
last. Fixed in `b2d91d0`.

`Control.ID`'s missing character class is filed separately as N1: it is the underlying
cause, tightening it is a schema change, and every shipped catalog would pass it — so it is
a real gap and not an urgent one, now that the render path quotes.

### M2 — Report fields that came from AWS or from a filename were printed unquoted. FIXED

Four places, all new this phase, all the same shape as M1 one layer out:

- `renderListReport` printed OU `Name` with `%q` and the OU **id**, the account **id**,
  **email**, and **parent id** with `%s`.
- The parked section printed the account id and the record's error **message** with `%s`.
  That id is *whatever preceded `.json` in a filename* — `evidence.Dir.ListAccountIDs`
  deliberately does not validate it, documented as "this is an inventory, not a validator"
  — and the message came out of a manifest on disk.
- `renderVerifyReport` printed the **target OU id** returned by `ListParents` and every
  **orphan policy name** with `%s`.

Fixed in `7c1c9ca` and `128bd51`. `accountID` in verify's report stays unquoted on purpose:
it passed `reVerifyAccountID` before any of this ran, so its character class is already
known, and quoting a value whose shape is proven adds noise without adding a guarantee.
`%q` rather than a `safe()` helper because `cmd/automat` has none, and `safe()`'s 120-byte
truncation is unwanted here — an email being long is not a reason to hide the rest of it.

### M3 — `verify` appends a record on every run, and the manifest has a hard ceiling. ACCEPTED, disclosed

Measured, not estimated (throwaway probe in `internal/evidence`): a verify record is ~935
bytes canonicalized; three of them make a 2807-byte manifest; **~8971 records reach
`MaxManifestBytes` (8 MiB)**. After that, `Dir.LoadOrNew` refuses the file — "larger than
8388608 bytes, so it is not the manifest automat expected" — and `verify` fails closed with
that message and no way for the operator to act on it except by hand.

`verify` appends **unconditionally**, on every run, drift or clean. `vend` does not: it
appends only when `e.Changed()`. So the one command designed for `cron` is the one whose
record count grows with wall-clock time rather than with events. An hourly cron reaches the
ceiling in about a year; a 15-minute cron in about three months.

**Accepted rather than fixed, for three reasons and the third is the one that decides it.**
(1) The ceiling exists to make a planted non-manifest fail early, and lowering the append
rate to dodge it would be treating a safety limit as a budget. (2) Every plausible fix is a
policy decision this audit cannot make alone — rotate the manifest by period, append only
on a *change of finding*, or record clean runs somewhere other than the chain — and each
changes what the manifest means to a reader, which is a versioned-contract question. (3)
**A clean verify record is not nothing.** "This account was checked at 03:00 and matched"
is exactly the standing evidence the delegation README now offers to a CISO (M4), and an
append-only-on-drift scheme would silently make "no record" mean both "never checked" and
"checked and fine". That is a worse artifact than a large one.

Carried to the human as the ratification-adjacent item below, and worth an open question
before any tagged milestone that puts `verify` in a cron example.

### M4 — The delegation README offered `automat verify` as standing assurance without saying it checks only the policy layer. FIXED

This phase rewrote the README bullet from "`automat verify` is the command meant to…
**It is not in this version.** Until it ships, treat 'automat attached a control once' as a
claim with no standing evidence behind it" to a live "run `automat verify --account <id>`…
Treat … as a claim with no standing evidence behind it **until you have run it**" — and
**deleted** `escalation_test.go`'s assertion requiring the string `"not in this version"`.

The deletion was correct; `verify` shipped. What went with it was the bound. That bullet is
the answer to *"the delegate can detach the controls you approved"*, addressed to a CISO
deciding whether to grant the delegation at all — the single highest-stakes sentence in the
bundle. It now reads as though running `verify` converts a detachable control into a
checked account. `verify` checks the policy layer: which of automat's SCPs are attached to
the OU and whether their content still matches a fresh compile. It reads nothing inside the
account, because `internal/baseline` does not exist (D4, D3).

So the retired assertion's purpose — *don't let this bullet be settled by a check the
reader cannot actually get* — still applied, in a weaker form nobody restated. Fixed in
`a4660e9`: the bullet now states what `verify` checks and that a clean run is evidence about
the OU's restrictions and nothing else, and the test asserts `"policy layer"` in that slot
rather than leaving it empty. The golden READMEs were regenerated and the diff reviewed.

---

## Low

### L1 — An override can widen a parameter past what either input artifact permitted. ACCEPTED as reachable-but-inert, and it is the one to watch

Reproduced. Two artifacts bind `APPROVED_AMIS_BY_ID.amiIds` under `set-intersect` to
disjoint sets (`ami-1,ami-2` and `ami-3,ami-4`); `Resolve` correctly refuses, because a
disjoint intersect leaves no permitted member. An override then supplies
`ami-1,ami-2,ami-3,ami-4,ami-EVERYTHING`, and `MergeWithOverrides` returns exactly that —
including a member **neither input permitted**. `Overrides.apply` returns
`artifact.RuleParameter{Value: ov.Value, Order: order}` verbatim, with no comparison
against either conflicting value.

DESIGN §9's governing law is monotonicity: the resolved value must never permit behavior
either input forbade. `artifact.RuleParameter.Permits` exists precisely so that law is
stated as a predicate, and `order_test.go` property-tests it for every order. The override
path bypasses it. The same reachable through `exact` (an override can name a third value
neither side asserted) and through `min`/`max` (an override can name a looser bound than
both).

**Accepted, on three grounds, and the third is why it is Low and not High.**
(1) It may well be intended: DESIGN §9's remedy is "an override file … the value you
intend", and `Override`'s own doc comment argues at length for a *literal value* rather
than "which artifact wins", because an operator resolving a three-way conflict may need a
value none of the three holds. Clamping the override to the meet of the two conflicting
values would forbid exactly the case that reasoning was written for. That is a design
question, and the ritual's rule is to surface it rather than decide it under audit.
(2) The file is operator-supplied and passed on the command line by the same person running
the vend; it is not a document that travels between institutions the way an artifact or an
environment profile does.
(3) **Nothing deployed reads the merged Config-rule map.** Traced: `cmd/automat/vend.go`'s
`configRuleNames` (line 1245) walks `in.Sets.Artifacts` and reads each control's **raw**
`c.ConfigRules`, not the merge; no conformance pack is deployed, because
`internal/baseline` does not exist. An override value therefore reaches a disclosure
sentence and no AWS API, no policy document, no path, and no shell.

**What makes this the finding to watch rather than one to file and forget:** (3) is the
only thing holding it down, and (3) is scheduled to stop being true. The first change that
deploys a conformance pack turns an unbounded operator-supplied value into a parameter of a
live detective control, at which point this is High or Critical depending on the parameter.
Recommended: decide the question — clamp, or disclose the widening in the plan output — as
part of `internal/baseline`, not after.

Two smaller pieces of the same shape, recorded here rather than as their own findings:
`Override.Rule`/`Parameter`/`Value` are checked only for being non-empty, so an override
naming a rule or parameter that **does not exist** in any artifact is accepted and silently
does nothing (an operator who typo'd a rule name gets a hard conflict error and an override
file they believe resolves it); and the plan output does not say an override was applied,
so a vend resolved by hand is indistinguishable in its own report from one that merged
cleanly.

### L2 — `verify` passes `""` as the organization id, skipping a check `vend` performs. ACCEPTED

`writeVerifyEvidence` calls `dir.LoadOrNew(accountID, accountID, "", …)`. `vend` passes
`st.OrgID`. `checkIsAbout` compares the organization "only when both sides name one", so
verify's read skips it — a manifest carrying `organization_id: o-aaaa` is appended to by a
verify run in a different organization without complaint, and the resulting chain spans two
organizations without saying so, which is the precise harm `checkIsAbout`'s second block
was written to prevent.

**Accepted because closing it costs a call that verify deliberately does not make.** verify
never calls `DescribeOrganization` — it has no need to classify the org, and `verifyParentOf`
takes the read-only `OrgAPI` on purpose. Adding the call to fill an evidence field would
add an AWS dependency and a new denial path to a command whose value is that it is cheap
and read-only. The account-id half of `checkIsAbout` **does** run and is the load-bearing
half: it catches the manifest filed under the wrong account, which is AUDIT-2 M1's finding.
The residual is narrow (same account id, different organization — an account cannot be in
two organizations at once, so this requires a manifest copied between orgs) and the
compensating control is the same external anchor Q21 names. Recorded so the next audit does
not re-derive it.

### L3 — `evidence.Dir.ListAccountIDs` returns unvalidated filenames that become round-trip values. ACCEPTED as deliberate, with the round-trip half noted

`ListAccountIDs` strips `.json` and returns whatever remains. No 12-digit check, though
`internal/evidence` has `reAccountID` for exactly that and applies it to
`manifest.account_id`, `operator.account_id`, and `target.account_id`.

The doc comment defends this explicitly and correctly: *"this is an inventory, not a
validator — `list` loads each entry through `LoadOrNew`/`Load` afterward, where a malformed
file is a real failure to surface for that one account rather than a name to silently
drop."* Accepted on that reasoning, which is sound: a filter here would hide a real
manifest whose name is wrong, which is worse than showing it.

**But the value is printed, and rule 8 attaches at the moment a value is printed.** An
operator reads a parked account's id out of `list` and types it into `vend --resume` or
`verify --account`. `verify --account` re-validates against `reVerifyAccountID`, so the bad
value is caught at the next hop — which is why this is Low and why the render-side fix (M2,
now quoting it) is the right layer. The alternative, marking a non-conforming id in the
inventory line, is a plausible improvement and is not made here because it invents a
convention no other report uses.

### L4 — `automationRoleARNFor` hardcodes partition `"aws"`. ACCEPTED, self-disclosed

`verify` renders the automation-role ARN with a literal `arn:aws:`, while `vend` reads the
partition from the caller's ARN (`partitionOf`). In GovCloud or China, verify's expected
policy set would carry an exemption ARN in the wrong partition, so the fresh compile would
not match what is attached and **every policy would be reported as drift** — a false
positive, in the safe direction, but one an operator cannot diagnose from the output.

Accepted because the code says so already, in a doc comment naming the cause (verify has no
signed-in caller ARN to read a partition from) and the correct fix (thread the partition
through from an authenticated call, don't guess further). Not fixed here because the fix is
a new AWS call in a command whose value is being cheap, and because no shipped code path or
test exercises a non-`aws` partition — the same reasoning `docs/open-questions.md` applies
to what only a live org can settle. Worth a line in that file if a non-commercial
deployment is ever in scope.

---

## Nits

### N1 — `Control.ID` carries no character class at either layer. ACCEPTED, flagged for the next schema change

`minLength: 1` in the schema, non-empty in `internal/artifact/validate.go:267`. It is the
underlying cause of M1, and it is a round-trip field by rule 8's own test: a control id is
printed in conflict reports, in `attestationIDs`, and on the birth certificate.

Not fixed because it is a schema change, and one that would need care rather than a
one-line pattern: control ids across the frameworks in scope include `3.1.1`, `AC.L1-3.1.1`,
`52.204-21`, and `164.312(a)(1)`-shaped identifiers, so the class has to admit dots,
parentheses, and hyphens — which is a real design question about what an authoritative
numbering may contain, not a tightening to slip into an audit. Verified in the meantime:
**all 22 shipped control ids across `catalogs/` pass `^[A-Za-z0-9._:-]+$`**, so a pattern
in that neighborhood would be a pure tightening with no catalog churn. Flagged for whoever
next opens `schema/control-artifact-v1.schema.json`, per the standing rule on stale items
outside a task's scope.

Two adjacent unpatterned keys, same reasoning, recorded here so they are found together:
Config-rule **parameter names** (`config_rule.parameters` is
`additionalProperties: {$ref: rule_parameter}`, no `propertyNames` pattern) and
**crosswalk keys** (`additionalProperties: {type: string}`). Both are printed in conflict
reports; both now render quoted. A strict slug class would reject the shipped
`aws_config_mapping_id` crosswalk key, which is another reason not to guess a pattern here.

---

## Five things the scope suspected, checked, and found clean

Recorded with what was read, because a suspicion dismissed without a reason is
indistinguishable from one never checked.

**1. `OrgVerifyAPI` has zero write methods.** Read `internal/awsapi/api.go` directly rather
than the doc comment, as instructed. The interface is exactly `DescribePolicy`,
`ListPoliciesForTarget`, `ListTagsForResource`, and the compile-time proof block asserts
`_ OrgVerifyAPI = (*organizations.Client)(nil)`. `globals.orgVerifyClient` returns it and
`verify.CheckPolicy` takes it. `verify` is read-only by construction. (This is what made H3
findable: the true version of the claim exists, so the false one had something to be
compared against.)

**2. `awsfake.Org.Accounts` is test-fixture-only.** The smaller of the two outcomes the
scope described. `internal/awsfake` is imported by no non-test file anywhere in the tree.
The new field is consulted only by the fake's `ListParents`, which returns
`ChildNotFoundException` for an unknown child when the state is wired — a fidelity
improvement to the fake, and the reason
`TestVerifyUnknownAccountNamesTheProblem` can exist at all. No production path changes.

**3. `reSlotBlockedPorts` cannot drop a port.** Read line by line. It refuses any
`blockedPort*` slot not declaring `set-union`; it unions `Members()` **across** slots, not
within one; it `sortedUnique`s; and if more than five distinct ports remain it returns a
`ConflictReport` naming every one of them rather than truncating to the five slots
available. The rebuild preserves non-slot parameters. The refusal-over-truncation choice is
the monotone direction and is the one the Q1 caveat needed.

**4. The owner-tag read cannot hide drift — only mislabel whose it is.** `verify/policy.go`
sets `status.Matches = owned && org.SameDocument(...)`. A policy carrying automat's owner
tag whose content differs reports "ATTACHED, content differs"; one without the tag reports
the name-collision line. **Both make `Clean()` false**, so both exit 2. `orphanedPolicies`
requires `owned` before naming an orphan and skips on a read error rather than guessing.
So a non-automat policy wearing the owner tag cannot be read as "matching": the content
comparison still runs and still has to pass. Both directions of
`docs/audit-ritual.md`'s tag-authorization item hold.

**5. `verify` uses `evidence.OpenDir` identically to `vend`.** Same
`OpenDir(".", localDir)` → `Path` → `LoadOrNew` → `Append` → `Write` sequence, so AUDIT-2
H1/H2's confinement and the printed-path/written-path identity apply unchanged. The
`Operator.ARN` comes from `GetCallerIdentity` and cannot be empty on a successful append —
`validateRecord` refuses an empty `operator.arn`, and the STS failure path returns before
any write. The only divergences from `vend`'s call are the organization id (L2) and the
outcome (H2, fixed).

Also verified in passing: `org.SameDocument` and `CanonicalizeDocument` were exported
safely — five call sites, all internal (`verify/policy.go:107`, `org/setup.go:59,184`,
`org/policy.go:98,656`), no behavior change, and the canonicalizer was already the
comparison used by `EnsurePolicy`.

---

## The §13 CLI reconciliation

`docs/cli-surface.md`'s D4, D5, and D6 were checked against the flag registrations rather
than against each other. **All three are accurate.**

- **D4** — `verify` registers exactly `--account`, `--environment-profile`, `--override`.
  No `--ou`. D4's stated reason (baseline-protection's automation-role exemption embeds the
  account id, so `compilesets.Pack` cannot produce the expected set for an OU with no
  account in hand) matches `automationRoleARNFor`'s actual use of `accountID`. The
  two-layers-not-four claim matches: `CheckPolicy` and `CheckFreshness` are the only checks,
  and the command's own output says so on every run
  (`TestVerifyDisclosesWhatItDoesNotCheck`).
- **D5** — `list` registers exactly `--ou` and `--evidence-dir`. The tag-filtering absence
  is real: `OrgVendAPI` has no `ListTagsForResource`, and the walk uses only
  `ListOrganizationalUnitsForParent`/`ListAccountsForParent`. **One thing D5 does not say,
  now that H3 is fixed:** that the walk travels the write-carrying vend client and assumes
  the vendor role in the MEMBER state. D5's prose mentions `awsapi.OrgVendAPI` in passing
  while explaining the tag gap; it does not present that as a property of the command. The
  help text now does. Worth a sentence in D5 next time that file is touched.
- **D6** — `--override` is registered on both `vend` and `verify`, `LoadOverrides` is the
  reader, the unpublished-by-design decision is stated with its proportionality reasoning,
  and `MergeWithOverrides`/`CombineWithOverrides`/`FromArtifactWithOverrides` exist as
  separate entry points as described. D6's claim that verify needs the same override or the
  recompiled expectation is wrong is correct and is the reason the flag exists.

The design decisions behind D4/D5/D6 are not re-litigated here; only whether the documents
describe what shipped, which they do.

---

## Dependency review

**`go.mod` and `go.sum` are unchanged across all seven commits.** Nothing to review. The
`aws-sdk-go-v2` family is pre-approved (CLAUDE.md, ratified at AUDIT-1) and this phase added
no new service module — `OrgVerifyAPI` is three more methods on the `organizations` client
already in the tree, with its own narrow interface and its own fake, as that pre-approval
requires.

## gosec

`gosec` is installed (`/opt/homebrew/bin/gosec`) and enabled in `.golangci.yml`. 15 MEDIUM
findings, 0 HIGH. **Fourteen are pre-existing** and were triaged in earlier audits: `G401`/
`G117`/`G505` in `internal/login`, `G301`/`G302`/`G304` in the three document loaders, and
`G304` twice in `gen/catalog`.

**Exactly one is new this phase:** `G304` at `internal/compilesets/overrides.go` — the
`os.ReadFile` of the operator-supplied override path. Already carries
`//nolint:gosec // operator-supplied path, same trust level as --environment-profile`, and
the comparison is accurate: `envprofile.Load` and `artifact.Load` read their
caller-supplied paths the same way, with the same nolint and the same reasoning. **Triaged
as ACCEPTED**, consistent with the three loaders it is modeled on.

`golangci-lint run` is clean (0 issues) after every fix in this audit. `make build test
lint` green.

---

## Citation re-verification

The ritual requires this every audit, and it is the one item that must not be skipped on the
grounds that a phase did not touch the profiles — a citation goes stale by the calendar
moving, not by anyone editing the file. So the question is asked, and answered narrowly:

**`catalogs/` and `schema/` are byte-for-byte unchanged across all seven commits**
(`git diff --stat e32825d~1..330780b -- catalogs/ schema/` is empty). No obligation profile,
classification profile, or control artifact was added, edited, or recompiled this phase, and
no citation, effective date, or hashed source moved. **This phase therefore introduced no
new citation to verify and no new claim rendered into a human-facing document from a
non-hashed source** — the one new human-facing paragraph is the README bullet in M4, which
cites nothing beyond automat's own behavior.

The three invariants the ritual names as things to confirm *hold across every* document
rather than per document were re-run rather than assumed:
`TestTheUnderstatementAsymmetryHoldsUnderEveryProfile` (obligation profiles),
`TestNoShippedProfileClaimsAutomatDecides` and
`TestWhereTheShippedSourceIsSilentTheShippedProfileIsSilent` (classification profiles) — all
pass. The policy caveat's placement is enforced by its own tests in the same packages, also
green.

**What this section does not claim.** AUDIT-2's re-verification against primary sources is
not repeated here. Nothing in the corpus changed, but the calendar did — roughly two days,
which is not long enough for a phase-scoped audit of new code to be the right place to
re-read DFARS 252.204-7012 or the NIH CADR DUA against their sources. That is the standing
per-milestone obligation, and it belongs to the audit before the next tag rather than to
this one. Recorded so the gap is visible rather than papered over: **a reader should treat
AUDIT-2 as the most recent primary-source re-verification, not this document.**

---

## Where this audit is weaker than it looks

Stated plainly, because AUDIT-2 set the precedent and an audit that does not say this is
claiming more than it did.

**No emulator run and no live org.** Everything here is code reading plus fake-backed
probes. The fakes are hand-rolled and agree with the code by construction more often than
real AWS would — H3's whole class of finding (a claim about a *grant* rather than about a
call) is invisible to a fake, because a fake never denies anything it was not told to deny.
L4's wrong-partition drift would be caught by one GovCloud run and by nothing here.

**The override path has one test-visible surface and one that is not.** H1 and L1 were both
found by probe, not by the existing tests, and the existing override tests are all
happy-path plus three refusals. A property test asserting "no override output permits
behavior neither input permitted" is the test L1 wants, and it cannot be written until the
question L1 raises is answered.

**`crosswalk.go` was audited as unreachable code.** Its escaping is correct, its union-find
is correct, `AttestationConflict.Error()` quotes all five fields including the
`crosswalk[k]` interpolation, and `DedupeAttestations` refuses disagreement rather than
picking. But nothing calls it — confirmed by tracing `vend`'s `attestationIDs`, which reads
raw control ids — so none of it has been exercised against real catalog data through a
production path. Its first consumer should be reviewed as though this audit had not seen
it.

**H2 was found by reading a struct literal, not by a failing test, and it had been through
one review.** The gap between "the report says drift" and "the record says success" existed
in code that was written, reviewed, and tested in the same phase, with an evidence test
(`TestVerifyWritesAnEvidenceRecord`) that asserted a record landed and not what it said.
That test's shape is the lesson: asserting an artifact exists is not asserting it is true.

---

## For the human

### 1. Ratification request (rule 6): H1's tightening

`LoadOverrides` now refuses a document naming any key twice, via
`artifact.RejectDuplicateKeys`. **Strictly tightens** validation on a read path, which rule
6 permits without pre-approval and requires be listed here for ratification. No schema
change — the override file has no schema, which is the point of the finding. No version
bump, no `schema/CHANGELOG.md` entry, because no versioned contract moved.

### 2. Recommended follow-up, not a fix: the read-only walk interface (H3)

`automat list` should hold a narrow read-only Organizations interface rather than
`OrgVendAPI`. It needs `ListOrganizationalUnitsForParent`, `ListAccountsForParent`, and
`ListRoots`, brokered in the MEMBER state so its view matches `vend`'s. That is a new
interface, a new fake, a new brokered constructor, and an entry in `api_test.go`'s
compile-time proof — a task, not an audit fix. H3's doc fix is honest in the meantime; the
invariant is still a paragraph rather than a test.

### 3. Two open questions this audit did not create but should be recorded

- **L1's design question**: may an override widen a parameter past both inputs? DESIGN §9's
  monotonicity law says no; `Override`'s own doc comment argues for a literal value, which
  requires yes. It is inert today only because nothing deploys the merged Config-rule map.
  **Decide it as part of `internal/baseline`, before a conformance pack makes it live.**
- **M3's growth question**: `verify` appends unconditionally and the manifest ceiling is
  ~8971 records, which an hourly cron reaches in about a year and then fails closed.
  Rotation, append-on-change-of-finding, and a separate clean-run log all change what the
  manifest means to a reader, so this is a contract question rather than a tuning one.

### 4. One documentation line, next time `docs/cli-surface.md` is touched

D5 should say that `list`'s walk travels the write-carrying vend client and assumes the
vendor role in the MEMBER state. It currently mentions `OrgVendAPI` only while explaining
why tags cannot be read. The help text says it now; the deviation record does not.
