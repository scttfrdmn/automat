# AUDIT-6 — Phase 5, closing (`automat reclaim`, the KMS evidence signer)

Adversarial self-audit per CLAUDE.md, "Security audit ritual", and the scope in
`docs/audit-ritual.md`. Conducted 2026-08-09 against the tip of `main` (`35b365e`) —
everything Phase 5 shipped: `automat reclaim` (`internal/org/reclaim.go`,
`internal/awsapi.OrgReclaimAPI`, `internal/awsfake/orgreclaim.go`, `cmd/automat/reclaim.go`)
and the KMS evidence signer (`internal/evidence/kmssigner.go`, `internal/awsapi.KMSAPI`,
`internal/awsfake/kms.go`, `cmd/automat/evidencesign.go`, the two new `config.Context`
fields). This closes Phase 5.

**Assumptions held throughout.** Everything AUDIT-1, AUDIT-2, AUDIT-4, and AUDIT-5 assumed,
plus what this phase's two pieces add. `reclaim` is the first destructive command this
project has ever shipped — every prior phase kept `DetachPolicy` and `CloseAccount`
unreachable specifically so this moment would need a real gate, not a retrofit — and the
auditor's job is to assume the gate has a hole until the code says otherwise. The account id
on the command line is attacker-controlled by the same standing threat model (a phished
operator, a copy-pasted flag from a chat message); so is every value a config file or an
environment profile hands to the KMS signer.

**What exists to audit that did not before.** `internal/org/reclaim.go`'s `Reclaimer` type
(`DetachOwnedPolicies`, `CloseAccount`, and their shared pagination/ownership helpers),
`internal/awsapi.OrgReclaimAPI`, `internal/awsfake/orgreclaim.go`, `cmd/automat/reclaim.go`'s
plan/apply/`--yes` wiring, `internal/evidence/kmssigner.go`'s `KMSSigner`/`KMSVerifier`,
`internal/awsapi.KMSAPI`, `internal/awsfake/kms.go`'s HMAC stand-in, `cmd/automat/evidencesign.go`,
and `config.Context`'s two new `evidence_kms_*` fields plus `validateEvidenceKMS`.

**Method.** Every finding below was reproduced by a throwaway probe test *before* being
written down, then fixed, then **counter-checked** in a temporary git worktree at the
commit immediately before that finding's fix: the new or changed test was copied there and
confirmed failing for the reason the fix addresses, not for an unrelated one, then the
worktree was removed. This is AUDIT-2's, AUDIT-4's, and AUDIT-5's method, unchanged. Four
separate worktree round-trips were run, one per fix, because each fix landed as its own
commit rather than being batched.

**Result.** 4 findings: 1 critical, 2 high, 1 medium, 0 low, 0 nit. **All 4 FIXED.** Plus a
walk of every numbered item the task named, gosec triaged (17 pre-existing, already-`nolint`'d
findings, nothing new), dependency review (nothing new — no dependency was added by this
phase or by this audit's fixes), a CLI-surface reconciliation (clean — `reclaim`'s four flags
match DESIGN §13 and `docs/cli-surface.md` D9 exactly), and a re-check of AUDIT-5's M3
(evidence-manifest growth) now that `reclaim` is a fourth writer and this audit's own H1 fix
means it can write a *second* kind of record.

**Fix commits.** C1 → `6255657`. H1 → `0e6c3af`. H2 → `2391e64`. M1 → `76301f7`.

---

## Critical

### C1 — `reclaim` detached a service control policy shared by a live sibling account, stripping that account's guardrails as a side effect of reclaiming a different one. FIXED

`DetachOwnedPolicies` (`internal/org/reclaim.go`) resolved the account being reclaimed's
parent OU (`target`, via `verifyParentOf` — the same `ListParents` call `verify` makes) and
detached every automat-owned policy attached to `target`, with no check for what else sits
under it. But a service control policy is attached **at the OU**, not the account (DESIGN
§5, §8, restated in `docs/reclaim-design.md` itself), and nothing in this codebase enforces
one account per OU — `resolveDestination` (`cmd/automat/vend.go`) places an account at
whatever `target_ou` an environment profile names, and two vends against the same profile
land two accounts under the same OU, sharing the one automat-owned SCP `EnsurePolicy` created
for it. `docs/cli-surface.md` D5's own description of `list`'s OU-tree walk already depends
on this being possible.

Reproduced by probe before any fix existed: vend two accounts under the same profile (both
land under `ou-exam-vendtest1` in the fixture, confirmed by `ParentOf`), confirm they share
one attached policy, then `reclaim --yes` account A alone.

```
policies on shared OU before reclaiming A: [p-auto0001]
policies on shared OU after reclaiming A (B is still ACTIVE): []
SECURITY: reclaiming account A (100000000001) detached the shared OU ou-exam-vendtest1's
automat-owned SCP, stripping guardrails from still-active sibling account B (100000000002)
```

Account B — never named on the command line, never mentioned in the plan, still `ACTIVE`
in AWS — lost every control the shared SCP enforced (region allowlist, service allowlist,
baseline-protection, whatever the environment profile's compile produced) the instant
account A's reclaim ran. This is exactly the "add restrictions, never loosen the
institutional floor" property `docs/security-review.md` and the bundle's own blast-radius
argument are built on, broken by automat's own destructive command rather than by anything
an attacker did to the delegation policy. Ranked critical rather than high: the harm is not
a report reading wrong or a denial pointing at the wrong file — it is a live, still-in-use
AWS account silently losing its enforced controls, with no warning printed and no evidence
record naming what happened to it, because the printed plan and the evidence manifest both
describe account A only.

**Fixed**: `internal/awsapi.OrgReclaimAPI` gained `ListAccountsForParent` (already granted
to the delegated identity by `internal/bundle/policy.go`'s `readActions`, scoped to the same
OU ARNs the attach/detach statement already names — no bundle change needed, the read this
fix needs was already granted and simply never called from this path).
`DetachOwnedPolicies` now takes the account being reclaimed's own id and, the first time it
finds an automat-owned policy to detach, lists the target OU's other accounts and refuses to
detach while any of them reports `ACTIVE` — reported as `VerbUnchanged` with the live
sibling's account id named in the detail, the same "report what nothing here may touch"
discipline the not-automat's-policy branch already follows, never silently skipped.
`TestDetachOwnedPoliciesLeavesAPolicyAttachedWhenALiveSiblingSharesTheOU`,
`TestDetachOwnedPoliciesDetachesWhenTheOnlyOtherAccountUnderTheOUIsNotActive` (a `SUSPENDED`
sibling does not block the detach — it has no guardrails left to strip),
`TestDetachOwnedPoliciesDetachesWhenNoSiblingSharesTheOU` (the ordinary one-account-per-OU
case keeps working exactly as before), and the CLI-level
`TestReclaimLeavesASharedOUPolicyAttachedWhenALiveSiblingExists` all pin it, the last one
also confirming the account actually named on the command line still closes even though the
shared policy stays. Counter-checked in a throwaway worktree at the pre-fix commit: the
CLI-level test, copied there against the single-argument pre-fix `DetachOwnedPolicies`,
fails for the documented reason (the shared policy is stripped) rather than a build error.
`docs/reclaim-design.md` gained a paragraph recording the decision.

---

## High

### H1 — A detach that genuinely happened, followed by a close that failed, left zero evidence record. FIXED

`cmd/automat/reclaim.go`'s `RunE` called `apply.DetachOwnedPolicies` and
`apply.CloseAccount` in sequence and, on either failing, returned `reclaimPartialError`'s
message **directly** — `writeReclaimEvidence` sat below both calls and was never reached on
this path. `vend.go`'s own `writeVendEvidence` states the discipline this violates in its own
comment: *"The manifest is written whether or not the vend succeeded, and before the error is
returned. A run that created an account and then failed to attach a policy has produced the
state that most needs recording."* `reclaim` did not follow its own sibling command's rule.

Reproduced by probe: seed a fixture where `CloseAccountQuotaExceeded` is set, run
`reclaim --yes` against an account with an automat-owned SCP attached. `DetachPolicy`
genuinely succeeds (the policy is gone from the OU, confirmed against `AttachedTo`),
`CloseAccount` genuinely fails, and the command returns an error — but `evidence/<id>.json`
does not exist at all. An account that just lost its own SCP protection, with the closure
still pending, has no record anywhere that its guardrails changed. This is not a cosmetic
gap: DESIGN §11 states the whole manifest's purpose is the born-compliant chain of custody,
and a step that changes an account's enforcement and writes nothing about it is the one
failure mode a hash-chained evidence store exists to make impossible.

Ranked high rather than critical: nothing was corrupted, nothing false was recorded, and the
account itself is not more exposed than the plan already disclosed it would be (its own
SCP, not a sibling's). It is high rather than medium because the missing record is not a
detail but the entire operation's evidence — an auditor reading this account's manifest
after the fact would see nothing between the last `vend`/`verify` record and whatever
eventually closed the account, with no trace of the interval where it briefly had no
automat-managed SCP at all.

**Fixed**: `RunE` now calls `writeReclaimEvidence` unconditionally after the apply attempt,
whether or not it errored, before any error is returned — the same order
`writeVendEvidence`'s call site already follows. `writeReclaimEvidence` gained an `applyErr`
parameter: nil produces the existing `OutcomeSuccess` record, non-nil produces an
`OutcomeFailure` record carrying `RecordError` (message, and action/resource/remediation
when the cause is a `PermissionError`) — the same success/failure split `verify`'s own
evidence write already makes for policy drift. `reclaimPartialError` now names the manifest
path in its returned message, mirroring `vendFailure`'s own "Recorded in %s" line.
`TestReclaimWritesEvidenceForAPartialFailureToo` pins it: partial failure, confirmed via a
quota-exceeded close, now produces an `OutcomeFailure` `OpReclaim` record naming the SCP that
was actually detached before the close failed. Counter-checked in a throwaway worktree: the
new test, copied to the commit immediately before this fix, fails with "manifest has no
OpReclaim record after the partial failure" — the documented gap, not a build error.

### H2 — A `DetachPolicy` denial in the MEMBER state sent the operator to widen the vendor role, a file that cannot grant a policy action. FIXED

`Reclaimer.denied` (`internal/org/reclaim.go`) branched on a single field, `r.Credential`,
and unconditionally attributed every denial to the vendor role when that field was
`Brokered`: *"ask the organization's management account to add [action] on [resource] to the
vendor role this account assumes."* But `r.Credential` describes `CloseAccount`'s own
credential shape only — native in MANAGEMENT, the brokered vendor role in MEMBER
(`Reclaimer`'s own field doc, `docs/reclaim-design.md`). `DetachPolicy` and the three read
methods `DetachOwnedPolicies` calls (`ListPoliciesForTarget`, `ListTagsForResource`, and this
audit's own new `ListAccountsForParent`) run on `r.Policy`, which the type's own doc comment
says is **never** brokered: in MEMBER state it is the caller's own delegated identity, gated
by `delegation-policy.json`, exactly the credential `OrgPolicyAPI` already uses. A single
`Reclaimer` built for MEMBER state sets `Credential` to `Brokered` (because `CloseAccount`
needs that word), and `denied` then applied that one word to every action indiscriminately.

Reproduced by probe: build a `Reclaimer` with `Credential: Brokered`, fail `DetachPolicy`
with `AccessDenied`, and read the remediation:

```
to fix: ask the organization's management account to add organizations:DetachPolicy on
p-fake0001 to the vendor role this account assumes — the file is vendor-role.cfn.yaml
(or vendor-role.tf) in the onboarding bundle (`automat setup --request`); account closure
cannot be delegated to a member account and must travel through that role
```

`vendor-role.cfn.yaml`/`.tf` (`internal/bundle/role.go`'s `vendorRoleActions`) has no
`DetachPolicy` entry and never will under this design — `docs/reclaim-design.md` is explicit
that `DetachPolicy` is delegable and deliberately never brokered. An operator following this
remediation would ask central IT to widen the wrong file, be told (correctly) that the
action does not belong there, and have no path forward from the error message itself. This
is CLAUDE.md rule 7's exact failure mode — "which action, which resource, what grant would
fix it" — with the third element actively wrong rather than merely absent.

Ranked high: `Ensurer.denied` (`internal/org/ensure.go`) already draws this identical
distinction for the identical policy-vs-account split, correctly, which is what makes this a
regression in the newer, less-exercised code rather than a novel design question — the
answer already existed one file over and `Reclaimer.denied`'s own doc comment claims to
mirror it ("Mirrors Ensurer.denied's shape") while actually reproducing only the
`Native`/`Brokered` branch and dropping the action-based one underneath it.

**Fixed**: `Reclaimer.denied` now switches on the action first: `organizations:CloseAccount`
keeps the existing Native/Brokered split (vendor role in MEMBER, own identity policy in
MANAGEMENT); every other action attributes a MEMBER-state denial to the delegation policy,
never the vendor role, regardless of what `r.Credential` says — matching
`Ensurer.denied`'s own `strings.HasPrefix`-based classification for the equivalent case.
`TestDetachPolicyDeniedInBrokeredStateBlamesTheDelegationPolicyNotTheVendorRole` and
`TestCloseAccountDeniedInBrokeredStateStillBlamesTheVendorRole` pin both halves. Counter-checked
in a throwaway worktree: the first test, copied to the pre-fix commit, fails with "error text
is missing \"delegation-policy.json\"" — the exact wrong-file bug, not a build error.

---

## Medium

### M1 — Re-running `reclaim --yes` against an account it had already closed surfaced AWS's raw exception instead of reporting success. FIXED

`Reclaimer.CloseAccount` recognized exactly two `ConstraintViolationException` reasons
(the closure quota, and "cannot close the management account") and otherwise fell through to
`r.denied`, which only wraps an *access-denied* error — anything else, including AWS's real,
named `AccountAlreadyClosedException`, passed through unrecognized as a bare SDK error with
no automat-authored remediation at all. `docs/reclaim-design.md` states plainly that
"detach succeeded, close failed" is "a plain, resumable state — the operator re-runs
`reclaim` and the detach step reports `unchanged`" — but the design page's own resumability
argument is silent on the case where the *close* is what a re-run repeats, and CLAUDE.md rule
4 requires every mutating command be safely re-runnable, full stop, not only the half the
design page happened to narrate.

Reproduced by probe: close an account once (succeeds), close it again through the same
`Reclaimer.CloseAccount` call. Before the fix, the second call returned AWS's bare
`AccountAlreadyClosedException: This account is already closed.` — no remediation, and
critically, `Applied` unset on no `Action` at all, meaning `reclaim`'s own printed plan and
evidence write for a legitimate re-run would treat the second invocation as a hard failure of
a command whose only actual problem is that it already succeeded once.

Ranked medium rather than high: nothing is corrupted, nothing is misreported as compliant,
and the account is in exactly the state the operator wanted (closed) either way — the defect
is that automat's own re-run story, the thing rule 4 exists to guarantee and the thing this
very design page argues for, did not hold for this one exception. An operator confused by a
first run's ambiguous outcome (a network blip after the request was accepted, say) who
re-runs `reclaim --yes` to be sure gets an error that looks like failure for an operation
that already succeeded.

**Fixed**: `CloseAccount` now recognizes `orgtypes.AccountAlreadyClosedException` via
`errors.As` and records `VerbUnchanged` — "already closed: AWS reports this account was
closed by an earlier request. Nothing further for this step to do" — rather than propagating
the raw exception. `internal/awsfake.OrgReclaim.CloseAccount` now returns this exception
when asked to close an account already `SUSPENDED`, so the fake actually exercises the path
rather than making it untestable by construction (before this fix, the fake happily
re-suspended an already-suspended account and returned success, which is not what real
`CloseAccount` does per its own SDK doc comment).
`TestCloseAccountReRunAgainstAnAlreadyClosedAccountIsUnchangedNotAnError` pins it, plus an
end-to-end probe confirming a full second `automat reclaim --yes` invocation against an
already-closed account now completes cleanly with an `Applied:` section reading "unchanged
account." Counter-checked in a throwaway worktree: the test, copied to the pre-fix commit
(where the fake had no `AccountAlreadyClosedException` branch either), fails with the
second call reporting `VerbClose`/`Applied: true` instead of the expected unchanged — the
exact pre-fix behavior, not a build error.

---

## Checked and found clean

Recorded with what was read to decide it, per AUDIT-1's binding precedent: a suspicion
dismissed without a reason is indistinguishable from one never checked.

**1. TOCTOU between the printed plan and the apply.** Traced `cmd/automat/reclaim.go`'s
`RunE` directly: `plan` and `apply` are two *separate* `org.Reclaimer` values, and `apply`'s
`DetachOwnedPolicies`/`CloseAccount` calls make their own fresh `ListPoliciesForTarget`/
`ListAccountsForParent`/`CloseAccount` calls — nothing caches or reuses `plan`'s action list.
Confirmed concretely: seeding a *third* automat-owned policy onto the target OU before the
single `reclaim --yes` invocation runs shows up in *both* the printed plan and the applied
detach list, because the plan step's own read sees it — there is no code path where an
apply trusts a stale read from an earlier phase. This is the same "a real run of the same
code in ModePlan" pattern `vend` and `init` already use, and it was already the audited
shape for those two commands; nothing about `reclaim` weakens it.

**2. `policyOwnership`/`attachedPolicies` copies, diverged from `policy.go`'s originals.**
Diffed both function bodies against `internal/org/policy.go`'s own `policyOwnership`/
`attachedPolicies` line by line (mechanical rename of receiver and field names, nothing
else). `policyOwnership` is byte-for-byte identical logic. `attachedPolicies` differs in
exactly one place: `policy.go`'s version special-cases `TargetNotFoundException` with a
tailored message ("no root, OU, or account with that id exists"), while `reclaim.go`'s
version falls through that case to the generic `r.denied` wrapper. This is a narrower, not a
wider, refusal — `reclaim`'s version still refuses on that error, just with `denied`'s
generic remediation instead of a bespoke sentence — so it is a message-quality gap, not a
security gap, and not addressed as a separate finding: `verifyParentOf` runs before
`DetachOwnedPolicies` in the actual command and already refuses a target that does not
exist, so this path is unreachable from the CLI today. Noted for whoever next touches this
copy rather than fixed, since fixing it would mean deciding whether to finally share the
helper the file's own comment explains why it does not.

**3. The KMS fake's three failure modes.** Probed directly: sign a message under key A,
attempt to verify it (a) under a different key id with a spliced-in claim
(`TestKMSVerifierRefusesASignatureFromADifferentKey`, already in the suite), (b) against a
tampered *message* with the original signature and key
(reproduced: `KMSInvalidSignatureException`), and (c) with a tampered *signature* byte
against the original message and key (reproduced: the same exception). All three are
genuinely distinct code paths through the HMAC comparison (`hmac.Equal` recomputed over
whatever `Message`/`KeyId` the caller supplied), not one collapsed check — the fake's stand-in
crypto exercises the wiring `KMSSigner`/`KMSVerifier` build on top of exactly as its own doc
comment claims, and none of the three would pass if `KMSSigner.Sign` or `KMSVerifier.Verify`
silently dropped the message or the key id from what they hand to `kms.SignInput`/
`VerifyInput`.

**4. The KMS alias-resolution trust boundary.** Re-read `KMSSigner.Sign`: `s.KeyID`
(config-supplied, possibly an alias) is sent as `SignInput.KeyId`; `aws.ToString(out.KeyId)`
(KMS's own response) is what gets written into `Signature.KeyID`, never the caller's value —
confirmed by `TestKMSSignerReportsTheKeyKMSActuallyUsed`, already in the suite, which sets
`fake.ResolvedKeyID` to a different string than the alias signed with and asserts the
signature carries the resolved value. The scenario the task asked about — a later
`KMSVerifier.Verify` checking against the alias rather than the resolved ARN — cannot arise
from automat's own code today because **nothing in this codebase calls `KMSVerifier.Verify`
at all**: grepped `cmd/automat/*.go` for `VerifyChain`/`KMSVerifier` outside test files and
found zero call sites. `docs/beyond.md` discloses this explicitly ("nothing in this codebase
*checks* one, and there is no trust-policy loader and no registry of accepted signers"), so
the alias-mismatch scenario is real but unreachable until a verify path is built — recorded
as an open question for whoever builds one, not a live finding against code that does not
exist.

**5. Round-trip field patterns, enumerated (rule 8).** `config.reKMSKeyID`
(`internal/config/config.go`), `evidence.reRoundTripRef`
(`internal/evidence/validate.go`), and `schema/evidence-manifest-v1.schema.json`'s
`round_trip_ref` `$def` are three independent copies of the same rule, per the schema's own
comment ("rule 8 is only meaningful if both layers state the same thing"). Diffed the three
patterns directly:

- Go, `internal/config`: `^[a-zA-Z0-9][a-zA-Z0-9._:/+=@-]{0,255}$`
- Go, `internal/evidence`: `^[a-zA-Z0-9][a-zA-Z0-9._:/+=@-]{0,255}$`
- JSON Schema: `^[a-zA-Z0-9][a-zA-Z0-9._:/+=@-]{0,255}$`

Byte-for-byte identical. A config value `reKMSKeyID` accepts cannot produce a
`KMSSigner.Sign` output whose `Signature.KeyID` the evidence validator or the published
schema would then reject, because `KMSSigner.Sign` writes back `aws.ToString(out.KeyId)` —
KMS's own response — and `NewKMSSigner`'s constructor already checks the *configured* value
against this exact `reRoundTripRef` pattern (not `reKMSKeyID`) before ever calling KMS, so an
operator who configures a value `config.validateEvidenceKMS` accepts is guaranteed to be
signing with a value `evidence.NewKMSSigner` would also accept, since both gates are the
same regular expression under different names.

**6. `automat reclaim`'s CLI surface against DESIGN §13 / `docs/cli-surface.md` D9.**
`cmd/automat/reclaim.go`'s four flags (`--account`, `--dry-run`, `--yes`,
`--evidence-dir`) match D9's own description and DESIGN §13's `automat reclaim` line
exactly, including the unconditional-`--yes` behavior (no default, refused outright without
a plan-contents check) both documents claim. No drift found.

**7. Onboarding bundle's disclosed `CloseAccount` gap.** Grepped `internal/bundle/role.go`
directly: `vendorRoleActions` has no `organizations:CloseAccount` entry, confirming
`docs/reclaim-design.md` and `docs/security-review.md`'s own claim that the vendor role
cannot close an account today. The MEMBER-state error path
(`reclaimOrgClients`, `cmd/automat/reclaim.go`) names this explicitly when
`orgCtx.VendorRoleARN` is empty ("the vendor role needs `organizations:CloseAccount` added to
it — see docs/reclaim-design.md") — actionable in the sense that it correctly identifies
where the grant belongs (there is no other template variant it could point to instead,
confirmed against `internal/bundle/role.go`'s single `VendorRoleCFN`/`VendorRoleTF` pair), even
though widening that template is disclosed, separate future work rather than something this
build can do for the operator. H2 above is the sibling gap this same code path had for the
*other* four actions; `CloseAccount` itself was already correctly attributed before this
audit, confirmed by `TestCloseAccountDeniedInBrokeredStateStillBlamesTheVendorRole`.

**8. gosec.** Ran `gosec ./...` directly (17 issues, all pre-existing and already
`//nolint:gosec`-annotated: G304 file-inclusion-via-variable across `internal/artifact`,
`internal/assess`, `internal/classprofile`, `internal/envprofile`, `gen/catalog` — every one
an operator-supplied document path, the same accepted shape `artifact.Load` set; G301/G302
directory/file permissions on published, non-secret documents; G117/G505 in `internal/login`'s
SSO token-cache filename, unrelated to secrecy per that file's own comment). Cross-checked
against `golangci-lint run ./...` (0 issues, gosec wired in per `.golangci.yml`) — both agree.
Nothing new in `internal/org/reclaim.go`, `internal/awsapi/api.go`, `internal/awsfake/orgreclaim.go`,
`internal/awsfake/kms.go`, `internal/evidence/kmssigner.go`, `cmd/automat/reclaim.go`,
`cmd/automat/evidencesign.go`, or `internal/config/config.go`'s new validation — the file count
and line count both grew (this audit's own fixes), the issue count did not.

**9. Dependency review.** No new dependency this phase or from this audit's fixes.
`internal/awsapi.KMSAPI` uses `github.com/aws/aws-sdk-go-v2/service/kms`, already
pre-approved under CLAUDE.md's blanket aws-sdk-go-v2 ratification (AUDIT-1). Nothing else
imported that the tree did not already depend on.

---

## AUDIT-5's M3, re-checked now that `reclaim` is a fourth writer and can write a failure record

AUDIT-4's M3 (accepted, and re-confirmed by AUDIT-5 with the sum measured rather than
assumed) is about the per-account evidence manifest's hard ~8 MiB / ~8,971-record ceiling
under multiple writers. This phase adds `reclaim` as a **fourth** writer, and this audit's
own H1 fix means `reclaim` can now append a *second kind* of record (an `OutcomeFailure`
`OpReclaim`, alongside the `OutcomeSuccess` one it already wrote) — worth re-running the
math rather than assuming H1 changed nothing about it.

Measured directly (throwaway probe, `evidence.CanonicalRecordJSON` over a representative
record of each kind): an `OpReclaim` success record with one detached SCP ARN canonicalizes
to 417 bytes; a failure record carrying the same SCP plus a `RecordError` is 577 bytes —
both smaller than `verify`'s own ~935-byte record, so `reclaim` reaching the ceiling on its
own would take longer than `verify` does, matching the shape AUDIT-5 already found for
`assess`.

**But `reclaim` does not gain a cron-shaped reason to run repeatedly the way `verify`
does.** AUDIT-5's own reasoning for `assess` applies here with more force, not less: an
account is reclaimed once, at the end of its life — there is no "reclaim every account every
15 minutes" use case, and M1's fix (this audit) means a confused operator's *retry* of a
reclaim that already succeeded now reports `VerbUnchanged` rather than erroring, so a nervous
double-run does not even produce a second write (`writeReclaimEvidence` still appends a
record for that retry, but exactly one, not a growing sequence — `Applied` stays false on
the unchanged action, so nothing about the retry loop this audit could construct produces
unbounded growth). H1's fix widens *what* a single reclaim attempt can write (one record
instead of none, on the specific path where detach succeeded and close failed) but does not
change *how often* reclaim runs, which is the variable the growth-rate math actually depends
on. AUDIT-4's own three reasons for accepting M3 rather than fixing it — the ceiling is a
safety limit, not a budget to dodge; every plausible fix is a policy decision about what the
manifest means; a clean record is itself standing evidence — all still hold, now measured
against a fourth writer whose own contribution is smaller per-record than either of the other
three and whose call frequency is bounded by "once per account's death," not by a timer.
**Still accepted, same reasons, sum re-measured with reclaim's two record shapes included.**

---

## CLI surface vs. DESIGN §13

Unchanged from `docs/cli-surface.md` D9's own reconciliation, re-confirmed directly against
`cmd/automat/reclaim.go`: `--account`, `--dry-run`, `--yes`, `--evidence-dir`, all four
present from this command's first commit, `--yes` unconditional with no default. No addition
and no contradiction found this audit.

---

## For the human

Nothing requires a decision beyond reviewing the four fixes above, all of which strictly
tighten or correct existing destructive-path behavior rather than loosening anything (rule 6
does not apply — no schema changed). One item worth a note for whoever next touches
`internal/org/reclaim.go`'s `attachedPolicies`: it silently drops `policy.go`'s bespoke
`TargetNotFoundException` message (clean item 2 above) — harmless today because
`verifyParentOf` already refuses an unknown target earlier in the same command, but worth
restoring if that ordering ever changes. A second note for whoever eventually builds a
verification path for KMS-signed manifests (clean item 4): the alias-vs-resolved-ARN mismatch
this audit's prompt anticipated is real in principle and cannot be checked today because no
`KMSVerifier.Verify` call site exists anywhere in this codebase outside its own tests.
