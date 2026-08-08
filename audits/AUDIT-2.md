# AUDIT-2 — Phase 2 (union semantics, the SCP packer, evidence, `init`, `vend`, and the profile axes)

Adversarial self-audit per CLAUDE.md, "Security audit ritual", and the scope in
`docs/audit-ritual.md`. Conducted 2026-08-05/06 against the tree from `541c3ec` (the
AUDIT-1 baseline) through `b2ca812`.

**Assumptions held throughout.** Everything AUDIT-1 assumed, plus what Phase 2 added.
Every document automat *reads* — control artifact, environment profile, classification
profile, obligation profile, evidence manifest — is attacker-supplied, including ones
that arrive with a hash and a signature attached. Every value automat *writes* into a
human-facing document is a claim that will be forwarded, quoted in a contract annex, or
typed onto a command line by someone who did not run the command. **A vend is not a dry
run**: it creates an account in a real organization, attaches policies to a real OU, and
writes a birth certificate somebody will treat as a record.

**What exists to audit in Phase 2 that did not before.** `internal/compilesets` (union
semantics, narrowing, the quota-aware packer, the SCP reader),
`internal/evidence` (hash-chained manifests and the signer interface),
`internal/envprofile` and `internal/classprofile` (two new document types with their own
validators, canonicalizers, and attestation checks), `internal/catalog` (id → embedded
document resolution), `internal/org`'s mutating half (ensure-semantics account, OU, and
policy operations), `gen/catalog` (the compiler and its curated sources),
`catalogs/` (two control artifacts, three obligation profiles, two classification
profiles), and `cmd/automat`'s `init` and `vend`. Still absent: `verify`, `assess`, the
in-child baseline (DESIGN §7 step 5), and any KMS signer.

**Method.** Findings came from mangling documents and running the resulting bytes through
the real command paths, not from reading for smells. Every finding was reproduced before
it was written down, and three were re-graded after a probe contradicted the reading that
produced them — one upward, two downward. Fixes were **counter-checked** rather than
jam-checked this time: the new test is copied into a throwaway git worktree at the
*previous* commit and run there, with `git diff --numstat` over the production files
confirming zero changes. This replaces AUDIT-1's practice of deliberately breaking the fix
in place, which the harness correctly refused as security-test removal; the worktree
method proves the same thing without a tree in which the fix is absent.

**Adversarial agents.** Independent hostile-auditor passes were run with disjoint lenses —
the packer and union semantics, the evidence chain, the profile load paths, and citation
re-verification. Their reports are triaged here in writing. Several items were wrong or
overstated; each is recorded **with the reason**, per AUDIT-1's binding precedent, because
a finding dismissed without one is indistinguishable from a finding missed.

**Two numbering schemes, and why they are not renumbered here.** The code findings are
`C1` / `H1`–`H8` / `M1`–`M5` / `L1`–`L4` / `N1`; the citation-and-provenance pass has its
own `F1`–`F8` plus `F14`. Both are already cited by number in committed code, catalog
notes, and `docs/open-questions.md` — `AUDIT-2 F1` appears in six Go files, `F5` in Q18,
`F6` in three places. **Unifying them now would silently redirect every one of those
references**, so the schemes stay as they were assigned and this document says which is
which. Recorded as a process finding in its own right: two parallel numbering schemes in
one audit is a defect in how the audit was run, and the fix belongs at the start of
AUDIT-3, not retroactively.

**Result.** 28 findings: 1 critical, 8 high, 5 medium, 4 low, 1 nit, and 9 in the citation
series. **23 FIXED, 5 resolved without a code change, each with a written reason** — `H3`
(open and now disclosed; closing it needs a versioned-contract change), `F5` (needs a
maintainer decision, Q18), `L4` (needs a live org, Q20), `L2` (accepted as deliberate), and
`N1` (flagged and left, per the standing rule on stale items outside a task's scope). Plus
AUDIT-1's nine carried-forward items resolved, three findings re-graded on inspection, one
agent finding recorded as **WRONG**, six stale-documentation items flagged and left, and one
new open question (Q20).

**Fix commits.** C1 → `b8b1c67`. H1, H2, H4 and M1 → `15e9ab3`. H5 → `81ab59c`.
H6, L1, L3 → `bb5b73e`. H7 → `f5e9b71`. H8 → `b2ca812`. M2, M3 → `4ef2442`. M4 → `a0fa025`.
M5 → `e74be37`. F1 and F14 → `c386f74`. F2, F3, F4 → `f24a01f`. F6, F7, F8 → `c86c822`.
H3, F5, L2, L4, N1 carry no fix commit by design — see each.

**For the human: 3 open findings, 6 ratification requests, 1 new open question, 6 stale-doc
items, and a 28-item citation-verification list that automat cannot check for itself — in
the sections at the end.** Carried item 1 (the `os.Root` acceptance) is **closed, not
renewed**; see that section for why the acceptance was keyed to the wrong file.

---

## Critical

### C1 — A `--resume` did not prove whose create it was resuming. FIXED

A create-account request id is printed on the birth certificate and recorded in the evidence
manifest, precisely so an operator can type it back. **It is not a secret and never was.**
But `--resume` treated possession of one as sufficient: `AccountSpec.validate()`
short-circuited on `RequestID`, and nothing compared the resumed `CreateAccountStatus`
against anything the caller claimed.

So a request id — a value automat *publishes* — was an authority to adopt the account it
named: attach the profile's SCPs to it, write a birth certificate for it, and move it into
the destination OU. **A request id is a name, not a capability**, and treating it as one
inverts what it is for. Rule 8 exists because these values are designed to travel through
human hands; that same design is what makes them useless as authorization.

Fixed in `b8b1c67`, with the doc comment `# The request id is not a capability (AUDIT-2)`.
H7 is the same harm through a door where nobody has to type an id at all, found later and
fixed separately.

---

## High

### H6 — `vend` sent the wrong value for the tag its own delegation gates on. FIXED

`internal/bundle/role.go` renders the vendor role's `CreateAccount` grant with a
`StringEquals` condition on `aws:RequestTag/automat:ou`, pinning the literal delegated OU.
`cmd/automat/vend.go` passed `st.Destination` — the OU the account is *placed* in, which
differs from the delegated OU whenever `placement.ou_path` is set. **Every vend with a
non-empty `ou_path` would have been `AccessDenied` in a real organization**, at the
`CreateAccount` call, after the plan printed successfully.

It passed the whole suite because `awsfake`'s `RequiredCreateTags` checked tag *keys*. A
`StringEquals` denies a wrong value exactly as flatly as a missing key, so a presence-only
fake agrees with every value. Added `RequiredCreateTagValues` alongside it.

Two reasons the fix is the sent value and not a widened grant, both recorded in
`vendCreateTags` because either alone invites the wrong repair:

- **An opaque id cannot be pattern-matched into a subtree.** OU ids are
  `ou-<root>-<random>`, so no `StringLike` on `aws:RequestTag/automat:ou` can express "an
  OU below this one" — the subtree relationship lives in the ARN path, and `aws:RequestTag`
  compares an unstructured string. A condition admitting arbitrary sub-OU ids admits
  arbitrary strings.
- **A tag immutable after creation cannot record a mutable fact.** `automat:ou` is
  deliberately absent from `mutableTagKeys` while
  `MoveAccountsIntoTheDelegatedSubtreeOnly` permits moving the account anywhere in the
  subtree. A value naming the leaf OU is stale after the first *permitted* move. The
  delegated OU stays true for the account's whole life: `automat:ou` answers "under which
  delegation was this vended", and `ListParents` answers "where is it now".

Counter-check: `TestVendTagsTheDelegatedOUEvenWhenItPlacesDeeper` fails at `c86c822` with
`AccessDeniedException` on `CreateAccount`. Fixed in `bb5b73e`.

### H7 — `vend` adopted any account whose root email matched, and moved it. FIXED

`vend` adopts on an email match rather than creating a second account, because one address
belongs to exactly one AWS account (DESIGN §3, fact 11) and rule 4 requires a re-run to be
safe. **Email uniqueness identifies an account; it does not make it yours.** Any account in
the searched containers holding the address the profile resolves to was adopted: the
profile's SCPs attached to it, a birth certificate written for it, and — sitting under the
root, where a freshly created account lands — a `MoveAccount` into the destination OU,
taking it out from under every policy attached where it was. That is the same harm `--resume`
was hardened against in C1, reached with no request id typed by anyone.

Reach established by probe, in three seeded-victim variants, because "it would adopt" and
"it would move" are different findings:

| victim's location | outcome before the fix |
| --- | --- |
| an unsearched OU | not found — fail-safe, `PARKED` |
| the destination OU | adopted, 0 moves |
| under the organization root | adopted, **1 `MoveAccount`** |

The fix refuses when the account's `Name` does not match the vend's. It is **corroboration,
not proof**, and the doc comment says so: the authoritative check is `automat:vended-by`,
which needs a `ListTagsForResource` grant the vendor-role bundle does not contain (Q19).
An account coinciding on *both* keys is still adopted, and
`TestVendWillNotAdoptAnAccountItWasNotAskedToVend` asserts that case explicitly so no
reader upgrades the claim.

Refused rather than skipped, deliberately: a skip would fall through to `CreateAccount`,
AWS would answer `EMAIL_ALREADY_EXISTS`, and the operator would be told the address is in
use somewhere they cannot see — while automat is looking straight at it.

Counter-check: the mismatch subtest fails at `bb5b73e`, naming the OU the victim was moved
into. The both-keys subtest passes on both sides, so it pins rule 4 rather than the fix.
Fixed in `f5e9b71`.

### H5 — The packer's merge keys were not injective, so two guards could become one. FIXED

Found independently by two lenses, which is why it is graded above the widening question it
sits beneath. The packer decides which statements to merge by comparing canonical keys built
with `strings.Join` over variable-length fields. **That encoding is not injective:** a
resource containing the separator byte produces the same key as two resources, an empty
resource member produces the same key as an absent resource list, and a condition key
carrying a separator produces the same key as two condition keys.

Two distinct guards that key alike are merged, and the merged statement carries one guard
where the catalog wrote two. This is the defect that makes carried item 2 worth probing
rather than reasoning about: **a key collision does not widen an allowlist, it drops a
guard**, so no monotonicity property is shaped to see it, and the deterministic
golden-output test sits contentedly on top of both.

Fixed by length-prefixing every key component in `81ab59c`.

### H1 — The evidence read and write resolved the path separately. FIXED

`vend` reads and writes one manifest in one command, and nothing tied the two resolutions
together, so the directory read from and the directory written to were the same place only by
convention. Reproduced: a profile carrying `local_dir: "out/evidence"` plus a symlink named
`out`, and **the manifest landed outside the working directory while the birth certificate
printed the path inside it**.

`evidence.Dir` now resolves once and both operations go through the descriptor.
`safeio.EnsureDirUnder` descends the document-supplied components one at a time — which is the
trust boundary `EnsureDir` deliberately does not draw for flag-derived paths, and the
distinction is the point: a path from a *document* is attacker-supplied in a way a path from a
flag is not. Fixed in `15e9ab3`.

### H2 — The evidence write was confined but unchecked. FIXED

`writeThrough` opened the manifest with a bare `root.OpenFile(name, O_WRONLY|O_CREATE)`.
`os.Root` kept the write inside the directory, and **confinement is not the whole property**.
Within it, all three reproduced: a symlink was written through; a hardlink landed manifest
bytes on a file outside the root entirely (a hardlink is not a path, so no confinement can
stop it); and a FIFO hung the command with no output.

The manifest's real name looked defended only by accident — `Write`'s caller parses it first,
a JSON parser standing in for a filesystem check — and the sibling temp name, derived from the
account id and written **first**, had no such accident covering it. The checks moved to
`safeio.CreateChecked` next to the read-side ones, with the `O_EXCL`-first ordering and the
`SameFile` identity tie. Fixed in `15e9ab3`.

### H4 — The manifest header was outside every hash. FIXED

`Meta` is not in `CanonicalRecordJSON`, so a manifest could be relabelled to any account with
every hash and signature intact, and **a signed record transplanted into another account's
manifest verified**.

Covering `Meta` in the record hash is the wrong fix: a typo in `created_at` would then
invalidate the whole chain. The header is a label *on* evidence, so the property is "the label
cannot disagree with what is signed" — `validateHeaderAgainstRecords` compares
`target.account_id` against `meta.account_id` on every read, at no cost to the chain.

Two fields deliberately not compared, recorded because their absence looks like an oversight:
`operator.account_id` (the management account in every state automat runs in, so the
natural-looking check would fire on every *correct* manifest) and `meta.organization_id` (no
record field carries one — **a real residual, and named as one**). Fixed in `15e9ab3`.

### H3 — Head truncation of an unsigned chain is undetectable from the local copy. OPEN, disclosed

Removing records from the *front* of an unsigned manifest leaves a chain that verifies.
`created_at` does not catch it — after the truncation the bound is satisfied by construction,
which was checked *hoping* otherwise — and equality with `records[0].timestamp` is unavailable,
since the two come from one run rather than one value. Signatures do catch it, because
`previous_sha256` is inside `record_sha256`; but `VerifyChain` deliberately skips an unsigned
record, so whoever rewrites the file can also strip the signatures they invalidated.

**The leniency is correct and stays.** automat ships no trust anchor and cosigning is optional;
a verifier that refused unsigned records would refuse the ordinary manifest. What was missing
is that nothing let a reader *ask*, so `Manifest.SignatureCoverage` now answers the question the
verifier's silence does not.

**Why this is not fixed here.** Closing truncation properly needs a genesis anchor in the
header — a versioned-contract change under rule 6, and the maintainer's call. Disclosed rather
than implied, which is the same remedy pattern as F1: the reader of the artifact is told, in the
artifact.

### H8 — A duplicate JSON key was accepted on every read path, and reached the birth certificate. FIXED

`encoding/json` takes the **last** occurrence of a duplicate object key and reports nothing.
That turns a hashed document into two documents: the one a person reads, and the one automat
loaded.

Established by probe through the full command path, not by argument. Appending a second
`"review_by"` to an environment profile vends successfully — account created, policies
attached — and prints `review by 2099-12-31` on the birth certificate while the file on disk
still reads `2027-06-30` on the line a reviewer's eye lands on. `review_by` is inside the
content hash precisely because deferring a re-reading is a change no earlier attestation
vouches for. **This is why the finding was re-graded from the LOW it was first written as to
a HIGH**: the reported version was "duplicate keys are accepted", a parser-hygiene note; the
probe made it a false claim in a delivered record.

Nothing already in the load path covers it:

- `DisallowUnknownFields` does not fire — the key *is* known, twice.
- `additionalProperties: false` constrains which names may appear, not how often. RFC 8259
  permits duplicates and leaves the behavior to the implementation.
- `VerifyContentHash` catches it only where a hash is already recorded *and* the duplicate
  falls inside the hashed payload. A duplicate in `Meta` does not, and the hash is computed
  *from the parse*, so a document whose hash was set after the duplicate was introduced is
  self-consistent and wrong.
- An attestation catches it only for a document that carries one, and signatures are
  optional everywhere, so the ordinary unattested profile has no backstop. Where an
  attestation *does* fire it reports a **stale signature** — pointing the operator at
  re-attesting rather than at the second copy, which is a worse outcome than silence
  because it names a plausible wrong cause.

`artifact.RejectDuplicateKeys` scans with a token decoder; unmarshalling into
`map[string]any` would itself collapse what it is looking for. Wired into all three `Decode`
paths *after* the decode, so a malformed document still gets `decodeError`'s offset and type.

**The first draft of the scanner was wrong in the dangerous direction and is recorded here
rather than quietly fixed.** It guessed key-from-value by alternation, which cannot work: an
array of strings has no keys, so "every other string is a key" misreads every element of
one. It refused a valid artifact, reporting `the key "scp" appears twice` — `scp` being an
enforcement *class*, a value, listed once per control. A load-path check that rejects real
documents does not fail safe; it fails closed on everything. Each frame now records whether
its container is an object, and the test's eight accept cases exist for that direction
specifically.

Counter-check at `e74be37` with production code untouched (`git diff --numstat` over
`canonical.go` and the three `load.go` files: 0 lines): the vend test creates the account and
prints `2099-12-31`; all three `envprofile` subtests fail. Fixed in `b2ca812`.

---

## Medium

### M1 — `Dir.LoadOrNew`'s identity arguments were used only on the new-file branch. FIXED

So a file at `999988887777.json` holding **another account's valid chain** was adopted and
appended to. The identity check existed and ran in the one case where there was nothing yet
to check. Fixed in `15e9ab3`.

### M2 — The escalation invariant's enumerator excluded digits. FIXED

`TestNoConditionReadsATagTheBundleLetsTheDelegateWrite` is what the audit ritual names as the
thing standing between a shipped bundle and AUDIT-1's C1 coming back. Its enumerator matched
`(automat:[a-z-]+)`, which excludes digits — so `automat:artifact-sha256`, one of the three
keys in `mutableTagKeys` and writable by design, truncated to `automat:artifact-sha`, and
`tagKeyIsWritable`'s explicit-list branch found no grant naming *that*. **The moment any
condition reads a digit-bearing key, the invariant silently passes.**

The class is now every character AWS permits in a tag key minus the colon, and the pattern is
a package-level var so the new negative control exercises **this** one rather than a widened
copy — a second literal would reproduce the original defect inside the test written to catch
it. The control drives both helpers over a synthetic document carrying the forbidden
read/write pair and fails if they report it clean, which is the demonstration the invariant
had been going without. Fixed in `4ef2442`.

### M3 — A test hardcoded "now" and decayed into a tautology. FIXED

`TestEveryShippedProfileSchedulesItsOwnReReading` skipped any citation effective on or before
a literal `"2026-08-05"` — correct the day it was written. By 2026-08-06 all thirteen
citations across the three shipped profiles had passed that literal, so the inner comparison
executed **zero times** and the test asserted only that `review_by` was non-empty, which the
schema already requires.

**A test that hardcodes "now" does not fail when it goes stale; it narrows to a tautology and
keeps reporting PASS** in a suite the audit ritual treats as evidence. The horizon is the
build clock now, the count of forward-looking comparisons is logged (zero is legitimate, and
is also exactly what the vacuous version reported), and the profiles are checked from the
other side too: a review date already behind us is a lapsed reading — the failure the field
exists to prevent, and one this test could never see. Fixed in `4ef2442`.

### M4 — The exemption conflict check compared one operator where six are accepted. FIXED

`renderCondition` refuses to add exemption ARNs to a condition that already constrains
`aws:PrincipalArn`, because the exemptions an operator then reads in the rendered policy are
not the list the catalog wrote. It compared against the literal `"ArnNotLike"` while
`behavior.go` models **six** negative operators over the same key, and IAM accepts every one
of them with an `IfExists` suffix too. Five spellings walked past it, confirmed against `HEAD`
in a throwaway worktree.

This is AUDIT-1 carried item 6's second half — intersect-not-concatenate — and the lesson is
narrower than "the prose wasn't read": it had been read and implemented one type too narrow.
Fixed in `a0fa025`.

### M5 — A compiled artifact's source hash named bytes the `uri` did not point at. FIXED

The same shape as F6, one layer down, in `gen/catalog`. A compiled artifact's `sha256` is of
the **curated file** the compiler read; its `uri` names the **upstream publication** a human
transcribed from. A reviewer who fetches the uri and hashes the result gets a different value
and concludes the provenance is broken.

The `sha256` cannot be moved to the upstream value: the compiler never fetches upstream, so
an artifact whose hash named bytes the build did not read would be a hash nothing in the
build could check. **What was wrong was the label**, and all four entries now name the
curated file explicitly. The two `mapping` entries additionally disclose that they *share*
one hash, because two entries carrying the same hash reads as a duplicate when it is the
join.

`TestEverySourceHashIsAttributedToTheFileItIsOf` asserts every recorded hash is one of the
three curated files' *and* that the note names that file. Counter-check: it failed against
the committed catalog on exactly the two `catalog` entries; the two `mapping` entries passed,
having already named their file. `catalogs/cmmc-l1.json` was regenerated —
`content_sha256` `7c18a4a0…` unchanged before and after, which is empirical proof that
`Meta.Sources` sits outside the content hash rather than an argument that it should. Fixed
in `e74be37`.

---

## Low

### L1 — Rule 7's remediation text describes a missing action even when the action was granted. FIXED

`PermissionError`'s grant sentence is composed **before the call**, so it always reads as
"you lack action X on resource Y; here is the grant that fixes it". A matched-but-failed
*condition* returns the same error code, and the remediation is then confidently wrong —
"grant `CreateAccount` in the management account" to an operator who already has it. H6 is
exactly that case, and it is how H6 was nearly misdiagnosed: the first counter-check
produced remediation text that sent me looking at the wrong grant.

Only AWS's own message names the real cause ("…with the request tags provided"). Both are now
printed, **attributed** — `AWS said: …` on its own line — because automat's remediation is an
inference and AWS's text is evidence, and collapsing the two would make the inference look
like the evidence. `TestAWSMessageSurvivesSoAConditionFailureIsDistinguishable` includes a
non-AWS-cause case asserting no dangling `AWS said:` label. Fixed in `bb5b73e`.

Graded LOW because nothing is mis-enforced; it is a reporting defect. Named in the audit
anyway because rule 7 makes remediation text a **headline feature**, not logging, and a
confidently wrong remediation is worse than none — it spends the operator's trust on a grant
they already have.

### L2 — `Enforcement.validate` contains an unreachable check. ACCEPTED as deliberate

Harmless, and left visible rather than deleted: the check guards a case the schema already
refuses, so removing it would mean the Go layer depends on the schema having run. Rule 8's
both-layers discipline applies to more than round-trip fields. **Recorded specifically so a
later reader does not "simplify" it** — an unreachable check whose reason is undocumented is
indistinguishable from dead code, which is how a second layer gets removed.

### L3 — `docs/cli-surface.md`'s `account.tags` disclosure was inaccurate. FIXED

D3's shortfall bullet listed which tags this build writes without saying **which OU
`automat:ou` names**. Amended in `bb5b73e` with the opaque-id and immutability arguments, and
with the note that DESIGN §14's one-line list does not itself say which is meant — so the
design is the thing to amend if the answer should be the other one.

### L4 — The `\u0001`-bearing ARN in an attached SCP could not be verified. ACCEPTED

**Reason.** An adversarial pass constructed an ARN containing a `\u0001` control byte and could
not establish what real IAM does with it in an *attached* SCP. Neither could I: fakes cannot
answer it, and CLAUDE.md rule 1 forbids finding out in CI. The value is refused at the
validator (rule 8's character-class patterns apply at both layers), so **no automat-authored
path produces one**; what is unverified is what would happen if one arrived by another route.

Accepted rather than fixed because the only available "fix" is to guess IAM's behavior and code
to the guess. Recorded as **Q20** in `docs/open-questions.md`, which is the mechanism CLAUDE.md's
working-style rule prescribes for exactly this: write the code behind an interface, note the
uncertainty, keep going, and let a live org answer it.

---

## Nits

### N1 — `internal/bundle/role.go:53` cites "DESIGN §217". FLAGGED, left

It means §14. Flagged rather than corrected in this pass because it falls outside the scope
of every commit that touched the file, per the standing rule that a stale item found outside
the current task's scope is flagged and left. Listed in the stale-doc section below.

---

## The citation and provenance series (F1–F8, F14)

Its own numbering because it is its own pass — the citation re-verification duty AUDIT-1's
carried item 9 assigned, discharged here for the first time. **These numbers are cited in
committed code and catalog notes and must not be renumbered** (see the note at the top).

Every one of these is a claim about an external authority, in a document that renders exactly
as confidently whether the claim is right or wrong. The maintainer's standing rule grades a
superseded or wrong legal citation as **medium at minimum, never a documentation nit**, and
that rule is why this series is not filed as docs cleanup.

### F1 — The unresolved-source gate was a map literal inside a test function. FIXED (high)

`docs/policy-caveat.md`'s standing obligation is that every claim automat *renders* into a
human-facing document traces to a hashed source. The discipline was held by
`TestNoUnresolvedHashInARenderableProfile` — over a `renderable` map declared **inside the test
function**. No renderer could consult it. So the gate was an assertion about a list that
existed only while the test ran, and meanwhile `vend` printed `dfars-7012 sha256:<claimed>` on
the birth certificate for a profile whose own provenance is sixty-four zeros. **Both
unvendored profiles were reachable that way.**

This is AUDIT-1 carried item 8, and the check it explicitly told AUDIT-2 not to take on faith
is the one that did not hold.

The fact now travels with the profile (`ObligationFacts.UnresolvedSources`,
`ProvenanceIsComplete()`), from the resolver that already read its bytes to whatever renders
it — so a renderer can say so **in the rendered output**, which is the only place the caveat is
any use. The page explaining it is not what gets forwarded and attached to an agreement. The
sentinel is asserted against the bytes the shipped profiles carry, because a sentinel that
stopped matching would report complete provenance for a profile that has none. Fixed in
`c386f74`.

### F2 — `cmmc-l1` conflated two paragraphs of the rule. FIXED (partly wrong as reported)

The profile said Level 1 practices are "enumerated at 170.14(c)(1)". The rule splits those
claims: **(c)(1) "Numbering"** defines the `DD.L#-REQ` identifier scheme, and **(c)(2)**
enumerates the requirements as "those set forth in 48 CFR 52.204-21(b)(1)(i) through (xv)" —
confirmed from `gen/.cache/ecfr170.xml` and by 170.15's own cross-reference to (c)(2). The note
conflated them and the `revision` field labeled a requirement set with the numbering paragraph.

**Recorded as partly wrong as reported**: the finding had also claimed this contradicted Q2's
ratified answer in `docs/open-questions.md`. It does not — every other `(c)(1)` citation in the
repo is about the identifier scheme and is right as written. Fixed in `f24a01f`.

### F3 — FAR 52.204-21 bore a date that is neither of its two real ones. FIXED

Dated `2016-11-30`. The clause's actual dates: original effective 2016-06-15 (81 FR 30439), and
the current revision (Nov 2021) effective 2021-12-06 (86 FR 61017). Now the latter, because
that is the text `gen/sources/far-52.204-21.json` vendored — **the vendored bytes say "(Nov
2021)" and the profile disagreed with its own source**, which is the cheapest kind of citation
error to catch and was shipping anyway. The 2021 revision touched only paragraph (c)'s
"commercial items" wording, so the fifteen requirements are unaffected. Fixed in `f24a01f`.

### F4 — A 48 CFR clause carried the 32 CFR program rule's date, in two profiles. FIXED

`48 CFR 252.204-7021` was dated `2024-12-16` in **both** `cmmc-l1` and `dfars-7012`. The clause
heading is (NOV 2025), set by 90 FR 43560 (DFARS Case 2019-D041), effective 2025-11-10.

Two profiles agreeing on a wrong date is the method finding of this whole pass: **agreement is
not corroboration when both copies came from the same misremembering.** The same fix repaired
`dfars-7012`'s note, which asserted a Phase 2 date its own citation could not produce; 32 CFR
170.16(e)(1) keys Phase 1 to the acquisition rule's effective date (2025-11-10) and (e)(2) puts
Phase 2 one calendar year later, so CMMC Phase 2 begins 2026-11-10 — at which point most CUI
contracts require a C3PAO-assessed Level 2 rather than a self-assessment. Fixed in `f24a01f`.

### F5 — UC's BFB-IS-3 citation has no shape to say "never retrieved". NOT FIXED — needs the maintainer (Q18)

`citation.date_basis` has three values and **all three describe a document that was
retrieved**. There is no value for *never retrieved*, and the UC profile has such a citation:
`BFB-IS-3` is the parent policy the Classification Standard says drives it, retrieval was
attempted and failed with a TLS error, and the profile records it because a reader needs to
know it exists and that this profile has not read it.

Its note says NOT RETRIEVED in the first two words. The machine-readable fields say otherwise:
`date_basis: retrieved-only` asserts the document *was* retrieved and found dateless, and
`source_id` names a **different document** — the Classification Standard — because the
validator requires a `source_id` under that basis and the only hashed source available is the
other one. **Reasonable under the shapes available, and wrong in the field a tool reads.**

**Why the audit that found it did not fix it.** Every repair needs either a fourth enum value
or a relaxed `source_id` rule, and rule 6 reserves both. Three candidates are written out in
Q18; the shape chosen will be copied by every profile after it, and unretrieved parent policy
is the *normal* case rather than the exception.

### F6 — The UC source hashed PDF bytes and recorded the HTML page as its uri. FIXED (medium)

So the one field a re-verifier needs was unusable: fetch that page, hash it, and the comparison
fails **against a hash that is in fact correct**. The uri now names the Standard's own PDF,
confirmed by re-fetching it — `sha256 e36e44a7…` reproduces exactly, unchanged, which is how
the finding was resolved rather than assumed. The *citation's* uri stays the policy page, which
is what the Standard's Step 2 names. M5 is this same defect reaching the catalog compiler a
commit later. Fixed in `c86c822`.

### F7 — 75 control citations named the one table cell that does not contain the text. FIXED (medium)

Stanford's Minimum Security Standards tables are
`Standard | Recurring Task | What to do | Low Risk | Moderate Risk | High Risk`. The requirement
text is in **"What to do"**; the risk columns hold only an applicability marker ("Required for
Low Risk Data"). All 75 control citations and 4 external-obligation citations named just the
risk column — so **a reader following a citation would have found a two-word marker where a
requirement was claimed to be**, with the real text one cell to the left. Each now names both
cells and which fact comes from which. Table structure was re-read at the source URI before
anything changed; no requirement text was altered. Fixed in `c86c822`.

### F8 — automat's own inference was presented as the source's designation. FIXED (medium)

Stanford's `determination.roles: ["Data owner"]` was automat's reading, rendered as the page's
designation. The page names **no** determination authority; "data owner" appears twice, both
times parenthetically qualifying an example row ("Research data (at data owner's discretion)").
Discretion over two example rows is not authority over a determination.

`roles[]` has `minItems: 1`, so the profile **cannot** express "the source designates nobody"
by leaving the list empty — the disclosure therefore lives in the value itself, with the
reasoning in `process`. Recorded as a schema-shape observation as well as a citation fix: a
required-non-empty list forces a claim where the honest answer is silence. Fixed in `c86c822`.

### F14 — `docs/policy-caveat.md` pointed at a test file that does not exist. FIXED

It named `internal/artifact/policy_caveat_test.go`; the list is in `obligation_profile_test.go`.
It also omitted classification profiles although the schema requires the field and
`internal/classprofile` holds it. Both corrected, plus a new section stating what the caveat
does **not** cover — it warns that a citation may be stale, which is not the same claim as
never having been checked at all. Fixed in `c386f74`.

**Numbering gap.** F9–F13 and F15+ were never assigned; the series ran F1–F8 with F14 added by
the same commit as F1. Left as a gap rather than closed up, because closing it would shift F14.

---

## Three findings re-graded on inspection

Recorded with the reason, because a finding silently downgraded is indistinguishable from one
missed — and because two of these came from agent passes whose reports would otherwise read
as unaddressed.

1. **The `envprofile.permitted` deny-all hash collision — NOT A FINDING. Already fixed.**
   Reported as: a present-but-empty `permitted` block canonicalizes to the same bytes as an
   absent one, so a deny-all profile and an unrestricted profile share a content hash. It
   does not: `CanonicalContentJSON` carries the guard
   `if p.Permitted != nil && (p.Permitted.Regions != nil || p.Permitted.Services != nil)`
   with the reasoning written out, `keepEmpty` preserves the distinction deliberately, and
   `load_test.go:153-179` and `canonical_test.go:78-178` cover it. The agent read the
   canonicalizer without the guard in view.

2. **`Meta.Description` outside the content hash — real, but lower than reported.** Reported
   as an unhashed field carrying the non-endorsement disclaimer. The load-bearing disclaimer
   is `interpretation.non_endorsement`, which **is** covered, as are `Issuer` and
   `PolicyCaveat`. What actually sits outside the hash is the "EXAMPLE, not maintained"
   framing — worth knowing, not the finding that was filed. No change made; recorded so the
   next audit does not re-file it at the original severity.

3. **`artifact.Meta.Sources` — upgraded from a note to a systematic finding.** Filed as a
   single mislabeled entry. All four sources had it, `sha256` and `uri` describing different
   documents in every one, and two mapping entries shared a hash with nothing disclosing the
   join. Became M5.

---

## AUDIT-1's nine carried-forward items, resolved

### 1. The A1 / `os.Root` acceptance. CLOSED, not renewed — and the acceptance was keyed to the wrong file

AUDIT-1 said the acceptance "may not be renewed a third time" and set the trigger at
"`artifact.Load` called with a path from a profile, a catalog reference, or anything but a
CLI flag".

**That trigger never fired, and could not have: `artifact.Load` has no caller.** The only
production call is `artifact.LoadFS` at `internal/catalog/resolve.go:145`, over the embedded
catalog FS, where path confinement is not the relevant property. Meanwhile the condition the
acceptance was *about* — a read whose path comes from document content — arrived through
`evidence.Load` / `evidence.Write`, which the acceptance did not name.

Recorded this way because it is a lesson about how acceptances are written, not only about
this one: **an acceptance keyed to a named function expires when that function is called, and
a trigger that names the wrong function reads as satisfied forever.** The item is closed on
the merits (the paths in question now go through `safeio`, and `resolve.go`'s embedded read
is not a confinement question) rather than renewed. Future acceptances of this kind should be
keyed to the *property* — "any read whose path derives from document content" — not to a
symbol.

### 2. The packer's can-any-merge-widen question. ADDRESSED, and honestly incomplete

The property tests exist and hold: `TestUnionIsMonotone`,
`TestUnionIsMonotoneOnAllowlists`, `TestUnionIsMonotoneOnTheGlobalServiceExemptionList`,
`TestUnionIsMonotoneOverRenderedPolicies`, `TestUnionIsIdempotent`,
`TestNarrowingNeverWidensTheAllowlists`, `TestNarrowingNeverWidensTheRenderedPolicy`. Two of
them — `TestTheRenderedPropertyReadsTheDocumentAndNotTheStatementField` and
`TestTheRenderedMonotonicityPropertyIsNotMostlyRefusals` — exist specifically to stop the
properties from passing vacuously, which is the failure mode AUDIT-1 was worried about.

What the audit found *below* the widening question was H5: a merge key collision that drops a
guard rather than widening a set, which no monotonicity property is shaped to catch. See
"Where this audit is weaker than it looks" for what remains unestablished.

### 3 and 7. Tag-write authority, both halves. DISCHARGED, and it produced H6

Every `aws:RequestTag` / `aws:ResourceTag` condition in the bundle was paired against which
principals can write that tag at the same scope. `mutableTagKeys` is a closed list precisely
because of what is *not* on it, and `automat:ou`'s absence is load-bearing. The audit of the
*sent value* against the *pinned value* is what produced H6 — which is the item's point: a
condition can be correctly written and still never match.

### 4. `automat compile` is in DESIGN §13 with nothing shipping it. UNRESOLVED — carried to the maintainer

Confirmed still true: no `compile` subcommand exists; `gen/catalog` is maintainer tooling by
design. See the §13 reconciliation section — this is D2/D3's sibling and needs the same
either/or decision, not a third audit noting it.

### 5. `make smoke` runs zero tests. CONFIRMED still deliberate, still documented

No file carries a `smoke` build tag. `docs/smoke.md` specifies the checklist. The gap is
deliberate and the runbook is written, but **a target that runs zero tests and exits 0 reads
as a pass** — AUDIT-1's own words, and still true. Left as-is per rule 1's prohibition on
finding out in CI; flagged again because a second confirmation is not a resolution.

### 6. Chain terminality and intersect-not-concatenate. Half discharged, half produced M4

> **Corrected — see "Corrections to this record."** Chain terminality IS enforced; the
> paragraph below was wrong when written.

Intersect-not-concatenate produced M4 (implemented one type too narrow, so a conflict could
go unreported). Chain terminality — that a `custody-transfer` record is the *last* record —
is still enforced nowhere: `TestTheSchemaCannotSayCustodyTransferIsLast` keeps it visible
rather than blessing it. Carried to AUDIT-3, because `verify` is where the chain validator
lands and `verify` does not exist yet.

### 8. Three unresolved hashes and an empty renderable list. Produced F1

The test's name was exactly the thing not to take on faith. See F1.

### 9. The citation re-verification duty. DISCHARGED, and it produced F1–F8

Plus a 28-item list of claims automat cannot verify for itself — see the citation section
below.

---

## The §13 CLI reconciliation, and D1–D3

`docs/cli-surface.md` tracks every place the shipped CLI and DESIGN §13 disagree. Two
deviations carry explicit maintainer instructions that this audit must not resolve by
narrowing the code, and both are restated here so they are findable:

- **D2.** `init` accepts two preflight states where §13's line names one. The instruction:
  *either §13's `init` line is amended to name the two states it permits, or this deviation is
  re-ratified as it stands.* **Do not resolve it by narrowing the command.** Unresolved;
  needs the maintainer.
- **D3.** `vend` does not perform DESIGN §7 step 5 (the in-child baseline). The instruction:
  *this is not a deviation to re-ratify. Either step 5 ships and D3 is struck, or §13's `vend`
  line is amended.* **What must not happen is D3 quietly becoming the definition of vending.**
  Unresolved; needs the maintainer. L3 amended D3's disclosure accuracy, which is not the
  same as resolving D3.
- **D1** was resolved in AUDIT-1.
- **`compile`** (carried item 4) needs the same shape of decision as D2.

The plan/apply split required by rule 5 exists: `vend` prints a plan before applying, and the
plan discloses each shortfall rather than omitting it. The "unknown" lines in plan output are
load-bearing and were checked to still be present after H6's changes.

---

## Dependency review

**No dependency added in Phase 2.** `go.mod` is unchanged in the direct-requirement block
across the whole range `541c3ec..b2ca812`.

Per CLAUDE.md's pre-approval of the `aws-sdk-go-v2` module family, ratified at AUDIT-1: every
per-service module still owes a narrow interface and a fake. Phase 2's new AWS surface
(`OrgVendAPI`'s mutating half) is behind hand-written interfaces with `awsfake`
implementations, and H6 is a finding about a *fake being too permissive*, which is the
predictable failure mode of that arrangement and worth naming as such: **a fake that checks
tag keys does not check tag values.** No mocking framework was introduced.

---

## Citation re-verification

Discharged for the first time (AUDIT-1 carried item 9). Produced F2–F4 (`f24a01f`, three
citation errors plus the cross-check that catches the next one) and F6–F8 (`c86c822`, four
provenance defects in the classification profiles).

**The method finding, recorded because it changes how the next pass should be run:** two
independent transcriptions agreeing is not correctness. Two copies of the same wrong date
agreed, and the check that caught it asserts against the source rather than against the other
copy.

**28 items require human verification and automat cannot check any of them.** They are claims
about what an external authority currently says, and no test over vendored bytes can falsify
one. The full list is in the citation pass's output; the highest-value item by a wide margin:

> **Item 7 — Is DoD class deviation 2024-O0013 still in effect?** It is the *sole* basis for
> pinning 800-171 **r2** rather than r3. If it has lapsed, every profile pinned to r2 cites a
> superseded standard while rendering exactly as confidently as a current one — the maintainer's
> standing rule makes that a medium finding at minimum, and it would be a medium finding in
> three shipped documents at once.

`nih-cadr-dua` was checked first per carried item 9's instruction. Confirmed: it still ships
**no revision default**, the schema forbids the field, and the test additionally rejects a
revision named in `hints` — which is the shape a default takes when it comes back wearing a
different hat.

---

## Where this audit is weaker than it looks

Recorded because an audit that only reports what it found is itself a claim outrunning its
evidence.

- **The packer's widening question is established by property tests over generated inputs, not
  proved.** The properties hold on everything `rapid` produced, and two anti-vacuity tests stop
  them passing on refusals. That is meaningfully stronger than an example test and meaningfully
  weaker than "no merge can widen". H5 is the existence proof that a defect can live below the
  shape a property is written in: a key collision drops a guard without widening any set, and no
  monotonicity property is shaped to see it.
- **Every claim about live AWS behavior remains untested by construction.** H6's whole content is
  that a condition automat renders never matched the value automat sent — and it was found by
  making a *fake* stricter, not by observing AWS. The same class of defect in a condition the
  fake models loosely, or does not model, would still be invisible. Q5–Q9 and now Q20 are the
  honest list.
- **H7's fix is corroboration and the test says so, which is not the same as being sufficient.**
  An account coinciding on both email and name is still adopted and still moved. The authoritative
  check needs a grant the bundle does not contain (Q19). What ships is better than what shipped
  and is not the check that should exist.
- **The duplicate-key scanner is new code on every load path, written during an audit.** Its first
  draft rejected a valid artifact. The accept cases are the shapes I thought of plus the shapes
  that ship; a JSON document shaped in a way neither covers would be refused at load, which is a
  broken load path rather than a security failure, but it is the failure mode to watch.
- **Three findings were re-graded after a probe contradicted the reading that produced them.** Two
  down, one up. Every one of those readings was mine or an agent's, arrived at by inspection, and
  looked sound at the time. The graded severity of anything in this document that was *not* probed
  should be read with that in mind.

### One agent finding recorded as WRONG

The `envprofile.permitted` deny-all hash collision (re-graded item 1 above): reported as a live
hash collision between a deny-all and an unrestricted profile. The guard exists, the reasoning is
written out in the canonicalizer, and two test files cover it. The agent read
`CanonicalContentJSON` without the `p.Permitted != nil && (…)` condition in view. Recorded rather
than dropped, per AUDIT-1's precedent.

---

## For the human to review — ratification requests

Per CLAUDE.md's "ask the human before" rule and rule 6. Items 1–4 are schema changes made during
the phase; 5 and 6 are validator tightenings. **All six strictly tighten**, which rule 6 permits
without pre-approval provided they are listed here for ratification — which is what this is. None
loosens or restructures, with the single exception noted in item 1, which was asked about at the
time.

1. **`control-artifact/v1`'s payload restructuring (`6700bc0`).** `region_deny_exempt_services`
   moved inside the content hash, since it is the one field that decides whether a region Deny
   covers IAM. This **restructures** rather than tightens, was asked about before it landed, and is
   listed here for the record with its `schema/CHANGELOG.md` note.
2. **Five `environment-profile/v1` tightenings** (carried from `770c477`, `f8764ae`).
3. **`classification-profile/v1`, new in `99b12a5`, and its four `minItems` tightenings.**
4. **The `docsProductAllowlist` from `b947498` — never ratified.** Flagged as such: it guards
   `docs/` against rule 3 (no product/vendor references but AWS) and has been in force since Phase
   1 without appearing in an audit's ratification list. It belongs in one.
5. **The `action` / `resource` validator tightening from `81ab59c`** (H5's second half).
6. **`artifact.RejectDuplicateKeys` on all three load paths (`b2ca812`, H8's fix).** A strictly
   tightening load-path change: no document that was valid remains invalid, and every document it
   now refuses was one automat previously read differently from how it reads. Listed because it
   changes what three `Decode` functions accept, and that is a contract.

---

## For the human to review — open questions and stale items

### New open questions

- **Q18 — `classification-profile/v1` has no way to record a citation it could not retrieve.** F5's
  unfixed finding. Every repair needs either a fourth `date_basis` value or a relaxed `source_id`
  rule, and rule 6 reserves both; the shape chosen will be copied by every profile after it.
- **Q19 — the vendor-role bundle cannot read `automat:vended-by`, so `vend` cannot prove an account
  is its own.** H7's limit. Three candidate shapes are written out in `docs/open-questions.md`: add
  `ListTagsForResource` to the bundle; adopt only what local manifests record; or require an
  explicit `--adopt <account-id>`. Each trades a different thing, and the choice is the
  maintainer's.
- **Q20 — what does real IAM do with a control character in an ARN inside an attached SCP?** L4's
  accepted finding: refuse, preserve literally, or normalize, and only the first is safe. No fake
  can answer it. Parked alongside it: whether any shipped command can point
  `internal/catalog.Options.FS` at an attacker-controlled tree. **None does today** — and if
  vendored-only is load-bearing it should be written down as a control rather than left as a
  property of the current call sites.

### Stale documentation, flagged and left

Per the standing rule: a stale item found outside the current task's scope is flagged in the
response and left, and a fix that would edit a record adds to it instead.

1. **`docs/conventions.md` does not exist**, though DESIGN §14:320 cites it.
2. **`internal/bundle/role.go:53` cites "DESIGN §217"**, meaning §14 (N1).
3. **`catalogs/` lacks the `800-171r2` and `800-171r3` artifacts** that CLAUDE.md:60 and
   ROADMAP.md:8 both name. What ships is `cmmc-l1` and `baseline-protection`.
4. **ROADMAP.md:26's "the rename has landed, the fields have not" is now false** — the fields
   landed in `770c477`.
5. **`docs/audit-ritual.md`'s "the whole profile set"** now reads more broadly than it can be
   satisfied, since the set grew two document types after the sentence was written.
6. **`/Users/scttfrdmn/src/CLAUDE.md`** is a stale copy of the project file, outside the repo, and
   is the maintainer's to fix. Untouched. **Corrected — see "Corrections to this record":** no
   file exists at that path.
7. **`internal/baseline/` does not exist**, though CLAUDE.md:52 names it in the layout block —
   the same gap D3 names from `cmd/automat/vend.go`'s side, seen here from the package tree.

---

## Carried forward to AUDIT-3

Recorded here rather than left in a review message, because a carry-forward that lives only in
conversation is one the next audit will not find.

1. **Confirm chain-terminality enforcement survives into `verify`** (AUDIT-1 carried item 6;
   corrected below — it is enforced in Go, not "enforced nowhere" as this item originally read).
   `internal/evidence/validate.go`'s `validateChain` refuses a manifest with records appended
   *after* a `custody-transfer`, on every load and write path. What AUDIT-3 owes is narrower than
   this item first stated: confirm the same enforcement is reachable from `verify` once `verify`
   exists, and that `TestTheSchemaCannotSayCustodyTransferIsLast` continues to be read as
   documenting a schema limit rather than as coverage of the obligation itself.
2. **`automat compile` and D2/D3 need maintainer decisions, not another audit noting them.** Three
   audits in a row have observed the `compile` gap.
3. **`make smoke` still runs zero tests and exits 0.** Confirmed deliberate twice now. A third
   confirmation is not a resolution; either a test carries the tag or the target should say what it
   is.
4. **The property-coverage lesson from H5.** A monotonicity property cannot see a defect that drops
   a guard without widening a set. AUDIT-3 should ask, for each property test in
   `internal/compilesets`, what shape of defect it is *blind* to — not whether it passes.
5. **Overclaiming test names.** Names that assert more than the body establishes, found while
   reading for F1's failure mode. **Corrected — see "Corrections to this record," item 6:** the
   original count of eight was never itemized, and a re-derivation found two, not eight — report
   what a re-check actually finds rather than treating the original count as a target. H7's test
   has the corrected shape to imitate: the subtest that documents the *limit* of the check is as
   load-bearing as the one that documents the check.
6. **Q19 and Q20 are live security questions, not curiosities.** Q19 in particular: `vend`'s
   adoption path rests on corroboration because the authoritative check is ungranted.
7. **28 citation items await human verification**, item 7 (DoD class deviation 2024-O0013) first,
   because it is the sole basis for pinning r2 in three shipped documents.

---

## Corrections to this record

This audit is a dated record of what was found on 2026-08-05/06. The standing rule for a
committed record is that a wrong statement is corrected by *addition*, not by silent edit — a
changelog, or an audit, records what was said at the time. What follows are five statements in
the sections above that were wrong when written, found while starting the remediation work this
audit's own findings required, verified against the tree rather than taken on the audit's own
authority. Each is marked at its original location with a pointer here.

**One exception.** Five occurrences of `F5` that meant `H5` (in "AUDIT-1's nine carried-forward
items, resolved" item 2 and "Where this audit is weaker than it looks", plus the two
ratification/carry-forward items citing `81ab59c`) were corrected **in place**, not by marker.
This document's own opening section states why unifying the two numbering schemes "would
silently redirect every one of those references" — `F5` is cited with a different meaning in
`docs/open-questions.md:673` and twice in `catalogs/classification/uc-protection-levels.json`,
so leaving a wrong `F5` in place performs exactly the redirection the numbering note forbids.
One of the five occurrences is a ratification request (item 5 in "For the human to review —
ratification requests") read at the moment of ratification, where an addendum footnote three
sections away would not be seen. The corrected text now reads `H5` in each of the five places;
this paragraph is the record that the correction happened and why.

1. **Chain terminality is enforced, not "enforced nowhere."** AUDIT-1's carried item 6 and this
   audit's own carry-forward item 1 both said the obligation was undischarged. It is enforced at
   `internal/evidence/validate.go:540-547`, inside `validateChain`, reached from `Validate()` on
   every read and write path (`store.go:200`, `store_dir.go:170`, `chain.go:107`, `chain.go:161`);
   `Append` refuses independently at `chain.go:57-63`; `TestTheGoValidatorEnforcesCustody‑
   TransferTerminality` (`internal/evidence/custody_test.go:39`) passes. It landed in `e823c04`
   — **inside the range this audit covers** (`541c3ec..b2ca812`). More: `schema/CHANGELOG.md:413-
   419` already carries a `> **Superseded in part**` marker stating "the terminality gap named in
   the paragraph above is enforced in Go." This audit carried forward an obligation that a
   document already in the repository recorded as discharged — an audit that repeats a stale
   claim from a prior audit without checking the code, when a second document in the same repo
   already contradicts it, has read the docs less carefully than the code, and got the code wrong
   too. Carry-forward item 1 above is not struck: `verify` does not exist yet, so what remains for
   AUDIT-3 is confirming the enforcement is reachable from `verify` once it exists, not enforcing
   it for the first time.
2. **Five `F5` mislabels, corrected in place** — see the exception above.
3. **"Produced F7 … and F8"** in "Citation re-verification" misattributed both parentheticals.
   `f24a01f` ("fix(catalogs): three citation errors, and the cross-check for the next one") is
   F2–F4; `c86c822` ("fix(catalogs): four provenance defects in the classification profiles") is
   F6–F8. Corrected in place to name the right findings against the right commits.
4. **Stale item 6 claimed a file exists that does not.** "`/Users/scttfrdmn/src/CLAUDE.md` is a
   stale copy of the project file… Untouched" asserts a present file. No file exists at that path,
   nor at `/Users/scttfrdmn/CLAUDE.md`. Marked at its location; the finding that a stale copy
   existed cannot be verified and should not be relied on by AUDIT-3.
5. **The 28-item citation-verification list is referenced three times and does not exist in the
   repository.** "The full list is in the citation pass's output" (twice) and "a 28-item citation-
   verification list… in the sections at the end" all point at a list that lived only in a
   subagent transcript and was never committed. It could not be reproduced faithfully after the
   fact — see `docs/citation-verification.md`, added separately, which re-derives a queue from the
   shipped catalogs by a stated method and says plainly that it is a re-derivation, not a recovery,
   and that its item numbers do not correspond to whatever the original 28 were.
6. **"Eight overclaiming test names" (carry-forward item 5) is unnamed — here is a re-derived
   list, not a recovery of the original eight.** The same failure mode as item 5 above: a count
   without the list behind it cannot be checked and cannot be acted on. Re-derived by grepping
   every `^func Test` name touched in `541c3ec..b2ca812` for the words that make a universal claim
   — `Every`, `Never`, `Always`, `Only`, `Cannot`, `All`, `Any` — and reading each candidate's body
   against its name. Most held up; roughly forty were checked and only two did not, which is
   reported honestly rather than stretched to eight:
   - `TestVendorRoleCannotTagOutsideAutomatsNamespace` (`internal/bundle/escalation_test.go:315`)
     checks only that the string `aws:TagKeys` appears anywhere in the rendered document — never
     that the condition's key list is actually scoped to `automat:*`. A rendered policy carrying
     `aws:TagKeys` set to `["anything"]` would pass. Its sibling three tests away,
     `TestDelegateCannotTagItsWayIntoCentralITsPolicies`, checks the real thing
     (`ForAllValues:StringLike` plus a prefix match) — which is the shape this one should imitate.
   - `TestNoProductReferences` (`internal/artifact/schema_conformance_test.go:623`) is named as if
     it enforces DESIGN §15 in general. It checks a hardcoded four-word list ("control tower",
     "controltower", "audit manager", "landing zone accelerator") over two directories — a
     hand-picked enumeration standing in for a general property, which is exactly F1's failure
     shape (a map literal presented as coverage). `docsProductAllowlist`, forty lines below in the
     same file, is the more thorough version — it walks `docs/` too, with an explicit allowlist
     rather than a blocklist — and is the shape to imitate.
   - Two candidates that looked suspicious and were confirmed fine on inspection, recorded because
     a wrong-but-plausible finding dismissed without a reason is what this audit's own precedent
     forbids: `TestEveryPaginatedListNeedsDraining` names exactly the five paginated fake methods
     that exist (verified against `internal/awsfake/orgvend.go` and `orgpolicy.go`; `ListParents`
     returns one item and is not paginated) — "every" is correct, not aspirational. Carry-forward
     item 5's own cited example, `TestNoShippedProfileClaimsAutomatDecides`, does genuinely iterate
     every shipped classification profile.
   - Not renamed here, per carry-forward item 5's own instruction that the reading is AUDIT-3's to
     do — this gives AUDIT-3 two confirmed starting points instead of a bare count of eight.
