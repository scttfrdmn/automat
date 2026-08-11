# Conventions (the adoption contract)

These are automat's own — documented here so an external system may adopt them without
asking. automat depends on nothing external in return: nothing in this tool reads a
convention from any other project's output. See DESIGN §14 for the pointer to this page
and §15's branding rule for why the dependency direction only ever runs one way.

## Tags on vended accounts

Every account `vend` creates carries:

- `automat:vended-by` — the identity that ran the vend (`internal/bundle/role.go`'s
  `vendorCreateRequestTags`; the vendor role's `CreateAccount` grant requires it as an
  `aws:RequestTag` condition, so an account created outside this condition cannot exist).
- `automat:ou` — the delegated OU, matching the same condition on `MoveAccount`.
- `automat:artifact-id`, `automat:artifact-sha256`, `automat:version` — which compiled
  control artifact and which build of automat produced the account, so a reviewer months
  later can trace what was actually attached without the evidence manifest in hand.

Enable these as cost-allocation tags where your billing console allows it — chargeback
matters as much as compliance to this project's audience, and the tags already carry the
information a chargeback report needs.

## Service control policy naming

`automat-<environment-profile-id>-<n>` (e.g. `automat-research-cui-1`) — an ordinal over
the packed policy set, not one name per artifact or per class.

This is forced by how a vend actually builds policies (DESIGN §9): a vend unions every
named control set into a shared pool of statements and packs that pool against a
five-SCP-per-target quota, so one attached policy has no single artifact id and no single
class to name. The environment profile id is the one id every packed policy from that vend
has exactly one of, and Organizations enforces name uniqueness in a way an ordinal
satisfies and a per-artifact name would not — two vends against one OU under different
profiles would otherwise collide on a name naming neither.

`automat verify` finds and distinguishes its own policies by the owner tag below, never by
parsing this name — the name is for a human reading the Organizations console, not a
machine-readable key.

## The owner tag

Every resource automat creates and later needs to recognize as its own — a service control
policy, an organizational unit, an IAM role — carries `automat:managed-by=automat`
(`internal/org.OwnerTagKey`/`OwnerTagValue`). This is the single tag every ownership check
in the codebase reads: `EnsurePolicy` refuses to adopt an untagged policy sharing its name
(the AUDIT-1 C1 argument), `reclaim`'s `DetachOwnedPolicies` detaches only what carries it,
and the delegation policy's own SCP-modification statements are scoped to it
(`internal/bundle`'s `scpModifyActions`).

There is no separate "OU marker tag" distinct from this one — an OU automat creates gets
the identical `automat:managed-by=automat` tag a policy does, not a second convention.

## What DESIGN §14 named as future and is now half built

DESIGN §14's original draft named a manifest storage convention —
`s3://automat-evidence-<acct>/manifests/…` plus a management-side mirror — as part of the
adoption contract. **The write half of that now exists; the read half does not.**

Every evidence-writing command (`vend`, `verify`, `reclaim`, `assess`) still writes the
local file first and unconditionally, through `internal/evidence.Dir`
(`OpenDir`/`LoadOrNew`/`Write`) against a directory named by the environment profile's
`baseline.evidence.local_dir` (or a command's own `--evidence-dir` flag) — that has not
changed and is not going to: DESIGN §11's "local copy always" priority.

What is new is `internal/evidence.Mirror` (`S3Mirror`, `internal/awsapi.S3MirrorAPI`,
`internal/awsfake.S3`): after the local write succeeds, `cmd/automat`'s `evidenceMirror`
helper builds zero, one, or two mirrors from an environment profile's
`baseline.evidence.in_account_bucket` and `management_mirror_bucket` — both, if a profile
sets both, following DESIGN §11's own "and/or" — and uploads the same bytes the local file
holds to each, via `s3:PutObject`. A mirror upload failure is reported as a warning and
never fails the command that produced the manifest, and never blocks on the local write,
which has already happened by the time a mirror is even considered.

This is write-only. **`verify` does not fetch the mirrored copy and does not compare it
against the local file.** ROADMAP.md's "Remote evidence mirror" backlog item calls that
comparison slice 2 — a second interface method (kept separate from `Mirror`, the same
`Signer`/`Verifier` split for the same reason: a writer never needs read access) that
`verify` would use to flag drift between the two copies as a new finding class. Until that
lands, a rewritten local manifest and its now-stale mirrored copy are two documents nothing
in this codebase compares — the mirror is a copy an operator or auditor can go read by
hand, not yet a check `verify` performs. This page states only what ships; when the
read-and-diff half lands, it earns its own paragraph here rather than this one being
corrected quietly.
