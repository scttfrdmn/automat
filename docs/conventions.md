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

## What DESIGN §14 named as future and is not built

DESIGN §14's original draft named a manifest storage convention —
`s3://automat-evidence-<acct>/manifests/…` plus a management-side mirror — as part of the
adoption contract. **That storage layer does not exist in this codebase.** Evidence
manifests today are local files, written and read through `internal/evidence.Dir`
(`OpenDir`/`LoadOrNew`/`Write`) against a directory named by the environment profile's
`baseline.evidence.local_dir` (or a command's own `--evidence-dir` flag) — no S3 client,
no remote mirror, no `internal/awsapi` interface for either. The mirror is referenced in
`docs/open-questions.md` and in `internal/evidence`'s own doc comments as the intended
compensating control against a rewritten local chain (DESIGN §11), but it is design intent
for a later phase, not a convention this build follows. This page states only what ships;
when a remote store lands, it earns its own section here rather than this one being
corrected quietly.
