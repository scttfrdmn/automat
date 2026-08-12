// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package baseline performs the in-child half of DESIGN §7 step 5: the work a
// vend does after assuming OrganizationAccountAccessRole into the account it
// just created, rather than against the organization itself (internal/org's
// job, steps 3 and 4).
//
// Two pieces of that step are built so far: EnsureAutomationRole, which
// creates and permissions "the automat automation role" DESIGN §7 step 5
// names — "least privilege for future verify" — and EnsureRegions, which
// ensures opt-in region enablement matches envprofile.BaselineRegions
// (ROADMAP's "internal/baseline, slices 2-9", item 5). The remaining pieces
// (a Config recorder and delivery channel, a conformance pack, attestation
// stubs) are later, separate slices against awsapi.ConfigAPI, which already
// exists as an interface (a prior slice) but has no Ensurer method yet.
// Nothing here calls it; the automation role's own permissions policy is
// scoped to its methods anyway (see automationRoleActions), so a later
// slice's Ensurer methods find the grant already in place rather than having
// to widen a role a catalog's baseline-protection SCP may by then forbid
// touching at all (the very ordering problem this package's doc comment
// spends the rest of its words on).
//
// # The ordering surprise: this step runs BEFORE the SCP that DESIGN §7 lists
// after it
//
// DESIGN §7 numbers the in-child baseline work step 5, after step 4's
// "ensure the OU's service control policies match the artifact". Read
// literally, a vend would attach every control set — including
// baseline-protection — and only then assume into the account to establish
// the automation role.
//
// That order is unsafe, and this package exists because of it
// (docs/open-questions.md Q13). baseline-protection's BP.IAM-1 control denies
// iam:Attach*/Delete*/Detach*/Put*/Update* on OrganizationAccountAccessRole
// and on the automation role itself, to every principal in the account, with
// NO exemption — not even for the automation role, because a role exempted
// from a Deny on its own permissions could rewrite them, which is the
// privilege-escalation path least privilege exists to close. If
// baseline-protection attaches before the automation role is fully
// permissioned, the very iam:PutRolePolicy call that permissions it lands on
// a Deny automat itself compiled — a vend that fails by tripping its own
// control, with a remediation message that would misdiagnose the cause as a
// missing grant.
//
// So `cmd/automat/vend.go` calls EnsureAutomationRole BEFORE
// `org.Ensurer.EnsurePolicySet` attaches the OU's policy set — REVERSING
// DESIGN §7's listed order of steps 4 and 5, for this one sub-step of step 5.
// This is a deliberate, disclosed decision (CLAUDE.md rule 2), not a silent
// reinterpretation: the automation role must exist and be fully permissioned
// before baseline-protection can safely attach, and DESIGN's own numbering is
// wrong about which comes first. iam:CreateRole and iam:TagRole are absent
// from BP.IAM-1's deny list, so creating the role (without attaching baseline
// yet) is never itself a problem; only re-permissioning it after attachment
// is.
//
// # Re-permissioning after baseline-protection is already attached: PARK, not
// fail or silently succeed
//
// A re-vend against an account whose baseline-protection is already attached
// from an earlier run hits the same Deny if this build's desired automation-role
// policy has since changed. EnsureAutomationRole distinguishes this from an
// ordinary permission problem — the role already existing, its current policy
// differing from what is wanted, and the write failing AccessDenied is exactly
// Q13's scenario — and returns an error carrying BOTH readings, because
// AccessDenied alone cannot prove which applies: if baseline-protection is the
// cause, no grant fixes it (detach it from the OU first, apply, then
// re-attach); if it is not, this is an ordinary missing grant. `cmd/automat`'s
// existing park/resume machinery (org.Parkable, `vend --resume`) recognizes the
// AccessDenied either way and records the vend as PARKED rather than letting it
// read as a plain failure or, worse, silently reporting success on a role that
// still carries the old policy.
//
// # Reuses org.Action, org.Verb, and org.Mode rather than a parallel vocabulary
//
// A manifest reader should not need two different "verb" dictionaries for two
// pipeline stages that both feed the same evidence chain (a later slice wires
// this package's actions into it — DESIGN §11, evidence.OpBaselineApply,
// already exists on the Operation enum but is not populated by this slice).
// Ensurer's shape mirrors internal/org.Ensurer's for the same reason
// internal/org's own doc comment gives for reusing this discipline everywhere
// in the vend pipeline: ensure-semantics, a plan/apply split with no mutating
// call in ModePlan, and the same read-first-and-tolerate-the-duplicate
// discipline org.Ensurer's own doc names.
//
// # What this package does not construct
//
// EnsureAutomationRole is handed an already-assumed awsapi.IAMRoleAPI client,
// and EnsureRegions an already-assumed awsapi.AccountAPI client; neither
// method ever builds an aws.Config or assumes a role itself. Session
// construction — assuming OrganizationAccountAccessRole into the just-vended
// account — is `cmd/automat/globals.go`'s job, the same division org.Ensurer
// already enforces for its own OrgVendAPI/OrgPolicyAPI clients.
package baseline
