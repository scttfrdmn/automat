// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package org performs the Organizations half of a vend with ensure semantics:
// every operation is create-or-verify, and re-running one writes nothing.
//
// Its role in the vend pipeline is steps 3 and 4 of DESIGN §7 — place the
// account in its OU, and make the OU's service control policies match the
// compiled artifact — plus `init`'s two calls. It sits between the packer, which
// decides what the policies should say, and `internal/evidence`, which records
// what happened.
//
// # Why ensure rather than create
//
// CLAUDE.md rule 4, and it is not a style preference. A vend is a sequence of
// mutations against a live organization, any one of which can fail after the
// preceding ones succeeded, and the account exists from step 2 onward. So the
// only safe recovery is to run the whole sequence again — which means every step
// has to be a statement about the desired state rather than an instruction to
// change something. `vend --resume` is that re-run, and every operation here is
// written so a second pass reads, finds what it wants, and issues no write.
//
// Organizations does not help. Nothing here is idempotent on the AWS side:
// CreateOrganizationalUnit refuses a duplicate name, AttachPolicy refuses a
// duplicate attachment, EnablePolicyType refuses a second enable, and
// CreatePolicy refuses a duplicate name. Each refusal is a distinct exception
// which ensure semantics has to read as "already true".
//
// # Read first AND tolerate the duplicate
//
// Both, everywhere, and this is the package's central discipline
// (docs/open-questions.md Q12). The read is the correct path: it is how automat
// learns the ids it needs, how it avoids a write it does not need, and how the
// "run twice = no diff" property is achievable at all. The tolerance covers the
// window between the read and the write, which is not hypothetical — a
// concurrent vend, a console click, or a retry of a call whose response was lost
// all land in it. Code written against only one of the two has exactly one of
// them, and which one is missing decides whether it fails on the happy path or
// on the unlucky one.
//
// # Plan and apply
//
// CLAUDE.md rule 5 asks for the plan/apply split from Phase 2, before anything
// destructive exists. Ensurer.Mode is that split: in ModePlan every operation
// performs its reads and reports the Action it would take, and issues no
// mutating call. TestPlanTouchesNothing holds it against the fakes' call log
// rather than by inspection.
//
// A plan cannot know the id of something it would create, so Action.ID is empty
// for a planned creation and every operation says so rather than inventing a
// placeholder. That is also why EnsureOUPath's plan degrades honestly: once a
// level would be created, no deeper level can be read, and the plan says
// "parent does not exist yet" instead of guessing.
//
// # What is deliberately not here
//
// No detach, no delete, no account closure — see the note at the end of
// internal/awsapi/api.go. The interfaces this package holds cannot express them,
// which is a stronger guarantee than a code review of this file.
//
// No account tag ensure, for a narrower reason: OrgVendAPI has no
// ListTagsForResource, so an account's current tags cannot be read through the
// credential that would write them, and a tag ensure that cannot read is a
// blind write dressed as a comparison. The five tags of DESIGN §14 are applied
// at CreateAccount, where the vendor role's aws:RequestTag condition fixes the
// two that conditions elsewhere read. Policy tags *are* ensured, because
// OrgPolicyAPI can read them.
//
// # Ordering constraints callers must respect
//
// Attaching the baseline-protection SCP closes doors on the account, automat's
// own included: BP.IAM-1 denies iam:Put*/Attach*/Update* on the automation role
// with no exemption, deliberately (docs/open-questions.md Q13). So the caller
// establishes in-child roles *before* calling EnsurePolicyAttachment for that
// policy, and an AccessDenied on PutRolePolicy afterwards is automat's own
// control working rather than a missing grant.
package org
