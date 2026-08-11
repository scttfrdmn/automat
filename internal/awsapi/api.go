// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsapi

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// STSAPI is caller identity and role assumption.
//
// GetCallerIdentity is the first call automat makes: preflight cannot classify
// an org state without knowing which account it is speaking as. AssumeRole
// covers both the brokered vendor role (DESIGN §5) and
// OrganizationAccountAccessRole for in-child baselining (DESIGN §7 step 5).
type STSAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput,
		optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
	AssumeRole(ctx context.Context, in *sts.AssumeRoleInput,
		optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// OrgAPI is the read half of AWS Organizations that preflight needs.
//
// Deliberately read-only: the mutating operations (CreateAccount, MoveAccount,
// CreateOrganizationalUnit, the policy calls) are Phase 2 and 3, and land on
// their own interface so that a Phase 1 code path cannot mutate an organization
// even by mistake. DescribeResourcePolicy is here because it is the only
// documented way to see a delegation policy from a member account, and per
// DESIGN §16 how much of it is visible from that side is still an open question.
type OrgAPI interface {
	DescribeOrganization(ctx context.Context, in *organizations.DescribeOrganizationInput,
		optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListRoots(ctx context.Context, in *organizations.ListRootsInput,
		optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListParents(ctx context.Context, in *organizations.ListParentsInput,
		optFns ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
	DescribeOrganizationalUnit(ctx context.Context, in *organizations.DescribeOrganizationalUnitInput,
		optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationalUnitOutput, error)
	DescribeResourcePolicy(ctx context.Context, in *organizations.DescribeResourcePolicyInput,
		optFns ...func(*organizations.Options)) (*organizations.DescribeResourcePolicyOutput, error)
}

// The mutating half of Organizations is THREE interfaces, not one, and the split
// is forced by DESIGN §5 rather than chosen for tidiness.
//
// In the MEMBER state a vend runs on two different credentials at once:
// CreateAccount and CreateOrganizationalUnit cannot be delegated (DESIGN §3,
// facts 1 and 2), so they are borrowed through an assumed role in the management
// account, while policy management *is* delegable and runs as the caller's own
// identity (fact 3). Those are two clients. A single OrgWriteAPI would be a type
// no MEMBER-state caller could ever satisfy, so the code would either hold a
// client with powers it does not have or paper over the difference — and the
// difference is the entire security argument the onboarding bundle makes.
//
// A second reason to keep them apart: the interface is where a capability
// automat does not need becomes a capability it cannot exercise. See the note on
// what is deliberately absent, below.

// OrgVendAPI is the account-and-OU half, carried by the brokered vendor role in
// the MEMBER state and by the caller's own credentials in MANAGEMENT.
//
// The reads are here as well as on OrgAPI, deliberately: in the MEMBER state
// these calls go through a *different client* than preflight's, and an ensure
// operation that writes with one credential must read back with the same one or
// it is asserting something about a view it does not have.
type OrgVendAPI interface {
	CreateAccount(ctx context.Context, in *organizations.CreateAccountInput,
		optFns ...func(*organizations.Options)) (*organizations.CreateAccountOutput, error)
	DescribeCreateAccountStatus(ctx context.Context, in *organizations.DescribeCreateAccountStatusInput,
		optFns ...func(*organizations.Options)) (*organizations.DescribeCreateAccountStatusOutput, error)
	MoveAccount(ctx context.Context, in *organizations.MoveAccountInput,
		optFns ...func(*organizations.Options)) (*organizations.MoveAccountOutput, error)
	CreateOrganizationalUnit(ctx context.Context, in *organizations.CreateOrganizationalUnitInput,
		optFns ...func(*organizations.Options)) (*organizations.CreateOrganizationalUnitOutput, error)
	TagResource(ctx context.Context, in *organizations.TagResourceInput,
		optFns ...func(*organizations.Options)) (*organizations.TagResourceOutput, error)

	DescribeAccount(ctx context.Context, in *organizations.DescribeAccountInput,
		optFns ...func(*organizations.Options)) (*organizations.DescribeAccountOutput, error)
	ListParents(ctx context.Context, in *organizations.ListParentsInput,
		optFns ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
	ListOrganizationalUnitsForParent(ctx context.Context, in *organizations.ListOrganizationalUnitsForParentInput,
		optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListAccountsForParent(ctx context.Context, in *organizations.ListAccountsForParentInput,
		optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error)
}

// OrgPolicyAPI is the SCP half, carried by delegated permissions in the MEMBER
// state (DESIGN §5, "policy half") and by the caller's own credentials in
// MANAGEMENT.
//
// TagResource appears here and on OrgVendAPI. That is not an oversight and not
// duplication to be factored out: the same action is granted twice by two
// different instruments, on two different resource types, to two different
// credentials — accounts by the vendor role, policies by the delegation policy —
// and the tag conditions differ between them (internal/bundle's scpTagActions
// gates on the *resource* tag; the account grant gates on the *request* tag).
// Collapsing them into one interface would suggest one grant.
type OrgPolicyAPI interface {
	CreatePolicy(ctx context.Context, in *organizations.CreatePolicyInput,
		optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error)
	UpdatePolicy(ctx context.Context, in *organizations.UpdatePolicyInput,
		optFns ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error)
	AttachPolicy(ctx context.Context, in *organizations.AttachPolicyInput,
		optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error)
	TagResource(ctx context.Context, in *organizations.TagResourceInput,
		optFns ...func(*organizations.Options)) (*organizations.TagResourceOutput, error)

	DescribePolicy(ctx context.Context, in *organizations.DescribePolicyInput,
		optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListPolicies(ctx context.Context, in *organizations.ListPoliciesInput,
		optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	ListPoliciesForTarget(ctx context.Context, in *organizations.ListPoliciesForTargetInput,
		optFns ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	ListTagsForResource(ctx context.Context, in *organizations.ListTagsForResourceInput,
		optFns ...func(*organizations.Options)) (*organizations.ListTagsForResourceOutput, error)
}

// OrgInitAPI is `automat init` from the STANDALONE state, and nothing else calls
// it (DESIGN §3, fact 12; DESIGN §4).
//
// Separate because it is the only interface whose operations are meaningless
// after the first successful call, and because EnablePolicyType is what makes
// fact 8 true: SCPs require the ALL feature set, so an org created without it is
// an org where every control automat attaches is silently unenforceable.
type OrgInitAPI interface {
	CreateOrganization(ctx context.Context, in *organizations.CreateOrganizationInput,
		optFns ...func(*organizations.Options)) (*organizations.CreateOrganizationOutput, error)
	EnablePolicyType(ctx context.Context, in *organizations.EnablePolicyTypeInput,
		optFns ...func(*organizations.Options)) (*organizations.EnablePolicyTypeOutput, error)
}

// OrgSetupAPI is `automat setup` from the MANAGEMENT state, applying the
// delegation policy DESIGN §5's "policy half" describes.
//
// PutResourcePolicy is on TestNoWriteInterfaceCanDestroy's list of actions kept
// unreachable until the interface exposing them says why it is safe — this is
// that interface, and the reason is the same shape as OrgPolicyAPI.UpdatePolicy's:
// the write is gated on reading back what is already there first. Organizations
// holds exactly ONE resource policy per organization, not a list keyed by id the
// way service control policies are — PutResourcePolicy REPLACES it wholesale, and
// there is no per-statement update and no owner tag on the document itself to
// check before overwriting. So org.EnsureDelegationPolicy (internal/org) reads
// DescribeResourcePolicy first and only calls PutResourcePolicy when the result
// is absent or already matches automat's own rendering of the request — never
// when a document with different content already exists. DeleteResourcePolicy is
// NOT here: nothing in Phase 3 removes a delegation, and adding it needs its own
// gate the way DeletePolicy will when `reclaim` is written.
type OrgSetupAPI interface {
	DescribeResourcePolicy(ctx context.Context, in *organizations.DescribeResourcePolicyInput,
		optFns ...func(*organizations.Options)) (*organizations.DescribeResourcePolicyOutput, error)
	PutResourcePolicy(ctx context.Context, in *organizations.PutResourcePolicyInput,
		optFns ...func(*organizations.Options)) (*organizations.PutResourcePolicyOutput, error)
}

// OrgVerifyAPI is `automat verify`'s read-only view of attached policies.
//
// A sibling of OrgPolicyAPI carrying none of its write methods, on purpose:
// verify reads what is attached and compares it against a fresh compile
// (internal/compilesets.Pack + the same sameDocument comparator
// internal/org already uses for drift detection during vend's own re-runs) —
// it has no reason to hold CreatePolicy, UpdatePolicy, or AttachPolicy, and
// giving it none means a bug in verify cannot mutate an organization no
// matter what it does. DescribePolicy plus ListPoliciesForTarget is the read
// pair OrgPolicyAPI already carries for the same purpose; ListTagsForResource
// is here because a policy's automat:managed-by tag is part of what a verify
// report distinguishes ("automat's, drifted" vs. "not automat's, present
// anyway").
type OrgVerifyAPI interface {
	DescribePolicy(ctx context.Context, in *organizations.DescribePolicyInput,
		optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListPoliciesForTarget(ctx context.Context, in *organizations.ListPoliciesForTargetInput,
		optFns ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	ListTagsForResource(ctx context.Context, in *organizations.ListTagsForResourceInput,
		optFns ...func(*organizations.Options)) (*organizations.ListTagsForResourceOutput, error)
}

// OrgReclaimAPI is `automat reclaim`'s destructive surface — the one this
// project has deliberately kept unreachable through every prior phase
// (docs/reclaim-design.md). Two of its three write methods appear on the
// destructive list below in every OTHER interface in this file; here, they
// are reachable, behind the plan/apply split and the unconditional `--yes`
// gate (CLAUDE.md rule 5) `cmd/automat/reclaim.go` builds around this
// interface, never around a bare client call.
//
// DetachPolicy is delegable at the Organizations level (DESIGN §3 fact 3) and
// carried natively in MANAGEMENT or by the caller's own delegated identity in
// MEMBER — never brokered, the same credential shape OrgPolicyAPI already
// uses. CloseAccount is NOT delegable (absent from every delegable-action
// list DESIGN documents, the same class as CreateAccount/
// CreateOrganizationalUnit), so it needs the brokered vendor role in MEMBER —
// the same MANAGEMENT/MEMBER split OrgVendAPI already implements for
// CreateAccount, reused here rather than reinvented. The two halves of this
// interface are therefore reached through two different client
// constructions depending on org state, exactly as OrgVendAPI's own doc
// comment already describes for its own two halves.
//
// ListPoliciesForTarget and ListTagsForResource are the read-before-write
// pair `docs/reclaim-design.md` requires: reclaim detaches only a policy
// carrying automat's own owner tag, the identical ownership check
// EnsurePolicyAttachment already performs before ever attaching one.
//
// ListAccountsForParent is a second, later-added read (AUDIT-6 C1):
// DetachPolicy's target is the account's parent OU, and an SCP is attached
// at the OU rather than the account (DESIGN §5, §8) — so an OU can hold more
// than one account, the same fact `docs/cli-surface.md` D5's tree walk
// already depends on. Detaching the OU's automat-owned policy while another
// ACTIVE account still sits under that OU strips that sibling's guardrails
// as a side effect of reclaiming a DIFFERENT account entirely. This method
// is what DetachOwnedPolicies checks before detaching anything, the same
// read OrgVendAPI already grants `list` for the identical tree-walk reason.
//
// DeletePolicy is deliberately ABSENT even though the onboarding bundle
// currently requests it: docs/reclaim-design.md decided reclaim detaches but
// does not delete, so this interface stays narrower than the grant it could
// use — the safe direction, since a granted-but-unreachable action costs
// nothing (this file's own guardrail, restated below).
type OrgReclaimAPI interface {
	DetachPolicy(ctx context.Context, in *organizations.DetachPolicyInput,
		optFns ...func(*organizations.Options)) (*organizations.DetachPolicyOutput, error)
	CloseAccount(ctx context.Context, in *organizations.CloseAccountInput,
		optFns ...func(*organizations.Options)) (*organizations.CloseAccountOutput, error)

	ListPoliciesForTarget(ctx context.Context, in *organizations.ListPoliciesForTargetInput,
		optFns ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	ListTagsForResource(ctx context.Context, in *organizations.ListTagsForResourceInput,
		optFns ...func(*organizations.Options)) (*organizations.ListTagsForResourceOutput, error)
	ListAccountsForParent(ctx context.Context, in *organizations.ListAccountsForParentInput,
		optFns ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error)
}

// # What is deliberately absent from all four
//
// DeletePolicy, DeleteOrganizationalUnit, RemoveAccountFromOrganization,
// LeaveOrganization, DeleteOrganization.
//
// The onboarding bundle *does* request DeletePolicy —
// `docs/reclaim-design.md` considered and rejected using it. But a granted
// action automat has no interface method for is an action no code path in
// this repository can reach, which is a stronger guarantee than a code
// review. The same reasoning made OrgAPI read-only through Phase 1;
// DetachPolicy and CloseAccount were their Phase 5 counterpart until
// OrgReclaimAPI above gave them the plan/apply split and the unconditional
// `--yes` gate (CLAUDE.md rule 5) that made them safe to make reachable.
//
// TestNoWriteInterfaceCanDestroy holds this. Adding one of these methods to an
// interface above fails the build rather than the review.

// IAMAPI is permission simulation.
//
// One method, and a load-bearing caveat: SimulatePrincipalPolicy does **not**
// evaluate service control policies (DESIGN §3, fact 9). A pass from a member
// account therefore means "the caller's identity policies allow this", not "this
// call will succeed" — an SCP above the account can still deny it. Every report
// built on this method must say so; see preflight.Report.
type IAMAPI interface {
	SimulatePrincipalPolicy(ctx context.Context, in *iam.SimulatePrincipalPolicyInput,
		optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
}

// IAMRoleAPI is `automat setup` creating and ensuring the vendor role DESIGN §5
// describes.
//
// Read-modify-write, the same shape as OrgSetupAPI: GetRole decides whether
// CreateRole or UpdateAssumeRolePolicy runs, so a re-run corrects a role's trust
// policy in place rather than either failing on "already exists" or blindly
// recreating it. PutRolePolicy is Organizations' CreatePolicy/UpdatePolicy
// distinction collapsed into one call — IAM's inline-policy API is already
// create-or-replace, so there is no separate update method to choose between.
// TagRole applies the automat:managed-by convention after CreateRole, since
// CreateRoleInput's own Tags field only takes effect on the account's FIRST
// creation and a later run must be able to correct a tag that was removed by
// hand. No DeleteRole, no DetachRolePolicy: nothing in Phase 3 removes a vendor
// role, matching OrgSetupAPI's absence of DeleteResourcePolicy.
type IAMRoleAPI interface {
	GetRole(ctx context.Context, in *iam.GetRoleInput,
		optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	CreateRole(ctx context.Context, in *iam.CreateRoleInput,
		optFns ...func(*iam.Options)) (*iam.CreateRoleOutput, error)
	UpdateAssumeRolePolicy(ctx context.Context, in *iam.UpdateAssumeRolePolicyInput,
		optFns ...func(*iam.Options)) (*iam.UpdateAssumeRolePolicyOutput, error)
	GetRolePolicy(ctx context.Context, in *iam.GetRolePolicyInput,
		optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	PutRolePolicy(ctx context.Context, in *iam.PutRolePolicyInput,
		optFns ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error)
	TagRole(ctx context.Context, in *iam.TagRoleInput,
		optFns ...func(*iam.Options)) (*iam.TagRoleOutput, error)
}

// QuotaAPI is Service Quotas lookup.
//
// Preflight reports the accounts-per-organization quota because it is low by
// default and raiseable only by a support request, which is a lead-time problem
// an operator wants to discover before planning a vend, not during one
// (DESIGN §3, fact 11).
type QuotaAPI interface {
	GetServiceQuota(ctx context.Context, in *servicequotas.GetServiceQuotaInput,
		optFns ...func(*servicequotas.Options)) (*servicequotas.GetServiceQuotaOutput, error)
}

// KMSAPI is the evidence-signing surface DESIGN §11 asks for as a drop-in
// alongside the local ed25519 signer (internal/evidence.LocalSigner):
// Sign, so evidence.KMSSigner can implement evidence.Signer, and Verify, for
// the matching evidence.KMSVerifier. Nothing here reads or exports key
// material — KMS signs a message it is handed and returns bytes, and it
// cannot be asked to reveal a key, which is the whole reason
// evidence.Signer was shaped this way from the start.
//
// GetPublicKey is deliberately absent: this project has no local-verification
// path against a downloaded public key, only KMS's own Verify call, so there
// is nothing here for it to feed.
type KMSAPI interface {
	Sign(ctx context.Context, in *kms.SignInput,
		optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, in *kms.VerifyInput,
		optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

// S3MirrorAPI is the remote evidence-mirror surface DESIGN §11's "in-account
// S3 (created at vend) and/or the vending account" compensating control asks
// for, and ROADMAP.md's "Remote evidence mirror" backlog item names as slice
// 1 (write-only) and slice 2 (read-and-diff in `verify`).
//
// PutObject is slice 1's whole job: evidence.S3Mirror.Upload calls it and
// nothing else. GetObject is carried here now, ahead of any caller using it,
// so this interface is complete for both slices rather than needing a second
// widening later — slice 2's read-and-diff will use it once `verify` gains a
// second interface method (kept separate from evidence.Mirror, the same
// Signer/Verifier split evidence/signer.go's own doc comment explains: a
// writer never needs read access, and bundling the two would make a
// write-only caller ask for a grant it does not need).
//
// # What is deliberately absent, and why
//
// DeleteObject: automat never administers or deletes a mirror copy. A copy of
// the evidence chain that automat's own credentials can delete is not a
// compensating control against a compromise of those credentials — it is the
// same single point of failure the local copy already has, mirrored.
//
// PutBucketPolicy, PutObjectLockConfiguration, PutBucketVersioning: automat
// never configures the bucket-level protections — Object Lock, versioning —
// that would make the mirror WORM. Those are operator/infrastructure
// decisions, not something this tool configures for itself. The reasoning is
// the same shape as the DeleteObject absence, one level up: giving automat a
// method to configure its own tamper-evidence infrastructure would let a
// compromise of automat's own credentials disable the very protection meant
// to survive that compromise. A bucket's WORM configuration has to be set up
// and held by someone automat vending an account cannot impersonate, or the
// "compensating control" is a control automat compensates for itself.
type S3MirrorAPI interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput,
		optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput,
		optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// SSOOIDCAPI is the device authorization grant used by `automat login`.
//
// automat does not implement a credential store: a successful device flow
// writes the same cache file the AWS SDKs already read, so every later command
// resolves credentials through the ordinary chain. Nothing else in the tool
// touches a token (DESIGN §13: never store secrets).
type SSOOIDCAPI interface {
	RegisterClient(ctx context.Context, in *ssooidc.RegisterClientInput,
		optFns ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorization(ctx context.Context, in *ssooidc.StartDeviceAuthorizationInput,
		optFns ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error)
	CreateToken(ctx context.Context, in *ssooidc.CreateTokenInput,
		optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error)
}

// ConfigAPI is the in-child detective baseline internal/baseline (not yet
// built; DESIGN §7 step 5) will drive: the AWS Config recorder, delivery
// channel, and conformance pack DESIGN §10's baseline-protection controls
// exist to guard.
//
// The read-before-write triplet — DescribeConfigurationRecorders,
// DescribeDeliveryChannels, DescribeConformancePacks — is here for the same
// reason OrgSetupAPI.DescribeResourcePolicy is: ensure-semantics needs a read
// first, and in this case there are three resources to check rather than one,
// each with its own Put. DescribeConformancePackStatus is the poll target for
// the async half — a conformance pack deploys via a CloudFormation stack
// under the hood, so PutConformancePack returning does not mean the pack is
// live, the same "accepted, not finished" shape OrgVendAPI.
// DescribeCreateAccountStatus already polls for CreateAccount.
//
// StartConfigurationRecorder is its own method, not folded into
// PutConfigurationRecorder, because the two are genuinely different calls
// against the real API: Put creates or replaces the recorder's configuration
// but does not turn it on, and a recorder that exists but was never started
// records nothing while reporting no error. This is the same "created but not
// enabled" trap org.EnsureSCPEnabled's doc comment describes for
// EnablePolicyType — a freshly created organization has the SCP policy type
// off by default, so CreatePolicy and AttachPolicy both succeed and nothing
// is enforced until EnablePolicyType runs. A future baseline.EnsureRecorder
// has to call Start after Put for the same reason org.EnsureSCPEnabled calls
// EnablePolicyType after (or instead of, once already on) create — the write
// that makes the resource exist is not the write that makes it active.
//
// # What is deliberately absent
//
// DeleteConfigurationRecorder, StopConfigurationRecorder,
// DeleteDeliveryChannel, and DeleteConformancePack are absent because they
// are exactly the actions catalogs/baseline-protection.json's BP.CFG family
// denies: BP.CFG-1 denies config:DeleteConfigurationRecorder and
// config:StopConfigurationRecorder (plus config:PutConfigurationRecorder,
// which is NOT absent here — see below), BP.CFG-2 denies
// config:DeleteDeliveryChannel, and BP.CFG-3 denies
// config:DeleteConformancePack. A capability automat has no interface method
// for is a capability no code path in this repository can reach, which is
// the same guarantee OrgReclaimAPI's own doc comment claims for
// DeletePolicy — stronger than a code review, and TestNoWriteInterfaceCanDestroy
// holds it the same way.
//
// PutConfigurationRecorder and PutDeliveryChannel ARE on this interface even
// though BP.CFG-1 and BP.CFG-2 deny them to every OTHER principal in the
// account: automat's own baselining is the one caller that must be able to
// issue them (ensure-semantics has no other way to correct drift in a
// recorder's recording group or a channel's destination), and
// catalogs/baseline-protection.json's exemption list is exactly the
// mechanism that reconciles "denied to the account" with "automat still
// needs it" — see DESIGN §10's exempt_principals paragraph.
//
// PutRemediationConfigurations, and anything else in Config's auto-remediation
// surface, is absent for a different reason than the four above: it is not
// something baseline-protection denies, it is something this project does not
// build at all. DESIGN.md's non-goals are explicit — "No continuous
// monitoring / evidence collection agents. `verify` is point-in-time." — and
// an auto-remediation action that reacts to a Config finding without an
// operator invoking a command is exactly the kind of standing agent that
// non-goal rules out.
type ConfigAPI interface {
	DescribeConfigurationRecorders(ctx context.Context, in *configservice.DescribeConfigurationRecordersInput,
		optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	DescribeDeliveryChannels(ctx context.Context, in *configservice.DescribeDeliveryChannelsInput,
		optFns ...func(*configservice.Options)) (*configservice.DescribeDeliveryChannelsOutput, error)
	DescribeConformancePacks(ctx context.Context, in *configservice.DescribeConformancePacksInput,
		optFns ...func(*configservice.Options)) (*configservice.DescribeConformancePacksOutput, error)

	PutConfigurationRecorder(ctx context.Context, in *configservice.PutConfigurationRecorderInput,
		optFns ...func(*configservice.Options)) (*configservice.PutConfigurationRecorderOutput, error)
	PutDeliveryChannel(ctx context.Context, in *configservice.PutDeliveryChannelInput,
		optFns ...func(*configservice.Options)) (*configservice.PutDeliveryChannelOutput, error)
	PutConformancePack(ctx context.Context, in *configservice.PutConformancePackInput,
		optFns ...func(*configservice.Options)) (*configservice.PutConformancePackOutput, error)

	DescribeConformancePackStatus(ctx context.Context, in *configservice.DescribeConformancePackStatusInput,
		optFns ...func(*configservice.Options)) (*configservice.DescribeConformancePackStatusOutput, error)

	StartConfigurationRecorder(ctx context.Context, in *configservice.StartConfigurationRecorderInput,
		optFns ...func(*configservice.Options)) (*configservice.StartConfigurationRecorderOutput, error)
}

// AccountAPI is opt-in region enablement, performed in-child via the Account
// Management API and scoped to exactly one field of an environment profile:
// envprofile.BaselineRegions (envprofile.Baseline.Regions), which is
// deliberately distinct from envprofile.Permitted's region allowlist — that
// field constrains which regions a principal may CALL into (an SCP condition),
// while this interface's four methods control which regions are ENABLED at
// all for the account, a prerequisite that has nothing to do with permission.
// An operator can enable a region without ever permitting calls into it, and
// vice versa; envprofile's own doc comment on Regions makes the same
// distinction for exactly that reason.
//
// ListRegions is the read-first half, same ensure-semantics reasoning as
// ConfigAPI's triplet and OrgSetupAPI.DescribeResourcePolicy before it: a
// future baseline.EnsureRegions has to know an account's current opt-in
// status before deciding whether EnableRegion or DisableRegion is a write or
// a no-op. GetRegionOptStatus is the poll target — region enablement is
// asynchronous, taking anywhere from minutes to hours per EnableRegionInput's
// own doc comment, the same "accepted, not finished" shape
// OrgVendAPI.DescribeCreateAccountStatus already polls for CreateAccount and
// ConfigAPI.DescribeConformancePackStatus polls for PutConformancePack.
//
// Nothing else: no billing, no alternate-contact, no account-name calls. This
// interface's whole job is region opt-in/opt-out, and account.Client carries
// GetContactInformation, PutAlternateContact, PutAccountName, and several
// primary-email operations that have no connection to baseline.regions and
// no reason to be reachable through automat.
type AccountAPI interface {
	ListRegions(ctx context.Context, in *account.ListRegionsInput,
		optFns ...func(*account.Options)) (*account.ListRegionsOutput, error)

	EnableRegion(ctx context.Context, in *account.EnableRegionInput,
		optFns ...func(*account.Options)) (*account.EnableRegionOutput, error)
	DisableRegion(ctx context.Context, in *account.DisableRegionInput,
		optFns ...func(*account.Options)) (*account.DisableRegionOutput, error)

	GetRegionOptStatus(ctx context.Context, in *account.GetRegionOptStatusInput,
		optFns ...func(*account.Options)) (*account.GetRegionOptStatusOutput, error)
}

// Compile-time proof that the real clients satisfy the interfaces. If an SDK
// upgrade changes a signature, this fails at build time in one place rather than
// wherever the interface happens to be used.
var (
	_ STSAPI        = (*sts.Client)(nil)
	_ OrgAPI        = (*organizations.Client)(nil)
	_ OrgVendAPI    = (*organizations.Client)(nil)
	_ OrgPolicyAPI  = (*organizations.Client)(nil)
	_ OrgInitAPI    = (*organizations.Client)(nil)
	_ OrgSetupAPI   = (*organizations.Client)(nil)
	_ OrgVerifyAPI  = (*organizations.Client)(nil)
	_ OrgReclaimAPI = (*organizations.Client)(nil)
	_ IAMAPI        = (*iam.Client)(nil)
	_ IAMRoleAPI    = (*iam.Client)(nil)
	_ QuotaAPI      = (*servicequotas.Client)(nil)
	_ KMSAPI        = (*kms.Client)(nil)
	_ S3MirrorAPI   = (*s3.Client)(nil)
	_ SSOOIDCAPI    = (*ssooidc.Client)(nil)
	_ ConfigAPI     = (*configservice.Client)(nil)
	_ AccountAPI    = (*account.Client)(nil)
)
