// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/org"
)

// AutomationRolePolicyName is the inline policy EnsureAutomationRole writes
// with PutRolePolicy — one fixed name, the same create-or-replace shape
// org.EnsureVendorRole's "automat-vend" inline policy already uses, since
// IAM's inline-policy write has no separate update call to choose between.
const AutomationRolePolicyName = "automat-automation"

// Ensurer performs baseline's in-child ensure operations against a client
// already assumed into the vended account.
//
// Mirrors internal/org.Ensurer's shape (Mode, Principal, an actions
// accumulator) for the reason the package doc gives: a manifest reader should
// not need two different "verb" vocabularies for two pipeline stages that both
// feed the same evidence chain. Deliberately narrower than org.Ensurer in one
// respect — no Credential field. org.Ensurer's Native/Brokered distinction
// exists because DESIGN §5 routes account-and-OU and policy operations
// through two different credential shapes depending on whether the caller is
// in the management account or a member. Every operation THIS package
// performs, by contrast, always runs through an assumed
// OrganizationAccountAccessRole session in the child (DESIGN §7 step 5) —
// there is no native/brokered split to carry, so there is no field for it.
type Ensurer struct {
	// Role carries the automation role's create/read/write surface — the SAME
	// awsapi.IAMRoleAPI interface internal/org.Ensurer.Role already carries for
	// the vendor role in the management account (internal/org/setup.go). Built
	// against a session assumed into the CHILD account rather than the
	// management account; the caller constructs that session
	// (cmd/automat/globals.go), never this package — see the package doc's
	// closing section.
	Role awsapi.IAMRoleAPI

	// Mode is plan or apply, reusing org.Mode rather than a parallel enum.
	// The zero value is org.ModePlan, deliberately: a forgotten field must not
	// mutate an account, matching org.Ensurer's own reasoning for the same
	// default.
	Mode org.Mode
	// Principal is the identity automat is speaking as, for error text.
	Principal string

	// actions accumulates every Action this Ensurer produced, in order.
	actions []org.Action
}

// Actions returns every action this Ensurer produced so far, in order.
func (e *Ensurer) Actions() []org.Action { return append([]org.Action(nil), e.actions...) }

// planning reports whether writes are suppressed.
func (e *Ensurer) planning() bool { return e.Mode != org.ModeApply }

func (e *Ensurer) record(a org.Action) *org.Action {
	e.actions = append(e.actions, a)
	return &e.actions[len(e.actions)-1]
}

// EnsureAutomationRole makes the in-account automation role DESIGN §7 step 5
// names — "the automat automation role... least privilege for future
// verify" — exist under roleName, trusted per trustPolicy, and carrying
// permsPolicy as its inline permissions policy. Returns the role's ARN (empty
// for a planned creation, matching org.Ensurer's own convention: a plan
// cannot know the id of something it would create) and the actions this call
// produced.
//
// Read-first, the same shape org.EnsureVendorRole uses for the vendor role:
// GetRole decides whether this is a create or a permissions check on an
// existing role. Idempotent — a second call against an unchanged desired
// state issues no write and reports VerbUnchanged, which is what makes a
// re-vend (`vend --resume`, or a plain re-run) safe to call this again.
//
// # The Q13 park, not an ordinary denial
//
// If the role already exists, its current permissions policy differs from
// permsPolicy, and PutRolePolicy fails AccessDenied, this may be
// baseline-protection's BP.IAM-1 control doing exactly what it is compiled to
// do: deny iam:Put* on this role to every principal in the account, with no
// exemption, once baseline-protection is attached to the OU
// (docs/open-questions.md Q13). AccessDenied alone cannot distinguish that
// from an ordinary missing grant, so the remediation text states both
// readings rather than picking one — the same reasoning
// docs/open-questions.md documents for why org.Ensurer.denied does not print
// a single confident guess either. The error is a plain awsapi.PermissionError
// either way, which org.Parkable already recognizes (it treats any
// AccessDenied as recoverable) — so a caller wiring this into `vend` gets a
// PARKED vend rather than a bare failure or, worse, a re-run that silently
// keeps applying an old policy because the write kept failing quietly.
//
// A denial on the CREATE path (the role did not exist a moment ago in this
// same call) cannot be Q13 — baseline-protection could not have attached to a
// role that had no ARN yet — so that branch reports an ordinary missing
// grant instead.
func (e *Ensurer) EnsureAutomationRole(ctx context.Context, roleName string,
	trustPolicy, permsPolicy []byte) (roleARN string, actions []org.Action, err error) {
	if roleName == "" {
		return "", nil, fmt.Errorf("cannot ensure an automation role with no name")
	}
	before := len(e.actions)

	out, gerr := e.Role.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	switch {
	case gerr == nil:
		roleARN, err = e.updateAutomationRole(ctx, roleName, out, permsPolicy)
	case isNoSuchEntity(gerr):
		roleARN, err = e.createAutomationRole(ctx, roleName, trustPolicy, permsPolicy)
	default:
		err = awsapi.Denied(gerr, "iam:GetRole", roleName, e.Principal,
			grantSentence("iam:GetRole", roleName, e.Principal))
	}
	return roleARN, append([]org.Action(nil), e.actions[before:]...), err
}

func (e *Ensurer) createAutomationRole(ctx context.Context, roleName string,
	trust, perms []byte) (string, error) {
	if e.planning() {
		e.record(org.Action{
			Verb: org.VerbCreate, Kind: "automation role", Name: roleName,
			Detail: "would be created with the trust and permissions policies this vend describes; " +
				"the ARN is assigned by AWS at creation and cannot be predicted",
		})
		return "", nil
	}

	out, err := e.Role.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(string(trust)),
	})
	if err != nil {
		return "", awsapi.Denied(err, "iam:CreateRole", roleName, e.Principal,
			grantSentence("iam:CreateRole", roleName, e.Principal))
	}
	roleARN := aws.ToString(out.Role.Arn)

	if _, err := e.Role.TagRole(ctx, &iam.TagRoleInput{
		RoleName: aws.String(roleName),
		Tags:     []iamtypes.Tag{{Key: aws.String(org.OwnerTagKey), Value: aws.String(org.OwnerTagValue)}},
	}); err != nil {
		return roleARN, awsapi.Denied(err, "iam:TagRole", roleARN, e.Principal,
			grantSentence("iam:TagRole", roleARN, e.Principal))
	}

	// A denial here cannot be Q13: baseline-protection could not have attached
	// to a role that did not exist a moment ago in this same apply. See the
	// method doc.
	if _, err := e.Role.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String(AutomationRolePolicyName),
		PolicyDocument: aws.String(string(perms)),
	}); err != nil {
		return roleARN, awsapi.Denied(err, "iam:PutRolePolicy", roleARN, e.Principal,
			grantSentence("iam:PutRolePolicy", roleARN, e.Principal))
	}

	e.record(org.Action{
		Verb: org.VerbCreate, Kind: "automation role", Name: roleName, ID: roleARN,
		Detail: "created with the trust and permissions policies this vend describes", Applied: true,
	})
	return roleARN, nil
}

// updateAutomationRole handles a role found under roleName: compares the
// current inline policy against perms and writes only on drift, the same
// read-then-branch shape org.EnsurePolicy and org.EnsureVendorRole both use.
func (e *Ensurer) updateAutomationRole(ctx context.Context, roleName string,
	out *iam.GetRoleOutput, perms []byte) (string, error) {
	roleARN := aws.ToString(out.Role.Arn)

	current, exists, err := e.currentPolicy(ctx, roleName)
	if err != nil {
		return roleARN, err
	}
	if exists && org.SameDocument(current, string(perms)) {
		e.record(org.Action{
			Verb: org.VerbUnchanged, Kind: "automation role", Name: roleName, ID: roleARN,
			Detail: "permissions policy already matches what this vend would apply",
		})
		return roleARN, nil
	}

	if e.planning() {
		detail := "permissions policy is missing and would be created"
		if exists {
			detail = "permissions policy differs from what this vend would apply and would be replaced"
		}
		e.record(org.Action{
			Verb: org.VerbUpdate, Kind: "automation role", Name: roleName, ID: roleARN, Detail: detail,
		})
		return roleARN, nil
	}

	if _, err := e.Role.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String(AutomationRolePolicyName),
		PolicyDocument: aws.String(string(perms)),
	}); err != nil {
		if awsapi.IsAccessDenied(err) {
			return roleARN, awsapi.Denied(err, "iam:PutRolePolicy", roleARN, e.Principal,
				"if baseline-protection is attached to this account's organizational unit, its "+
					"BP.IAM-1 control denies iam:Put* on this role to every principal in the account, "+
					"including automat's own automation role, with no exemption "+
					"(docs/open-questions.md Q13) — detach baseline-protection from the OU, apply this "+
					"permissions change, then re-attach baseline-protection; if baseline-protection is "+
					"NOT attached to this OU, grant iam:PutRolePolicy on "+roleARN+" to "+
					principalOr(e.Principal)+" instead. AWS does not distinguish the two causes, so "+
					"both are stated")
		}
		return roleARN, awsapi.Denied(err, "iam:PutRolePolicy", roleARN, e.Principal,
			grantSentence("iam:PutRolePolicy", roleARN, e.Principal))
	}

	e.record(org.Action{
		Verb: org.VerbUpdate, Kind: "automation role", Name: roleName, ID: roleARN,
		Detail: "permissions policy replaced to match what this vend describes", Applied: true,
	})
	return roleARN, nil
}

// currentPolicy reads the automation role's inline policy, distinguishing
// "not written yet" from a read failure.
func (e *Ensurer) currentPolicy(ctx context.Context, roleName string) (doc string, exists bool, err error) {
	out, gerr := e.Role.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
		RoleName: aws.String(roleName), PolicyName: aws.String(AutomationRolePolicyName),
	})
	switch {
	case gerr == nil:
		return aws.ToString(out.PolicyDocument), true, nil
	case isNoSuchEntity(gerr):
		// The role itself was already confirmed to exist by the caller's GetRole;
		// NoSuchEntityException here means the named inline policy specifically
		// has never been written.
		return "", false, nil
	default:
		return "", false, awsapi.Denied(gerr, "iam:GetRolePolicy", roleName, e.Principal,
			grantSentence("iam:GetRolePolicy", roleName, e.Principal))
	}
}

func isNoSuchEntity(err error) bool { return awsapi.APIErrorCode(err) == "NoSuchEntityException" }

func principalOr(p string) string {
	if p == "" {
		return "the calling identity"
	}
	return p
}

// grantSentence is the ordinary (non-Q13) remediation: automat is speaking
// through an assumed OrganizationAccountAccessRole session in the child, so
// the fix is a grant to that session in the account it is IN — never a
// delegation policy or a vendor role, which is what distinguishes this from
// org.Ensurer.denied's Native/Brokered branches.
func grantSentence(action, resource, principal string) string {
	return "grant " + action + " on " + resource + " to " + principalOr(principal) + " in the vended " +
		"account; automat reached it by assuming OrganizationAccountAccessRole, and this is what " +
		"that session still needs"
}

// automationRoleActions is the automation role's own IAM permissions,
// translated one for one from every method on awsapi.ConfigAPI and
// awsapi.AccountAPI — the two in-child interfaces the REMAINING slices of
// DESIGN §7 step 5 (a Config recorder and delivery channel, a conformance
// pack, opt-in region enablement — ROADMAP.md's "internal/baseline, slices
// 3-5") will drive, none of which are built yet and none of which this slice
// calls.
//
// Widened now, ahead of the slices that will actually call these actions,
// deliberately: option (b) of this task's two choices, over leaving the
// policy minimal with a comment to come back later. The reason is Q13 rather
// than convenience — once baseline-protection attaches to the OU, BP.IAM-1
// denies iam:Put* on this role to every principal in the account including
// automat's own automation role, with no exemption. A later slice that needed
// to WIDEN this policy would hit exactly the park this package exists to
// detect, on a vend that had already completed and moved on. Rendering the
// full policy now, while the role is still being created for the first time
// (iam:CreateRole and iam:TagRole are absent from BP.IAM-1's deny list, but
// iam:PutRolePolicy is not), means slices 3-5 find the grant already in place
// rather than discovering they need a migration to get it.
var automationRoleActions = []string{
	// awsapi.ConfigAPI
	"config:DescribeConfigurationRecorders",
	"config:DescribeDeliveryChannels",
	"config:DescribeConformancePacks",
	"config:PutConfigurationRecorder",
	"config:PutDeliveryChannel",
	"config:PutConformancePack",
	"config:DescribeConformancePackStatus",
	"config:StartConfigurationRecorder",
	// awsapi.AccountAPI
	"account:ListRegions",
	"account:EnableRegion",
	"account:DisableRegion",
	"account:GetRegionOptStatus",
}

// PermissionsPolicyJSON renders the automation role's inline permissions
// policy from automationRoleActions. Static — nothing about a particular
// vended account varies the action list — so it takes no arguments and the
// same rendering is correct for every vend.
//
// Resource "*" rather than per-resource ARNs: a Config recorder, delivery
// channel, or conformance pack has no stable ARN form this policy could name
// ahead of the resource existing, and an AWS Account Management region
// operation is not resource-scoped at all. The same reasoning
// internal/bundle's VendorRolePermissionsPolicyJSON gives for its own
// ReadTheOrganization statement.
func PermissionsPolicyJSON() ([]byte, error) {
	doc := policyDocument{
		Version: "2012-10-17",
		Statement: []policyStatement{
			{
				Sid:      "AutomatBaselineOperations",
				Effect:   "Allow",
				Action:   append([]string(nil), automationRoleActions...),
				Resource: []string{"*"},
			},
		},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render the automation role's permissions policy: %w", err)
	}
	return out, nil
}

// TrustPolicyJSON renders the automation role's trust policy: only the
// organization's management account may assume it.
//
// Trust is placed on the management ACCOUNT (a root-principal ARN), not on
// one role's ARN inside it, matching the shape AWS itself gives
// OrganizationAccountAccessRole by default (DESIGN §3 fact 6). "Future
// verify" (DESIGN §7 step 5's own phrase — not built by this slice) may run
// natively from the management account, or in the MEMBER state through the
// same vendor-role session `vend` already assumes for
// CreateAccount/MoveAccount (DESIGN §5); trusting the account rather than one
// role ARN inside it is what lets either caller assume this role later
// without a second grant naming a role that may not even exist yet when this
// document is rendered.
func TrustPolicyJSON(managementAccountID, partition string) ([]byte, error) {
	if managementAccountID == "" {
		return nil, fmt.Errorf("cannot render the automation role's trust policy: no management " +
			"account id was given")
	}
	if partition == "" {
		partition = "aws"
	}
	doc := policyDocument{
		Version: "2012-10-17",
		Statement: []policyStatement{
			{
				Sid:       "AutomatManagementAccountMayAssume",
				Effect:    "Allow",
				Principal: &policyPrincipal{AWS: "arn:" + partition + ":iam::" + managementAccountID + ":root"},
				Action:    []string{"sts:AssumeRole"},
			},
		},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render the automation role's trust policy: %w", err)
	}
	return out, nil
}

// policyDocument, policyStatement, and policyPrincipal are a minimal,
// struct-marshaled IAM policy document — the same discipline
// internal/bundle's own policyDocument follows and for the same reason
// (internal/bundle/policy.go's doc comment): a document built from Go structs
// and marshaled by encoding/json cannot have a value close a string early or
// open a statement, whatever the value contains. Not shared with
// internal/bundle's identically-named types: that package is a maintainer
// tool rendering documents for a human or `automat setup` to apply, while
// this one is `EnsureAutomationRole`'s own input, and the two have no
// dependency either direction to justify importing one from the other for a
// three-field struct.
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Sid       string           `json:"Sid"`
	Effect    string           `json:"Effect"`
	Principal *policyPrincipal `json:"Principal,omitempty"`
	Action    []string         `json:"Action"`
	Resource  []string         `json:"Resource,omitempty"`
}

type policyPrincipal struct {
	AWS string `json:"AWS"`
}
