// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsapi

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
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

// Compile-time proof that the real clients satisfy the interfaces. If an SDK
// upgrade changes a signature, this fails at build time in one place rather than
// wherever the interface happens to be used.
var (
	_ STSAPI     = (*sts.Client)(nil)
	_ OrgAPI     = (*organizations.Client)(nil)
	_ IAMAPI     = (*iam.Client)(nil)
	_ QuotaAPI   = (*servicequotas.Client)(nil)
	_ SSOOIDCAPI = (*ssooidc.Client)(nil)
)
