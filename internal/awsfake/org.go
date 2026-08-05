// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// Org fakes awsapi.OrgAPI over an in-memory organization.
//
// The zero value is a standalone account: DescribeOrganization returns
// AWSOrganizationsNotInUseException, which is how preflight detects STANDALONE.
// Use NewOrg to build an organization.
type Org struct {
	Recorder

	// InOrg is false for a standalone account.
	InOrg bool
	// OrgID, ManagementAccountID, ManagementEmail, FeatureSet describe the org.
	OrgID               string
	ManagementAccountID string
	ManagementEmail     string
	FeatureSet          orgtypes.OrganizationFeatureSet
	// RootID is the org root, "r-" prefixed.
	RootID string

	// OUs maps an OU id to its record. Parent is the id of the containing OU or
	// the root.
	OUs map[string]OU

	// ResourcePolicy is the org's delegation policy document, if the caller can
	// see it. Empty means DescribeResourcePolicy reports none configured.
	ResourcePolicy string
	// ResourcePolicyErr, if set, fails DescribeResourcePolicy. The realistic
	// value is AccessDenied: a member account usually cannot read the policy
	// that grants it, so preflight must not treat "cannot see it" as "not
	// granted" (DESIGN §16).
	ResourcePolicyErr error

	// SCPStatus is the status ListRoots reports for the service control policy
	// type on the root. NewOrg sets ENABLED.
	//
	// The empty value means the root reports NO policy types at all, which is what
	// a root where SCPs were never enabled looks like — and it is a state worth
	// reaching in a test, because it is the one in which CreatePolicy and
	// AttachPolicy both succeed and nothing is enforced. PENDING_ENABLE is the
	// other value that matters: code reading it as "on" would assert a control is
	// live while AWS is still deciding.
	SCPStatus orgtypes.PolicyTypeStatus

	// Errs overrides the result of a named operation, e.g. "ListRoots".
	Errs map[string]error
}

// OU is one organizational unit in the fake org.
type OU struct {
	ID     string
	Name   string
	Parent string
}

// NewOrg returns an org fake with all features enabled and one root.
func NewOrg(orgID, managementAccountID string) *Org {
	return &Org{
		InOrg:               true,
		OrgID:               orgID,
		ManagementAccountID: managementAccountID,
		ManagementEmail:     "org-management@example.edu",
		FeatureSet:          orgtypes.OrganizationFeatureSetAll,
		RootID:              "r-exam",
		SCPStatus:           orgtypes.PolicyTypeStatusEnabled,
		OUs:                 map[string]OU{},
		Errs:                map[string]error{},
	}
}

// AddOU registers an OU under the given parent and returns its id.
func (f *Org) AddOU(id, name, parent string) *Org {
	if f.OUs == nil {
		f.OUs = map[string]OU{}
	}
	f.OUs[id] = OU{ID: id, Name: name, Parent: parent}
	return f
}

func (f *Org) err(op string) error {
	if f.Errs == nil {
		return nil
	}
	return f.Errs[op]
}

// DescribeOrganization implements awsapi.OrgAPI.
func (f *Org) DescribeOrganization(_ context.Context, _ *organizations.DescribeOrganizationInput,
	_ ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	f.Record("DescribeOrganization")
	if err := f.err("DescribeOrganization"); err != nil {
		return nil, err
	}
	if !f.InOrg {
		return nil, NotInOrganization()
	}
	return &organizations.DescribeOrganizationOutput{
		Organization: &orgtypes.Organization{
			Id:                 aws.String(f.OrgID),
			Arn:                aws.String("arn:aws:organizations::" + f.ManagementAccountID + ":organization/" + f.OrgID),
			FeatureSet:         f.FeatureSet,
			MasterAccountId:    aws.String(f.ManagementAccountID),
			MasterAccountEmail: aws.String(f.ManagementEmail),
			MasterAccountArn: aws.String("arn:aws:organizations::" + f.ManagementAccountID +
				":account/" + f.OrgID + "/" + f.ManagementAccountID),
		},
	}, nil
}

// ListRoots implements awsapi.OrgAPI.
//
// A member account is typically denied this call, so tests reach that state by
// setting Errs["ListRoots"] rather than by the fake guessing at it.
func (f *Org) ListRoots(_ context.Context, _ *organizations.ListRootsInput,
	_ ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	f.Record("ListRoots")
	if err := f.err("ListRoots"); err != nil {
		return nil, err
	}
	if !f.InOrg {
		return nil, NotInOrganization()
	}
	root := orgtypes.Root{
		Id:   aws.String(f.RootID),
		Arn:  aws.String("arn:aws:organizations::" + f.ManagementAccountID + ":root/" + f.OrgID + "/" + f.RootID),
		Name: aws.String("Root"),
	}
	if f.SCPStatus != "" {
		root.PolicyTypes = []orgtypes.PolicyTypeSummary{{
			Type:   orgtypes.PolicyTypeServiceControlPolicy,
			Status: f.SCPStatus,
		}}
	}
	return &organizations.ListRootsOutput{Roots: []orgtypes.Root{root}}, nil
}

// ListParents implements awsapi.OrgAPI.
func (f *Org) ListParents(_ context.Context, in *organizations.ListParentsInput,
	_ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	f.Record("ListParents")
	if err := f.err("ListParents"); err != nil {
		return nil, err
	}
	child := aws.ToString(in.ChildId)
	if ou, ok := f.OUs[child]; ok {
		kind := orgtypes.ParentTypeOrganizationalUnit
		if ou.Parent == f.RootID {
			kind = orgtypes.ParentTypeRoot
		}
		return &organizations.ListParentsOutput{Parents: []orgtypes.Parent{{
			Id: aws.String(ou.Parent), Type: kind,
		}}}, nil
	}
	// An unknown child sits under the root: a member account whose own placement
	// automat has not been told about.
	return &organizations.ListParentsOutput{Parents: []orgtypes.Parent{{
		Id: aws.String(f.RootID), Type: orgtypes.ParentTypeRoot,
	}}}, nil
}

// DescribeOrganizationalUnit implements awsapi.OrgAPI.
func (f *Org) DescribeOrganizationalUnit(_ context.Context, in *organizations.DescribeOrganizationalUnitInput,
	_ ...func(*organizations.Options)) (*organizations.DescribeOrganizationalUnitOutput, error) {
	f.Record("DescribeOrganizationalUnit")
	if err := f.err("DescribeOrganizationalUnit"); err != nil {
		return nil, err
	}
	id := aws.ToString(in.OrganizationalUnitId)
	ou, ok := f.OUs[id]
	if !ok {
		return nil, &APIError{
			Code:    "OrganizationalUnitNotFoundException",
			Message: "We can't find an OU with the OrganizationalUnitId that you specified.",
		}
	}
	return &organizations.DescribeOrganizationalUnitOutput{
		OrganizationalUnit: &orgtypes.OrganizationalUnit{
			Id:   aws.String(ou.ID),
			Name: aws.String(ou.Name),
			Arn: aws.String("arn:aws:organizations::" + f.ManagementAccountID +
				":ou/" + f.OrgID + "/" + ou.ID),
		},
	}, nil
}

// DescribeResourcePolicy implements awsapi.OrgAPI.
func (f *Org) DescribeResourcePolicy(_ context.Context, _ *organizations.DescribeResourcePolicyInput,
	_ ...func(*organizations.Options)) (*organizations.DescribeResourcePolicyOutput, error) {
	f.Record("DescribeResourcePolicy")
	if f.ResourcePolicyErr != nil {
		return nil, f.ResourcePolicyErr
	}
	if f.ResourcePolicy == "" {
		return nil, &APIError{
			Code:    "ResourcePolicyNotFoundException",
			Message: "We can't find a resource policy for the organization.",
		}
	}
	return &organizations.DescribeResourcePolicyOutput{
		ResourcePolicy: &orgtypes.ResourcePolicy{
			Content: aws.String(f.ResourcePolicy),
			ResourcePolicySummary: &orgtypes.ResourcePolicySummary{
				Id:  aws.String("rp-fake"),
				Arn: aws.String("arn:aws:organizations::" + f.ManagementAccountID + ":resourcepolicy/" + f.OrgID + "/rp-fake"),
			},
		},
	}, nil
}

var _ awsapi.OrgAPI = (*Org)(nil)
