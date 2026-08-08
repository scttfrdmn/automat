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

// OrgSetup fakes awsapi.OrgSetupAPI: `automat setup` applying the delegation
// policy from the MANAGEMENT state.
//
// Backed by the same *OrgState a vend's fakes share, because a test of the whole
// onboarding-then-vend sequence needs the policy setup wrote to be visible to the
// account/OU fakes reading the organization afterward — the same reason OrgVend
// and OrgPolicy share one state rather than each holding its own copy.
type OrgSetup struct {
	Recorder
	State *OrgState
	// Read, when set by Observing, is updated after a successful
	// PutResourcePolicy so a later DescribeResourcePolicy through the read fake
	// (what preflight.checkDelegationVisibility calls) sees what this client
	// wrote — the same link OrgInit.Observing gives CreateOrganization.
	Read *Org
}

// NewOrgSetup returns a setup fake over s.
func NewOrgSetup(s *OrgState) *OrgSetup {
	return &OrgSetup{State: s}
}

// Observing returns a setup fake whose successful PutResourcePolicy also updates
// the read fake, mirroring OrgInit.Observing.
func (f *OrgSetup) Observing(read *Org) *OrgSetup {
	f.Read = read
	return f
}

// DescribeResourcePolicy implements awsapi.OrgSetupAPI.
//
// Reproduces the real API's ResourcePolicyNotFoundException when none exists,
// the same shape Org.DescribeResourcePolicy already does for the read-only
// caller — org.EnsureDelegationPolicy distinguishes "none configured yet" (safe
// to create) from every other error (refuse) by that code, and a fake that
// returned a different shape for "none" would let that branch go untested.
func (f *OrgSetup) DescribeResourcePolicy(_ context.Context, _ *organizations.DescribeResourcePolicyInput,
	_ ...func(*organizations.Options)) (*organizations.DescribeResourcePolicyOutput, error) {
	f.Record("DescribeResourcePolicy")
	s := f.State
	if err := s.err("DescribeResourcePolicy"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ResourcePolicy == "" {
		return nil, &APIError{
			Code:    "ResourcePolicyNotFoundException",
			Message: "We can't find a resource policy for the organization.",
		}
	}
	return &organizations.DescribeResourcePolicyOutput{
		ResourcePolicy: &orgtypes.ResourcePolicy{
			Content: aws.String(s.ResourcePolicy),
			ResourcePolicySummary: &orgtypes.ResourcePolicySummary{
				Id:  aws.String("rp-fake"),
				Arn: aws.String("arn:aws:organizations::" + s.ManagementAccountID + ":resourcepolicy/" + s.OrgID + "/rp-fake"),
			},
		},
	}, nil
}

// PutResourcePolicy implements awsapi.OrgSetupAPI.
//
// Unconditional overwrite, matching the real API: PutResourcePolicy "creates or
// updates" the org's one resource policy with no notion of a prior version to
// compare against. The refusal that keeps this from clobbering someone else's
// delegation lives in org.EnsureDelegationPolicy, one layer up, which reads
// DescribeResourcePolicy first — this fake's job is only to behave like the real
// call, not to reimplement the safety check on top of it.
func (f *OrgSetup) PutResourcePolicy(_ context.Context, in *organizations.PutResourcePolicyInput,
	_ ...func(*organizations.Options)) (*organizations.PutResourcePolicyOutput, error) {
	f.Record("PutResourcePolicy")
	s := f.State
	if err := s.err("PutResourcePolicy"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.ResourcePolicy = aws.ToString(in.Content)
	s.mu.Unlock()

	if f.Read != nil {
		f.Read.ResourcePolicy = aws.ToString(in.Content)
	}

	return &organizations.PutResourcePolicyOutput{
		ResourcePolicy: &orgtypes.ResourcePolicy{
			Content: in.Content,
			ResourcePolicySummary: &orgtypes.ResourcePolicySummary{
				Id:  aws.String("rp-fake"),
				Arn: aws.String("arn:aws:organizations::" + s.ManagementAccountID + ":resourcepolicy/" + s.OrgID + "/rp-fake"),
			},
		},
	}, nil
}

var _ awsapi.OrgSetupAPI = (*OrgSetup)(nil)
