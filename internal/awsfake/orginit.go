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

// OrgInit fakes awsapi.OrgInitAPI: `automat init` from the STANDALONE state.
//
// The state it starts from is the interesting one. A standalone account has no
// organization, so this fake's zero-ish setup is an OrgState with InOrg false, and
// CreateOrganization is what brings the org into existence — after which every
// other fake over the same state starts working. That ordering is the test: an
// init path that attached a policy before enabling the policy type would look
// fine against a fake that had SCPs on from the start.
type OrgInit struct {
	Recorder
	State *OrgState

	// Created reports whether CreateOrganization has succeeded. A second call must
	// be refused, which is the whole idempotency question for `init`: re-running it
	// has to be safe, and "safe" here means recognizing
	// AlreadyInOrganizationException as success rather than as failure.
	Created bool
}

// NewOrgInit returns an init fake over a state that does not yet have an
// organization. The state's ids are used once CreateOrganization succeeds, so a
// test can name the org it expects to come into being.
func NewOrgInit(s *OrgState) *OrgInit {
	return &OrgInit{State: s}
}

// CreateOrganization implements awsapi.OrgInitAPI.
//
// Refuses anything but FeatureSet=ALL. DESIGN §3 fact 8 says SCPs require it, and
// DESIGN §7 hangs every control on an SCP, so an org created in
// consolidated-billing mode is an org where automat's output is decorative. The
// fake refuses rather than accepting-and-degrading because a degraded success is
// the failure that reaches production: everything reports fine and nothing is
// enforced.
func (f *OrgInit) CreateOrganization(_ context.Context, in *organizations.CreateOrganizationInput,
	_ ...func(*organizations.Options)) (*organizations.CreateOrganizationOutput, error) {
	f.Record("CreateOrganization")
	s := f.State
	if err := s.err("CreateOrganization"); err != nil {
		return nil, err
	}
	if err := s.before("CreateOrganization"); err != nil {
		return nil, err
	}
	if f.Created {
		return nil, &orgtypes.AlreadyInOrganizationException{
			Message: aws.String("The provided account is already a member of an organization."),
		}
	}
	if in.FeatureSet != orgtypes.OrganizationFeatureSetAll {
		// Not what AWS returns for this input — AWS accepts CONSOLIDATED_BILLING
		// happily. The fake is stricter on purpose, because automat has no reason to
		// ever send it and a test that did so should fail loudly rather than proceed
		// into an org where no SCP can be created. If a real need for the other
		// feature set ever appears, this is where the argument for it goes.
		return nil, &orgtypes.InvalidInputException{
			Message: aws.String("automat creates organizations with FeatureSet=ALL only: " +
				"service control policies require it (DESIGN §3 fact 8), and every control " +
				"automat attaches is an SCP."),
			Reason: orgtypes.InvalidInputExceptionReasonInvalidEnum,
		}
	}

	f.Created = true
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FeatureSet = orgtypes.OrganizationFeatureSetAll
	// SCPs are NOT enabled by a fresh CreateOrganization. AWS enables the SCP
	// policy type on the root separately, and this is the trap: the org is in ALL
	// features mode, CreatePolicy works, AttachPolicy works, and nothing is
	// enforced until EnablePolicyType runs. Starting the fake with SCPEnabled false
	// is what makes an init path that forgets it fail here rather than in an
	// auditor's report.
	s.SCPEnabled = false

	return &organizations.CreateOrganizationOutput{Organization: &orgtypes.Organization{
		Id:                 aws.String(s.OrgID),
		Arn:                aws.String("arn:aws:organizations::" + s.ManagementAccountID + ":organization/" + s.OrgID),
		FeatureSet:         orgtypes.OrganizationFeatureSetAll,
		MasterAccountId:    aws.String(s.ManagementAccountID),
		MasterAccountEmail: aws.String("org-management@example.edu"),
		MasterAccountArn: aws.String("arn:aws:organizations::" + s.ManagementAccountID +
			":account/" + s.OrgID + "/" + s.ManagementAccountID),
	}}, nil
}

// EnablePolicyType implements awsapi.OrgInitAPI.
//
// Idempotent in the AWS sense, which is to say not: a second call returns
// PolicyTypeAlreadyEnabledException. Ensure-semantics code must treat that as
// success, and it can only learn to if the fake produces it.
func (f *OrgInit) EnablePolicyType(_ context.Context, in *organizations.EnablePolicyTypeInput,
	_ ...func(*organizations.Options)) (*organizations.EnablePolicyTypeOutput, error) {
	f.Record("EnablePolicyType")
	s := f.State
	if err := s.err("EnablePolicyType"); err != nil {
		return nil, err
	}
	if err := s.before("EnablePolicyType"); err != nil {
		return nil, err
	}
	if in.PolicyType != orgtypes.PolicyTypeServiceControlPolicy {
		return nil, &orgtypes.InvalidInputException{
			Message: aws.String("You specified an unsupported policy type."),
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if aws.ToString(in.RootId) != s.RootID {
		return nil, &orgtypes.RootNotFoundException{
			Message: aws.String("We can't find a root with the RootId that you specified."),
		}
	}
	if s.SCPEnabled {
		return nil, &orgtypes.PolicyTypeAlreadyEnabledException{
			Message: aws.String("The specified policy type is already enabled."),
		}
	}
	if s.FeatureSet != orgtypes.OrganizationFeatureSetAll {
		return nil, &orgtypes.ConstraintViolationException{
			Message: aws.String("The organization must be in all features mode."),
			Reason:  orgtypes.ConstraintViolationExceptionReasonOrganizationNotInAllFeaturesMode,
		}
	}
	s.SCPEnabled = true

	return &organizations.EnablePolicyTypeOutput{Root: &orgtypes.Root{
		Id:   aws.String(s.RootID),
		Arn:  aws.String("arn:aws:organizations::" + s.ManagementAccountID + ":root/" + s.OrgID + "/" + s.RootID),
		Name: aws.String("Root"),
		PolicyTypes: []orgtypes.PolicyTypeSummary{{
			Type:   orgtypes.PolicyTypeServiceControlPolicy,
			Status: orgtypes.PolicyTypeStatusEnabled,
		}},
	}}, nil
}

var _ awsapi.OrgInitAPI = (*OrgInit)(nil)
