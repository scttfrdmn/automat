// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// fakeRole is one in-memory IAM role.
type fakeRole struct {
	assumeRolePolicy string
	inlinePolicies   map[string]string
	tags             map[string]string
}

// IAMRole fakes awsapi.IAMRoleAPI: `automat setup` creating and ensuring the
// vendor role.
//
// Its own state rather than a share of OrgState — a role lives in IAM, not in
// Organizations, and nothing else in this package needs to see it. Keyed by role
// name because that is the identity every method takes; ARNs are assembled from
// ManagementAccountID the same way the real ones are, for messages that need one.
type IAMRole struct {
	Recorder

	ManagementAccountID string

	roles map[string]*fakeRole

	// Errs overrides the result of a named operation, e.g. "CreateRole".
	Errs map[string]error
}

// NewIAMRole returns an empty IAM role fake for the given management account.
func NewIAMRole(managementAccountID string) *IAMRole {
	return &IAMRole{
		ManagementAccountID: managementAccountID,
		roles:               map[string]*fakeRole{},
		Errs:                map[string]error{},
	}
}

func (f *IAMRole) err(op string) error {
	if f.Errs == nil {
		return nil
	}
	return f.Errs[op]
}

func (f *IAMRole) roleARN(name string) string {
	return "arn:aws:iam::" + f.ManagementAccountID + ":role/" + name
}

// GetRole implements awsapi.IAMRoleAPI.
//
// NoSuchEntityException for an absent role, the real API's shape and the one
// org.EnsureVendorRole branches on: absent means CreateRole, present means
// UpdateAssumeRolePolicy — the same "read decides which write" shape
// org.EnsureDelegationPolicy uses for the resource policy.
func (f *IAMRole) GetRole(_ context.Context, in *iam.GetRoleInput,
	_ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	f.Record("GetRole")
	if err := f.err("GetRole"); err != nil {
		return nil, err
	}
	name := aws.ToString(in.RoleName)
	r, ok := f.roles[name]
	if !ok {
		return nil, &APIError{
			Code:    "NoSuchEntityException",
			Message: "The role with name " + name + " cannot be found.",
		}
	}
	tags := make([]iamtypes.Tag, 0, len(r.tags))
	for k, v := range r.tags {
		tags = append(tags, iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return &iam.GetRoleOutput{
		Role: &iamtypes.Role{
			RoleName:                 aws.String(name),
			Arn:                      aws.String(f.roleARN(name)),
			AssumeRolePolicyDocument: aws.String(r.assumeRolePolicy),
			CreateDate:               aws.Time(time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)),
			Tags:                     tags,
		},
	}, nil
}

// CreateRole implements awsapi.IAMRoleAPI.
//
// Refuses a second create for the same name the way the real API does
// (EntityAlreadyExistsException) — org.EnsureVendorRole calls GetRole first
// specifically so this branch is never exercised in the ensure path, and this
// fake enforces that rather than silently overwriting if a caller skips the read.
func (f *IAMRole) CreateRole(_ context.Context, in *iam.CreateRoleInput,
	_ ...func(*iam.Options)) (*iam.CreateRoleOutput, error) {
	f.Record("CreateRole")
	if err := f.err("CreateRole"); err != nil {
		return nil, err
	}
	name := aws.ToString(in.RoleName)
	if _, exists := f.roles[name]; exists {
		return nil, &APIError{
			Code:    "EntityAlreadyExistsException",
			Message: "Role with name " + name + " already exists.",
		}
	}
	tags := make(map[string]string, len(in.Tags))
	for _, t := range in.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	f.roles[name] = &fakeRole{
		assumeRolePolicy: aws.ToString(in.AssumeRolePolicyDocument),
		inlinePolicies:   map[string]string{},
		tags:             tags,
	}
	return &iam.CreateRoleOutput{
		Role: &iamtypes.Role{
			RoleName:                 aws.String(name),
			Arn:                      aws.String(f.roleARN(name)),
			AssumeRolePolicyDocument: in.AssumeRolePolicyDocument,
			CreateDate:               aws.Time(time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)),
		},
	}, nil
}

// UpdateAssumeRolePolicy implements awsapi.IAMRoleAPI.
func (f *IAMRole) UpdateAssumeRolePolicy(_ context.Context, in *iam.UpdateAssumeRolePolicyInput,
	_ ...func(*iam.Options)) (*iam.UpdateAssumeRolePolicyOutput, error) {
	f.Record("UpdateAssumeRolePolicy")
	if err := f.err("UpdateAssumeRolePolicy"); err != nil {
		return nil, err
	}
	name := aws.ToString(in.RoleName)
	r, ok := f.roles[name]
	if !ok {
		return nil, &APIError{
			Code:    "NoSuchEntityException",
			Message: "The role with name " + name + " cannot be found.",
		}
	}
	r.assumeRolePolicy = aws.ToString(in.PolicyDocument)
	return &iam.UpdateAssumeRolePolicyOutput{}, nil
}

// GetRolePolicy implements awsapi.IAMRoleAPI.
func (f *IAMRole) GetRolePolicy(_ context.Context, in *iam.GetRolePolicyInput,
	_ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	f.Record("GetRolePolicy")
	if err := f.err("GetRolePolicy"); err != nil {
		return nil, err
	}
	roleName, policyName := aws.ToString(in.RoleName), aws.ToString(in.PolicyName)
	r, ok := f.roles[roleName]
	if !ok {
		return nil, &APIError{
			Code:    "NoSuchEntityException",
			Message: "The role with name " + roleName + " cannot be found.",
		}
	}
	doc, ok := r.inlinePolicies[policyName]
	if !ok {
		return nil, &APIError{
			Code:    "NoSuchEntityException",
			Message: "The role policy with name " + policyName + " cannot be found.",
		}
	}
	return &iam.GetRolePolicyOutput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String(policyName),
		PolicyDocument: aws.String(doc),
	}, nil
}

// PutRolePolicy implements awsapi.IAMRoleAPI.
//
// Create-or-replace, matching the real API: IAM's inline-policy write has no
// separate update call because Put already means both.
func (f *IAMRole) PutRolePolicy(_ context.Context, in *iam.PutRolePolicyInput,
	_ ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error) {
	f.Record("PutRolePolicy")
	if err := f.err("PutRolePolicy"); err != nil {
		return nil, err
	}
	name := aws.ToString(in.RoleName)
	r, ok := f.roles[name]
	if !ok {
		return nil, &APIError{
			Code:    "NoSuchEntityException",
			Message: "The role with name " + name + " cannot be found.",
		}
	}
	r.inlinePolicies[aws.ToString(in.PolicyName)] = aws.ToString(in.PolicyDocument)
	return &iam.PutRolePolicyOutput{}, nil
}

// TagRole implements awsapi.IAMRoleAPI.
func (f *IAMRole) TagRole(_ context.Context, in *iam.TagRoleInput,
	_ ...func(*iam.Options)) (*iam.TagRoleOutput, error) {
	f.Record("TagRole")
	if err := f.err("TagRole"); err != nil {
		return nil, err
	}
	name := aws.ToString(in.RoleName)
	r, ok := f.roles[name]
	if !ok {
		return nil, &APIError{
			Code:    "NoSuchEntityException",
			Message: "The role with name " + name + " cannot be found.",
		}
	}
	for _, t := range in.Tags {
		r.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return &iam.TagRoleOutput{}, nil
}

// RolePolicy returns a role's stored inline policy document, or "" if the role
// or the policy does not exist. A test helper for asserting on what
// org.EnsureVendorRole actually wrote, without going through GetRolePolicy's
// error-shaped return.
func (f *IAMRole) RolePolicy(roleName, policyName string) string {
	r, ok := f.roles[roleName]
	if !ok {
		return ""
	}
	return r.inlinePolicies[policyName]
}

// RoleTags returns a role's tags, or nil if the role does not exist.
func (f *IAMRole) RoleTags(roleName string) map[string]string {
	r, ok := f.roles[roleName]
	if !ok {
		return nil
	}
	return r.tags
}

var _ awsapi.IAMRoleAPI = (*IAMRole)(nil)
