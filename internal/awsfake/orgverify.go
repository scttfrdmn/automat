// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// OrgVerify fakes awsapi.OrgVerifyAPI over an OrgState.
//
// The read-only sibling of OrgPolicy: same shared state (so a test can seed
// attachments through OrgVend/OrgPolicy's fakes and read them back here,
// exactly as `automat verify` reads what a real vend attached), but with no
// method that could mutate it. Unlike OrgPolicy, there is no RequireOwnerTag
// or AttachableTargets scoping to reproduce — a read-only credential has no
// write to gate.
type OrgVerify struct {
	Recorder
	State *OrgState
}

// NewOrgVerify returns a verify fake over the given state.
func NewOrgVerify(s *OrgState) *OrgVerify { return &OrgVerify{State: s} }

// DescribePolicy implements awsapi.OrgVerifyAPI, identically to
// OrgPolicy.DescribePolicy — the read behavior is the same regardless of
// which credential asks, only the write behavior differs.
func (f *OrgVerify) DescribePolicy(_ context.Context, in *organizations.DescribePolicyInput,
	_ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	f.Record("DescribePolicy")
	s := f.State
	if err := s.err("DescribePolicy"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := aws.ToString(in.PolicyId)
	if _, ok := s.policies[id]; !ok {
		return nil, &orgtypes.PolicyNotFoundException{
			Message: aws.String("We can't find a policy with the PolicyId that you specified."),
		}
	}
	return &organizations.DescribePolicyOutput{Policy: s.policyOut(id)}, nil
}

// ListPoliciesForTarget implements awsapi.OrgVerifyAPI, identically to
// OrgPolicy.ListPoliciesForTarget.
func (f *OrgVerify) ListPoliciesForTarget(_ context.Context,
	in *organizations.ListPoliciesForTargetInput,
	_ ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	f.Record("ListPoliciesForTarget")
	s := f.State
	if err := s.err("ListPoliciesForTarget"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for _, id := range s.attachments[aws.ToString(in.TargetId)] {
		p, ok := s.policies[id]
		if !ok || (in.Filter != "" && p.Type != in.Filter) {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ids, next := page(s, ids, in.NextToken, in.MaxResults)
	out := make([]orgtypes.PolicySummary, 0, len(ids))
	for _, id := range ids {
		out = append(out, *s.policyOut(id).PolicySummary)
	}
	return &organizations.ListPoliciesForTargetOutput{Policies: out, NextToken: next}, nil
}

// ListTagsForResource implements awsapi.OrgVerifyAPI, identically to
// OrgPolicy.ListTagsForResource.
func (f *OrgVerify) ListTagsForResource(_ context.Context,
	in *organizations.ListTagsForResourceInput,
	_ ...func(*organizations.Options)) (*organizations.ListTagsForResourceOutput, error) {
	f.Record("ListTagsForResource")
	s := f.State
	if err := s.err("ListTagsForResource"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tags := s.tags[aws.ToString(in.ResourceId)]
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	keys, next := page(s, keys, in.NextToken, nil)
	out := make([]orgtypes.Tag, 0, len(keys))
	for _, k := range keys {
		out = append(out, orgtypes.Tag{Key: aws.String(k), Value: aws.String(tags[k])})
	}
	return &organizations.ListTagsForResourceOutput{Tags: out, NextToken: next}, nil
}

var _ awsapi.OrgVerifyAPI = (*OrgVerify)(nil)
