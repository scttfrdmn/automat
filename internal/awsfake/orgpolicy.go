// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// OrgPolicy fakes awsapi.OrgPolicyAPI over an OrgState.
//
// This is the delegated half (DESIGN §5, "policy half"), and its refusals are the
// interesting part of the fake. The delegation policy internal/bundle generates
// scopes policy modification by a resource tag and attachment by OU ARN; both are
// reproduced here, because the security argument the onboarding bundle makes is
// entirely about what this credential CANNOT do. A fake that let every call
// through would test automat against a delegation nobody would ever approve.
type OrgPolicy struct {
	Recorder
	State *OrgState

	// RequireOwnerTag, when non-empty, is a "key=value" pair that a policy must
	// already carry for UpdatePolicy, AttachPolicy, or TagResource to be permitted
	// against it. This is internal/bundle's scpModifyActions condition.
	//
	// Deliberately the RESOURCE tag, never the request tag. AUDIT-1's C1 was that
	// distinction: a condition reading a tag the caller may write constrains
	// nothing, and the two halves looked unremarkable in separate files. Encoding
	// the resource-tag reading here means code written against this fake is written
	// against the condition as it actually is.
	RequireOwnerTag string

	// AttachableTargets, when non-empty, is the set of target ids AttachPolicy
	// accepts — the delegation's OU ARN scoping. An empty set means unrestricted,
	// which is the MANAGEMENT-state case.
	AttachableTargets map[string]bool
}

// NewOrgPolicy returns a policy fake over the given state.
func NewOrgPolicy(s *OrgState) *OrgPolicy { return &OrgPolicy{State: s} }

// NewDelegatedOrgPolicy returns a policy fake scoped the way the onboarding
// bundle's delegation policy scopes it: modification gated on the owner tag,
// attachment confined to the given OU and its descendants.
func NewDelegatedOrgPolicy(s *OrgState, ownerTag, ouID string) *OrgPolicy {
	targets := map[string]bool{ouID: true}
	s.mu.Lock()
	for id := range s.ous {
		if s.inSubtree(id, ouID) {
			targets[id] = true
		}
	}
	s.mu.Unlock()
	return &OrgPolicy{State: s, RequireOwnerTag: ownerTag, AttachableTargets: targets}
}

// ownerTagSatisfied reports whether the resource carries the required tag.
func (f *OrgPolicy) ownerTagSatisfied(resourceID string) bool {
	if f.RequireOwnerTag == "" {
		return true
	}
	key, want := splitPair(f.RequireOwnerTag)
	return f.State.tags[resourceID][key] == want
}

func splitPair(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

// CreatePolicy implements awsapi.OrgPolicyAPI.
//
// Enforces the two limits the SCP packer has to live inside: the document size
// cap, and name uniqueness. Name uniqueness is what makes an ensure operation
// possible — a re-run cannot just create again — and it is also the only handle
// automat has for finding its own policy, since an Organizations policy id is
// assigned at creation and no ARN pattern distinguishes automat's SCPs from
// central IT's.
func (f *OrgPolicy) CreatePolicy(_ context.Context, in *organizations.CreatePolicyInput,
	_ ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error) {
	f.Record("CreatePolicy")
	s := f.State
	if err := s.err("CreatePolicy"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	name := aws.ToString(in.Name)
	content := aws.ToString(in.Content)

	if in.Type != orgtypes.PolicyTypeServiceControlPolicy {
		return nil, &orgtypes.InvalidInputException{
			Message: aws.String("You specified an unsupported policy type."),
		}
	}
	// Fact 8: an SCP cannot exist in an org that is not in ALL features mode.
	if s.FeatureSet != orgtypes.OrganizationFeatureSetAll {
		return nil, &orgtypes.ConstraintViolationException{
			Message: aws.String("The organization must be in all features mode to use service control policies."),
			Reason:  orgtypes.ConstraintViolationExceptionReasonOrganizationNotInAllFeaturesMode,
		}
	}
	if s.PolicySizeLimit > 0 && len(content) > s.PolicySizeLimit {
		return nil, &orgtypes.ConstraintViolationException{
			Message: aws.String(fmt.Sprintf(
				"The provided policy document exceeds the maximum size of %d characters.", s.PolicySizeLimit)),
			Reason: orgtypes.ConstraintViolationExceptionReasonPolicyContentLimitExceeded,
		}
	}
	for _, p := range s.policies {
		if p.Name == name {
			return nil, &orgtypes.DuplicatePolicyException{
				Message: aws.String("A policy with the same name already exists."),
			}
		}
	}

	s.nextPolicy++
	id := fmt.Sprintf("p-auto%04d", s.nextPolicy)
	s.policies[id] = &fakePolicy{
		ID: id, Name: name, Content: content,
		Desc: aws.ToString(in.Description), Type: orgtypes.PolicyTypeServiceControlPolicy,
	}
	// Tags on the create call. This is the request-tag path: the policy comes into
	// existence already carrying automat's owner tag, which is what makes the
	// resource-tag conditions on every later operation reachable at all.
	if tags := tagsToMap(in.Tags); len(tags) > 0 {
		s.tags[id] = tags
	}
	return &organizations.CreatePolicyOutput{Policy: s.policyOut(id)}, nil
}

// UpdatePolicy implements awsapi.OrgPolicyAPI.
//
// Gated on the resource tag. This is the call that would let a delegate rewrite
// central IT's institutional SCP if the gate were on the request tag instead, so a
// test that seeds an untagged policy and watches this refuse is testing the
// argument the whole delegation rests on.
func (f *OrgPolicy) UpdatePolicy(_ context.Context, in *organizations.UpdatePolicyInput,
	_ ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error) {
	f.Record("UpdatePolicy")
	s := f.State
	if err := s.err("UpdatePolicy"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	id := aws.ToString(in.PolicyId)
	p, ok := s.policies[id]
	if !ok {
		return nil, &orgtypes.PolicyNotFoundException{
			Message: aws.String("We can't find a policy with the PolicyId that you specified."),
		}
	}
	if !f.ownerTagSatisfied(id) {
		return nil, AccessDenied("organizations:UpdatePolicy")
	}
	if in.Content != nil {
		content := aws.ToString(in.Content)
		if s.PolicySizeLimit > 0 && len(content) > s.PolicySizeLimit {
			return nil, &orgtypes.ConstraintViolationException{
				Message: aws.String("The provided policy document exceeds the maximum size."),
				Reason:  orgtypes.ConstraintViolationExceptionReasonPolicyContentLimitExceeded,
			}
		}
		p.Content = content
	}
	if in.Description != nil {
		p.Desc = aws.ToString(in.Description)
	}
	if in.Name != nil {
		p.Name = aws.ToString(in.Name)
	}
	return &organizations.UpdatePolicyOutput{Policy: s.policyOut(id)}, nil
}

// AttachPolicy implements awsapi.OrgPolicyAPI.
//
// Two gates and one quota, all three load-bearing:
//
//   - The owner tag, so a delegate cannot attach central IT's SCP anywhere.
//   - The target set, so it cannot attach automat's SCP outside the delegated OU.
//     An SCP is a deny instrument (DESIGN §3 fact 7), so attaching one to somebody
//     else's account denies actions in it — the reason internal/bundle grants no
//     account-level attachment at all.
//   - Five policies per target. Union output plus region plus service plus
//     baseline-protection is already four, so this is a limit the packer meets in
//     ordinary use rather than an exotic case.
func (f *OrgPolicy) AttachPolicy(_ context.Context, in *organizations.AttachPolicyInput,
	_ ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
	f.Record("AttachPolicy")
	s := f.State
	if err := s.err("AttachPolicy"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	pid := aws.ToString(in.PolicyId)
	tid := aws.ToString(in.TargetId)

	if _, ok := s.policies[pid]; !ok {
		return nil, &orgtypes.PolicyNotFoundException{
			Message: aws.String("We can't find a policy with the PolicyId that you specified."),
		}
	}
	if !f.ownerTagSatisfied(pid) {
		return nil, AccessDenied("organizations:AttachPolicy")
	}
	if len(f.AttachableTargets) > 0 && !f.AttachableTargets[tid] {
		return nil, AccessDenied("organizations:AttachPolicy")
	}
	if !s.SCPEnabled {
		return nil, &orgtypes.PolicyTypeNotEnabledException{
			Message: aws.String("The specified policy type isn't currently enabled in this root."),
		}
	}
	for _, existing := range s.attachments[tid] {
		if existing == pid {
			// Already attached. AWS is explicit here — DuplicatePolicyAttachment — so
			// ensure-semantics has to either read first or treat this code as success.
			return nil, &orgtypes.DuplicatePolicyAttachmentException{
				Message: aws.String("The policy is already attached to the specified target."),
			}
		}
	}
	if s.PoliciesPerTarget > 0 && len(s.attachments[tid]) >= s.PoliciesPerTarget {
		return nil, &orgtypes.ConstraintViolationException{
			Message: aws.String(fmt.Sprintf(
				"You have exceeded the maximum number of policies (%d) attachable to a target.",
				s.PoliciesPerTarget)),
			Reason: orgtypes.ConstraintViolationExceptionReasonMaxPolicyTypeAttachmentLimitExceeded,
		}
	}
	s.attachments[tid] = append(s.attachments[tid], pid)
	return &organizations.AttachPolicyOutput{}, nil
}

// TagResource implements awsapi.OrgPolicyAPI.
//
// Gated on the resource tag, which reads circularly and is not: the delegation
// lets automat tag a policy that ALREADY carries its owner tag (adding
// cost-allocation keys to its own policy) and refuses to apply that tag to a
// policy lacking it. That asymmetry is the fix for AUDIT-1's C1 — see
// internal/bundle's scpTagActions, which explains why gating on the request tag
// here would hand the delegate the institutional baseline.
func (f *OrgPolicy) TagResource(_ context.Context, in *organizations.TagResourceInput,
	_ ...func(*organizations.Options)) (*organizations.TagResourceOutput, error) {
	f.Record("TagResource")
	s := f.State
	if err := s.err("TagResource"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := aws.ToString(in.ResourceId)
	if !f.ownerTagSatisfied(id) {
		return nil, AccessDenied("organizations:TagResource")
	}
	if s.tags[id] == nil {
		s.tags[id] = map[string]string{}
	}
	for k, v := range tagsToMap(in.Tags) {
		s.tags[id][k] = v
	}
	return &organizations.TagResourceOutput{}, nil
}

// DescribePolicy implements awsapi.OrgPolicyAPI.
func (f *OrgPolicy) DescribePolicy(_ context.Context, in *organizations.DescribePolicyInput,
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

// ListPolicies implements awsapi.OrgPolicyAPI.
//
// Returns central IT's policies too, which is the point: automat has to find its
// own by tag or by name, and a fake that only returned automat's would let a
// name-collision bug through.
func (f *OrgPolicy) ListPolicies(_ context.Context, in *organizations.ListPoliciesInput,
	_ ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	f.Record("ListPolicies")
	s := f.State
	if err := s.err("ListPolicies"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id, p := range s.policies {
		if in.Filter != "" && p.Type != in.Filter {
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
	return &organizations.ListPoliciesOutput{Policies: out, NextToken: next}, nil
}

// ListPoliciesForTarget implements awsapi.OrgPolicyAPI.
func (f *OrgPolicy) ListPoliciesForTarget(_ context.Context,
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
	// Filtered before paging, not after. Paging first and then dropping items would
	// return a short page with a NextToken, which is legal in AWS and is the exact
	// case a caller that stops at the first non-full page gets wrong — but it would
	// mean the fake's page boundaries depended on the filter, making a
	// truncated-read bug appear and disappear with the fixture.
	ids, next := page(s, ids, in.NextToken, in.MaxResults)
	out := make([]orgtypes.PolicySummary, 0, len(ids))
	for _, id := range ids {
		out = append(out, *s.policyOut(id).PolicySummary)
	}
	return &organizations.ListPoliciesForTargetOutput{Policies: out, NextToken: next}, nil
}

// ListTagsForResource implements awsapi.OrgPolicyAPI.
func (f *OrgPolicy) ListTagsForResource(_ context.Context,
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

// policyOut renders a policy. Caller holds the lock.
func (s *OrgState) policyOut(id string) *orgtypes.Policy {
	p := s.policies[id]
	return &orgtypes.Policy{
		Content: aws.String(p.Content),
		PolicySummary: &orgtypes.PolicySummary{
			Id:          aws.String(p.ID),
			Arn:         aws.String(s.policyARN(p.ID)),
			Name:        aws.String(p.Name),
			Description: aws.String(p.Desc),
			Type:        p.Type,
		},
	}
}

var _ awsapi.OrgPolicyAPI = (*OrgPolicy)(nil)
