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

// OrgReclaim fakes awsapi.OrgReclaimAPI over an OrgState.
//
// Deliberately as narrow as the interface it fakes (docs/reclaim-design.md):
// DeletePolicy is absent here too, so a test written against this fake
// cannot accidentally exercise a call the design decided against.
type OrgReclaim struct {
	Recorder
	State *OrgState

	// RequireOwnerTag mirrors OrgPolicy's own field exactly: a "key=value"
	// pair a policy must carry for DetachPolicy to succeed against it. The
	// same delegation-policy condition, checked the same way, because
	// DetachPolicy is delegable and reclaim uses the identical resource-tag
	// gate `verify`'s own grant already relies on.
	RequireOwnerTag string

	// CloseAccountQuotaExceeded, when true, makes CloseAccount fail with the
	// real AWS reason code for the closure rate limit
	// (docs/reclaim-design.md) instead of succeeding — the one rejection
	// path reclaim has remediation text for and cannot pre-check.
	CloseAccountQuotaExceeded bool
}

// NewOrgReclaim returns a reclaim fake over the given state.
func NewOrgReclaim(s *OrgState) *OrgReclaim { return &OrgReclaim{State: s} }

func (f *OrgReclaim) ownerTagSatisfied(resourceID string) bool {
	if f.RequireOwnerTag == "" {
		return true
	}
	key, want := splitPair(f.RequireOwnerTag)
	return f.State.tags[resourceID][key] == want
}

// DetachPolicy implements awsapi.OrgReclaimAPI, identically gated to
// OrgPolicy.AttachPolicy's own owner-tag check — the same delegation
// condition, the opposite direction.
func (f *OrgReclaim) DetachPolicy(_ context.Context, in *organizations.DetachPolicyInput,
	_ ...func(*organizations.Options)) (*organizations.DetachPolicyOutput, error) {
	f.Record("DetachPolicy")
	s := f.State
	if err := s.err("DetachPolicy"); err != nil {
		return nil, err
	}
	if err := s.before("DetachPolicy"); err != nil {
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
		return nil, AccessDenied("organizations:DetachPolicy")
	}
	attached := s.attachments[tid]
	idx := -1
	for i, id := range attached {
		if id == pid {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, &orgtypes.PolicyNotAttachedException{
			Message: aws.String("The policy isn't attached to the specified target."),
		}
	}
	s.attachments[tid] = append(attached[:idx], attached[idx+1:]...)
	return &organizations.DetachPolicyOutput{}, nil
}

// CloseAccount implements awsapi.OrgReclaimAPI.
//
// Marks the account SUSPENDED, the status AWS's own CloseAccount doc comment
// says a closed account settles into (docs/reclaim-design.md quotes it).
// CloseAccountQuotaExceeded, when set, makes this fail with the real reason
// code instead — the one path Reclaimer.CloseAccount has bespoke remediation
// text for. An account already SUSPENDED fails with
// AccountAlreadyClosedException (AUDIT-6 M1) — a real, named SDK exception
// type, reachable by re-running `reclaim --yes` against an account this same
// command already closed, which docs/reclaim-design.md's own resumability
// promise depends on being handled rather than surfaced raw.
func (f *OrgReclaim) CloseAccount(_ context.Context, in *organizations.CloseAccountInput,
	_ ...func(*organizations.Options)) (*organizations.CloseAccountOutput, error) {
	f.Record("CloseAccount")
	s := f.State
	if err := s.err("CloseAccount"); err != nil {
		return nil, err
	}
	if err := s.before("CloseAccount"); err != nil {
		return nil, err
	}
	if f.CloseAccountQuotaExceeded {
		return nil, &orgtypes.ConstraintViolationException{
			Message: aws.String("You have exceeded the number of accounts you can close within a " +
				"rolling 30 day period."),
			Reason: orgtypes.ConstraintViolationExceptionReasonCloseAccountQuotaExceeded,
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	id := aws.ToString(in.AccountId)
	acct, ok := s.accounts[id]
	if !ok {
		return nil, &orgtypes.AccountNotFoundException{
			Message: aws.String(fmt.Sprintf("We can't find an account with the AccountId %s.", id)),
		}
	}
	if id == s.ManagementAccountID {
		return nil, &orgtypes.ConstraintViolationException{
			Message: aws.String("You can't close the management account."),
			Reason:  orgtypes.ConstraintViolationExceptionReasonCannotCloseManagementAccount,
		}
	}
	if acct.Status == orgtypes.AccountStatusSuspended {
		return nil, &orgtypes.AccountAlreadyClosedException{
			Message: aws.String(fmt.Sprintf("The account %s is already closed.", id)),
		}
	}
	acct.Status = orgtypes.AccountStatusSuspended
	return &organizations.CloseAccountOutput{}, nil
}

// ListPoliciesForTarget implements awsapi.OrgReclaimAPI, identically to
// OrgPolicy.ListPoliciesForTarget.
func (f *OrgReclaim) ListPoliciesForTarget(_ context.Context,
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

// ListTagsForResource implements awsapi.OrgReclaimAPI, identically to
// OrgPolicy.ListTagsForResource.
func (f *OrgReclaim) ListTagsForResource(_ context.Context,
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

// ListAccountsForParent implements awsapi.OrgReclaimAPI (AUDIT-6 C1):
// DetachOwnedPolicies calls this before detaching anything, to see whether
// another account still sits under the same OU. Reports each account's REAL
// status rather than hardcoding ACTIVE the way OrgVend.DescribeAccount does
// for a different, narrower reason (its own comment: "a vend against
// [a suspended account] must fail rather than half-succeed") — here the
// point is exactly the opposite: a caller checking for a live sibling needs
// to see a SUSPENDED one as not blocking the detach, or this fake would
// hide the bug it exists to catch.
func (f *OrgReclaim) ListAccountsForParent(_ context.Context,
	in *organizations.ListAccountsForParentInput,
	_ ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
	f.Record("ListAccountsForParent")
	s := f.State
	if err := s.err("ListAccountsForParent"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	parent := aws.ToString(in.ParentId)
	var ids []string
	for id, p := range s.parents {
		if p == parent {
			if _, ok := s.accounts[id]; ok {
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	ids, next := page(s, ids, in.NextToken, in.MaxResults)
	out := make([]orgtypes.Account, 0, len(ids))
	for _, id := range ids {
		a := s.accounts[id]
		status := a.Status
		if status == "" {
			status = orgtypes.AccountStatusActive
		}
		out = append(out, orgtypes.Account{
			Id: aws.String(a.ID), Arn: aws.String(s.accountARN(a.ID)),
			Name: aws.String(a.Name), Email: aws.String(a.Email), Status: status,
		})
	}
	return &organizations.ListAccountsForParentOutput{Accounts: out, NextToken: next}, nil
}

var _ awsapi.OrgReclaimAPI = (*OrgReclaim)(nil)
