// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// OrgVend fakes awsapi.OrgVendAPI over an OrgState.
//
// In the MEMBER state this stands in for the brokered vendor role; in MANAGEMENT,
// for the caller's own credentials. Which one it is matters only for what the fake
// refuses, so the refusals are configurable rather than assumed — see
// DenyOutsideOU.
type OrgVend struct {
	Recorder
	State *OrgState

	// DenyOutsideOU, when non-empty, refuses MoveAccount to any destination that
	// is not this OU or one of its descendants, and CreateOrganizationalUnit under
	// any parent outside the subtree.
	//
	// This is the vendor role's resource scoping (internal/bundle/role.go), and it
	// belongs in the fake rather than only in the template because the template is
	// tested for what it *says* while this tests what automat *does* when told no.
	// The two failures are different: a bundle that grants too little is a bad
	// afternoon, and code that assumes it can move an account anywhere is a vend
	// that dies halfway with an account parked under the root.
	DenyOutsideOU string
}

// NewOrgVend returns a vend fake over the given state.
func NewOrgVend(s *OrgState) *OrgVend { return &OrgVend{State: s} }

func tagsToMap(tags []orgtypes.Tag) map[string]string {
	out := map[string]string{}
	for _, t := range tags {
		out[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return out
}

// inSubtree reports whether id is root or a descendant of it.
func (s *OrgState) inSubtree(id, root string) bool {
	if id == root {
		return true
	}
	// Bounded by OU depth (five levels, DESIGN §3 fact 10) plus slack, so a
	// malformed parent cycle in a test fixture cannot hang the suite.
	for i := 0; i < 16; i++ {
		p, ok := s.parents[id]
		if !ok {
			return false
		}
		if p == root {
			return true
		}
		id = p
	}
	return false
}

// CreateAccount implements awsapi.OrgVendAPI.
//
// Returns IN_PROGRESS, like the real API: the account does not exist when this
// returns, and DESIGN §7 step 2 polls for it. The two things that can go wrong
// synchronously — a duplicate email and a missing mandatory tag — are the two the
// real grant and the real service actually enforce.
func (f *OrgVend) CreateAccount(_ context.Context, in *organizations.CreateAccountInput,
	_ ...func(*organizations.Options)) (*organizations.CreateAccountOutput, error) {
	f.Record("CreateAccount")
	s := f.State
	if err := s.err("CreateAccount"); err != nil {
		return nil, err
	}
	if err := s.before("CreateAccount"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	email := aws.ToString(in.Email)
	name := aws.ToString(in.AccountName)
	tags := tagsToMap(in.Tags)

	// The aws:RequestTag condition on the vendor role's CreateAccount grant. AWS
	// reports a failed condition as AccessDenied, not as a validation error, which
	// is worth reproducing exactly: code that treats "missing tag" as a bad-input
	// bug will send the operator to the wrong person.
	var missing []string
	for _, k := range s.RequiredCreateTags {
		if _, ok := tags[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, &APIError{
			Code: "AccessDeniedException",
			Message: "User: arn:aws:sts::" + s.ManagementAccountID +
				":assumed-role/automat-vendor/session is not authorized to perform: " +
				"organizations:CreateAccount because no identity-based policy allows the " +
				"organizations:CreateAccount action with the request tags provided " +
				"(missing: " + strings.Join(missing, ", ") + ")",
		}
	}

	// Every account needs a globally unique email (DESIGN §3 fact 11). AWS reports
	// this asynchronously as EMAIL_ALREADY_EXISTS, so the request is accepted and
	// then fails — the shape that catches code checking only the immediate return.
	s.nextRequest++
	reqID := fmt.Sprintf("car-exam%04d", s.nextRequest)
	req := &createRequest{
		ID: reqID, AccountName: name, Email: email, Tags: tags,
		pollsLeft: s.CreateAccountPolls, state: orgtypes.CreateAccountStateInProgress,
	}
	switch {
	case s.emails[email] != "":
		req.failure = orgtypes.CreateAccountFailureReasonEmailAlreadyExists
	case s.FailNextCreateWith != "":
		req.failure = s.FailNextCreateWith
		s.FailNextCreateWith = ""
	}
	s.requests[reqID] = req

	return &organizations.CreateAccountOutput{
		CreateAccountStatus: &orgtypes.CreateAccountStatus{
			Id:          aws.String(reqID),
			AccountName: aws.String(name),
			State:       orgtypes.CreateAccountStateInProgress,
		},
	}, nil
}

// DescribeCreateAccountStatus implements awsapi.OrgVendAPI.
//
// The account materializes here, under the ROOT — never in a target OU (DESIGN §3
// fact 4). A fake that placed it in the destination would erase the parked-account
// problem from DESIGN §5 and make the move step look unnecessary.
func (f *OrgVend) DescribeCreateAccountStatus(_ context.Context,
	in *organizations.DescribeCreateAccountStatusInput,
	_ ...func(*organizations.Options)) (*organizations.DescribeCreateAccountStatusOutput, error) {
	f.Record("DescribeCreateAccountStatus")
	s := f.State
	if err := s.err("DescribeCreateAccountStatus"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	reqID := aws.ToString(in.CreateAccountRequestId)
	req, ok := s.requests[reqID]
	if !ok {
		return nil, &APIError{
			Code:    "CreateAccountStatusNotFoundException",
			Message: "We can't find an create account request with the CreateAccountRequestId that you specified.",
		}
	}

	if req.state == orgtypes.CreateAccountStateInProgress {
		if req.pollsLeft > 0 {
			req.pollsLeft--
		} else if req.failure != "" {
			req.state = orgtypes.CreateAccountStateFailed
		} else {
			s.nextAccount++
			id := fmt.Sprintf("%012d", 100000000000+s.nextAccount)
			s.accounts[id] = &fakeAccount{ID: id, Name: req.AccountName, Email: req.Email}
			// Under the root. This is the whole reason MoveAccount exists in the flow.
			s.parents[id] = s.RootID
			s.emails[req.Email] = id
			if len(req.Tags) > 0 {
				s.tags[id] = map[string]string{}
				for k, v := range req.Tags {
					s.tags[id][k] = v
				}
			}
			req.accountID = id
			req.state = orgtypes.CreateAccountStateSucceeded
		}
	}

	out := &orgtypes.CreateAccountStatus{
		Id:          aws.String(req.ID),
		AccountName: aws.String(req.AccountName),
		State:       req.state,
	}
	if req.accountID != "" {
		out.AccountId = aws.String(req.accountID)
	}
	if req.state == orgtypes.CreateAccountStateFailed {
		out.FailureReason = req.failure
	}
	return &organizations.DescribeCreateAccountStatusOutput{CreateAccountStatus: out}, nil
}

// MoveAccount implements awsapi.OrgVendAPI.
//
// Note what the real API requires and this reproduces: SourceParentId is
// mandatory. A caller that does not already know where the account is cannot move
// it, which is why the flow reads ListParents first — and why a resumed vend
// cannot simply retry the same call it made the first time.
func (f *OrgVend) MoveAccount(_ context.Context, in *organizations.MoveAccountInput,
	_ ...func(*organizations.Options)) (*organizations.MoveAccountOutput, error) {
	f.Record("MoveAccount")
	s := f.State
	if err := s.err("MoveAccount"); err != nil {
		return nil, err
	}
	if err := s.before("MoveAccount"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	acct := aws.ToString(in.AccountId)
	dst := aws.ToString(in.DestinationParentId)
	src := aws.ToString(in.SourceParentId)

	if _, ok := s.accounts[acct]; !ok {
		return nil, &APIError{
			Code:    "AccountNotFoundException",
			Message: "We can't find an Amazon Web Services account with the AccountId that you specified.",
		}
	}
	if _, ok := s.ous[dst]; !ok && dst != s.RootID {
		return nil, &APIError{
			Code:    "DestinationParentNotFoundException",
			Message: "We can't find the destination container (a root or OU) with the ParentId that you specified.",
		}
	}
	if f.DenyOutsideOU != "" && !s.inSubtree(dst, f.DenyOutsideOU) {
		return nil, AccessDenied("organizations:MoveAccount")
	}

	now := s.parents[acct]
	if now == dst {
		// Already where it belongs. See OrgState.MoveToSamePlaceErrors: which of
		// these AWS does is unresolved, and ensure-semantics code has to survive
		// both. The error is the harsher reading, so it is the one worth being able
		// to turn on.
		if s.MoveToSamePlaceErrors {
			return nil, &APIError{
				Code:    "DuplicateAccountException",
				Message: "That account is already present in the specified destination.",
			}
		}
		return &organizations.MoveAccountOutput{}, nil
	}
	if src != "" && src != now {
		return nil, &APIError{
			Code:    "SourceParentNotFoundException",
			Message: "We can't find a source root or OU with the ParentId that you specified.",
		}
	}
	s.parents[acct] = dst
	return &organizations.MoveAccountOutput{}, nil
}

// CreateOrganizationalUnit implements awsapi.OrgVendAPI.
//
// Enforces both limits that bite in practice: five levels of OU depth (DESIGN §3
// fact 10) and the name uniqueness that makes ensure-semantics possible at all —
// a second create with the same name under the same parent is refused, so
// "ensure" has to mean look-then-create rather than create-and-ignore-the-error.
func (f *OrgVend) CreateOrganizationalUnit(_ context.Context,
	in *organizations.CreateOrganizationalUnitInput,
	_ ...func(*organizations.Options)) (*organizations.CreateOrganizationalUnitOutput, error) {
	f.Record("CreateOrganizationalUnit")
	s := f.State
	if err := s.err("CreateOrganizationalUnit"); err != nil {
		return nil, err
	}
	if err := s.before("CreateOrganizationalUnit"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	parent := aws.ToString(in.ParentId)
	name := aws.ToString(in.Name)

	if _, ok := s.ous[parent]; !ok && parent != s.RootID {
		return nil, &APIError{
			Code:    "ParentNotFoundException",
			Message: "We can't find a root or OU with the ParentId that you specified.",
		}
	}
	if f.DenyOutsideOU != "" && !s.inSubtree(parent, f.DenyOutsideOU) {
		return nil, AccessDenied("organizations:CreateOrganizationalUnit")
	}
	for id, ou := range s.ous {
		if ou.Name == name && s.parents[id] == parent {
			return nil, &APIError{
				Code:    "DuplicateOrganizationalUnitException",
				Message: "An OU with the same name already exists.",
			}
		}
	}
	// Depth: the root is level 0, and five levels of OU may hang below it.
	depth := 0
	for p := parent; p != s.RootID; p = s.parents[p] {
		depth++
		if depth > 16 {
			break
		}
	}
	if depth >= 5 {
		return nil, &orgtypes.ConstraintViolationException{
			Message: aws.String("You have exceeded the nesting depth for organizational units."),
			Reason:  orgtypes.ConstraintViolationExceptionReasonOuDepthLimitExceeded,
		}
	}

	s.nextOU++
	id := fmt.Sprintf("ou-exam-%08d", s.nextOU)
	s.ous[id] = &fakeOU{ID: id, Name: name}
	s.parents[id] = parent
	if tags := tagsToMap(in.Tags); len(tags) > 0 {
		s.tags[id] = tags
	}
	return &organizations.CreateOrganizationalUnitOutput{
		OrganizationalUnit: &orgtypes.OrganizationalUnit{
			Id:   aws.String(id),
			Name: aws.String(name),
			Arn:  aws.String(s.ouARN(id)),
		},
	}, nil
}

// TagResource implements awsapi.OrgVendAPI.
//
// Additive, like the real API: tagging an already-tagged resource updates the
// listed keys and leaves the rest. The mandatory tags automat sets at creation are
// NOT resettable here in the real grant — internal/bundle/role.go restricts the
// vendor role's TagResource to three cost-allocation keys precisely because two
// tags are read by conditions elsewhere. The fake does not enforce that key
// restriction, because the grant does and TestNoConditionReadsATagTheBundleLets
// TheDelegateWrite already holds it; enforcing it twice in different words would
// make one of them the wrong one eventually.
func (f *OrgVend) TagResource(_ context.Context, in *organizations.TagResourceInput,
	_ ...func(*organizations.Options)) (*organizations.TagResourceOutput, error) {
	f.Record("TagResource")
	s := f.State
	if err := s.err("TagResource"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := aws.ToString(in.ResourceId)
	if s.tags[id] == nil {
		s.tags[id] = map[string]string{}
	}
	for k, v := range tagsToMap(in.Tags) {
		s.tags[id][k] = v
	}
	return &organizations.TagResourceOutput{}, nil
}

// DescribeAccount implements awsapi.OrgVendAPI.
func (f *OrgVend) DescribeAccount(_ context.Context, in *organizations.DescribeAccountInput,
	_ ...func(*organizations.Options)) (*organizations.DescribeAccountOutput, error) {
	f.Record("DescribeAccount")
	s := f.State
	if err := s.err("DescribeAccount"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[aws.ToString(in.AccountId)]
	if !ok {
		return nil, &APIError{
			Code:    "AccountNotFoundException",
			Message: "We can't find an Amazon Web Services account with the AccountId that you specified.",
		}
	}
	return &organizations.DescribeAccountOutput{Account: &orgtypes.Account{
		Id:    aws.String(a.ID),
		Arn:   aws.String(s.accountARN(a.ID)),
		Name:  aws.String(a.Name),
		Email: aws.String(a.Email),
		// ACTIVE, not "whatever the caller hoped". A suspended account is a real
		// state and a vend against one must fail rather than half-succeed; a test
		// reaches it through Errs.
		Status: orgtypes.AccountStatusActive,
	}}, nil
}

// ListParents implements awsapi.OrgVendAPI.
//
// Organizations guarantees exactly one parent, which is what makes it usable as
// the read half of an idempotent move.
func (f *OrgVend) ListParents(_ context.Context, in *organizations.ListParentsInput,
	_ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	f.Record("ListParents")
	s := f.State
	if err := s.err("ListParents"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	child := aws.ToString(in.ChildId)
	p, ok := s.parents[child]
	if !ok {
		return nil, &APIError{
			Code:    "ChildNotFoundException",
			Message: "We can't find an organizational unit (OU) or Amazon Web Services account with the ChildId that you specified.",
		}
	}
	kind := orgtypes.ParentTypeOrganizationalUnit
	if p == s.RootID {
		kind = orgtypes.ParentTypeRoot
	}
	return &organizations.ListParentsOutput{Parents: []orgtypes.Parent{{
		Id: aws.String(p), Type: kind,
	}}}, nil
}

// ListOrganizationalUnitsForParent implements awsapi.OrgVendAPI.
//
// Paginated, PageSize items at a time. See OrgState.PageSize: a caller that
// ignores NextToken gets a truncated list and no error, which is how an ensure
// operation decides to create an OU that already exists.
func (f *OrgVend) ListOrganizationalUnitsForParent(_ context.Context,
	in *organizations.ListOrganizationalUnitsForParentInput,
	_ ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	f.Record("ListOrganizationalUnitsForParent")
	s := f.State
	if err := s.err("ListOrganizationalUnitsForParent"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	parent := aws.ToString(in.ParentId)
	var ids []string
	for id := range s.ous {
		if s.parents[id] == parent {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	ids, next := page(s, ids, in.NextToken, in.MaxResults)
	out := make([]orgtypes.OrganizationalUnit, 0, len(ids))
	for _, id := range ids {
		out = append(out, orgtypes.OrganizationalUnit{
			Id:   aws.String(id),
			Name: aws.String(s.ous[id].Name),
			Arn:  aws.String(s.ouARN(id)),
		})
	}
	return &organizations.ListOrganizationalUnitsForParentOutput{
		OrganizationalUnits: out, NextToken: next,
	}, nil
}

// ListAccountsForParent implements awsapi.OrgVendAPI.
func (f *OrgVend) ListAccountsForParent(_ context.Context,
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
	for id := range s.accounts {
		if s.parents[id] == parent {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	ids, next := page(s, ids, in.NextToken, in.MaxResults)
	out := make([]orgtypes.Account, 0, len(ids))
	for _, id := range ids {
		a := s.accounts[id]
		out = append(out, orgtypes.Account{
			Id:     aws.String(a.ID),
			Arn:    aws.String(s.accountARN(a.ID)),
			Name:   aws.String(a.Name),
			Email:  aws.String(a.Email),
			Status: orgtypes.AccountStatusActive,
		})
	}
	return &organizations.ListAccountsForParentOutput{Accounts: out, NextToken: next}, nil
}

func (s *OrgState) ouARN(id string) string {
	return "arn:aws:organizations::" + s.ManagementAccountID + ":ou/" + s.OrgID + "/" + id
}

func (s *OrgState) accountARN(id string) string {
	return "arn:aws:organizations::" + s.ManagementAccountID + ":account/" + s.OrgID + "/" + id
}

func (s *OrgState) policyARN(id string) string {
	return "arn:aws:organizations::" + s.ManagementAccountID +
		":policy/" + s.OrgID + "/service_control_policy/" + id
}

var _ awsapi.OrgVendAPI = (*OrgVend)(nil)
