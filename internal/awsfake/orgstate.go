// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"fmt"
	"sort"
	"strconv"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// OrgState is a mutable in-memory organization, shared by the write fakes.
//
// One state behind several fakes, because that is the situation a vend is
// actually in. DESIGN §5: in the MEMBER state, account and OU operations run
// through a role assumed in the management account while policy operations run as
// the caller's own delegated identity. Two clients, two credentials, one
// organization. A fake per client with private state would let a test pass that
// could never work — the policy half attaching to an OU the vend half created is
// exactly the interaction worth testing, and it only exists if they share a
// world.
//
// It is also why each fake keeps its own Recorder: the state is shared, the call
// log is not, so a test can assert that the policy client issued no account
// operation. That is the property the interface split exists to give, and this is
// where it becomes checkable.
//
// # Determinism
//
// Every generated id comes from a counter, never from a clock or a random source.
// Golden tests over vend output are the acceptance criterion for Phase 2, and a
// fake that produced a different account id per run would make them impossible —
// or, worse, would push the ids out of the golden files and out of the assertion.
type OrgState struct {
	mu sync.Mutex

	// OrgID, ManagementAccountID, RootID identify the organization.
	OrgID               string
	ManagementAccountID string
	RootID              string

	// FeatureSet and SCPEnabled together decide whether an attached SCP does
	// anything. DESIGN §3 fact 8: SCPs require the ALL feature set. An org in
	// consolidated-billing mode accepts no SCP at all, and a root with the policy
	// type disabled accepts the policy but enforces nothing — which is the
	// dangerous one, because it looks like success.
	FeatureSet orgtypes.OrganizationFeatureSet
	SCPEnabled bool

	accounts map[string]*fakeAccount
	ous      map[string]*fakeOU
	policies map[string]*fakePolicy
	// parents maps a child id (account or OU) to its parent id.
	parents map[string]string
	// attachments maps a target id to the policy ids attached to it.
	attachments map[string][]string
	// tags maps a resource id to its tags.
	tags map[string]map[string]string
	// requests tracks in-flight CreateAccount calls by request id.
	requests map[string]*createRequest
	// emails is the org-wide unique email set (DESIGN §3 fact 11).
	emails map[string]string

	nextAccount, nextOU, nextPolicy, nextRequest int

	// RequiredCreateTags are tag keys CreateAccount must carry or be refused.
	//
	// The vendor role's CreateAccount grant has an aws:RequestTag condition
	// requiring automat:vended-by and automat:ou (internal/bundle/role.go). A fake
	// that accepted an untagged create would hide the one failure the real grant
	// produces, and the code would ship having never been run against the
	// condition it was written for.
	RequiredCreateTags []string

	// CreateAccountPolls is how many DescribeCreateAccountStatus calls report
	// IN_PROGRESS before one reports SUCCEEDED. Zero means the first poll
	// succeeds; the default from NewOrgState is 2, because account creation is
	// asynchronous in a way that has bitten every tool that assumed otherwise, and
	// a fake that completed instantly would let a missing poll loop pass.
	CreateAccountPolls int

	// FailNextCreateWith, if set, makes the next CreateAccount request terminate
	// FAILED with this reason instead of succeeding. Asynchronous failure is the
	// shape AWS actually uses — CreateAccount itself returns 200 — so code that
	// only checks the immediate error will believe a failed create succeeded.
	FailNextCreateWith orgtypes.CreateAccountFailureReason

	// MoveToSamePlaceErrors decides what MoveAccount does when the account is
	// already in the destination.
	//
	// This is a genuine uncertainty, not a preference: it is the single most
	// important behavior for `vend --resume`, since a resumed vend re-runs the move
	// on an account that is already where it belongs. Only a live org settles it,
	// so it is a knob and both readings are tested (docs/open-questions.md Q12).
	// Ensure-semantics code must pass either way.
	MoveToSamePlaceErrors bool

	// PolicySizeLimit is the maximum policy document length in bytes. AWS
	// documents 5120 for an SCP; the packer (ROADMAP Phase 2) has to respect it,
	// and a fake without the limit would let an unpackable policy set look fine.
	PolicySizeLimit int
	// PoliciesPerTarget is the maximum SCPs attachable to one target, 5 in AWS.
	// Union output plus a region SCP plus a service SCP plus baseline protection is
	// already four, so this limit is reachable in ordinary use, not an edge case.
	PoliciesPerTarget int

	// PageSize is how many items a paginated list returns per call. Default 2.
	//
	// Deliberately small, and deliberately not "all of them". Every List operation
	// in Organizations paginates, and a caller that ignores NextToken gets a
	// truncated answer with no error — which for automat means an ensure operation
	// concluding a policy is not attached when it is, or `list` reporting a subset
	// of the accounts as though it were the inventory. A fake that returned one page
	// would make that bug invisible in exactly the tests written to prevent it. Two
	// is small enough that any realistic fixture spans several pages.
	PageSize int

	// Errs overrides the result of a named operation, e.g. "MoveAccount".
	Errs map[string]error
}

// page returns the slice of items for the requested token, and the next token
// ("" when the slice is exhausted).
//
// Tokens are the stringified offset. AWS's are opaque, and a caller must not
// construct one — but a caller that parses ours would be relying on a fake's
// internals, which is a different mistake than the one this exists to catch.
func page[T any](s *OrgState, items []T, token *string, max *int32) ([]T, *string) {
	size := s.PageSize
	if size <= 0 {
		size = 2
	}
	if max != nil && int(*max) > 0 && int(*max) < size {
		size = int(*max)
	}
	start := 0
	if token != nil {
		if n, err := strconv.Atoi(*token); err == nil {
			start = n
		}
	}
	if start >= len(items) {
		return nil, nil
	}
	end := start + size
	if end >= len(items) {
		return items[start:], nil
	}
	return items[start:end], aws.String(strconv.Itoa(end))
}

type fakeAccount struct {
	ID    string
	Name  string
	Email string
}

type fakeOU struct {
	ID   string
	Name string
}

type fakePolicy struct {
	ID      string
	Name    string
	Content string
	Desc    string
	Type    orgtypes.PolicyType
}

type createRequest struct {
	ID          string
	AccountName string
	Email       string
	Tags        map[string]string
	// pollsLeft counts down to completion.
	pollsLeft int
	state     orgtypes.CreateAccountState
	failure   orgtypes.CreateAccountFailureReason
	accountID string
}

// NewOrgState returns an organization with all features enabled, SCPs enabled,
// one root, and AWS's real quotas.
func NewOrgState(orgID, managementAccountID string) *OrgState {
	return &OrgState{
		OrgID:               orgID,
		ManagementAccountID: managementAccountID,
		RootID:              "r-exam",
		FeatureSet:          orgtypes.OrganizationFeatureSetAll,
		SCPEnabled:          true,
		accounts:            map[string]*fakeAccount{},
		ous:                 map[string]*fakeOU{},
		policies:            map[string]*fakePolicy{},
		parents:             map[string]string{},
		attachments:         map[string][]string{},
		tags:                map[string]map[string]string{},
		requests:            map[string]*createRequest{},
		emails:              map[string]string{},
		CreateAccountPolls:  2,
		PolicySizeLimit:     5120,
		PoliciesPerTarget:   5,
		PageSize:            2,
		Errs:                map[string]error{},
	}
}

func (s *OrgState) err(op string) error {
	if s.Errs == nil {
		return nil
	}
	return s.Errs[op]
}

// ---------------------------------------------------------------------------
// Seeding.
//
// Tests set up prior state through these rather than through the API fakes, for
// two reasons. The recorder then contains only what the code under test did,
// which is what makes "issued no redundant write" assertable. And some prior
// states cannot be reached through automat's own interfaces at all — central IT's
// SCP attached above the delegated OU is the important one, since automat has no
// permission to create it and the whole blast-radius argument is about it being
// there.
// ---------------------------------------------------------------------------

// SeedOU adds an OU under parent and returns its id.
func (s *OrgState) SeedOU(name, parent string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextOU++
	id := fmt.Sprintf("ou-exam-%08d", s.nextOU)
	s.ous[id] = &fakeOU{ID: id, Name: name}
	s.parents[id] = parent
	return id
}

// SeedOUWithID adds an OU under parent with a caller-chosen id, for tests that
// need to name it in a fixture or a golden file.
func (s *OrgState) SeedOUWithID(id, name, parent string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ous[id] = &fakeOU{ID: id, Name: name}
	s.parents[id] = parent
	return id
}

// SeedAccount adds an existing account under parent and returns its id.
func (s *OrgState) SeedAccount(name, email, parent string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextAccount++
	id := fmt.Sprintf("%012d", 200000000000+s.nextAccount)
	s.accounts[id] = &fakeAccount{ID: id, Name: name, Email: email}
	s.parents[id] = parent
	s.emails[email] = id
	return id
}

// SeedPolicy adds an existing policy and returns its id. Use it for a policy
// automat did not create: central IT's institutional SCP is the case that
// matters, and automat cannot create one.
func (s *OrgState) SeedPolicy(name, content string, tags map[string]string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextPolicy++
	id := fmt.Sprintf("p-fake%04d", s.nextPolicy)
	s.policies[id] = &fakePolicy{
		ID: id, Name: name, Content: content, Type: orgtypes.PolicyTypeServiceControlPolicy,
	}
	if len(tags) > 0 {
		s.tags[id] = map[string]string{}
		for k, v := range tags {
			s.tags[id][k] = v
		}
	}
	return id
}

// SeedAttachment attaches a policy to a target without going through the API, so
// a test can start from an org that already has policies in place.
func (s *OrgState) SeedAttachment(policyID, targetID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attachments[targetID] = append(s.attachments[targetID], policyID)
}

// ---------------------------------------------------------------------------
// Inspection. Tests assert on the resulting organization, not on call sequences —
// see the package doc for why.
// ---------------------------------------------------------------------------

// ParentOf returns the parent id of an account or OU, or "" if unknown.
func (s *OrgState) ParentOf(childID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.parents[childID]
}

// AccountIDs returns every account in the org, sorted by creation order.
func (s *OrgState) AccountIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.accounts))
	for id := range s.accounts {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// PolicyContent returns a policy's document, or "" if there is no such policy.
func (s *OrgState) PolicyContent(policyID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.policies[policyID]; ok {
		return p.Content
	}
	return ""
}

// PolicyIDByName returns the id of the policy with the given name, or "".
func (s *OrgState) PolicyIDByName(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, p := range s.policies {
		if p.Name == name {
			return id
		}
	}
	return ""
}

// AttachedTo returns the policy ids attached to a target, sorted.
func (s *OrgState) AttachedTo(targetID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string(nil), s.attachments[targetID]...)
	sort.Strings(out)
	return out
}

// TagsOf returns a copy of a resource's tags.
func (s *OrgState) TagsOf(resourceID string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for k, v := range s.tags[resourceID] {
		out[k] = v
	}
	return out
}
