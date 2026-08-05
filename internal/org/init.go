// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// Info is what `init` learned about the organization it ensured.
type Info struct {
	// ID is the organization id (o-…).
	ID string
	// MasterAccountID is the management account. Kept because it is the account
	// whose credentials every later privileged step needs, and an operator who
	// runs `init` from the wrong account should be told which one they are in.
	MasterAccountID string
	// FeatureSet is ALL or CONSOLIDATED_BILLING. See the note in
	// EnsureOrganization: CONSOLIDATED_BILLING is a state in which automat can
	// do essentially nothing, and it is not one automat can leave.
	FeatureSet string
	// PreExisting is true when the organization was already there. `init`
	// reports it because "created an organization" and "found one" are very
	// different sentences to put in front of an operator who thinks they are
	// setting up a sandbox.
	PreExisting bool
}

// EnsureOrganization makes an organization exist with ALL features, and returns
// what it is.
//
// ALL features is not a default worth softening. DESIGN §3 fact 8: service control
// policies do not exist in CONSOLIDATED_BILLING mode, so in that feature set every
// preventive control in every catalog is unenforceable, and automat's entire
// preventive story is a comment. There is no API that upgrades the feature set
// without every member account accepting a handshake, so automat cannot fix it
// either — which is why finding an organization in that mode is a hard error with
// a pointer at the console rather than something automat works around.
//
// AlreadyInOrganizationException is success. It is AWS's shape for the second call
// to a create that has no idempotent form, and it is the ordinary case: nearly
// every institution already has an organization, and `init` exists mostly to make
// that discoverable and to enable the policy type.
func (e *Ensurer) EnsureOrganization(ctx context.Context, read awsapi.OrgAPI) (Info, *Action, error) {
	if e.Init == nil {
		return Info{}, nil, fmt.Errorf("cannot ensure an organization: this Ensurer has no " +
			"organization-init client. Only `automat init` creates an organization, and it is the only " +
			"command that should hold that capability")
	}
	if read == nil {
		return Info{}, nil, fmt.Errorf("cannot ensure an organization: no read client was given, and " +
			"automat will not call CreateOrganization without first checking whether one exists — a " +
			"create it did not need is the one call in this package that cannot be undone by re-running")
	}

	// Read first, and here the read is not merely an optimization: automat has to
	// know the feature set of an organization it did not create, and
	// CreateOrganization's error does not report it.
	info, err := describeOrg(ctx, read)
	switch {
	case err != nil && !awsapi.IsNotInOrganization(err):
		return Info{}, nil, e.denied(err, "organizations:DescribeOrganization",
			"this account's organization")
	case err == nil:
		info.PreExisting = true
		if info.FeatureSet != string(orgtypes.OrganizationFeatureSetAll) {
			return info, nil, fmt.Errorf("organization %s exists but its feature set is %s rather than "+
				"ALL: service control policies do not exist in that mode (DESIGN §3, fact 8), so no "+
				"preventive control in any catalog can be enforced and automat would be reporting "+
				"compliance it is not delivering. automat cannot change this — enabling all features "+
				"requires every existing member account to accept an invitation, which is an "+
				"organization-wide decision rather than a vend step. Enable all features from the "+
				"Organizations console in account %s, then re-run `automat init`",
				info.ID, info.FeatureSet, info.MasterAccountID)
		}
		return info, e.record(Action{
			Verb: VerbUnchanged, Kind: "organization", ID: info.ID,
			Detail: fmt.Sprintf("already exists with feature set ALL, management account %s; automat did "+
				"not create it", info.MasterAccountID),
		}), nil
	}

	// Not in an organization.
	if e.planning() {
		return Info{}, e.record(Action{
			Verb: VerbCreate, Kind: "organization",
			Detail: "this account is not in an organization; one would be created with feature set ALL, " +
				"making this account the management account permanently — the id is assigned by AWS and " +
				"cannot be predicted",
		}), nil
	}

	out, cerr := e.Init.CreateOrganization(ctx, &organizations.CreateOrganizationInput{
		FeatureSet: orgtypes.OrganizationFeatureSetAll,
	})
	switch {
	case cerr == nil:
		info = Info{
			ID:              aws.ToString(out.Organization.Id),
			MasterAccountID: aws.ToString(out.Organization.MasterAccountId),
			FeatureSet:      string(out.Organization.FeatureSet),
		}
		return info, e.record(Action{
			Verb: VerbCreate, Kind: "organization", ID: info.ID,
			Detail: fmt.Sprintf("created with feature set ALL, management account %s. The service control "+
				"policy type is NOT enabled by a new organization and must be enabled separately, or "+
				"every attached policy will enforce nothing", info.MasterAccountID),
			Applied: true,
		}), nil
	case isCode(cerr, "AlreadyInOrganizationException"):
		// Created between the read and the write, or by the same operator in
		// another terminal. Re-read: the feature set matters and this error does
		// not carry it.
		info, rerr := describeOrg(ctx, read)
		if rerr != nil {
			return Info{}, nil, fmt.Errorf("AWS reports this account is already in an organization, "+
				"but automat cannot read which one: %w. Grant organizations:DescribeOrganization to the "+
				"calling identity and re-run", rerr)
		}
		info.PreExisting = true
		if info.FeatureSet != string(orgtypes.OrganizationFeatureSetAll) {
			return info, nil, fmt.Errorf("this account joined organization %s between automat's check and "+
				"its create, and that organization's feature set is %s rather than ALL — see the note "+
				"above about why automat cannot proceed or fix it", info.ID, info.FeatureSet)
		}
		return info, e.record(Action{
			Verb: VerbUnchanged, Kind: "organization", ID: info.ID,
			Detail: "already in an organization: AWS refused the create, which happened between " +
				"automat's read and this call",
		}), nil
	default:
		return Info{}, nil, e.denied(cerr, "organizations:CreateOrganization",
			"a new organization for this account")
	}
}

// RootID returns the organization's single root id.
//
// A separate call because ListRoots is on the READ interface rather than on
// OrgInitAPI: reading the root is not a privilege `init` needs specially, and
// putting it on the init client would have made every command that wants a root id
// hold an interface that can create organizations.
//
// An organization has exactly one root. AWS has always returned one and the API is
// nonetheless a paginated list, so this refuses a second entry rather than taking
// the first: if that ever changes, "which root did automat attach the policy to"
// becomes a question with a wrong answer, and a wrong answer here silently
// attaches an institution's controls to the wrong half of its organization.
func RootID(ctx context.Context, read awsapi.OrgAPI) (string, error) {
	out, err := read.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return "", err
	}
	switch len(out.Roots) {
	case 0:
		return "", fmt.Errorf("this organization reports no roots, which should be impossible — every " +
			"organization has exactly one. Check that the credential is for an account inside the " +
			"organization")
	case 1:
		return aws.ToString(out.Roots[0].Id), nil
	default:
		return "", fmt.Errorf("this organization reports %d roots. automat is written against the "+
			"documented invariant that there is exactly one, and it will not guess which one an "+
			"institution's controls belong on. Report this", len(out.Roots))
	}
}

// SCPEnabled reports whether the service control policy type is enabled on the
// root.
//
// Worth reading even though EnsureSCPEnabled tolerates the already-enabled error,
// because the two answer different questions. EnsureSCPEnabled makes it true;
// this tells `preflight` and `vend` whether it is true *before* anything is
// attached — and a vend that attaches policies into a root with the type disabled
// succeeds at every call and enforces nothing, which is the one failure in this
// package that produces a green run and an unprotected account.
func SCPEnabled(ctx context.Context, read awsapi.OrgAPI) (bool, error) {
	out, err := read.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return false, err
	}
	for _, r := range out.Roots {
		for _, pt := range r.PolicyTypes {
			if pt.Type != orgtypes.PolicyTypeServiceControlPolicy {
				continue
			}
			// Only ENABLED counts. PENDING_ENABLE and PENDING_DISABLE are both
			// states in which enforcement is not yet a fact, and reading either as
			// "on" would be automat asserting a control is live while AWS is still
			// deciding.
			return pt.Status == orgtypes.PolicyTypeStatusEnabled, nil
		}
	}
	return false, nil
}

func describeOrg(ctx context.Context, read awsapi.OrgAPI) (Info, error) {
	out, err := read.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return Info{}, err
	}
	if out.Organization == nil {
		return Info{}, fmt.Errorf("describing the organization: AWS returned no organization and no error")
	}
	return Info{
		ID:              aws.ToString(out.Organization.Id),
		MasterAccountID: aws.ToString(out.Organization.MasterAccountId),
		FeatureSet:      string(out.Organization.FeatureSet),
	}, nil
}
