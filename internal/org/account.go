// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// AccountSpec is the account a vend wants to exist.
type AccountSpec struct {
	// Name is the account name. NOT a unique key: AWS permits two accounts with
	// the same name, so it is never what automat searches by.
	Name string
	// Email is the account's root email, and it IS the unique key — one account
	// per address across all of AWS (DESIGN §3, fact 11). That is what makes an
	// ensure operation possible without a state file: the desired account's
	// identity is a value the caller already holds.
	Email string
	// Tags are applied at creation. The two that conditions elsewhere read —
	// automat:vended-by and automat:ou — can only be set here, through
	// aws:RequestTag, which is what makes those conditions mean anything
	// (internal/bundle's mutableTagKeys). A create missing them is refused by the
	// vendor role, so they are required rather than defaulted.
	Tags map[string]string

	// RequestID is a CreateAccountRequestId from an earlier run. When set,
	// EnsureAccount polls it instead of creating anything: this is
	// `vend --resume`, and it is the only handle that reliably identifies an
	// in-flight or completed create.
	RequestID string

	// SearchParents are the containers to look in for an account that already
	// has this email. The root and the destination OU are the two that matter: a
	// create that succeeded lands the account under the root (DESIGN §3, fact 4),
	// and a run that got as far as the move left it in the destination.
	//
	// Bounded rather than organization-wide because it has to be: the vendor role
	// grants ListAccountsForParent and deliberately not ListAccounts
	// (internal/bundle's vendorRoleActions), so no credential automat holds in
	// the MEMBER state can enumerate the whole organization. An account a human
	// moved somewhere else is therefore invisible to this search, which is why
	// RequestID is the reliable resume handle and this is the second line.
	SearchParents []string
}

// AccountResult is what EnsureAccount found or produced.
type AccountResult struct {
	// ID is the account id, empty only for a plan that would create one.
	ID string
	// RequestID is the CreateAccountRequestId, when a create was involved. The
	// caller must persist it into the evidence record BEFORE waiting on it: it is
	// the only thing that makes a create resumable, and a run killed during the
	// poll has already consumed the account quota.
	RequestID string
	// Parent is where the account currently sits, when known.
	Parent string
}

// EnsureAccount makes an account with the spec's email exist, and returns it.
//
// The order of attempts is the whole design, and it is chosen so that no path
// can create a second account:
//
//  1. A RequestID given by the caller is polled. AWS retains create-account
//     statuses, so this answers definitively for a create that is in flight, one
//     that succeeded, and one that failed.
//  2. Otherwise the search parents are read for an account with this email. A
//     hit is a previous run that got at least as far as the create.
//  3. Otherwise, and only in ModeApply, CreateAccount runs and is polled.
//  4. If that create fails with EMAIL_ALREADY_EXISTS, the parents are read
//     again. The email is unique across AWS, so this means either a previous
//     run's account (adopt it) or an address that belongs to someone else's
//     account entirely (a hard error naming the address, because no retry can
//     fix it).
//
// Step 4 is the account-shaped instance of the discipline in the package doc:
// read first, and also tolerate the duplicate. Neither half alone is enough.
func (e *Ensurer) EnsureAccount(ctx context.Context, spec AccountSpec) (AccountResult, *Action, error) {
	if err := spec.validate(); err != nil {
		return AccountResult{}, nil, err
	}

	if spec.RequestID != "" {
		return e.resumeAccount(ctx, spec)
	}

	if id, parent, err := e.findAccountByEmail(ctx, spec); err != nil {
		return AccountResult{}, nil, err
	} else if id != "" {
		return AccountResult{ID: id, Parent: parent}, e.record(Action{
			Verb: VerbUnchanged, Kind: "account", Name: spec.Name, ID: id, Target: parent,
			Detail: "an account with root email " + spec.Email + " already exists under " + parent +
				"; adopted rather than created, because that address can belong to only one account",
		}), nil
	}

	if e.planning() {
		return AccountResult{}, e.record(Action{
			Verb: VerbCreate, Kind: "account", Name: spec.Name,
			Detail: "would be created with root email " + spec.Email + " and would land under the " +
				"organization root, not in the destination OU (DESIGN §3, fact 4); the id is assigned " +
				"by AWS and cannot be predicted",
		}), nil
	}

	out, err := e.Vend.CreateAccount(ctx, &organizations.CreateAccountInput{
		AccountName: aws.String(spec.Name),
		Email:       aws.String(spec.Email),
		Tags:        tagList(spec.Tags),
	})
	if err != nil {
		return AccountResult{}, nil, e.denied(err, "organizations:CreateAccount", "the organization")
	}
	reqID := aws.ToString(out.CreateAccountStatus.Id)

	id, ferr := e.pollCreate(ctx, reqID, spec)
	if ferr != nil {
		var dup *duplicateEmailError
		if !asDuplicateEmail(ferr, &dup) {
			// The request id travels with the error. Without it a `--resume` is
			// impossible and the operator has an account they cannot find.
			return AccountResult{RequestID: reqID}, nil, ferr
		}
		// EMAIL_ALREADY_EXISTS after our own read found nothing: somebody created
		// it in between, or it is outside what this credential can list.
		existing, parent, serr := e.findAccountByEmail(ctx, spec)
		if serr != nil {
			return AccountResult{RequestID: reqID}, nil, serr
		}
		if existing == "" {
			return AccountResult{RequestID: reqID}, nil, fmt.Errorf(
				"cannot create an account with root email %s: AWS reports that address is already in "+
					"use, and no account with it is visible in %s. One root email belongs to exactly one "+
					"AWS account anywhere in AWS (DESIGN §3, fact 11), so this is not something a retry "+
					"fixes: either the address already belongs to an account outside the containers "+
					"automat can list, or it belongs to a different organization entirely. Use a "+
					"different address — a plus-addressed variant of the same mailbox is enough — or "+
					"pass --resume with the create-account request id if a previous automat run made it",
				spec.Email, strings.Join(spec.SearchParents, ", "))
		}
		return AccountResult{ID: existing, RequestID: reqID, Parent: parent}, e.record(Action{
			Verb: VerbUnchanged, Kind: "account", Name: spec.Name, ID: existing, Target: parent,
			Detail: "created concurrently with automat's own create, which AWS refused as a duplicate " +
				"email; adopted the existing account rather than failing",
		}), nil
	}

	parent, perr := e.parentOf(ctx, id)
	if perr != nil {
		return AccountResult{ID: id, RequestID: reqID}, nil, perr
	}
	return AccountResult{ID: id, RequestID: reqID, Parent: parent}, e.record(Action{
		Verb: VerbCreate, Kind: "account", Name: spec.Name, ID: id, Target: parent,
		Detail: "created with root email " + spec.Email + " and landed under " + parent +
			" (create-account request " + reqID + ")",
		Applied: true,
	}), nil
}

// resumeAccount handles a caller-supplied request id.
//
// In ModePlan this reports rather than waits: a plan that blocked for five
// minutes on somebody else's in-flight create would not be a plan. VerbWait says
// so explicitly instead of guessing at the outcome.
func (e *Ensurer) resumeAccount(ctx context.Context, spec AccountSpec) (AccountResult, *Action, error) {
	if e.planning() {
		st, err := e.describeCreate(ctx, spec.RequestID)
		if err != nil {
			return AccountResult{RequestID: spec.RequestID}, nil, err
		}
		switch st.State {
		case orgtypes.CreateAccountStateSucceeded:
			id := aws.ToString(st.AccountId)
			parent, perr := e.parentOf(ctx, id)
			if perr != nil {
				return AccountResult{ID: id, RequestID: spec.RequestID}, nil, perr
			}
			return AccountResult{ID: id, RequestID: spec.RequestID, Parent: parent}, e.record(Action{
				Verb: VerbUnchanged, Kind: "account", Name: spec.Name, ID: id, Target: parent,
				Detail: "create-account request " + spec.RequestID + " already succeeded; the account exists",
			}), nil
		case orgtypes.CreateAccountStateFailed:
			return AccountResult{RequestID: spec.RequestID}, nil, e.createFailed(st, spec)
		default:
			return AccountResult{RequestID: spec.RequestID}, e.record(Action{
				Verb: VerbWait, Kind: "account", Name: spec.Name,
				Detail: "create-account request " + spec.RequestID + " is still in progress; an apply " +
					"would wait for it rather than create a second account",
			}), nil
		}
	}

	id, err := e.pollCreate(ctx, spec.RequestID, spec)
	if err != nil {
		return AccountResult{RequestID: spec.RequestID}, nil, err
	}
	parent, perr := e.parentOf(ctx, id)
	if perr != nil {
		return AccountResult{ID: id, RequestID: spec.RequestID}, nil, perr
	}
	return AccountResult{ID: id, RequestID: spec.RequestID, Parent: parent}, e.record(Action{
		Verb: VerbUnchanged, Kind: "account", Name: spec.Name, ID: id, Target: parent,
		Detail: "resumed create-account request " + spec.RequestID + "; the account exists under " + parent +
			", so nothing was created",
	}), nil
}

// pollCreate waits for a create-account request to finish and returns the
// account id.
//
// Creation is asynchronous and CreateAccount itself returns 200 (DESIGN §3, fact
// 6), so the failure arrives here or not at all. Code that checked only the
// immediate error would report a failed create as a success and then move an
// account that does not exist.
func (e *Ensurer) pollCreate(ctx context.Context, reqID string, spec AccountSpec) (string, error) {
	for i := 0; i < e.maxPolls(); i++ {
		st, err := e.describeCreate(ctx, reqID)
		if err != nil {
			return "", err
		}
		switch st.State {
		case orgtypes.CreateAccountStateSucceeded:
			id := aws.ToString(st.AccountId)
			if id == "" {
				return "", fmt.Errorf("create-account request %s reports SUCCEEDED with no account id, "+
					"which automat cannot act on; re-run with --resume %s to read the status again",
					reqID, reqID)
			}
			return id, nil
		case orgtypes.CreateAccountStateFailed:
			return "", e.createFailed(st, spec)
		}
		if err := e.sleep(ctx, e.pollInterval()); err != nil {
			return "", fmt.Errorf("waiting for create-account request %s: %w — the request is still in "+
				"flight at AWS and the account may yet appear; re-run with --resume %s rather than "+
				"vending again", reqID, err, reqID)
		}
	}
	return "", fmt.Errorf("create-account request %s did not finish within %s. The request is still in "+
		"flight at AWS and may yet succeed, so re-run with --resume %s — vending again would create a "+
		"second account and consume another of the organization's account quota",
		reqID, time.Duration(e.maxPolls())*e.pollInterval(), reqID)
}

func (e *Ensurer) describeCreate(ctx context.Context, reqID string) (*orgtypes.CreateAccountStatus, error) {
	out, err := e.Vend.DescribeCreateAccountStatus(ctx,
		&organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: aws.String(reqID)})
	switch {
	case err == nil:
	case isCode(err, "CreateAccountStatusNotFoundException"):
		return nil, fmt.Errorf("no create-account request with id %s exists in this organization. A "+
			"request id is scoped to the organization that made it, so check that these credentials "+
			"belong to the same organization as the run being resumed", reqID)
	default:
		return nil, e.denied(err, "organizations:DescribeCreateAccountStatus", reqID)
	}
	if out.CreateAccountStatus == nil {
		return nil, fmt.Errorf("create-account request %s: AWS returned no status and no error", reqID)
	}
	return out.CreateAccountStatus, nil
}

// duplicateEmailError is EMAIL_ALREADY_EXISTS, distinguished from every other
// creation failure because it is the one that means "this may already be yours".
type duplicateEmailError struct{ email string }

func (e *duplicateEmailError) Error() string {
	return "an AWS account with root email " + e.email + " already exists"
}

func asDuplicateEmail(err error, out **duplicateEmailError) bool {
	var d *duplicateEmailError
	if errors.As(err, &d) {
		*out = d
		return true
	}
	return false
}

// createFailed turns an asynchronous creation failure into remediation text.
//
// Every reason gets its own sentence because the owners differ completely: an
// email collision is the operator's to fix in seconds, an account limit is a
// support ticket with days of lead time, and a payment-instrument failure belongs
// to whoever owns the organization's billing — which at a university is neither
// of the first two people.
func (e *Ensurer) createFailed(st *orgtypes.CreateAccountStatus, spec AccountSpec) error {
	reqID := aws.ToString(st.Id)
	switch st.FailureReason {
	case orgtypes.CreateAccountFailureReasonEmailAlreadyExists:
		return &duplicateEmailError{email: spec.Email}
	case orgtypes.CreateAccountFailureReasonInvalidEmail:
		return fmt.Errorf("create-account request %s failed: AWS rejected %s as a root email address. "+
			"Correct the address, or the email pattern in the config file that produced it — an account "+
			"root address must be a real deliverable mailbox, because AWS sends password resets to it",
			reqID, spec.Email)
	case orgtypes.CreateAccountFailureReasonAccountLimitExceeded:
		return fmt.Errorf("create-account request %s failed: the organization is at its accounts quota. "+
			"Raising it is a support request with real lead time, not a setting — open one for "+
			"\"Organizations / accounts per organization\" (quota L-29A0C5DF) from the management "+
			"account; `automat preflight` reports the current limit so this is visible before a vend "+
			"rather than during one", reqID)
	case orgtypes.CreateAccountFailureReasonMissingPaymentInstrument,
		orgtypes.CreateAccountFailureReasonInvalidPaymentInstrument:
		return fmt.Errorf("create-account request %s failed: the organization's management account has "+
			"no valid payment method. This belongs to whoever owns the AWS bill rather than to whoever "+
			"runs automat — a new member account cannot be created until it is fixed in the management "+
			"account's billing settings", reqID)
	case orgtypes.CreateAccountFailureReasonConcurrentAccountModification:
		return fmt.Errorf("create-account request %s failed: another account operation was running in "+
			"this organization at the same time. Organizations serializes these, so this is a retry "+
			"rather than a fault — re-run the vend", reqID)
	case orgtypes.CreateAccountFailureReasonInternalFailure:
		return fmt.Errorf("create-account request %s failed with an internal AWS error. Nothing in the "+
			"request was wrong; re-run the vend, and if it recurs the request id above is what AWS "+
			"support will ask for", reqID)
	case "":
		return fmt.Errorf("create-account request %s failed and AWS reported no reason. Read the request "+
			"status in the Organizations console before re-running: automat will not guess at a cause",
			reqID)
	default:
		return fmt.Errorf("create-account request %s failed: %s. automat has no specific remediation for "+
			"that reason — look it up under DescribeCreateAccountStatus's FailureReason in the "+
			"Organizations API reference, which lists what each one means",
			reqID, st.FailureReason)
	}
}

// EnsurePlacement makes the account sit directly under destination.
//
// This is DESIGN §7 step 3, and it is where docs/open-questions.md Q12 lands.
// Whether MoveAccount into the parent the account is already in succeeds or
// returns DuplicateAccountException is not documented and cannot be settled from
// fakes, so this does BOTH things the question requires:
//
//   - It reads ListParents first and skips the move entirely when the account is
//     already where it belongs. That is the correct path, and it is also
//     necessary for its own sake: MoveAccount requires SourceParentId, so a
//     resumed vend cannot replay the call it made the first time — the source it
//     recorded is stale precisely because the move succeeded.
//   - It treats DuplicateAccountException from the move as success. That covers
//     the window between the read and the write, which a concurrent vend, a
//     console click, or a retried request all land in.
//
// Neither half alone is enough. With only the read, a TOCTOU loss fails a vend
// that has already done the right thing; with only the tolerance, automat
// depends on an undocumented behavior for its ordinary success path.
func (e *Ensurer) EnsurePlacement(ctx context.Context, accountID, destination string) (*Action, error) {
	switch {
	case accountID == "":
		return nil, fmt.Errorf("cannot place an account: no account id was given")
	case destination == "":
		return nil, fmt.Errorf("cannot place account %s: no destination OU was given — set `ou` in the "+
			"config file or pass --ou. A new account lands under the organization root (DESIGN §3, fact "+
			"4), and an account left there carries none of the policies attached to the OU, which is the "+
			"parked state DESIGN §5 names", accountID)
	}

	current, err := e.parentOf(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if current == destination {
		return e.record(Action{
			Verb: VerbUnchanged, Kind: "account placement", ID: accountID, Target: destination,
			Detail: "already directly under " + destination,
		}), nil
	}
	if e.planning() {
		return e.record(Action{
			Verb: VerbMove, Kind: "account placement", ID: accountID, Target: destination,
			Detail: "would move out of " + current + ", which also moves it out from under every service " +
				"control policy attached there",
		}), nil
	}

	_, err = e.Vend.MoveAccount(ctx, &organizations.MoveAccountInput{
		AccountId:           aws.String(accountID),
		SourceParentId:      aws.String(current),
		DestinationParentId: aws.String(destination),
	})
	switch {
	case err == nil:
		return e.record(Action{
			Verb: VerbMove, Kind: "account placement", ID: accountID, Target: destination,
			Detail: "moved from " + current + " to " + destination, Applied: true,
		}), nil
	case isCode(err, "DuplicateAccountException"):
		// Already in the destination. Q12's other reading of the same call, and
		// the TOCTOU window's landing spot: somebody moved it between automat's
		// read and its write. Both mean the desired state holds.
		return e.record(Action{
			Verb: VerbUnchanged, Kind: "account placement", ID: accountID, Target: destination,
			Detail: "already under " + destination + ": AWS reported the account is present in the " +
				"destination, which happened between automat's read of its parent and this move",
		}), nil
	case isCode(err, "SourceParentNotFoundException"):
		return nil, fmt.Errorf("cannot move account %s into %s: AWS rejected %s as its current parent, "+
			"which automat had just read. Something moved the account in between; re-run, and the "+
			"re-read will find where it is now", accountID, destination, current)
	case isCode(err, "DestinationParentNotFoundException"):
		return nil, fmt.Errorf("cannot move account %s: no root or OU with id %s exists in this "+
			"organization. Correct `ou` in the config file, or ask for the right OU id — the account "+
			"is now under %s, carrying whatever policies are attached there and none of the profile's",
			accountID, destination, current)
	default:
		return nil, e.denied(err, "organizations:MoveAccount", destination)
	}
}

// findAccountByEmail looks for an account with the spec's email in the search
// parents, returning its id and parent, or "" for both.
//
// By email, never by name: AWS permits two accounts with the same name, so a
// name match would let a second vend adopt an unrelated account and attach
// somebody else's policies to it. The email is unique across all of AWS.
//
// The comparison is case-insensitive on the whole address. Strictly speaking the
// local part is case-sensitive per RFC 5321 and the domain is not — but AWS
// treats the address as one account key, and an ensure operation that decided
// Lab@example.edu and lab@example.edu were different accounts would create the
// second one and then be told by AWS that they are the same.
func (e *Ensurer) findAccountByEmail(ctx context.Context, spec AccountSpec) (id, parent string, err error) {
	want := strings.ToLower(spec.Email)
	for _, container := range dedupe(spec.SearchParents) {
		var token *string
		seen := map[string]bool{}
		for i := 0; i < listPageCap; i++ {
			out, lerr := e.Vend.ListAccountsForParent(ctx, &organizations.ListAccountsForParentInput{
				ParentId: aws.String(container), NextToken: token,
			})
			switch {
			case lerr == nil:
			case isCode(lerr, "ParentNotFoundException"):
				// A container the caller named that does not exist. Skipping it
				// would hide a misconfigured OU id until the move failed.
				return "", "", fmt.Errorf("cannot look for an existing account in %s: no root or OU with "+
					"that id exists in this organization", container)
			default:
				return "", "", e.denied(lerr, "organizations:ListAccountsForParent", container)
			}
			for _, a := range out.Accounts {
				if strings.ToLower(aws.ToString(a.Email)) == want {
					return aws.ToString(a.Id), container, nil
				}
			}
			if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
				break
			}
			if seen[aws.ToString(out.NextToken)] {
				return "", "", fmt.Errorf("listing accounts under %s: the same pagination token came "+
					"back twice, so the list does not terminate; automat stopped rather than looping",
					container)
			}
			seen[aws.ToString(out.NextToken)] = true
			token = out.NextToken
		}
	}
	return "", "", nil
}

// parentOf reads an account's or OU's single parent.
//
// Organizations guarantees exactly one, which is what makes it usable as the
// read half of an idempotent move — and also what makes a move destructive in a
// way worth naming: moving an account IN moves it OUT from under whatever
// policies bound it before.
func (e *Ensurer) parentOf(ctx context.Context, childID string) (string, error) {
	out, err := e.Vend.ListParents(ctx, &organizations.ListParentsInput{ChildId: aws.String(childID)})
	switch {
	case err == nil:
	case isCode(err, "ChildNotFoundException"):
		return "", fmt.Errorf("cannot read the parent of %s: no account or organizational unit with that "+
			"id exists in this organization", childID)
	default:
		return "", e.denied(err, "organizations:ListParents", childID)
	}
	if len(out.Parents) == 0 {
		return "", fmt.Errorf("cannot read the parent of %s: AWS returned no parent, though every account "+
			"and OU in an organization has exactly one", childID)
	}
	return aws.ToString(out.Parents[0].Id), nil
}

func (spec AccountSpec) validate() error {
	switch {
	case spec.RequestID != "":
		// A resume needs nothing else: the request id identifies the create at
		// AWS, and the name and email are only used for message text.
		return nil
	case spec.Name == "":
		return fmt.Errorf("cannot ensure an account with no name")
	case spec.Email == "":
		return fmt.Errorf("cannot ensure an account with no root email: the address is the only key that " +
			"identifies the account across runs (DESIGN §3, fact 11), and without it a re-run would " +
			"create a second account rather than finding the first")
	case len(spec.SearchParents) == 0:
		return fmt.Errorf("cannot ensure account %q: no containers were given to look in. A re-run must "+
			"be able to find an account a previous run created, and with nowhere to look it would "+
			"create a second one — pass at least the organization root, where a new account lands "+
			"(DESIGN §3, fact 4)", spec.Name)
	}
	for k := range spec.Tags {
		if !strings.HasPrefix(k, tagNamespace) {
			return fmt.Errorf("cannot ensure account %q: tag key %q is outside automat's %q namespace. "+
				"The vendor role's grant bounds the keys it may write (internal/bundle's mutableTagKeys), "+
				"so a key outside the namespace is refused by AWS in the MEMBER state; refusing it here "+
				"too keeps the two states behaving the same", spec.Name, k, tagNamespace)
		}
	}
	return nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
