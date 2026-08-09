// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// Reclaimer performs `automat reclaim`'s two-step account closure
// (docs/reclaim-design.md): detach automat's own service control policies,
// then close the account.
//
// A separate type from Ensurer rather than a method added to it, deliberately:
// Ensurer's fields (Vend, Policy, Init, Setup, Role) are all read/write
// capability this project has exercised through four phases without a
// destructive action anywhere in reach. Giving Reclaimer its own type, its
// own field, and its own plan/apply state keeps the one destructive surface
// visibly separate rather than one more field on a struct that already does
// several other things — mirroring the interface-level separation
// internal/awsapi.OrgReclaimAPI already draws.
type Reclaimer struct {
	// Policy carries DetachPolicy and the two read methods, on whichever
	// credential is delegated to make policy calls in this state — native
	// in MANAGEMENT, the caller's own delegated identity in MEMBER. Never
	// brokered: DetachPolicy is delegable at the Organizations level
	// (DESIGN §3 fact 3), the same shape OrgPolicyAPI already uses.
	Policy awsapi.OrgReclaimAPI
	// Close carries CloseAccount, on whichever credential can make it —
	// native in MANAGEMENT, the brokered vendor role in MEMBER, because
	// CloseAccount is NOT delegable (same class as CreateAccount, DESIGN §3
	// facts 1-2). Deliberately a second field rather than reusing Policy:
	// in MEMBER state the two are two different clients on two different
	// credentials, exactly the reason Ensurer keeps Vend and Policy apart.
	Close awsapi.OrgReclaimAPI

	// Mode is plan or apply. The zero value is ModePlan, deliberately: a
	// forgotten field must not close an account.
	Mode Mode
	// Credential selects the remediation wording, same meaning as Ensurer's
	// own field.
	Credential Credential
	// Principal is the identity automat is speaking as, for error text.
	Principal string

	actions []Action
}

// Actions returns every action produced so far, in order.
func (r *Reclaimer) Actions() []Action { return append([]Action(nil), r.actions...) }

func (r *Reclaimer) planning() bool { return r.Mode != ModeApply }

func (r *Reclaimer) record(a Action) *Action {
	r.actions = append(r.actions, a)
	return &r.actions[len(r.actions)-1]
}

// denied wraps an authorization failure with the remediation for this
// credential. Mirrors Ensurer.denied's shape; not shared by embedding, for
// the same reason the two types are not merged — a shared helper here would
// be the one seam through which Reclaimer's destructive calls could ride
// along on Ensurer's machinery.
func (r *Reclaimer) denied(err error, action, resource string) error {
	if err == nil || !awsapi.IsAccessDenied(err) {
		return err
	}
	var grant string
	if r.Credential == Brokered {
		grant = "ask the organization's management account to add " + action + " on " + resource +
			" to the vendor role this account assumes — the file is vendor-role.cfn.yaml (or " +
			"vendor-role.tf) in the onboarding bundle (`automat setup --request`); account closure " +
			"cannot be delegated to a member account and must travel through that role"
	} else {
		grant = "grant " + action + " on " + resource + " to " + principalOr(r.Principal, "the calling identity") +
			" in the management account; automat is running natively rather than through a broker, so " +
			"this is your own identity policy rather than a delegation somebody else owns"
	}
	return awsapi.Denied(err, action, resource, r.Principal, grant)
}

// DetachOwnedPolicies detaches every service control policy automat owns
// (carrying OwnerTagKey=OwnerTagValue) from target, and reports every policy
// found that is NOT automat's rather than silently skipping it — an operator
// running reclaim needs to know an institutional-floor policy is still
// attached to an account about to be closed, even though nothing here may
// touch it.
//
// Ownership is checked the identical way EnsurePolicyAttachment's own
// read-before-write does: ListPoliciesForTarget, then ListTagsForResource
// per candidate. Detach-then-close is docs/reclaim-design.md's own ordering
// decision: a failed close afterward leaves a known, resumable state (no
// automat SCPs, account otherwise intact) rather than an ambiguous one.
func (r *Reclaimer) DetachOwnedPolicies(ctx context.Context, target string) ([]*Action, error) {
	if target == "" {
		return nil, fmt.Errorf("cannot detach policies from an empty target")
	}
	attached, err := r.attachedPolicies(ctx, target)
	if err != nil {
		return nil, err
	}

	var out []*Action
	for _, p := range attached {
		owned, _, oerr := r.policyOwnership(ctx, p.id)
		if oerr != nil {
			return out, oerr
		}
		label := p.name
		if label == "" {
			label = p.id
		}
		if !owned {
			out = append(out, r.record(Action{
				Verb: VerbUnchanged, Kind: "service control policy", Name: label, ID: p.id, Target: target,
				Detail: "not automat's — left attached. This is the institution's own floor, not " +
					"automat's control, and reclaim never touches a policy it did not create",
			}))
			continue
		}
		if r.planning() {
			out = append(out, r.record(Action{
				Verb: VerbDetach, Kind: "service control policy", Name: label, ID: p.id, Target: target,
				Detail: "automat's — would be detached before the account closes",
			}))
			continue
		}
		_, derr := r.Policy.DetachPolicy(ctx, &organizations.DetachPolicyInput{
			PolicyId: aws.String(p.id), TargetId: aws.String(target),
		})
		switch {
		case derr == nil:
			out = append(out, r.record(Action{
				Verb: VerbDetach, Kind: "service control policy", Name: label, ID: p.id, Target: target,
				Detail: "detached", Applied: true,
			}))
		case isCode(derr, "PolicyNotAttachedException"):
			out = append(out, r.record(Action{
				Verb: VerbUnchanged, Kind: "service control policy", Name: label, ID: p.id, Target: target,
				Detail: "already detached: AWS reported no attachment, which happened between automat's " +
					"read and this detach",
			}))
		default:
			return out, r.denied(derr, "organizations:DetachPolicy", p.id)
		}
	}
	return out, nil
}

// CloseAccount closes accountID, or reports that it would.
//
// The remediation on a quota rejection names the actual AWS-documented limit
// (docs/reclaim-design.md: the higher of 250 or 20% of member accounts per
// rolling 30 days, up to 1,000) rather than a client-side guess, because no
// Service Quotas code exposes this rate for automat to check in advance.
func (r *Reclaimer) CloseAccount(ctx context.Context, accountID string) (*Action, error) {
	if accountID == "" {
		return nil, fmt.Errorf("cannot close an empty account id")
	}
	if r.planning() {
		return r.record(Action{
			Verb: VerbClose, Kind: "account", ID: accountID,
			Detail: "would be closed. AWS will hold it in SUSPENDED status for a 90-day grace window, " +
				"reinstatable by contacting AWS Support; after that it cannot be reopened",
		}), nil
	}

	_, err := r.Close.CloseAccount(ctx, &organizations.CloseAccountInput{
		AccountId: aws.String(accountID),
	})
	if err == nil {
		return r.record(Action{
			Verb: VerbClose, Kind: "account", ID: accountID,
			Detail: "close requested. AWS closes accounts asynchronously — it may report SUSPENDED " +
				"only after a few minutes", Applied: true,
		}), nil
	}

	var cv *orgtypes.ConstraintViolationException
	if errors.As(err, &cv) {
		switch cv.Reason {
		case orgtypes.ConstraintViolationExceptionReasonCloseAccountQuotaExceeded,
			orgtypes.ConstraintViolationExceptionReasonCloseAccountRequestsLimitExceeded:
			return nil, fmt.Errorf("cannot close account %s: AWS's closure rate limit was hit (the higher "+
				"of 250 or 20%% of member accounts per rolling 30 days, up to 1,000 — see \"Quotas for "+
				"Organizations\" in the AWS Organizations User Guide). This is not automat's limit and "+
				"there is no override; retry after the rolling window admits another closure: %w", accountID, err)
		case orgtypes.ConstraintViolationExceptionReasonCannotCloseManagementAccount:
			return nil, fmt.Errorf("cannot close account %s: it is the organization's management "+
				"account, which Organizations refuses to close through this API: %w", accountID, err)
		}
	}
	return nil, r.denied(err, "organizations:CloseAccount", accountID)
}

// attachedPolicies and policyOwnership mirror policy.go's own helpers of the
// same name exactly, against Reclaimer's narrower awsapi.OrgReclaimAPI rather
// than Ensurer's awsapi.OrgPolicyAPI. Not shared by extracting a common
// helper over a smaller interface both could accept: the two read methods
// are already declared twice, on two interfaces, for a documented reason
// (internal/awsapi's own OrgPolicyAPI/OrgReclaimAPI doc comments) — a shared
// implementation would want a shared interface parameter, undoing that
// separation for the sake of a few lines.
func (r *Reclaimer) attachedPolicies(ctx context.Context, target string) ([]attachedPolicy, error) {
	var out []attachedPolicy
	var token *string
	seen := map[string]bool{}
	for i := 0; i < listPageCap; i++ {
		page, err := r.Policy.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
			TargetId:  aws.String(target),
			Filter:    orgtypes.PolicyTypeServiceControlPolicy,
			NextToken: token,
		})
		if err != nil {
			return nil, r.denied(err, "organizations:ListPoliciesForTarget", target)
		}
		for _, p := range page.Policies {
			out = append(out, attachedPolicy{id: aws.ToString(p.Id), name: aws.ToString(p.Name)})
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			return out, nil
		}
		if seen[aws.ToString(page.NextToken)] {
			return nil, fmt.Errorf("listing policies attached to %s: the same pagination token came back "+
				"twice, so the list does not terminate; automat stopped rather than looping", target)
		}
		seen[aws.ToString(page.NextToken)] = true
		token = page.NextToken
	}
	return nil, fmt.Errorf("listing policies attached to %s: stopped after %d pages without reaching the "+
		"end of the list", target, listPageCap)
}

func (r *Reclaimer) policyOwnership(ctx context.Context, policyID string) (bool, map[string]string, error) {
	tags := map[string]string{}
	var token *string
	seen := map[string]bool{}
	for i := 0; i < listPageCap; i++ {
		out, err := r.Policy.ListTagsForResource(ctx, &organizations.ListTagsForResourceInput{
			ResourceId: aws.String(policyID), NextToken: token,
		})
		if err != nil {
			return false, nil, r.denied(err, "organizations:ListTagsForResource", policyID)
		}
		for _, t := range out.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		if seen[aws.ToString(out.NextToken)] {
			return false, nil, fmt.Errorf("listing tags on %s: the same pagination token came back twice, "+
				"so the list does not terminate; automat stopped rather than looping", policyID)
		}
		seen[aws.ToString(out.NextToken)] = true
		token = out.NextToken
	}
	return tags[OwnerTagKey] == OwnerTagValue, tags, nil
}
