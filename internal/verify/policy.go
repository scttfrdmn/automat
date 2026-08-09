// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/compilesets"
	"github.com/scttfrdmn/automat/internal/org"
)

// listPageCap bounds every pagination loop, matching internal/org's own cap —
// not a quota, a stop against a service or fake that never terminates.
const listPageCap = 500

// PolicyStatus is one attached-vs-expected comparison for a single policy name.
type PolicyStatus struct {
	// Name is the policy name automat would ensure — the same
	// automat-<profile-id>-<n> convention org.PolicySpec.Name documents.
	Name string
	// Attached reports whether a policy of this name is attached to the target
	// at all.
	Attached bool
	// Matches reports whether the attached document is structurally the same as
	// the freshly compiled one (org.SameDocument). Meaningless when Attached is
	// false.
	Matches bool
	// PolicyID is the attached policy's id, empty when Attached is false.
	PolicyID string
	// Owned reports whether the attached policy carries automat's owner tag.
	// A policy present under the right name but NOT owned is not drift automat
	// caused — it is a name collision with something else, and the report says
	// so rather than calling it a mismatch.
	Owned bool
}

// PolicyReport is CheckPolicy's result: what a fresh compile expects at a
// target, and what is actually attached.
type PolicyReport struct {
	// Target is the OU or account id the attached policies were read from.
	Target string
	// Expected is one entry per policy the compile produced, in compile order.
	Expected []PolicyStatus
	// Orphans are automat-owned policies attached to the target that are not
	// named by the current compile — the same leftover org.EnsurePolicySet
	// reports and cannot remove, because no write interface holds DetachPolicy.
	// A narrowed artifact leaves a previous vend's policies in force, which is
	// the safe direction (strictly more restrictive), but it is drift worth
	// naming.
	Orphans []string
}

// Clean reports whether every expected policy is attached and matches, with no
// orphans. The one-line answer a cron job's exit code is built from.
func (r *PolicyReport) Clean() bool {
	if len(r.Orphans) > 0 {
		return false
	}
	for _, s := range r.Expected {
		if !s.Attached || !s.Matches {
			return false
		}
	}
	return true
}

// CheckPolicy compares what packed says should be attached at target against
// what awsapi.OrgVerifyAPI reports is actually there.
//
// Read-only: the interface carries no write method, so nothing this function
// does can change target's attached policies no matter what it finds.
func CheckPolicy(ctx context.Context, api awsapi.OrgVerifyAPI, target string, packed *compilesets.Packed) (*PolicyReport, error) {
	if target == "" {
		return nil, fmt.Errorf("cannot check policies: no target was given")
	}

	attached, err := attachedPolicies(ctx, api, target)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]attachedPolicy, len(attached))
	for _, p := range attached {
		byName[p.name] = p
	}

	report := &PolicyReport{Target: target, Expected: make([]PolicyStatus, 0, len(packed.Policies))}
	want := make(map[string]bool, len(packed.Policies))
	for _, pol := range packed.Policies {
		want[pol.Name] = true
		status := PolicyStatus{Name: pol.Name}
		if p, ok := byName[pol.Name]; ok {
			status.Attached = true
			status.PolicyID = p.id
			owned, doc, oerr := policyOwnershipAndContent(ctx, api, p.id)
			if oerr != nil {
				return nil, oerr
			}
			status.Owned = owned
			status.Matches = owned && org.SameDocument(doc, pol.Document)
		}
		report.Expected = append(report.Expected, status)
	}

	report.Orphans, err = orphanedPolicies(ctx, api, attached, want)
	if err != nil {
		return nil, err
	}
	return report, nil
}

type attachedPolicy struct{ id, name string }

// attachedPolicies lists the SCPs attached to target, paginated — the
// read-only twin of internal/org's own attachedPolicies, over the narrower
// interface.
func attachedPolicies(ctx context.Context, api awsapi.OrgVerifyAPI, target string) ([]attachedPolicy, error) {
	var out []attachedPolicy
	var token *string
	seen := map[string]bool{}
	for i := 0; i < listPageCap; i++ {
		page, err := api.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
			TargetId:  aws.String(target),
			Filter:    orgtypes.PolicyTypeServiceControlPolicy,
			NextToken: token,
		})
		switch {
		case err == nil:
		case awsapi.APIErrorCode(err) == "TargetNotFoundException":
			return nil, fmt.Errorf("cannot list the service control policies on %s: no root, OU, or "+
				"account with that id exists in this organization", target)
		default:
			return nil, denied(err, "organizations:ListPoliciesForTarget", target)
		}
		for _, p := range page.Policies {
			out = append(out, attachedPolicy{id: aws.ToString(p.Id), name: aws.ToString(p.Name)})
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			return out, nil
		}
		if seen[aws.ToString(page.NextToken)] {
			return nil, fmt.Errorf("listing the service control policies on %s: the same pagination token "+
				"came back twice, so the list does not terminate; automat stopped rather than looping", target)
		}
		seen[aws.ToString(page.NextToken)] = true
		token = page.NextToken
	}
	return nil, fmt.Errorf("listing the service control policies on %s: stopped after %d pages without "+
		"reaching the end of the list", target, listPageCap)
}

// policyOwnershipAndContent reads a policy's owner tag and content in one
// place, since CheckPolicy needs both and a caller reading them separately
// would make two round trips where one suffices in practice — though this
// still issues two calls (DescribePolicy has no tag field), it keeps them
// adjacent rather than scattering the pagination twice across the file.
func policyOwnershipAndContent(ctx context.Context, api awsapi.OrgVerifyAPI, policyID string) (owned bool, document string, err error) {
	out, err := api.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: aws.String(policyID)})
	if err != nil {
		return false, "", denied(err, "organizations:DescribePolicy", policyID)
	}
	if out.Policy == nil {
		return false, "", fmt.Errorf("describing service control policy %s: AWS returned no policy and no error",
			policyID)
	}
	document = aws.ToString(out.Policy.Content)

	tags, terr := allTags(ctx, api, policyID)
	if terr != nil {
		return false, "", terr
	}
	return tags[org.OwnerTagKey] == org.OwnerTagValue, document, nil
}

// allTags reads every tag on a resource, paginated.
func allTags(ctx context.Context, api awsapi.OrgVerifyAPI, resourceID string) (map[string]string, error) {
	tags := map[string]string{}
	var token *string
	seen := map[string]bool{}
	for i := 0; i < listPageCap; i++ {
		out, err := api.ListTagsForResource(ctx, &organizations.ListTagsForResourceInput{
			ResourceId: aws.String(resourceID), NextToken: token,
		})
		if err != nil {
			return nil, denied(err, "organizations:ListTagsForResource", resourceID)
		}
		for _, t := range out.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			return tags, nil
		}
		if seen[aws.ToString(out.NextToken)] {
			return nil, fmt.Errorf("listing tags on %s: the same pagination token came back twice, "+
				"so the list does not terminate; automat stopped rather than looping", resourceID)
		}
		seen[aws.ToString(out.NextToken)] = true
		token = out.NextToken
	}
	return nil, fmt.Errorf("listing tags on %s: stopped after %d pages without reaching the end of the list",
		resourceID, listPageCap)
}

// orphanedPolicies names automat-owned policies attached to target that are
// not in want — the same leftover org.EnsurePolicySet's own orphan check
// reports, read back independently here because verify may run long after the
// vend that left them and must not assume its own in-memory spec set.
func orphanedPolicies(ctx context.Context, api awsapi.OrgVerifyAPI, attached []attachedPolicy, want map[string]bool) ([]string, error) {
	var out []string
	for _, p := range attached {
		if want[p.name] {
			continue
		}
		owned, _, err := policyOwnershipAndContent(ctx, api, p.id)
		if err != nil || !owned {
			// Not automat's, or unreadable. Not something to report as automat's
			// leftover: a policy that merely exists is not automat's problem to
			// name, and an unreadable tag must not be reported as ownership either
			// way.
			continue
		}
		out = append(out, fmt.Sprintf("%s (%s)", p.name, p.id))
	}
	sort.Strings(out)
	return out, nil
}

// denied wraps an authorization failure with the remediation this package can
// state without knowing whether it is running natively or through a broker.
//
// Deliberately generic rather than Native/Brokered-branched the way
// org.Ensurer.denied is: that branch exists for WRITE actions, where the fix
// differs completely between "edit your own identity policy" and "ask
// management to widen the vendor role or the delegation policy" (DESIGN §5).
// A read denial has no such split to make — internal/bundle's delegation
// policy already grants DescribePolicy, ListPoliciesForTarget, and
// ListTagsForResource to the delegated identity (the same three this package
// calls), so a MEMBER-state denial here almost always means the delegation
// was scoped to a narrower OU subtree than the target being checked, not that
// a different instrument needs a new grant — which one sentence can say
// either way. This mirrors internal/preflight's own read-denial remediations
// (checkDelegationVisibility, checkTargetOU), which are single generic
// sentences for the same reason.
func denied(err error, action, resource string) error {
	if err == nil || !awsapi.IsAccessDenied(err) {
		return err
	}
	grant := "grant " + action + " on " + resource + " to the identity running verify — in the " +
		"management account this is your own identity policy; in a member account it is the " +
		"delegation policy the management account applied (delegation-policy.json in the onboarding " +
		"bundle), most likely because it is scoped to a narrower OU subtree than " + resource
	return awsapi.Denied(err, action, resource, "", grant)
}
