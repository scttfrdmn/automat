// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// PolicySpec is one service control policy a vend wants attached.
type PolicySpec struct {
	// Name is the policy name, and it is the only handle automat has on its own
	// policy across runs. DESIGN §14 fixes the convention:
	// automat-<environment-profile-id>-<n>, an ordinal over the packed policy set
	// rather than one name per artifact or class — a packed policy has no single
	// artifact id or class to name (Q16, docs/open-questions.md). Organizations
	// enforces name uniqueness, which is what makes a name usable as a key at all.
	Name string
	// Document is the rendered policy, normally from internal/compilesets.Pack.
	Document string
	// Description is optional prose stored on the policy.
	Description string
	// Tags are applied at creation alongside the owner tag, and ensured after.
	// Keys must be inside automat's namespace.
	Tags map[string]string
}

// EnsurePolicy makes a policy with the spec's name exist and carry the spec's
// document, and returns its id.
//
// Three refusals worth stating, because each is a place this could have been
// written to do something quietly dangerous instead:
//
//   - A policy with the right name but WITHOUT automat's owner tag is not
//     adopted. It is a hard error. Tagging it would be automat taking ownership
//     of a document somebody else wrote, and the tag is exactly what the
//     delegation policy reads to decide who may rewrite an SCP
//     (internal/bundle's scpTagActions) — so adopting by tagging is the
//     privilege escalation AUDIT-1's C1 was about, performed by automat on its
//     own behalf.
//   - A tagged policy whose document differs IS updated, because that is the
//     ensure operation working: the compiled artifact is the desired state.
//   - The comparison is structural rather than byte-for-byte (see
//     sameDocument), so a service-side reformat does not produce an
//     UpdatePolicy on every run and fail the run-twice criterion.
func (e *Ensurer) EnsurePolicy(ctx context.Context, spec PolicySpec) (string, *Action, error) {
	if err := spec.validate(); err != nil {
		return "", nil, err
	}

	id, err := e.findPolicy(ctx, spec.Name)
	if err != nil {
		return "", nil, err
	}

	if id == "" {
		if e.planning() {
			return "", e.record(Action{
				Verb: VerbCreate, Kind: "service control policy", Name: spec.Name,
				Detail: fmt.Sprintf("would be created, %d characters, tagged %s=%s; the id is assigned "+
					"by AWS at creation and cannot be predicted",
					len(spec.Document), OwnerTagKey, OwnerTagValue),
			}), nil
		}
		return e.createPolicy(ctx, spec)
	}

	// Found by name. Ownership before content: an untagged policy is not
	// automat's to read a diff against, let alone to rewrite.
	owned, tags, err := e.policyOwnership(ctx, id)
	if err != nil {
		return "", nil, err
	}
	if !owned {
		return "", nil, fmt.Errorf("a service control policy named %q already exists (%s) and does not "+
			"carry %s=%s, so automat did not create it and will not modify it. Service control policy "+
			"names are unique per organization, so this name is taken. automat deliberately does not tag "+
			"the policy to claim it: that tag is what the delegation policy reads to decide who may "+
			"rewrite an SCP, so applying it to a document automat did not write would grant automat "+
			"control over somebody else's policy. Either rename the existing policy, or vend against an "+
			"artifact whose id produces a different policy name",
			spec.Name, id, OwnerTagKey, OwnerTagValue)
	}

	current, err := e.policyDocument(ctx, id)
	if err != nil {
		return "", nil, err
	}
	if sameDocument(current, spec.Document) {
		act, terr := e.ensurePolicyTags(ctx, id, spec, tags)
		if terr != nil {
			return "", nil, terr
		}
		if act != nil {
			return id, act, nil
		}
		return id, e.record(Action{
			Verb: VerbUnchanged, Kind: "service control policy", Name: spec.Name, ID: id,
			Detail: "content already matches the compiled artifact",
		}), nil
	}

	if e.planning() {
		return id, e.record(Action{
			Verb: VerbUpdate, Kind: "service control policy", Name: spec.Name, ID: id,
			Detail: fmt.Sprintf("content differs from the compiled artifact (%d characters attached, "+
				"%d compiled) and would be replaced", len(current), len(spec.Document)),
		}), nil
	}

	if _, err := e.Policy.UpdatePolicy(ctx, &organizations.UpdatePolicyInput{
		PolicyId: aws.String(id),
		Content:  aws.String(spec.Document),
		// Name is deliberately not sent. The policy was found BY name, so
		// resending it is a no-op at best; at worst a future refactor turns this
		// into a rename, and a renamed policy is one no later run can find.
		Description: descriptionOrNil(spec.Description),
	}); err != nil {
		if isCode(err, "MalformedPolicyDocumentException") {
			return "", nil, e.malformed(err, spec, id)
		}
		return "", nil, e.denied(err, "organizations:UpdatePolicy", id)
	}
	act := e.record(Action{
		Verb: VerbUpdate, Kind: "service control policy", Name: spec.Name, ID: id,
		Detail: "content replaced to match the compiled artifact", Applied: true,
	})
	if _, terr := e.ensurePolicyTags(ctx, id, spec, tags); terr != nil {
		return "", nil, terr
	}
	return id, act, nil
}

func (e *Ensurer) createPolicy(ctx context.Context, spec PolicySpec) (string, *Action, error) {
	want := map[string]string{OwnerTagKey: OwnerTagValue}
	for k, v := range spec.Tags {
		want[k] = v
	}
	out, err := e.Policy.CreatePolicy(ctx, &organizations.CreatePolicyInput{
		Name:        aws.String(spec.Name),
		Content:     aws.String(spec.Document),
		Description: aws.String(spec.Description),
		Type:        orgtypes.PolicyTypeServiceControlPolicy,
		// The owner tag is applied AT CREATION, through the request tag, and this
		// is the only moment it can be: the delegation policy gates every later
		// tag write on the tag already being present (internal/bundle's
		// scpTagActions). A policy created without it could never acquire it.
		Tags: tagList(want),
	})
	switch {
	case err == nil:
		id := aws.ToString(out.Policy.PolicySummary.Id)
		return id, e.record(Action{
			Verb: VerbCreate, Kind: "service control policy", Name: spec.Name, ID: id,
			Detail: fmt.Sprintf("created, %d characters, tagged %s=%s",
				len(spec.Document), OwnerTagKey, OwnerTagValue),
			Applied: true,
		}), nil
	case isCode(err, "DuplicatePolicyException"):
		// Created between the read and the write. Re-read, and apply the same
		// ownership rule: a policy that appeared under this name in the last
		// moment is no more automat's than one that was there all along.
		id, ferr := e.findPolicy(ctx, spec.Name)
		if ferr != nil {
			return "", nil, ferr
		}
		if id == "" {
			return "", nil, fmt.Errorf("cannot create service control policy %q: AWS reports a policy "+
				"with that name already exists, but automat cannot see one — the credential may not be "+
				"permitted to list it. Check the organization's policies before re-running", spec.Name)
		}
		owned, _, oerr := e.policyOwnership(ctx, id)
		if oerr != nil {
			return "", nil, oerr
		}
		if !owned {
			return "", nil, fmt.Errorf("cannot create service control policy %q: a policy with that name "+
				"appeared between automat's read and its create (%s) and does not carry %s=%s. automat "+
				"will not modify or adopt it; see the note on ownership in EnsurePolicy",
				spec.Name, id, OwnerTagKey, OwnerTagValue)
		}
		return id, e.record(Action{
			Verb: VerbUnchanged, Kind: "service control policy", Name: spec.Name, ID: id,
			Detail: "created concurrently by another caller between automat's read and its create; " +
				"adopted rather than duplicated",
		}), nil
	case isCode(err, "MalformedPolicyDocumentException"):
		return "", nil, e.malformed(err, spec, "")
	default:
		return "", nil, e.denied(err, "organizations:CreatePolicy", "a new service control policy")
	}
}

// malformed is the MalformedPolicyDocument path, and it gets its own function
// because of when it happens.
//
// ROADMAP Phase 2 names it: this arrives at CreatePolicy or UpdatePolicy in step
// 4, AFTER the account exists and has been moved. It is a resumable parked state
// rather than a fatal error (Parkable reports true for it), and the message has
// to tell an operator that — otherwise the natural response to a failed vend is
// to run `vend` again, which creates a second account.
//
// The cause is nearly always in the compiled artifact rather than in the
// organization: a duplicate Sid within a document is one path, which is why
// gen/catalog/baseline.go refuses duplicate Sids at compile time.
func (e *Ensurer) malformed(err error, spec PolicySpec, id string) error {
	where := "creating"
	if id != "" {
		where = "updating " + id + ","
	}
	return fmt.Errorf("AWS rejected the document for service control policy %q while %s as malformed: %w. "+
		"The document comes from the compiled artifact, so the fault is there rather than in the "+
		"organization — a duplicate Sid within one document is the usual cause. Recompile the "+
		"catalog with `go run ./gen/catalog -check` and re-run the vend with --resume: if the "+
		"account was already created, it exists and is parked, and running `vend` again from the "+
		"top would create a second one",
		spec.Name, where, err)
}

// EnsurePolicyAttachment attaches a policy to a target, or confirms it is already
// attached.
//
// Reads ListPoliciesForTarget first and tolerates DuplicatePolicyAttachment,
// which is the same both-halves discipline as the move: the read is how a re-run
// writes nothing, and the tolerance covers the window between the read and the
// attach.
//
// # Ordering
//
// The caller must have finished with the child account's IAM before attaching a
// baseline-protection policy. BP.IAM-1 denies iam:Put*/Attach*/Update* on the
// automation role with no exemption, automat's own included and deliberately so
// (docs/open-questions.md Q13) — so an attach that runs first turns automat's own
// control into what looks like a missing grant. This function cannot enforce the
// ordering, because it cannot see the child account; `vend` orders the steps and
// the vend tests hold it.
func (e *Ensurer) EnsurePolicyAttachment(ctx context.Context, policyID, policyName, target string) (*Action, error) {
	switch {
	case policyID == "":
		return nil, fmt.Errorf("cannot attach a service control policy to %s: no policy id was given. "+
			"In a plan this means the policy does not exist yet, and the caller should report the "+
			"attachment as unknown rather than call this", target)
	case target == "":
		return nil, fmt.Errorf("cannot attach service control policy %s: no target was given", policyID)
	}

	attached, err := e.policyAttached(ctx, target, policyID)
	if err != nil {
		return nil, err
	}
	if attached {
		return e.record(Action{
			Verb: VerbUnchanged, Kind: "policy attachment", Name: policyName, ID: policyID, Target: target,
			Detail: "already attached to " + target,
		}), nil
	}
	if e.planning() {
		return e.record(Action{
			Verb: VerbAttach, Kind: "policy attachment", Name: policyName, ID: policyID, Target: target,
			Detail: "would be attached to " + target,
		}), nil
	}

	_, err = e.Policy.AttachPolicy(ctx, &organizations.AttachPolicyInput{
		PolicyId: aws.String(policyID),
		TargetId: aws.String(target),
	})
	switch {
	case err == nil:
		return e.record(Action{
			Verb: VerbAttach, Kind: "policy attachment", Name: policyName, ID: policyID, Target: target,
			Detail: "attached to " + target, Applied: true,
		}), nil
	case isCode(err, "DuplicatePolicyAttachmentException"):
		return e.record(Action{
			Verb: VerbUnchanged, Kind: "policy attachment", Name: policyName, ID: policyID, Target: target,
			Detail: "already attached: AWS reported the attachment exists, which happened between " +
				"automat's read and this attach",
		}), nil
	case isCode(err, "PolicyTypeNotEnabledException"):
		// The dangerous one, and the reason it is not simply "enable it": the org
		// can be in ALL features mode with the SCP policy type disabled on the
		// root, in which case creating and attaching policies both work and
		// nothing is enforced. Here AWS did refuse, which is the good case.
		return nil, fmt.Errorf("cannot attach service control policy %s to %s: the service control "+
			"policy type is not enabled on this organization's root. Until it is, no preventive control "+
			"in any catalog does anything. The management account enables it once, from the "+
			"Organizations console or with organizations:EnablePolicyType on the root — `automat init` "+
			"does it for an organization automat creates. The account, if this vend created one, exists "+
			"and is parked; re-run with --resume once the policy type is enabled: %w",
			policyID, target, err)
	default:
		var cv *orgtypes.ConstraintViolationException
		if errors.As(err, &cv) &&
			cv.Reason == orgtypes.ConstraintViolationExceptionReasonMaxPolicyTypeAttachmentLimitExceeded {
			return nil, e.attachmentQuota(ctx, policyID, policyName, target, err)
		}
		return nil, e.denied(err, "organizations:AttachPolicy", target)
	}
}

// attachmentQuota renders the five-per-target limit with the current occupants
// listed.
//
// The count is the whole remediation: AWS's message says the limit was exceeded
// and never says by what, and the operator's options — attach at a parent OU, or
// compile fewer sets — depend entirely on which of the five slots are taken and
// by whom. A policy that is not automat's is central IT's institutional floor,
// which is the one thing here nobody should be advised to detach.
func (e *Ensurer) attachmentQuota(ctx context.Context, policyID, policyName, target string, cause error) error {
	names, lerr := e.attachedNames(ctx, target)
	var occupants string
	if lerr == nil && len(names) > 0 {
		occupants = " Attached now: " + strings.Join(names, ", ") + "."
	}
	return fmt.Errorf("cannot attach service control policy %q (%s) to %s: the target already holds the "+
		"maximum number of service control policies AWS permits (%d, one of which is FullAWSAccess).%s "+
		"Policies attached at a PARENT OU are inherited without consuming this target's slots, so the "+
		"remedy is either to attach the overflow above this OU or to compile fewer control sets into one "+
		"artifact. Do not detach a policy automat did not create: an SCP it does not own is the "+
		"institution's own floor, and removing it widens permissions for everything below. If this vend "+
		"created an account, it exists and is parked — re-run with --resume after making room: %w",
		policyName, policyID, target, maxPoliciesPerTarget, occupants, cause)
}

// maxPoliciesPerTarget is AWS's limit. internal/compilesets has the same number
// for its own budgeting; it is repeated rather than imported because this package
// uses it only for an error message and importing the packer to render one
// sentence would make the org layer depend on the compile layer.
const maxPoliciesPerTarget = 5

// EnsureSCPEnabled turns the service control policy type on for the root.
//
// `automat init` only, and it is the call that makes DESIGN §3 fact 8 true in
// practice. The trap it closes: a freshly created organization is in ALL features
// mode with the SCP policy type DISABLED, so CreatePolicy succeeds, AttachPolicy
// succeeds, and nothing is enforced. Everything reports fine and no control is
// live, which is the failure that reaches production.
//
// PolicyTypeAlreadyEnabledException is success — AWS's usual shape for an
// idempotent call it does not implement idempotently.
//
// read is the organization read client, and it may be nil. Given one, this reads
// the root's current status first, which is the same read-then-write discipline
// every other operation in this package follows and it is not merely cosmetic here:
// without it the second run of `init` issues an EnablePolicyType it knows will be
// refused, so "run twice writes nothing" is false at the API even though the
// organization is unchanged. Tolerating the already-enabled error stays, because it
// is still the outcome when the status changes between the read and the write.
//
// With no read client the write is attempted blind, which is safe — the write is
// idempotent in effect, if not in return value — but it cannot report the status a
// plan wants, and PENDING_ENABLE is the case that makes the read worth doing: the
// status is neither on nor off, EnablePolicyType against it errors, and an
// unconditional write would report that as a failure of the command rather than as
// AWS still deciding.
func (e *Ensurer) EnsureSCPEnabled(ctx context.Context, rootID string, read awsapi.OrgAPI) (*Action, error) {
	if e.Init == nil {
		return nil, fmt.Errorf("cannot enable the service control policy type: this Ensurer has no " +
			"organization-init client. Only `automat init` enables a policy type, and it is the only " +
			"command that should hold that capability")
	}
	if rootID == "" {
		return nil, fmt.Errorf("cannot enable the service control policy type: no root id was given")
	}

	// Read first when there is something to read with.
	if read != nil {
		on, err := SCPEnabled(ctx, read)
		if err != nil {
			return nil, e.denied(err, "organizations:ListRoots", "root "+rootID)
		}
		if on {
			return e.record(Action{
				Verb: VerbUnchanged, Kind: "service control policy type", Target: rootID,
				Detail: "already enabled on the root",
			}), nil
		}
	}

	if e.planning() {
		detail := "would be enabled on the root; until this is on, an attached policy enforces nothing"
		if read == nil {
			detail = "would be enabled on the root if it is not already; automat cannot tell which " +
				"without a read client, and ListRoots is not on the init client's interface"
		}
		return e.record(Action{
			Verb: VerbEnable, Kind: "service control policy type", Target: rootID, Detail: detail,
		}), nil
	}

	_, err := e.Init.EnablePolicyType(ctx, &organizations.EnablePolicyTypeInput{
		RootId:     aws.String(rootID),
		PolicyType: orgtypes.PolicyTypeServiceControlPolicy,
	})
	switch {
	case err == nil:
		return e.record(Action{
			Verb: VerbEnable, Kind: "service control policy type", Target: rootID,
			Detail:  "enabled on the root; until this is on, an attached policy enforces nothing",
			Applied: true,
		}), nil
	case isCode(err, "PolicyTypeAlreadyEnabledException"):
		detail := "already enabled on the root"
		if read != nil {
			// The read said otherwise moments ago, so somebody else enabled it in the
			// window. Worth distinguishing in the record: both runs wanted the same
			// end state, and the operator reading the manifest should not conclude
			// that automat's own read was wrong.
			detail = "enabled by another caller between automat's read and this call; " +
				"adopted rather than treated as a failure"
		}
		return e.record(Action{
			Verb: VerbUnchanged, Kind: "service control policy type", Target: rootID,
			Detail: detail,
		}), nil
	default:
		return nil, e.denied(err, "organizations:EnablePolicyType", rootID)
	}
}

// findPolicy returns the id of the service control policy named name, or "".
//
// Paginated, and filtered to SERVICE_CONTROL_POLICY: the same name can exist for
// a tag policy and an SCP, and a match on the wrong type would send an
// UpdatePolicy at a document that is not a policy automat understands.
func (e *Ensurer) findPolicy(ctx context.Context, name string) (string, error) {
	var token *string
	seen := map[string]bool{}
	for i := 0; i < listPageCap; i++ {
		out, err := e.Policy.ListPolicies(ctx, &organizations.ListPoliciesInput{
			Filter:    orgtypes.PolicyTypeServiceControlPolicy,
			NextToken: token,
		})
		if err != nil {
			return "", e.denied(err, "organizations:ListPolicies", "the organization's policies")
		}
		for _, p := range out.Policies {
			if aws.ToString(p.Name) == name {
				return aws.ToString(p.Id), nil
			}
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			return "", nil
		}
		if seen[aws.ToString(out.NextToken)] {
			return "", fmt.Errorf("listing service control policies: the same pagination token came back " +
				"twice, so the list does not terminate; automat stopped rather than looping")
		}
		seen[aws.ToString(out.NextToken)] = true
		token = out.NextToken
	}
	return "", fmt.Errorf("listing service control policies: stopped after %d pages without reaching the "+
		"end of the list", listPageCap)
}

// policyOwnership reports whether the policy carries automat's owner tag, and
// returns its tags.
//
// A read failure is NOT treated as "not owned": that would turn a missing
// ListTagsForResource grant into "somebody else owns this policy", which is a
// confident false statement about the organization. It is an error naming the
// grant instead.
func (e *Ensurer) policyOwnership(ctx context.Context, policyID string) (bool, map[string]string, error) {
	tags := map[string]string{}
	var token *string
	seen := map[string]bool{}
	for i := 0; i < listPageCap; i++ {
		out, err := e.Policy.ListTagsForResource(ctx, &organizations.ListTagsForResourceInput{
			ResourceId: aws.String(policyID), NextToken: token,
		})
		if err != nil {
			return false, nil, e.denied(err, "organizations:ListTagsForResource", policyID)
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

// ensurePolicyTags writes the spec's tags when they are absent or differ, and
// returns nil when nothing was needed.
//
// Only keys the spec names are compared. A tag automat did not ask for is left
// alone: the cost-allocation keys of DESIGN §14 are the operator's to set, and an
// ensure operation that removed unrecognized tags would delete an institution's
// chargeback labels on every vend.
func (e *Ensurer) ensurePolicyTags(ctx context.Context, policyID string, spec PolicySpec,
	current map[string]string) (*Action, error) {
	missing := map[string]string{}
	for k, v := range spec.Tags {
		if current[k] != v {
			missing[k] = v
		}
	}
	if current[OwnerTagKey] != OwnerTagValue {
		// Unreachable: the caller checked ownership before getting here. Left in
		// because if it ever becomes reachable, silently tagging is the outcome
		// that must not happen.
		return nil, fmt.Errorf("refusing to tag service control policy %s: it does not carry %s=%s, and "+
			"applying that tag would claim a policy automat did not create", policyID, OwnerTagKey, OwnerTagValue)
	}
	if len(missing) == 0 {
		return nil, nil
	}
	if e.planning() {
		return e.record(Action{
			Verb: VerbTag, Kind: "service control policy", Name: spec.Name, ID: policyID,
			Detail: "tags would be written: " + renderTags(missing),
		}), nil
	}
	if _, err := e.Policy.TagResource(ctx, &organizations.TagResourceInput{
		ResourceId: aws.String(policyID), Tags: tagList(missing),
	}); err != nil {
		return nil, e.denied(err, "organizations:TagResource", policyID)
	}
	return e.record(Action{
		Verb: VerbTag, Kind: "service control policy", Name: spec.Name, ID: policyID,
		Detail: "tags written: " + renderTags(missing), Applied: true,
	}), nil
}

// policyDocument reads a policy's current content.
func (e *Ensurer) policyDocument(ctx context.Context, policyID string) (string, error) {
	out, err := e.Policy.DescribePolicy(ctx, &organizations.DescribePolicyInput{
		PolicyId: aws.String(policyID),
	})
	if err != nil {
		return "", e.denied(err, "organizations:DescribePolicy", policyID)
	}
	if out.Policy == nil {
		return "", fmt.Errorf("describing service control policy %s: AWS returned no policy and no error",
			policyID)
	}
	return aws.ToString(out.Policy.Content), nil
}

// policyAttached reports whether policyID is attached to target.
func (e *Ensurer) policyAttached(ctx context.Context, target, policyID string) (bool, error) {
	ids, err := e.attachedPolicies(ctx, target)
	if err != nil {
		return false, err
	}
	for _, p := range ids {
		if p.id == policyID {
			return true, nil
		}
	}
	return false, nil
}

type attachedPolicy struct{ id, name string }

// attachedPolicies lists the SCPs attached to a target, paginated.
//
// The pagination matters more here than anywhere else in this package: a caller
// that read only the first page would conclude a policy is not attached, call
// AttachPolicy, and get DuplicatePolicyAttachment — which this package tolerates,
// so the bug would be invisible except as a target quietly one slot closer to the
// five-policy limit than the plan said.
func (e *Ensurer) attachedPolicies(ctx context.Context, target string) ([]attachedPolicy, error) {
	var out []attachedPolicy
	var token *string
	seen := map[string]bool{}
	for i := 0; i < listPageCap; i++ {
		page, err := e.Policy.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
			TargetId:  aws.String(target),
			Filter:    orgtypes.PolicyTypeServiceControlPolicy,
			NextToken: token,
		})
		switch {
		case err == nil:
		case isCode(err, "TargetNotFoundException"):
			return nil, fmt.Errorf("cannot list the service control policies on %s: no root, OU, or "+
				"account with that id exists in this organization", target)
		default:
			return nil, e.denied(err, "organizations:ListPoliciesForTarget", target)
		}
		for _, p := range page.Policies {
			out = append(out, attachedPolicy{id: aws.ToString(p.Id), name: aws.ToString(p.Name)})
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			return out, nil
		}
		if seen[aws.ToString(page.NextToken)] {
			return nil, fmt.Errorf("listing the service control policies on %s: the same pagination token "+
				"came back twice, so the list does not terminate; automat stopped rather than looping",
				target)
		}
		seen[aws.ToString(page.NextToken)] = true
		token = page.NextToken
	}
	return nil, fmt.Errorf("listing the service control policies on %s: stopped after %d pages without "+
		"reaching the end of the list", target, listPageCap)
}

// attachedNames renders the attached policies for the quota error, marking which
// are not automat's — because those are the ones nobody should be advised to
// remove.
func (e *Ensurer) attachedNames(ctx context.Context, target string) ([]string, error) {
	ps, err := e.attachedPolicies(ctx, target)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		label := p.name
		if label == "" {
			label = p.id
		}
		owned, _, oerr := e.policyOwnership(ctx, p.id)
		switch {
		case oerr != nil:
			// Do not fail the quota message over a tag read. An unlabeled entry
			// is better than no list at all.
		case owned:
			label += " (automat's)"
		default:
			label += " (not automat's)"
		}
		out = append(out, label)
	}
	return out, nil
}

func (spec PolicySpec) validate() error {
	switch {
	case spec.Name == "":
		return fmt.Errorf("cannot ensure a service control policy with no name: the name is the only " +
			"handle automat has on its own policy between runs, since a policy id is assigned at " +
			"creation and there is no state file")
	case len(spec.Name) > 128:
		return fmt.Errorf("service control policy name is %d characters; AWS permits 128", len(spec.Name))
	case spec.Document == "":
		return fmt.Errorf("cannot ensure service control policy %q with an empty document", spec.Name)
	}
	if _, ok := canonicalizeDocument(spec.Document); !ok {
		return fmt.Errorf("cannot ensure service control policy %q: the document is not valid JSON. It "+
			"comes from the compiled artifact, so this is a bug in automat's packer rather than "+
			"something a catalog can cause; report it rather than editing the policy by hand", spec.Name)
	}
	for k := range spec.Tags {
		if k == OwnerTagKey {
			// Not an error to state the owner tag, but it must not be given a
			// different value: everything downstream reads it as a boolean.
			if spec.Tags[k] != OwnerTagValue {
				return fmt.Errorf("cannot ensure service control policy %q: tag %q is set to %q, and "+
					"automat's own tag must be %q — the delegation policy reads that exact value to "+
					"decide which policies automat may modify",
					spec.Name, k, spec.Tags[k], OwnerTagValue)
			}
			continue
		}
		if !strings.HasPrefix(k, tagNamespace) {
			return fmt.Errorf("cannot ensure service control policy %q: tag key %q is outside automat's "+
				"%q namespace, which the delegation policy bounds with aws:TagKeys — AWS would refuse it "+
				"in the MEMBER state, so automat refuses it in both", spec.Name, k, tagNamespace)
		}
	}
	return nil
}

func descriptionOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return aws.String(s)
}

func renderTags(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for _, t := range tagList(m) {
		parts = append(parts, aws.ToString(t.Key)+"="+aws.ToString(t.Value))
	}
	return strings.Join(parts, ", ")
}
