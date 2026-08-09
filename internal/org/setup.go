// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"

	"github.com/scttfrdmn/automat/internal/bundle"
)

// EnsureDelegationPolicy makes the organization's resource (delegation) policy
// match req's rendering of it, and refuses rather than overwrites when it does
// not already match — DESIGN §5's "policy half".
//
// # Why this cannot be an ordinary ensure operation
//
// Organizations holds exactly ONE resource policy per organization. Unlike a
// service control policy — many, keyed by id, owner-tagged so EnsurePolicy can
// tell "automat's, safe to update" from "somebody else's, refuse" —
// PutResourcePolicy REPLACES the single document wholesale, and there is no
// per-statement update and no tag on the document itself to check first. A
// university's organization may already have a resource policy for something
// automat knows nothing about: a different tool's delegation, a hand-written
// one, a prior automat run configured against a different OU. Blindly calling
// PutResourcePolicy with only automat's content would silently destroy whatever
// was already there.
//
// So the check this function makes is narrower and stricter than EnsurePolicy's:
// absent means safe to create; present means compare against exactly what
// bundle.DelegationPolicy(req) would render for THIS request, and refuse unless
// it already matches. There is no update path — a resource policy that exists
// with different content is never automat's to change, only to report on.
func (e *Ensurer) EnsureDelegationPolicy(ctx context.Context, req *bundle.Request) (*Action, error) {
	want, err := bundle.DelegationPolicy(req)
	if err != nil {
		return nil, err
	}

	out, err := e.Setup.DescribeResourcePolicy(ctx, &organizations.DescribeResourcePolicyInput{})
	switch {
	case err == nil:
		// fall through to the comparison below
	case isCode(err, "ResourcePolicyNotFoundException"):
		return e.createDelegationPolicy(ctx, want)
	default:
		return nil, e.denied(err, "organizations:DescribeResourcePolicy", "the organization's resource policy")
	}

	current := aws.ToString(out.ResourcePolicy.Content)
	if sameDocument(current, string(want)) {
		return e.record(Action{
			Verb: VerbUnchanged, Kind: "delegation policy",
			Detail: "already matches this request",
		}), nil
	}

	// Refuse. Not park, not warn-and-continue: there is no safe automated repair
	// for "a resource policy exists and is not automat's", and printing both
	// documents is what lets a human decide whether to merge them by hand.
	return nil, fmt.Errorf("the organization already has a resource policy, and it does not match "+
		"what this request would apply. Organizations holds exactly one resource policy per "+
		"organization — applying this one would REPLACE the existing document, not merge with it, "+
		"and automat cannot tell whether the existing one governs something else that would be lost.\n"+
		"\nExisting policy:\n%s\n\nautomat would apply:\n%s\n\n"+
		"If the existing policy is safe to replace, remove it by hand first "+
		"(organizations:DeleteResourcePolicy is not a grant automat holds) and re-run "+
		"`automat setup`. If it is not automat's, merge the two statements into the existing "+
		"document yourself", indentedJSON(current), indentedJSON(string(want)))
}

func (e *Ensurer) createDelegationPolicy(ctx context.Context, want []byte) (*Action, error) {
	if e.planning() {
		return e.record(Action{
			Verb: VerbCreate, Kind: "delegation policy",
			Detail: fmt.Sprintf("would be created, %d characters", len(want)),
		}), nil
	}
	if _, err := e.Setup.PutResourcePolicy(ctx, &organizations.PutResourcePolicyInput{
		Content: aws.String(string(want)),
	}); err != nil {
		return nil, e.denied(err, "organizations:PutResourcePolicy", "the organization's resource policy")
	}
	return e.record(Action{
		Verb: VerbCreate, Kind: "delegation policy",
		Detail: fmt.Sprintf("created, %d characters", len(want)), Applied: true,
	}), nil
}

// indentedJSON re-indents a policy document two spaces per level for the error
// message above, falling back to the raw string if it does not parse — an
// unparseable "existing policy" is itself informative and must not be hidden
// behind a formatting failure.
func indentedJSON(s string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(s), "", "  "); err != nil {
		return s
	}
	return buf.String()
}

// EnsureVendorRole makes the vendor role req describes exist in the management
// account with the right trust policy, permissions policy, and tags —
// DESIGN §5's "vending half".
//
// Ensure-semantics, the same read-then-branch shape as EnsurePolicy: GetRole
// decides CreateRole vs. UpdateAssumeRolePolicy, and PutRolePolicy runs either
// way because IAM's inline-policy write is already create-or-replace. Unlike
// EnsureDelegationPolicy, there is a real update path here — a role is scoped to
// req by name (VendorRoleName), so a role found under that name that this
// function did not just create is treated as automat's to correct, the same way
// EnsurePolicy corrects a tagged SCP's drifted content. What makes that safe
// without an ownership tag check first is that IAM role names are chosen by the
// operator running `automat setup`, not discovered — a name collision with an
// unrelated role is a config mistake to report, not a security boundary to
// defend, unlike the SCP case where the tag is read by conditions elsewhere.
func (e *Ensurer) EnsureVendorRole(ctx context.Context, req *bundle.Request, externalID string) (*Action, error) {
	trust, err := bundle.VendorRoleTrustPolicyJSON(req, externalID)
	if err != nil {
		return nil, err
	}
	perms, err := bundle.VendorRolePermissionsPolicyJSON(req)
	if err != nil {
		return nil, err
	}
	tags := bundle.VendorRoleTags(req)

	out, err := e.Role.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(req.VendorRoleName)})
	switch {
	case err == nil:
		return e.updateVendorRole(ctx, req, out, trust, perms, tags)
	case isCode(err, "NoSuchEntityException"):
		return e.createVendorRole(ctx, req, trust, perms, tags)
	default:
		return nil, e.denied(err, "iam:GetRole", req.VendorRoleName)
	}
}

func (e *Ensurer) createVendorRole(ctx context.Context, req *bundle.Request,
	trust, perms []byte, tags map[string]string) (*Action, error) {
	if e.planning() {
		return e.record(Action{
			Verb: VerbCreate, Kind: "vendor role", Name: req.VendorRoleName,
			Detail: "would be created with the trust and permissions policies this request describes",
		}), nil
	}
	if _, err := e.Role.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(req.VendorRoleName),
		AssumeRolePolicyDocument: aws.String(string(trust)),
		MaxSessionDuration:       aws.Int32(3600),
		Tags:                     iamTagList(tags),
	}); err != nil {
		return nil, e.denied(err, "iam:CreateRole", req.VendorRoleName)
	}
	if _, err := e.Role.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(req.VendorRoleName),
		PolicyName:     aws.String("automat-vend"),
		PolicyDocument: aws.String(string(perms)),
	}); err != nil {
		return nil, e.denied(err, "iam:PutRolePolicy", req.VendorRoleName)
	}
	return e.record(Action{
		Verb: VerbCreate, Kind: "vendor role", Name: req.VendorRoleName,
		Detail: "created with the trust and permissions policies this request describes", Applied: true,
	}), nil
}

// updateVendorRole corrects a role found under req.VendorRoleName. The trust
// policy is compared and updated only on drift, the same shape EnsurePolicy uses
// for an SCP's content; the permissions policy and the tags are always written,
// because PutRolePolicy and TagRole are each already idempotent and a
// same-content write costs nothing extra to reason about.
func (e *Ensurer) updateVendorRole(ctx context.Context, req *bundle.Request, out *iam.GetRoleOutput,
	trust, perms []byte, tags map[string]string) (*Action, error) {
	current := aws.ToString(out.Role.AssumeRolePolicyDocument)
	trustChanged := !sameDocument(current, string(trust))

	if e.planning() {
		detail := "trust and permissions policies already match this request"
		if trustChanged {
			detail = "trust policy differs from this request and would be replaced"
		}
		return e.record(Action{
			Verb: VerbUnchanged, Kind: "vendor role", Name: req.VendorRoleName, Detail: detail,
		}), nil
	}

	if trustChanged {
		if _, err := e.Role.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
			RoleName:       aws.String(req.VendorRoleName),
			PolicyDocument: aws.String(string(trust)),
		}); err != nil {
			return nil, e.denied(err, "iam:UpdateAssumeRolePolicy", req.VendorRoleName)
		}
	}
	if _, err := e.Role.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(req.VendorRoleName),
		PolicyName:     aws.String("automat-vend"),
		PolicyDocument: aws.String(string(perms)),
	}); err != nil {
		return nil, e.denied(err, "iam:PutRolePolicy", req.VendorRoleName)
	}
	if _, err := e.Role.TagRole(ctx, &iam.TagRoleInput{
		RoleName: aws.String(req.VendorRoleName), Tags: iamTagList(tags),
	}); err != nil {
		return nil, e.denied(err, "iam:TagRole", req.VendorRoleName)
	}

	verb, detail := VerbUnchanged, "permissions policy and tags ensured; trust policy already matched"
	if trustChanged {
		verb, detail = VerbUpdate, "trust policy replaced to match this request; permissions policy and tags ensured"
	}
	return e.record(Action{
		Verb: verb, Kind: "vendor role", Name: req.VendorRoleName, Detail: detail, Applied: true,
	}), nil
}

func iamTagList(m map[string]string) []iamtypes.Tag {
	out := make([]iamtypes.Tag, 0, len(m))
	for k, v := range m {
		out = append(out, iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return out
}
