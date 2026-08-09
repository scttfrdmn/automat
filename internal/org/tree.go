// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
)

// TreeAccount is one account discovered while walking an OU subtree.
type TreeAccount struct {
	ID         string
	Name       string
	Email      string
	ParentOUID string
}

// TreeOU is one organizational unit discovered while walking a subtree,
// including the id of the parent it was found under.
type TreeOU struct {
	ID       string
	Name     string
	ParentID string
}

// Tree is WalkTree's result: every OU and account in a subtree, in the order
// discovered (breadth-first, one level at a time).
type Tree struct {
	OUs      []TreeOU
	Accounts []TreeAccount
}

// WalkTree lists every account and OU in the subtree rooted at root,
// including root's direct children and everything below them, down to
// MaxOUDepth additional levels — the same bound EnsureOUPath enforces
// against creation, applied here against traversal so a cycle or an
// unexpectedly deep tree cannot make `automat list` loop forever.
//
// A method on Ensurer, not a free function, so a denied read gets the same
// Native/Brokered remediation wording every other read and write in this
// package produces (e.denied) — `automat list` runs against exactly the
// same two credential shapes `vend` does (DESIGN §5), and a walk that
// invented its own remediation text would be a second place for that
// wording to drift from Ensurer's.
func (e *Ensurer) WalkTree(ctx context.Context, root string) (*Tree, error) {
	if root == "" {
		return nil, fmt.Errorf("cannot walk the organization tree: no root or OU id was given")
	}
	tree := &Tree{}
	level := []string{root}
	for depth := 0; depth <= MaxOUDepth && len(level) > 0; depth++ {
		var next []string
		for _, parent := range level {
			ous, err := e.listOUsForParent(ctx, parent)
			if err != nil {
				return nil, err
			}
			for _, ou := range ous {
				tree.OUs = append(tree.OUs, TreeOU{ID: ou.id, Name: ou.name, ParentID: parent})
				next = append(next, ou.id)
			}
			accounts, err := e.listAccountsForParent(ctx, parent)
			if err != nil {
				return nil, err
			}
			for _, a := range accounts {
				tree.Accounts = append(tree.Accounts,
					TreeAccount{ID: a.id, Name: a.name, Email: a.email, ParentOUID: parent})
			}
		}
		level = next
	}
	if len(level) > 0 {
		return nil, fmt.Errorf("the organizational unit tree under %s is deeper than %d levels, which "+
			"AWS does not permit (DESIGN §3, fact 10) — this is either a cycle this walk failed to "+
			"detect or an organization in a state automat's assumptions do not cover; report it",
			root, MaxOUDepth)
	}
	return tree, nil
}

type namedID struct{ id, name string }
type namedAccount struct{ id, name, email string }

// listOUsForParent lists parent's direct OU children, paginated — the same
// discipline findOU's own pagination loop follows (ou.go), duplicated
// rather than shared because findOU stops at the first name match and this
// collects everything.
func (e *Ensurer) listOUsForParent(ctx context.Context, parent string) ([]namedID, error) {
	var out []namedID
	var token *string
	seen := map[string]bool{}
	for i := 0; i < listPageCap; i++ {
		page, err := e.Vend.ListOrganizationalUnitsForParent(ctx,
			&organizations.ListOrganizationalUnitsForParentInput{ParentId: aws.String(parent), NextToken: token})
		if err != nil {
			if isCode(err, "ParentNotFoundException") {
				return nil, fmt.Errorf("cannot list organizational units under %s: no root or OU with "+
					"that id exists in this organization", parent)
			}
			return nil, e.denied(err, "organizations:ListOrganizationalUnitsForParent", parent)
		}
		for _, ou := range page.OrganizationalUnits {
			out = append(out, namedID{id: aws.ToString(ou.Id), name: aws.ToString(ou.Name)})
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			return out, nil
		}
		if seen[aws.ToString(page.NextToken)] {
			return nil, fmt.Errorf("listing organizational units under %s: the same pagination token "+
				"came back twice, so the list does not terminate; automat stopped rather than looping", parent)
		}
		seen[aws.ToString(page.NextToken)] = true
		token = page.NextToken
	}
	return nil, fmt.Errorf("listing organizational units under %s: stopped after %d pages without "+
		"reaching the end of the list", parent, listPageCap)
}

// listAccountsForParent lists parent's direct account children, paginated.
func (e *Ensurer) listAccountsForParent(ctx context.Context, parent string) ([]namedAccount, error) {
	var out []namedAccount
	var token *string
	seen := map[string]bool{}
	for i := 0; i < listPageCap; i++ {
		page, err := e.Vend.ListAccountsForParent(ctx,
			&organizations.ListAccountsForParentInput{ParentId: aws.String(parent), NextToken: token})
		if err != nil {
			if isCode(err, "ParentNotFoundException") {
				return nil, fmt.Errorf("cannot list accounts under %s: no root or OU with that id "+
					"exists in this organization", parent)
			}
			return nil, e.denied(err, "organizations:ListAccountsForParent", parent)
		}
		for _, a := range page.Accounts {
			out = append(out, namedAccount{
				id: aws.ToString(a.Id), name: aws.ToString(a.Name), email: aws.ToString(a.Email),
			})
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			return out, nil
		}
		if seen[aws.ToString(page.NextToken)] {
			return nil, fmt.Errorf("listing accounts under %s: the same pagination token came back "+
				"twice, so the list does not terminate; automat stopped rather than looping", parent)
		}
		seen[aws.ToString(page.NextToken)] = true
		token = page.NextToken
	}
	return nil, fmt.Errorf("listing accounts under %s: stopped after %d pages without reaching the "+
		"end of the list", parent, listPageCap)
}
