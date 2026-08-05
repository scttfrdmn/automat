// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// EnsureOU makes an OU named name exist directly under parent, and returns its
// id and what it took.
//
// Read first, then create, then tolerate the duplicate (Q12's discipline applied
// to OUs, where AWS is unambiguous): CreateOrganizationalUnit refuses a second
// OU with the same name under the same parent with
// DuplicateOrganizationalUnitException, so the tolerant path re-reads to find
// the id somebody else's create just produced. Without the re-read, tolerating
// the exception would return no id at all, which is worse than the error.
//
// The name is the only handle. An OU id is assigned at creation and automat has
// nowhere to persist one between runs — there is no state file by design — so
// "the OU automat vends into" is identified by name, which is what makes the
// name uniqueness AWS enforces a feature rather than an obstacle.
func (e *Ensurer) EnsureOU(ctx context.Context, parent, name string) (string, *Action, error) {
	if err := validOUName(name); err != nil {
		return "", nil, err
	}
	if parent == "" {
		return "", nil, fmt.Errorf("cannot ensure organizational unit %q: no parent was given — "+
			"pass the root id or a parent OU id; every OU has exactly one parent and automat "+
			"will not guess at the root", name)
	}

	id, err := e.findOU(ctx, parent, name)
	if err != nil {
		return "", nil, err
	}
	if id != "" {
		return id, e.record(Action{
			Verb: VerbUnchanged, Kind: "organizational unit", Name: name, ID: id, Target: parent,
			Detail: "already exists under " + parent,
		}), nil
	}

	if e.planning() {
		return "", e.record(Action{
			Verb: VerbCreate, Kind: "organizational unit", Name: name, Target: parent,
			Detail: "would be created under " + parent + "; the id is assigned by AWS at creation " +
				"and cannot be predicted",
		}), nil
	}

	out, err := e.Vend.CreateOrganizationalUnit(ctx, &organizations.CreateOrganizationalUnitInput{
		ParentId: aws.String(parent),
		Name:     aws.String(name),
		Tags:     ownerTags(),
	})
	switch {
	case err == nil:
		id = aws.ToString(out.OrganizationalUnit.Id)
		return id, e.record(Action{
			Verb: VerbCreate, Kind: "organizational unit", Name: name, ID: id, Target: parent,
			Detail: "created under " + parent, Applied: true,
		}), nil
	case isCode(err, "DuplicateOrganizationalUnitException"):
		// Created between the read and the write. Re-read rather than error: a
		// concurrent vend or a console click is a legitimate way for this to
		// happen, and both runs want the same OU.
		id, ferr := e.findOU(ctx, parent, name)
		if ferr != nil {
			return "", nil, ferr
		}
		if id == "" {
			// The duplicate exists but is not visible under this parent, which
			// means the name collides somewhere the caller did not ask about.
			// Reporting it as an ordinary failure would send the operator looking
			// for an OU that is not there.
			return "", nil, fmt.Errorf("organizational unit %q under %s: AWS reports the name is already "+
				"taken, but no such OU is visible under that parent — either the credential cannot list "+
				"it or the name belongs to an OU elsewhere in the organization; check the OU tree in the "+
				"Organizations console before re-running", name, parent)
		}
		return id, e.record(Action{
			Verb: VerbUnchanged, Kind: "organizational unit", Name: name, ID: id, Target: parent,
			Detail: "created concurrently by another caller between automat's read and its create; " +
				"adopted rather than duplicated",
		}), nil
	default:
		return "", nil, e.denied(err, "organizations:CreateOrganizationalUnit", parent)
	}
}

// EnsureOUPath ensures a chain of OUs below parent, returning the id of the
// deepest one.
//
// DESIGN §7 step 3 allows creating intermediate OUs "if the profile says so,
// within depth limits". The depth limit is checked before anything is created,
// because a path that is one level too deep fails halfway and leaves the shallow
// levels behind — the account then lands in an OU that carries none of the
// policies the profile asked for, which is the parked case with extra steps.
//
// In ModePlan the walk stops at the first level that would be created: nothing
// below it can be read, so the plan reports VerbUnknown for the deeper levels
// rather than asserting they are absent. A plan that claimed to know is a plan
// that would be wrong whenever a concurrent vend got there first.
func (e *Ensurer) EnsureOUPath(ctx context.Context, parent string, names []string) (string, []Action, error) {
	if len(names) == 0 {
		return parent, nil, nil
	}
	if parent == "" {
		// Not reachable from `vend`, which resolves the root first, but the loop
		// below reports an unreadable level by naming the level above it — and at
		// the first level, the level above it is this parent. An empty parent would
		// make that reference meaningless and the whole path a create at an unknown
		// location, which is the one thing worse than refusing.
		return "", nil, fmt.Errorf("cannot ensure the organizational unit path %q: no parent was given, "+
			"and automat will not create an OU at an unknown location — resolve the root or the "+
			"destination OU first", strings.Join(names, "/"))
	}
	if len(names) > MaxOUDepth {
		return "", nil, fmt.Errorf("cannot ensure an organizational unit path %d levels deep: AWS permits "+
			"%d levels of OU below the root (DESIGN §3, fact 10), and this path has %d — shorten it in the "+
			"profile before vending, because a path that fails halfway leaves the account in an OU with "+
			"none of the policies the profile asked for",
			len(names), MaxOUDepth, len(names))
	}
	// The remaining budget below parent, so a path that fits on its own but not
	// under this parent is refused before anything is created.
	depth, err := e.depthOf(ctx, parent)
	switch {
	case err != nil:
		return "", nil, err
	case depth >= 0 && depth+len(names) > MaxOUDepth:
		return "", nil, fmt.Errorf("cannot ensure %d more organizational unit levels under %s: it is "+
			"already %d levels below the root and AWS permits %d (DESIGN §3, fact 10) — either shorten "+
			"the path in the profile or vend into a shallower parent",
			len(names), parent, depth, MaxOUDepth)
	}

	var out []Action
	cur := parent
	// above names the level whose id `cur` holds, for the plan's benefit. Carried
	// rather than computed from the index: the first iteration's "level above" is
	// the caller's parent, not names[-1].
	above := parent
	for _, name := range names {
		if cur == "" {
			// A planned creation above this level means there is no id to read
			// under. Say so, once per remaining level, and keep going so the plan
			// still lists the whole path.
			out = append(out, *e.record(Action{
				Verb: VerbUnknown, Kind: "organizational unit", Name: name,
				Detail: fmt.Sprintf("cannot be checked: its parent %q does not exist yet, so a plan "+
					"cannot read below it — apply the plan to find out", above),
			}))
			above = name
			continue
		}
		id, act, err := e.EnsureOU(ctx, cur, name)
		if err != nil {
			return "", out, err
		}
		out = append(out, *act)
		cur = id
		above = name
	}
	if cur == "" {
		return "", out, nil
	}
	return cur, out, nil
}

// findOU returns the id of the OU named name under parent, or "" if there is
// none.
//
// Paginated properly, and that is the point of the loop rather than an
// incidental detail: ListOrganizationalUnitsForParent truncates silently, so a
// caller reading only the first page concludes an OU does not exist and creates
// a duplicate — which AWS then refuses, turning a missing NextToken into a vend
// that cannot proceed. awsfake.OrgState.PageSize defaults to 2 so this is
// exercised by every fixture with three OUs.
func (e *Ensurer) findOU(ctx context.Context, parent, name string) (string, error) {
	var token *string
	seen := map[string]bool{}
	for i := 0; i < listPageCap; i++ {
		out, err := e.Vend.ListOrganizationalUnitsForParent(ctx,
			&organizations.ListOrganizationalUnitsForParentInput{
				ParentId: aws.String(parent), NextToken: token,
			})
		if err != nil {
			if isCode(err, "ParentNotFoundException") {
				return "", fmt.Errorf("cannot look for organizational unit %q: no root or OU with id %s "+
					"exists in this organization — correct the parent id, which comes from `ou` in the "+
					"config file or from the profile's OU path", name, parent)
			}
			return "", e.denied(err, "organizations:ListOrganizationalUnitsForParent", parent)
		}
		for _, ou := range out.OrganizationalUnits {
			if aws.ToString(ou.Name) == name {
				return aws.ToString(ou.Id), nil
			}
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			return "", nil
		}
		if seen[aws.ToString(out.NextToken)] {
			return "", fmt.Errorf("listing organizational units under %s: the same pagination token came "+
				"back twice, so the list does not terminate; automat stopped rather than looping. Retry, "+
				"and report it if it persists", parent)
		}
		seen[aws.ToString(out.NextToken)] = true
		token = out.NextToken
	}
	return "", fmt.Errorf("listing organizational units under %s: stopped after %d pages without "+
		"reaching the end of the list", parent, listPageCap)
}

// depthOf returns how many OU levels below the root the given container is: 0
// for the root, 1 for an OU directly under it. It returns -1 when the depth
// cannot be determined, which is not an error — a member account is frequently
// denied ListParents on an OU it may nonetheless vend into, and refusing to vend
// because automat could not count would make the delegation useless.
func (e *Ensurer) depthOf(ctx context.Context, container string) (int, error) {
	if strings.HasPrefix(container, "r-") {
		return 0, nil
	}
	cur := container
	for depth := 1; depth <= MaxOUDepth+1; depth++ {
		out, err := e.Vend.ListParents(ctx, &organizations.ListParentsInput{ChildId: aws.String(cur)})
		switch {
		case err == nil:
		case isCode(err, "ChildNotFoundException"):
			return 0, fmt.Errorf("cannot measure the depth of %s: no OU or account with that id exists "+
				"in this organization", cur)
		default:
			// Includes AccessDenied. Undetermined, not fatal — see above.
			return -1, nil
		}
		if len(out.Parents) == 0 {
			return -1, nil
		}
		p := out.Parents[0]
		if p.Type == orgtypes.ParentTypeRoot {
			return depth, nil
		}
		cur = aws.ToString(p.Id)
	}
	// Deeper than AWS permits. Not automat's problem to diagnose, but it must not
	// be reported as a depth automat can add to.
	return -1, nil
}

// ownerTags returns the tag automat marks its own resources with.
func ownerTags() []orgtypes.Tag {
	return []orgtypes.Tag{{Key: aws.String(OwnerTagKey), Value: aws.String(OwnerTagValue)}}
}

// tagList renders a map as an Organizations tag list in sorted key order, so two
// runs with the same desired tags produce the same request.
func tagList(m map[string]string) []orgtypes.Tag {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]orgtypes.Tag, 0, len(keys))
	for _, k := range keys {
		out = append(out, orgtypes.Tag{Key: aws.String(k), Value: aws.String(m[k])})
	}
	return out
}

// validOUName rejects a name automat must not send.
//
// Narrower than AWS accepts, for the same reason internal/bundle's patterns are:
// an OU name reaches a rendered plan, an evidence record, and a markdown
// document a privileged reader acts on. Control bytes and the characters that
// terminate a string in JSON or YAML are refused here rather than escaped later,
// because escaping is a property of every render site and this is one check.
// Interior spaces are allowed — "Research Computing" is what an OU is really
// called — and a leading or trailing space is not: a name that reads as one
// thing and compares as another breaks the name-is-the-handle property EnsureOU
// depends on.
func validOUName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("cannot ensure an organizational unit with an empty name: the name is the only " +
			"handle automat has on an OU between runs, since there is no state file and an OU id is " +
			"assigned at creation")
	case len(name) > 128:
		return fmt.Errorf("organizational unit name is %d characters; AWS permits 128", len(name))
	case strings.TrimSpace(name) != name:
		return fmt.Errorf("organizational unit name %q has leading or trailing whitespace: it would read "+
			"as one name and compare as another, and automat finds an existing OU by exact name", name)
	}
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("organizational unit name contains a control character (%#U): the name is "+
				"rendered into plans, evidence records, and documents a reviewer reads", r)
		case strings.ContainsRune("\"'\\{}[]$`", r):
			return fmt.Errorf("organizational unit name %q contains %q, which can terminate a string or "+
				"open a substitution in the documents automat renders it into; use letters, digits, "+
				"spaces, and .-_", name, r)
		}
	}
	return nil
}
