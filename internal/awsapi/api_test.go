// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// These tests assert properties of the interfaces themselves, by reflection over
// the interface types rather than over an implementation.
//
// That is the point: the interfaces are where a capability automat does not need
// becomes a capability no code path in this repository can reach. A code review
// can confirm `internal/org` never calls CloseAccount; only the interface can
// make the call unwritable. So the invariant belongs here, where it fails at
// `go test` for the person adding the method, rather than in a document.

// interfaceMethods returns the method names of an interface type.
func interfaceMethods(t *testing.T, iface reflect.Type) []string {
	t.Helper()
	if iface.Kind() != reflect.Interface {
		t.Fatalf("%s is not an interface", iface)
	}
	var out []string
	for i := 0; i < iface.NumMethod(); i++ {
		out = append(out, iface.Method(i).Name)
	}
	sort.Strings(out)
	return out
}

// allInterfaces is every interface in this package, by name. Kept as a list so a
// new interface must be added here to be covered — and so the coverage test below
// can tell that it was not.
func allInterfaces(t *testing.T) map[string]reflect.Type {
	t.Helper()
	return map[string]reflect.Type{
		"STSAPI":       reflect.TypeOf((*STSAPI)(nil)).Elem(),
		"OrgAPI":       reflect.TypeOf((*OrgAPI)(nil)).Elem(),
		"OrgVendAPI":   reflect.TypeOf((*OrgVendAPI)(nil)).Elem(),
		"OrgPolicyAPI": reflect.TypeOf((*OrgPolicyAPI)(nil)).Elem(),
		"OrgInitAPI":   reflect.TypeOf((*OrgInitAPI)(nil)).Elem(),
		"OrgSetupAPI":  reflect.TypeOf((*OrgSetupAPI)(nil)).Elem(),
		"IAMAPI":       reflect.TypeOf((*IAMAPI)(nil)).Elem(),
		"IAMRoleAPI":   reflect.TypeOf((*IAMRoleAPI)(nil)).Elem(),
		"QuotaAPI":     reflect.TypeOf((*QuotaAPI)(nil)).Elem(),
		"SSOOIDCAPI":   reflect.TypeOf((*SSOOIDCAPI)(nil)).Elem(),
	}
}

// TestNoWriteInterfaceCanDestroy is the invariant the api.go comment claims.
//
// Every one of these operations is irreversible or nearly so, and CLAUDE.md rule
// 5 puts them behind a plan/apply split and `--yes`. None of that plumbing exists
// yet in Phase 2, and the honest way to enforce a gate that does not exist is to
// make the action unreachable rather than to trust that nobody calls it.
//
// The onboarding bundle *does* request DetachPolicy and DeletePolicy — `verify`
// and `reclaim` will need them — so the grant and the capability are deliberately
// out of step for now. That is the safe direction: a grant automat cannot exercise
// costs nothing, while a capability automat has without a gate is the thing rule 5
// is about.
//
// When `reclaim` is written, the fix is a new interface with its own doc comment
// explaining the gate, not a method appended to one of these.
func TestNoWriteInterfaceCanDestroy(t *testing.T) {
	// Why each one, because "destructive" is not self-evident for all of them.
	//
	// UpdatePolicy is deliberately NOT on this list, and it is the closest call:
	// rewriting a policy's content changes what a live account is subject to. It is
	// permitted because ensure-semantics needs it — an SCP whose content drifted from
	// the artifact must be corrected in place, since replacing it would mean a window
	// with the control detached. What makes that acceptable is the tag condition in
	// internal/bundle's scpModifyActions: UpdatePolicy is reachable only against
	// policies automat created.
	//
	// PutResourcePolicy is likewise NOT on this list as of Phase 3 task 3, for the
	// analogous reason stated on OrgSetupAPI's own doc comment: it is gated on
	// reading the existing resource policy first and refusing to overwrite content
	// that is not already automat's own rendering of the request.
	destructive := map[string]string{
		"DetachPolicy":                     "removes a control from a live account; the account stops being what its evidence manifest says it is",
		"DeletePolicy":                     "destroys the control itself, not just its attachment",
		"DeleteOrganizationalUnit":         "an OU with accounts under it is the destination every SCP resource ARN names",
		"CloseAccount":                     "irreversible, and rate-limited to ~10% of member accounts per 30 days (DESIGN §3 fact 11), so a mistake is not re-runnable",
		"RemoveAccountFromOrganization":    "the account keeps existing and stops being governed by any SCP",
		"LeaveOrganization":                "the same, initiated from the child",
		"DeleteOrganization":               "deletes the org automat was pointed at",
		"DeregisterDelegatedAdministrator": "revokes the delegation the whole MEMBER path depends on",
		"DisablePolicyType":                "turns SCPs off org-wide; every attached control silently stops applying (DESIGN §3 fact 8)",
		"DeleteResourcePolicy":             "removes the org's whole delegation policy, not just automat's part of it",
		"UntagResource":                    "removes a tag, and two of automat's tags are read by conditions in the delegation policy",
	}

	for name, iface := range allInterfaces(t) {
		for _, m := range interfaceMethods(t, iface) {
			why, listed := destructive[m]
			if !listed {
				continue
			}
			t.Errorf("%s has method %s, which %s.\n\n"+
				"CLAUDE.md rule 5 puts destructive operations behind a printed plan and "+
				"--yes. That plumbing is not built yet, so this action must stay "+
				"unreachable rather than merely uncalled. If it is time to build it, add "+
				"an interface that says so in its doc comment and remove this entry — "+
				"do not append the method here.", name, m, why)
		}
	}
}

// TestTheVendAndPolicyHalvesStaySeparate holds the split DESIGN §5 forces.
//
// In the MEMBER state the two halves run on different credentials: account and OU
// operations through the brokered vendor role, policy operations as the caller's
// own delegated identity. If OrgVendAPI grew a policy method, the vendor role
// would have to grant it — and DESIGN §5 is explicit that the role carries no
// policy actions, which is what keeps it reviewable in the length central IT will
// read. The reverse leak is worse: CreateAccount is not delegable at all
// (DESIGN §3 fact 1), so a delegated client with that method on it is a type whose
// calls cannot succeed.
func TestTheVendAndPolicyHalvesStaySeparate(t *testing.T) {
	policyOnly := map[string]bool{
		"CreatePolicy": true, "UpdatePolicy": true, "DeletePolicy": true,
		"AttachPolicy": true, "DetachPolicy": true, "DescribePolicy": true,
		"ListPolicies": true, "ListPoliciesForTarget": true, "ListTargetsForPolicy": true,
	}
	// Not delegable via a resource-based delegation policy — DESIGN §3, facts 1
	// and 2. The API rejects CreateOrganizationalUnit in a delegation policy
	// outright ("unsupported action").
	vendOnly := map[string]bool{
		"CreateAccount": true, "CreateOrganizationalUnit": true,
		"DescribeCreateAccountStatus": true, "MoveAccount": true,
	}

	for _, m := range interfaceMethods(t, reflect.TypeOf((*OrgVendAPI)(nil)).Elem()) {
		if policyOnly[m] {
			t.Errorf("OrgVendAPI has %s, a policy operation. In MEMBER state this "+
				"interface is the brokered vendor role, and DESIGN §5 says that role "+
				"carries no policy actions — adding this means asking central IT to widen "+
				"a grant whose reviewability is the reason the university path works.", m)
		}
	}
	for _, m := range interfaceMethods(t, reflect.TypeOf((*OrgPolicyAPI)(nil)).Elem()) {
		if vendOnly[m] {
			t.Errorf("OrgPolicyAPI has %s, which cannot be delegated to a member account "+
				"(DESIGN §3 facts 1 and 2). In MEMBER state this interface is the caller's "+
				"own delegated credentials, so a call to %s here cannot succeed no matter "+
				"what the delegation policy says.", m, m)
		}
	}
}

// TestEveryWriteInterfaceCanReadBackWhatItWrote.
//
// CLAUDE.md rule 4 is ensure-semantics: create-or-verify, safely re-runnable. An
// ensure operation has to read the current state before deciding to write, and in
// the MEMBER state the read must go through the SAME client as the write —
// preflight's OrgAPI is a different credential with a different view, so
// "OrgAPI can already list policies" does not help. A write interface with no
// reads on it can only blind-write, which is the opposite of idempotent.
func TestEveryWriteInterfaceCanReadBackWhatItWrote(t *testing.T) {
	for _, name := range []string{"OrgVendAPI", "OrgPolicyAPI"} {
		methods := interfaceMethods(t, allInterfaces(t)[name])
		var reads int
		for _, m := range methods {
			if strings.HasPrefix(m, "Describe") || strings.HasPrefix(m, "List") {
				reads++
			}
		}
		if reads == 0 {
			t.Errorf("%s has no Describe/List method, so nothing on it can be made "+
				"idempotent: an ensure operation must read current state through the same "+
				"credential it writes with. CLAUDE.md rule 4.", name)
		}
	}
}

// TestEveryInterfaceIsListed keeps the two tests above honest.
//
// Both iterate a hand-written map, which is the standard way for a guard like this
// to rot: someone adds OrgReclaimAPI to api.go, does not add it here, and the
// destructive-method check silently covers everything except the interface that
// most needed it. Counting declared interfaces in the source is crude, but it fails
// loudly in exactly that case.
func TestEveryInterfaceIsListed(t *testing.T) {
	declared := declaredInterfaceNames(t)
	listed := allInterfaces(t)
	for _, name := range declared {
		if _, ok := listed[name]; !ok {
			t.Errorf("api.go declares interface %s but allInterfaces does not list it, so "+
				"TestNoWriteInterfaceCanDestroy is not checking it. Add it.", name)
		}
	}
	for name := range listed {
		found := false
		for _, d := range declared {
			if d == name {
				found = true
			}
		}
		if !found {
			t.Errorf("allInterfaces lists %s, which api.go no longer declares", name)
		}
	}
}

// declaredInterfaceNames parses api.go for exported interface declarations.
//
// Parsing rather than grepping: a `//` comment line naming an interface would fool
// a grep, and this test's whole job is to notice something that was added.
func declaredInterfaceNames(t *testing.T) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "api.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse api.go: %v", err)
	}
	var out []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			if _, isIface := ts.Type.(*ast.InterfaceType); isIface && ts.Name.IsExported() {
				out = append(out, ts.Name.Name)
			}
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("found no interfaces in api.go; this test would assert nothing")
	}
	return out
}
