// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// setupApplyArgs is the common flag set for `automat setup` without --request.
func setupApplyArgs(extra ...string) []string {
	return append([]string{
		"setup",
		"--member-account", testMember,
		"--org", testOrg,
		"--ou", testOU,
		"--contact", "research-it@example.edu",
		"--external-id-ref", "env:AUTOMAT_TEST_EXTERNAL_ID",
	}, extra...)
}

// TestSetupApplyCreatesTheRoleAndTheDelegationPolicy is Phase 3 task 3's actual
// point: applying directly creates both halves of DESIGN §5 without a human
// deploying a template.
func TestSetupApplyCreatesTheRoleAndTheDelegationPolicy(t *testing.T) {
	g, f := fakeSet(t, testOrg, testManagement, testManagement, "iam:CreateRole")
	t.Setenv("AUTOMAT_TEST_EXTERNAL_ID", testExternalID)

	out, _, err := runCLI(t, g, setupApplyArgs()...)
	if err != nil {
		t.Fatalf("setup apply: %v", err)
	}
	if !strings.Contains(out, "Applied:") {
		t.Fatalf("no Applied section in output:\n%s", out)
	}

	if f.State.ResourcePolicy == "" {
		t.Error("no resource policy was created")
	}
	perms := f.IAMRole.RolePolicy("automat-vendor", "automat-vend")
	if perms == "" {
		t.Fatal("no permissions policy was written to the vendor role")
	}
	if !strings.Contains(perms, testMember) {
		t.Errorf("the permissions policy does not name the member account:\n%s", perms)
	}
	tags := f.IAMRole.RoleTags("automat-vendor")
	if tags["automat:managed-by"] != "automat" {
		t.Errorf("the role is not tagged automat:managed-by=automat: %v", tags)
	}
	if !strings.Contains(out, "arn:") || !strings.Contains(out, "automat-vendor") {
		t.Errorf("the output does not tell the operator the role ARN to configure:\n%s", out)
	}
}

// TestSetupApplyRunTwiceChangesNothing is CLAUDE.md rule 4: the second run of a
// mutating command must be a no-op that reports so, not a second create that
// fails on "already exists" or blindly recreates.
func TestSetupApplyRunTwiceChangesNothing(t *testing.T) {
	g, f := fakeSet(t, testOrg, testManagement, testManagement, "iam:CreateRole")
	t.Setenv("AUTOMAT_TEST_EXTERNAL_ID", testExternalID)

	if _, _, err := runCLI(t, g, setupApplyArgs()...); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	before := map[string]int{
		"CreateRole":        f.IAMRole.CallCount("CreateRole"),
		"PutResourcePolicy": f.Setup.CallCount("PutResourcePolicy"),
	}

	out, _, err := runCLI(t, g, setupApplyArgs()...)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	for op, n := range before {
		var got int
		switch op {
		case "CreateRole":
			got = f.IAMRole.CallCount("CreateRole")
		case "PutResourcePolicy":
			got = f.Setup.CallCount("PutResourcePolicy")
		}
		if got != n {
			t.Errorf("second apply called %s %d more times; a re-run must change nothing", op, got-n)
		}
	}
	if !strings.Contains(out, "unchanged") {
		t.Errorf("the second run's plan does not say anything is unchanged:\n%s", out)
	}
}

// TestSetupApplyRefusesToOverwriteAForeignResourcePolicy is EnsureDelegationPolicy's
// whole reason for existing: Organizations holds exactly one resource policy per
// organization, and PutResourcePolicy replaces it wholesale. A document already
// there that is not automat's rendering of this request must not be silently
// replaced.
func TestSetupApplyRefusesToOverwriteAForeignResourcePolicy(t *testing.T) {
	g, f := fakeSet(t, testOrg, testManagement, testManagement, "iam:CreateRole")
	t.Setenv("AUTOMAT_TEST_EXTERNAL_ID", testExternalID)
	f.State.ResourcePolicy = `{"Version":"2012-10-17","Statement":[{"Sid":"SomeoneElsesDelegation",` +
		`"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"s3:*",` +
		`"Resource":"*"}]}`

	_, _, err := runCLI(t, g, setupApplyArgs()...)
	if err == nil {
		t.Fatal("setup apply overwrote an existing resource policy it did not write")
	}
	for _, want := range []string{"SomeoneElsesDelegation", "REPLACE", "one resource policy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	if f.Setup.CallCount("PutResourcePolicy") != 0 {
		t.Error("PutResourcePolicy was called despite the refusal")
	}
	if f.State.ResourcePolicy == "" || strings.Contains(f.State.ResourcePolicy, testMember) {
		t.Error("the foreign resource policy was overwritten")
	}
}

// TestSetupApplyDryRunWritesNothing mirrors vend's --dry-run test: a plan that
// mutated anything would defeat rule 5's whole reason for the plan/apply split.
func TestSetupApplyDryRunWritesNothing(t *testing.T) {
	g, f := fakeSet(t, testOrg, testManagement, testManagement, "iam:CreateRole")
	t.Setenv("AUTOMAT_TEST_EXTERNAL_ID", testExternalID)

	out, _, err := runCLI(t, g, setupApplyArgs("--dry-run")...)
	if err != nil {
		t.Fatalf("setup apply --dry-run: %v", err)
	}
	if !strings.Contains(out, "Nothing was applied") {
		t.Errorf("output does not say nothing was applied:\n%s", out)
	}
	if f.State.ResourcePolicy != "" {
		t.Error("--dry-run created a resource policy")
	}
	if f.IAMRole.CallCount("CreateRole") != 0 {
		t.Error("--dry-run called CreateRole")
	}
}

// TestSetupApplyRefusesAnUnresolvableExternalIdRef confirms the resolve failure
// surfaces before any AWS write, the same property internal/broker's own tests
// pin for the assume path — checked here because setup resolves the reference
// itself rather than delegating to internal/broker.
func TestSetupApplyRefusesAnUnresolvableExternalIdRef(t *testing.T) {
	g, f := fakeSet(t, testOrg, testManagement, testManagement, "iam:CreateRole")
	// AUTOMAT_TEST_EXTERNAL_ID_UNSET is deliberately never set.

	_, _, err := runCLI(t, g, "setup",
		"--member-account", testMember, "--org", testOrg, "--ou", testOU,
		"--contact", "research-it@example.edu",
		"--external-id-ref", "env:AUTOMAT_TEST_EXTERNAL_ID_UNSET")
	if err == nil {
		t.Fatal("setup apply succeeded with an unresolvable ExternalId reference")
	}
	if !strings.Contains(err.Error(), "AUTOMAT_TEST_EXTERNAL_ID_UNSET") {
		t.Errorf("error does not name the unset variable: %v", err)
	}
	if f.IAMRole.CallCount("CreateRole") != 0 {
		t.Error("CreateRole was called despite the unresolvable reference")
	}
}
