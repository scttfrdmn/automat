// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"context"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsfake"
	"github.com/scttfrdmn/automat/internal/org"
)

const (
	testRoleName  = "automat-automation"
	testMgmtAcct  = "111111111111"
	testTrust     = `{"Version":"2012-10-17","Statement":[{"Sid":"T","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]}`
	testPerms     = `{"Version":"2012-10-17","Statement":[{"Sid":"P","Effect":"Allow","Action":["config:PutConfigurationRecorder"],"Resource":"*"}]}`
	testPermsWide = `{"Version":"2012-10-17","Statement":[{"Sid":"P","Effect":"Allow","Action":["config:PutConfigurationRecorder","account:EnableRegion"],"Resource":"*"}]}`
)

func ctx() context.Context { return context.Background() }

func newFixtureEnsurer(mode org.Mode) (*Ensurer, *awsfake.IAMRole) {
	role := awsfake.NewIAMRole(testMgmtAcct)
	return &Ensurer{Role: role, Mode: mode, Principal: "arn:aws:sts::222222222222:assumed-role/OrganizationAccountAccessRole/automat-baseline"}, role
}

// TestEnsureAutomationRolePlanCreatesNothing is CLAUDE.md rule 5: a plan must
// issue no mutating call.
func TestEnsureAutomationRolePlanCreatesNothing(t *testing.T) {
	e, role := newFixtureEnsurer(org.ModePlan)

	arn, actions, err := e.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPerms))
	if err != nil {
		t.Fatalf("EnsureAutomationRole: %v", err)
	}
	if arn != "" {
		t.Errorf("a plan must not report an ARN for a role it has not created, got %q", arn)
	}
	for _, op := range []string{"CreateRole", "TagRole", "PutRolePolicy", "UpdateAssumeRolePolicy"} {
		if n := role.CallCount(op); n != 0 {
			t.Errorf("plan mode called %s %d times; a plan must write nothing", op, n)
		}
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbCreate {
		t.Fatalf("want one create action, got %+v", actions)
	}
}

// TestEnsureAutomationRoleApplyCreatesRole is the apply-mode counterpart:
// the role must be created, tagged, and permissioned.
func TestEnsureAutomationRoleApplyCreatesRole(t *testing.T) {
	e, role := newFixtureEnsurer(org.ModeApply)

	arn, actions, err := e.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPerms))
	if err != nil {
		t.Fatalf("EnsureAutomationRole: %v", err)
	}
	if arn == "" {
		t.Fatal("an applied create must report the role's ARN")
	}
	if role.CallCount("CreateRole") != 1 {
		t.Errorf("CreateRole called %d times, want 1", role.CallCount("CreateRole"))
	}
	if role.CallCount("TagRole") != 1 {
		t.Errorf("TagRole called %d times, want 1", role.CallCount("TagRole"))
	}
	if role.CallCount("PutRolePolicy") != 1 {
		t.Errorf("PutRolePolicy called %d times, want 1", role.CallCount("PutRolePolicy"))
	}
	if got := role.RolePolicy(testRoleName, AutomationRolePolicyName); !org.SameDocument(got, testPerms) {
		t.Errorf("stored policy = %s, want %s", got, testPerms)
	}
	if got := role.RoleTags(testRoleName)[org.OwnerTagKey]; got != org.OwnerTagValue {
		t.Errorf("owner tag = %q, want %q", got, org.OwnerTagValue)
	}
	if len(actions) != 1 || !actions[0].Applied || actions[0].Verb != org.VerbCreate {
		t.Fatalf("want one applied create action, got %+v", actions)
	}
}

// TestEnsureAutomationRoleIdempotent is CLAUDE.md rule 4: a second apply
// against an unchanged desired state must issue no write.
func TestEnsureAutomationRoleIdempotent(t *testing.T) {
	e, role := newFixtureEnsurer(org.ModeApply)
	if _, _, err := e.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPerms)); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	role.Reset()

	arn, actions, err := e.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPerms))
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if arn == "" {
		t.Error("the second ensure must still report the role's ARN")
	}
	for _, op := range []string{"CreateRole", "TagRole", "PutRolePolicy", "UpdateAssumeRolePolicy"} {
		if n := role.CallCount(op); n != 0 {
			t.Errorf("the second ensure called %s %d times; a re-run must write nothing", op, n)
		}
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbUnchanged || actions[0].Applied {
		t.Fatalf("want one unchanged, unapplied action, got %+v", actions)
	}
}

// TestEnsureAutomationRolePlanOnExistingRoleReportsDriftWithoutWriting checks
// the plan-mode read-then-report path against a role that already exists with
// a different policy.
func TestEnsureAutomationRolePlanOnExistingRoleReportsDriftWithoutWriting(t *testing.T) {
	apply, role := newFixtureEnsurer(org.ModeApply)
	if _, _, err := apply.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPerms)); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	role.Reset()

	plan := &Ensurer{Role: role, Mode: org.ModePlan, Principal: apply.Principal}
	arn, actions, err := plan.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPermsWide))
	if err != nil {
		t.Fatalf("plan against drifted policy: %v", err)
	}
	if arn == "" {
		t.Error("a plan against an EXISTING role must report its ARN")
	}
	for _, op := range []string{"PutRolePolicy", "CreateRole", "TagRole"} {
		if n := role.CallCount(op); n != 0 {
			t.Errorf("plan mode called %s %d times; a plan must write nothing", op, n)
		}
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbUpdate || actions[0].Applied {
		t.Fatalf("want one unapplied update action, got %+v", actions)
	}
}

// TestEnsureAutomationRoleUpdatesDriftedPolicy is the apply-mode counterpart:
// a role that exists with a DIFFERENT policy must have it replaced.
func TestEnsureAutomationRoleUpdatesDriftedPolicy(t *testing.T) {
	e, role := newFixtureEnsurer(org.ModeApply)
	if _, _, err := e.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPerms)); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	role.Reset()

	arn, actions, err := e.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPermsWide))
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if arn == "" {
		t.Error("an update must still report the role's ARN")
	}
	if role.CallCount("PutRolePolicy") != 1 {
		t.Errorf("PutRolePolicy called %d times, want 1", role.CallCount("PutRolePolicy"))
	}
	if role.CallCount("CreateRole") != 0 {
		t.Error("an update path must not call CreateRole")
	}
	if got := role.RolePolicy(testRoleName, AutomationRolePolicyName); !org.SameDocument(got, testPermsWide) {
		t.Errorf("stored policy = %s, want %s", got, testPermsWide)
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbUpdate || !actions[0].Applied {
		t.Fatalf("want one applied update action, got %+v", actions)
	}
}

// TestEnsureAutomationRoleParksOnRePermissionDenial is Q13: a role that
// exists, whose policy needs to change, and whose PutRolePolicy is denied —
// the shape baseline-protection's BP.IAM-1 produces once it is attached to
// the account's OU. This must not surface as an undifferentiated AWS error;
// it must be an awsapi.PermissionError (so org.Parkable recognizes it) whose
// remediation names BOTH the baseline-protection reading and the ordinary
// missing-grant reading, because AccessDenied alone cannot prove which
// applies.
func TestEnsureAutomationRoleParksOnRePermissionDenial(t *testing.T) {
	e, role := newFixtureEnsurer(org.ModeApply)
	if _, _, err := e.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPerms)); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	role.Reset()
	role.Errs["PutRolePolicy"] = awsfake.AccessDenied("iam:PutRolePolicy")

	_, actions, err := e.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPermsWide))
	if err == nil {
		t.Fatal("want an error when PutRolePolicy is denied against a drifted policy")
	}
	if !org.Parkable(err) {
		t.Errorf("this denial must be org.Parkable so `vend` parks rather than fails outright: %v", err)
	}
	if !strings.Contains(err.Error(), "baseline-protection") {
		t.Errorf("error does not mention baseline-protection: %v", err)
	}
	if !strings.Contains(err.Error(), "detach baseline-protection") {
		t.Errorf("error carries no remediation to detach baseline-protection: %v", err)
	}
	if !strings.Contains(err.Error(), "Q13") {
		t.Errorf("error does not cite Q13: %v", err)
	}
	// A denied write must not be reported as an applied or unchanged action —
	// the caller learns about it only through the returned error.
	for _, a := range actions {
		if a.Applied {
			t.Errorf("a denied write must not be recorded as Applied: %+v", a)
		}
	}
}

// TestEnsureAutomationRoleCreateDenialIsNotMisreadAsQ13 draws the boundary the
// package doc promises: a denial on the CREATE path cannot be Q13, because
// baseline-protection cannot have attached to a role with no ARN yet, so the
// remediation must be the ordinary reading only.
func TestEnsureAutomationRoleCreateDenialIsNotMisreadAsQ13(t *testing.T) {
	e, role := newFixtureEnsurer(org.ModeApply)
	role.Errs["CreateRole"] = awsfake.AccessDenied("iam:CreateRole")

	_, _, err := e.EnsureAutomationRole(ctx(), testRoleName, []byte(testTrust), []byte(testPerms))
	if err == nil {
		t.Fatal("want an error when CreateRole is denied")
	}
	if strings.Contains(err.Error(), "baseline-protection") {
		t.Errorf("a create-path denial must not be attributed to baseline-protection: %v", err)
	}
	if !strings.Contains(err.Error(), "iam:CreateRole") {
		t.Errorf("error does not name the denied action: %v", err)
	}
}

// TestEnsureAutomationRoleRefusesAnEmptyName is a narrow input-validation
// check: EnsureAutomationRole must not be called with nothing to name the
// role.
func TestEnsureAutomationRoleRefusesAnEmptyName(t *testing.T) {
	e, _ := newFixtureEnsurer(org.ModeApply)
	if _, _, err := e.EnsureAutomationRole(ctx(), "", []byte(testTrust), []byte(testPerms)); err == nil {
		t.Fatal("want an error for an empty role name")
	}
}

// TestPermissionsPolicyJSONIsValidAndCoversBothInterfaces confirms the
// rendered permissions policy is well-formed JSON and names an action from
// each of ConfigAPI and AccountAPI, since those are exactly the two
// interfaces this policy is derived from (see automationRoleActions).
func TestPermissionsPolicyJSONIsValidAndCoversBothInterfaces(t *testing.T) {
	doc, err := PermissionsPolicyJSON()
	if err != nil {
		t.Fatalf("PermissionsPolicyJSON: %v", err)
	}
	if _, ok := org.CanonicalizeDocument(string(doc)); !ok {
		t.Fatalf("PermissionsPolicyJSON did not produce valid JSON:\n%s", doc)
	}
	s := string(doc)
	if !strings.Contains(s, "config:PutConfigurationRecorder") {
		t.Error("policy does not name a ConfigAPI action")
	}
	if !strings.Contains(s, "account:EnableRegion") {
		t.Error("policy does not name an AccountAPI action")
	}
	// A Config delete action (absent from awsapi.ConfigAPI on purpose, per that
	// interface's own doc) must also be absent here — this policy must not
	// grant more than the interfaces it was derived from.
	if strings.Contains(s, "config:Delete") {
		t.Error("policy grants a Config delete action, which is not on awsapi.ConfigAPI")
	}
}

// TestTrustPolicyJSONNamesTheManagementAccount confirms the rendered trust
// policy trusts the management account's root principal, not a literal role
// ARN — see TrustPolicyJSON's doc comment for why.
func TestTrustPolicyJSONNamesTheManagementAccount(t *testing.T) {
	doc, err := TrustPolicyJSON(testMgmtAcct, "")
	if err != nil {
		t.Fatalf("TrustPolicyJSON: %v", err)
	}
	if _, ok := org.CanonicalizeDocument(string(doc)); !ok {
		t.Fatalf("TrustPolicyJSON did not produce valid JSON:\n%s", doc)
	}
	if !strings.Contains(string(doc), "arn:aws:iam::"+testMgmtAcct+":root") {
		t.Errorf("trust policy does not name the management account's root principal:\n%s", doc)
	}
}

// TestTrustPolicyJSONRefusesNoManagementAccount is a narrow input check: a
// trust policy naming no principal at all would trust nobody, silently.
func TestTrustPolicyJSONRefusesNoManagementAccount(t *testing.T) {
	if _, err := TrustPolicyJSON("", ""); err == nil {
		t.Fatal("want an error for an empty management account id")
	}
}
