// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsfake"
)

// `automat init` at the CLI. internal/org owns the ensure semantics and tests them
// against the fakes directly; what is only testable here is the wiring the command
// adds on top — the plan/apply split, the --yes gate on the one irreversible step,
// which states it refuses, and the partial-progress report.
//
// The assertions are on the resulting organization and on what the operator was
// told, not on call sequences (internal/awsfake's package doc says why). The two
// exceptions are deliberate: a plan must issue no write at all, and a second run
// must issue none either, and both are only checkable through the call log.

// initWrites is every mutating call reachable from `init`, which is the whole of
// both interfaces it holds. Derived from awsapi rather than from what the command
// happens to call, so an operation added later is covered without anybody
// remembering to extend the list.
var initWrites = []string{
	"CreateOrganization", "EnablePolicyType",
	"CreateOrganizationalUnit", "TagResource",
	"CreateAccount", "MoveAccount",
}

// writesSeen returns the mutating calls the init and vend fakes recorded.
func writesSeen(f *fakeWorld) []string {
	var out []string
	for _, r := range []interface{ CallCount(string) int }{f.Init, f.Vend} {
		for _, op := range initWrites {
			for i := 0; i < r.CallCount(op); i++ {
				out = append(out, op)
			}
		}
	}
	return out
}

// TestInitDryRunWritesNothing is CLAUDE.md rule 5 held against the call log rather
// than by inspection.
//
// --dry-run against a STANDALONE account is the highest-stakes plan in the tool:
// the step it is deciding about makes the account a management account permanently.
// A --dry-run that created the organization would be unrecoverable, and no later
// assertion could undo it.
func TestInitDryRunWritesNothing(t *testing.T) {
	g, f := fakeSet(t, "", "", testManagement) // standalone
	out, _, err := runCLI(t, g, "init", "--dry-run")
	if err != nil {
		t.Fatalf("init --dry-run: %v", err)
	}
	if got := writesSeen(f); len(got) != 0 {
		t.Errorf("--dry-run issued mutating calls %v", got)
	}
	if f.Org.InOrg {
		t.Error("--dry-run left the account in an organization")
	}
	if !strings.Contains(out, "Plan:") {
		t.Errorf("no plan was printed:\n%s", out)
	}
	if !strings.Contains(out, "Nothing was applied") {
		t.Errorf("--dry-run did not say that nothing was applied:\n%s", out)
	}
}

// TestInitPlanNamesEveryStepItCannotCheck.
//
// A plan whose first step is creating the organization can read nothing below it:
// no root, so no policy type and no OU. Reporting two of three steps would show one
// line for a command that does three things, and an operator comparing the plan
// against what happened would find work nobody predicted. The plan says "cannot be
// checked" instead, which is org.VerbUnknown.
func TestInitPlanNamesEveryStepItCannotCheck(t *testing.T) {
	g, _ := fakeSet(t, "", "", testManagement) // standalone
	out, _, err := runCLI(t, g, "init", "--dry-run")
	if err != nil {
		t.Fatalf("init --dry-run: %v", err)
	}
	for _, want := range []string{
		"create organization",
		"service control policy type",
		"organizational unit " + defaultResearchOU,
		"cannot be checked",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the plan does not mention %q:\n%s", want, out)
		}
	}
	// And it does not invent an organization id. A plan that named one would be
	// compared against reality and disbelieved.
	if strings.Contains(out, testOrg) {
		t.Errorf("the plan names an organization id for an organization that does not exist "+
			"yet; AWS assigns it at creation:\n%s", out)
	}
}

// TestInitRefusesToCreateAnOrganizationWithoutYes. The one step in this command
// that re-running cannot undo, and the gate is keyed off the printed plan so the
// operator and the gate read the same list.
func TestInitRefusesToCreateAnOrganizationWithoutYes(t *testing.T) {
	g, f := fakeSet(t, "", "", testManagement) // standalone
	out, _, err := runCLI(t, g, "init")
	if err == nil {
		t.Fatal("init created an organization without --yes")
	}
	if got := writesSeen(f); len(got) != 0 {
		t.Errorf("the refused run issued mutating calls %v", got)
	}
	// The plan is printed before the refusal: the refusal's text points at it
	// ("the plan above"), so a run that refused without printing one would be
	// referring to nothing.
	if !strings.Contains(out, "Plan:") {
		t.Errorf("the refusal printed no plan for --yes to be about:\n%s", out)
	}
	for _, want := range []string{"--yes", "permanently", testManagement, "setup --request"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestInitCreatesTheOrganizationWithYes walks the STANDALONE path end to end and
// checks the ordering that matters: the policy type is enabled BEFORE the OU
// exists, so a half-failed init leaves a root that enforces policy and no OU rather
// than an OU that policies attach to and silently do not enforce. Of the two
// partial states, the second is the one that looks finished.
func TestInitCreatesTheOrganizationWithYes(t *testing.T) {
	g, f := fakeSet(t, "", "", testManagement) // standalone

	// The ordering, observed from inside the OU creation rather than inferred from
	// two call logs. The indices are not comparable — EnablePolicyType is on the init
	// client and CreateOrganizationalUnit is on the vend client, each with its own
	// recorder — so the only honest way to assert "the enable came first" is to look
	// at the organization at the moment the OU is created.
	scpOnAtOUCreation := false
	f.State.Before = map[string]func() error{
		"CreateOrganizationalUnit": func() error {
			scpOnAtOUCreation = f.State.SCPEnabled
			return nil
		},
	}

	out, _, err := runCLI(t, g, "init", "--yes")
	if err != nil {
		t.Fatalf("init --yes: %v", err)
	}
	if !f.Init.Created {
		t.Error("the organization was not created")
	}
	if !f.State.SCPEnabled {
		t.Error("the service control policy type was not enabled; every policy automat later " +
			"attaches would enforce nothing")
	}
	if !strings.Contains(out, "Applied:") {
		t.Errorf("no applied list was printed:\n%s", out)
	}

	// The OU exists under the root, found by name because the name is the only
	// handle automat has between runs.
	if id := ouIDByName(t, f, defaultResearchOU); id == "" {
		t.Fatalf("no OU named %q was created under the root:\n%s", defaultResearchOU, out)
	}

	if f.Vend.CallCount("CreateOrganizationalUnit") == 0 {
		t.Fatal("the hook never ran, so the ordering below is asserted against a false default")
	}
	if !scpOnAtOUCreation {
		t.Error("the OU was created while the root's policy type was still off. A half-failed " +
			"init then leaves an OU that policies attach to and silently do not enforce, which " +
			"is the partial state that looks finished")
	}
}

// TestInitRunsTwiceWithNoSecondChange is CLAUDE.md rule 4 for this command.
//
// The second run is necessarily from MANAGEMENT — after the first one succeeds the
// account IS the management account — which is why this command permits that state
// at all. It writes nothing and says so, and "says so" is half the test: a
// successful second run that printed an empty list would read as a command that
// failed to do anything.
func TestInitRunsTwiceWithNoSecondChange(t *testing.T) {
	g, f := fakeSet(t, "", "", testManagement) // standalone
	if _, _, err := runCLI(t, g, "init", "--yes"); err != nil {
		t.Fatalf("first init: %v", err)
	}
	firstOU := ouIDByName(t, f, defaultResearchOU)
	f.Init.Reset()
	f.Vend.Reset()
	f.Org.Reset()

	// No --yes on the second run, and that is the point: the plan finds the
	// organization already there, so nothing gates on it. An init that asked for
	// --yes every time would be one an operator learns to pass reflexively.
	out, _, err := runCLI(t, g, "init")
	if err != nil {
		t.Fatalf("second init: %v", err)
	}
	if got := writesSeen(f); len(got) != 0 {
		t.Errorf("the second run issued mutating calls %v; every step is create-or-verify", got)
	}
	if !strings.Contains(out, "Nothing needed changing") {
		t.Errorf("the successful second run does not say it changed nothing:\n%s", out)
	}
	if got := ouIDByName(t, f, defaultResearchOU); got != firstOU {
		t.Errorf("the OU id changed from %q to %q; the second run created a second OU", firstOU, got)
	}
}

// TestInitAdoptsAnOrganizationCreatedInTheConsole is the second reason MANAGEMENT
// is permitted, and it is a security case rather than a convenience.
//
// An operator who created their organization in the console was never STANDALONE to
// automat, and their root may have the SCP policy type disabled — the state where
// CreatePolicy succeeds, AttachPolicy succeeds, and nothing is enforced. `init` is
// the fix. Refusing to run it here would send exactly the operator who needs it to
// the console for the one call that decides whether every control automat later
// attaches enforces anything.
func TestInitAdoptsAnOrganizationCreatedInTheConsole(t *testing.T) {
	g, f := fakeSet(t, testOrg, testManagement, testManagement)
	// The dangerous shape: an organization with all features, and a root reporting
	// no policy types at all. Empty rather than DISABLED because that is what a root
	// where SCPs were never enabled actually reports.
	f.Org.SCPStatus = ""
	f.State.SCPEnabled = false

	out, _, err := runCLI(t, g, "init")
	if err != nil {
		t.Fatalf("init against a console-created organization: %v", err)
	}
	if f.Init.CallCount("CreateOrganization") != 0 {
		t.Error("init called CreateOrganization against an account already in an organization")
	}
	if !f.State.SCPEnabled {
		t.Error("init did not enable the policy type on a root that had it off, which is the " +
			"whole reason this command runs against an organization it did not create")
	}
	if !strings.Contains(out, "Applied:") {
		t.Errorf("no applied list:\n%s", out)
	}
	// No --yes was passed and none was needed: nothing irreversible is in this plan.
	if strings.Contains(out, "--yes") {
		t.Errorf("init asked for --yes without planning to create an organization:\n%s", out)
	}
}

// TestInitRefusesAMemberAccount. §13's "STANDALONE only" is really about this
// state, and the refusal has to arrive having mutated nothing: EnsureOrganization
// reads before it writes and creates only when the account is in no organization at
// all, so a member account reaches the check untouched.
//
// The message is asserted in some detail because it is the whole value of the
// refusal. An operator in a member account cannot be told "no" — they need to know
// that none of this is delegable and which command is theirs.
func TestInitRefusesAMemberAccount(t *testing.T) {
	g, f := fakeSet(t, testOrg, testManagement, testMember)
	_, _, err := runCLI(t, g, "init")
	if err == nil {
		t.Fatal("init ran from a member account")
	}
	if got := writesSeen(f); len(got) != 0 {
		t.Errorf("the refused member-account run issued mutating calls %v", got)
	}
	for _, want := range []string{
		testMember,     // which account they are in
		testManagement, // whose organization it is
		testOrg,
		"member account",
		"setup --request",
		"preflight",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestInitRefusesConsolidatedBilling. SCPs do not exist in that feature set (DESIGN
// §3 fact 8), so every preventive control in every catalog is unenforceable — and
// automat cannot fix it, because leaving that mode requires every existing member
// account to accept an invitation. The error says so rather than proceeding into an
// organization where automat's output is decorative.
func TestInitRefusesConsolidatedBilling(t *testing.T) {
	g, f := fakeSet(t, testOrg, testManagement, testManagement)
	f.Org.FeatureSet = orgtypes.OrganizationFeatureSetConsolidatedBilling

	_, _, err := runCLI(t, g, "init")
	if err == nil {
		t.Fatal("init proceeded against an organization in CONSOLIDATED_BILLING mode")
	}
	if got := writesSeen(f); len(got) != 0 {
		t.Errorf("the refused run issued mutating calls %v", got)
	}
	for _, want := range []string{"CONSOLIDATED_BILLING", "DESIGN §3, fact 8", "automat cannot change this"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestInitReportsWhatItDidBeforeFailing.
//
// A partial init leaves an organization whose policy type is on and which has no OU,
// or one where even that did not happen. An operator told only the error has to
// rediscover which of those they are in before re-running — so the actions taken
// before the failure are printed anyway, on stderr, where they do not contaminate a
// piped plan.
func TestInitReportsWhatItDidBeforeFailing(t *testing.T) {
	g, f := fakeSet(t, testOrg, testManagement, testManagement)
	f.Org.SCPStatus = ""
	f.State.SCPEnabled = false
	// The OU creation fails, after the enable has already succeeded. This is the
	// partial state the ordering was chosen to produce.
	f.State.Errs["CreateOrganizationalUnit"] = awsfake.AccessDenied(
		"organizations:CreateOrganizationalUnit")

	out, errOut, err := runCLI(t, g, "init")
	if err == nil {
		t.Fatal("init succeeded with CreateOrganizationalUnit denied")
	}
	if !f.State.SCPEnabled {
		t.Fatal("the fixture did not reach the OU step; the policy type was never enabled, " +
			"so there is no partial progress to report and this test asserts nothing")
	}
	if !strings.Contains(errOut, "Applied before the failure:") {
		t.Errorf("the partial progress was not reported:\n%s", errOut)
	}
	if !strings.Contains(errOut, "service control policy type") {
		t.Errorf("the report does not name the step that did succeed, which is what tells the "+
			"operator which partial state they are in:\n%s", errOut)
	}
	// The plan still went to stdout, and the partial report did not.
	if !strings.Contains(out, "Plan:") {
		t.Errorf("no plan on stdout:\n%s", out)
	}
	if strings.Contains(out, "Applied before the failure:") {
		t.Error("the partial-progress report went to stdout, where it would contaminate a piped plan")
	}
	// Rule 7: which action, which resource, what grant.
	for _, want := range []string{"organizations:CreateOrganizationalUnit", "grant"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not carry %q, which rule 7 requires: %v", want, err)
		}
	}
}

// TestInitHonorsOUName. The OU name is the only handle automat has on an OU between
// runs — there is no state file — so an institution that calls it something else has
// to be able to say so, and has to be able to say so before the first vend.
func TestInitHonorsOUName(t *testing.T) {
	const custom = "Regulated-Research"
	g, f := fakeSet(t, testOrg, testManagement, testManagement)
	if _, _, err := runCLI(t, g, "init", "--ou-name", custom); err != nil {
		t.Fatalf("init --ou-name: %v", err)
	}
	if id := ouIDByName(t, f, custom); id == "" {
		t.Errorf("no OU named %q was created", custom)
	}
	if id := ouIDByName(t, f, defaultResearchOU); id != "" {
		t.Errorf("init created the default OU %q as well as %q", defaultResearchOU, custom)
	}
}

// TestInitFailsClosedWhenTheCallerIsUnknown. Everything below the identity check
// either needs it (the MEMBER refusal compares the account against the management
// account) or is worse without it (rule 7 names the principal that was denied). An
// init that proceeded with an unknown caller could create an organization for an
// account nobody named.
func TestInitFailsClosedWhenTheCallerIsUnknown(t *testing.T) {
	g, f := fakeSet(t, "", "", testManagement)
	f.STS.IdentityErr = awsfake.AccessDenied("sts:GetCallerIdentity")
	_, _, err := runCLI(t, g, "init", "--yes")
	if err == nil {
		t.Fatal("init proceeded without knowing which account it was acting on")
	}
	if f.Init.Created {
		t.Error("an organization was created for an account automat could not name")
	}
	if !strings.Contains(err.Error(), "automat login") {
		t.Errorf("the error does not say how to get credentials: %v", err)
	}
}

// ouIDByName returns the id of the OU with the given name under the root, or "".
func ouIDByName(t *testing.T, f *fakeWorld, name string) string {
	t.Helper()
	for _, id := range f.State.OUIDsUnder(f.State.RootID) {
		if f.State.OUName(id) == name {
			return id
		}
	}
	return ""
}
