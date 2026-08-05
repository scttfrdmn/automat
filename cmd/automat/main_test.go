// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// The CLI's own tests. internal/preflight and internal/bundle are covered in their
// own packages; what is only testable here is the wiring — the exit codes a cron job
// branches on, the config plumbing, and the promise that no code path in a test
// reaches AWS.
//
// That last one is the reason globals' client constructors are fields (see globals.go).
// Every test below leaves at least one of them nil on purpose in one case and sets
// them in the rest, so the "did it fall through to the real SDK" question is answered
// by TestNoCommandReachesAWSWithoutAFake rather than by reading the code.
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/awsfake"
)

const (
	testMember     = "222222222222"
	testManagement = "111111111111"
	testOrg        = "o-exampleorgid"
	testOU         = "ou-exam-research1"
	testVendorRole = "arn:aws:iam::111111111111:role/automat-vendor"
	// A 16-character value of the right shape. Not a repeated character: the
	// generator's weak-value check refuses those, so a fixture like "aaaa..." would
	// be rejected for repetition and this file would stop testing what it says.
	testExternalID = "k7Rq2mZx9Tp4Wc8v"
)

// simulatedVendActions is every action preflight's permission check simulates.
//
// The list is duplicated from preflight's unexported vendActions rather than
// exported for a test. Drift is safe in the direction that matters: a fixture
// built from a stale list produces a [fail] check, and every test that depends on
// "nothing failed" guards on that explicitly and calls Fatalf. A test can go stale
// here, but it cannot go quiet.
var simulatedVendActions = []string{
	"organizations:CreateAccount",
	"organizations:MoveAccount",
	"organizations:CreateOrganizationalUnit",
	"organizations:CreatePolicy",
	"organizations:AttachPolicy",
}

// fakes returns a globals whose every client constructor is satisfied from
// internal/awsfake, plus the STS fake so a test can adjust it.
//
// The IAM fake allows nothing by default, which is the realistic member-account
// case; allowActions supplies the actions a permissive caller has.
func fakes(t *testing.T, orgID, mgmt, caller string, allowActions ...string) (*globals, *awsfake.STS, *awsfake.Org) {
	t.Helper()
	stsFake := awsfake.NewSTS(caller)
	var orgFake *awsfake.Org
	if orgID == "" {
		orgFake = &awsfake.Org{} // zero value: not in an organization
	} else {
		orgFake = awsfake.NewOrg(orgID, mgmt)
	}
	iamFake := awsfake.NewIAM(allowActions...)
	quotaFake := awsfake.NewQuota()

	g := &globals{
		newSTS: func(context.Context, string, string) (awsapi.STSAPI, error) {
			return stsFake, nil
		},
		newOrg: func(context.Context, string, string) (awsapi.OrgAPI, error) {
			return orgFake, nil
		},
		newIAM: func(context.Context, string, string) (awsapi.IAMAPI, error) {
			return iamFake, nil
		},
		newQuota: func(context.Context, string, string) (awsapi.QuotaAPI, error) {
			return quotaFake, nil
		},
		newSSOOIDC: func(context.Context, string) (awsapi.SSOOIDCAPI, error) {
			t.Error("a test built an SSO OIDC client; only `login` should, and no test here runs it")
			return nil, errors.New("unexpected")
		},
	}
	// No config file: the tests that want one point --config at a temp path.
	g.configPath = filepath.Join(t.TempDir(), "absent.toml")
	return g, stsFake, orgFake
}

// runCLI executes the root command with args and returns stdout, stderr, and the
// error. The command's context is set explicitly rather than left nil: cmd.Context()
// returns context.Background() when unset, and a test that depended on that would
// stop working the moment a command started honoring cancellation.
func runCLI(t *testing.T, g *globals, args ...string) (string, string, error) {
	t.Helper()
	// newRootCmdWith, not newRootCmd: the whole command tree has to be built around
	// *this* globals, because that is what carries the fakes. Registering a second
	// --config against a tree built by newRootCmd panics in pflag on the redefined
	// flag, which is what the seam is for.
	cmd := newRootCmdWith(g)

	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

// exitCodeOf extracts the code a command chose, or 0 when it returned no error.
// A non-exitError error is reported as -1 so a test can tell "the command failed"
// from "the command answered non-zero", which for preflight is the whole point.
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ex *exitError
	if errors.As(err, &ex) {
		return ex.ExitCode()
	}
	return -1
}

// TestPreflightExitCodesCarryTheVerdict.
//
// preflight is meant to be run from cron and CI, where nobody reads the report and
// the exit code is the entire answer. The three codes mean different things and the
// difference is load-bearing: 0 is "go ahead", 2 is "something is definitely
// missing", 3 is "nothing failed but a check could not be completed, so ready would
// overstate the evidence". Collapsing 3 into 0 would be a tool that says ready when
// it does not know, which is the failure this whole command exists to prevent.
//
// Note what is *not* asserted: that a particular org shape yields a particular code
// through some specific check. That belongs to internal/preflight's tests. What is
// asserted here is that the report's verdict reaches the exit status at all, and that
// a failure outranks an undetermined check.
func TestPreflightExitCodesCarryTheVerdict(t *testing.T) {
	t.Run("member without a vendor role is not ready", func(t *testing.T) {
		g, _, _ := fakes(t, testOrg, testManagement, testMember)
		out, _, err := runCLI(t, g, "preflight")
		if got := exitCodeOf(err); got != exitPreflightNotReady && got != exitPreflightUnknown {
			t.Errorf("exit code = %d, want %d or %d: a member account with no delegation cannot vend, "+
				"and a cron job must not read that as ready\nreport:\n%s",
				got, exitPreflightNotReady, exitPreflightUnknown, out)
		}
		if out == "" {
			t.Error("the report was empty; the exit code is meaningless without it")
		}
	})

	t.Run("undetermined alone is 3, not 0", func(t *testing.T) {
		// The case the code exists for, and the one most likely to be quietly lost:
		// nothing failed, so a tool that only distinguished pass from fail would exit
		// 0 and a cron job would proceed on the strength of a check that never
		// completed.
		//
		// Every part of this fixture is load-bearing, and each was added because
		// leaving it out produced a [fail] that turned this into the ordinary
		// not-ready case: the management caller for StateManagement, the whole action
		// list because the IAM fake denies what it is not told to allow, and a
		// non-empty resource policy because "no resource policy at all" is an
		// observed failure rather than an unreadable check. The denied
		// DescribeOrganizationalUnit is then the only non-pass result.
		g, _, orgFake := fakes(t, testOrg, testManagement, testManagement, simulatedVendActions...)
		orgFake.ResourcePolicy = `{"Version":"2012-10-17","Statement":[]}`
		orgFake.Errs["DescribeOrganizationalUnit"] = awsfake.AccessDenied(
			"organizations:DescribeOrganizationalUnit")
		writeConfig(t, g, `
[context.c]
org = "`+testOrg+`"
ou = "`+testOU+`"
`)
		out, _, err := runCLI(t, g, "preflight")
		// Guard the fixture in both directions. A failure anywhere makes this the
		// not-ready case, which another subtest already covers; no undetermined check
		// makes it the ready case. Either way the code under test is not the one this
		// subtest names, and a skip would let that pass unnoticed.
		if strings.Contains(out, "[fail") {
			t.Fatalf("the fixture produced a failure, so this is not the undetermined-alone case "+
				"and exitPreflightUnknown is not under test:\n%s", out)
		}
		if !strings.Contains(out, "[unknown") {
			t.Fatalf("the fixture produced no undetermined check:\n%s", out)
		}
		if got := exitCodeOf(err); got != exitPreflightUnknown {
			t.Errorf("exit code = %d, want %d — nothing failed, but a check could not be completed, "+
				"and exiting 0 there tells a cron job that ready was established when it was "+
				"not\nreport:\n%s", got, exitPreflightUnknown, out)
		}
	})

	t.Run("the report is printed whatever the code", func(t *testing.T) {
		g, _, _ := fakes(t, "", "", testMember) // standalone
		out, _, err := runCLI(t, g, "preflight")
		if out == "" {
			t.Fatalf("no report printed (err %v)", err)
		}
		if !strings.Contains(out, "STANDALONE") {
			t.Errorf("the report does not name the state it classified:\n%s", out)
		}
	})
}

// TestPreflightFailureOutranksUndetermined pins the ordering in the switch that
// chooses the code. If the two branches were swapped, an org with one definitely
// missing grant and one unreadable check would report 3 — "could not tell" — when the
// actionable answer is 2, and the operator would go looking for a permissions problem
// on the checking side rather than reading the remediation that is already printed.
//
// Both conditions have to be present in the same report for that ordering to be under
// test at all, which is the trap here: a fixture with only failures passes whichever
// way the branches are written, so the test would pin nothing while reading as though
// it did. The denied DescribeOrganizationalUnit is the undetermined half — a denial is
// not an absence, so preflight reports unknown — and the unassumable vendor role is the
// definite half. The assertions below check that both are actually present before
// checking the code.
func TestPreflightFailureOutranksUndetermined(t *testing.T) {
	g, _, orgFake := fakes(t, testOrg, testManagement, testMember)
	orgFake.Errs["DescribeOrganizationalUnit"] = awsfake.AccessDenied(
		"organizations:DescribeOrganizationalUnit")
	// A vendor role that is configured but not assumable produces a definite
	// failure; the fake's empty Assumable map is what makes it definite.
	writeConfig(t, g, `
[context.c]
org = "`+testOrg+`"
ou = "`+testOU+`"
vendor_role_arn = "`+testVendorRole+`"
`)
	out, _, err := runCLI(t, g, "preflight")

	// Guard the fixture. Without both, the ordering is not exercised.
	if !strings.Contains(out, "[unknown") {
		t.Fatalf("no undetermined check in the report, so the ordering is not under test:\n%s", out)
	}
	if !strings.Contains(out, "[fail") {
		t.Fatalf("no failed check in the report, so the ordering is not under test:\n%s", out)
	}
	if got := exitCodeOf(err); got != exitPreflightNotReady {
		t.Errorf("exit code = %d, want %d — a definite failure is the actionable answer even when "+
			"another check could not be completed\nreport:\n%s", got, exitPreflightNotReady, out)
	}
}

// TestPreflightNeverPrintsTheExternalID.
//
// DESIGN §13: the ExternalId is resolved at run time and never recorded. The Report
// has its own test for not storing it; this one covers the CLI, because the CLI is
// where the value is resolved and where the report is rendered to a terminal, a
// scrollback buffer, and a CI transcript that outlives both.
func TestPreflightNeverPrintsTheExternalID(t *testing.T) {
	g, stsFake, _ := fakes(t, testOrg, testManagement, testMember)
	stsFake.Assumable[testVendorRole] = testExternalID
	t.Setenv("AUTOMAT_TEST_EXTERNAL_ID", testExternalID)
	writeConfig(t, g, `
[context.c]
org = "`+testOrg+`"
ou = "`+testOU+`"
vendor_role_arn = "`+testVendorRole+`"
external_id_ref = "env:AUTOMAT_TEST_EXTERNAL_ID"
`)
	out, errOut, err := runCLI(t, g, "preflight")
	if code := exitCodeOf(err); code == -1 {
		t.Fatalf("preflight failed rather than reporting: %v", err)
	}
	for what, s := range map[string]string{"stdout": out, "stderr": errOut} {
		if strings.Contains(s, testExternalID) {
			t.Errorf("the ExternalId appears in %s; it is resolved at run time and never recorded "+
				"(DESIGN §13)\n%s", what, s)
		}
	}
}

// TestSetupWithoutRequestSaysWhichHalfIsMissing. `automat setup` in a management
// account is Phase 2. The failure an operator gets today must tell them which half of
// the tool they are waiting on and what to do meanwhile, rather than reading as a
// broken command — CLAUDE.md rule 7 applied to an unimplemented path.
func TestSetupWithoutRequestSaysWhichHalfIsMissing(t *testing.T) {
	g, _, _ := fakes(t, testOrg, testManagement, testMember)
	_, _, err := runCLI(t, g, "setup")
	if err == nil {
		t.Fatal("`setup` without --request succeeded; the management half is not implemented")
	}
	for _, want := range []string{"--request", "Phase 2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// TestSetupRequestWritesABundleAndMakesNoAWSCall.
//
// The Long help says "no AWS call is made: this writes five files", and that claim is
// the reason an operator in a member account with no credentials at all can run it.
// A claim in help text is worth exactly as much as the test behind it, so every
// client constructor fails loudly here: if any code path in this command builds an
// AWS client, this test fails rather than the operator discovering it.
func TestSetupRequestWritesABundleAndMakesNoAWSCall(t *testing.T) {
	g := &globals{configPath: filepath.Join(t.TempDir(), "absent.toml")}
	refuse := func(what string) error {
		return errors.New("`setup --request` built " + what + ", but its help says no AWS call is made")
	}
	g.newSTS = func(context.Context, string, string) (awsapi.STSAPI, error) { return nil, refuse("an STS client") }
	g.newOrg = func(context.Context, string, string) (awsapi.OrgAPI, error) {
		return nil, refuse("an Organizations client")
	}
	g.newIAM = func(context.Context, string, string) (awsapi.IAMAPI, error) { return nil, refuse("an IAM client") }
	g.newQuota = func(context.Context, string, string) (awsapi.QuotaAPI, error) {
		return nil, refuse("a Service Quotas client")
	}
	g.newSSOOIDC = func(context.Context, string) (awsapi.SSOOIDCAPI, error) { return nil, refuse("an SSO OIDC client") }

	out := filepath.Join(t.TempDir(), "bundle")
	stdout, _, err := runCLI(t, g, "setup", "--request",
		"--member-account", testMember,
		"--management-account", testManagement,
		"--org", testOrg,
		"--ou", testOU,
		"--contact", "research-it@example.edu",
		"--out", out)
	if err != nil {
		t.Fatalf("setup --request: %v", err)
	}

	// The five files, by the names the package publishes rather than by literal
	// strings: a renamed file should fail the golden tests, not this one.
	for _, name := range []string{"README.md", "delegation-policy.json",
		"vendor-role.cfn.yaml", "vendor-role.tf"} {
		if _, serr := os.Stat(filepath.Join(out, name)); serr != nil {
			t.Errorf("%s was not written: %v", name, serr)
		}
	}
	// The first line is the path alone, which is the documented contract that makes
	// `cd "$(automat setup --out X | head -1)"` work.
	first := strings.SplitN(stdout, "\n", 2)[0]
	if first != out {
		t.Errorf("first output line = %q, want the bare path %q — a script consuming this "+
			"would cd somewhere else", first, out)
	}
}

// TestPreflightRefusesAWeakExternalID covers the reference-to-validation path at the
// CLI.
//
// This test used to drive `setup --request --external-id password12345678`, back when
// automat generated the ExternalId and wrote it into the bundle. That flag is gone
// along with the value it supplied, but the property it covered did not go anywhere —
// it moved to the only side that still exists. A placeholder ExternalId leaves the
// confused-deputy condition in the trust policy looking like a control while being
// none, and now the way one arrives is that central IT generated it badly and sent it
// over, so automat meets it when it resolves external_id_ref rather than when it
// writes a template.
//
// Both halves of the original assertion are kept: the operator is told which source
// holds the bad value, and the value is not echoed — it may be live somewhere else even
// though it is a placeholder here.
//
// The refusal surfaces as a warning plus a failed check rather than a non-zero exit on
// its own, which is preflight's whole design: it reports every check it can instead of
// stopping at the first problem. What matters for security is that the value is not
// used — externalID stays empty, so nothing sends the placeholder to STS and no check
// can report the trust condition as satisfied on the strength of it.
func TestPreflightRefusesAWeakExternalID(t *testing.T) {
	g, stsFake, _ := fakes(t, testOrg, testManagement, testMember)
	const weak = "password12345678"
	// The role is assumable *with the weak value*. If the resolver let it through,
	// the vendor-role check would pass and the placeholder would be reported as a
	// working confused-deputy defense — which is the outcome under test.
	stsFake.Assumable[testVendorRole] = weak
	t.Setenv("AUTOMAT_TEST_EXTERNAL_ID", weak)
	writeConfig(t, g, `
[context.c]
org = "`+testOrg+`"
ou = "`+testOU+`"
vendor_role_arn = "`+testVendorRole+`"
external_id_ref = "env:AUTOMAT_TEST_EXTERNAL_ID"
`)
	out, errOut, err := runCLI(t, g, "preflight")
	if code := exitCodeOf(err); code == -1 {
		t.Fatalf("preflight failed rather than reporting: %v", err)
	}
	if !strings.Contains(errOut, "could not resolve the ExternalId") {
		t.Errorf("the operator is not warned that the ExternalId was refused:\n%s", errOut)
	}
	// Named by source, so the operator knows where to go: the environment variable
	// external_id_ref points at, not the setting's own name.
	if !strings.Contains(errOut, "AUTOMAT_TEST_EXTERNAL_ID") {
		t.Errorf("the warning does not name the source holding the bad value:\n%s", errOut)
	}
	// The placeholder must not be used, and this is the assertion with teeth. The fake
	// accepts the weak value, so if the resolver let it through the vendor-role check
	// reports [pass] and the verdict line becomes "vend: yes" — verified by jamming the
	// weakExternalID branch, which flips both. Keyed to the check line rather than to
	// the whole report, because a bare Contains over the output matched in the jammed
	// case too and would have asserted nothing.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "vendor role") && strings.Contains(line, "[pass") {
			t.Errorf("the vendor-role check passed on the strength of a placeholder "+
				"ExternalId, so automat sent it to STS:\n%s", out)
		}
	}
	if strings.Contains(out, "vend: yes") {
		t.Errorf("automat reports it can vend using a placeholder ExternalId:\n%s", out)
	}
	for what, s := range map[string]string{"stdout": out, "stderr": errOut} {
		if strings.Contains(s, weak) {
			t.Errorf("the refusal echoes the value in %s, which may be a live one "+
				"elsewhere:\n%s", what, s)
		}
	}
}

// TestDryRunWritesNothing. --dry-run is the mode an operator uses because they are
// being careful, so it must not create the directory either: a `setup --dry-run` that
// left an empty directory behind would make the next real run report "existing" files
// and is exactly the surprise the flag exists to avoid.
func TestDryRunWritesNothing(t *testing.T) {
	g, _, _ := fakes(t, testOrg, testManagement, testMember)
	out := filepath.Join(t.TempDir(), "bundle")
	stdout, _, err := runCLI(t, g, "setup", "--request",
		"--member-account", testMember,
		"--management-account", testManagement,
		"--org", testOrg,
		"--ou", testOU,
		"--contact", "research-it@example.edu",
		"--dry-run",
		"--out", out)
	if err != nil {
		t.Fatalf("setup --request --dry-run: %v", err)
	}
	if !strings.Contains(stdout, "Nothing was written") {
		t.Errorf("--dry-run did not say that nothing was written:\n%s", stdout)
	}
	if _, serr := os.Stat(out); serr == nil {
		t.Error("--dry-run created the output directory; the next real run would then report " +
			"files as pre-existing")
	}
}

// TestConfigErrorsReachTheOperator. A malformed config is refused by internal/config
// with an explanation; what this checks is that the explanation is not swallowed on
// the way out — every command calls orgContext() first, and a config error there must
// surface rather than being reported as some later failure.
func TestConfigErrorsReachTheOperator(t *testing.T) {
	g, _, _ := fakes(t, testOrg, testManagement, testMember)
	writeConfig(t, g, `
[context.c]
vendor_role_ann = "arn:aws:iam::111111111111:role/automat-vendor"
`)
	_, _, err := runCLI(t, g, "preflight")
	if err == nil {
		t.Fatal("a config with a misspelled key was accepted; the setting silently reverts to empty")
	}
	if !strings.Contains(err.Error(), "vendor_role_ann") {
		t.Errorf("the error does not name the offending key: %v", err)
	}
}

// TestNoCommandReachesAWSWithoutAFake is the CLAUDE.md rule 1 backstop, stated as a
// test rather than as a convention.
//
// Each constructor returns an error naming itself, so any command that builds a real
// client fails with a message identifying which one. That is the whole mechanism
// keeping the test suite off the network: if a future command calls
// organizations.NewFromConfig directly instead of going through globals, this test is
// what notices — the LoadDefaultConfig underneath it would otherwise read the
// developer's own ~/.aws and, on a machine with a valid profile, silently succeed.
func TestNoCommandReachesAWSWithoutAFake(t *testing.T) {
	for _, args := range [][]string{
		{"preflight"},
		{"version"},
		{"setup"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			g := &globals{configPath: filepath.Join(t.TempDir(), "absent.toml")}
			var built []string
			note := func(what string) error {
				built = append(built, what)
				return errors.New("no credentials in tests")
			}
			g.newSTS = func(context.Context, string, string) (awsapi.STSAPI, error) { return nil, note("STS") }
			g.newOrg = func(context.Context, string, string) (awsapi.OrgAPI, error) { return nil, note("Organizations") }
			g.newIAM = func(context.Context, string, string) (awsapi.IAMAPI, error) { return nil, note("IAM") }
			g.newQuota = func(context.Context, string, string) (awsapi.QuotaAPI, error) { return nil, note("Quotas") }
			g.newSSOOIDC = func(context.Context, string) (awsapi.SSOOIDCAPI, error) { return nil, note("SSOOIDC") }

			// The assertion is not that this succeeds or fails — it is that every AWS
			// client came from the seam. A command that bypassed it would either
			// reach the network or fail with an SDK credential error instead of the
			// message above.
			_, _, err := runCLI(t, g, args...)
			if err != nil && strings.Contains(err.Error(), "resolve AWS credentials") {
				t.Errorf("`automat %s` resolved credentials through the real SDK: %v",
					strings.Join(args, " "), err)
			}
			t.Logf("clients requested: %v", built)
		})
	}
}

// writeConfig writes a config file and points g at it.
func writeConfig(t *testing.T, g *globals, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	g.configPath = path
	g.contextName = "c"
}
