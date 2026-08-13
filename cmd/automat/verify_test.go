// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/evidence"
)

// verifyArgs is the common flag set.
func verifyArgs(profilePath, accountID string) []string {
	return []string{
		"verify",
		"--environment-profile", profilePath,
		"--account", accountID,
	}
}

// vendThenVerify vends one account against profile and returns its id, ready
// for a verify test to check immediately afterward — the same organization,
// the same working directory, so the evidence manifest verify writes lands
// beside the one vend already wrote.
func vendThenVerify(t *testing.T, g *globals, f *fakeWorld, profile string) string {
	t.Helper()
	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend: %v", err)
	}
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("vend produced %d accounts, want 1: %v", len(accounts), accounts)
	}
	return accounts[0]
}

// TestVerifyCleanRightAfterVend is the property the whole command exists to
// hold: an account this binary just vended, checked immediately afterward,
// reports clean. If this fails, either the packer and the checker disagree
// about what "the same compile" means, or org.SameDocument's reformatting
// tolerance does not actually cover what Organizations' fakes return.
func TestVerifyCleanRightAfterVend(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	out, _, err := runCLI(t, g, verifyArgs(profile, accountID)...)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out, "matches") {
		t.Errorf("verify did not report any policy as matching:\n%s", out)
	}
	if strings.Contains(out, "NOT ATTACHED") || strings.Contains(out, "differs") {
		t.Errorf("verify reported drift against an account it just vended:\n%s", out)
	}
}

// TestVerifyFromMemberReadsThroughTheDelegatedIdentity is the MEMBER-state
// counterpart: the delegation policy already grants DescribePolicy,
// ListPoliciesForTarget, and ListTagsForResource (internal/bundle/policy.go's
// readActions), so verify's POLICY layer's read must succeed WITHOUT the
// vendor role ever being assumed — that layer never brokers, unlike vend's
// account/OU half.
//
// AssumeRole's total count DOES rise here, and that is expected rather than
// a regression: the detective layer (verify.CheckDetective,
// configVerifyClient) assumes OrganizationAccountAccessRole into the CHILD
// account to read back the Config recorder/delivery channel/conformance
// pack — the identical non-brokered, no-ExternalId assumption vend's own
// baseline steps make (childConfigClient's doc comment), not the brokered
// vendor-role one. What this test pins is that the vendor role's OWN
// ExternalId is never sent a second time by verify — LastAssumeRole is
// captured before verify runs and compared after, so a vendor-role
// assumption (which WOULD carry an ExternalId) is what would fail this,
// not the automation-role one (which carries none).
func TestVerifyFromMemberReadsThroughTheDelegatedIdentity(t *testing.T) {
	g, f := vendMemberWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	f.STS.LastAssumeRole = nil

	out, _, err := runCLI(t, g, verifyArgs(profile, accountID)...)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out, "matches") {
		t.Errorf("verify did not report any policy as matching:\n%s", out)
	}
	if f.STS.LastAssumeRole != nil && aws.ToString(f.STS.LastAssumeRole.ExternalId) != "" {
		t.Errorf("verify's last AssumeRole carried an ExternalId, which means it assumed the "+
			"BROKERED vendor role rather than reading through the delegated identity or the "+
			"in-child automation-role assumption (neither of which sends one): %+v",
			f.STS.LastAssumeRole)
	}
}

// TestVerifyReportsDrift catches a hand-edited SCP the way the plan's Task 1
// scoping promised: an operator (or another tool) changes what a policy
// automat attached actually says, and verify must notice.
func TestVerifyReportsDrift(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	names := f.State.PolicyNames()
	if len(names) == 0 {
		t.Fatal("the vend attached no policies; nothing for this test to drift")
	}
	id := f.State.PolicyIDByName(names[0])
	f.State.SetPolicyContent(id, `{"Version":"2012-10-17","Statement":[{"Sid":"HandEdited","Effect":"Deny","Action":"s3:*","Resource":"*"}]}`)

	out, _, err := runCLI(t, g, verifyArgs(profile, accountID)...)
	if err == nil {
		t.Fatal("verify succeeded against a hand-edited policy, want a non-zero exit for drift")
	}
	if code := exitCodeOf(err); code != exitVerifyDrift {
		t.Errorf("exit code = %d, want %d (exitVerifyDrift)", code, exitVerifyDrift)
	}
	if !strings.Contains(out, "differs") {
		t.Errorf("verify's output does not mention the drift:\n%s", out)
	}
}

// TestVerifyLapsedReviewByWarnsNotFails holds DESIGN §11a/§12's rule: a
// lapsed review_by is a warning, and warnings do not change the exit code —
// only the policy layer's own findings do (TestVerifyReportsDrift covers
// that side).
func TestVerifyLapsedReviewByWarnsNotFails(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, func(doc map[string]any) {
		doc["review_by"] = "2020-01-01"
	})
	accountID := vendThenVerify(t, g, f, profile)

	out, _, err := runCLI(t, g, verifyArgs(profile, accountID)...)
	if err != nil {
		t.Fatalf("verify with a lapsed review_by returned an error, want a clean exit: %v", err)
	}
	if !strings.Contains(out, "has passed") {
		t.Errorf("verify did not warn about the lapsed review_by:\n%s", out)
	}
}

// TestVerifyReportsDetectiveAndProceduralLayers holds ROADMAP.md's
// "internal/baseline, slices 2-9" item 9 in the running binary: an account
// this binary just vended, with a Config recorder and a conformance pack
// (vendProfileJSON's default profile enables both) and procedural controls
// (cmmc-l1 compiles several), must report BOTH new layers as clean in
// verify's own output — not "not checked", the old claim this test replaces
// now that internal/baseline exists and vend actually installs what these
// layers check.
func TestVerifyReportsDetectiveAndProceduralLayers(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	out, _, err := runCLI(t, g, verifyArgs(profile, accountID)...)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out, "Detective layer:") {
		t.Errorf("verify's output has no detective-layer section:\n%s", out)
	}
	if !strings.Contains(out, "Config recorder: present, recording, matches") {
		t.Errorf("verify did not report the Config recorder as clean:\n%s", out)
	}
	if !strings.Contains(out, "Conformance pack") || !strings.Contains(out, "present, matches") {
		t.Errorf("verify did not report the conformance pack as present and matching:\n%s", out)
	}
	if !strings.Contains(out, "Procedural layer:") {
		t.Errorf("verify's output has no procedural-layer section:\n%s", out)
	}
	if !strings.Contains(out, "present, current") {
		t.Errorf("verify did not report any attestation stub as present and current:\n%s", out)
	}
	if strings.Contains(out, "not checked in this build") {
		t.Errorf("verify still claims the detective/procedural layers are unchecked:\n%s", out)
	}
}

// TestVerifyReportsDetectiveDriftAsAFailedOutcome is
// TestVerifyRecordsDriftAsAFailedOutcome's detective-layer counterpart: a
// hand-edited (or out-of-band) recorder — RecorderRunning flipped false,
// simulating an operator who ran `stop-configuration-recorder` outside
// automat — must fail this run's exit code AND land in the evidence
// manifest as outcome failure, not success.
func TestVerifyReportsDetectiveDriftAsAFailedOutcome(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	f.ChildConfig(accountID).RecorderRunning["default"] = false

	out, _, err := runCLI(t, g, verifyArgs(profile, accountID)...)
	if err == nil {
		t.Fatal("verify succeeded against a stopped Config recorder, want a non-zero exit for drift")
	}
	if code := exitCodeOf(err); code != exitVerifyDrift {
		t.Errorf("exit code = %d, want %d (exitVerifyDrift)", code, exitVerifyDrift)
	}
	if !strings.Contains(out, "NOT RECORDING") {
		t.Errorf("verify's output does not mention the stopped recorder:\n%s", out)
	}

	m, lerr := evidence.Load(filepath.Join(envprofile.DefaultEvidenceDir, accountID+".json"), nil)
	if lerr != nil {
		t.Fatalf("load the manifest verify wrote: %v", lerr)
	}
	var last *evidence.Record
	for i := range m.Records {
		if m.Records[i].Operation == evidence.OpVerify {
			last = &m.Records[i]
		}
	}
	if last == nil {
		t.Fatal("no verify record in the manifest")
	}
	if last.Outcome != evidence.OutcomeFailure {
		t.Errorf("the verify record's outcome is %q on a run that found detective drift, want %q",
			last.Outcome, evidence.OutcomeFailure)
	}
	if last.Err == nil || !strings.Contains(last.Err.Message, "recording") {
		t.Errorf("the error block does not name the detective finding: %+v", last.Err)
	}
}

// TestVerifyUnknownAccountNamesTheProblem is the boundary case DESIGN §12
// needs before any account exists to check: an id nothing in the organization
// recognizes must not be reported as drift-free.
func TestVerifyUnknownAccountNamesTheProblem(t *testing.T) {
	g, _ := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	_, _, err := runCLI(t, g, verifyArgs(profile, "999999999999")...)
	if err == nil {
		t.Fatal("verify succeeded against an account id nothing created")
	}
	if !strings.Contains(err.Error(), "no account with that id exists") {
		t.Errorf("error = %v, want it to name the missing account", err)
	}
}

// TestVerifyRequiresAccountAndProfile pins the two required flags' refusal
// text — the same "refuse before any AWS call" discipline vend's own flag
// checks hold.
func TestVerifyRequiresAccountAndProfile(t *testing.T) {
	g, _ := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	if _, _, err := runCLI(t, g, "verify", "--environment-profile", profile); err == nil {
		t.Error("verify with no --account succeeded, want a refusal")
	}
	if _, _, err := runCLI(t, g, "verify", "--account", "123456789012"); err == nil {
		t.Error("verify with no --environment-profile succeeded, want a refusal")
	}
	if _, _, err := runCLI(t, g, "verify", "--account", "not-an-account-id",
		"--environment-profile", profile); err == nil {
		t.Error("verify with a malformed --account succeeded, want a refusal")
	}
}

// TestVerifyWritesAnEvidenceRecord follows the same pattern vend's own
// evidence assertions do: an OpVerify record lands in the account's manifest,
// naming the identity that ran it.
func TestVerifyWritesAnEvidenceRecord(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	out, _, err := runCLI(t, g, verifyArgs(profile, accountID)...)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out, "Evidence:") {
		t.Errorf("verify did not report where it wrote the evidence manifest:\n%s", out)
	}
}

// TestVerifyRecordsDriftAsAFailedOutcome is AUDIT-4 H2. The record used to say
// `"outcome": "success"` on a run that reported drift and exited 2, and the
// manifest is the artifact that outlives the exit code — a reader counting
// successful verify records would have counted the drifted ones.
//
// Asserted against the manifest on disk rather than against the printed report:
// the report was already right, and the whole finding is that the durable
// document disagreed with it.
func TestVerifyRecordsDriftAsAFailedOutcome(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	names := f.State.PolicyNames()
	if len(names) == 0 {
		t.Fatal("the vend attached no policies; nothing for this test to drift")
	}
	f.State.SetPolicyContent(f.State.PolicyIDByName(names[0]),
		`{"Version":"2012-10-17","Statement":[{"Sid":"HandEdited","Effect":"Deny",`+
			`"Action":"s3:*","Resource":"*"}]}`)

	if _, _, err := runCLI(t, g, verifyArgs(profile, accountID)...); err == nil {
		t.Fatal("verify succeeded against a hand-edited policy, want a drift exit")
	}

	m, err := evidence.Load(filepath.Join(envprofile.DefaultEvidenceDir, accountID+".json"), nil)
	if err != nil {
		t.Fatalf("load the manifest verify wrote: %v", err)
	}
	var last *evidence.Record
	for i := range m.Records {
		if m.Records[i].Operation == evidence.OpVerify {
			last = &m.Records[i]
		}
	}
	if last == nil {
		t.Fatal("no verify record in the manifest")
	}
	if last.Outcome != evidence.OutcomeFailure {
		t.Errorf("the verify record's outcome is %q on a run that found drift and exited %d; the "+
			"manifest outlives the exit code, so a reader counting successful verifies counts this one",
			last.Outcome, exitVerifyDrift)
	}
	if last.Err == nil {
		t.Fatal("a failed verify record carries no error block, so the manifest says the check " +
			"failed and withholds what it found")
	}
	if !strings.Contains(last.Err.Message, "differs") {
		t.Errorf("the error block does not name the finding: %+v", last.Err)
	}
	if last.Err.Remediation == "" {
		t.Error("the error block carries no remediation (CLAUDE.md rule 7)")
	}
}
