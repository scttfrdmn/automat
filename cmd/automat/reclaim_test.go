// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/evidence"
)

func reclaimArgs(accountID string, extra ...string) []string {
	return append([]string{"reclaim", "--account", accountID}, extra...)
}

func TestReclaimRequiresAccount(t *testing.T) {
	g, _ := vendWorld(t)
	if _, _, err := runCLI(t, g, "reclaim"); err == nil {
		t.Error("reclaim with no --account succeeded, want a refusal")
	}
	if _, _, err := runCLI(t, g, "reclaim", "--account", "not-an-id"); err == nil {
		t.Error("reclaim with a malformed --account succeeded, want a refusal")
	}
}

// TestReclaimDryRunAppliesNothing is CLAUDE.md rule 5's plan half at the CLI
// layer: --dry-run must call neither DetachPolicy nor CloseAccount.
func TestReclaimDryRunAppliesNothing(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	out, _, err := runCLI(t, g, reclaimArgs(accountID, "--dry-run")...)
	if err != nil {
		t.Fatalf("reclaim --dry-run: %v", err)
	}
	if !strings.Contains(out, "Nothing was applied") {
		t.Errorf("reclaim --dry-run did not report that nothing was applied:\n%s", out)
	}
	for _, call := range f.Reclaim.Calls() {
		if call == "DetachPolicy" || call == "CloseAccount" {
			t.Errorf("--dry-run made a %s call — CLAUDE.md rule 5's plan half must write nothing", call)
		}
	}
}

// TestReclaimRefusesWithoutYes is the unconditional --yes gate
// docs/reclaim-design.md requires — no gated-only-on-one-step nuance the
// way `init` has, since every apply here is destructive.
func TestReclaimRefusesWithoutYes(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	_, _, err := runCLI(t, g, reclaimArgs(accountID)...)
	if err == nil {
		t.Fatal("reclaim without --yes succeeded, want a refusal")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("refusal does not mention --yes: %v", err)
	}
	for _, call := range f.Reclaim.Calls() {
		if call == "DetachPolicy" || call == "CloseAccount" {
			t.Errorf("a run refused for lacking --yes made a %s call", call)
		}
	}
}

// TestReclaimDetachesThenCloses exercises the full apply path against an
// account this binary just vended: automat's own SCP must be detached from
// the account's OU, and the account must end up SUSPENDED.
func TestReclaimDetachesThenCloses(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)
	ou := f.State.ParentOf(accountID)
	before := f.State.AttachedTo(ou)
	if len(before) == 0 {
		t.Fatalf("account %s's OU %s has no policies attached before reclaim; the fixture is wrong", accountID, ou)
	}

	out, _, err := runCLI(t, g, reclaimArgs(accountID, "--yes")...)
	if err != nil {
		t.Fatalf("reclaim --yes: %v", err)
	}
	if !strings.Contains(out, "Applied:") {
		t.Errorf("reclaim did not print an Applied section:\n%s", out)
	}
	if !strings.Contains(out, "Evidence:") {
		t.Errorf("reclaim did not report where it wrote the evidence manifest:\n%s", out)
	}

	after := f.State.AttachedTo(ou)
	if len(after) != 0 {
		t.Errorf("policies still attached to %s after reclaim: %v", ou, after)
	}
	if got := f.State.AccountStatus(accountID); got != orgtypes.AccountStatusSuspended {
		t.Errorf("account status after reclaim = %q, want SUSPENDED", got)
	}
}

// TestReclaimLeavesACentralPolicyAttached is the security assertion at the
// CLI layer: a policy not carrying automat's owner tag must survive
// reclaim, the same argument TestDetachOwnedPoliciesDetachesOnlyAutomatsOwn
// makes at the org-package layer.
func TestReclaimLeavesACentralPolicyAttached(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)
	ou := f.State.ParentOf(accountID)
	central := f.State.SeedPolicy("central-floor", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:*","Resource":"*"}]}`, nil)
	f.State.SeedAttachment(central, ou)

	out, _, err := runCLI(t, g, reclaimArgs(accountID, "--yes")...)
	if err != nil {
		t.Fatalf("reclaim --yes: %v", err)
	}
	if !strings.Contains(out, "not automat's") {
		t.Errorf("reclaim did not report the central policy as not automat's:\n%s", out)
	}

	after := f.State.AttachedTo(ou)
	found := false
	for _, id := range after {
		if id == central {
			found = true
		}
	}
	if !found {
		t.Errorf("central policy %s was detached by reclaim, want it left alone", central)
	}
}

// TestReclaimWritesAnOpReclaimEvidenceRecord follows vend/verify/assess's
// own evidence-assertion pattern.
func TestReclaimWritesAnOpReclaimEvidenceRecord(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	if _, _, err := runCLI(t, g, reclaimArgs(accountID, "--yes")...); err != nil {
		t.Fatalf("reclaim --yes: %v", err)
	}

	manifestPath := "evidence/" + accountID + ".json"
	m, err := evidence.LoadOrNew(manifestPath, accountID, accountID, "", "", nil)
	if err != nil {
		t.Fatalf("load the evidence manifest: %v", err)
	}
	var found bool
	for _, rec := range m.Records {
		if rec.Operation == evidence.OpReclaim {
			found = true
			if rec.Outcome != evidence.OutcomeSuccess {
				t.Errorf("OpReclaim record outcome = %q, want success", rec.Outcome)
			}
		}
	}
	if !found {
		t.Fatalf("manifest has no OpReclaim record: %+v", m.Records)
	}
}

// TestReclaimHonorsEvidenceDirFlag mirrors assess's own AUDIT-5 fix
// (TestAssessHonorsEvidenceDirFlag): reclaim has no --environment-profile to
// read baseline.evidence.local_dir out of, so --evidence-dir must actually
// route the write or the OpReclaim record lands in a manifest disconnected
// from the one vend and verify wrote to.
func TestReclaimHonorsEvidenceDirFlag(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)
	customDir := "compliance-evidence"

	if _, _, err := runCLI(t, g, reclaimArgs(accountID, "--yes", "--evidence-dir", customDir)...); err != nil {
		t.Fatalf("reclaim: %v", err)
	}

	manifestPath := customDir + "/" + accountID + ".json"
	m, err := evidence.LoadOrNew(manifestPath, accountID, accountID, "", "", nil)
	if err != nil {
		t.Fatalf("load the evidence manifest at the custom directory: %v", err)
	}
	var found bool
	for _, rec := range m.Records {
		if rec.Operation == evidence.OpReclaim {
			found = true
		}
	}
	if !found {
		t.Errorf("manifest at %s has no OpReclaim record: %+v", manifestPath, m.Records)
	}
}

// TestReclaimReportsTheCloseAccountQuotaByName exercises AWS's rejection
// path end to end: the CLI must surface the actual documented limit, not a
// bare AWS error.
func TestReclaimReportsTheCloseAccountQuotaByName(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)
	f.Reclaim.CloseAccountQuotaExceeded = true

	_, _, err := runCLI(t, g, reclaimArgs(accountID, "--yes")...)
	if err == nil {
		t.Fatal("reclaim succeeded despite the fake reporting the closure quota exceeded")
	}
	for _, want := range []string{"250", "20%", "rolling 30 day"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is missing %q: %v", want, err)
		}
	}
}
