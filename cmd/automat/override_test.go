// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeOverrideFile writes a minimal override file naming one rule+parameter
// resolution, for a test that only needs to prove the flag reaches
// compilesets.LoadOverrides — not that a real conflict was resolved, which
// internal/compilesets/overrides_test.go already covers directly.
func writeOverrideFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "overrides.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write override file: %v", err)
	}
	return path
}

// TestVendRefusesAMalformedOverrideFileAtPlanTime holds the same "refuse
// before any AWS call" discipline TestVendRefusesAnEmptyIntersectionAtPlanTime
// pins for a bad environment profile: an override file automat cannot parse
// must be caught while loading documents, before a credential is resolved.
func TestVendRefusesAMalformedOverrideFileAtPlanTime(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	overridePath := writeOverrideFile(t, `{"overrides":[{"rule":"X","parameter":"Y","value":"Z","typo":"oops"}]}`)

	_, _, err := runCLI(t, g, vendArgs(profile, "--override", overridePath, "--dry-run")...)
	if err == nil {
		t.Fatal("vend accepted an override file with an unknown field, want a refusal")
	}
	if seen := vendWritesSeen(f); len(seen) > 0 {
		t.Errorf("the refusal arrived after %v had already been called; it must arrive at plan "+
			"time, before anything exists", seen)
	}
	if got := f.STS.CallCount("GetCallerIdentity"); got != 0 {
		t.Errorf("the refusal arrived after %d GetCallerIdentity calls; every document check "+
			"happens before a credential is even resolved", got)
	}
}

// TestVendAcceptsAWellFormedOverrideFile is the ordinary case: an override
// naming no real conflict in the shipped catalogs (there is none between
// cmmc-l1 and baseline-protection under this profile) must not itself cause
// a refusal — the flag is optional plumbing, not a claim that a conflict
// exists.
func TestVendAcceptsAWellFormedOverrideFile(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	overridePath := writeOverrideFile(t,
		`{"overrides":[{"rule":"IAM_PASSWORD_POLICY","parameter":"MinimumPasswordLength","value":"14"}]}`)

	if _, _, err := runCLI(t, g, vendArgs(profile, "--override", overridePath)...); err != nil {
		t.Fatalf("vend with a well-formed, non-conflicting override file failed: %v", err)
	}
	if len(f.State.AccountIDs()) != 1 {
		t.Fatalf("vend did not produce an account")
	}
}

// TestVerifyRefusesAMalformedOverrideFile mirrors the vend-side refusal for
// automat verify's own --override flag.
func TestVerifyRefusesAMalformedOverrideFile(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)
	overridePath := writeOverrideFile(t, `{"overrides":[{"rule":"X","parameter":"Y","value":"Z","typo":"oops"}]}`)

	_, _, err := runCLI(t, g, append(verifyArgs(profile, accountID), "--override", overridePath)...)
	if err == nil {
		t.Fatal("verify accepted an override file with an unknown field, want a refusal")
	}
	if !strings.Contains(err.Error(), "override") {
		t.Errorf("the refusal does not mention the override file: %v", err)
	}
}
