// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMakefileSmokeClaimIsStillTrue is AUDIT-2 carry-forward item 3, made durable.
//
// The Makefile's `smoke` target has run zero tests since it was written: nothing
// in the tree carries a `smoke` build tag, so `go test -tags=smoke … -run
// 'Smoke'` matches no test and exits 0. A target that runs nothing and exits 0
// reads as a pass, so the Makefile now says so explicitly rather than staying
// silent about it (AUDIT-2).
//
// That claim decays the moment a smoke-tagged test is added and nobody remembers
// to remove the sentence. This walks the tree for `//go:build smoke` and asserts
// the Makefile's "no automated test carries the smoke tag" wording is present
// only when that is still true.
func TestMakefileSmokeClaimIsStillTrue(t *testing.T) {
	repoRoot := "../.."

	var smokeTagged []string
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "bin" || d.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || filepath.Base(path) == "smoke_claim_test.go" {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // fixed repo-relative walk, not user input
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "//go:build smoke" || line == "// +build smoke" {
				smokeTagged = append(smokeTagged, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}

	makefile, err := os.ReadFile(filepath.Join(repoRoot, "Makefile")) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	claimsNoSmokeTests := strings.Contains(string(makefile), "No test in this tree carries the smoke build tag")

	switch {
	case len(smokeTagged) == 0 && !claimsNoSmokeTests:
		t.Fatal("no file carries a `smoke` build tag, but the Makefile no longer says so — " +
			"the smoke target now runs zero tests silently, which is the exact defect AUDIT-2 found")
	case len(smokeTagged) > 0 && claimsNoSmokeTests:
		t.Fatalf("the Makefile still claims no automated test carries the smoke tag, but %d do: %v — "+
			"update the smoke target's comment and help text to reflect what now runs", len(smokeTagged), smokeTagged)
	}
}
