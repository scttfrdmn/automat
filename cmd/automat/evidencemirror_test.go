// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsfake"
)

// TestVendWithManagementMirrorBucketUploadsTheManifest is ROADMAP.md's
// "Remote evidence mirror" slice 1 wired end to end: a profile naming
// baseline.evidence.management_mirror_bucket makes `vend` call PutObject
// with the manifest's own bytes, through evidenceMirror/uploadToMirrors.
func TestVendWithManagementMirrorBucketUploadsTheManifest(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, func(doc map[string]any) {
		baseline := doc["baseline"].(map[string]any)
		baseline["evidence"] = map[string]any{
			"management_mirror_bucket": "automat-evidence-mirror",
		}
	})

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend: %v", err)
	}
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("want 1 account, got %v", accounts)
	}
	accountID := accounts[0]

	if n := f.S3.CallCount("PutObject"); n != 1 {
		t.Fatalf("PutObject called %d times, want 1", n)
	}
	if n := f.S3.CallCount("GetObject"); n != 0 {
		t.Errorf("slice 1 (write-only) called GetObject %d times, want 0", n)
	}

	local := loadVendManifest(t, accountID)
	localBytes, err := local.MarshalIndented()
	if err != nil {
		t.Fatalf("MarshalIndented the local manifest: %v", err)
	}
	mirrored, ok := f.S3.Object("automat-evidence-mirror", accountID+".json")
	if !ok {
		t.Fatalf("no object was uploaded to automat-evidence-mirror/%s.json", accountID)
	}
	if string(mirrored) != string(localBytes) {
		t.Errorf("the mirrored bytes differ from the local file's own bytes:\nmirrored: %s\nlocal:    %s",
			mirrored, localBytes)
	}
}

// TestVendWithNoMirrorBucketMakesNoS3Call is the common, today's-default
// case: a profile naming neither in_account_bucket nor
// management_mirror_bucket must not build an S3 client at all, let alone
// call it — the same "no code path reaches AWS without being told to"
// discipline TestNoCommandReachesAWSWithoutAFake holds for every other
// client.
func TestVendWithNoMirrorBucketMakesNoS3Call(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend: %v", err)
	}
	if calls := f.S3.Calls(); len(calls) != 0 {
		t.Errorf("a profile naming no mirror bucket reached S3: %v", calls)
	}
}

// TestVendWithBothMirrorBucketsUploadsToBoth is DESIGN §11's "and/or":
// in_account_bucket and management_mirror_bucket are independently
// configured, and a profile naming both gets both uploaded to.
func TestVendWithBothMirrorBucketsUploadsToBoth(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, func(doc map[string]any) {
		baseline := doc["baseline"].(map[string]any)
		baseline["evidence"] = map[string]any{
			"in_account_bucket":        "automat-evidence-in-account",
			"management_mirror_bucket": "automat-evidence-mirror",
		}
	})

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend: %v", err)
	}
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("want 1 account, got %v", accounts)
	}
	accountID := accounts[0]

	if n := f.S3.CallCount("PutObject"); n != 2 {
		t.Fatalf("PutObject called %d times, want 2 (one per configured bucket)", n)
	}
	if _, ok := f.S3.Object("automat-evidence-in-account", accountID+".json"); !ok {
		t.Error("no object uploaded to the in-account bucket")
	}
	if _, ok := f.S3.Object("automat-evidence-mirror", accountID+".json"); !ok {
		t.Error("no object uploaded to the management mirror bucket")
	}
}

// TestVendMirrorUploadFailureIsAWarningNotAFailure is the CRITICAL
// failure-handling rule the task named: a mirror upload failure must never
// fail the command that produced the manifest, and the local write must
// already have succeeded either way.
func TestVendMirrorUploadFailureIsAWarningNotAFailure(t *testing.T) {
	g, f := vendWorld(t)
	f.S3.PutObjectErr = errDenyForTest
	profile := vendProfileJSON(t, func(doc map[string]any) {
		baseline := doc["baseline"].(map[string]any)
		baseline["evidence"] = map[string]any{
			"management_mirror_bucket": "automat-evidence-mirror",
		}
	})

	out, _, err := runCLI(t, g, vendArgs(profile)...)
	if err != nil {
		t.Fatalf("vend with a denied mirror upload must still succeed: %v", err)
	}
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("want 1 account created regardless of the mirror failure, got %v", accounts)
	}
	if _, statErr := loadVendManifestBytes(t, accounts[0]); statErr != nil {
		t.Errorf("the local manifest must exist even though the mirror upload failed: %v", statErr)
	}
	if !strings.Contains(out, "evidence mirror upload failed") {
		t.Errorf("stdout does not report the mirror upload failure as a warning:\n%s", out)
	}
}

// errDenyForTest is a fixed s3:PutObject denial, standing in for a real
// AccessDeniedException the way awsfake.AccessDenied's own callers use it.
var errDenyForTest = awsfake.AccessDenied("s3:PutObject")

// loadVendManifestBytes reads the raw bytes of accountID's local evidence
// manifest, for a byte-for-byte comparison against what was mirrored —
// loadVendManifest (vend_test.go) decodes into a struct, which is one
// unmarshal/marshal round trip away from the exact bytes this test needs.
func loadVendManifestBytes(t *testing.T, accountID string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(filepath.Join("evidence", accountID+".json")) //nolint:gosec // test's own temp dir
}
