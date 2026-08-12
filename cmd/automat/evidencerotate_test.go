// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsfake"
	"github.com/scttfrdmn/automat/internal/evidence"
)

const (
	rotateAcct     = "444455556666"
	rotateOperator = "arn:aws:iam::111122223333:role/automat-operator"
	rotateTool     = "0.1.0"
	rotateTS0      = "2026-08-05T00:00:00Z"
	rotateTS1      = "2026-08-05T01:00:00Z"
)

func openRotateTestDir(t *testing.T) *evidence.Dir {
	t.Helper()
	base := t.TempDir()
	dir, err := evidence.OpenDir(base, "evidence")
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return dir
}

func rotateTestRecord(op evidence.Operation, ts string) evidence.Record {
	return evidence.Record{
		Timestamp:   ts,
		Operation:   op,
		Operator:    evidence.Operator{ARN: rotateOperator, AccountID: "111122223333"},
		Target:      &evidence.Target{AccountID: rotateAcct},
		ToolVersion: rotateTool,
	}
}

// TestOpenActiveManifestFollowsARotationPointer is the ordinary case
// openActiveManifest exists for: an account whose original manifest was
// already rotated must have its next record land in the successor, not in
// the closed original.
func TestOpenActiveManifestFollowsARotationPointer(t *testing.T) {
	dir := openRotateTestDir(t)

	original := evidence.NewManifest(rotateAcct, rotateAcct, "o-abc1234567", rotateTS0)
	if _, err := original.Append(rotateTestRecord(evidence.OpAccountCreate, rotateTS0), nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	successorKey := rotateAcct + "-2"
	if _, _, err := original.Rotate(successorKey, "reached the test threshold", rotateTS1, nil); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := dir.WriteNamed(original, rotateAcct); err != nil {
		t.Fatalf("write original: %v", err)
	}

	key, m, err := openActiveManifest(dir, rotateAcct, "o-abc1234567", rotateTS1)
	if err != nil {
		t.Fatalf("openActiveManifest: %v", err)
	}
	if key != successorKey {
		t.Errorf("key = %q, want %q (the rotation pointer's target)", key, successorKey)
	}
	if len(m.Records) != 0 {
		t.Errorf("the resolved successor has %d records, want 0: it was never written to disk, "+
			"so LoadOrNewNamed must have started a fresh manifest for it", len(m.Records))
	}
	if m.Meta.AccountID != rotateAcct {
		t.Errorf("successor Meta.AccountID = %q, want %q", m.Meta.AccountID, rotateAcct)
	}
}

// TestOpenActiveManifestStopsAtACustodyTransfer is the case openActiveManifest
// must NOT follow: a custody-transferred manifest may name a successor
// manifest id too, but automat is not the one writing to it — custody left
// automat's hands, so the account-named file staying closed is correct, not a
// bug to route around.
func TestOpenActiveManifestStopsAtACustodyTransfer(t *testing.T) {
	dir := openRotateTestDir(t)

	m := evidence.NewManifest(rotateAcct, rotateAcct, "o-abc1234567", rotateTS0)
	if _, err := m.Append(rotateTestRecord(evidence.OpAccountCreate, rotateTS0), nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	transfer := evidence.Record{
		Timestamp: rotateTS1,
		Operation: evidence.OpCustodyTransfer,
		Operator:  evidence.Operator{ARN: rotateOperator, AccountID: "111122223333"},
		Custody: &evidence.Custody{
			Transferee:          "Research Computing",
			EffectiveDate:       "2026-09-01",
			Reason:              "Handed over.",
			FinalArtifact:       evidence.DocRef{ID: "cmmc-l1", ContentSHA256: strings.Repeat("1", 64)},
			SuccessorManifestID: "rc-central-444455556666",
		},
		ToolVersion: rotateTool,
	}
	if _, err := m.Append(transfer, nil); err != nil {
		t.Fatalf("append transfer: %v", err)
	}
	if err := dir.WriteNamed(m, rotateAcct); err != nil {
		t.Fatalf("write: %v", err)
	}

	key, resolved, err := openActiveManifest(dir, rotateAcct, "o-abc1234567", rotateTS1)
	if err != nil {
		t.Fatalf("openActiveManifest: %v", err)
	}
	if key != rotateAcct {
		t.Errorf("key = %q, want %q: a custody transfer's successor is not automat's to follow",
			key, rotateAcct)
	}
	if !resolved.Closed() {
		t.Error("the resolved manifest is not closed, but its last record is a custody transfer")
	}
}

// TestNextRotationKeyFindsTheFirstUnusedSuffix checks the naming scheme this
// project settled on: "<accountID>-2.json", then "-3", and so on, skipping
// names already claimed on disk.
func TestNextRotationKeyFindsTheFirstUnusedSuffix(t *testing.T) {
	dir := openRotateTestDir(t)

	key, err := nextRotationKey(dir, rotateAcct)
	if err != nil {
		t.Fatalf("nextRotationKey: %v", err)
	}
	if key != rotateAcct+"-2" {
		t.Errorf("first rotation key = %q, want %q", key, rotateAcct+"-2")
	}

	// Claim -2 and -3 on disk; the next call must skip both.
	for _, suffix := range []string{"-2", "-3"} {
		claimed := evidence.NewManifest(rotateAcct+suffix, rotateAcct, "", rotateTS0)
		if _, aerr := claimed.Append(rotateTestRecord(evidence.OpAccountCreate, rotateTS0), nil); aerr != nil {
			t.Fatalf("append: %v", aerr)
		}
		if werr := dir.WriteNamed(claimed, rotateAcct+suffix); werr != nil {
			t.Fatalf("write %s: %v", suffix, werr)
		}
	}
	key, err = nextRotationKey(dir, rotateAcct)
	if err != nil {
		t.Fatalf("nextRotationKey: %v", err)
	}
	if key != rotateAcct+"-4" {
		t.Errorf("key = %q, want %q (the first name not already on disk)", key, rotateAcct+"-4")
	}
}

// TestWriteManifestWithRotationPrintsANoticeAndOpensASuccessor exercises the
// full rotation path a repeated `verify` run against one account takes once
// the threshold is crossed: the old manifest is closed and rewritten, the
// successor is written even though nothing has been appended to it yet, and
// the notice is not silent (ROADMAP.md's Q23 entry — explicit, disclosed
// behavior, never implicit magic).
func TestWriteManifestWithRotationPrintsANoticeAndOpensASuccessor(t *testing.T) {
	dir := openRotateTestDir(t)
	orig := rotateThresholdRecords
	rotateThresholdRecords = 2
	t.Cleanup(func() { rotateThresholdRecords = orig })

	m := evidence.NewManifest(rotateAcct, rotateAcct, "", rotateTS0)
	if _, err := m.Append(rotateTestRecord(evidence.OpAccountCreate, rotateTS0), nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := m.Append(rotateTestRecord(evidence.OpVerify, rotateTS1), nil); err != nil {
		t.Fatalf("append: %v", err)
	}

	var out bytes.Buffer
	path, written, err := writeManifestWithRotation(dir, rotateAcct, m, nil, rotateTS1, &out)
	if err != nil {
		t.Fatalf("writeManifestWithRotation: %v", err)
	}
	if path != dir.Path(rotateAcct) {
		t.Errorf("path = %q, want %q", path, dir.Path(rotateAcct))
	}
	if written != m {
		t.Error("writeManifestWithRotation must return the pre-rotation manifest, whose content " +
			"just changed, not the empty successor")
	}
	if !m.Closed() {
		t.Error("the manifest was not closed by rotation despite reaching the (test) threshold")
	}

	notice := out.String()
	for _, want := range []string{"Rotated evidence manifest", dir.Path(rotateAcct), "is now closed", "continuing at"} {
		if !strings.Contains(notice, want) {
			t.Errorf("the rotation notice must say %q; got:\n%s", want, notice)
		}
	}

	// The successor must actually be on disk and loadable, with no records —
	// Rotate/writeManifestWithRotation only open it, they do not seed a first
	// record into it.
	successorKey := rotateAcct + "-2"
	_, successor, err := openActiveManifest(dir, rotateAcct, "", rotateTS1)
	if err != nil {
		t.Fatalf("openActiveManifest after rotation: %v", err)
	}
	if len(successor.Records) != 0 {
		t.Errorf("the successor has %d records, want 0", len(successor.Records))
	}
	if got := dir.Path(successorKey); !strings.Contains(notice, got) {
		t.Errorf("the notice must name the successor's path %q; got:\n%s", got, notice)
	}
}

// TestMirrorUploadAfterRotationUsesTheClosedManifestsOwnKey is this task's
// own audit finding, pinned as a regression: uploadToMirrors, called with
// evidenceManifestKey(path) the way every real call site (vend.go, verify.go,
// reclaim.go, assess.go) now does, must land the CLOSED (pre-rotation, just
// rotated) manifest's mirror upload at ITS OWN object key — never at a key
// that a later successor-manifest upload could collide with.
//
// Before this fix, evidence.Mirror.Upload derived the S3 key purely from
// m.Meta.AccountID (which does not change across a rotation), so the closed
// original's mirror upload and every later successor's mirror upload landed
// at the SAME object key — the second write silently overwriting the
// mirrored copy of the first. That defeats exactly the compensating control
// ROADMAP.md's "Remote evidence mirror" slice 2 exists to read back from.
func TestMirrorUploadAfterRotationUsesTheClosedManifestsOwnKey(t *testing.T) {
	dir := openRotateTestDir(t)
	orig := rotateThresholdRecords
	rotateThresholdRecords = 2
	t.Cleanup(func() { rotateThresholdRecords = orig })

	m := evidence.NewManifest(rotateAcct, rotateAcct, "", rotateTS0)
	if _, err := m.Append(rotateTestRecord(evidence.OpAccountCreate, rotateTS0), nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := m.Append(rotateTestRecord(evidence.OpVerify, rotateTS1), nil); err != nil {
		t.Fatalf("append: %v", err)
	}

	var out bytes.Buffer
	path, closed, err := writeManifestWithRotation(dir, rotateAcct, m, nil, rotateTS1, &out)
	if err != nil {
		t.Fatalf("writeManifestWithRotation: %v", err)
	}
	if !closed.Closed() {
		t.Fatal("the manifest was not closed by rotation; nothing to regress-test")
	}

	fake := awsfake.NewS3()
	mirror, merr := evidence.NewS3Mirror(fake, "automat-evidence-mirror", "")
	if merr != nil {
		t.Fatalf("NewS3Mirror: %v", merr)
	}
	key := evidenceManifestKey(path)
	if key != rotateAcct {
		t.Fatalf("evidenceManifestKey(%q) = %q, want %q", path, key, rotateAcct)
	}
	if warnings := uploadToMirrors(context.Background(), []evidence.Mirror{mirror}, key, closed); len(warnings) != 0 {
		t.Fatalf("uploadToMirrors: %v", warnings)
	}

	// Now simulate the successor's own later mirror upload, once it has a
	// first record and its own manifestPath.
	successorKey := rotateAcct + "-2"
	_, successor, oerr := openActiveManifest(dir, rotateAcct, "", rotateTS1)
	if oerr != nil {
		t.Fatalf("openActiveManifest: %v", oerr)
	}
	if _, aerr := successor.Append(rotateTestRecord(evidence.OpVerify, rotateTS1), nil); aerr != nil {
		t.Fatalf("append to successor: %v", aerr)
	}
	successorPath, successorWritten, werr := writeManifestWithRotation(dir, successorKey, successor, nil, rotateTS1, &out)
	if werr != nil {
		t.Fatalf("writeManifestWithRotation (successor): %v", werr)
	}
	successorMirrorKey := evidenceManifestKey(successorPath)
	if successorMirrorKey != successorKey {
		t.Fatalf("evidenceManifestKey(%q) = %q, want %q", successorPath, successorMirrorKey, successorKey)
	}
	if warnings := uploadToMirrors(context.Background(), []evidence.Mirror{mirror}, successorMirrorKey, successorWritten); len(warnings) != 0 {
		t.Fatalf("uploadToMirrors (successor): %v", warnings)
	}

	// The regression: both objects must exist, at DIFFERENT keys, each still
	// holding its own manifest's content.
	closedObj, ok := fake.Object("automat-evidence-mirror", rotateAcct+".json")
	if !ok {
		t.Fatal("the closed (pre-rotation) manifest's mirror object is missing")
	}
	successorObj, ok := fake.Object("automat-evidence-mirror", successorKey+".json")
	if !ok {
		t.Fatal("the successor's mirror object is missing")
	}
	if string(closedObj) == string(successorObj) {
		t.Fatal("the closed manifest's mirror object and the successor's are identical bytes at " +
			"different keys — suspicious for two manifests with different record counts, but not " +
			"itself the bug this test targets")
	}
	// The actual bug reproduced literally: before the fix, both uploads
	// landed at "444455556666.json" and the second overwrote the first.
	if fake.CallCount("PutObject") != 2 {
		t.Fatalf("PutObject called %d times, want 2 (one per manifest, at two distinct keys)",
			fake.CallCount("PutObject"))
	}
}

// TestWriteManifestWithRotationDoesNotRotateBelowThreshold is the negative
// case: an ordinary write, below the threshold, closes nothing and prints
// nothing.
func TestWriteManifestWithRotationDoesNotRotateBelowThreshold(t *testing.T) {
	dir := openRotateTestDir(t)

	m := evidence.NewManifest(rotateAcct, rotateAcct, "", rotateTS0)
	if _, err := m.Append(rotateTestRecord(evidence.OpAccountCreate, rotateTS0), nil); err != nil {
		t.Fatalf("append: %v", err)
	}

	var out bytes.Buffer
	_, written, err := writeManifestWithRotation(dir, rotateAcct, m, nil, rotateTS0, &out)
	if err != nil {
		t.Fatalf("writeManifestWithRotation: %v", err)
	}
	if written.Closed() {
		t.Error("the manifest was closed even though it is nowhere near the rotation threshold")
	}
	if out.Len() != 0 {
		t.Errorf("a write below the threshold printed something: %q", out.String())
	}
}
