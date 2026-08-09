// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

// TestListAccountIDsEmptyDirectory is the state `automat init` leaves an
// evidence directory in before anything is vended: present, empty.
func TestListAccountIDsEmptyDirectory(t *testing.T) {
	_, dir := tempDir(t)
	ids, err := dir.ListAccountIDs()
	if err != nil {
		t.Fatalf("ListAccountIDs: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v, want none", ids)
	}
}

// writeMinimalManifest writes a valid, single-record manifest for id — enough
// to satisfy Validate, since ListAccountIDs's own tests care about which
// filenames are found, not about record content.
func writeMinimalManifest(t *testing.T, dir *Dir, id string) {
	t.Helper()
	m := NewManifest(id, id, "o-abc1234567", ts0)
	rec := Record{
		Timestamp:   ts0,
		Operation:   OpAccountCreate,
		Operator:    Operator{ARN: "arn:aws:iam::" + id + ":role/automat-operator", AccountID: id},
		Target:      &Target{AccountID: id},
		ToolVersion: toolVer,
	}
	if _, err := m.Append(rec, nil); err != nil {
		t.Fatalf("append record for %s: %v", id, err)
	}
	if err := dir.Write(m, id); err != nil {
		t.Fatalf("write %s: %v", id, err)
	}
}

// TestListAccountIDsReturnsEveryManifestSorted is the ordinary case: several
// accounts vended into one evidence directory, and `list` needs a
// deterministic order rather than directory-read order, which filesystems do
// not guarantee.
func TestListAccountIDsReturnsEveryManifestSorted(t *testing.T) {
	_, dir := tempDir(t)
	for _, id := range []string{"333333333333", "111111111111", "222222222222"} {
		writeMinimalManifest(t, dir, id)
	}
	ids, err := dir.ListAccountIDs()
	if err != nil {
		t.Fatalf("ListAccountIDs: %v", err)
	}
	want := []string{"111111111111", "222222222222", "333333333333"}
	if len(ids) != len(want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("ids[%d] = %q, want %q", i, ids[i], want[i])
		}
	}
}

// TestListAccountIDsSkipsNonManifestEntries: an evidence directory is
// operator territory (a colleague might keep notes beside the manifests, or
// an editor might drop a swap file), and ListAccountIDs is an inventory, not
// a validator — a non-".json" entry is not this account's problem to
// surface.
func TestListAccountIDsSkipsNonManifestEntries(t *testing.T) {
	base, dir := tempDir(t)
	writeMinimalManifest(t, dir, "123456789012")
	if err := os.WriteFile(filepath.Join(base, "evidence", "README.txt"), []byte("notes"), 0o600); err != nil {
		t.Fatalf("write README.txt: %v", err)
	}
	if err := os.Mkdir(filepath.Join(base, "evidence", "archive"), 0o700); err != nil {
		t.Fatalf("mkdir archive: %v", err)
	}

	ids, err := dir.ListAccountIDs()
	if err != nil {
		t.Fatalf("ListAccountIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != "123456789012" {
		t.Errorf("ids = %v, want exactly [123456789012]", ids)
	}
}
