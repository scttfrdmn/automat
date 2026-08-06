// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Hostile filesystem shapes at the manifest path and its temp name (AUDIT-2).
//
// A symlink, a hardlink, or a FIFO planted at either name, plus the three cases that must
// still work: an ordinary write, a shorter manifest truncating a longer one, and a loose
// mode tightened on re-run (ensure semantics, CLAUDE.md rule 4).

func jamManifest(t *testing.T) *Manifest {
	t.Helper()
	return storeManifest(t, nil)
}

func TestSymlinkAtManifestName(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "m.json")
	if err := os.Symlink("victim.txt", path); err != nil {
		t.Fatal(err)
	}
	err := jamManifest(t).Write(path)
	got, _ := os.ReadFile(victim)
	if err == nil {
		t.Fatalf("WROTE THROUGH A SYMLINK: victim now holds %d bytes", len(got))
	}
	if string(got) != "original\n" {
		t.Fatalf("victim was modified despite the refusal: %q", got)
	}
	t.Logf("refused: %v", err)
}

func TestSymlinkAtTempName(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "999988887777.json")
	if err := os.WriteFile(victim, []byte("other account\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := "100000000001.json"
	if err := os.Symlink("999988887777.json", filepath.Join(dir, ".automat-"+base+".tmp")); err != nil {
		t.Fatal(err)
	}
	err := jamManifest(t).Write(filepath.Join(dir, base))
	got, _ := os.ReadFile(victim)
	if err == nil {
		t.Fatalf("WROTE THROUGH THE TEMP SYMLINK: other manifest now holds %d bytes", len(got))
	}
	if string(got) != "other account\n" {
		t.Fatalf("the other account's manifest was modified: %q", got)
	}
	t.Logf("refused: %v", err)
}

func TestHardlinkAtManifestName(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "m.json")
	if err := os.Link(victim, path); err != nil {
		t.Fatal(err)
	}
	err := jamManifest(t).Write(path)
	got, _ := os.ReadFile(victim)
	if err == nil {
		t.Fatalf("WROTE THROUGH A HARDLINK: victim clobbered with %d bytes", len(got))
	}
	if string(got) != "original\n" {
		t.Fatalf("victim was modified despite the refusal: %q", got)
	}
	t.Logf("refused: %v", err)
}

func TestHardlinkAtTempName(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(outside, []byte("ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := "100000000001.json"
	if err := os.Link(outside, filepath.Join(dir, ".automat-"+base+".tmp")); err != nil {
		t.Fatal(err)
	}
	err := jamManifest(t).Write(filepath.Join(dir, base))
	got, _ := os.ReadFile(outside)
	if err == nil {
		t.Fatalf("WROTE THROUGH A HARDLINK AT THE TEMP NAME, OUTSIDE THE ROOT: %s holds %d bytes",
			outside, len(got))
	}
	if string(got) != "ssh-ed25519 AAAA\n" {
		t.Fatalf("the file outside the root was modified: %q", got)
	}
	t.Logf("refused: %v", err)
}

func TestFIFOAtManifestName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- jamManifest(t).Write(path) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Write SUCCEEDED on a FIFO")
		}
		t.Logf("refused: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("HUNG: Write on a FIFO at the manifest name did not return within 3s")
	}
}

func TestFIFOAtTempName(t *testing.T) {
	dir := t.TempDir()
	base := "100000000001.json"
	if err := syscall.Mkfifo(filepath.Join(dir, ".automat-"+base+".tmp"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- jamManifest(t).Write(filepath.Join(dir, base)) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Write SUCCEEDED with a FIFO at the temp name")
		}
		t.Logf("refused: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("HUNG: Write on a FIFO at the temp name did not return within 3s")
	}
}

// The two cases that must still WORK, so the fix is not a refusal of everything.
func TestOrdinaryWriteStillWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json")
	m := jamManifest(t)
	if err := m.Write(path); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := m.Write(path); err != nil {
		t.Fatalf("second write (idempotent re-run): %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode is %s, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Lstat(filepath.Join(dir, ".automat-m.json.tmp")); err == nil {
		t.Fatal("the temp file was left behind")
	}
	if _, err := Load(path, nil); err != nil {
		t.Fatalf("the written manifest does not load: %v", err)
	}
}

// A shorter manifest replacing a longer one must not leave a tail behind.
func TestTruncationStillHappens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json")
	if err := os.WriteFile(path, make([]byte, 40000), 0o600); err != nil {
		t.Fatal(err)
	}
	m := jamManifest(t)
	if err := m.Write(path); err != nil {
		t.Fatalf("write over a longer file: %v", err)
	}
	want, err := m.MarshalIndented()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("file is %d bytes, manifest is %d — a tail of the old content survived",
			len(got), len(want))
	}
}

// Existing loose modes must be tightened on re-run (ensure semantics, rule 4).
func TestLooseModeIsTightened(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json")
	if err := os.WriteFile(path, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := jamManifest(t).Write(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode is %s, want 0600", fi.Mode().Perm())
	}
}
