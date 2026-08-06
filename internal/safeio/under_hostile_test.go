// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package safeio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Path resolution under a confined base, attacked (AUDIT-2).
//
// An intermediate symlink, a final-component symlink, an absolute rel, and dot-dot
// escape — plus the two shapes that must still work: a symlinked BASE, which is
// operator territory (on darwin /tmp is one), and a multi-component rel through real
// directories, which is the ordinary case.

func TestUnderRefusesAnIntermediateSymlink(t *testing.T) {
	base := tightDir(t)
	if err := os.Mkdir(filepath.Join(base, "elsewhere"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(base, "out")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	root, err := EnsureDirUnder(base, "out/evidence", SecretDirMode)
	if err == nil {
		_ = root.Close()
		landed := filepath.Join(base, "elsewhere", "evidence")
		if _, serr := os.Stat(landed); serr == nil {
			t.Fatalf("ESCAPED THROUGH AN INTERMEDIATE SYMLINK: the directory landed at %s", landed)
		}
		t.Fatal("EnsureDirUnder accepted a path through an intermediate symlink")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("the refusal should name the symlink: %v", err)
	}
	t.Logf("refused: %v", err)
}

func TestUnderRefusesASymlinkAtTheFinalComponent(t *testing.T) {
	base := tightDir(t)
	if err := os.Mkdir(filepath.Join(base, "elsewhere"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(base, "evidence")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := EnsureDirUnder(base, "evidence", SecretDirMode); err == nil {
		t.Fatal("EnsureDirUnder accepted a symlink at the final component")
	}
}

func TestUnderRefusesAnAbsoluteRel(t *testing.T) {
	base := tightDir(t)
	if _, err := EnsureDirUnder(base, "/etc/automat", SecretDirMode); err == nil {
		t.Fatal("EnsureDirUnder accepted an absolute rel")
	}
}

func TestUnderRefusesEscapeByDotDot(t *testing.T) {
	base := tightDir(t)
	inner := filepath.Join(base, "work")
	if err := os.Mkdir(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureDirUnder(inner, "../escaped", SecretDirMode); err == nil {
		if _, serr := os.Stat(filepath.Join(base, "escaped")); serr == nil {
			t.Fatalf("ESCAPED VIA ..: the directory landed at %s", filepath.Join(base, "escaped"))
		}
		t.Fatal("EnsureDirUnder accepted a rel containing ..")
	}
}

// The two cases that must still WORK. A symlinked BASE is operator territory — on
// darwin /tmp is one — and a multi-component rel through real directories is the
// ordinary case.
func TestUnderAllowsASymlinkedBase(t *testing.T) {
	outer := tightDir(t)
	real := filepath.Join(outer, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(outer, "via")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	root, err := EnsureDirUnder(filepath.Join(outer, "via"), "evidence", SecretDirMode)
	if err != nil {
		t.Fatalf("a symlinked base must be allowed: %v", err)
	}
	_ = root.Close()
	if _, err := os.Stat(filepath.Join(real, "evidence")); err != nil {
		t.Errorf("the directory did not land through the symlinked base: %v", err)
	}
}

func TestUnderCreatesAMultiComponentRelAndIsRepeatable(t *testing.T) {
	base := tightDir(t)
	for i := range 2 {
		root, err := EnsureDirUnder(base, "a/b/c/evidence", SecretDirMode)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if err := writeProbe(root); err != nil {
			t.Fatalf("run %d: write through the root: %v", i, err)
		}
		_ = root.Close()
	}
	if _, err := os.Stat(filepath.Join(base, "a", "b", "c", "evidence", "probe")); err != nil {
		t.Errorf("the probe did not land where the path names: %v", err)
	}
}

func writeProbe(root *os.Root) error {
	f, err := root.OpenFile("probe", os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.WriteString("ok\n")
	return err
}
