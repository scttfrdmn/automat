// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// TestEveryDesignCitationNamesARealSection is AUDIT-2's N1, made durable.
//
// internal/bundle/role.go once cited a three-digit DESIGN section it meant as
// section 14 — DESIGN.md has sixteen top-level sections, so the citation could
// not have existed, but nothing said so until an audit read the file next to
// DESIGN.md open in another window. A
// citation is a promise that a specific paragraph backs a specific claim, and a
// promise nobody checks decays the moment the section numbering shifts under it.
//
// This walks every Go and JSON file for a "DESIGN §<n>" citation and every
// heading in DESIGN.md, and asserts each cited section exists. It is deliberately
// narrow: it proves the number resolves, not that the citation still supports the
// claim made next to it — that half stays a human's job.
func TestEveryDesignCitationNamesARealSection(t *testing.T) {
	repoRoot := "../.."

	design, err := os.ReadFile(filepath.Join(repoRoot, "DESIGN.md")) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read DESIGN.md: %v", err)
	}

	headingRe := regexp.MustCompile(`(?m)^#{2,3} (\d+[a-z]?)\.`)
	sections := make(map[string]bool)
	for _, m := range headingRe.FindAllStringSubmatch(string(design), -1) {
		sections[m[1]] = true
	}
	if len(sections) < 10 {
		t.Fatalf("parsed only %d DESIGN.md section headings; the heading pattern probably drifted "+
			"from DESIGN.md's actual format", len(sections))
	}

	citationRe := regexp.MustCompile(`DESIGN[ .]*§(\d+[a-z]?)`)

	var files []string
	for _, dir := range []string{".", "cmd", "gen", "catalogs"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			switch filepath.Ext(path) {
			case ".go", ".json":
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(files)

	type badCitation struct {
		file    string
		section string
	}
	var bad []badCitation

	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // fixed in-repo path list, built above
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range citationRe.FindAllStringSubmatch(string(data), -1) {
			if !sections[m[1]] {
				bad = append(bad, badCitation{file: f, section: m[1]})
			}
		}
	}

	if len(bad) > 0 {
		var msg string
		for _, b := range bad {
			msg += fmt.Sprintf("\n  %s cites DESIGN §%s, which DESIGN.md has no heading for", b.file, b.section)
		}
		t.Fatalf("%d citation(s) name a section DESIGN.md does not have:%s\n\n"+
			"DESIGN.md's sections run 1-16 (some with letter suffixes like 7a, 11a); a three-digit "+
			"citation is almost certainly a transposition of a real one — check the nearest heading "+
			"before assuming the section was renumbered.", len(bad), msg)
	}
}
