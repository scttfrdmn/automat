// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryShippedCitationIsInTheVerificationQueue pins docs/citation-verification.md
// to the shipped catalogs.
//
// AUDIT-2 ran a citation re-verification pass and referenced its output — "the
// citation pass's output," three times — as a 28-item list. That list was never
// committed; it lived only in the pass's transcript, so docs/citation-‑
// verification.md is a re-derivation rather than a recovery, built by walking
// every citations[] entry in every shipped catalog. A list nothing checks against
// the catalogs it describes is the same failure mode as F1's `renderable` map
// literal: correct when written, silently wrong the first time a source is added
// without updating the list alongside it.
//
// This does not check that the queue's claims are still true — that is the
// re-verification pass itself, and it needs a human. It only checks that every
// citation a shipped document makes has an entry to be checked at all.
func TestEveryShippedCitationIsInTheVerificationQueue(t *testing.T) {
	queue, err := os.ReadFile("../../docs/citation-verification.md") //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read docs/citation-verification.md: %v", err)
	}
	queueText := string(queue)

	dirs := []string{
		"../../catalogs/obligations",
		"../../catalogs/classification",
	}

	type citation struct {
		file string
		id   string
	}
	var citations []citation

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path list, built above
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			var doc struct {
				Citations []struct {
					ID string `json:"id"`
				} `json:"citations"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, c := range doc.Citations {
				citations = append(citations, citation{file: path, id: c.ID})
			}
		}
	}

	if len(citations) == 0 {
		t.Fatal("found zero citations across the shipped catalogs; the directory list or the " +
			"citations[] field name has drifted from what the catalogs actually use")
	}

	sort.Slice(citations, func(i, j int) bool { return citations[i].id < citations[j].id })

	var missing []citation
	for _, c := range citations {
		if !containsCitationID(queueText, c.id) {
			missing = append(missing, c)
		}
	}

	if len(missing) > 0 {
		msg := ""
		for _, m := range missing {
			msg += "\n  " + m.id + " (" + m.file + ")"
		}
		t.Fatalf("%d citation(s) ship without an entry in docs/citation-verification.md:%s\n\n"+
			"add an entry naming the claim, the field, the authority, and what would falsify it — "+
			"a citation nobody queued for a human to check is a claim nobody will ever check.",
			len(missing), msg)
	}
}

// containsCitationID reports whether the queue document mentions this citation id
// verbatim. The queue is prose, not structured data, so this is a substring check
// rather than a parse — deliberately: forcing every citation id into a rigid
// markdown shape would make the queue harder to write for a human, which is the
// audience it exists for.
func containsCitationID(queueText, id string) bool {
	return strings.Contains(queueText, id)
}
