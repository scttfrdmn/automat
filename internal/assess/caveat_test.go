// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import "strings"

// requiredCaveatSubstance and missingCaveatSubstance are internal/artifact's
// own helpers (obligation_profile_test.go), copied rather than imported: a
// test-only helper is not something a package exports, and the phrase list
// is docs/policy-caveat.md's contract, not internal/artifact's private
// business. See docs/policy-caveat.md's table for why each phrase is here.
var requiredCaveatSubstance = []string{
	"not legal advice",
	"not a compliance determination",
	"governs",
	"sponsored programs",
	"counsel",
	"records the operator's declaration",
	"verify against the primary source",
}

func missingCaveatSubstance(text string) []string {
	flat := strings.Join(strings.Fields(strings.ReplaceAll(strings.ToLower(text), ">", " ")), " ")
	var missing []string
	for _, phrase := range requiredCaveatSubstance {
		if !strings.Contains(flat, phrase) {
			missing = append(missing, phrase)
		}
	}
	return missing
}
