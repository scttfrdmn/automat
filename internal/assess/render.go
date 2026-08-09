// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"fmt"
	"strings"
)

// draftMarking is Invariant 1's required marking
// (docs/assessment-reporting.md): every rendered page states plainly that it
// is not a submission, so a document that reads like an official CMMC L1
// annual affirmation is never mistaken for one.
const draftMarking = "DRAFT — NOT A SUBMISSION"

// renderer pairs a name with the function that renders a Result into a
// human-facing form — internal/bundle's own registry pattern
// (render_test.go's TestEveryRendererIsReachable), copied here so a
// renderer added later (the 800-171A worksheet, Stage 2) cannot be added
// without both a name in this list and a check that it carries the DRAFT
// marking and no signature affordance.
var renderers = []struct {
	name   string
	render func(*Result) ([]byte, error)
}{
	{"l1-summary", RenderL1Summary},
}

// renderersCount forces a human to count entries when adding one — the
// same discipline internal/bundle's renderersCount enforces.
const renderersCount = 1

// RenderL1Summary renders a Result's CMMC L1 rollup as the human-facing
// summary an affirming official reads — never the thing they sign
// (Invariant 1). It states the DRAFT marking, the account's declared scope,
// the fifteen practices with their resolved values, the fixed
// no-machine-evidence disclosure, and whether an annual affirmation is
// possible at all.
func RenderL1Summary(r *Result) ([]byte, error) {
	var b strings.Builder
	w := func(format string, args ...any) {
		if len(args) == 0 {
			b.WriteString(format)
			return
		}
		fmt.Fprintf(&b, format, args...)
	}

	w("%s\n\n", draftMarking)
	w("CMMC Level 1 self-assessment summary — account %s\n", r.Account.ID)
	w("Rendered %s by automat %s.\n\n", r.RenderedAt, r.ToolVersion)
	w("Scope, as declared by the operator: %s\n\n", r.Account.ScopeStatement)
	w("Assessed against obligation profile %s (content %s) and control artifact %s (content %s).\n\n",
		r.Profile.ID, r.Profile.ContentSHA256, r.Artifact.ID, r.Artifact.ContentSHA256)

	w("%s\n\n", NoMachineEvidenceYet)

	w("| Practice | Resolved | Basis |\n")
	w("|---|---|---|\n")
	for _, row := range r.Objectives {
		basis := "no operator determination on file"
		if row.Determination != "" {
			basis = "operator determination " + row.Determination
		}
		w("| %s | %s | %s |\n", row.ID, row.Resolved, basis)
	}
	w("\n")

	w("Total: %d practices, %d MET, %d NOT MET.\n\n",
		r.L1Summary.Total, r.L1Summary.MetCount, r.L1Summary.NotMetCount)

	if r.L1Summary.AffirmationPossible {
		w("Every practice resolves MET. CMMC Level 1 permits no partial credit and no plan of " +
			"action, so this is the one state in which the senior official's own annual review " +
			"of this posture has something to conclude about. That review, and any resulting " +
			"paperwork, is outside this tool.\n\n")
	} else {
		w("%d practice(s) resolve NOT MET. CMMC Level 1 permits no partial credit and no plan of "+
			"action, so there is nothing this year's senior-official review can conclude until "+
			"every practice above resolves MET.\n\n", r.L1Summary.NotMetCount)
	}

	w("%s\n", r.PolicyCaveat)

	return []byte(b.String()), nil
}
