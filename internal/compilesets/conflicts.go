// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"fmt"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// ConflictReport is a Config-rule parameter conflict the union could not
// resolve on its own, as a value rather than only as an error string.
//
// DESIGN §9: "hard error with a conflict report demanding explicit
// resolution (an override file)." artifact.ParamConflict already carries
// this shape as an error (internal/artifact/order.go), but an error is
// consumed once, at the call site that returns it — a caller building an
// override file (overrides.go) or rendering a report to an operator needs
// to hold the conflict as data afterward, name it by rule and parameter,
// and match it against an override's own Rule/Parameter fields. This type
// is that data; Error() still satisfies the error interface so a
// ConflictReport can be returned and handled exactly where an error was
// before.
type ConflictReport struct {
	// Rule is the AWS Config managed rule identifier the parameter belongs
	// to, e.g. "RESTRICTED_INCOMING_TRAFFIC".
	Rule string
	// Parameter is the rule parameter name.
	Parameter string
	// Values are the conflicting values that could not be reconciled, in
	// the order they were seen. Two for an ordinary pairwise conflict;
	// more when a re-slotting failure (Q1) reports every port that would
	// not fit.
	Values []string
	// Reason says what about the values could not be resolved — the same
	// prose artifact.ParamConflict.Reason carries.
	Reason string
	// Origins are "artifact-id:control-id" pairs that bound the conflicting
	// values, sorted and deduped, so an operator writing an override knows
	// which catalogs to read rather than which two strings disagree.
	Origins []string
}

// Error renders the conflict the same way artifact.ParamConflict does,
// naming the override file as the remediation (CLAUDE.md rule 7) — the
// wording is deliberately close to ParamConflict.Error()'s, since the two
// report the same kind of fact at two different points in the pipeline and
// a reader should not have to learn two vocabularies for one problem.
func (c *ConflictReport) Error() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s parameter %s binds conflicting values", safe(c.Rule), safe(c.Parameter))
	if len(c.Values) > 0 {
		quoted := make([]string, len(c.Values))
		for i, v := range c.Values {
			quoted[i] = safe(v)
		}
		fmt.Fprintf(&sb, " (%s)", strings.Join(quoted, ", "))
	}
	fmt.Fprintf(&sb, ": %s.", c.Reason)
	fmt.Fprintf(&sb, " Resolve it explicitly in an override file naming %s and the value you intend; "+
		"union must never guess which is stricter (DESIGN §9)", safe(c.Parameter))
	if len(c.Origins) > 0 {
		fmt.Fprintf(&sb, ". From: %s", strings.Join(c.Origins, ", "))
	}
	return sb.String()
}

// conflictReportFrom turns an artifact.ParamConflict (or any other error
// Resolve could in principle return) into a *ConflictReport carrying this
// package's provenance, or returns nil for a nil error — so a caller can
// write `if cr := conflictReportFrom(err, ...); cr != nil { return cr }`
// without a separate nil check.
func conflictReportFrom(err error, rule, parameter string, existingOrigins []string, newOrigins ...string) *ConflictReport {
	if err == nil {
		return nil
	}
	var pc *artifact.ParamConflict
	if p, ok := err.(*artifact.ParamConflict); ok {
		pc = p
	}
	origins := sortedUnique(append(append([]string(nil), existingOrigins...), newOrigins...))
	if pc == nil {
		return &ConflictReport{Rule: rule, Parameter: parameter, Reason: err.Error(), Origins: origins}
	}
	return &ConflictReport{
		Rule: rule, Parameter: parameter, Values: []string{pc.A, pc.B}, Reason: pc.Reason, Origins: origins,
	}
}

// safe renders a catalog-supplied string for an error message, escaping
// control characters and newlines — the same discipline
// internal/artifact.safe and internal/catalog.safe apply, restated here
// because a conflict's Rule/Parameter/Values all come from a control
// artifact, which is attacker-controlled in the threat model, and this
// package's own errors are read by an operator deciding what override to
// write.
func safe(s string) string {
	const max = 120
	if len(s) > max {
		return fmt.Sprintf("%q (truncated from %d bytes)", s[:max], len(s))
	}
	return fmt.Sprintf("%q", s)
}
