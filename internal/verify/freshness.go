// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"time"
)

// dateLayout is the review_by wire format — plain YYYY-MM-DD, the same layout
// envprofile.Profile.ReviewBy, classprofile.Profile.ReviewBy, and
// evidence.EnvProfileRef.ReviewBy all validate against with the identical
// regex. time.DateOnly (Go 1.20+) equals this string; spelled out rather than
// using the constant so the format is visible at the call site of the one
// function in this package that parses it.
const dateLayout = "2006-01-02"

// FreshnessStatus is one review-by date compared against now.
type FreshnessStatus struct {
	// Subject names what the date belongs to, for a report covering more than
	// one document — "environment profile web-tier-2026", say.
	Subject string
	// ReviewBy is the date as the document carries it.
	ReviewBy string
	// Lapsed reports whether now is after ReviewBy. False when ReviewBy could
	// not be parsed — see Unparseable.
	Lapsed bool
	// Unparseable reports that ReviewBy did not parse as YYYY-MM-DD, so Lapsed
	// carries no meaning. Reachable only for a document verify reads directly
	// off disk rather than one that already passed envprofile.Validate's regex
	// check, since a loaded profile cannot reach this function with a
	// malformed date.
	Unparseable bool
}

// CheckFreshness compares reviewBy against now and reports whether it has
// lapsed.
//
// Warn, never fail: what has lapsed is anyone's current assurance that the
// document still reads policy correctly, not the account's actual posture
// (DESIGN §11a, envprofile.Profile.ReviewBy's own doc comment) — a hard
// failure here would make `verify` unusable in the unattended run it exists
// for, over a document that may still be perfectly accurate.
func CheckFreshness(subject, reviewBy string, now time.Time) FreshnessStatus {
	status := FreshnessStatus{Subject: subject, ReviewBy: reviewBy}
	parsed, err := time.Parse(dateLayout, reviewBy)
	if err != nil {
		status.Unparseable = true
		return status
	}
	// "review BY date" admits the whole of that day; lapsed only once it has
	// fully passed, not at its first midnight.
	status.Lapsed = now.After(parsed.AddDate(0, 0, 1))
	return status
}

// String renders the status as one line, for a plain-text report.
func (s FreshnessStatus) String() string {
	switch {
	case s.Unparseable:
		return fmt.Sprintf("%s: review_by %q is not a YYYY-MM-DD date, so freshness cannot be checked",
			s.Subject, s.ReviewBy)
	case s.Lapsed:
		return fmt.Sprintf("%s: review_by %s has passed; re-read this document against current policy",
			s.Subject, s.ReviewBy)
	default:
		return fmt.Sprintf("%s: review_by %s has not yet passed", s.Subject, s.ReviewBy)
	}
}
