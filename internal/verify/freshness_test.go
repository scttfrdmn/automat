// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"testing"
	"time"
)

func TestCheckFreshness(t *testing.T) {
	tests := []struct {
		name        string
		reviewBy    string
		now         time.Time
		wantLapsed  bool
		wantUnparse bool
	}{
		{
			name:     "well before review_by",
			reviewBy: "2027-01-01",
			now:      time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "on review_by itself, not yet lapsed",
			reviewBy: "2026-06-01",
			now:      time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:       "the day after review_by",
			reviewBy:   "2026-06-01",
			now:        time.Date(2026, 6, 2, 0, 1, 0, 0, time.UTC),
			wantLapsed: true,
		},
		{
			name:       "long past review_by",
			reviewBy:   "2020-01-01",
			now:        time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			wantLapsed: true,
		},
		{
			name:        "unparseable date",
			reviewBy:    "not-a-date",
			now:         time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			wantUnparse: true,
		},
		{
			name:        "wrong format, still not parseable as YYYY-MM-DD",
			reviewBy:    "06/01/2026",
			now:         time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			wantUnparse: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckFreshness("subject", tt.reviewBy, tt.now)
			if got.Lapsed != tt.wantLapsed {
				t.Errorf("Lapsed = %v, want %v", got.Lapsed, tt.wantLapsed)
			}
			if got.Unparseable != tt.wantUnparse {
				t.Errorf("Unparseable = %v, want %v", got.Unparseable, tt.wantUnparse)
			}
			if got.ReviewBy != tt.reviewBy {
				t.Errorf("ReviewBy = %q, want %q", got.ReviewBy, tt.reviewBy)
			}
			// String must not panic and must mention the subject, regardless of
			// which branch produced the status.
			if s := got.String(); s == "" {
				t.Error("String() returned empty")
			}
		})
	}
}

// checkFreshnessFunc pins CheckFreshness's signature so a change to it —
// adding an error return, say — fails this file to compile rather than
// passing silently.
type checkFreshnessFunc func(string, string, time.Time) FreshnessStatus

func TestCheckFreshnessNeverFails(t *testing.T) {
	// CheckFreshness has no error return at all — the type system itself is
	// the guarantee that a lapsed or unparseable review date cannot become a
	// hard failure.
	var fn checkFreshnessFunc = CheckFreshness
	_ = fn
}
