// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"

	"github.com/scttfrdmn/automat/internal/org"
)

// renderActions prints a list of ensure-operation outcomes under a header.
//
// One renderer for both halves of the plan/apply split (CLAUDE.md rule 5), and
// that is the point rather than a convenience: a plan printed in a different shape
// from the apply it predicts is a plan nobody can diff against what happened.
// internal/org uses one Action type for both for the same reason, so the only
// thing that differs between the two printouts here is the header.
//
// Errors from the writer are returned rather than ignored. A command whose whole
// output is the list of things it changed must not exit 0 having failed to say
// what they were — the operator's only record of a mutating run is this text.
func renderActions(w io.Writer, header string, actions []org.Action) error {
	if _, err := fmt.Fprintf(w, "%s\n", header); err != nil {
		return fmt.Errorf("write the plan: %w", err)
	}
	if len(actions) == 0 {
		// Reachable, and worth saying out loud: an ensure operation that finds
		// everything already true is the successful second run, not a no-op that
		// failed to do anything.
		if _, err := fmt.Fprintln(w, "  (nothing)"); err != nil {
			return fmt.Errorf("write the plan: %w", err)
		}
		return nil
	}
	for _, a := range actions {
		if _, err := fmt.Fprintf(w, "  %s\n", a.String()); err != nil {
			return fmt.Errorf("write the plan: %w", err)
		}
	}
	return nil
}
