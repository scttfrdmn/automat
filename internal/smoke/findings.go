// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build smoke

package smoke

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Finding is one observation about real AWS behavior, captured by a smoke
// subtest for a human to read afterward and fold into
// docs/open-questions.md by hand (docs/smoke.md rule 4: "the output of a
// smoke run is an edit to docs/open-questions.md... not what passed").
//
// Deliberately not evidence.Record's shape, and not sharing a type with it:
// an evidence record is a compliance chain-of-custody claim about a
// production mutation, signed and hash-chained for an auditor years later.
// A Finding is a research note about what real AWS did when nobody has
// documented it, read once by the person who ran the smoke suite and then
// discarded — reusing the compliance shape here would let a research note
// masquerade as a compliance artifact, the same reasoning internal/assess's
// own validate.go gives for not sharing internal/artifact's Problem type.
type Finding struct {
	// Question is the docs/open-questions.md id this observation answers
	// (e.g. "Q9"), so a human reviewing the findings file can go straight to
	// the entry that needs editing.
	Question string `json:"question"`
	// Detail is the free-text observation: an error message and its
	// resource ARN, a latency number, which of several already-handled
	// outcomes occurred. Prose, because the whole point of a Finding is
	// that it does not fit a boolean.
	Detail string `json:"detail"`
	// Extra carries structured data alongside Detail when it exists —
	// latency durations, exception codes, counts — for a human who wants to
	// eyeball the JSON rather than parse the prose. Optional; nil is fine.
	Extra map[string]any `json:"extra,omitempty"`
	// At is when the observation was made, so a findings file spanning a
	// long or resumed run can be read in order.
	At time.Time `json:"at"`
}

// findingsPath resolves where Findings are written: AUTOMAT_SMOKE_FINDINGS
// if set, or a fixed path under the OS temp directory otherwise. A fixed
// default (not a fresh temp file per run) so that re-running the suite
// against the same sandbox appends to one file an operator already knows
// to look at, rather than scattering a new unnamed file per run they'd have
// to hunt for.
func findingsPath() string {
	if p := os.Getenv("AUTOMAT_SMOKE_FINDINGS"); p != "" {
		return p
	}
	return os.TempDir() + "/automat-smoke-findings.jsonl"
}

// recordFinding appends one Finding as a JSON line to the findings file.
//
// Append-only, one line per call: a smoke run's findings accumulate across
// however many subtests actually run (a failed early subtest should not
// erase what a later, independent one already observed), and JSON lines
// (rather than one JSON array) means a run that is killed partway through
// still leaves every line written so far parseable.
func recordFinding(f Finding) error {
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal finding for %s: %w", f.Question, err)
	}
	path := findingsPath()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // operator-chosen path, smoke-tagged only
	if err != nil {
		return fmt.Errorf("open findings file %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write finding for %s to %s: %w", f.Question, path, err)
	}
	return nil
}
