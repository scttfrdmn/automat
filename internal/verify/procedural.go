// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/scttfrdmn/automat/internal/baseline"
	"github.com/scttfrdmn/automat/internal/compilesets"
	"github.com/scttfrdmn/automat/internal/safeio"
)

// StaleAfter maps an attestation frequency (internal/artifact.AllFrequencies)
// to how long a stub's content may go unreviewed before CheckProcedural
// calls it stale — DESIGN §12's own wording for the procedural layer:
// "attestation stubs present; staleness vs. declared frequency". DESIGN.md
// does not name exact day-thresholds for any frequency, so this mapping is
// this package's own choice, stated here rather than buried in a
// conditional, so it can be read, argued with, and changed in one place.
//
// annual/semiannual/quarterly/monthly use the calendar reading of the word,
// at 365/182/91/30 days — deliberately not calendar-exact (a year is not
// always 365 days), because a mtime-based staleness check has no way to know
// which anniversary a stub is measured against and an off-by-a-day slop in
// the conservative direction (a control that turns stale a day or two before
// its true anniversary) is a cheaper mistake than the reverse.
//
// on-change and continuous are deliberately ABSENT from this map, and that
// absence is load-bearing, not an oversight: neither cadence names a
// calendar interval at all. "on-change" means "attested again when the
// underlying practice changes", a fact this tool has no way to observe from
// a file's mtime — a stub five years old may be perfectly current if nothing
// about the practice changed, and a stub written yesterday may already be
// stale if the practice changed today. "continuous" is the same non-claim
// one level further: the practice is supposed to be attested continuously,
// which a point-in-time tool (DESIGN.md's own non-goal: "no continuous
// monitoring / evidence collection agents") cannot itself observe either.
// staleAfter's own doc comment states what CheckProcedural does with a
// frequency absent from this map: it is never reported stale by time,
// because time is not the fact that would make it stale.
var staleAfter = map[string]time.Duration{
	"annual":     365 * 24 * time.Hour,
	"semiannual": 182 * 24 * time.Hour,
	"quarterly":  91 * 24 * time.Hour,
	"monthly":    30 * 24 * time.Hour,
}

// staleAfterFrequency reports the staleness threshold for frequency, and
// whether that frequency is time-checkable at all — see the staleAfter map's
// own doc comment for on-change/continuous's deliberate absence, and for an
// unrecognized frequency (which should be impossible for a group that passed
// artifact validation, but this function does not assume that of a caller).
func staleAfterFrequency(frequency string) (time.Duration, bool) {
	d, ok := staleAfter[frequency]
	return d, ok
}

// AttestationStubStatus is CheckProcedural's finding for one deduped
// attestation group: does its stub file exist, is it empty, and — when its
// frequency is time-checkable — is it stale.
type AttestationStubStatus struct {
	// ControlIDs is the group's own DedupedAttestation.ControlIDs, carried
	// through for the report line.
	ControlIDs []string
	// FileName is the stub's expected basename, computed the identical way
	// internal/baseline.EnsureAttestationStubs would (baseline.StubFileName).
	FileName string
	// Frequency is the group's declared cadence, for the report line and for
	// StaleChecked's own reasoning.
	Frequency string

	// Present reports whether the stub file exists at all.
	Present bool
	// Empty reports whether it exists but carries no content — the same
	// "never filled in" state internal/baseline/attestations.go's own doc
	// comment describes for an operator's bare `touch`. Meaningless when
	// Present is false. A DIFFERENT, also-reportable finding from Stale: an
	// empty stub was never written into at all, while a stale one was
	// written into once and has since aged past its own declared cadence.
	Empty bool
	// StaleChecked reports whether Frequency names a time-checkable cadence
	// at all (staleAfterFrequency's own ok return) — false for "on-change"
	// and "continuous", where Stale carries no meaning either way (the
	// staleAfter map's own doc comment). Checking this before reading Stale
	// is what keeps "not stale" and "staleness is not a calendar fact for
	// this cadence" from collapsing into the same false value.
	StaleChecked bool
	// Stale reports whether the stub's mtime is older than its frequency's
	// staleness threshold. Meaningless when Present is false, Empty is true,
	// or StaleChecked is false.
	Stale bool
	// ModTime is the stub's last-modified time, zero when Present is false.
	ModTime time.Time
}

// Clean reports whether this stub is exactly what its group describes:
// present, non-empty, and (when its cadence is time-checkable) not stale.
func (s *AttestationStubStatus) Clean() bool {
	return s != nil && s.Present && !s.Empty && (!s.StaleChecked || !s.Stale)
}

// ProceduralReport is CheckProcedural's result: one AttestationStubStatus per
// deduped attestation group, in the order groups was given (compilesets.
// DedupeAttestations' own deterministic sort — see that function's doc
// comment).
type ProceduralReport struct {
	Stubs []AttestationStubStatus
}

// Clean reports whether every stub is present, non-empty, and not stale by
// its own declared cadence. The one-line answer a cron job's exit code is
// built from, matching PolicyReport.Clean's own shape.
func (r *ProceduralReport) Clean() bool {
	if r == nil {
		return true
	}
	for i := range r.Stubs {
		if !r.Stubs[i].Clean() {
			return false
		}
	}
	return true
}

// CheckProcedural compares the attestation stubs a vend would have written
// (or would write on a future vend, for a group added since) against what
// actually exists under dir, read-only.
//
// A group whose stub is missing entirely (Present false) is a clear
// finding — a documented control with no evidence it was ever attested. A
// group whose stub exists but is empty (Empty true) is a DIFFERENT,
// also-reportable finding: it was created (by an earlier vend, or an
// operator's `touch`) but never written into. Neither is treated as "could
// not be checked" — both are definite, reportable answers to "does this
// stub exist and carry content", which safeio.OpenDirUnder's own read-only
// resolution can always determine without creating anything (unlike
// internal/baseline.EnsureAttestationStubs' own plan-mode branch, which
// cannot check existence without ALSO being willing to create the
// directory — see that method's doc comment. CheckProcedural has no such
// conflict: a missing directory is read as "every stub in it is missing",
// which is the honest answer, not skipped).
//
// len(groups) == 0 (a compile with no procedural control at all) returns a
// report with an empty Stubs slice, which Clean() reports as true — nothing
// was asked for, so there is nothing to be dirty. This mirrors
// DetectiveReport's own "opt-in, and not opted into" discipline for a
// profile whose config_recorder is disabled.
func CheckProcedural(dir string, groups []compilesets.DedupedAttestation, now time.Time) (*ProceduralReport, error) {
	report := &ProceduralReport{Stubs: make([]AttestationStubStatus, 0, len(groups))}
	if len(groups) == 0 {
		return report, nil
	}

	root, err := safeio.OpenDirUnder(".", dir)
	missingDir := errors.Is(err, fs.ErrNotExist)
	if err != nil && !missingDir {
		return nil, fmt.Errorf("open the attestation directory %s: %w", dir, err)
	}
	if root != nil {
		defer func() { _ = root.Close() }()
	}

	for i := range groups {
		g := &groups[i]
		fileName, ferr := baseline.StubFileName(g)
		if ferr != nil {
			return nil, ferr
		}
		status := AttestationStubStatus{
			ControlIDs: append([]string(nil), g.ControlIDs...),
			FileName:   fileName,
			Frequency:  g.Frequency,
		}
		if threshold, ok := staleAfterFrequency(g.Frequency); ok {
			status.StaleChecked = true
			if !missingDir {
				if err := statOneStub(root, fileName, dir+"/"+fileName, now, threshold, &status); err != nil {
					return nil, err
				}
			}
		} else if !missingDir {
			// Frequency is not time-checkable, but Present/Empty are still
			// definite, checkable facts about the file regardless — only
			// Stale is withheld.
			if err := statOneStub(root, fileName, dir+"/"+fileName, now, 0, &status); err != nil {
				return nil, err
			}
		}
		report.Stubs = append(report.Stubs, status)
	}
	return report, nil
}

// statOneStub fills Present, Empty, ModTime, and — when threshold is
// nonzero — Stale into status, via safeio.OpenChecked's read-only descriptor
// discipline: no symlink substitution, no FIFO stall (internal/safeio's own
// package doc). A missing file is fs.ErrNotExist, unwrapped, exactly the
// signal internal/baseline/attestations.go's own ensureOneStub already
// treats as "nothing here yet" — read the same way here, as Present: false,
// not an error.
func statOneStub(root *os.Root, fileName, shown string, now time.Time, threshold time.Duration,
	status *AttestationStubStatus) error {
	f, fi, err := safeio.OpenChecked(root, fileName, shown)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check attestation stub %s: %w", shown, err)
	}
	defer func() { _ = f.Close() }()

	status.Present = true
	status.ModTime = fi.ModTime()
	if fi.Size() == 0 {
		status.Empty = true
		return nil
	}
	if threshold > 0 {
		status.Stale = now.Sub(fi.ModTime()) > threshold
	}
	return nil
}
