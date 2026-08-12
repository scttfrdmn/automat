// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"

	"github.com/scttfrdmn/automat/internal/evidence"
)

// rotateThresholdRecords is evidence.RotateThresholdRecords, held in a
// package variable rather than read directly so a test can lower it — 2,000
// records is not something a unit test should actually write to exercise
// this path.
var rotateThresholdRecords = evidence.RotateThresholdRecords

// openActiveManifest resolves the manifest an account's next record should be
// appended to, following a rotation pointer if the account's original
// manifest has already been closed by one (Q23, docs/open-questions.md).
//
// Every account's evidence starts at "<accountID>.json", the way it always
// has. Once evidence.RotateThresholdRecords is crossed, that file is closed
// by a terminal OpRotate record naming a successor, and this account's
// active file becomes the successor from then on. A caller that always
// opened "<accountID>.json" directly would find a closed manifest on the
// very next run and fail every subsequent Append with evidence.ErrClosed —
// so every write path needs to follow the pointer rather than assume the
// account-named file is still the live one.
//
// Custody-transfer closes a chain the same way but names no successor to
// follow: an account whose custody has transferred is not automat's to keep
// writing to. The loop stops there — on a custody-transferred manifest, or on
// an open one — and lets the existing evidence.ErrClosed behavior stand for
// the first case.
func openActiveManifest(dir *evidence.Dir, accountID, organizationID, createdAt string) (string, *evidence.Manifest, error) {
	key := accountID
	for {
		m, err := dir.LoadOrNewNamed(key, accountID, accountID, organizationID, createdAt, nil)
		if err != nil {
			return "", nil, err
		}
		last := m.Last()
		if last == nil || last.Operation != evidence.OpRotate || last.Rotation == nil ||
			last.Rotation.SuccessorManifestID == "" {
			return key, m, nil
		}
		key = last.Rotation.SuccessorManifestID
	}
}

// maxRotationSuffixSearch bounds nextRotationKey's scan for an unused
// successor name. Not a limit on how many times an account may legitimately
// be rotated — at RotateThresholdRecords apart, that many rotations is
// millions of records — only a guard against looping forever if something
// else has filled the evidence directory with stray "<accountID>-N.json"
// names.
const maxRotationSuffixSearch = 10000

// nextRotationKey returns the first unused "<accountID>-N" name, starting at
// N=2 ("<accountID>" itself is implicitly the first, unnumbered segment).
//
// Existence is checked through evidence.Dir.Exists against the filesystem
// rather than derived from any counter kept in memory, because the count that
// matters is what is actually on disk: two independently invoked commands
// could each decide to rotate the same account without coordinating, and
// whichever writes second must not collide with the name the first one just
// claimed.
func nextRotationKey(dir *evidence.Dir, accountID string) (string, error) {
	for n := 2; n < maxRotationSuffixSearch; n++ {
		candidate := fmt.Sprintf("%s-%d", accountID, n)
		exists, err := dir.Exists(candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not find an unused rotation name for %s after %d attempts",
		accountID, maxRotationSuffixSearch)
}

// writeManifestWithRotation writes m — already appended to by the caller —
// to key, then rotates it if it has reached evidence.RotateThresholdRecords:
// closes it with a terminal OpRotate record, writes it again with that
// record included, and prints a notice to out.
//
// Nothing here is silent. ROADMAP.md's Q23 entry states this project's
// preference for explicit, disclosed behavior over implicit magic, and an
// operator who never sees the notice below has no way to learn their
// evidence now continues at a second file.
//
// The successor manifest Rotate returns is NOT written here. evidence.Manifest
// refuses to write a chain with zero records (the schema requires at least
// one), so a freshly rotated successor — which holds none yet — has nothing
// valid to write. This is not a gap: the next call for this account goes
// through openActiveManifest, which follows the rotation pointer, finds no
// file at the successor's name, and starts a fresh in-memory manifest for it
// — the same LoadOrNewNamed path every account's very first manifest already
// takes. The successor becomes a real file the first time IT has a record to
// hold, same as any other manifest ever has.
//
// Returns the manifest actually written to by THIS call — the pre-rotation
// one, with the terminal rotate record appended if rotation happened — since
// that is the file whose content just changed, which is what a caller's
// mirror-upload step and birth-certificate print should be looking at.
func writeManifestWithRotation(dir *evidence.Dir, key string, m *evidence.Manifest,
	signer evidence.Signer, now string, out io.Writer) (string, *evidence.Manifest, error) {
	path := dir.Path(key)
	if err := dir.WriteNamed(m, key); err != nil {
		return "", nil, err
	}
	if len(m.Records) < rotateThresholdRecords {
		return path, m, nil
	}

	preRotateCount := len(m.Records)
	successorKey, err := nextRotationKey(dir, m.Meta.AccountID)
	if err != nil {
		return "", nil, fmt.Errorf("manifest %s reached the rotation threshold but a successor name "+
			"could not be chosen: %w", path, err)
	}
	reason := fmt.Sprintf("reached %d records, automat's evidence-manifest rotation threshold of %d",
		preRotateCount, rotateThresholdRecords)
	if _, _, err := m.Rotate(successorKey, reason, now, signer); err != nil {
		return "", nil, fmt.Errorf("rotate evidence manifest %s: %w", path, err)
	}
	if err := dir.WriteNamed(m, key); err != nil {
		return "", nil, fmt.Errorf("write the closed manifest after rotation: %w", err)
	}
	successorPath := dir.Path(successorKey)
	if _, perr := fmt.Fprintf(out, "Rotated evidence manifest: %s is now closed (%d records); "+
		"continuing at %s\n", path, preRotateCount, successorPath); perr != nil {
		return "", nil, fmt.Errorf("write the rotation notice: %w", perr)
	}
	return path, m, nil
}
