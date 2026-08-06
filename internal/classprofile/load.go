// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package classprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LoadOptions controls how strictly Load treats a document.
type LoadOptions struct {
	// SkipValidate parses without validating. Used only by tests that need to
	// construct an invalid document deliberately.
	//
	// There is no SkipHashCheck counterpart: a classification profile carries no
	// self-declared hash to check (see ContentHash).
	SkipValidate bool
	// SkipAttestationSubjects parses without checking that each attestation names this
	// document's content hash.
	//
	// Needed by the forking path, and that path is the normal one here rather than an
	// edge case: "example-and-forkable" means an institution is expected to take a
	// derived profile, correct automat's reading of its own policy, and re-attest. The
	// document in hand mid-edit correctly has attestations over the previous content,
	// and refusing to load it would mean the only way to re-attest is to delete the
	// interpreter's attestation first, blind.
	SkipAttestationSubjects bool
}

// Decode parses a classification profile from raw JSON.
//
// Unknown fields are rejected: the schema declares additionalProperties false, and an
// unrecognized field in this document is either a typo in something load-bearing —
// `rank` misspelled leaves a level ranked zero, `non_endorsment` drops the disclaimer —
// or a field from a newer schema this build would silently not act on. Both read to an
// operator as a boundary that is in place.
//
// A typo'd `automat_determines` deserves its own mention as the worst case: silently
// ignored, it would leave the field at Go's false zero value, which happens to be the
// safe answer. Rejecting the document means the operator learns the field name was wrong
// rather than being right by luck.
func Decode(data []byte, opts LoadOptions) (*Profile, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()

	var p Profile
	if err := dec.Decode(&p); err != nil {
		return nil, decodeError(err)
	}
	// Reject trailing content; a file with two JSON documents in it is a mistake, not a
	// profile.
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}

	if !opts.SkipValidate {
		// Validate BEFORE canonicalizing, the same ordering envprofile uses and for a
		// sharper reason here: Canonicalize collapses an empty controls array to nil,
		// and a present-but-empty `controls: []` is a defect Validate reports — it
		// claims the source was consulted and stated nothing, which renders identically
		// to a level nobody transcribed. Canonicalizing first would erase the evidence
		// of the very thing being refused.
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	p.Canonicalize()
	if !opts.SkipAttestationSubjects {
		if err := p.VerifyAttestationSubjects(); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

func ensureEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("unexpected trailing content after the JSON document; a file must hold exactly one classification profile")
		}
		return fmt.Errorf("unexpected trailing content after the JSON document: %w", err)
	}
	return nil
}

// decodeError turns encoding/json's terse errors into ones that name the fix.
func decodeError(err error) error {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		// The likeliest instance of this in a classification profile is a rank written
		// as a string — `"rank": "4"` — which is exactly the field whose type carries
		// the ordering, so the hint is worth the extra clause.
		return fmt.Errorf("field %q has the wrong type: expected %s, got JSON %s (at byte offset %d) — "+
			"note that a level's rank is an integer, not a string: it is what orders the levels, and "+
			"string ordering would put rank 10 below rank 2",
			ute.Field, ute.Type, ute.Value, ute.Offset)
	}
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("malformed JSON at byte offset %d: %w", se.Offset, err)
	}
	// A truncated document reports io.ErrUnexpectedEOF, which carries no offset and no
	// hint — and truncation is the likeliest way a profile arrives broken: an interrupted
	// copy, a partial download, a file cut off by a full disk. Left bare it reads as an
	// automat bug rather than as a file to re-fetch.
	//
	// Truncation matters more in this document type than in most, because the blocks
	// that make a derived profile honest sit at the END of the file — policy_caveat,
	// sources, signatures — so a tail-truncated profile is precisely one that has lost
	// its disclaimers while keeping its claims.
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("malformed JSON: the document ends in the middle of a value (%w) — "+
			"the file is truncated; re-fetch or restore it rather than repairing the tail", err)
	}
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("the document is empty (%w); a classification profile must hold one JSON object", err)
	}
	if msg := err.Error(); strings.Contains(msg, "unknown field") {
		return fmt.Errorf("%w — the classification profile schema does not allow unknown fields; "+
			"check for a typo, or bump the schema version if this is a new field", err)
	}
	return err
}

// Load reads and validates a classification profile from a file.
func Load(path string, opts LoadOptions) (*Profile, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller-supplied profile path is the point
	if err != nil {
		return nil, fmt.Errorf("read classification profile %s: %w", path, err)
	}
	p, err := Decode(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// LoadFS reads and validates a classification profile from a filesystem.
//
// This is the path the shipped derived profiles are read by: they are embedded from
// catalogs/classification/ rather than read off disk, so that the bytes automat validates
// are the bytes it was built with.
func LoadFS(fsys fs.FS, path string, opts LoadOptions) (*Profile, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read classification profile %s: %w", path, err)
	}
	p, err := Decode(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Write writes the profile to path in the human-reviewable indented form.
//
// The write is atomic, for the reason artifact.Write's is: a half-written profile that
// still parses would be worse than a missing file. Here that means a levels array cut
// short — a scheme missing its top level reads as complete, and the level it lost is the
// one an operator most needs to see.
//
// Attestation subjects are NOT checked here. Writing is how a document becomes the thing
// its attestations are stale against, and the check that would fail is the same one the
// next Load performs.
func (p *Profile) Write(path string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	data, err := p.MarshalIndented()
	if err != nil {
		return err
	}

	// A classification profile is a reviewed, committed document, and by construction
	// contains nothing secret: every claim in it is a reading of a policy the
	// institution has already published. Writing it 0600 would break the ordinary case
	// of a profile read by another user or by CI running as a different account.
	dir := filepath.Dir(path)
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil { //nolint:gosec // see above: published policy, not a secret
		return fmt.Errorf("create %s: %w", dir, mkErr)
	}
	tmp, err := os.CreateTemp(dir, ".automat-"+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	// CreateTemp makes the file 0600; widen it to match the directory rationale above,
	// since the temp file becomes the profile on rename.
	if err := os.Chmod(tmpName, 0o644); err != nil { //nolint:gosec // published policy, not a secret
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}
