// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package envprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// LoadOptions controls how strictly Load treats a document.
type LoadOptions struct {
	// SkipValidate parses without validating. Used only by tests that need to
	// construct an invalid document deliberately.
	//
	// There is no SkipHashCheck counterpart: an environment profile carries no
	// self-declared hash to check (see ContentHash).
	SkipValidate bool
	// SkipAttestationSubjects parses without checking that each attestation names
	// this document's content hash.
	//
	// Needed by the editing path, and only there: an operator who has just changed a
	// profile has a document whose attestations are, correctly, over the previous
	// content. Refusing to load it would mean the only way to re-attest is to delete
	// the old attestations first, blind.
	SkipAttestationSubjects bool
}

// Decode parses an environment profile from raw JSON.
//
// Unknown fields are rejected: the schema declares additionalProperties false, and an
// unrecognized field in this document is either a typo in something load-bearing —
// `permited`, `control_set` — or a field from a newer schema this build would silently
// not act on. Both read to an operator as a boundary that is in place.
func Decode(data []byte, opts LoadOptions) (*Profile, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()

	var p Profile
	if err := dec.Decode(&p); err != nil {
		return nil, decodeError(err)
	}
	// Reject trailing content; a file with two JSON documents in it is a mistake,
	// not a profile.
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}
	// A duplicate key is a second document hiding in this one — see
	// artifact.RejectDuplicateKeys. Established on THIS type: a second "review_by"
	// appended to an environment profile vends and prints 2099-12-31 on the birth
	// certificate while the file says 2027-06-30. Unknown-field rejection does not
	// fire, because the key is known twice.
	if err := artifact.RejectDuplicateKeys(data); err != nil {
		return nil, err
	}

	if !opts.SkipValidate {
		// Validate BEFORE canonicalizing. Canonicalization normalizes the sets whose
		// present-but-empty form is the deny-all Validate exists to refuse, and while
		// keepEmpty preserves that distinction deliberately, ordering the two so the
		// refusal can never depend on it is cheaper than depending on it.
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
			return fmt.Errorf("unexpected trailing content after the JSON document; a file must hold exactly one environment profile")
		}
		return fmt.Errorf("unexpected trailing content after the JSON document: %w", err)
	}
	return nil
}

// decodeError turns encoding/json's terse errors into ones that name the fix.
func decodeError(err error) error {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		return fmt.Errorf("field %q has the wrong type: expected %s, got JSON %s (at byte offset %d)",
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
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("malformed JSON: the document ends in the middle of a value (%w) — "+
			"the file is truncated; re-fetch or restore it rather than repairing the tail", err)
	}
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("the document is empty (%w); an environment profile must hold one JSON object", err)
	}
	if msg := err.Error(); strings.Contains(msg, "unknown field") {
		return fmt.Errorf("%w — the environment profile schema does not allow unknown fields; "+
			"check for a typo, or bump the schema version if this is a new field", err)
	}
	return err
}

// Load reads and validates an environment profile from a file.
func Load(path string, opts LoadOptions) (*Profile, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller-supplied profile path is the point
	if err != nil {
		return nil, fmt.Errorf("read environment profile %s: %w", path, err)
	}
	p, err := Decode(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// LoadFS reads and validates an environment profile from a filesystem, for embedded
// examples and for tests.
func LoadFS(fsys fs.FS, path string, opts LoadOptions) (*Profile, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read environment profile %s: %w", path, err)
	}
	p, err := Decode(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Write writes the profile to path in the human-reviewable indented form.
//
// The write is atomic, for the reason artifact.Write's is: an environment profile is
// the document a vend is decided from, and a half-written one that still parses would
// be worse than a missing file — it would describe a posture nobody chose.
//
// Attestation subjects are NOT checked here. Writing is how a document becomes the
// thing its attestations are stale against, and the check that would fail is the same
// one the next Load performs.
func (p *Profile) Write(path string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	data, err := p.MarshalIndented()
	if err != nil {
		return err
	}

	// An environment profile is a reviewed, committed document meant to be read by
	// the office that approved it, and by design contains no secrets (DESIGN §13).
	// Writing it 0600 would break the ordinary case of a profile read by another user
	// or by CI running as a different account.
	dir := filepath.Dir(path)
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil { //nolint:gosec // see above: reviewed document, not a secret
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
	// CreateTemp makes the file 0600; widen it to match the directory rationale
	// above, since the temp file becomes the profile on rename.
	if err := os.Chmod(tmpName, 0o644); err != nil { //nolint:gosec // reviewed document, not a secret
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}
