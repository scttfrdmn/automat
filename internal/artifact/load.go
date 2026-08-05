// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

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
	// SkipHashCheck loads without verifying the declared content hash. Used by
	// the catalog compiler, which sets the hash rather than checking it. Every
	// other caller wants the check.
	SkipHashCheck bool
	// SkipValidate parses without validating. Used only by tests that need to
	// construct an invalid document deliberately.
	SkipValidate bool
}

// Decode parses a control artifact from raw JSON.
//
// Unknown fields are rejected: the schema declares additionalProperties false,
// and silently ignoring an unrecognized field in a compliance artifact is how a
// control quietly stops being enforced.
func Decode(data []byte, opts LoadOptions) (*Artifact, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()

	var a Artifact
	if err := dec.Decode(&a); err != nil {
		return nil, decodeError(err)
	}
	// Reject trailing content; a file with two JSON documents in it is a
	// mistake, not an artifact.
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}

	if !opts.SkipValidate {
		if err := a.Validate(); err != nil {
			return nil, err
		}
	}
	if !opts.SkipHashCheck {
		// Canonicalize first: the hash is defined over canonical form, and a
		// hand-edited file may list controls out of order yet still be correct.
		a.Canonicalize()
		if err := a.VerifyContentHash(); err != nil {
			return nil, err
		}
	} else {
		a.Canonicalize()
	}
	return &a, nil
}

func ensureEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("unexpected trailing content after the JSON document; a file must hold exactly one artifact")
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
	if msg := err.Error(); strings.Contains(msg, "unknown field") {
		return fmt.Errorf("%w — the control artifact schema does not allow unknown fields; "+
			"check for a typo, or bump the schema version if this is a new field", err)
	}
	return err
}

// Load reads and validates a control artifact from a file.
func Load(path string, opts LoadOptions) (*Artifact, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller-supplied catalog path is the point
	if err != nil {
		return nil, fmt.Errorf("read control artifact %s: %w", path, err)
	}
	a, err := Decode(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return a, nil
}

// LoadFS reads and validates a control artifact from a filesystem, for embedded
// catalogs.
func LoadFS(fsys fs.FS, path string, opts LoadOptions) (*Artifact, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read control artifact %s: %w", path, err)
	}
	a, err := Decode(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return a, nil
}

// Write writes the artifact to path in the human-reviewable indented form used
// for vendored catalogs, setting its content hash first.
//
// The write is atomic: catalogs are committed artifacts, and a half-written one
// that still parses would be worse than a missing file.
func (a *Artifact) Write(path string) error {
	if err := a.SetContentHash(); err != nil {
		return err
	}
	if err := a.Validate(); err != nil {
		return err
	}
	data, err := a.MarshalIndented()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
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
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}
