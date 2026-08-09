// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Determinations is an operator-determinations document — the operator's own
// assertions, the mechanism that makes docs/assessment-reporting.md's
// Invariant 2 enforceable (schema/operator-determinations-v1.schema.json).
// automat itself never writes a Determination; it only reads one back.
type Determinations struct {
	SchemaVersion         string                 `json:"schema_version"`
	RevisionDetermination *RevisionDetermination `json:"revision_determination,omitempty"`
	List                  []Determination        `json:"determinations"`
}

// RevisionDetermination is the operator's own declared revision for a
// control catalog an obligation profile leaves unpinned.
type RevisionDetermination struct {
	Catalog      string `json:"catalog"`
	Revision     string `json:"revision"`
	DeterminedBy string `json:"determined_by"`
	DeterminedAt string `json:"determined_at"`
	Statement    string `json:"statement"`
}

// Determination is one operator assertion: a value from the profile's own
// vocabulary, who is asserting it and when, and the objective(s) it covers.
type Determination struct {
	ID               string   `json:"id"`
	Objectives       []string `json:"objectives"`
	Value            string   `json:"value"`
	Statement        string   `json:"statement"`
	Date             string   `json:"date"`
	ResponsibleParty string   `json:"responsible_party"`
	Note             string   `json:"note,omitempty"`
}

// LoadDeterminations reads and validates an operator-determinations document
// from a file. Validation here is shape-only (Validate); ValidateAgainst
// checks it against a specific obligation profile's own vocabulary and
// revision-policy requirements, since those live in a different document.
func LoadDeterminations(path string, opts LoadOptions) (*Determinations, error) {
	data, err := os.ReadFile(path) //nolint:gosec // determinations path is the point, same trust level as artifact.Load
	if err != nil {
		return nil, fmt.Errorf("read operator determinations %s: %w", path, err)
	}
	d, err := decodeDeterminations(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

// LoadDeterminationsFS reads and validates an operator-determinations
// document from a filesystem.
func LoadDeterminationsFS(fsys fs.FS, path string, opts LoadOptions) (*Determinations, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read operator determinations %s: %w", path, err)
	}
	d, err := decodeDeterminations(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

func decodeDeterminations(data []byte, opts LoadOptions) (*Determinations, error) {
	var d Determinations
	if err := decodeStrict(data, &d); err != nil {
		return nil, err
	}
	if !opts.SkipValidate {
		if err := d.Validate(); err != nil {
			return nil, err
		}
	}
	return &d, nil
}

// decodeStrict decodes data into v with the same three refusals every
// document loader in this package applies: no unknown field, no trailing
// content, no duplicate key. Shared here because Determinations is the
// second document type this package reads; a third would still call this
// rather than a fourth copy of the same three lines.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(newByteReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return decodeError(err)
	}
	if err := ensureEOF(dec); err != nil {
		return err
	}
	return artifact.RejectDuplicateKeys(data)
}

// ContentHash returns the SHA-256 of the document's canonical content — every
// field except schema_version, per this schema's own $comment. Out-of-band:
// no self-referential hash field on the document, matching every other
// document in schema/ (internal/envprofile's ContentHash carries the same
// reasoning).
func (d *Determinations) ContentHash() (string, error) {
	payload := struct {
		RevisionDetermination *RevisionDetermination `json:"revision_determination,omitempty"`
		Determinations        []Determination        `json:"determinations"`
	}{
		RevisionDetermination: d.RevisionDetermination,
		Determinations:        d.List,
	}
	b, err := artifact.CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Find returns the determination with the given id, and whether it exists.
func (d *Determinations) Find(id string) (Determination, bool) {
	for _, det := range d.List {
		if det.ID == id {
			return det, true
		}
	}
	return Determination{}, false
}

// ForObjective returns the determination whose Objectives names objectiveID,
// and whether one exists. A determination may cover more than one objective
// at once (a group treated as one practice); the first match wins, and
// ValidateAgainst refuses a document naming the same objective twice so
// "first" never hides a second, conflicting claim.
func (d *Determinations) ForObjective(objectiveID string) (Determination, bool) {
	for _, det := range d.List {
		for _, obj := range det.Objectives {
			if obj == objectiveID {
				return det, true
			}
		}
	}
	return Determination{}, false
}
