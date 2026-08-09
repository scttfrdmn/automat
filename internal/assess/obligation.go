// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// Profile is an obligation profile's full document — the first Go-typed
// reader of the shape schema/obligation-profile-v1.schema.json publishes.
// See package doc for why this is the first consumer entitled to one.
//
// Field set mirrors the schema exactly; a field this package has no present
// use for (assessment.notes, poam.notes, and similar) is still modeled, both
// because DisallowUnknownFields means an unmodeled field is a load failure
// and because a partial reader here would be exactly the second, narrower
// reading of the document the schema's own history warns against
// (schema/CHANGELOG.md's obligation-profile/v1 entry).
type Profile struct {
	SchemaVersion   string             `json:"schema_version"`
	Meta            ProfileMeta        `json:"profile"`
	Status          string             `json:"status"`
	ReviewBy        string             `json:"review_by"`
	Citations       []Citation         `json:"citations"`
	ControlCatalogs []CatalogReference `json:"control_catalogs"`
	Assessment      Assessment         `json:"assessment"`
	Determinations  DeterminationSpec  `json:"determinations"`
	POAM            POAMPolicy         `json:"poam"`
	Scoring         Scoring            `json:"scoring"`
	Submission      Submission         `json:"submission"`
	Applicability   Applicability      `json:"applicability"`
	Signatures      []Attestation      `json:"signatures,omitempty"`
	PolicyCaveat    string             `json:"policy_caveat"`
	Sources         []HashedReference  `json:"sources"`
}

// ProfileMeta identifies the profile.
type ProfileMeta struct {
	ID               string `json:"id"`
	Title            string `json:"title"`
	Description      string `json:"description,omitempty"`
	IssuingAuthority string `json:"issuing_authority"`
}

// Citation is one published instrument behind the obligation.
type Citation struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	EffectiveDate string `json:"effective_date"`
	Role          string `json:"role,omitempty"`
	URI           string `json:"uri,omitempty"`
	Note          string `json:"note,omitempty"`
}

// CatalogReference names a control catalog this obligation is assessed
// against, and whether its revision is pinned by the instrument or left to
// the operator.
type CatalogReference struct {
	Catalog        string `json:"catalog"`
	RevisionPolicy string `json:"revision_policy"`
	Revision       string `json:"revision,omitempty"`
	ArtifactID     string `json:"artifact_id,omitempty"`
	Note           string `json:"note,omitempty"`
}

// RevisionOperatorDetermined is the CatalogReference.RevisionPolicy value
// that requires an operator-supplied revision determination before assess
// may run under this profile.
const RevisionOperatorDetermined = "operator-determined"

// Assessment describes who performs the assessment and how often.
type Assessment struct {
	Type                   string   `json:"type"`
	SignedBy               []string `json:"signed_by"`
	Cadence                string   `json:"cadence"`
	AuditedByIssuer        string   `json:"audited_by_issuer,omitempty"`
	DocumentationSubmitted string   `json:"documentation_submitted,omitempty"`
	Notes                  string   `json:"notes,omitempty"`
}

// DeterminationSpec is the regime's own determination vocabulary and which
// member of it automat may write on its own.
type DeterminationSpec struct {
	Values              []string `json:"values"`
	PartialCredit       bool     `json:"partial_credit"`
	UnderstatementValue string   `json:"understatement_value"`
}

// IsUnderstatementValue reports whether value is the member of Values that
// automat itself may write — the understatement asymmetry
// (docs/assessment-reporting.md, Invariant 2) read as a predicate rather
// than restated as a comparison at every call site.
func (d DeterminationSpec) IsUnderstatementValue(value string) bool {
	return value == d.UnderstatementValue
}

// POAMPolicy states whether unmet items may be deferred under a plan of
// action.
type POAMPolicy struct {
	Permitted          bool   `json:"permitted"`
	RequiresTargetDate bool   `json:"requires_target_date,omitempty"`
	Notes              string `json:"notes,omitempty"`
}

// Scoring names the aggregate scoring method, if any.
type Scoring struct {
	Method      string           `json:"method"`
	WeightTable *HashedReference `json:"weight_table,omitempty"`
}

// Submission states where results go and whether automat may format for
// that target.
type Submission struct {
	Target           string `json:"target"`
	AutomatMayFormat bool   `json:"automat_may_format"`
	Notes            string `json:"notes,omitempty"`
}

// Applicability is prose for a human; see the field's own schema doc comment
// for why it is never evaluable.
type Applicability struct {
	Trigger            string   `json:"trigger"`
	Hints              []string `json:"hints,omitempty"`
	Exclusions         []string `json:"exclusions,omitempty"`
	DeclaredByOperator bool     `json:"declared_by_operator"`
}

// Attestation is one provenance claim over the profile's content hash.
// PROVENANCE ONLY — see schema/obligation-profile-v1.schema.json's own doc
// comment; automat performs no verification of any attestation in v1.
type Attestation struct {
	Role          string     `json:"role"`
	Identity      string     `json:"identity"`
	Statement     string     `json:"statement"`
	ContentSHA256 string     `json:"content_sha256"`
	AttestedAt    string     `json:"attested_at"`
	Signature     *Signature `json:"signature,omitempty"`
}

// Signature is the cryptographic material behind an Attestation, when there
// is any.
type Signature struct {
	Format         string `json:"format"`
	Value          string `json:"value"`
	KeyID          string `json:"key_id,omitempty"`
	IdentityIssuer string `json:"identity_issuer,omitempty"`
}

// HashedReference is a retrieved document, named by hash — the same shape a
// control artifact uses for its own compile sources.
type HashedReference struct {
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Version     string `json:"version,omitempty"`
	RetrievedAt string `json:"retrieved_at,omitempty"`
	URI         string `json:"uri,omitempty"`
	SHA256      string `json:"sha256"`
	Note        string `json:"note,omitempty"`
}

// LoadOptions controls how strictly LoadProfile treats a document.
type LoadOptions struct {
	// SkipValidate parses without validating. Tests only.
	SkipValidate bool
}

// LoadProfile reads and validates an obligation profile from a file.
func LoadProfile(path string, opts LoadOptions) (*Profile, error) {
	data, err := os.ReadFile(path) //nolint:gosec // catalog path is the point, same trust level as artifact.Load
	if err != nil {
		return nil, fmt.Errorf("read obligation profile %s: %w", path, err)
	}
	p, err := decodeProfile(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// LoadProfileFS reads and validates an obligation profile from a
// filesystem, for the embedded catalog tree.
func LoadProfileFS(fsys fs.FS, path string, opts LoadOptions) (*Profile, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read obligation profile %s: %w", path, err)
	}
	p, err := decodeProfile(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// decodeProfile parses an obligation profile from raw JSON.
//
// Unknown fields are rejected: the schema declares additionalProperties
// false, and an obligation profile is a set of claims about a published
// instrument — an ignored field is a claim the writer made and the reader
// dropped, exactly the failure evidence's own Decode refuses for the same
// reason.
func decodeProfile(data []byte, opts LoadOptions) (*Profile, error) {
	var p Profile
	if err := decodeStrict(data, &p); err != nil {
		return nil, err
	}
	if !opts.SkipValidate {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

// newByteReader is the one place this package turns a []byte into the
// io.Reader json.NewDecoder wants, so decodeStrict has a single import to
// account for rather than each caller picking its own.
func newByteReader(data []byte) io.Reader {
	return bytes.NewReader(data)
}

func ensureEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing content after the JSON document; a file holds " +
				"exactly one obligation profile")
		}
		return fmt.Errorf("unexpected trailing content after the JSON document: %w", err)
	}
	return nil
}

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
		return fmt.Errorf("%w — the obligation-profile schema does not allow unknown fields; "+
			"check for a typo, or ask before adding a new field (CLAUDE.md rule 6)", err)
	}
	return err
}
