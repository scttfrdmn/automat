// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// ObjectivesCatalogSchemaVersion is the objectives-catalog schema version
// this build emits and reads. schema/objectives-catalog-v1.schema.json is a
// DRAFT — see that file's $comment_draft_status — so this constant, like the
// schema itself, is not yet a ratified contract the way
// artifact.SchemaVersion is (ROADMAP.md's "Backlog — research complete",
// Phase 0: the schema file is an identified-but-not-yet-sent pre-approval
// ask).
const ObjectivesCatalogSchemaVersion = "1.0.0"

// ObjectivesCatalog is NIST's assessment-objective decomposition of a
// control catalog's requirements (schema/objectives-catalog-v1.schema.json,
// DRAFT). Deliberately a NEW, STANDALONE document type rather than a field
// on artifact.Control: several control-artifact catalogs share that schema
// (cmmc-l1, 800-171r2, baseline-protection), and adding an Objectives field
// there would be a schema change to all of them for a decomposition only
// 800-171-family catalogs have. Nothing in internal/assess yet USES this
// type for worksheet rendering or scoring — that is Stage 1/2, a later,
// separate task (ROADMAP.md, "Assessment Stages 1-2").
type ObjectivesCatalog struct {
	SchemaVersion string                  `json:"schema_version"`
	Catalog       ObjectivesCatalogMeta   `json:"catalog"`
	Requirements  []RequirementObjectives `json:"requirements"`
}

// ObjectivesCatalogMeta identifies the objectives catalog and names the
// control-artifact catalog it decomposes.
type ObjectivesCatalogMeta struct {
	ID               string             `json:"id"`
	Title            string             `json:"title"`
	Description      string             `json:"description,omitempty"`
	ControlCatalogID string             `json:"control_catalog_id"`
	Sources          []ObjectivesSource `json:"sources"`
	CompiledAt       string             `json:"compiled_at"`
	ContentHash      string             `json:"content_sha256"`
}

// ObjectivesSource is one compile input, mirroring artifact.Source's shape
// minus the artifact-union member (an objectives catalog is never a union of
// other objectives catalogs).
type ObjectivesSource struct {
	Catalog     string `json:"catalog"`
	Version     string `json:"version,omitempty"`
	RetrievedAt string `json:"retrieved_at,omitempty"`
	URI         string `json:"uri,omitempty"`
	SHA256      string `json:"sha256"`
	Note        string `json:"note,omitempty"`
}

// RequirementObjectives is one requirement's assessment-objective
// decomposition: its lettered determination statements, plus the candidate
// evidence sources NIST associates with the requirement as a whole.
type RequirementObjectives struct {
	ID                string            `json:"id"`
	Objectives        []Objective       `json:"objectives"`
	AssessmentMethods AssessmentMethods `json:"assessment_methods"`
}

// Objective is one assessment-objective determination statement, e.g.
// "3.1.1[a]": "authorized users are identified.".
//
// MethodClass is reserved and unpopulated by every catalog this package
// compiles today: NIST's own CPRT data model attaches one EXAMINE/INTERVIEW/
// TEST triple to the requirement as a whole (AssessmentMethods), not to each
// lettered determination, so there is no per-objective method class to
// record without inventing a distinction the source does not make. The
// field exists so a later pass that does find a finer-grained source is an
// additive change, not a restructuring one.
type Objective struct {
	ID          string   `json:"id"`
	Statement   string   `json:"statement"`
	MethodClass []string `json:"method_class,omitempty"`
}

// AssessmentMethods is the candidate EXAMINE/INTERVIEW/TEST evidence sources
// NIST associates with one requirement.
type AssessmentMethods struct {
	Examine   string `json:"examine"`
	Interview string `json:"interview"`
	Test      string `json:"test"`
}

// reObjectiveID matches an objective id: a requirement number, optionally
// followed by a bracketed lowercase-letter suffix — NIST's own CPRT
// identifier shape (e.g. "3.1.1", "3.1.1[a]"), not a value automat mints.
var reObjectiveID = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*(\[[a-z]+\])?$`)

// ObjectivesLoadOptions controls how strictly LoadObjectivesCatalog treats a
// document. Named distinctly from LoadOptions (used by Profile and
// Determinations) rather than reused, because a SkipHashCheck knob belongs
// here and does not on those two types — reusing the type would make an
// irrelevant field appear applicable to every loader in the package.
type ObjectivesLoadOptions struct {
	// SkipValidate parses without validating. Tests only.
	SkipValidate bool
	// SkipHashCheck loads without verifying the declared content hash. Used
	// by the catalog compiler, which sets the hash rather than checking it.
	SkipHashCheck bool
}

// LoadObjectivesCatalog reads and validates an objectives catalog from a
// file.
func LoadObjectivesCatalog(path string, opts ObjectivesLoadOptions) (*ObjectivesCatalog, error) {
	data, err := os.ReadFile(path) //nolint:gosec // catalog path is the point, same trust level as artifact.Load
	if err != nil {
		return nil, fmt.Errorf("read objectives catalog %s: %w", path, err)
	}
	oc, err := decodeObjectivesCatalog(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return oc, nil
}

// LoadObjectivesCatalogFS reads and validates an objectives catalog from a
// filesystem, for the embedded catalog tree.
func LoadObjectivesCatalogFS(fsys fs.FS, path string, opts ObjectivesLoadOptions) (*ObjectivesCatalog, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read objectives catalog %s: %w", path, err)
	}
	oc, err := decodeObjectivesCatalog(data, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return oc, nil
}

// decodeObjectivesCatalog parses an objectives catalog from raw JSON.
//
// Unknown fields, trailing content, and duplicate keys are all refused —
// the same three-refusal discipline decodeStrict applies to Profile and
// Determinations, so an unrecognized field in this catalog cannot be
// silently dropped.
func decodeObjectivesCatalog(data []byte, opts ObjectivesLoadOptions) (*ObjectivesCatalog, error) {
	var oc ObjectivesCatalog
	if err := decodeStrict(data, &oc); err != nil {
		return nil, err
	}
	if !opts.SkipValidate {
		if err := oc.Validate(); err != nil {
			return nil, err
		}
	}
	if !opts.SkipHashCheck {
		if err := oc.VerifyContentHash(); err != nil {
			return nil, err
		}
	}
	return &oc, nil
}

// Canonicalize puts the catalog into canonical form in place: requirements
// sorted by id, and within each requirement, objectives sorted by id. This
// is what makes the content hash meaningful — two catalogs with the same
// requirements must hash identically no matter what order they arrived in —
// mirroring artifact.Artifact.Canonicalize's role for control artifacts.
func (oc *ObjectivesCatalog) Canonicalize() {
	sort.SliceStable(oc.Requirements, func(i, j int) bool {
		return oc.Requirements[i].ID < oc.Requirements[j].ID
	})
	for i := range oc.Requirements {
		objs := oc.Requirements[i].Objectives
		sort.SliceStable(objs, func(a, b int) bool { return objs[a].ID < objs[b].ID })
	}
}

// MarshalIndented renders the catalog as stable, human-reviewable JSON with
// a trailing newline, canonicalizing first — the same convention
// artifact.Artifact.MarshalIndented follows for vendored catalogs.
func (oc *ObjectivesCatalog) MarshalIndented() ([]byte, error) {
	oc.Canonicalize()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(oc); err != nil {
		return nil, fmt.Errorf("marshal objectives catalog %q: %w", oc.Catalog.ID, err)
	}
	return buf.Bytes(), nil
}

// Write writes the catalog to path in the human-reviewable indented form
// used for vendored catalogs, setting its content hash first. The write is
// atomic, mirroring artifact.Artifact.Write's reasoning: a catalog is a
// committed artifact, and a half-written one that still parses would be
// worse than a missing file.
func (oc *ObjectivesCatalog) Write(path string) error {
	if err := oc.SetContentHash(); err != nil {
		return err
	}
	if err := oc.Validate(); err != nil {
		return err
	}
	data, err := oc.MarshalIndented()
	if err != nil {
		return err
	}

	// A catalog is a published, committed artifact — meant to be
	// world-readable and, by design, containing no secrets (DESIGN §13).
	dir := filepath.Dir(path)
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil { //nolint:gosec // see above: published artifact, not a secret
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
	if err := os.Chmod(tmpName, 0o644); err != nil { //nolint:gosec // published artifact, not a secret
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// ContentHash returns the SHA-256 of the catalog's canonical content:
// requirements[] alone. Excluded: schema_version (a major bump changes what
// the covered fields mean) and the catalog metadata block (which carries
// this value, and whose sources entries are each vouched for by their own
// sha256) — the same exclusions control-artifact-v1's own content hash
// makes, for the same reasons.
func (oc *ObjectivesCatalog) ContentHash() (string, error) {
	payload := struct {
		Requirements []RequirementObjectives `json:"requirements"`
	}{
		Requirements: oc.Requirements,
	}
	b, err := artifact.CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// SetContentHash canonicalizes the catalog and stores its computed content
// hash in Catalog.ContentHash.
func (oc *ObjectivesCatalog) SetContentHash() error {
	oc.Canonicalize()
	h, err := oc.ContentHash()
	if err != nil {
		return err
	}
	oc.Catalog.ContentHash = h
	return nil
}

// VerifyContentHash recomputes the content hash and reports a mismatch as an
// error naming both values.
func (oc *ObjectivesCatalog) VerifyContentHash() error {
	got, err := oc.ContentHash()
	if err != nil {
		return err
	}
	if oc.Catalog.ContentHash != got {
		return fmt.Errorf(
			"objectives catalog %q content hash mismatch: document declares %s but its requirements "+
				"hash to %s; the requirements were edited without recompiling or the file is corrupt",
			oc.Catalog.ID, oc.Catalog.ContentHash, got)
	}
	return nil
}

// Find returns the requirement-objectives entry for the given requirement
// id, and whether it exists.
func (oc *ObjectivesCatalog) Find(requirementID string) (RequirementObjectives, bool) {
	for _, r := range oc.Requirements {
		if r.ID == requirementID {
			return r, true
		}
	}
	return RequirementObjectives{}, false
}

// CrossReferenceControlArtifact checks that this objectives catalog and art
// name exactly the same requirement ids — every objective's requirement id
// exists in art's controls, and every control in art has at least one
// objective here. A mismatch either direction is reported in full rather
// than at the first difference, since a maintainer resolving a real
// discrepancy between NIST's two CPRT datasets wants the whole set, not one
// id at a time.
func (oc *ObjectivesCatalog) CrossReferenceControlArtifact(art *artifact.Artifact) error {
	haveObjectives := make(map[string]bool, len(oc.Requirements))
	for _, r := range oc.Requirements {
		haveObjectives[r.ID] = true
	}
	haveControls := make(map[string]bool, len(art.Controls))
	for _, c := range art.Controls {
		haveControls[c.ID] = true
	}

	var onlyInObjectives, onlyInControls []string
	for id := range haveObjectives {
		if !haveControls[id] {
			onlyInObjectives = append(onlyInObjectives, id)
		}
	}
	for id := range haveControls {
		if !haveObjectives[id] {
			onlyInControls = append(onlyInControls, id)
		}
	}
	if len(onlyInObjectives) == 0 && len(onlyInControls) == 0 {
		return nil
	}

	var probs problems
	for _, id := range sortedStrings(onlyInObjectives) {
		probs.add(fmt.Sprintf("requirements[%s]", id),
			fmt.Sprintf("names a requirement not present in control artifact %q", art.Meta.ID),
			"remove the orphaned entry, or check whether the objectives catalog and the control "+
				"artifact were retrieved from different NIST revisions")
	}
	for _, id := range sortedStrings(onlyInControls) {
		probs.add(fmt.Sprintf("control_artifact.controls[%s]", id),
			fmt.Sprintf("has no matching entry in objectives catalog %q", oc.Catalog.ID),
			"add an objectives entry for this requirement, or confirm NIST's own objectives "+
				"dataset genuinely has none for it and document why")
	}
	return &ValidationError{
		Subject:  fmt.Sprintf("objectives catalog %q cross-referenced against control artifact %q", oc.Catalog.ID, art.Meta.ID),
		Problems: probs.list,
	}
}

// sortedStrings returns a's elements in a stable sorted order, for
// deterministic error output.
func sortedStrings(a []string) []string {
	out := make([]string, len(a))
	copy(out, a)
	sort.Strings(out)
	return out
}

// Validate checks the objectives catalog against
// schema/objectives-catalog-v1.schema.json's constraints (DRAFT — see that
// file's own status note) and returns a *ValidationError listing every
// problem found. Reports every problem in one pass, the same reasoning
// Profile.Validate and Determinations.Validate give.
func (oc *ObjectivesCatalog) Validate() error {
	var probs problems

	if oc.SchemaVersion == "" {
		probs.add("schema_version", "missing", "set it, e.g. \""+ObjectivesCatalogSchemaVersion+"\"")
	} else if !reSemver.MatchString(oc.SchemaVersion) {
		probs.add("schema_version", fmt.Sprintf("%s is not semver", safe(oc.SchemaVersion)), "use MAJOR.MINOR.PATCH")
	}

	oc.validateCatalogMeta(&probs)

	if len(oc.Requirements) == 0 {
		probs.add("requirements", "empty", "an objectives catalog with no requirements decomposes nothing")
	}
	seenReq := make(map[string]int, len(oc.Requirements))
	for i, r := range oc.Requirements {
		path := fmt.Sprintf("requirements[%d]", i)
		if r.ID == "" {
			probs.add(path+".id", "missing", "use the requirement's id in the referenced control-artifact catalog")
		} else {
			if prev, dup := seenReq[r.ID]; dup {
				probs.add(path+".id", fmt.Sprintf("duplicate requirement id %s (first seen at requirements[%d])", safe(r.ID), prev), "")
			}
			seenReq[r.ID] = i
			path = fmt.Sprintf("requirements[%s]", safe(r.ID))
		}
		oc.validateRequirementObjectives(&probs, path, r)
	}

	if len(probs.list) == 0 {
		return nil
	}
	return &ValidationError{Subject: "objectives catalog " + safe(oc.Catalog.ID), Problems: probs.list}
}

func (oc *ObjectivesCatalog) validateCatalogMeta(probs *problems) {
	m := oc.Catalog
	if m.ID == "" {
		probs.add("catalog.id", "missing", "give the catalog a stable id, e.g. \"800-171a-objectives\"")
	} else if !reSlug.MatchString(m.ID) {
		probs.add("catalog.id", fmt.Sprintf("%s is not a valid id", safe(m.ID)),
			"use 2-64 chars of lowercase letters, digits, and hyphens, starting and ending alphanumeric")
	}
	if m.Title == "" {
		probs.add("catalog.title", "missing", "give the catalog a human-readable title")
	}
	if m.ControlCatalogID == "" {
		probs.add("catalog.control_catalog_id", "missing",
			"name the control-artifact catalog this document decomposes, e.g. \"800-171r2\"")
	} else if !reSlug.MatchString(m.ControlCatalogID) {
		probs.add("catalog.control_catalog_id", fmt.Sprintf("%s is not a valid catalog id", safe(m.ControlCatalogID)), "")
	}
	if m.CompiledAt == "" {
		probs.add("catalog.compiled_at", "missing", "set it to the compile time in RFC 3339 UTC")
	} else if !reTimestamp.MatchString(m.CompiledAt) {
		probs.add("catalog.compiled_at", fmt.Sprintf("%s is not second-precision UTC RFC 3339", safe(m.CompiledAt)), "")
	}
	if m.ContentHash == "" {
		probs.add("catalog.content_sha256", "missing", "call SetContentHash before writing the catalog")
	} else if !reSHA256.MatchString(m.ContentHash) {
		probs.add("catalog.content_sha256", fmt.Sprintf("%s is not a lowercase hex SHA-256", safe(m.ContentHash)), "")
	}
	if len(m.Sources) == 0 {
		probs.add("catalog.sources", "empty", "record at least one source with its sha256")
	}
	for i, s := range m.Sources {
		path := fmt.Sprintf("catalog.sources[%d]", i)
		if s.Catalog == "" {
			probs.add(path+".catalog", "missing", "name the authoritative source, e.g. \"NIST SP 800-171A\"")
		}
		if s.SHA256 == "" {
			probs.add(path+".sha256", "missing", "hash the source bytes you actually consumed")
		} else if !reSHA256.MatchString(s.SHA256) {
			probs.add(path+".sha256", fmt.Sprintf("%s is not a lowercase hex SHA-256", safe(s.SHA256)), "")
		}
		if s.RetrievedAt != "" && !reTimestamp.MatchString(s.RetrievedAt) {
			probs.add(path+".retrieved_at", fmt.Sprintf("%s is not second-precision UTC RFC 3339", safe(s.RetrievedAt)), "")
		}
	}
}

func (oc *ObjectivesCatalog) validateRequirementObjectives(probs *problems, path string, r RequirementObjectives) {
	if len(r.Objectives) == 0 {
		probs.add(path+".objectives", "empty", "a requirement with no objectives decomposes into nothing")
	}
	seenObj := make(map[string]int, len(r.Objectives))
	for i, o := range r.Objectives {
		opath := fmt.Sprintf("%s.objectives[%d]", path, i)
		switch {
		case o.ID == "":
			probs.add(opath+".id", "missing", "use NIST's own objective id, e.g. \"3.1.1[a]\"")
		case !reObjectiveID.MatchString(o.ID):
			probs.add(opath+".id", fmt.Sprintf("%s is not a valid objective id", safe(o.ID)),
				"use the requirement id, optionally with a bracketed lowercase-letter suffix, e.g. \"3.1.1\" or \"3.1.1[a]\"")
		default:
			if prev, dup := seenObj[o.ID]; dup {
				probs.add(opath+".id", fmt.Sprintf("duplicate objective id %s (first seen at %s.objectives[%d])",
					safe(o.ID), path, prev), "")
			}
			seenObj[o.ID] = i
		}
		if o.Statement == "" {
			probs.add(opath+".statement", "missing",
				"a plausible wrong statement is worse than an obviously absent one, because it produces output — "+
					"do not fill this in from memory")
		}
		for j, mc := range o.MethodClass {
			if mc != "examine" && mc != "interview" && mc != "test" {
				probs.add(fmt.Sprintf("%s.method_class[%d]", opath, j),
					fmt.Sprintf("%s is not one of examine, interview, test", safe(mc)), "")
			}
		}
	}

	am := r.AssessmentMethods
	if am.Examine == "" {
		probs.add(path+".assessment_methods.examine", "missing", "")
	}
	if am.Interview == "" {
		probs.add(path+".assessment_methods.interview", "missing", "")
	}
	if am.Test == "" {
		probs.add(path+".assessment_methods.test", "missing", "")
	}
}
