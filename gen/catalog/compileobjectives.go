// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/assess"
)

// NIST SP 800-171A objectives catalog: the assessment-objective decomposition
// of NIST SP 800-171 Revision 2's 110 requirements (docs/open-questions.md
// Q4's "Adjacent CPRT datasets found while checking" note; ROADMAP.md
// "Backlog — research complete" › "Assessment Stages 1-2", item 3).
//
// A NEW, STANDALONE document type (schema/objectives-catalog-v1.schema.json,
// DRAFT — see that file's own status note), compiled and validated the same
// way compile171r2.go compiles 800-171r2, but into internal/assess's
// ObjectivesCatalog type rather than artifact.Artifact: several
// control-artifact catalogs share control-artifact-v1.schema.json (cmmc-l1,
// 800-171r2, baseline-protection), and this decomposition is not a field any
// of them need.
const (
	sourceObjectivesFile = "800-171a-objectives.json"
	catalogObjectivesID  = "800-171a-objectives"
	catalogObjectivesTTL = "NIST SP 800-171A objectives"
)

const catalogObjectivesDescription = "The assessment-objective decomposition of NIST SP 800-171 " +
	"Revision 2's 110 requirements, from NIST SP 800-171A version 1.0.0, extracted from NIST's " +
	"Cybersecurity and Privacy Reference Tool. Every requirement id here names a control present " +
	"in catalogs/800-171r2.json; this document adds no enforcement of its own and carries no " +
	"AWS-side mapping — it is read-side data for the 800-171A worksheet Stage 1 will build " +
	"(ROADMAP.md, Assessment Stages 1-2), not consumed by anything in this pass."

// curatedFamily171a is one curated family entry in the objectives source.
type curatedFamily171a struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// curatedObjective171a is one curated determination statement.
type curatedObjective171a struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
}

// curatedAssessmentMethods171a is the curated EXAMINE/INTERVIEW/TEST triple
// for one requirement.
type curatedAssessmentMethods171a struct {
	Examine   string `json:"examine"`
	Interview string `json:"interview"`
	Test      string `json:"test"`
}

// curatedRequirement171a is one curated requirement's objectives.
type curatedRequirement171a struct {
	ID                string                       `json:"id"`
	Family            string                       `json:"family"`
	Objectives        []curatedObjective171a       `json:"objectives"`
	AssessmentMethods curatedAssessmentMethods171a `json:"assessment_methods"`
}

// curatedObjectivesDoc171a is the curated NIST SP 800-171A source: every
// requirement's objectives, grouped by family, plus the provenance of the
// CPRT extraction they were transcribed from.
type curatedObjectivesDoc171a struct {
	Comment      string                   `json:"_comment"`
	Source       upstream                 `json:"source"`
	Families     []curatedFamily171a      `json:"families"`
	Requirements []curatedRequirement171a `json:"requirements"`
}

// reReqOrObjID171a matches either a bare 800-171 requirement id or one with a
// bracketed lowercase-letter objective suffix, mirroring compile171r2.go's
// reReq171r2ID with the optional suffix added.
var reReqOrObjID171a = regexp.MustCompile(`^3\.(1[0-4]|[1-9])\.[0-9]{1,2}(\[[a-z]+\])?$`)

// compileFromObjectives loads the curated NIST SP 800-171A source, compiles
// the objectives catalog, and cross-references it against a freshly
// compiled 800-171r2 control artifact — every objective's requirement id
// must exist there, and every 800-171r2 requirement must have at least one
// objective here, or the compile refuses rather than shipping a silent
// mismatch between NIST's two CPRT datasets.
func compileFromObjectives(srcDir string) (*assess.ObjectivesCatalog, error) {
	var doc curatedObjectivesDoc171a
	fileHash, err := readJSONAndHash(filepath.Join(srcDir, sourceObjectivesFile), &doc)
	if err != nil {
		return nil, err
	}
	if checkErr := doc.check(); checkErr != nil {
		return nil, checkErr
	}

	controlArt, err := compileFrom171r2(srcDir)
	if err != nil {
		return nil, fmt.Errorf("compile 800-171r2 for cross-reference: %w", err)
	}

	reqs := make([]assess.RequirementObjectives, 0, len(doc.Requirements))
	for _, r := range doc.Requirements {
		objs := make([]assess.Objective, 0, len(r.Objectives))
		for _, o := range r.Objectives {
			objs = append(objs, assess.Objective{ID: o.ID, Statement: o.Statement})
		}
		reqs = append(reqs, assess.RequirementObjectives{
			ID:         r.ID,
			Objectives: objs,
			AssessmentMethods: assess.AssessmentMethods{
				Examine:   r.AssessmentMethods.Examine,
				Interview: r.AssessmentMethods.Interview,
				Test:      r.AssessmentMethods.Test,
			},
		})
	}

	oc := &assess.ObjectivesCatalog{
		SchemaVersion: assess.ObjectivesCatalogSchemaVersion,
		Catalog: assess.ObjectivesCatalogMeta{
			ID:               catalogObjectivesID,
			Title:            catalogObjectivesTTL,
			Description:      catalogObjectivesDescription,
			ControlCatalogID: artifact171r2ID,
			Sources:          provenanceObjectives(doc.Source, fileHash),
			CompiledAt:       doc.Source.RetrievedAt,
		},
		Requirements: reqs,
	}
	if err := oc.SetContentHash(); err != nil {
		return nil, fmt.Errorf("hash objectives catalog %s: %w", catalogObjectivesID, err)
	}
	if err := oc.Validate(); err != nil {
		return nil, fmt.Errorf("compiled objectives catalog %s does not satisfy its own schema: %w", catalogObjectivesID, err)
	}
	if err := oc.CrossReferenceControlArtifact(controlArt); err != nil {
		return nil, fmt.Errorf("objectives catalog %s does not match control artifact %s: %w",
			catalogObjectivesID, artifact171r2ID, err)
	}
	return oc, nil
}

// provenanceObjectives records where this catalog came from.
func provenanceObjectives(s upstream, fileHash string) []assess.ObjectivesSource {
	return []assess.ObjectivesSource{{
		Catalog:     s.Catalog,
		Version:     s.Version,
		URI:         s.URI,
		RetrievedAt: s.RetrievedAt,
		SHA256:      fileHash,
		Note: fmt.Sprintf("verbatim objective text, all 110 requirements. This entry's sha256 is of "+
			"the curated file gen/sources/%s, which is what the compiler read; it was transcribed from "+
			"the CPRT export at %s (upstream sha256 %s), which is what the uri points at.",
			sourceObjectivesFile, s.URI, s.SHA256),
	}}
}

// check validates the source file before anything is compiled from it.
func (d *curatedObjectivesDoc171a) check() error {
	if err := d.checkProvenance(); err != nil {
		return err
	}

	const wantFamilies = 14
	if n := len(d.Families); n != wantFamilies {
		return fmt.Errorf("%s: found %d families, want %d — NIST SP 800-171A decomposes the same 14 "+
			"families as 800-171 Revision 2; re-extract the source", sourceObjectivesFile, n, wantFamilies)
	}
	const wantRequirements = 110
	if n := len(d.Requirements); n != wantRequirements {
		return fmt.Errorf("%s: found %d requirements, want %d — NIST SP 800-171A decomposes the same "+
			"110 requirements as 800-171 Revision 2; re-extract the source",
			sourceObjectivesFile, n, wantRequirements)
	}

	seenFam := make(map[string]bool, len(d.Families))
	for _, f := range d.Families {
		if f.ID == "" || f.Title == "" {
			return fmt.Errorf("%s: a family has an empty id or title", sourceObjectivesFile)
		}
		if seenFam[f.ID] {
			return fmt.Errorf("%s: duplicate family id %s", sourceObjectivesFile, f.ID)
		}
		seenFam[f.ID] = true
	}

	seenReq := make(map[string]bool, len(d.Requirements))
	seenObj := make(map[string]string, len(d.Requirements)*2)
	var empty []string
	for _, r := range d.Requirements {
		if r.ID == "" {
			return fmt.Errorf("%s: a requirement has an empty id", sourceObjectivesFile)
		}
		if seenReq[r.ID] {
			return fmt.Errorf("%s: duplicate requirement id %s", sourceObjectivesFile, r.ID)
		}
		seenReq[r.ID] = true
		if !strings.HasPrefix(r.ID, r.Family+".") {
			return fmt.Errorf("%s: requirement %s names family %q, which does not prefix its own id",
				sourceObjectivesFile, r.ID, r.Family)
		}
		if !seenFam[r.Family] {
			empty = append(empty, r.ID)
		}
		if len(r.Objectives) == 0 {
			return fmt.Errorf("%s: requirement %s has no objectives — an empty decomposition is worse "+
				"than an absent one, because it produces output", sourceObjectivesFile, r.ID)
		}
		for _, o := range r.Objectives {
			if o.ID == "" || o.Statement == "" {
				return fmt.Errorf("%s: requirement %s has an objective with an empty id or statement — "+
					"a plausible wrong statement is worse than an obviously absent one, because it "+
					"produces output", sourceObjectivesFile, r.ID)
			}
			if !reReqOrObjID171a.MatchString(o.ID) {
				return fmt.Errorf("%s: objective id %q is not of the form 3.<family>.<n> or "+
					"3.<family>.<n>[<letter>]", sourceObjectivesFile, o.ID)
			}
			if prev, dup := seenObj[o.ID]; dup {
				return fmt.Errorf("%s: duplicate objective id %s (requirements %s and %s)",
					sourceObjectivesFile, o.ID, prev, r.ID)
			}
			seenObj[o.ID] = r.ID
		}
		am := r.AssessmentMethods
		if am.Examine == "" || am.Interview == "" || am.Test == "" {
			return fmt.Errorf("%s: requirement %s is missing an examine, interview, or test method",
				sourceObjectivesFile, r.ID)
		}
	}
	if len(empty) > 0 {
		sort.Strings(empty)
		return fmt.Errorf("%s: requirement(s) %v name a family not present in the families list",
			sourceObjectivesFile, empty)
	}

	used := make(map[string]bool, len(d.Families))
	for _, r := range d.Requirements {
		used[r.Family] = true
	}
	var unused []string
	for _, f := range d.Families {
		if !used[f.ID] {
			unused = append(unused, f.ID)
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		return fmt.Errorf("%s: family(ies) %v have no requirements", sourceObjectivesFile, unused)
	}
	return nil
}

// checkProvenance refuses to compile a source whose own provenance block is
// incomplete, mirroring compile171r2.go's doc171r2.checkProvenance for the
// same reason.
func (d *curatedObjectivesDoc171a) checkProvenance() error {
	u := d.Source
	switch {
	case u.Catalog == "":
		return fmt.Errorf("%s: provenance block names no catalog", sourceObjectivesFile)
	case u.SHA256 == "":
		return fmt.Errorf("%s: provenance block has no upstream_sha256; the compiled catalog would "+
			"claim a source it cannot prove", sourceObjectivesFile)
	case !reUpstreamSHA256.MatchString(u.SHA256):
		return fmt.Errorf("%s: upstream_sha256 %q is not 64 lowercase hex characters", sourceObjectivesFile, u.SHA256)
	case u.URI == "":
		return fmt.Errorf("%s: provenance block has no uri; a hash with no location cannot be "+
			"re-fetched and re-verified", sourceObjectivesFile)
	case u.RetrievedAt == "":
		return fmt.Errorf("%s: provenance block has no retrieved_at; the compile timestamp is derived "+
			"from it so that %s is reproducible", sourceObjectivesFile, catalogObjectivesID)
	}
	return nil
}
