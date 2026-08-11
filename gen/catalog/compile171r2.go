// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// NIST SP 800-171 Revision 2: 110 requirements across 14 families
// (docs/open-questions.md Q4, ROADMAP.md "Backlog — research complete" ›
// "Assessment Stages 1-2").
//
// This catalog carries no AWS-side mapping. Q4 step 3 (Security Hub's NIST
// 800-171 Rev 2 standard and Audit Manager's 800-171 Rev 2 framework) is
// explicitly deferred to a later pass; every one of the 110 requirements here
// compiles as `procedural` with an attestation stub, per Q4 step 4's "everything
// unmapped stays procedural" rule — the same rule cmmc-l1 follows for its six
// unmapped requirements, applied here to all of them because no mapping exists
// yet at all.
//
// The 800-171 R2 requirement number IS this catalog's control id — there is no
// separate final-rule numbering the way CMMC's 32 CFR 170 gives cmmc-l1 one.
// Each control also carries `crosswalk["800-171r2"]` equal to its own id, which
// looks redundant in isolation but is the join key DESIGN §9's procedural dedupe
// (internal/compilesets.DedupeAttestations) uses to recognize that this
// catalog's 3.1.1 and cmmc-l1's AC.L1-b.1.i are the same practice.
const (
	source171r2File  = "800-171r2.json"
	artifact171r2ID  = "800-171r2"
	artifact171r2Ttl = "NIST SP 800-171 Revision 2"
)

const artifact171r2Description = "The 110 security requirements of NIST SP 800-171 Revision 2, " +
	"across its 14 families, extracted from NIST's Cybersecurity and Privacy Reference Tool. " +
	"Rev 2 is withdrawn and will never change, so this is a one-time acquisition. No AWS-side " +
	"mapping is joined yet (docs/open-questions.md Q4 step 3 is deferred future work): every " +
	"requirement here is procedural with an attestation stub."

// req171r2 is one curated requirement entry.
type req171r2 struct {
	ID     string `json:"id"`
	Family string `json:"family"`
	Title  string `json:"title"`
	Text   string `json:"text"`
}

// family171r2 is one curated family entry.
type family171r2 struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// doc171r2 is the curated NIST SP 800-171 Revision 2 source: every requirement's
// verbatim text, grouped by family, plus the provenance of the CPRT extraction
// they were transcribed from.
type doc171r2 struct {
	Comment      string        `json:"_comment"`
	Source       upstream      `json:"source"`
	Families     []family171r2 `json:"families"`
	Requirements []req171r2    `json:"requirements"`
}

// reReq171r2ID matches a bare 800-171 requirement number: one family digit
// (1-14), a dot, and a requirement digit within the family.
var reReq171r2ID = regexp.MustCompile(`^3\.(1[0-4]|[1-9])\.[0-9]{1,2}$`)

// reFamily171r2ID matches a bare 800-171 family number.
var reFamily171r2ID = regexp.MustCompile(`^3\.(1[0-4]|[1-9])$`)

// compileFrom171r2 loads the curated NIST SP 800-171 Revision 2 source and
// compiles the catalog.
func compileFrom171r2(srcDir string) (*artifact.Artifact, error) {
	var doc doc171r2
	fileHash, err := readJSONAndHash(filepath.Join(srcDir, source171r2File), &doc)
	if err != nil {
		return nil, err
	}
	if err := doc.check(); err != nil {
		return nil, err
	}

	famTitles := make(map[string]string, len(doc.Families))
	for _, f := range doc.Families {
		famTitles[f.ID] = f.Title
	}

	controls := make(artifact.Controls, 0, len(doc.Requirements))
	for _, r := range doc.Requirements {
		famTitle, ok := famTitles[r.Family]
		if !ok {
			return nil, fmt.Errorf("%s: requirement %s names family %q, which the file's families "+
				"list does not contain", source171r2File, r.ID, r.Family)
		}
		controls = append(controls, artifact.Control{
			ID:        r.ID,
			Title:     r.Title,
			Statement: r.Text,
			Crosswalk: map[string]string{"800-171r2": r.ID},
			Enforcement: []artifact.EnforcementClass{
				artifact.EnforcementProcedural,
			},
			Attestation: &artifact.Attestation{
				Template:  attestationTemplate171r2(famTitle),
				Frequency: "annual",
				Guidance: fmt.Sprintf("Record how %q (family %s, %s) is implemented, and how that is "+
					"evidenced. NIST SP 800-171A provides the assessment objectives for this requirement; "+
					"automat's detective baseline contributes no machine evidence for it today — no AWS-side "+
					"mapping is compiled into this catalog (docs/open-questions.md Q4 step 3 is deferred).",
					r.Title, r.Family, famTitle),
			},
		})
	}

	a := &artifact.Artifact{
		SchemaVersion: artifact.SchemaVersion,
		Meta: artifact.Meta{
			ID:          artifact171r2ID,
			Title:       artifact171r2Ttl,
			Description: artifact171r2Description,
			Sources:     provenance171r2(doc.Source, fileHash),
			CompiledAt:  doc.Source.RetrievedAt,
		},
		Controls: controls,
	}
	if err := a.SetContentHash(); err != nil {
		return nil, fmt.Errorf("hash artifact %s: %w", artifact171r2ID, err)
	}
	if err := a.Validate(); err != nil {
		return nil, fmt.Errorf("compiled artifact %s does not satisfy its own schema: %w", artifact171r2ID, err)
	}
	return a, nil
}

// attestationTemplate171r2 derives one attestation-stub template name per
// family, rather than per requirement.
//
// 110 per-requirement template names, hand-named ahead of any AWS mapping that
// would justify a per-control distinction, would mostly restate the family:
// nothing in this pass gives any one requirement within a family a different
// evidentiary shape than its siblings, since none of them carry any technical
// coverage yet. A per-family stub is what an operator would actually organize
// evidence collection around, and it keeps the stub set reviewable — 14 entries,
// not 110 — rather than manufacturing granularity this pass has no basis for.
func attestationTemplate171r2(familyTitle string) string {
	slug := strings.ToLower(familyTitle)
	slug = strings.ReplaceAll(slug, " and ", " ")
	slug = strings.Join(strings.Fields(slug), "-")
	return "800-171r2-" + slug + ".md"
}

// provenance171r2 records where this catalog came from.
func provenance171r2(s upstream, fileHash string) artifact.Sources {
	return artifact.Sources{{
		Catalog:     s.Catalog,
		Version:     s.Version,
		URI:         s.URI,
		RetrievedAt: s.RetrievedAt,
		SHA256:      fileHash,
		Note: fmt.Sprintf("verbatim requirement text, all 110 requirements. This entry's sha256 is of "+
			"the curated file gen/sources/%s, which is what the compiler read; it was transcribed from "+
			"the CPRT export at %s (upstream sha256 %s), which is what the uri points at. No AWS-side "+
			"mapping is joined in this pass (docs/open-questions.md Q4 step 3 is deferred future work), "+
			"so every requirement compiles as procedural.",
			source171r2File, s.URI, s.SHA256),
	}}
}

// check validates the source file before anything is compiled from it.
func (d *doc171r2) check() error {
	if err := d.checkProvenance(); err != nil {
		return err
	}

	const wantFamilies = 14
	if n := len(d.Families); n != wantFamilies {
		return fmt.Errorf("%s: found %d families, want %d — NIST SP 800-171 Revision 2 has exactly "+
			"14 families (docs/open-questions.md Q4); re-extract the source", source171r2File, n, wantFamilies)
	}
	const wantRequirements = 110
	if n := len(d.Requirements); n != wantRequirements {
		return fmt.Errorf("%s: found %d requirements, want %d — NIST SP 800-171 Revision 2 has exactly "+
			"110 requirements (docs/open-questions.md Q4); re-extract the source",
			source171r2File, n, wantRequirements)
	}

	seenFam := make(map[string]bool, len(d.Families))
	for _, f := range d.Families {
		if f.ID == "" || f.Title == "" {
			return fmt.Errorf("%s: a family has an empty id or title", source171r2File)
		}
		if !reFamily171r2ID.MatchString(f.ID) {
			return fmt.Errorf("%s: family id %q is not of the form 3.<n> (n = 1-14)", source171r2File, f.ID)
		}
		if seenFam[f.ID] {
			return fmt.Errorf("%s: duplicate family id %s", source171r2File, f.ID)
		}
		seenFam[f.ID] = true
	}

	seenReq := make(map[string]bool, len(d.Requirements))
	var empty []string
	for _, r := range d.Requirements {
		if r.ID == "" || r.Title == "" || r.Text == "" {
			return fmt.Errorf("%s: requirement %q has an empty id, title, or text — an empty requirement "+
				"is worse than an absent one, because it produces output", source171r2File, r.ID)
		}
		if !reReq171r2ID.MatchString(r.ID) {
			return fmt.Errorf("%s: requirement id %q is not of the form 3.<family>.<n>", source171r2File, r.ID)
		}
		if seenReq[r.ID] {
			return fmt.Errorf("%s: duplicate requirement id %s", source171r2File, r.ID)
		}
		seenReq[r.ID] = true
		if !strings.HasPrefix(r.ID, r.Family+".") {
			return fmt.Errorf("%s: requirement %s names family %q, which does not prefix its own id",
				source171r2File, r.ID, r.Family)
		}
		if !seenFam[r.Family] {
			empty = append(empty, r.ID)
		}
	}
	if len(empty) > 0 {
		sort.Strings(empty)
		return fmt.Errorf("%s: requirement(s) %v name a family not present in the families list",
			source171r2File, empty)
	}

	// Every family must have at least one requirement, or the family entry is
	// dead data nothing in the compiled catalog reflects.
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
		return fmt.Errorf("%s: family(ies) %v have no requirements", source171r2File, unused)
	}
	return nil
}

// checkProvenance refuses to compile a source whose own provenance block is
// incomplete, for the same reason the cmmc-l1 loader's version of this check
// gives: a half-filled provenance block reads as verified to a reviewer.
func (d *doc171r2) checkProvenance() error {
	u := d.Source
	switch {
	case u.Catalog == "":
		return fmt.Errorf("%s: provenance block names no catalog", source171r2File)
	case u.SHA256 == "":
		return fmt.Errorf("%s: provenance block has no upstream_sha256; the compiled artifact would "+
			"claim a source it cannot prove", source171r2File)
	case !reUpstreamSHA256.MatchString(u.SHA256):
		return fmt.Errorf("%s: upstream_sha256 %q is not 64 lowercase hex characters", source171r2File, u.SHA256)
	case u.URI == "":
		return fmt.Errorf("%s: provenance block has no uri; a hash with no location cannot be "+
			"re-fetched and re-verified", source171r2File)
	case u.RetrievedAt == "":
		return fmt.Errorf("%s: provenance block has no retrieved_at; the compile timestamp is derived "+
			"from it so that %s is reproducible", source171r2File, artifact171r2ID)
	}
	return nil
}
