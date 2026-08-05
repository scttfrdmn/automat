// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
)

const (
	artifactID    = "cmmc-l1"
	artifactTitle = "CMMC 2.0 Level 1"
)

const artifactDescription = "The fifteen basic safeguarding requirements of FAR 52.204-21(b)(1), " +
	"which 32 CFR 170.14(c)(2) establishes as CMMC Level 1, joined with the AWS Config " +
	"conformance-pack mapping AWS publishes for them."

// controlTitles are short labels for each requirement.
//
// The CMMC final rule assigns identifiers but not titles, so these are automat's
// own labels; they follow the practice names in common use so a reader can match
// them against an assessment guide. The authoritative text lives verbatim in
// each control's statement field, which is what a reviewer should read.
var controlTitles = map[string]string{
	"AC.L1-b.1.i":    "Authorized access control",
	"AC.L1-b.1.ii":   "Transaction and function control",
	"AC.L1-b.1.iii":  "External connections",
	"AC.L1-b.1.iv":   "Control public information",
	"IA.L1-b.1.v":    "Identification",
	"IA.L1-b.1.vi":   "Authentication",
	"MP.L1-b.1.vii":  "Media disposal",
	"PE.L1-b.1.viii": "Limit physical access",
	"PE.L1-b.1.ix":   "Manage visitors and physical access",
	"SC.L1-b.1.x":    "Boundary protection",
	"SC.L1-b.1.xi":   "Public-access system separation",
	"SI.L1-b.1.xii":  "Flaw remediation",
	"SI.L1-b.1.xiii": "Malicious code protection",
	"SI.L1-b.1.xiv":  "Update malicious code protection",
	"SI.L1-b.1.xv":   "System and file scanning",
}

// compile joins the curated sources into a control artifact.
//
// compiledAt is passed in rather than read from the clock: a catalog is a
// vendored, reviewable file, and `make catalogs` must be able to reproduce it
// byte for byte. The caller derives it from the sources.
func compile(s *sourceSet, compiledAt string) (*artifact.Artifact, error) {
	statements := make(map[string]string, len(s.far.Clauses))
	for _, c := range s.far.Clauses {
		statements[c.Paragraph] = c.Text
	}

	rulesByR2, awsIDByR2, err := indexAWSMapping(s)
	if err != nil {
		return nil, err
	}

	// Track which mapped 800-171 requirements the crosswalk actually consumed,
	// so a mapping AWS publishes can never be silently dropped.
	consumed := make(map[string]bool, len(rulesByR2))

	controls := make(artifact.Controls, 0, len(s.crosswalk.Controls))
	for _, cw := range s.crosswalk.Controls {
		title, ok := controlTitles[cw.ID]
		if !ok {
			return nil, fmt.Errorf("control %s has no title in controlTitles (gen/catalog/compile.go); "+
				"every requirement must be human-labeled before it can be vended against", cw.ID)
		}
		stmt, ok := statements[cw.Paragraph]
		if !ok {
			return nil, fmt.Errorf("control %s references FAR paragraph (%s) with no text in %s",
				cw.ID, cw.Paragraph, farSourceFile)
		}

		c := artifact.Control{
			ID:        cw.ID,
			Title:     title,
			Statement: stmt,
			Crosswalk: map[string]string{
				"far":       fmt.Sprintf("52.204-21(b)(1)(%s)", cw.Paragraph),
				"800-171r2": strings.Join(cw.R2, ", "),
			},
		}

		// Collect every Config rule AWS maps to any of this requirement's R2
		// equivalents, and record the AWS-side identifier so the join is
		// auditable and the legacy numbering stays addressable.
		var ruleNames []string
		var awsIDs []string
		for _, r2 := range cw.R2 {
			if names, ok := rulesByR2[r2]; ok {
				consumed[r2] = true
				ruleNames = append(ruleNames, names...)
				awsIDs = append(awsIDs, awsIDByR2[r2])
			}
		}
		if len(awsIDs) > 0 {
			sort.Strings(awsIDs)
			c.Crosswalk["aws_config_mapping_id"] = strings.Join(dedupe(awsIDs), ", ")
		}

		switch {
		case len(ruleNames) > 0:
			c.Enforcement = []artifact.EnforcementClass{artifact.EnforcementConfigRule}
			if c.ConfigRules, err = configRules(s, dedupe(ruleNames)); err != nil {
				return nil, fmt.Errorf("control %s: %w", cw.ID, err)
			}
		default:
			spec, ok := proceduralSpecs[cw.ID]
			if !ok {
				return nil, fmt.Errorf("control %s has no AWS Config coverage and no attestation stub in "+
					"proceduralSpecs (gen/catalog/enforcement.go); ROADMAP Phase 0 requires unmapped controls "+
					"be marked procedural with a provenance note rather than dropped", cw.ID)
			}
			c.Enforcement = []artifact.EnforcementClass{artifact.EnforcementProcedural}
			c.Attestation = &artifact.Attestation{
				Template:  spec.template,
				Frequency: spec.frequency,
				Guidance:  spec.guidance,
			}
		}
		controls = append(controls, c)
	}

	// Every requirement AWS maps must have landed on some control. If AWS adds a
	// mapping for a requirement the crosswalk does not list, that is a real
	// coverage gap, not something to shrug at.
	var orphans []string
	for r2 := range rulesByR2 {
		if !consumed[r2] {
			orphans = append(orphans, fmt.Sprintf("%s (AWS id %s)", r2, awsIDByR2[r2]))
		}
	}
	if len(orphans) > 0 {
		sort.Strings(orphans)
		return nil, fmt.Errorf("%s maps Config rules to 800-171 requirement(s) that no CMMC Level 1 control "+
			"claims: %v — either the crosswalk in %s is missing an equivalence or the mapping covers a "+
			"requirement outside Level 1; resolve it rather than dropping the rules",
			awsSourceFile, orphans, crosswalkSourceFile)
	}

	if err := checkCandidateNotes(controls); err != nil {
		return nil, err
	}

	a := &artifact.Artifact{
		SchemaVersion: artifact.SchemaVersion,
		Meta: artifact.Meta{
			ID:          artifactID,
			Title:       artifactTitle,
			Description: artifactDescription,
			Sources:     provenance(s),
			CompiledAt:  compiledAt,
		},
		Controls: controls,
	}
	if err := a.SetContentHash(); err != nil {
		return nil, fmt.Errorf("hash artifact %s: %w", artifactID, err)
	}
	if err := a.Validate(); err != nil {
		return nil, fmt.Errorf("compiled artifact %s does not satisfy its own schema: %w", artifactID, err)
	}
	return a, nil
}

// indexAWSMapping re-keys AWS's published mapping from its 800-171-style control
// ids onto bare 800-171 R2 requirement numbers.
//
// AWS publishes ids like "AC.L1-3.1.1" — CMMC 1.0-era numbering that embeds the
// R2 requirement. The R2 number is the join key onto the final-rule ids in
// 32 CFR 170.14(c)(1).
func indexAWSMapping(s *sourceSet) (rulesByR2 map[string][]string, awsIDByR2 map[string]string, err error) {
	rulesByR2 = make(map[string][]string, len(s.aws.AWSConfigMapping))
	awsIDByR2 = make(map[string]string, len(s.aws.AWSConfigMapping))
	for awsID, names := range s.aws.AWSConfigMapping {
		_, r2, ok := strings.Cut(awsID, "-")
		if !ok || r2 == "" {
			return nil, nil, fmt.Errorf("%s: mapping key %q is not of the form DOMAIN.L1-<800-171 requirement>; "+
				"the requirement number is the only thing that joins AWS's mapping to final-rule ids",
				awsSourceFile, awsID)
		}
		if prev, dup := awsIDByR2[r2]; dup {
			return nil, nil, fmt.Errorf("%s: mapping keys %q and %q both reduce to requirement %s",
				awsSourceFile, prev, awsID, r2)
		}
		awsIDByR2[r2] = awsID
		rulesByR2[r2] = names
	}
	return rulesByR2, awsIDByR2, nil
}

// configRules converts pack rule names into artifact config rules.
func configRules(s *sourceSet, names []string) ([]artifact.ConfigRule, error) {
	out := make([]artifact.ConfigRule, 0, len(names))
	for _, name := range names {
		r, ok := s.aws.Rules[name]
		if !ok {
			return nil, fmt.Errorf("rule %q is absent from %s", name, awsSourceFile)
		}
		cr := artifact.ConfigRule{
			Identifier:    r.Identifier,
			Name:          r.Name,
			ResourceTypes: r.ResourceTypes,
		}
		if len(r.Parameters) > 0 {
			cr.Parameters = make(map[string]artifact.RuleParameter, len(r.Parameters))
			for k, v := range r.Parameters {
				order, err := orderFor(name, k)
				if err != nil {
					return nil, err
				}
				cr.Parameters[k] = artifact.RuleParameter{Value: v, Order: order}
			}
		}
		out = append(out, cr)
	}
	return out, nil
}

// provenance converts the source set's entries into artifact sources.
func provenance(s *sourceSet) artifact.Sources {
	entries := s.artifactSources()
	out := make(artifact.Sources, 0, len(entries))
	for _, e := range entries {
		out = append(out, artifact.Source{
			Catalog:     e.catalog,
			Mapping:     e.mapping,
			Version:     e.version,
			RetrievedAt: e.retrievedAt,
			URI:         e.uri,
			SHA256:      e.sha256,
			Note:        e.note,
		})
	}
	return out
}

// compiledAtFrom derives the compile timestamp from the sources themselves.
//
// Using the newest source retrieval time rather than the clock is what makes
// `make catalogs` reproducible: recompiling unchanged sources rewrites the file
// byte for byte, so a diff means an input actually changed.
func compiledAtFrom(s *sourceSet) (string, error) {
	stamps := []string{s.far.Source.RetrievedAt, s.crosswalk.Source.RetrievedAt}
	for _, u := range s.aws.Sources {
		stamps = append(stamps, u.RetrievedAt)
	}
	newest := ""
	for _, t := range stamps {
		if t == "" {
			return "", fmt.Errorf("a curated source is missing retrieved_at; the compile timestamp is "+
				"derived from the sources so that %s is reproducible", artifactID)
		}
		if t > newest { // RFC 3339 UTC second-precision sorts lexicographically
			newest = t
		}
	}
	return newest, nil
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
