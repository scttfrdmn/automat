// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"strings"
	"testing"
)

// These two schemas have no Go types yet (internal/assess, Phase 4 assess
// Stage 3, not yet written) — the same situation obligation-profile/v1 was in
// before this package's obligation_profile_test.go existed. A minimal sample
// document, hand-built against the published schema, is what stands in for a
// Go-side round trip until a real implementation exists; see the schema's own
// $comment for the content-hash scope this stands in for.

func sampleAssessmentResult() map[string]any {
	return map[string]any{
		"schema_version": "1.0.0",
		"rendered_at":    "2026-08-09T00:00:00Z",
		"tool_version":   "dev",
		"account": map[string]any{
			"id":              "111122223333",
			"scope_statement": "This AWS account is the entire system boundary for this assessment.",
		},
		"profile": map[string]any{
			"id":             "cmmc-l1",
			"content_sha256": strings.Repeat("a", 64),
		},
		"artifact": map[string]any{
			"id":             "cmmc-l1",
			"content_sha256": strings.Repeat("b", 64),
		},
		"objectives": []any{
			map[string]any{
				"id":             "AC.L1-b.1.i",
				"evidence_class": "operator",
				"resolved":       "NOT MET",
			},
		},
		"l1_summary": map[string]any{
			"met_count":            0,
			"not_met_count":        1,
			"total":                15,
			"affirmation_possible": false,
		},
		"policy_caveat": "automat encodes a technical reading of published policy. It is not legal advice and not a compliance determination.",
	}
}

func TestSampleAssessmentResultSatisfiesPublishedSchema(t *testing.T) {
	sch := compileSchema(t, "assessment-result-v1.schema.json")
	doc := asGeneric(t, sampleAssessmentResult())
	if err := sch.Validate(doc); err != nil {
		t.Errorf("a hand-built assessment result this test considers valid violates the published "+
			"schema:\n%v", err)
	}
}

func TestAssessmentResultRequiresEveryTopLevelField(t *testing.T) {
	sch := compileSchema(t, "assessment-result-v1.schema.json")
	for _, field := range []string{
		"schema_version", "rendered_at", "tool_version", "account", "profile",
		"artifact", "objectives", "l1_summary", "policy_caveat",
	} {
		t.Run(field, func(t *testing.T) {
			m := sampleAssessmentResult()
			delete(m, field)
			if err := sch.Validate(asGeneric(t, m)); err == nil {
				t.Errorf("the schema accepted a document missing required field %q", field)
			}
		})
	}
}

func TestAssessmentResultAffirmationPossibleIsBoolean(t *testing.T) {
	sch := compileSchema(t, "assessment-result-v1.schema.json")
	m := sampleAssessmentResult()
	m["l1_summary"].(map[string]any)["affirmation_possible"] = "false"
	if err := sch.Validate(asGeneric(t, m)); err == nil {
		t.Error("the schema accepted affirmation_possible as a string, want boolean-only")
	}
}

func sampleOperatorDeterminations() map[string]any {
	return map[string]any{
		"schema_version": "1.0.0",
		"determinations": []any{
			map[string]any{
				"id":                "media-disposal-2026",
				"objectives":        []any{"MP.L1-b.1.vii"},
				"value":             "NOT MET",
				"statement":         "No media disposal process has been documented for this account.",
				"date":              "2026-08-01",
				"responsible_party": "Jane Researcher, PI",
			},
		},
	}
}

func TestSampleOperatorDeterminationsSatisfiesPublishedSchema(t *testing.T) {
	sch := compileSchema(t, "operator-determinations-v1.schema.json")
	doc := asGeneric(t, sampleOperatorDeterminations())
	if err := sch.Validate(doc); err != nil {
		t.Errorf("a hand-built determinations document this test considers valid violates the "+
			"published schema:\n%v", err)
	}
}

func TestOperatorDeterminationsRequiresEveryDeterminationField(t *testing.T) {
	sch := compileSchema(t, "operator-determinations-v1.schema.json")
	for _, field := range []string{"id", "objectives", "value", "statement", "date", "responsible_party"} {
		t.Run(field, func(t *testing.T) {
			m := sampleOperatorDeterminations()
			det := m["determinations"].([]any)[0].(map[string]any)
			delete(det, field)
			if err := sch.Validate(asGeneric(t, m)); err == nil {
				t.Errorf("the schema accepted a determination missing required field %q", field)
			}
		})
	}
}

func TestOperatorDeterminationsIDRejectsWhitespace(t *testing.T) {
	sch := compileSchema(t, "operator-determinations-v1.schema.json")
	m := sampleOperatorDeterminations()
	m["determinations"].([]any)[0].(map[string]any)["id"] = "media disposal 2026"
	if err := sch.Validate(asGeneric(t, m)); err == nil {
		t.Error("the schema accepted a determination id containing a space; round-trip ids " +
			"(CLAUDE.md rule 8) must not carry whitespace, or an operator cannot double-click " +
			"and retype it correctly")
	}
}

func TestOperatorDeterminationsRevisionDeterminationRequiresEveryField(t *testing.T) {
	sch := compileSchema(t, "operator-determinations-v1.schema.json")
	full := map[string]any{
		"catalog":       "nist-sp-800-171",
		"revision":      "Revision 2",
		"determined_by": "Jane Researcher, PI",
		"determined_at": "2026-08-01",
		"statement":     "Our office has determined Revision 2 applies to this data use agreement.",
	}
	for _, field := range []string{"catalog", "revision", "determined_by", "determined_at", "statement"} {
		t.Run(field, func(t *testing.T) {
			m := sampleOperatorDeterminations()
			rd := map[string]any{}
			for k, v := range full {
				rd[k] = v
			}
			delete(rd, field)
			m["revision_determination"] = rd
			if err := sch.Validate(asGeneric(t, m)); err == nil {
				t.Errorf("the schema accepted a revision_determination missing required field %q", field)
			}
		})
	}
}
