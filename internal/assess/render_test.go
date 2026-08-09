// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"strings"
	"testing"
)

func testResult(t *testing.T) *Result {
	t.Helper()
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	result, err := SummarizeL1(profile, art, nil, testAccount(), "dev", "2026-08-09T00:00:00Z")
	if err != nil {
		t.Fatalf("SummarizeL1: %v", err)
	}
	return result
}

// TestEveryRendererIsReachable guards the renderers table against a
// renderer that exists as a function but is never listed — internal/bundle's
// own pattern (render_test.go's TestEveryRendererIsReachable).
func TestEveryRendererIsReachable(t *testing.T) {
	if len(renderers) != renderersCount {
		t.Errorf("%d renderers, but renderersCount is %d", len(renderers), renderersCount)
	}
	seen := map[string]bool{}
	for _, rd := range renderers {
		if seen[rd.name] {
			t.Errorf("two renderers are named %s", rd.name)
		}
		seen[rd.name] = true
		if rd.render == nil {
			t.Errorf("%s has no renderer", rd.name)
		}
	}
}

// TestEveryRendererCarriesTheDraftMarking is Invariant 1's first half
// (docs/assessment-reporting.md): a renderer added later and omitted from
// this loop is itself a failure, the same discipline
// internal/bundle.TestNoProductOrVendorReference applies to its own five.
func TestEveryRendererCarriesTheDraftMarking(t *testing.T) {
	result := testResult(t)
	for _, rd := range renderers {
		data, err := rd.render(result)
		if err != nil {
			t.Fatalf("%s: %v", rd.name, err)
		}
		if !strings.Contains(string(data), draftMarking) {
			t.Errorf("%s does not carry %q", rd.name, draftMarking)
		}
	}
}

// TestNoRendererHasASignatureAffordance is Invariant 1's second half: no
// signature line, no "signed", no "affirm"/"affirmation"/"I certify", no
// "under penalty", no date-signed field, no submission framing. automat
// generates the packet the affirming official reads, never the thing they
// sign.
func TestNoRendererHasASignatureAffordance(t *testing.T) {
	result := testResult(t)
	forbidden := []string{
		"_________", "signature:", "signed by", "signed:", "i certify",
		"under penalty", "date signed", "submit this", "affirm ", "affirmation",
	}
	for _, rd := range renderers {
		data, err := rd.render(result)
		if err != nil {
			t.Fatalf("%s: %v", rd.name, err)
		}
		lower := strings.ToLower(string(data))
		for _, f := range forbidden {
			if strings.Contains(lower, f) {
				t.Errorf("%s contains %q — no rendered output may resemble a signable affirmation "+
					"(docs/assessment-reporting.md, Invariant 1)", rd.name, f)
			}
		}
	}
}

func TestRenderL1SummaryStatesTheConsequenceWhenNotEveryPracticeIsMet(t *testing.T) {
	result := testResult(t)
	data, err := RenderL1Summary(result)
	if err != nil {
		t.Fatalf("RenderL1Summary: %v", err)
	}
	if !strings.Contains(string(data), "nothing this year's senior-official review can conclude") {
		t.Error("rendered summary with practices NOT MET does not state the consequence " +
			"(docs/assessment-reporting.md, Invariant 3: a count is not a score at L1, it is a " +
			"fail with a work list)")
	}
}

func TestRenderL1SummaryCarriesThePolicyCaveat(t *testing.T) {
	result := testResult(t)
	data, err := RenderL1Summary(result)
	if err != nil {
		t.Fatalf("RenderL1Summary: %v", err)
	}
	if missing := missingCaveatSubstance(string(data)); len(missing) > 0 {
		t.Errorf("rendered summary is missing %v from the policy caveat (docs/policy-caveat.md)", missing)
	}
}

func TestRenderL1SummaryStatesTheNoMachineEvidenceDisclosure(t *testing.T) {
	result := testResult(t)
	data, err := RenderL1Summary(result)
	if err != nil {
		t.Fatalf("RenderL1Summary: %v", err)
	}
	if !strings.Contains(string(data), NoMachineEvidenceYet) {
		t.Error("rendered summary does not state the no-machine-evidence disclosure — this build " +
			"has zero machine evidence for any CMMC L1 practice and must say so, not stay silent")
	}
}
