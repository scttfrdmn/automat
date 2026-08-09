// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// artifactWithConfigRule mirrors artifactWithSCP's fixture shape for the
// detective half: one control, one Config-rule binding, validated so a test
// using it proves something about a real catalog shape.
func artifactWithConfigRule(t *testing.T, id string, rule artifact.ConfigRule) *artifact.Artifact {
	t.Helper()
	if rule.Provenance == "" {
		rule.Provenance = artifact.ProvenanceAWSMapping
	}
	a := &artifact.Artifact{
		SchemaVersion: artifact.SchemaVersion,
		Meta: artifact.Meta{
			ID:         id,
			Title:      "Test control set " + id,
			CompiledAt: "2026-01-01T00:00:00Z",
			Sources: artifact.Sources{{
				Catalog: "test",
				SHA256:  strings.Repeat("0", 64),
			}},
		},
		Controls: artifact.Controls{{
			ID:          "c-1",
			Title:       "Detective control",
			Enforcement: []artifact.EnforcementClass{artifact.EnforcementConfigRule},
			ConfigRules: []artifact.ConfigRule{rule},
		}},
	}
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("fixture %s: %v", id, err)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("fixture %s is not a valid artifact, so a test using it proves nothing: %v", id, err)
	}
	return a
}

func TestConfigRuleDedupedByIdentifierWithinOneArtifact(t *testing.T) {
	// Two controls in one artifact both bind IAM_PASSWORD_POLICY — the same
	// requirement stated twice, the case FromArtifact's own doc names.
	a := &artifact.Artifact{
		SchemaVersion: artifact.SchemaVersion,
		Meta: artifact.Meta{ID: "set", Title: "t", CompiledAt: "2026-01-01T00:00:00Z",
			Sources: artifact.Sources{{Catalog: "test", SHA256: strings.Repeat("0", 64)}}},
		Controls: artifact.Controls{
			{
				ID: "c-1", Title: "one", Enforcement: []artifact.EnforcementClass{artifact.EnforcementConfigRule},
				ConfigRules: []artifact.ConfigRule{{
					Identifier: "IAM_PASSWORD_POLICY", Provenance: artifact.ProvenanceAWSMapping,
					Parameters: map[string]artifact.RuleParameter{
						"MinimumPasswordLength": {Value: "14", Order: artifact.OrderMax},
					},
				}},
			},
			{
				ID: "c-2", Title: "two", Enforcement: []artifact.EnforcementClass{artifact.EnforcementConfigRule},
				ConfigRules: []artifact.ConfigRule{{
					Identifier: "IAM_PASSWORD_POLICY", Provenance: artifact.ProvenanceAWSMapping,
					Parameters: map[string]artifact.RuleParameter{
						"MinimumPasswordLength": {Value: "8", Order: artifact.OrderMax},
					},
				}},
			},
		},
	}
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("fixture is not a valid artifact: %v", err)
	}

	m := mustFromArtifact(t, a)
	if len(m.ConfigRules) != 1 {
		t.Fatalf("got %d rules, want exactly one deduped IAM_PASSWORD_POLICY: %+v", len(m.ConfigRules), m.ConfigRules)
	}
	got := m.ConfigRules["IAM_PASSWORD_POLICY"].Parameters["MinimumPasswordLength"]
	if got.Value != "14" {
		t.Errorf("MinimumPasswordLength = %q, want %q (max order picks the stricter, higher floor)",
			got.Value, "14")
	}
	if len(m.ConfigRules["IAM_PASSWORD_POLICY"].Origins) != 2 {
		t.Errorf("Origins = %v, want both controls named", m.ConfigRules["IAM_PASSWORD_POLICY"].Origins)
	}
}

func TestConfigRuleDedupedAcrossArtifacts(t *testing.T) {
	a := artifactWithConfigRule(t, "set-a", artifact.ConfigRule{
		Identifier: "IAM_PASSWORD_POLICY",
		Parameters: map[string]artifact.RuleParameter{
			"MinimumPasswordLength": {Value: "14", Order: artifact.OrderMax},
		},
	})
	b := artifactWithConfigRule(t, "set-b", artifact.ConfigRule{
		Identifier: "IAM_PASSWORD_POLICY",
		Parameters: map[string]artifact.RuleParameter{
			"MinimumPasswordLength": {Value: "20", Order: artifact.OrderMax},
			"RequireNumbers":        {Value: "true", Order: artifact.OrderExact},
		},
	})

	m := mustMerge(t, a, b)
	if len(m.ConfigRules) != 1 {
		t.Fatalf("got %d rules, want one deduped rule", len(m.ConfigRules))
	}
	rule := m.ConfigRules["IAM_PASSWORD_POLICY"]
	if got := rule.Parameters["MinimumPasswordLength"].Value; got != "20" {
		t.Errorf("MinimumPasswordLength = %q, want %q", got, "20")
	}
	if got := rule.Parameters["RequireNumbers"].Value; got != "true" {
		t.Errorf("RequireNumbers = %q, want %q (present on only one side, kept as-is)", got, "true")
	}
	if len(rule.Origins) != 2 {
		t.Errorf("Origins = %v, want both artifacts named", rule.Origins)
	}
}

func TestConfigRuleConflictIsAConflictReport(t *testing.T) {
	a := artifactWithConfigRule(t, "set-a", artifact.ConfigRule{
		Identifier: "IAM_PASSWORD_POLICY",
		Parameters: map[string]artifact.RuleParameter{
			"RequireSymbols": {Value: "true", Order: artifact.OrderExact},
		},
	})
	b := artifactWithConfigRule(t, "set-b", artifact.ConfigRule{
		Identifier: "IAM_PASSWORD_POLICY",
		Parameters: map[string]artifact.RuleParameter{
			"RequireSymbols": {Value: "false", Order: artifact.OrderExact},
		},
	})

	_, err := Merge(a, b)
	if err == nil {
		t.Fatal("Merge succeeded despite an exact-order conflict, want a *ConflictReport")
	}
	cr, ok := err.(*ConflictReport)
	if !ok {
		t.Fatalf("error is a %T, not *ConflictReport: %v", err, err)
	}
	if cr.Rule != "IAM_PASSWORD_POLICY" || cr.Parameter != "RequireSymbols" {
		t.Errorf("got rule=%q parameter=%q, want IAM_PASSWORD_POLICY/RequireSymbols", cr.Rule, cr.Parameter)
	}
	if len(cr.Origins) != 2 {
		t.Errorf("Origins = %v, want both artifacts named so an operator knows which catalogs to read",
			cr.Origins)
	}
	if !strings.Contains(cr.Error(), "override file") {
		t.Errorf("Error() does not name the remediation (an override file): %s", cr.Error())
	}
}

func TestConfigRuleConflictWithinOneArtifactIsReported(t *testing.T) {
	// Two controls in ONE artifact disagreeing is a catalog authoring bug,
	// and FromArtifact must catch it rather than let Combine paper over it
	// later by treating the artifact's own internal disagreement as if it
	// were agreement with itself.
	a := &artifact.Artifact{
		SchemaVersion: artifact.SchemaVersion,
		Meta: artifact.Meta{ID: "set", Title: "t", CompiledAt: "2026-01-01T00:00:00Z",
			Sources: artifact.Sources{{Catalog: "test", SHA256: strings.Repeat("0", 64)}}},
		Controls: artifact.Controls{
			{
				ID: "c-1", Title: "one", Enforcement: []artifact.EnforcementClass{artifact.EnforcementConfigRule},
				ConfigRules: []artifact.ConfigRule{{
					Identifier: "IAM_PASSWORD_POLICY", Provenance: artifact.ProvenanceAWSMapping,
					Parameters: map[string]artifact.RuleParameter{
						"RequireSymbols": {Value: "true", Order: artifact.OrderExact},
					},
				}},
			},
			{
				ID: "c-2", Title: "two", Enforcement: []artifact.EnforcementClass{artifact.EnforcementConfigRule},
				ConfigRules: []artifact.ConfigRule{{
					Identifier: "IAM_PASSWORD_POLICY", Provenance: artifact.ProvenanceAWSMapping,
					Parameters: map[string]artifact.RuleParameter{
						"RequireSymbols": {Value: "false", Order: artifact.OrderExact},
					},
				}},
			},
		},
	}
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("fixture is not a valid artifact: %v", err)
	}

	_, err := FromArtifact(a)
	if err == nil {
		t.Fatal("FromArtifact succeeded despite two controls in one artifact disagreeing, want a conflict")
	}
	if _, ok := err.(*ConflictReport); !ok {
		t.Fatalf("error is a %T, not *ConflictReport", err)
	}
}

func TestConfigRuleResourceTypesUnion(t *testing.T) {
	a := artifactWithConfigRule(t, "set-a", artifact.ConfigRule{
		Identifier:    "EC2_INSTANCE_NO_PUBLIC_IP",
		ResourceTypes: []string{"AWS::EC2::Instance"},
	})
	b := artifactWithConfigRule(t, "set-b", artifact.ConfigRule{
		Identifier:    "EC2_INSTANCE_NO_PUBLIC_IP",
		ResourceTypes: []string{"AWS::EC2::Instance", "AWS::EC2::NetworkInterface"},
	})

	m := mustMerge(t, a, b)
	rt := m.ConfigRules["EC2_INSTANCE_NO_PUBLIC_IP"].ResourceTypes
	if !sameStrings(rt, []string{"AWS::EC2::Instance", "AWS::EC2::NetworkInterface"}) {
		t.Errorf("ResourceTypes = %v, want the union of both sides", rt)
	}
}

func TestConfigRuleNoRulesIsOrdinary(t *testing.T) {
	// A control set that is entirely preventive (no Config rules at all) must
	// not error or fabricate a ConfigRules map — the same "honest empty" the
	// SCP half already holds for RegionAllowlist.
	a := artifactWithSCP(t, "preventive-only", &artifact.SCP{
		Statements: []artifact.SCPStatement{denyFragment("A", "iam:CreateUser")},
	})
	m := mustMerge(t, a)
	if len(m.ConfigRules) != 0 {
		t.Errorf("ConfigRules = %v, want none", m.ConfigRules)
	}
}

// --- Q1's carried caveat: blockedPort1-5 re-slotting ---

func blockedPortRule(ports ...string) artifact.ConfigRule {
	params := map[string]artifact.RuleParameter{}
	for i, p := range ports {
		params[blockedPortSlots[i]] = artifact.RuleParameter{Value: p, Order: artifact.OrderSetUnion}
	}
	return artifact.ConfigRule{
		Identifier:    "RESTRICTED_INCOMING_TRAFFIC",
		ResourceTypes: []string{"AWS::EC2::SecurityGroup"},
		Parameters:    params,
	}
}

func TestBlockedPortsReSlotAcrossArtifacts(t *testing.T) {
	// cmmc-l1's own shape: five slots, one port each. A second artifact
	// binds a DIFFERENT set of five ports under the same five slots — the
	// case that, without re-slotting, would resolve each slot independently
	// to a set-union VALUE (e.g. "20,99") that RESTRICTED_INCOMING_TRAFFIC
	// rejects, since it reads each parameter as a single integer.
	a := artifactWithConfigRule(t, "set-a", blockedPortRule("20", "21", "3389", "3306", "4333"))
	b := artifactWithConfigRule(t, "set-b", blockedPortRule("22", "23", "3390", "3307", "4334"))

	_, err := Merge(a, b)
	if err == nil {
		t.Fatal("ten distinct ports across five slots should overflow the five slots available, want a conflict")
	}
	cr, ok := err.(*ConflictReport)
	if !ok {
		t.Fatalf("error is a %T, not *ConflictReport: %v", err, err)
	}
	if len(cr.Values) != 10 {
		t.Errorf("conflict names %d ports, want all 10 so an operator can see the whole overflow: %v",
			len(cr.Values), cr.Values)
	}
}

func TestBlockedPortsReSlotWithinFiveTotal(t *testing.T) {
	// Two artifacts binding OVERLAPPING port sets that together still fit in
	// five slots must re-slot cleanly rather than conflict — the ordinary
	// case Q1 exists to make work, not just the overflow case.
	a := artifactWithConfigRule(t, "set-a", blockedPortRule("20", "21", "3389"))
	b := artifactWithConfigRule(t, "set-b", blockedPortRule("21", "3306", "4333"))

	m := mustMerge(t, a, b)
	rule := m.ConfigRules["RESTRICTED_INCOMING_TRAFFIC"]
	var got []string
	for _, slot := range blockedPortSlots {
		p, ok := rule.Parameters[slot]
		if !ok {
			continue
		}
		got = append(got, p.Value)
	}
	want := []string{"20", "21", "3306", "3389", "4333"}
	if len(got) != len(want) {
		t.Fatalf("got %d slotted ports, want %d: %v", len(got), len(want), got)
	}
	seen := map[string]bool{}
	for _, p := range got {
		seen[p] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("port %s missing from the re-slotted result: %v", w, got)
		}
	}
	// Every re-slotted parameter must still be set-union, or a later Combine
	// re-running this same rule through addOneConfigRule would refuse it as
	// declaring the wrong order.
	for _, slot := range blockedPortSlots {
		if p, ok := rule.Parameters[slot]; ok && p.Order != artifact.OrderSetUnion {
			t.Errorf("slot %s has order %q after re-slotting, want set-union", slot, p.Order)
		}
	}
}

func TestBlockedPortsSingleArtifactKeepsTheSameFiveValues(t *testing.T) {
	// The ordinary vend case: one artifact (cmmc-l1) binds all five slots and
	// nothing else is merged in. Re-slotting always re-sorts into canonical
	// (lexical) order — the same "canonical order, not input order"
	// discipline mergeStatements applies to SCPs — so this asserts the SET
	// of ports survives, not that each value stays in its original slot.
	a := artifactWithConfigRule(t, "set-a", blockedPortRule("20", "21", "3389", "3306", "4333"))
	m := mustMerge(t, a)
	rule := m.ConfigRules["RESTRICTED_INCOMING_TRAFFIC"]
	seen := map[string]bool{}
	for _, slot := range blockedPortSlots {
		seen[rule.Parameters[slot].Value] = true
	}
	for _, want := range []string{"20", "21", "3389", "3306", "4333"} {
		if !seen[want] {
			t.Errorf("port %s missing after re-slotting a single artifact's own five values: %v", want, seen)
		}
	}
}
