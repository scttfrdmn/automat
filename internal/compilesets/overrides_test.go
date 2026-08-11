// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/artifact"
)

func writeOverrides(t *testing.T, entries ...Override) string {
	t.Helper()
	o := Overrides{Entries: entries}
	data, err := json.Marshal(o)
	if err != nil {
		t.Fatalf("marshal overrides: %v", err)
	}
	path := filepath.Join(t.TempDir(), "overrides.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write overrides: %v", err)
	}
	return path
}

func TestLoadOverridesRoundTrip(t *testing.T) {
	path := writeOverrides(t, Override{Rule: "IAM_PASSWORD_POLICY", Parameter: "RequireSymbols", Value: "true"})
	o, err := LoadOverrides(path)
	if err != nil {
		t.Fatalf("LoadOverrides: %v", err)
	}
	if len(o.Entries) != 1 || o.Entries[0].Value != "true" {
		t.Fatalf("got %+v, want one entry with value true", o.Entries)
	}
}

func TestLoadOverridesRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overrides.json")
	if err := os.WriteFile(path, []byte(`{"overrides":[{"rule":"X","parameter":"Y","value":"Z","typo":"oops"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverrides(path); err == nil {
		t.Fatal("LoadOverrides accepted an unknown field, want a refusal")
	}
}

func TestLoadOverridesRejectsMissingFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
	}{
		{"no rule", `{"overrides":[{"parameter":"Y","value":"Z"}]}`},
		{"no parameter", `{"overrides":[{"rule":"X","value":"Z"}]}`},
		{"no value", `{"overrides":[{"rule":"X","parameter":"Y"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "overrides.json")
			if err := os.WriteFile(path, []byte(tc.json), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOverrides(path); err == nil {
				t.Fatalf("LoadOverrides accepted %s, want a refusal", tc.json)
			}
		})
	}
}

func TestLoadOverridesRejectsADuplicateEntry(t *testing.T) {
	path := writeOverrides(t,
		Override{Rule: "X", Parameter: "Y", Value: "1"},
		Override{Rule: "X", Parameter: "Y", Value: "2"},
	)
	if _, err := LoadOverrides(path); err == nil {
		t.Fatal("LoadOverrides accepted two entries for the same rule+parameter, want a refusal")
	}
}

// TestLoadOverridesRejectsADuplicateKey is AUDIT-4 H1, and it is a different
// failure from TestLoadOverridesRejectsADuplicateEntry above: that one is two
// entries in the list, which validate() catches. This one is one entry whose
// "value" key appears twice, which DisallowUnknownFields cannot catch — the key
// is known, twice — so encoding/json takes the LAST occurrence silently. The
// operator reviewing the file reads the first.
//
// AUDIT-2 H8 established this refusal on every document automat reads. An
// override file is the document whose entire content is one value a human
// decided on, so a read that quietly prefers the value they did not write is
// the worst place for the gap.
func TestLoadOverridesRejectsADuplicateKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
	}{
		{"value twice", `{"overrides":[{"rule":"X","parameter":"Y","value":"14","value":"6"}]}`},
		{"rule twice", `{"overrides":[{"rule":"X","rule":"Z","parameter":"Y","value":"1"}]}`},
		{"overrides twice", `{"overrides":[{"rule":"X","parameter":"Y","value":"1"}],` +
			`"overrides":[{"rule":"X","parameter":"Y","value":"2"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "overrides.json")
			if err := os.WriteFile(path, []byte(tc.json), 0o600); err != nil {
				t.Fatal(err)
			}
			o, err := LoadOverrides(path)
			if err == nil {
				t.Fatalf("LoadOverrides accepted a document naming a key twice and resolved it to "+
					"%+v; the operator reading the file sees the other value", o.Entries)
			}
			if !strings.Contains(err.Error(), "twice") {
				t.Errorf("the refusal does not say a key appeared twice: %v", err)
			}
		})
	}
}

func TestOverrideResolvesAMergeConflict(t *testing.T) {
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

	// Without an override, this is TestConfigRuleConflictIsAConflictReport's
	// case: a hard error.
	if _, err := Merge(a, b); err == nil {
		t.Fatal("Merge succeeded despite a real conflict with no override; the fixture is wrong")
	}

	overrides := &Overrides{Entries: []Override{
		{Rule: "IAM_PASSWORD_POLICY", Parameter: "RequireSymbols", Value: "true"},
	}}
	m, err := MergeWithOverrides(overrides, a, b)
	if err != nil {
		t.Fatalf("MergeWithOverrides: %v", err)
	}
	got := m.ConfigRules["IAM_PASSWORD_POLICY"].Parameters["RequireSymbols"].Value
	if got != "true" {
		t.Errorf("RequireSymbols = %q, want %q (the override's value)", got, "true")
	}
}

func TestOverrideDoesNotSuppressAnUnrelatedConflict(t *testing.T) {
	// An override naming a DIFFERENT parameter must not accidentally paper
	// over a real conflict on the one it does not name — apply() matches on
	// (rule, parameter) exactly, and this pins that it does not fall back to
	// "any override, any conflict."
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
	overrides := &Overrides{Entries: []Override{
		{Rule: "IAM_PASSWORD_POLICY", Parameter: "RequireNumbers", Value: "true"},
	}}
	_, err := MergeWithOverrides(overrides, a, b)
	if err == nil {
		t.Fatal("MergeWithOverrides succeeded despite an override that names a different parameter")
	}
	if _, ok := err.(*ConflictReport); !ok {
		t.Fatalf("error is a %T, not *ConflictReport", err)
	}
}

func TestOverrideResolvesAWithinArtifactConflict(t *testing.T) {
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

	overrides := &Overrides{Entries: []Override{
		{Rule: "IAM_PASSWORD_POLICY", Parameter: "RequireSymbols", Value: "false"},
	}}
	m, err := FromArtifactWithOverrides(a, overrides)
	if err != nil {
		t.Fatalf("FromArtifactWithOverrides: %v", err)
	}
	if got := m.ConfigRules["IAM_PASSWORD_POLICY"].Parameters["RequireSymbols"].Value; got != "false" {
		t.Errorf("RequireSymbols = %q, want %q", got, "false")
	}
}

// TestOverrideWideningIsAcceptedAndWarned is Q22's own worked example
// (docs/open-questions.md): a set-intersect conflict between "ami-1,ami-2"
// and "ami-3,ami-4" — disjoint, so their meet is provably empty and no
// clamp could resolve it — settled by an override naming
// "ami-1,ami-2,ami-3,ami-4,ami-EVERYTHING", a value that includes a member,
// ami-EVERYTHING, that neither conflicting side permitted.
//
// Two things must both be true, per Q22's decision: the override is still
// accepted verbatim (unchanged behavior — DO NOT clamp), and a warning now
// names ami-EVERYTHING specifically, not the whole override value
// undifferentiated.
func TestOverrideWideningIsAcceptedAndWarned(t *testing.T) {
	a := artifactWithConfigRule(t, "set-a", artifact.ConfigRule{
		Identifier: "EC2_MANAGEDINSTANCE_APPLICATIONS_BLACKLISTED",
		Parameters: map[string]artifact.RuleParameter{
			"allowedAmis": {Value: "ami-1,ami-2", Order: artifact.OrderSetIntersect},
		},
	})
	b := artifactWithConfigRule(t, "set-b", artifact.ConfigRule{
		Identifier: "EC2_MANAGEDINSTANCE_APPLICATIONS_BLACKLISTED",
		Parameters: map[string]artifact.RuleParameter{
			"allowedAmis": {Value: "ami-3,ami-4", Order: artifact.OrderSetIntersect},
		},
	})

	// Without an override this is a disjoint set-intersect: a hard error,
	// per artifact.RuleParameter.Resolve's own OrderSetIntersect case.
	if _, err := Merge(a, b); err == nil {
		t.Fatal("Merge succeeded despite a disjoint set-intersect with no override; the fixture is wrong")
	}

	overrides := &Overrides{Entries: []Override{
		{Rule: "EC2_MANAGEDINSTANCE_APPLICATIONS_BLACKLISTED", Parameter: "allowedAmis",
			Value: "ami-1,ami-2,ami-3,ami-4,ami-EVERYTHING"},
	}}
	m, err := MergeWithOverrides(overrides, a, b)
	if err != nil {
		t.Fatalf("MergeWithOverrides: %v (the override must still be accepted verbatim per Q22)", err)
	}
	got := m.ConfigRules["EC2_MANAGEDINSTANCE_APPLICATIONS_BLACKLISTED"].Parameters["allowedAmis"].Value
	want := "ami-1,ami-2,ami-3,ami-4,ami-EVERYTHING"
	if got != want {
		t.Errorf("allowedAmis = %q, want %q (the override's value, untouched)", got, want)
	}

	if len(m.Warnings) == 0 {
		t.Fatal("expected a warning naming the member neither side permitted, got none")
	}
	all := strings.Join(m.Warnings, "\n")
	if !strings.Contains(all, "ami-EVERYTHING") {
		t.Errorf("warning does not name ami-EVERYTHING specifically: %v", m.Warnings)
	}
	for _, member := range []string{"ami-1", "ami-2", "ami-3", "ami-4"} {
		if strings.Contains(all, `"`+member+`"`) {
			t.Errorf("warning names %s, a member at least one side already permitted — "+
				"only ami-EVERYTHING should be named: %v", member, m.Warnings)
		}
	}
}

// TestOverrideNamingNoConflictWarns is Q22's second gap: an override entry
// that names a (rule, parameter) with no actual conflict at that spot is
// silently a no-op today, and the compile plan says nothing about it.
func TestOverrideNamingNoConflictWarns(t *testing.T) {
	a := artifactWithConfigRule(t, "set-a", artifact.ConfigRule{
		Identifier: "IAM_PASSWORD_POLICY",
		Parameters: map[string]artifact.RuleParameter{
			"RequireSymbols": {Value: "true", Order: artifact.OrderExact},
		},
	})
	overrides := &Overrides{Entries: []Override{
		// No conflict exists at RequireSymbols (only one artifact binds it)
		// or at RequireNumbers (nobody binds it at all).
		{Rule: "IAM_PASSWORD_POLICY", Parameter: "RequireNumbers", Value: "true"},
	}}
	m, err := MergeWithOverrides(overrides, a)
	if err != nil {
		t.Fatalf("MergeWithOverrides: %v", err)
	}
	if len(m.Warnings) == 0 {
		t.Fatal("expected a warning that the override was never applied, got none")
	}
	all := strings.Join(m.Warnings, "\n")
	if !strings.Contains(all, "RequireNumbers") || !strings.Contains(all, "never applied") {
		t.Errorf("warning does not name the unapplied override: %v", m.Warnings)
	}
}
