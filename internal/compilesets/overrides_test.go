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
