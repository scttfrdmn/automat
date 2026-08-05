// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"strings"
	"testing"
)

func TestValidateAcceptsSample(t *testing.T) {
	if err := sampleArtifact().Validate(); err != nil {
		t.Fatalf("sample artifact should validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name string
		// mutate breaks the sample artifact in one specific way.
		mutate func(*Artifact)
		// wantPath is the problem path the report must name.
		wantPath string
		// wantFix is a substring the remediation text must contain, so that
		// every failure tells the operator what to change (CLAUDE.md rule 7).
		wantFix string
	}{
		{
			name:     "missing schema version",
			mutate:   func(a *Artifact) { a.SchemaVersion = "" },
			wantPath: "schema_version",
			wantFix:  SchemaVersion,
		},
		{
			name:     "unsupported major schema version",
			mutate:   func(a *Artifact) { a.SchemaVersion = "2.0.0" },
			wantPath: "schema_version",
			wantFix:  "upgrade automat",
		},
		{
			name:     "non-semver schema version",
			mutate:   func(a *Artifact) { a.SchemaVersion = "1.0" },
			wantPath: "schema_version",
			wantFix:  "MAJOR.MINOR.PATCH",
		},
		{
			name:     "missing artifact id",
			mutate:   func(a *Artifact) { a.Meta.ID = "" },
			wantPath: "artifact.id",
			wantFix:  "cmmc-l1",
		},
		{
			name:     "uppercase artifact id",
			mutate:   func(a *Artifact) { a.Meta.ID = "CMMC-L1" },
			wantPath: "artifact.id",
			wantFix:  "lowercase",
		},
		{
			name:     "bad compiled_at precision",
			mutate:   func(a *Artifact) { a.Meta.CompiledAt = "2026-08-04T00:00:00.123Z" },
			wantPath: "artifact.compiled_at",
			wantFix:  "deterministic hashing",
		},
		{
			name:     "compiled_at with offset",
			mutate:   func(a *Artifact) { a.Meta.CompiledAt = "2026-08-04T00:00:00-04:00" },
			wantPath: "artifact.compiled_at",
			wantFix:  "2026-08-04T00:00:00Z",
		},
		{
			name:     "no sources",
			mutate:   func(a *Artifact) { a.Meta.Sources = nil },
			wantPath: "artifact.sources",
			wantFix:  "provenance",
		},
		{
			name:     "source with no kind",
			mutate:   func(a *Artifact) { a.Meta.Sources[0] = Source{SHA256: strings.Repeat("a", 64)} },
			wantPath: "artifact.sources[0]",
			wantFix:  "exactly one of catalog",
		},
		{
			name: "source with two kinds",
			mutate: func(a *Artifact) {
				a.Meta.Sources[0] = Source{Catalog: "x", Mapping: "y", SHA256: strings.Repeat("a", 64)}
			},
			wantPath: "artifact.sources[0]",
			wantFix:  "exactly one of catalog",
		},
		{
			name:     "source missing hash",
			mutate:   func(a *Artifact) { a.Meta.Sources[0].SHA256 = "" },
			wantPath: "artifact.sources[0].sha256",
			wantFix:  "unprovenanced",
		},
		{
			name:     "source with uppercase hash",
			mutate:   func(a *Artifact) { a.Meta.Sources[0].SHA256 = strings.Repeat("A", 64) },
			wantPath: "artifact.sources[0].sha256",
			wantFix:  "64 lowercase hex",
		},
		{
			name:     "no controls",
			mutate:   func(a *Artifact) { a.Controls = nil },
			wantPath: "controls",
			wantFix:  "at least one control",
		},
		{
			name:     "duplicate control ids",
			mutate:   func(a *Artifact) { a.Controls[0].ID = a.Controls[1].ID },
			wantPath: "duplicate control id",
			wantFix:  "unique within an artifact",
		},
		{
			name:     "no enforcement class",
			mutate:   func(a *Artifact) { a.Controls[0].Enforcement = nil },
			wantPath: "enforcement",
			wantFix:  "silently dropped",
		},
		{
			name:     "unknown enforcement class",
			mutate:   func(a *Artifact) { a.Controls[0].Enforcement = []EnforcementClass{"magic"} },
			wantPath: "enforcement",
			wantFix:  "baseline-protection",
		},
		{
			name: "scp declared but absent",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP = nil
			},
			wantPath: "scp",
			wantFix:  "drop the class from enforcement",
		},
		{
			name: "scp present but not declared",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "ZZ.L1-b.1.z")
				c.SCP = &SCP{Statements: []SCPStatement{{Sid: "S", Effect: "Deny", Action: []string{"s3:*"}}}}
			},
			wantPath: "scp",
			wantFix:  "would never be attached",
		},
		{
			name: "config rules declared but absent",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "AA.L1-b.1.a")
				c.ConfigRules = nil
			},
			wantPath: "config_rules",
			wantFix:  "drop \"config-rule\"",
		},
		{
			name: "config rules present but not declared",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "ZZ.L1-b.1.z")
				c.ConfigRules = []ConfigRule{{Identifier: "SOME_RULE"}}
			},
			wantPath: "config_rules",
			wantFix:  "would never be deployed",
		},
		{
			name: "procedural without attestation",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "ZZ.L1-b.1.z")
				c.Attestation = nil
			},
			wantPath: "attestation",
			wantFix:  "produces no evidence",
		},
		{
			name: "attestation without procedural",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.Attestation = &Attestation{Template: "x.md", Frequency: "annual"}
			},
			wantPath: "attestation",
			wantFix:  "add \"procedural\"",
		},
		{
			name: "parameter without order",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "AA.L1-b.1.a")
				mustRule(t, c, "IAM_PASSWORD_POLICY").Parameters["MinimumPasswordLength"] = RuleParameter{Value: "14"}
			},
			wantPath: "order",
			wantFix:  "guessing is not allowed",
		},
		{
			name: "parameter with invalid order",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "AA.L1-b.1.a")
				mustRule(t, c, "IAM_PASSWORD_POLICY").Parameters["MinimumPasswordLength"] = RuleParameter{Value: "14", Order: "average"}
			},
			wantPath: "order",
			wantFix:  "hard error",
		},
		{
			name: "lowercase config rule identifier",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "AA.L1-b.1.a")
				mustRule(t, c, "IAM_PASSWORD_POLICY").Identifier = "iam-password-policy"
			},
			wantPath: "identifier",
			wantFix:  "uppercase with underscores",
		},
		{
			name: "allow effect is flagged",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].Effect = "Allow"
			},
			wantPath: "effect",
			wantFix:  "intersection of permitted behavior",
		},
		{
			name: "invalid effect",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].Effect = "Maybe"
			},
			wantPath: "effect",
			wantFix:  "use \"Deny\" or \"Allow\"",
		},
		{
			name: "statement with no actions",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].Action = nil
			},
			wantPath: "statements",
			wantFix:  "list the actions",
		},
		{
			name: "statement with both action and not_action",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].NotAction = []string{"s3:GetObject"}
			},
			wantPath: "statements",
			wantFix:  "pick one",
		},
		{
			name: "non-alphanumeric sid",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].Sid = "Protect-Recorder"
			},
			wantPath: "sid",
			wantFix:  "letters and digits",
		},
		{
			name: "bad region code",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "AA.L1-b.1.a")
				c.SCP.RegionAllowlist = []string{"US-East-1"}
			},
			wantPath: "region_allowlist",
			wantFix:  "us-east-1",
		},
		{
			name: "bad attestation frequency",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "ZZ.L1-b.1.z")
				c.Attestation.Frequency = "whenever"
			},
			wantPath: "frequency",
			wantFix:  "annual",
		},
		{
			name: "bad attestation template name",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "ZZ.L1-b.1.z")
				c.Attestation.Template = "Procedural.txt"
			},
			wantPath: "template",
			wantFix:  ".md",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := sampleArtifact()
			tc.mutate(a)
			err := a.Validate()
			if err == nil {
				t.Fatalf("expected a validation error for %q, got nil", tc.name)
			}
			ve, ok := AsValidationError(err)
			if !ok {
				t.Fatalf("expected *ValidationError, got %T: %v", err, err)
			}
			msg := ve.Error()
			if !strings.Contains(msg, tc.wantPath) {
				t.Errorf("report should name %q; got:\n%s", tc.wantPath, msg)
			}
			if !strings.Contains(msg, tc.wantFix) {
				t.Errorf("report should include remediation text containing %q; got:\n%s", tc.wantFix, msg)
			}
		})
	}
}

func TestEveryProblemCarriesRemediation(t *testing.T) {
	// A validation problem an operator cannot act on is a bug in the validator,
	// not a message to be improved later.
	a := &Artifact{}
	err := a.Validate()
	if err == nil {
		t.Fatal("an empty artifact must not validate")
	}
	ve, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Problems) == 0 {
		t.Fatal("expected problems")
	}
	for _, p := range ve.Problems {
		if p.Path == "" {
			t.Errorf("problem %+v has no path", p)
		}
		if p.Message == "" {
			t.Errorf("problem at %s has no message", p.Path)
		}
		if p.Fix == "" {
			t.Errorf("problem at %s has no remediation text: %q", p.Path, p.Message)
		}
	}
}

func TestValidateReportsAllProblemsAtOnce(t *testing.T) {
	a := sampleArtifact()
	a.SchemaVersion = ""
	a.Meta.ID = ""
	a.Meta.Title = ""
	err := a.Validate()
	ve, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	if len(ve.Problems) < 3 {
		t.Errorf("expected at least 3 problems reported together, got %d:\n%s", len(ve.Problems), ve.Error())
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	a := sampleArtifact()
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := a.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// A field name that is plausible but wrong: silently ignoring it would mean
	// a control quietly stops being enforced.
	withTypo := strings.Replace(string(data), `"enforcement"`, `"enforcment"`, 1)
	if withTypo == string(data) {
		t.Fatal("test setup: expected to introduce a typo")
	}
	_, err = Decode([]byte(withTypo), LoadOptions{})
	if err == nil {
		t.Fatal("expected an error for an unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error should name the unknown field, got: %v", err)
	}
}

func TestDecodeRejectsTrailingContent(t *testing.T) {
	a := sampleArtifact()
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := a.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	doubled := append(append([]byte{}, data...), data...)
	if _, err := Decode(doubled, LoadOptions{}); err == nil {
		t.Fatal("expected an error for two documents in one file, got nil")
	}
}

func TestBreakdownCountsEachClass(t *testing.T) {
	a := sampleArtifact()
	b := a.Breakdown()
	if b.Total != 3 {
		t.Errorf("Total = %d, want 3", b.Total)
	}
	want := map[EnforcementClass]int{
		EnforcementSCP:                1,
		EnforcementConfigRule:         1,
		EnforcementProcedural:         1,
		EnforcementBaselineProtection: 1,
	}
	for class, n := range want {
		if got := b.ByClass[class]; got != n {
			t.Errorf("ByClass[%s] = %d, want %d", class, got, n)
		}
	}
	// Every class must appear even at zero: `verify` prints the breakdown to
	// state the tool's limits, and an omitted class reads as "not applicable"
	// rather than "none".
	empty := (&Artifact{Controls: Controls{{Enforcement: []EnforcementClass{EnforcementProcedural}}}}).Breakdown()
	for _, class := range AllEnforcementClasses {
		if _, ok := empty.ByClass[class]; !ok {
			t.Errorf("breakdown omits class %s", class)
		}
	}
}
