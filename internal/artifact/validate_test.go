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
			name: "separator on a scalar parameter",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "AA.L1-b.1.a")
				mustRule(t, c, "IAM_PASSWORD_POLICY").Parameters["MaxPasswordAge"] = RuleParameter{
					Value: "90", Order: OrderMin, SetSeparator: ";",
				}
			},
			wantPath: "set_separator",
			wantFix:  "drop set_separator",
		},
		{
			name: "binding without provenance",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "AA.L1-b.1.a")
				mustRule(t, c, "IAM_PASSWORD_POLICY").Provenance = ""
			},
			wantPath: "provenance",
			wantFix:  "which claims are AWS's",
		},
		{
			name: "binding with invalid provenance",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "AA.L1-b.1.a")
				mustRule(t, c, "IAM_PASSWORD_POLICY").Provenance = "vibes"
			},
			wantPath: "provenance",
			wantFix:  "aws-mapping, curated",
		},
		{
			name: "curated binding without a rationale",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "AA.L1-b.1.a")
				mustRule(t, c, "RESTRICTED_INCOMING_TRAFFIC").Rationale = ""
			},
			wantPath: "rationale",
			wantFix:  "state in one line why",
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
			wantFix:  "use \"Deny\"",
		},
		{
			// An Allow is rejected outright, not warned about: it widens what a
			// parent SCP permits and does not compose under union. AUDIT-0 H4.
			name: "allow effect",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].Effect = "Allow"
			},
			wantPath: "effect",
			wantFix:  "does not compose under union",
		},
		{
			// An empty set is not a stricter set. AUDIT-0 H5.
			name: "set parameter with no members",
			mutate: func(a *Artifact) {
				r := mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "RESTRICTED_INCOMING_TRAFFIC")
				r.Parameters["authorizedTcpPorts"] = RuleParameter{Value: " , ", Order: OrderSetIntersect}
			},
			wantPath: "authorizedTcpPorts",
			wantFix:  "at least one member",
		},
		{
			name: "statement with no actions",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].Action = nil
			},
			wantPath: "action",
			wantFix:  "list the actions",
		},
		{
			// AUDIT-2 H5's second half. The published schema has always said
			// minLength:1 on these items; the Go validator did not, and the packer's
			// guard key could not tell resource [""] from an absent resource — so the
			// two merged, and the merged statement came out scoped to [""], which
			// matches nothing.
			name: "empty resource member",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].Resource = []string{""}
			},
			wantPath: "resource[0]",
			wantFix:  "matches nothing",
		},
		{
			name: "empty action member",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].Action = []string{"config:StopConfigurationRecorder", ""}
			},
			wantPath: "action[1]",
			wantFix:  "matches nothing",
		},
		{
			name: "duplicate action member",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].Action = []string{"config:StopConfigurationRecorder", "config:StopConfigurationRecorder"}
			},
			wantPath: "action[1]",
			wantFix:  "disagree with itself",
		},
		{
			name: "duplicate resource member",
			mutate: func(a *Artifact) {
				c := mustControl(t, a, "BB.L1-b.1.b")
				c.SCP.Statements[0].Resource = []string{"*", "*"}
			},
			wantPath: "resource[1]",
			wantFix:  "disagree with itself",
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
		{
			// A misspelled namespace exempts nothing, and the failure is silent:
			// the operator reads the catalog, sees the service listed, and the
			// rendered region Deny covers it anyway.
			name: "misspelled region-deny exempt service",
			mutate: func(a *Artifact) {
				a.RegionDenyExemptServices = []string{"iam", "STS"}
			},
			wantPath: "region_deny_exempt_services[1]",
			wantFix:  "silently exempts nothing",
		},
		{
			// Present-but-empty is not the same claim as absent, and it is a false
			// one: some services really are globally addressed.
			name: "present but empty region-deny exempt list",
			mutate: func(a *Artifact) {
				a.RegionDenyExemptServices = []string{}
			},
			wantPath: "region_deny_exempt_services",
			wantFix:  "omit the field entirely",
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

// TestReportsCannotBeForgedByCatalogInput proves AUDIT-0 finding M1 is fixed.
//
// A validation report is a multi-line bulleted list and a catalog file is
// attacker-controlled input. Before the fix, a control id containing a newline
// forged extra report lines, and an ANSI escape could recolor or erase real ones
// — a reviewer reads a clean report while the artifact is anything but. Every
// catalog-supplied value must therefore be quoted before it reaches output.
func TestReportsCannotBeForgedByCatalogInput(t *testing.T) {
	const forged = "AC.1\n  - controls[FORGED].scp: \x1b[32mno problems here\x1b[0m"

	t.Run("validation report", func(t *testing.T) {
		a := sampleArtifact()
		c := mustControl(t, a, "AA.L1-b.1.a")
		c.ID = forged
		c.Title = "" // force a problem that prints the path
		a.Meta.ID = "evil\nartifact"
		err := a.Validate()
		if err == nil {
			t.Fatal("expected a validation error")
		}
		assertNoForgedStructure(t, err.Error())
	})

	t.Run("parameter conflict report", func(t *testing.T) {
		p := RuleParameter{Value: "1", Order: OrderExact}
		q := RuleParameter{Value: "2\x1b[2K\rall clear", Order: OrderExact}
		_, err := p.Resolve(q, "rule\nname", "param\nname")
		if err == nil {
			t.Fatal("expected a conflict")
		}
		assertNoForgedStructure(t, err.Error())
	})
}

// assertNoForgedStructure checks that no untrusted value contributed a line
// break or an escape byte to a report.
func assertNoForgedStructure(t *testing.T, report string) {
	t.Helper()
	if strings.Contains(report, "\x1b") {
		t.Errorf("report contains a raw escape byte, so catalog input can recolor or erase it:\n%q", report)
	}
	for i, line := range strings.Split(report, "\n") {
		// Every legitimate line is either the subject line or a "  - " bullet the
		// validator itself emitted. A line from catalog input would be neither.
		if i == 0 || strings.HasPrefix(line, "  - ") {
			continue
		}
		t.Errorf("report line %d was not emitted by the validator, so catalog input forged it: %q", i, line)
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
