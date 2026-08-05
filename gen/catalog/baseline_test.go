// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/compilesets"
)

// Tests for the baseline-protection compiler.
//
// The subject is different from cmmc-l1's in one way that shapes every test here:
// this catalog's authority is a section of automat's own design document rather than
// a third-party publication, so there is no upstream hash to check it against. What
// replaces provenance-by-hash is the checklist in baseline.go — DESIGN §10's deny
// list, transcribed — plus the requirement that any departure from it says why, in
// the compiled artifact where a reviewer will read it. So most of what follows tests
// the checker rather than the output: a checklist that accepts everything is the
// failure mode a self-authored catalog has and a vendored one does not.

const baselineGoldenFile = "baseline-protection.json"

func compileBaselineForTest(t *testing.T) *artifact.Artifact {
	t.Helper()
	a, err := compileBaseline(sourcesDir)
	if err != nil {
		t.Fatalf("compile baseline from %s: %v", sourcesDir, err)
	}
	return a
}

// loadBaselineSource reads the curated source into a doc a test can mutate.
//
// Read fresh per case rather than shared: check() takes the doc by pointer and the
// mutations below are destructive, so a shared fixture would make the cases
// order-dependent.
func loadBaselineSource(t *testing.T) *baselineDoc {
	t.Helper()
	var doc baselineDoc
	if _, err := readJSONAndHash(filepath.Join(sourcesDir, baselineSourceFile), &doc); err != nil {
		t.Fatalf("read %s: %v", baselineSourceFile, err)
	}
	return &doc
}

func TestBaselineCatalogMatchesGolden(t *testing.T) {
	a := compileBaselineForTest(t)
	got, err := a.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(catalogsDir, baselineGoldenFile)

	if updateGolden() {
		if werr := os.WriteFile(path, got, 0o644); werr != nil { //nolint:gosec // reviewed, committed artifact
			t.Fatalf("write %s: %v", path, werr)
		}
		t.Logf("updated %s (content_sha256 %s)", path, a.Meta.ContentHash)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — run `make catalogs`", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s does not match a fresh compile of %s.\n"+
			"A change here changes the preventive posture of every account automat vends, so review the "+
			"diff rather than regenerating past it.\nvendored content_sha256: %s\nfresh content_sha256:    %s",
			path, sourcesDir, vendoredHash(t, want), a.Meta.ContentHash)
	}
}

func TestBaselineCompileIsDeterministic(t *testing.T) {
	first := compileBaselineForTest(t)
	firstBytes, err := first.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := range 3 {
		next := compileBaselineForTest(t)
		nextBytes, err := next.MarshalIndented()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(nextBytes) != string(firstBytes) {
			t.Fatalf("compile %d differs from compile 1; the compiler is not deterministic", i+2)
		}
		if next.Meta.ContentHash != first.Meta.ContentHash {
			t.Fatalf("compile %d hashed to %s, want %s", i+2, next.Meta.ContentHash, first.Meta.ContentHash)
		}
	}
}

func TestVendoredBaselineLoadsAndVerifies(t *testing.T) {
	path := filepath.Join(catalogsDir, baselineGoldenFile)
	a, err := artifact.Load(path, artifact.LoadOptions{})
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if a.Meta.ID != baselineID {
		t.Errorf("artifact id = %q, want %q", a.Meta.ID, baselineID)
	}
	if err := a.VerifyContentHash(); err != nil {
		t.Errorf("vendored baseline fails its own hash: %v", err)
	}
}

// TestEveryBaselineControlIsBaselineProtectionClass.
//
// The class is what the vend step selects on: DESIGN §10's set is attached at the OU
// on every vend, and it is found by enforcement class rather than by artifact id, so
// a control here carrying a different class would compile, validate, ship, and never
// be attached to anything.
func TestEveryBaselineControlIsBaselineProtectionClass(t *testing.T) {
	a := compileBaselineForTest(t)
	if len(a.Controls) == 0 {
		t.Fatal("the baseline catalog compiled with no controls")
	}
	for _, c := range a.Controls {
		if len(c.Enforcement) != 1 || c.Enforcement[0] != artifact.EnforcementBaselineProtection {
			t.Errorf("control %s has enforcement %v, want exactly [%s]: the vend step selects the "+
				"protection set by class, so any other class here is a control that ships and is never "+
				"attached", c.ID, c.Enforcement, artifact.EnforcementBaselineProtection)
		}
		if c.SCP == nil || len(c.SCP.Statements) == 0 {
			t.Errorf("control %s carries no SCP statement, so it prevents nothing", c.ID)
		}
	}
}

// TestTheBaselineCoversEveryDesignSection10Bullet.
//
// The catalog is allowed to grow — that is the point of it being data — but it must
// not quietly shrink. Each of §10's five bullets is checked by the behavior the
// compiled statements have, not by the presence of a control id, because a control
// can be renamed, merged, or split without changing what the account may do.
func TestTheBaselineCoversEveryDesignSection10Bullet(t *testing.T) {
	statements := compilesets.FromArtifact(compileBaselineForTest(t)).Statements
	const researcher = "arn:aws:iam::333333333333:role/researcher"

	cases := []struct {
		bullet string
		req    compilesets.Request
	}{
		{"1: the config recorder", compilesets.Request{
			Principal: researcher, Action: "config:DeleteConfigurationRecorder", Resource: "*"}},
		{"1: the config recorder (stop)", compilesets.Request{
			Principal: researcher, Action: "config:StopConfigurationRecorder", Resource: "*"}},
		{"1: the delivery channel", compilesets.Request{
			Principal: researcher, Action: "config:DeleteDeliveryChannel", Resource: "*"}},
		{"1: the conformance pack", compilesets.Request{
			Principal: researcher, Action: "config:DeleteConformancePack", Resource: "*"}},
		{"2: the trail (stop)", compilesets.Request{
			Principal: researcher, Action: "cloudtrail:StopLogging", Resource: "*"}},
		{"2: the trail (delete)", compilesets.Request{
			Principal: researcher, Action: "cloudtrail:DeleteTrail", Resource: "*"}},
		{"2: the trail (reconfigure)", compilesets.Request{
			Principal: researcher, Action: "cloudtrail:UpdateTrail", Resource: "*"}},
		{"3: leaving the organization", compilesets.Request{
			Principal: researcher, Action: "organizations:LeaveOrganization", Resource: "*"}},
		{"4: the management-assumable role", compilesets.Request{
			Principal: researcher, Action: "iam:UpdateAssumeRolePolicy",
			Resource: "arn:aws:iam::333333333333:role/OrganizationAccountAccessRole"}},
		{"4: automat's own automation role", compilesets.Request{
			Principal: researcher, Action: "iam:DeleteRolePolicy",
			Resource: "arn:aws:iam::333333333333:role/automat-automation"}},
		{"5: the root user", compilesets.Request{
			Principal: "arn:aws:iam::333333333333:root", Action: "s3:GetObject", Resource: "*"}},
	}
	for _, tc := range cases {
		if !compilesets.Denies(statements, tc.req) {
			t.Errorf("DESIGN §10 bullet %s is not enforced: the compiled baseline permits %s on %s by %s",
				tc.bullet, tc.req.Action, tc.req.Resource, tc.req.Principal)
		}
	}
}

// TestTheRootDenyStillLetsRolesWork.
//
// The other half of bullet 5, and the one that decides whether a vended account is
// usable. A root deny whose condition is wrong or absent denies every action to
// every principal, and the account cannot be recovered from inside itself. This is
// the assertion that would fail if the condition were ever dropped while the
// wildcard action stayed — which is precisely the shape rootDenyIsWellFormed exists
// to refuse at compile time, checked here at the behavioral layer as well because
// the two could drift.
func TestTheRootDenyStillLetsRolesWork(t *testing.T) {
	statements := compilesets.FromArtifact(compileBaselineForTest(t)).Statements
	for _, action := range []string{"s3:GetObject", "ec2:RunInstances", "sts:AssumeRole", "logs:PutLogEvents"} {
		req := compilesets.Request{
			Principal: "arn:aws:iam::333333333333:role/researcher",
			Action:    action,
			Resource:  "arn:aws:s3:::some-bucket/some-key",
		}
		if compilesets.Denies(statements, req) {
			t.Errorf("the baseline denies %s to an ordinary role; a vended account that cannot do "+
				"ordinary work is not a vended account", action)
		}
	}
}

// TestTheAutomationExemptionAppliesToTheDetectiveBaselineOnly.
//
// The exemption is the only thing in this catalog that widens anything, so its scope
// is the thing to pin. automat's automation role has to be able to install the
// detective baseline; it must NOT be able to rewrite its own permissions or detach
// the account from the organization, which are the two holes BP.IAM-1's and
// BP.ORG-1's extends_design text promises are absent.
func TestTheAutomationExemptionAppliesToTheDetectiveBaselineOnly(t *testing.T) {
	statements := compilesets.FromArtifact(compileBaselineForTest(t)).Statements
	const automation = artifact.AutomationRolePlaceholder

	allowed := []string{
		"config:PutConfigurationRecorder",
		"config:PutDeliveryChannel",
		"config:PutConformancePack",
		"cloudtrail:PutEventSelectors",
	}
	for _, action := range allowed {
		req := compilesets.Request{Principal: automation, Action: action, Resource: "*"}
		if compilesets.Denies(statements, req) {
			t.Errorf("the baseline denies %s to automat's own automation role; a control that blocks its "+
				"own installation parks every vend", action)
		}
	}

	denied := []struct {
		action, resource, why string
	}{
		{"organizations:LeaveOrganization", "*",
			"BP.ORG-1 states it carries no exemption: one call would take the whole baseline with it"},
		{"iam:UpdateAssumeRolePolicy", "arn:aws:iam::333333333333:role/automat-automation",
			"BP.IAM-1 states it carries no exemption: a role that can rewrite its own trust policy is a " +
				"standing privilege-escalation path"},
		{"iam:PutRolePolicy", "arn:aws:iam::333333333333:role/OrganizationAccountAccessRole",
			"BP.IAM-1 protects the management-assumable role from every principal in the account"},
	}
	for _, tc := range denied {
		req := compilesets.Request{Principal: automation, Action: tc.action, Resource: tc.resource}
		if !compilesets.Denies(statements, req) {
			t.Errorf("the baseline permits %s on %s to automat's automation role, but %s",
				tc.action, tc.resource, tc.why)
		}
	}
}

// TestTheBaselineIsRefusedIfItCanBeMergedIntoSomethingWider.
//
// The protection set is the one control set that is attached on EVERY vend, so it is
// the one most likely to be merged with something. §9's monotonicity property covers
// the merge in general; this pins the specific composition that ships, because a
// widening here is a widening in every account.
func TestTheBaselineIsRefusedIfItCanBeMergedIntoSomethingWider(t *testing.T) {
	baseline := compileBaselineForTest(t)
	other := compileForTest(t)

	alone := compilesets.Merge(baseline).Statements
	merged := compilesets.Merge(baseline, other).Statements

	probes := []compilesets.Request{
		{Principal: "arn:aws:iam::333333333333:role/researcher",
			Action: "config:StopConfigurationRecorder", Resource: "*"},
		{Principal: "arn:aws:iam::333333333333:role/researcher",
			Action: "organizations:LeaveOrganization", Resource: "*"},
		{Principal: "arn:aws:iam::333333333333:root", Action: "iam:CreateUser", Resource: "*"},
		{Principal: artifact.AutomationRolePlaceholder,
			Action: "iam:PutRolePolicy", Resource: "arn:aws:iam::333333333333:role/automat-automation"},
	}
	for _, req := range probes {
		if compilesets.Denies(alone, req) && !compilesets.Denies(merged, req) {
			t.Errorf("merging the baseline with %s WIDENS it: %s on %s by %s is denied by the baseline "+
				"alone and permitted by the merge", other.Meta.ID, req.Action, req.Resource, req.Principal)
		}
	}
}

// TestTheDesignBasisAndAnyDepartureReachTheArtifact.
//
// checkAgainstDesign refuses an unexplained departure on the grounds that the
// reviewer approving an account's preventive posture will read the reason. That is
// only true if the reason travels: the source file is upstream of a compile and is
// not what ships, so the text has to appear in the artifact itself. This asserts the
// claim the checker's error message makes.
func TestTheDesignBasisAndAnyDepartureReachTheArtifact(t *testing.T) {
	doc := loadBaselineSource(t)
	a := compileBaselineForTest(t)

	byID := map[string]artifact.Control{}
	for _, c := range a.Controls {
		byID[c.ID] = c
	}
	for _, src := range doc.Controls {
		c, ok := byID[src.ID]
		if !ok {
			t.Errorf("source control %s is not in the compiled artifact", src.ID)
			continue
		}
		if !strings.Contains(c.Statement, src.DesignBasis) {
			t.Errorf("control %s's compiled statement does not carry its design_basis, so a reviewer "+
				"holding only the artifact cannot trace the Deny to a decision", src.ID)
		}
		if src.ExtendsDesign != "" && !strings.Contains(c.Statement, src.ExtendsDesign) {
			t.Errorf("control %s departs from DESIGN §10 and its explanation does not reach the compiled "+
				"artifact; the compiler required the explanation on the grounds that the reviewer would "+
				"read it, and the artifact is the only document that reviewer is guaranteed to have", src.ID)
		}
	}
}

// TestTheBaselineProvenanceStatesTheAbsenceOfAnUpstream.
//
// Every other catalog's source entry hashes a third-party publication. This one
// hashes the curated file, which is the whole chain — and a reader who found a
// single self-referential source anywhere else would be right to call it a broken
// provenance chain. The note is the only thing distinguishing the two, so it is the
// one field here worth a test.
func TestTheBaselineProvenanceStatesTheAbsenceOfAnUpstream(t *testing.T) {
	a := compileBaselineForTest(t)
	if len(a.Meta.Sources) != 1 {
		t.Fatalf("baseline has %d sources, want exactly 1", len(a.Meta.Sources))
	}
	s := a.Meta.Sources[0]
	if s.SHA256 == "" {
		t.Error("the baseline source carries no hash, so the artifact cannot be traced to the file it " +
			"was compiled from")
	}
	for _, want := range []string{"no upstream publication", baselineSourceFile, "DESIGN.md §10"} {
		if !strings.Contains(s.Note, want) {
			t.Errorf("the source note does not mention %q; without it the single self-referential source "+
				"reads as a broken provenance chain rather than a stated absence: %q", want, s.Note)
		}
	}

	// The hash must be OF the curated file, not of something else that happens to
	// be present. Recomputed here through the same reader the compiler uses.
	var doc baselineDoc
	fileHash, err := readJSONAndHash(filepath.Join(sourcesDir, baselineSourceFile), &doc)
	if err != nil {
		t.Fatalf("read %s: %v", baselineSourceFile, err)
	}
	if s.SHA256 != fileHash {
		t.Errorf("the source hash is %s but %s hashes to %s", s.SHA256, baselineSourceFile, fileHash)
	}
}

// ---------------------------------------------------------------------------
// The checker
// ---------------------------------------------------------------------------

// TestTheDesignChecklistIsNotVacuous is a regression test, and the reason this file
// has a section for the checker at all.
//
// designSection10Actions originally included "*", transcribed from §10's fifth
// bullet. path.Match("*", anything) matches, so EVERY action was "enumerated by the
// design": the whole drift check passed on any input, including an action list with
// nothing to do with §10. A checklist with an entry that matches everything is not a
// checklist, and nothing about the compiler's output looked wrong.
func TestTheDesignChecklistIsNotVacuous(t *testing.T) {
	for _, action := range []string{
		"s3:DeleteBucket",
		"ec2:RunInstances",
		"kms:ScheduleKeyDeletion",
		"*",
		"config:GetResourceConfigHistory", // a real Config action §10 does not name
	} {
		if coveredByDesign(action) {
			t.Errorf("coveredByDesign(%q) is true, so the design-drift check would accept an action "+
				"DESIGN §10 does not enumerate without any explanation. If a checklist entry matches "+
				"everything, the check passes on everything", action)
		}
	}

	// And the positive direction, so the test above cannot be satisfied by a
	// checklist that matches nothing either.
	for _, action := range []string{
		"config:StopConfigurationRecorder",
		"cloudtrail:DeleteTrail",
		"organizations:LeaveOrganization",
		"iam:UpdateAssumeRolePolicy", // via iam:Update*
		"iam:AttachRolePolicy",       // via iam:Attach*
	} {
		if !coveredByDesign(action) {
			t.Errorf("coveredByDesign(%q) is false, but DESIGN §10 enumerates it; the checker would "+
				"demand an extends_design for a control that does exactly what the design says", action)
		}
	}
}

// TestTheCheckerRefusesASourceItShouldNotCompile.
//
// Table-driven over the mutations that matter, each one a way the source file could
// be wrong that produces a valid-looking artifact. The want string is the part of
// the message that carries the reason rather than the whole text, so rewording a
// message does not break the test but deleting its explanation does.
func TestTheCheckerRefusesASourceItShouldNotCompile(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*baselineDoc)
		want   string
	}{
		{
			// A typo in an exemption name compiles to a Deny with no hole where the
			// author intended one, or with a hole they did not write, depending on
			// which way the typo went.
			name:   "a control names an exemption the file does not define",
			mutate: func(d *baselineDoc) { d.Controls[0].Exemption = "baseline-automaton" },
			want:   "undefined exemption",
		},
		{
			// A reviewed-looking hole waiting for a future control to attach itself
			// to it.
			name: "an exemption no control uses",
			mutate: func(d *baselineDoc) {
				d.Exemptions["unused-hole"] = baselineExempt{
					Reason:     "a plausible-sounding reason",
					Principals: []string{"automat:automation-role"},
				}
			},
			want: "no control uses",
		},
		{
			name: "an exemption with no reason",
			mutate: func(d *baselineDoc) {
				ex := d.Exemptions["baseline-automation"]
				ex.Reason = ""
				d.Exemptions["baseline-automation"] = ex
			},
			want: "no reason",
		},
		{
			// MalformedPolicyDocument at CreatePolicy, mid-vend, with the account
			// already created.
			name:   "two controls sharing a Sid",
			mutate: func(d *baselineDoc) { d.Controls[1].Sid = d.Controls[0].Sid },
			want:   "unique within a",
		},
		{
			name:   "two controls sharing an id",
			mutate: func(d *baselineDoc) { d.Controls[1].ID = d.Controls[0].ID },
			want:   "duplicate control id",
		},
		{
			name: "an action DESIGN §10 does not enumerate, with no explanation",
			mutate: func(d *baselineDoc) {
				d.Controls[0].Actions = append(d.Controls[0].Actions, "s3:DeleteBucket")
				d.Controls[0].ExtendsDesign = ""
			},
			want: "which DESIGN §10 does not enumerate",
		},
		{
			name:   "a control with no design basis",
			mutate: func(d *baselineDoc) { d.Controls[0].DesignBasis = "" },
			want:   "no design_basis",
		},
		{
			// The shape that bricks an account: a Deny on every action with nothing
			// narrowing it denies every call every principal can make, including the
			// ones needed to remove the policy.
			name: "a wildcard action with no principal condition",
			mutate: func(d *baselineDoc) {
				c := rootControlIndex(t, d)
				d.Controls[c].Condition = nil
			},
			want: "without a condition on aws:PrincipalArn",
		},
		{
			// A condition on some other key is not a narrowing: the statement still
			// denies every action to every principal whenever that key matches.
			name: "a wildcard action narrowed by the wrong condition key",
			mutate: func(d *baselineDoc) {
				c := rootControlIndex(t, d)
				d.Controls[c].Condition = artifact.Condition{
					"StringEquals": {"aws:PrincipalTag/unit": []string{"physics"}},
				}
			},
			want: "without a condition on aws:PrincipalArn",
		},
		{
			// An exemption on a deny-everything statement is a principal no control
			// in the account applies to.
			name: "a wildcard action with an exemption",
			mutate: func(d *baselineDoc) {
				d.Controls[rootControlIndex(t, d)].Exemption = "baseline-automation"
			},
			want: "larger hole than the one the control closes",
		},
		{
			name:   "no controls at all",
			mutate: func(d *baselineDoc) { d.Controls = nil },
			want:   "attaches nothing while reporting",
		},
		{
			name:   "a control denying no actions",
			mutate: func(d *baselineDoc) { d.Controls[0].Actions = nil },
			want:   "denies nothing",
		},
		{
			name:   "a control naming no resources",
			mutate: func(d *baselineDoc) { d.Controls[0].Resources = nil },
			want:   "must scope to at least",
		},
		{
			name:   "a control with no statement for a reviewer to read",
			mutate: func(d *baselineDoc) { d.Controls[0].Statement = "" },
			want:   "both a title and a statement",
		},
		{
			name:   "provenance with no note",
			mutate: func(d *baselineDoc) { d.Source.Note = "" },
			want:   "broken provenance chain",
		},
		{
			name:   "provenance with no design section",
			mutate: func(d *baselineDoc) { d.Source.DesignSection = "" },
			want:   "no design_section",
		},
		{
			name:   "a non-UTC authored_at",
			mutate: func(d *baselineDoc) { d.Source.AuthoredAt = "2026-08-05T00:00:00-04:00" },
			want:   "second-precision UTC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := loadBaselineSource(t)
			tc.mutate(doc)
			err := doc.check()
			if err == nil {
				t.Fatalf("check() accepted a source file with %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error does not explain the problem (%q): %v", tc.want, err)
			}
		})
	}
}

// TestTheUnmutatedSourceCompilesCleanly is the control for the table above: every
// case there mutates a doc that must otherwise pass, or a case could be passing
// because of an unrelated defect in the shipped file.
func TestTheUnmutatedSourceCompilesCleanly(t *testing.T) {
	if err := loadBaselineSource(t).check(); err != nil {
		t.Fatalf("the shipped source does not pass its own checker: %v", err)
	}
}

// rootControlIndex finds the control that denies every action, by behavior.
//
// Searched rather than indexed by id or position: a test that hardcodes BP.ROOT-1
// silently stops testing the wildcard rules the day the control is renamed, and
// renaming a control is not supposed to be dangerous.
func rootControlIndex(t *testing.T, d *baselineDoc) int {
	t.Helper()
	for i, c := range d.Controls {
		for _, a := range c.Actions {
			if a == "*" {
				return i
			}
		}
	}
	t.Fatal("no control in the source denies action \"*\"; the wildcard cases below would test nothing. " +
		"If DESIGN §10's root-user deny was expressed some other way, retarget these cases at it")
	return -1
}

// TestTheSourceLoaderRejectsUnknownFieldsInTheBaselineToo.
//
// The same AUDIT-0 H2 defect as the cmmc-l1 loader, on a second file: a misspelled
// key parses cleanly and silently drops what it carries. Here the stakes are one
// level up — "extends_design" misspelled would drop a departure's explanation, and
// "condition" misspelled would drop the narrowing on a Deny for every action,
// producing a source file whose root-user control denies the whole account.
func TestTheSourceLoaderRejectsUnknownFieldsInTheBaselineToo(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sourcesDir, baselineSourceFile)) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	mangled := strings.Replace(string(data), `"condition"`, `"conditon"`, 1)
	if mangled == string(data) {
		t.Fatal("test setup: no condition key found to misspell")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, baselineSourceFile)
	if werr := os.WriteFile(path, []byte(mangled), 0o600); werr != nil {
		t.Fatalf("write: %v", werr)
	}

	if _, err := compileBaseline(dir); err == nil {
		t.Fatal("compileBaseline accepted a source with a misspelled key. A dropped \"condition\" leaves " +
			"a Deny on every action with nothing narrowing it, which denies every call in the account")
	} else if !strings.Contains(err.Error(), "conditon") {
		t.Errorf("the error does not name the offending key: %v", err)
	}
}

// TestTheBaselineArtifactSatisfiesThePublishedSchema.
//
// Against schema/, not against the Go types that produced it: an external consumer
// reads the schema, so that is the contract. The cmmc-l1 catalog has the equivalent
// test, and this one is not redundant with it — the baseline is the only shipped
// artifact whose controls carry SCP statements, exempt_principals, and a condition
// block, so it is the only one exercising those parts of the schema.
func TestTheBaselineArtifactSatisfiesThePublishedSchema(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(catalogsDir, baselineGoldenFile)) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse %s: %v", baselineGoldenFile, err)
	}
	if verr := publishedSchema(t).Validate(doc); verr != nil {
		t.Errorf("%s does not satisfy schema/control-artifact-v1.schema.json: %v", baselineGoldenFile, verr)
	}
}
