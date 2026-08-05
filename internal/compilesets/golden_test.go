// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Golden files for the packer, the ROADMAP's Phase 2 accept criterion ("SCP
// packer: quota-aware, deterministic output, golden-tested").
//
// What they are for: the property tests prove the merge cannot widen, and
// TestPackIsDeterministic proves the bytes are stable. Neither notices if the
// packed policy becomes something an operator would not want attached — a Sid
// changed, a condition dropped, the automation-role exemption quietly gone. A
// golden file makes that a reviewable diff, and these documents get attached to a
// real OU, so a reviewable diff is the point.
//
// Update with AUTOMAT_UPDATE_GOLDEN=1, the same convention internal/bundle and
// gen/catalog use.
const updateGoldenEnv = "AUTOMAT_UPDATE_GOLDEN"

func updateGolden() bool { return os.Getenv(updateGoldenEnv) == "1" }

// goldenScenarios are the input shapes the golden files cover.
//
// Every value here is fixed. Nothing may vary between runs — no timestamps, no
// map iteration reaching the output — or the golden test becomes noise that gets
// regenerated reflexively, which is the failure mode that makes golden files
// worthless.
var goldenScenarios = []struct {
	dir   string
	build func(t *testing.T) *Merged
}{
	{
		// The ordinary case: two frameworks restating overlapping requirements,
		// merged. This is what a real `compile` of two catalogs looks like, and the
		// interesting part of the diff is which statements collapsed.
		dir:   "two-frameworks",
		build: func(t *testing.T) *Merged { return Merge(goldenFrameworkA(t), goldenFrameworkB(t)) },
	},
	{
		// Exemption arithmetic, visible in the output. One set exempts a break-glass
		// role and the other does not; the packed policy must exempt nobody for the
		// action they share, and both must keep the exemption for the actions only
		// one of them constrains.
		dir:   "disagreeing-exemptions",
		build: func(t *testing.T) *Merged { return Merge(goldenFrameworkA(t), goldenExemptionDisagreement(t)) },
	},
	{
		// The allowlists, which are the only NotAction statements automat emits and
		// the ones most likely to brick an account if the global-service exemption
		// list changes shape.
		dir: "allowlists",
		build: func(t *testing.T) *Merged {
			return Merge(goldenFrameworkA(t), goldenAllowlisted(t))
		},
	},
	{
		// A pack that needs more than one policy, so the bin packing itself is
		// pinned: a change in how statements are distributed across documents is a
		// change in what gets attached.
		//
		// A fixed statement count, unlike the quota tests' searched fixtures. Those
		// need a particular shape and should find it; this one needs particular
		// bytes, and a size that moved with the renderer would regenerate rather than
		// diff.
		dir:   "multi-policy",
		build: func(t *testing.T) *Merged { return wideMerged(t, 60) },
	},
}

func TestPackedPoliciesMatchGolden(t *testing.T) {
	for _, sc := range goldenScenarios {
		t.Run(sc.dir, func(t *testing.T) {
			got := mustPack(t, sc.build(t), packOpts())

			dir := filepath.Join("testdata", "golden", sc.dir)
			if updateGolden() {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				// Remove stale documents from a previous run that produced more
				// policies, so a pack that shrinks does not leave an orphan file
				// asserting a policy nothing emits.
				old, _ := filepath.Glob(filepath.Join(dir, "*.json"))
				for _, p := range old {
					if err := os.Remove(p); err != nil {
						t.Fatal(err)
					}
				}
			}

			for _, p := range got.Policies {
				path := filepath.Join(dir, p.Name+".json")
				// Indented for review. The packed document is deliberately compact
				// — every character counts against 5120 — but a golden file exists
				// to be read in a diff, so it is stored pretty-printed and
				// re-compacted for comparison.
				pretty := indentJSON(t, p.Document)
				if updateGolden() {
					// 0644: a golden file is a committed, reviewed artifact. The
					// ARNs in it are the fixed test ones.
					if err := os.WriteFile(path, []byte(pretty), 0o644); err != nil { //nolint:gosec // reviewed, committed fixture
						t.Fatalf("write %s: %v", path, err)
					}
					t.Logf("updated %s (%d bytes packed)", path, len(p.Document))
					continue
				}
				want, err := os.ReadFile(path) //nolint:gosec // fixed testdata path
				if err != nil {
					t.Fatalf("read %s: %v — run `AUTOMAT_UPDATE_GOLDEN=1 go test ./internal/compilesets/`",
						path, err)
				}
				if pretty != string(want) {
					t.Errorf("%s does not match the golden file.\n%s\n"+
						"If the change is intended, run "+
						"`AUTOMAT_UPDATE_GOLDEN=1 go test ./internal/compilesets/` and review the diff: "+
						"these documents get attached to an OU.",
						p.Name, firstDiff(string(want), pretty))
				}
			}
			if !updateGolden() {
				assertNoOrphanGolden(t, dir, got)
			}
		})
	}
}

// assertNoOrphanGolden catches the direction the loop above cannot: a pack that
// stops emitting a policy the golden directory still has a file for. Without this,
// losing a policy — dropping half the controls — passes.
func assertNoOrphanGolden(t *testing.T, dir string, got *Packed) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	have := make(map[string]bool, len(got.Policies))
	for _, p := range got.Policies {
		have[p.Name+".json"] = true
	}
	for _, f := range files {
		if !have[filepath.Base(f)] {
			t.Errorf("%s exists but the packer no longer emits that policy — either a policy was lost "+
				"(the statements in it are no longer enforced) or the golden file is stale", f)
		}
	}
	if len(files) != len(got.Policies) {
		t.Errorf("%s has %d golden documents but the pack produced %d policies", dir, len(files),
			len(got.Policies))
	}
}

// TestEveryGoldenScenarioIsCoveredByAFile.
//
// The check that keeps the accept criterion honest: a scenario added without
// running the update step would otherwise pass by never being compared.
func TestEveryGoldenScenarioIsCoveredByAFile(t *testing.T) {
	if updateGolden() {
		t.Skip("writing golden files")
	}
	root := filepath.Join("testdata", "golden")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v — run `AUTOMAT_UPDATE_GOLDEN=1 go test ./internal/compilesets/`", root, err)
	}
	extra := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			extra[e.Name()] = true
		}
	}
	for _, sc := range goldenScenarios {
		if !extra[sc.dir] {
			t.Errorf("scenario %s has no golden directory", sc.dir)
		}
		delete(extra, sc.dir)
	}
	for dir := range extra {
		t.Errorf("testdata/golden/%s has no scenario — a stale directory from a renamed or deleted "+
			"scenario, still committed and asserting nothing", dir)
	}
}

// TestTheModelUnderstandsEveryOperatorTheCatalogsUse.
//
// Owed by name from behavior.go: Denies answers "does not deny" for a condition
// operator it does not model, and that under-reporting is only harmless while it
// is measured. If a catalog starts using StringLike with a numeric operator, or
// ForAllValues:, the property tests keep passing and stop testing the statements
// that carry it.
//
// Scoped to everything the repo can hand the packer — the shipped catalogs and the
// golden fixtures — because a test whose subject is empty is a test that cannot
// fail.
//
// The shipped-catalog contribution used to be LOGGED rather than asserted, and the
// comment here said why: cmmc-l1 carries no SCP at all, permanently and by design,
// so there was nothing shipped for the model to be checked against. That is no
// longer true. catalogs/baseline-protection.json is a shipped control set whose
// entries are SCP-class by definition, and it is the set attached to every account
// automat vends — so it is the last artifact whose operators should go unmodeled,
// and the count is now an assertion. The specific failure it guards is a
// baseline-protection statement that acquires a condition operator Denies does not
// evaluate: the property suite would keep passing over a statement contributing
// nothing to it.
func TestTheModelUnderstandsEveryOperatorTheCatalogsUse(t *testing.T) {
	var statements []Statement
	var scpControls int

	for _, path := range shippedCatalogs(t) {
		a, err := artifact.Load(path, artifact.LoadOptions{})
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		for _, c := range a.Controls {
			if c.SCP != nil {
				scpControls++
			}
		}
		statements = append(statements, FromArtifact(a).Statements...)
	}
	if scpControls == 0 || len(statements) == 0 {
		t.Fatalf("the shipped catalogs contribute %d SCP-bearing controls and %d statements. This test's "+
			"subject is the preventive posture automat actually ships; if the SCP-bearing catalog moved or "+
			"stopped being globbed, this passes while checking only the fixtures below",
			scpControls, len(statements))
	}
	t.Logf("shipped catalogs contribute %d SCP-bearing controls and %d statements",
		scpControls, len(statements))

	for _, sc := range goldenScenarios {
		statements = append(statements, sc.build(t).Statements...)
	}

	if unknown := UnknownOperators(statements); len(unknown) > 0 {
		t.Errorf("the behavioral model does not understand these condition operators: %v.\n"+
			"Denies reports 'does not deny' for an unmodeled operator, so every property test over a "+
			"statement carrying one is weakened without saying so. Add the operator to conditionMatches, "+
			"or state in behavior.go why it cannot be modeled.", unknown)
	}
}

func shippedCatalogs(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "catalogs", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no shipped catalogs found; the path this test globs must have moved")
	}
	return paths
}

// ---------------------------------------------------------------------------
// Golden fixtures
// ---------------------------------------------------------------------------

// goldenMerged is the fixture the determinism and ordering tests use: broad
// enough to exercise merging, exemptions, and both allowlists at once.
func goldenMerged(t *testing.T) *Merged {
	t.Helper()
	return Merge(goldenFrameworkA(t), goldenFrameworkB(t), goldenAllowlisted(t))
}

// goldenFrameworkA is a plausible baseline-protection control set: don't let the
// account turn off its own evidence collection.
func goldenFrameworkA(t *testing.T) *artifact.Artifact {
	t.Helper()
	return artifactWithSCP(t, "golden-a", &artifact.SCP{Statements: []artifact.SCPStatement{
		{
			Sid:      "ProtectConfigRecorder",
			Effect:   "Deny",
			Action:   []string{"config:DeleteConfigurationRecorder", "config:StopConfigurationRecorder"},
			Resource: []string{"*"},
			ExemptPrincipals: artifact.ExemptPrincipals{{
				Principal: artifact.AutomationRolePlaceholder,
				Reason:    "automat configures the recorder during vend",
			}},
		},
		{
			Sid:      "ProtectCloudTrail",
			Effect:   "Deny",
			Action:   []string{"cloudtrail:DeleteTrail", "cloudtrail:StopLogging"},
			Resource: []string{"*"},
			ExemptPrincipals: artifact.ExemptPrincipals{{
				Principal: artifact.AutomationRolePlaceholder,
				Reason:    "automat configures the trail during vend",
			}},
		},
		{
			Sid:      "DenyRootUser",
			Effect:   "Deny",
			Action:   []string{"*"},
			Resource: []string{"*"},
			Condition: artifact.Condition{
				"StringLike": {"aws:PrincipalArn": {"arn:aws:iam::*:root"}},
			},
		},
	}})
}

// goldenFrameworkB restates two of A's requirements — the crosswalk case — and
// adds one of its own. The merged output should show A's and B's provenance on the
// shared statements.
func goldenFrameworkB(t *testing.T) *artifact.Artifact {
	t.Helper()
	return artifactWithSCP(t, "golden-b", &artifact.SCP{Statements: []artifact.SCPStatement{
		{
			// Same guard and same actions as A's, different Sid and wording: what a
			// second framework citing the same requirement looks like.
			Sid:      "AuditLogProtection",
			Effect:   "Deny",
			Action:   []string{"config:StopConfigurationRecorder"},
			Resource: []string{"*"},
			ExemptPrincipals: artifact.ExemptPrincipals{{
				Principal: artifact.AutomationRolePlaceholder,
				Reason:    "the provisioning role establishes the recorder",
			}},
		},
		{
			Sid:      "DenyIAMUserCreation",
			Effect:   "Deny",
			Action:   []string{"iam:CreateUser", "iam:CreateAccessKey"},
			Resource: []string{"*"},
		},
	}})
}

// goldenExemptionDisagreement constrains one action A also constrains, without
// A's exemption, and one action nobody else constrains, with an exemption. The
// packed output shows both halves of the intersection.
func goldenExemptionDisagreement(t *testing.T) *artifact.Artifact {
	t.Helper()
	return artifactWithSCP(t, "golden-strict", &artifact.SCP{Statements: []artifact.SCPStatement{
		{
			// No exemption. A exempts the automation role for this action; the
			// intersection must exempt nobody.
			Sid:      "NoOneStopsTheRecorder",
			Effect:   "Deny",
			Action:   []string{"config:StopConfigurationRecorder"},
			Resource: []string{"*"},
		},
		{
			Sid:      "ProtectKMSKeys",
			Effect:   "Deny",
			Action:   []string{"kms:ScheduleKeyDeletion"},
			Resource: []string{"*"},
			ExemptPrincipals: artifact.ExemptPrincipals{{
				Principal: "arn:aws:iam::111111111111:role/break-glass",
				Reason:    "documented incident-response procedure, reviewed annually",
			}},
		},
	}})
}

// goldenAllowlisted carries both allowlists.
func goldenAllowlisted(t *testing.T) *artifact.Artifact {
	t.Helper()
	a := artifactWithSCP(t, "golden-allow", &artifact.SCP{Statements: []artifact.SCPStatement{{
		Sid:      "DenySecurityHubDisable",
		Effect:   "Deny",
		Action:   []string{"securityhub:DisableSecurityHub"},
		Resource: []string{"*"},
	}}})
	a.Controls[0].SCP.RegionAllowlist = []string{"us-east-1", "us-west-2"}
	a.Controls[0].SCP.ServiceAllowlist = []string{"s3", "ec2", "batch", "fsx"}
	return a
}

// indentJSON re-renders a packed document for review.
func indentJSON(t *testing.T, doc string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(doc), "", "  "); err != nil {
		t.Fatalf("the packed document is not valid JSON: %v\n%s", err, doc)
	}
	return buf.String() + "\n"
}

// firstDiff reports the first differing line, since a whole-file dump of a packed
// policy hides the one line that changed.
func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return "first difference at line " + itoa(i+1) + ":\n  golden: " + w + "\n  now:    " + g
		}
	}
	return "the files differ only in trailing bytes"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
