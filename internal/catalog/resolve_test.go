// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Resolution is where an id from a file becomes a path, so these tests are as much
// about what is refused as about what loads. The embedded tree is the subject wherever
// the assertion is about the shipped catalogs; fstest.MapFS is the subject wherever the
// assertion is about a tree automat should not accept, since a hand-supplied catalog is
// the only way those states arise.

func TestResolveControlSetsLoadsTheShippedCatalog(t *testing.T) {
	got, err := ResolveControlSets([]string{"cmmc-l1"}, Options{})
	if err != nil {
		t.Fatalf("resolve cmmc-l1 from the embedded tree: %v", err)
	}
	if len(got.IDs) != len(got.Artifacts) {
		t.Fatalf("%d ids and %d artifacts; the two are documented as positionally aligned",
			len(got.IDs), len(got.Artifacts))
	}
	for i, id := range got.IDs {
		if got.Artifacts[i].Meta.ID != id {
			t.Errorf("IDs[%d] is %q but Artifacts[%d] is %q; a caller reporting on one would name "+
				"the wrong other", i, id, i, got.Artifacts[i].Meta.ID)
		}
	}
	// The hash was verified, not skipped: LoadOptions defaults to checking it, and a
	// resolver that quietly passed SkipHashCheck would make every downstream tag and
	// evidence record quote a value nothing confirmed.
	for _, a := range got.Artifacts {
		if err := a.VerifyContentHash(); err != nil {
			t.Errorf("%s: %v", a.Meta.ID, err)
		}
	}
}

// TestBaselineProtectionIsAlwaysResolved is DESIGN §10's meta-control held as a
// property of the resolver rather than a convention callers follow.
//
// The three inputs are the three ways a profile can talk about it: not at all, by name,
// and by name twice. All three produce the same set, and the second and third produce
// it exactly once — a duplicate would put the same statements through Merge twice, and
// while the union is idempotent the origin list in a conflict report is not.
func TestBaselineProtectionIsAlwaysResolved(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
	}{
		{"not named", []string{"cmmc-l1"}},
		{"named", []string{"cmmc-l1", BaselineProtectionID}},
		{"named twice", []string{BaselineProtectionID, "cmmc-l1", BaselineProtectionID}},
		{"named alone", []string{BaselineProtectionID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveControlSets(tc.in, Options{})
			if err != nil {
				t.Fatalf("resolve %v: %v", tc.in, err)
			}
			n := 0
			for _, id := range got.IDs {
				if id == BaselineProtectionID {
					n++
				}
			}
			if n != 1 {
				t.Errorf("baseline-protection appears %d times in %v; it must appear exactly once "+
					"whether or not the profile named it", n, got.IDs)
			}
		})
	}
}

// TestResolveControlSetsIsOrderIndependent. Merge is commutative, so order cannot
// change what is enforced — but it can change an error message's bytes and a conflict
// report's origin list, and two runs of the same vend must produce the same text.
func TestResolveControlSetsIsOrderIndependent(t *testing.T) {
	a, err := ResolveControlSets([]string{"cmmc-l1", BaselineProtectionID}, Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	b, err := ResolveControlSets([]string{BaselineProtectionID, "cmmc-l1"}, Options{})
	if err != nil {
		t.Fatalf("resolve reversed: %v", err)
	}
	if strings.Join(a.IDs, ",") != strings.Join(b.IDs, ",") {
		t.Errorf("order of control_sets changed the resolved order: %v vs %v", a.IDs, b.IDs)
	}
}

// TestUnresolvableControlSetNamesWhatIsAvailable.
//
// The failure an operator actually hits is a typo, and the remediation for a typo is
// the list. A hard error rather than a skip: a vend that silently dropped a control set
// would produce an account whose birth certificate claims a posture nothing enforced.
func TestUnresolvableControlSetNamesWhatIsAvailable(t *testing.T) {
	_, err := ResolveControlSets([]string{"cmcc-l1"}, Options{})
	if err == nil {
		t.Fatal("a control set id that names no document resolved")
	}
	var re *ResolveError
	if !errors.As(err, &re) {
		t.Fatalf("error is not a *ResolveError, so a caller cannot see what was available: %T", err)
	}
	if len(re.Available) == 0 {
		t.Error("the error lists nothing as available; the list is the remediation for a typo")
	}
	for _, want := range []string{"cmcc-l1", "cmmc-l1", BaselineProtectionID, "make catalogs"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// TestObligationsAreNotResolvableAsControlSets, and the converse.
//
// `cmmc-l1` is BOTH a control artifact and an obligation profile — same id, two
// documents, and the directory is what says which one a reference means. A resolver
// that searched one flat namespace would hand an obligation profile to artifact.Load,
// or worse, silently satisfy an obligation reference with a control artifact.
func TestTheTwoIDNamespacesDoNotCollide(t *testing.T) {
	// The control-set resolution of `cmmc-l1` is the control artifact.
	cs, err := ResolveControlSets([]string{"cmmc-l1"}, Options{})
	if err != nil {
		t.Fatalf("resolve control set cmmc-l1: %v", err)
	}
	var found *artifact.Artifact
	for i, id := range cs.IDs {
		if id == "cmmc-l1" {
			found = cs.Artifacts[i]
		}
	}
	if found == nil {
		t.Fatal("cmmc-l1 did not resolve as a control set")
	}
	if len(found.Controls) == 0 {
		t.Error("the document resolved as a control set carries no controls, so it is not one")
	}

	// And `baseline-protection` is a control set only: there is no obligation profile
	// by that name, and asking for one is an error rather than a fallback to the
	// top-level file.
	if _, err := ResolveObligations([]string{BaselineProtectionID}, Options{}); err == nil {
		t.Error("baseline-protection resolved as an obligation profile; the resolver fell back to " +
			"the control-artifact namespace, which would let a control set satisfy an obligation " +
			"reference")
	}
}

// TestResolveObligationsReadsTheRevisionPolicy is the one fact this package extracts
// that changes whether a vend proceeds: `nih-cadr-dua` leaves the control catalog
// revision to the operator, and CheckObligations refuses a reference to it that carries
// no determination.
func TestResolveObligationsReadsTheRevisionPolicy(t *testing.T) {
	set, err := ResolveObligations([]string{"cmmc-l1", "dfars-7012", "nih-cadr-dua"}, Options{})
	if err != nil {
		t.Fatalf("resolve the shipped obligation profiles: %v", err)
	}
	want := map[string]bool{"cmmc-l1": false, "dfars-7012": false, "nih-cadr-dua": true}
	for id, wantDet := range want {
		facts, ok := set.Obligation(id)
		if !ok {
			t.Errorf("%s did not resolve", id)
			continue
		}
		if facts.ID != id {
			t.Errorf("%s resolved to facts for %q", id, facts.ID)
		}
		if facts.RequiresRevisionDetermination != wantDet {
			t.Errorf("%s: RequiresRevisionDetermination is %v, want %v. This decides whether a "+
				"vend refuses a reference carrying no operator determination",
				id, facts.RequiresRevisionDetermination, wantDet)
		}
	}
}

// TestResolveObligationsReportsTheHashAsUnknown.
//
// Not an oversight and not a TODO: `obligation-profile/v1` does not define what its
// content hash covers, so there is no correct value to report. CheckObligations reads
// empty as "unknown" and never as "matches", which is the fail-closed direction for a
// check that cannot yet be made — but the check IS skipped, and this test is what makes
// that visible rather than something a reader has to infer from a hash that happens to
// verify. Q15.
//
// Delete this test when Q15 is decided. It asserts the absence of a check, so leaving it
// in place after the check exists would pin the gap open.
func TestResolveObligationsReportsTheHashAsUnknown(t *testing.T) {
	set, err := ResolveObligations([]string{"cmmc-l1"}, Options{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	facts, _ := set.Obligation("cmmc-l1")
	if facts.ContentSHA256 != "" {
		t.Errorf("ContentSHA256 is %q. Reporting a hash computed some plausible way is worse "+
			"than reporting none: CheckObligations would then compare a reference against a "+
			"definition nobody ratified, and every environment profile in the world would carry "+
			"the wrong value while looking checked. See Q15 in docs/open-questions.md",
			facts.ContentSHA256)
	}
}

// TestIDsAreRefusedBeforeTheyBecomePaths.
//
// The id arrives from a file that is attacker-controlled in the threat model and is
// about to be joined into a path. The traversal cases are the point; the rest bound the
// class. Asserted against BOTH resolvers, because a check on one entry point is not a
// property of the package.
func TestIDsAreRefusedBeforeTheyBecomePaths(t *testing.T) {
	bad := []struct{ name, id string }{
		{"parent traversal", "../../etc/passwd"},
		{"absolute", "/etc/passwd"},
		{"dot segment", "./cmmc-l1"},
		{"subdirectory", "obligations/cmmc-l1"},
		{"suffix already present", "cmmc-l1.json"},
		{"null byte", "cmmc-l1\x00"},
		{"newline", "cmmc-l1\ninjected"},
		{"uppercase", "CMMC-L1"},
		{"empty", ""},
		{"single character", "a"},
		{"leading hyphen", "-cmmc-l1"},
		{"trailing hyphen", "cmmc-l1-"},
		{"too long", strings.Repeat("a", 65)},
		{"windows separator", `cmmc-l1\..\..\etc`},
		{"url", "https://example.invalid/evil.json"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ResolveControlSets([]string{tc.id}, Options{}); err == nil {
				t.Errorf("control set id %q resolved", tc.id)
			} else if !strings.Contains(err.Error(), "not a catalog id") {
				// The distinction matters: "not a catalog id" means it was refused
				// before path.Join, and "names no document" means it became a path
				// and was then not found.
				t.Errorf("id %q was refused as a lookup miss rather than as a malformed id, "+
					"which means it reached path.Join: %v", tc.id, err)
			}
			if _, err := ResolveObligations([]string{tc.id}, Options{}); err == nil {
				t.Errorf("obligation profile id %q resolved", tc.id)
			}
		})
	}
}

// TestRefusalsDoNotEchoRawIDs. An id reaches an error message from a file, and the
// message is read by an operator deciding what to fix. A control byte in an id must not
// be able to forge a line of that report.
func TestRefusalsDoNotEchoRawIDs(t *testing.T) {
	const forged = "cmmc-l1\nApplied: everything is fine"
	_, err := ResolveControlSets([]string{forged}, Options{})
	if err == nil {
		t.Fatal("an id containing a newline resolved")
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("the error carries a raw newline from the id, so a catalog id can forge a line "+
			"of a report:\n%s", err)
	}
	if !strings.Contains(err.Error(), `\n`) {
		t.Errorf("the id was not rendered escaped, so it is unclear what the operator typed: %v", err)
	}
}

// TestIDClassMatchesThePublishedSchema is the drift detector this package's reID
// comment promises.
//
// The pattern is duplicated deliberately — a resolver whose only defense is its
// caller's validation has no defense — and duplication without a test is drift waiting
// to happen. Read out of the published schema rather than out of internal/envprofile,
// so the assertion is against the contract rather than against the other copy.
func TestIDClassMatchesThePublishedSchema(t *testing.T) {
	path := filepath.Join("../../schema", "environment-profile-v1.schema.json")
	data, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Properties struct {
			ControlSets struct {
				Items struct {
					Pattern string `json:"pattern"`
				} `json:"items"`
			} `json:"control_sets"`
		} `json:"properties"`
	}
	if uerr := json.Unmarshal(data, &doc); uerr != nil {
		t.Fatalf("parse %s: %v", path, uerr)
	}
	want := doc.Properties.ControlSets.Items.Pattern
	if want == "" {
		t.Fatal("the published schema declares no pattern for control_sets[]; either the schema " +
			"stopped bounding the id class or this test is reading the wrong node — both are " +
			"findings, since an id becomes a path")
	}
	if got := reID.String(); got != want {
		t.Errorf("this package refuses ids by %q; the published schema publishes %q.\n\n"+
			"The two are required to agree (CLAUDE.md rule 8): the schema is what an operator's "+
			"editor validates against and this is what decides whether a path is built.", got, want)
	}
}

// TestAFileWhoseInteriorIDDiffersIsRefused.
//
// The filename is how an id resolves, and every SCP tag and evidence record quotes the
// interior id — so a mismatch makes one document reachable under two names while
// everything it produces is labeled with only one. Unreachable for a vendored catalog
// (gen/catalog writes the file named for what it compiled) and reachable for a
// hand-supplied tree, which is what Options.FS exists for.
func TestAFileWhoseInteriorIDDiffersIsRefused(t *testing.T) {
	base, err := ResolveControlSets([]string{"cmmc-l1"}, Options{})
	if err != nil {
		t.Fatalf("resolve from the embedded tree: %v", err)
	}
	var src *artifact.Artifact
	for i, id := range base.IDs {
		if id == "cmmc-l1" {
			src = base.Artifacts[i]
		}
	}
	if src == nil {
		t.Fatal("cmmc-l1 did not resolve")
	}
	data, err := src.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	bp := mustRead(t, "baseline-protection")

	// The same document under a different name. Its declared hash still verifies —
	// the id is inside the hashed payload, but the FILENAME is not, which is exactly
	// why the filename cannot be trusted to say what a document is.
	fsys := fstest.MapFS{
		"impersonator.json":            &fstest.MapFile{Data: data},
		BaselineProtectionID + ".json": &fstest.MapFile{Data: bp},
	}
	_, err = ResolveControlSets([]string{"impersonator"}, Options{FS: fsys})
	if err == nil {
		t.Fatal("a file named impersonator.json holding the cmmc-l1 artifact resolved as " +
			"control set \"impersonator\"; the same control set is then reachable under two " +
			"names while every tag it produces quotes one of them")
	}
	for _, want := range []string{"impersonator", "cmmc-l1", "rename"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// TestATreeWithoutBaselineProtectionFailsLoudly. An institution vending against its own
// catalog must not be able to omit the meta-control by leaving the file out — that would
// be the same opt-out the append exists to prevent, taken one level down.
func TestATreeWithoutBaselineProtectionFailsLoudly(t *testing.T) {
	fsys := fstest.MapFS{"cmmc-l1.json": &fstest.MapFile{Data: mustRead(t, "cmmc-l1")}}
	_, err := ResolveControlSets([]string{"cmmc-l1"}, Options{FS: fsys})
	if err == nil {
		t.Fatal("resolution succeeded against a tree with no baseline-protection.json; a catalog " +
			"can then omit the meta-control by omitting a file")
	}
	if !strings.Contains(err.Error(), BaselineProtectionID) {
		t.Errorf("the error does not name the missing control set: %v", err)
	}
}

// TestAnArtifactWithABadHashIsRefused. The catalogs are embedded, so this is not about a
// file changing underneath automat — it is that a catalog's declared hash is the value
// every SCP tag and evidence record quotes, and nothing downstream re-derives it. If it
// does not cover the artifact's own controls, the tag names a posture the account does
// not have.
func TestAnArtifactWithABadHashIsRefused(t *testing.T) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, "cmmc-l1"), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(doc["artifact"], &meta); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	meta["content_sha256"] = json.RawMessage(`"` + strings.Repeat("0", 64) + `"`)
	remeta, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	doc["artifact"] = remeta
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	fsys := fstest.MapFS{
		"cmmc-l1.json":                 &fstest.MapFile{Data: tampered},
		BaselineProtectionID + ".json": &fstest.MapFile{Data: mustRead(t, BaselineProtectionID)},
	}
	if _, err := ResolveControlSets([]string{"cmmc-l1"}, Options{FS: fsys}); err == nil {
		t.Fatal("an artifact whose declared content hash does not cover its own controls loaded")
	}
}

// TestResolveObligationsWithNoReferencesIsNotAnError. A profile naming no obligations is
// ordinary: obligations are optional in the schema, and CheckObligations returns early
// on an empty list. A resolver that errored here would make the optional field mandatory
// by the back door.
func TestResolveObligationsWithNoReferencesIsNotAnError(t *testing.T) {
	set, err := ResolveObligations(nil, Options{})
	if err != nil {
		t.Fatalf("resolving no obligations: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("resolving no obligations produced %d facts", len(set))
	}
}

// TestUnresolvableObligationNamesWhatIsAvailable, and names the obligation namespace
// rather than the control-set one. An operator who typed `dfars7012` needs the shipped
// profiles listed, not the control sets.
func TestUnresolvableObligationNamesWhatIsAvailable(t *testing.T) {
	_, err := ResolveObligations([]string{"dfars7012"}, Options{})
	if err == nil {
		t.Fatal("an obligation profile id that names no document resolved")
	}
	var re *ResolveError
	if !errors.As(err, &re) {
		t.Fatalf("error is not a *ResolveError: %T", err)
	}
	got := strings.Join(re.Available, ",")
	if !strings.Contains(got, "dfars-7012") {
		t.Errorf("available lists %q, which does not include the shipped obligation profiles", got)
	}
	if strings.Contains(got, BaselineProtectionID) {
		t.Errorf("available lists %q, which includes a CONTROL SET; the two namespaces are "+
			"separate and an operator sent to the wrong list will type an id from it", got)
	}
}

// TestAnObligationProfileWhoseInteriorIDDiffersIsRefused, for the same reason the
// control-artifact case is: the reference and the evidence record quote the interior id
// while the filename is how it resolved.
func TestAnObligationProfileWhoseInteriorIDDiffersIsRefused(t *testing.T) {
	data := mustReadObligation(t, "dfars-7012")
	fsys := fstest.MapFS{"obligations/impostor.json": &fstest.MapFile{Data: data}}
	_, err := ResolveObligations([]string{"impostor"}, Options{FS: fsys})
	if err == nil {
		t.Fatal("obligations/impostor.json holding the dfars-7012 profile resolved as \"impostor\"")
	}
	for _, want := range []string{"impostor", "dfars-7012"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// TestAnUnparseableObligationProfileIsRefused. Not reachable for a vendored profile —
// the schema conformance tests would have caught it — and reachable for a
// hand-supplied one, where the alternative is silently treating a profile automat could
// not read as one with no operator determination outstanding.
func TestAnUnparseableObligationProfileIsRefused(t *testing.T) {
	fsys := fstest.MapFS{
		"obligations/broken.json": &fstest.MapFile{Data: []byte(`{"profile": `)},
	}
	_, err := ResolveObligations([]string{"broken"}, Options{FS: fsys})
	if err == nil {
		t.Fatal("an obligation profile that is not JSON resolved")
	}
	if !strings.Contains(err.Error(), "parseable") {
		t.Errorf("the error does not say the document could not be parsed: %v", err)
	}
}

// TestAvailableSurvivesAnUnlistableTree. The list is a courtesy on top of the real
// error; a tree that cannot be enumerated must still produce "names no document" rather
// than a different, less specific failure.
func TestAvailableSurvivesAnUnlistableTree(t *testing.T) {
	_, err := ResolveObligations([]string{"cmmc-l1"}, Options{FS: fstest.MapFS{}})
	if err == nil {
		t.Fatal("an obligation id resolved against an empty tree")
	}
	if !strings.Contains(err.Error(), "names no document") {
		t.Errorf("the error is not the lookup miss: %v", err)
	}
	if strings.Contains(err.Error(), "available:") {
		t.Errorf("the error offers an empty available list, which reads as a tree holding nothing "+
			"rather than one that could not be listed: %v", err)
	}
}

func mustRead(t *testing.T, id string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../catalogs", id+".json")) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read catalog %s: %v", id, err)
	}
	return data
}

func mustReadObligation(t *testing.T, id string) []byte {
	t.Helper()
	p := filepath.Join("../../catalogs/obligations", id+".json")
	data, err := os.ReadFile(p) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read obligation profile %s: %v", id, err)
	}
	return data
}
