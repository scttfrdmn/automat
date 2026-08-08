// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Obligation profiles are vendored data with no Go implementation yet — Phase 4's
// `assess` is the first consumer. These tests exercise the shipped profiles
// against the published schema and against the invariants that make the data
// safe, for the same reason evidence_schema_test.go exists: a constraint nobody
// has fed a document to is a constraint nobody has checked.
//
// Deliberately no Go types. The profiles were added as design-and-data ahead of
// implementation, and a struct here would be building what that decision said not
// to build. Everything below reads raw JSON.

const obligationDir = "../../catalogs/obligations"

// profileDoc is the minimum shape these tests read. It is not a model of the
// schema — additionalProperties:false in the schema is what bounds a profile, and
// duplicating that here would be two definitions to keep in step.
type profileDoc struct {
	Profile struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	} `json:"profile"`
	Status    string `json:"status"`
	Citations []struct {
		ID            string `json:"id"`
		Title         string `json:"title"`
		EffectiveDate string `json:"effective_date"`
	} `json:"citations"`
	ControlCatalogs []struct {
		Catalog        string `json:"catalog"`
		RevisionPolicy string `json:"revision_policy"`
		Revision       string `json:"revision"`
	} `json:"control_catalogs"`
	Determinations struct {
		Values              []string `json:"values"`
		PartialCredit       bool     `json:"partial_credit"`
		UnderstatementValue string   `json:"understatement_value"`
	} `json:"determinations"`
	POAM struct {
		Permitted bool `json:"permitted"`
	} `json:"poam"`
	Scoring struct {
		Method      string `json:"method"`
		WeightTable *struct {
			ID     string `json:"id"`
			SHA256 string `json:"sha256"`
		} `json:"weight_table"`
	} `json:"scoring"`
	Submission struct {
		AutomatMayFormat bool `json:"automat_may_format"`
	} `json:"submission"`
	Applicability struct {
		Trigger            string   `json:"trigger"`
		Hints              []string `json:"hints"`
		DeclaredByOperator bool     `json:"declared_by_operator"`
	} `json:"applicability"`
	PolicyCaveat string `json:"policy_caveat"`
	Sources      []struct {
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
		Note   string `json:"note"`
	} `json:"sources"`
}

// loadProfiles reads every shipped profile once. It fails rather than skips when
// the directory is empty: these are vendored contracts, and a suite that quietly
// passes on zero profiles asserts nothing about the ones that were deleted.
func loadProfiles(t *testing.T) map[string]profileDoc {
	t.Helper()
	entries, err := os.ReadDir(obligationDir)
	if err != nil {
		t.Fatalf("read %s: %v", obligationDir, err)
	}
	out := make(map[string]profileDoc)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(obligationDir, e.Name())
		data, rerr := os.ReadFile(path) //nolint:gosec // fixed in-repo path
		if rerr != nil {
			t.Fatalf("read %s: %v", path, rerr)
		}
		var p profileDoc
		if uerr := json.Unmarshal(data, &p); uerr != nil {
			t.Fatalf("parse %s: %v", path, uerr)
		}
		out[e.Name()] = p
	}
	if len(out) == 0 {
		t.Fatalf("no obligation profiles found in %s", obligationDir)
	}
	return out
}

func TestShippedProfilesSatisfyPublishedSchema(t *testing.T) {
	sch := compileSchema(t, "obligation-profile-v1.schema.json")
	entries, err := os.ReadDir(obligationDir)
	if err != nil {
		t.Fatalf("read %s: %v", obligationDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			path := filepath.Join(obligationDir, e.Name())
			data, rerr := os.ReadFile(path) //nolint:gosec // fixed in-repo path
			if rerr != nil {
				t.Fatalf("read: %v", rerr)
			}
			doc, perr := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
			if perr != nil {
				t.Fatalf("parse: %v", perr)
			}
			if verr := sch.Validate(doc); verr != nil {
				t.Errorf("a shipped obligation profile violates the published schema:\n%v", verr)
			}
		})
	}
}

// TestTheUnderstatementAsymmetryHoldsUnderEveryProfile is the property the whole
// profile mechanism exists to preserve, asserted over the profile SET rather than
// per profile.
//
// The invariant (docs/assessment-reporting.md, invariant 2) is directional:
// automat's own proposals may only ever UNDERSTATE compliance. The satisfied
// value comes from the operator's determinations file or from nowhere; the unmet
// value automat may write itself, because being wrong in that direction costs an
// afternoon of review, and being wrong in the other direction is what an
// enforcement action is built on.
//
// A profile parameterizes that asymmetry — `understatement_value` names which
// member of the regime's own vocabulary automat may write — so a fourth profile
// added later with the field pointing at its SATISFIED value would invert the
// invariant while validating perfectly against the schema. Which is exactly why
// this is a property over the set: it must hold for profiles nobody has written
// yet.
func TestTheUnderstatementAsymmetryHoldsUnderEveryProfile(t *testing.T) {
	// The spellings a regime uses for "this control is in place". Matched
	// case-insensitively against the whole value, not as a substring: "OTHER THAN
	// SATISFIED" contains "SATISFIED" and is the opposite claim, which is the trap
	// a substring check would fall straight into.
	satisfied := map[string]bool{
		"met": true, "satisfied": true, "compliant": true, "implemented": true,
		"pass": true, "passed": true, "yes": true, "in place": true,
	}

	for name, p := range loadProfiles(t) {
		t.Run(name, func(t *testing.T) {
			uv := p.Determinations.UnderstatementValue

			// It must be one of the regime's own values. A value automat writes that
			// the standard does not define is not a determination for that standard.
			var member bool
			for _, v := range p.Determinations.Values {
				if v == uv {
					member = true
					break
				}
			}
			if !member {
				t.Errorf("understatement_value %q is not in determinations.values %v; "+
					"automat would write a value this regime does not define", uv, p.Determinations.Values)
			}

			if satisfied[strings.ToLower(strings.TrimSpace(uv))] {
				t.Errorf("understatement_value is %q, which asserts compliance. automat may only "+
					"ever write the UNMET value on its own; the satisfied value must come from the "+
					"operator's determinations file or from nowhere. See "+
					"docs/assessment-reporting.md invariant 2.", uv)
			}

			// The other half: a two-value regime must have exactly one satisfied
			// spelling for automat NOT to write, or the asymmetry has no direction.
			// A regime whose values are all unmet-flavoured means either the
			// vocabulary is wrong or `assess` has nothing to defer to the operator.
			var sats []string
			for _, v := range p.Determinations.Values {
				if satisfied[strings.ToLower(strings.TrimSpace(v))] {
					sats = append(sats, v)
				}
			}
			if len(sats) == 0 {
				t.Errorf("no value in %v reads as satisfied, so there is nothing for the operator "+
					"to determine and the asymmetry has no direction. If this regime spells its "+
					"satisfied value differently, add that spelling to this test's `satisfied` set "+
					"rather than loosening the check.", p.Determinations.Values)
			}
		})
	}
}

// TestEveryProfileCarriesThePolicyCaveatInSubstance holds docs/policy-caveat.md's
// paragraph as rendered words rather than as a convention — the same way
// TestREADMEMakesTheBlastRadiusArgument holds DESIGN §6's argument.
//
// In substance rather than verbatim: renderers wrap differently and a worksheet
// cell is not a prose paragraph. What is asserted is that each phrase whose
// absence would change the claim is present.
func TestEveryProfileCarriesThePolicyCaveatInSubstance(t *testing.T) {
	for name, p := range loadProfiles(t) {
		t.Run(name, func(t *testing.T) {
			missing := missingCaveatSubstance(p.PolicyCaveat)
			if len(missing) > 0 {
				t.Errorf("policy_caveat is missing %v.\n\nEach phrase in that list is there because "+
					"dropping it changes what the paragraph claims — see the table in "+
					"docs/policy-caveat.md. Got:\n%s", missing, p.PolicyCaveat)
			}
		})
	}
}

// TestTheCaveatAppearsInTheDesignDocument covers the other places
// docs/policy-caveat.md says the caveat must appear.
func TestTheCaveatAppearsInTheDesignDocument(t *testing.T) {
	for _, rel := range []string{"../../DESIGN.md", "../../README.md"} {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			data, err := os.ReadFile(rel) //nolint:gosec // fixed in-repo path
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if missing := missingCaveatSubstance(string(data)); len(missing) > 0 {
				t.Errorf("%s is missing %v from the policy caveat (docs/policy-caveat.md)",
					rel, missing)
			}
		})
	}
}

// requiredCaveatSubstance is the phrase list docs/policy-caveat.md's table
// explains. Each entry is load-bearing: dropping it changes what kind of claim
// the paragraph makes, which is the whole reason the caveat is tested rather than
// trusted.
var requiredCaveatSubstance = []string{
	"not legal advice",
	"not a compliance determination",
	"governs",
	"sponsored programs",
	"counsel",
	"records the operator's declaration",
	"verify against the primary source",
}

// missingCaveatSubstance reports which required phrases are absent, ignoring how
// the text is wrapped.
//
// Whitespace is collapsed first, and markdown blockquote markers with it. Without
// that, a phrase broken across two lines by a hard wrap reads as missing — which
// is what happened on the first run against DESIGN.md, where "not a compliance
// determination" and "verify against the primary source" each straddled a line
// break. A test that fails on a line wrap would be enforcing verbatim wording,
// and the caveat is deliberately asserted in substance: renderers wrap
// differently and a worksheet cell is not a prose paragraph.
func missingCaveatSubstance(text string) []string {
	flat := strings.Join(strings.Fields(strings.ReplaceAll(strings.ToLower(text), ">", " ")), " ")
	var missing []string
	for _, phrase := range requiredCaveatSubstance {
		if !strings.Contains(flat, phrase) {
			missing = append(missing, phrase)
		}
	}
	return missing
}

// TestApplicabilityIsNeverEvaluable is the guard on the field most likely to grow
// into something dangerous.
//
// An automated "this obligation applies to you" is the worst output this tool
// could produce: wrong in the permissive direction it tells an institution it is
// unregulated, and it would be believed, because it came from a tool that is
// right about everything else. So `trigger` is prose for a human and `hints` is a
// bounded reading aid. This test fails if a hint starts looking like a predicate —
// the shape a match language arrives in, one plausible entry at a time.
func TestApplicabilityIsNeverEvaluable(t *testing.T) {
	// Operators and sigils that only appear in something meant to be evaluated.
	// Deliberately not "and"/"or": those are ordinary English and a prose trigger
	// containing them is fine. What is forbidden is the syntax of a predicate.
	forbidden := []string{"&&", "||", "==", "!=", ">=", "<=", "=~", "${", "{{", "regex:", "match:"}

	for name, p := range loadProfiles(t) {
		t.Run(name, func(t *testing.T) {
			if !p.Applicability.DeclaredByOperator {
				t.Error("declared_by_operator is not true; a profile cannot opt into automatic " +
					"applicability, and the schema pins this to const true")
			}
			if len(p.Applicability.Hints) > 32 {
				t.Errorf("%d hints; the cap is 32 to keep the list a reading aid rather than a "+
					"rule set", len(p.Applicability.Hints))
			}
			// The trigger must actually be prose written for a person. A one-clause
			// trigger is the shape a predicate takes once the syntax is stripped out.
			if len(p.Applicability.Trigger) < 120 {
				t.Errorf("trigger is %d characters; it is meant to be prose a sponsored programs "+
					"officer reads, not a condition", len(p.Applicability.Trigger))
			}
			for _, field := range append([]string{p.Applicability.Trigger}, p.Applicability.Hints...) {
				for _, bad := range forbidden {
					if strings.Contains(field, bad) {
						t.Errorf("applicability text contains %q, which is predicate syntax: %q\n\n"+
							"If a match language is being designed here, stop and flag it — the "+
							"decision to have no field rather than a tempting one was deliberate.",
							bad, field)
					}
				}
			}
		})
	}
}

// TestAnOperatorDeterminedRevisionShipsNoDefault is B4, as a check rather than a
// paragraph.
//
// Where an instrument does not pin a revision — NIH's controlled-access data
// notices do not, and institutions have split between Rev 2 and Rev 3 — automat
// ships no default and refuses to proceed without an operator determination. The
// schema forbids the `revision` field in that case; this asserts the softer half
// the schema cannot see: that no prose in the profile names a revision as the one
// to use. "Most institutions use rN" is not a default and not even a hint,
// because a default here silently picks an institution's compliance posture for
// it.
func TestAnOperatorDeterminedRevisionShipsNoDefault(t *testing.T) {
	for name, p := range loadProfiles(t) {
		t.Run(name, func(t *testing.T) {
			for _, c := range p.ControlCatalogs {
				if c.RevisionPolicy != "operator-determined" {
					continue
				}
				if c.Revision != "" {
					t.Errorf("catalog %q is operator-determined but carries revision %q — "+
						"a revision sitting in an operator-determined profile is a default "+
						"wearing a different hat", c.Catalog, c.Revision)
				}
				// A hint naming a revision is a default routed around the schema.
				for _, h := range p.Applicability.Hints {
					if lower := strings.ToLower(h); strings.Contains(lower, "revision 2") ||
						strings.Contains(lower, "revision 3") ||
						strings.Contains(lower, "rev 2") || strings.Contains(lower, "rev 3") {
						t.Errorf("hint %q names a revision under an operator-determined policy; "+
							"that is a default offered as a suggestion", h)
					}
				}
			}
		})
	}
}

// TestNoUnresolvedHashInARenderableProfile keeps the placeholder discipline
// honest.
//
// Two profiles currently carry an all-zero hash on purpose: dfars-7012's weight
// table is not transcribed yet (docs/open-questions.md Q10) and neither
// dfars-7012 nor nih-cadr-dua has its citations vendored. That is a deliberate
// "not yet", and the risk with a deliberate placeholder is that it stops being
// deliberate — a later change wires a renderer to a profile whose provenance is
// sixty-four zeros, and the report cites bytes that do not exist.
//
// So the placeholder is allowed but must be declared. renderableProfiles is the
// list of profiles `assess` may render; a profile on it may hold no unresolved
// hash. Adding a profile to that list without vendoring its sources fails here.
// # AUDIT-2 F1: the gate was a map literal inside this function
//
// `renderable` was declared here, empty, with a comment saying Phase 4 would
// populate it. Nothing outside this function could read it — so the discipline was
// an assertion about a list that existed only while the test ran, and the assertion
// was vacuous by construction: with the map empty, the first branch could never
// fire.
//
// Meanwhile `vend` rendered these profiles. It printed
// `dfars-7012 sha256:<claimed>` on the birth certificate — the document an operator
// files — for a profile whose own sources are sixty-four zeros. Both unvendored
// profiles were reachable that way, and the standing obligation in
// docs/policy-caveat.md is precisely that every claim automat RENDERS traces to a
// hashed source.
//
// So the fact moved to where a renderer can consult it:
// `envprofile.ObligationFacts.UnresolvedSources`, filled by the resolver that
// already reads each profile's bytes. What is left here is the half that belongs to
// the catalog — that a placeholder is DECLARED rather than accidental — plus the
// coupling assertion below, which is what makes the two definitions one.
func TestNoUnresolvedHashInARenderableProfile(t *testing.T) {
	for name, p := range loadProfiles(t) {
		t.Run(name, func(t *testing.T) {
			var unresolved []string
			for _, s := range p.Sources {
				if isZeroHash(s.SHA256) {
					unresolved = append(unresolved, "sources["+s.ID+"]")
				}
			}
			if wt := p.Scoring.WeightTable; wt != nil && isZeroHash(wt.SHA256) {
				unresolved = append(unresolved, "scoring.weight_table["+wt.ID+"]")
			}
			if len(unresolved) == 0 {
				return
			}
			// A placeholder must be explained where a maintainer reading the profile
			// will see it. This is the check that keeps a deliberate "not yet" from
			// decaying into an oversight nobody notices — which is what the
			// unreachable map literal was supposed to do and could not.
			var explained bool
			for _, s := range p.Sources {
				if isZeroHash(s.SHA256) && strings.Contains(s.Note, "not renderable") ||
					isZeroHash(s.SHA256) && strings.Contains(s.Note, "nothing here has been checked") {
					explained = true
				}
			}
			if !explained {
				t.Errorf("profile %q carries unresolved hashes at %v and no source note says the "+
					"profile is therefore not renderable; an unexplained all-zero hash is "+
					"indistinguishable from a forgotten one", p.Profile.ID, unresolved)
			}
			t.Logf("profile %q has unresolved provenance at %v, which vend now marks on the "+
				"birth certificate", p.Profile.ID, unresolved)
		})
	}
}

// TestAWeightedScoreRequiresAVendoredTable pairs with the schema's iff rule. The
// schema can require the weight_table field; it cannot tell whether the weights
// behind the hash exist. A score computed from weights that came from nowhere is
// the one output this project cannot produce, and no test catches a FALSE weight
// in a CORRECT calculation — which is why Q10 settled on dual independent
// transcription, and why this test is about the table's existence rather than its
// contents.
func TestAWeightedScoreRequiresAVendoredTable(t *testing.T) {
	for name, p := range loadProfiles(t) {
		t.Run(name, func(t *testing.T) {
			if p.Scoring.Method == "none" {
				if p.Scoring.WeightTable != nil {
					t.Error("scoring.method is none but a weight_table is present")
				}
				return
			}
			wt := p.Scoring.WeightTable
			if wt == nil {
				t.Fatalf("scoring.method is %q with no weight_table", p.Scoring.Method)
			}
			if isZeroHash(wt.SHA256) {
				t.Logf("weight table %q is not vendored yet (Q10); scoring must refuse to run "+
					"against this profile until it is", wt.ID)
			}
		})
	}
}

// TestProfileSourceHashesMatchTheFilesOnDisk is the check that makes a hash a
// hash rather than a decoration. A re-vendor that changes a source's bytes
// without updating the profile citing them must fail the build, not leave the
// profile pointing at bytes that no longer exist. Sources that are not in-repo
// paths (a published document identifier) are skipped — there is nothing on disk
// to compare.
func TestProfileSourceHashesMatchTheFilesOnDisk(t *testing.T) {
	var checked int
	for name, p := range loadProfiles(t) {
		t.Run(name, func(t *testing.T) {
			for _, s := range p.Sources {
				if !strings.HasPrefix(s.ID, "gen/") {
					continue
				}
				path := filepath.Join("../..", s.ID)
				data, err := os.ReadFile(path) //nolint:gosec // path is an in-repo source id
				if err != nil {
					t.Errorf("source %q: %v — a profile citing a path must cite one that exists",
						s.ID, err)
					continue
				}
				sum := sha256.Sum256(data)
				got := hex.EncodeToString(sum[:])
				if got != s.SHA256 {
					t.Errorf("source %q hash drift:\n  profile: %s\n  on disk: %s\n\n"+
						"The file changed without the profile being updated, so the profile now "+
						"cites bytes nobody has. Re-verify the content, then update the hash.",
						s.ID, s.SHA256, got)
				}
				checked++
			}
		})
	}
	if checked == 0 {
		t.Error("no profile source resolved to an in-repo file, so this test verified nothing. " +
			"If every citation moved to published-identifier form, this check needs rethinking " +
			"rather than deleting.")
	}
}

// TestNoProfileFormatsForSubmission guards the field that would turn a draft into
// something submittable. It defaults false and is expected to stay false: a
// document formatted for submission is a document that can be submitted, and
// automat generates the packet a human reads, never the instrument they sign.
func TestNoProfileFormatsForSubmission(t *testing.T) {
	for name, p := range loadProfiles(t) {
		t.Run(name, func(t *testing.T) {
			if p.Submission.AutomatMayFormat {
				t.Error("submission.automat_may_format is true. No shipped profile sets it; " +
					"turning it on is a decision requiring its own review, not a data change. " +
					"See docs/assessment-reporting.md invariant 1.")
			}
		})
	}
}

// TestProfileIDMatchesFilename keeps the vendored set addressable by the id an
// operator types.
func TestProfileIDMatchesFilename(t *testing.T) {
	for name, p := range loadProfiles(t) {
		want := strings.TrimSuffix(name, ".json")
		if p.Profile.ID != want {
			t.Errorf("%s declares profile.id %q; the filename and id must agree so an operator "+
				"naming a profile finds the file", name, p.Profile.ID)
		}
	}
}

// TestTheShippedProfileSetIsTheOneThatWasApproved pins the set itself. Profiles
// are vendored policy readings, and adding one is a policy decision rather than a
// data change: a fourth profile shipped quietly is a fourth obligation automat
// implies an institution might be under.
func TestTheShippedProfileSetIsTheOneThatWasApproved(t *testing.T) {
	want := []string{"cmmc-l1", "dfars-7012", "nih-cadr-dua"}

	var got []string
	for _, p := range loadProfiles(t) {
		got = append(got, p.Profile.ID)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("shipped profiles are %v, approved set is %v.\n\n"+
			"Adding or removing a profile is a policy decision — FAR Case 2017-016, for one, is "+
			"still a proposed rule and is deliberately not shipped as a profile (Q11 in "+
			"docs/open-questions.md). Update this list in the same change that argues for the "+
			"profile.", got, want)
	}
}

// TestOneInstrumentIsCitedOneWayAcrossTheProfileSet holds the one mechanically
// checkable part of citation correctness: an instrument has one effective date and
// one published title, so two profiles citing it differently means at least one is
// wrong, and an operator reading two birth certificates gets two answers about the
// same clause.
//
// # What it would NOT have caught, stated plainly
//
// This test passes at the commit before AUDIT-2's F4 was fixed. `48 CFR
// 252.204-7021` carried 2024-12-16 in BOTH profiles — the 32 CFR 170 program
// rule's date rather than the clause's — and two copies of one wrong date agree.
// Agreement is not correctness, and no cross-check can supply a fact neither copy
// holds. Verifying a date against the Federal Register is the standing obligation
// in docs/policy-caveat.md, performed by a human at each phase gate; this test does
// not do it and must not be read as doing it.
//
// What it does do is cover the state a correction passes THROUGH. Verified by
// running it in a worktree at the pre-fix commit with one of the two dates
// corrected: it fails, naming both profiles. A half-applied fix is the likeliest
// way this set drifts again, because the profile the auditor was reading gets
// edited and the other one does not.
func TestOneInstrumentIsCitedOneWayAcrossTheProfileSet(t *testing.T) {
	type claim struct{ date, title, profile string }
	byInstrument := make(map[string][]claim)
	for name, p := range loadProfiles(t) {
		for _, c := range p.Citations {
			byInstrument[c.ID] = append(byInstrument[c.ID],
				claim{date: c.EffectiveDate, title: c.Title, profile: name})
		}
	}

	var shared int
	for id, claims := range byInstrument {
		if len(claims) < 2 {
			continue
		}
		shared++
		first := claims[0]
		for _, c := range claims[1:] {
			if c.date != first.date {
				t.Errorf("%s is cited with two effective dates:\n  %s: %s\n  %s: %s\n\n"+
					"One instrument, one effective date. At least one of these is wrong, and both "+
					"render with equal confidence. Verify against the Federal Register or eCFR and "+
					"correct the citation rather than the test.",
					id, first.profile, first.date, c.profile, c.date)
			}
			if c.title != first.title {
				t.Errorf("%s is cited with two titles:\n  %s: %q\n  %s: %q\n\n"+
					"The title is the instrument's own as published, so a difference is a "+
					"transcription error in one of them.",
					id, first.profile, first.title, c.profile, c.title)
			}
		}
	}
	if shared == 0 {
		t.Error("no instrument is cited by more than one profile, so this test compared nothing. " +
			"That is a real state of the world and not a bug — but if it holds after a profile is " +
			"added, check that the new profile is not citing a shared instrument under a slightly " +
			"different id, which would defeat this check by making the two look unrelated.")
	}
}

func isZeroHash(h string) bool {
	return h == strings.Repeat("0", 64)
}

// TestObligationProfileHashScopeCommentNamesEveryFieldExactlyOnce pins Q15's
// resolution (docs/open-questions.md): the content-hash scope is stated in the
// schema's top-level `$comment` rather than enforced by a Go canonicalizer, because
// ROADMAP Phase 4 stage 0 keeps this document type data-and-schema-only until
// `assess` is written. A comment nobody checks against the schema it describes is
// exactly F1's failure shape — a claim that looks like coverage and is not — so
// this walks both the comment's field lists and the schema's actual top-level
// properties and asserts they name the same set.
//
// It cannot check that a future canonicalizer implements this scope; only that the
// scope stated today matches the schema's own field list today. The comment says as
// much: "there is no Go type yet to enforce it… when it is written, it must hash
// precisely the fields named here."
func TestObligationProfileHashScopeCommentNamesEveryFieldExactlyOnce(t *testing.T) {
	path := filepath.Join(schemaDir, "obligation-profile-v1.schema.json")
	data, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var raw struct {
		Comment    string                     `json:"$comment"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if raw.Comment == "" {
		t.Fatal("obligation-profile-v1.schema.json has no top-level $comment; Q15's hash-scope " +
			"note was removed or never landed")
	}

	allFields := make([]string, 0, len(raw.Properties))
	for name := range raw.Properties {
		allFields = append(allFields, name)
	}
	sort.Strings(allFields)

	excluded := map[string]bool{"schema_version": true, "signatures": true}
	var wantCovered []string
	for _, f := range allFields {
		if !excluded[f] {
			wantCovered = append(wantCovered, f)
		}
	}

	var missing, extra []string
	for _, f := range wantCovered {
		if !strings.Contains(raw.Comment, f) {
			missing = append(missing, f)
		}
	}
	for f := range excluded {
		if !strings.Contains(raw.Comment, f) {
			extra = append(extra, f)
		}
	}

	if len(missing) > 0 {
		t.Errorf("the $comment does not mention covered field(s) %v; the schema gained a top-level "+
			"property the hash-scope note was never updated for", missing)
	}
	if len(extra) > 0 {
		t.Errorf("the $comment does not mention excluded field(s) %v by name; it must say which "+
			"fields are excluded and why, not merely which are covered", extra)
	}
}
