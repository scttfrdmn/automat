// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package classprofile

import (
	"encoding/json"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/catalogs"
	"github.com/scttfrdmn/automat/internal/evidence"
)

// This file tests the two documents automat actually ships — the ones that make claims
// about published institutional policy. profile_test.go tests the model with fixtures;
// these tests are the ones that would catch a claim automat should not be making.

const classificationDir = "classification"

// loadShipped reads every vendored classification profile with FULL validation,
// including attestation-subject verification. Nothing here is skipped: a shipped
// document that only loads under a relaxed option is a shipped document that does not
// load.
func loadShipped(t *testing.T) map[string]*Profile {
	t.Helper()
	fsys := catalogs.FS()
	entries, err := fs.ReadDir(fsys, classificationDir)
	if err != nil {
		t.Fatalf("the embedded tree has no %s/ directory: %v", classificationDir, err)
	}
	out := map[string]*Profile{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := classificationDir + "/" + e.Name()
		p, err := LoadFS(fsys, path, LoadOptions{})
		if err != nil {
			t.Fatalf("%s does not load:\n%v", path, err)
		}
		out[e.Name()] = p
	}
	if len(out) == 0 {
		t.Fatal("no classification profiles are embedded; either the glob in catalogs/embed.go " +
			"stopped matching or the directory is empty, and both fail silently at run time")
	}
	return out
}

// TestTheShippedProfileSetIsTheOneThatWasApproved pins the file list.
//
// Two documents, named. A classification profile is a reading of somebody else's policy
// published under their name, so a third one arriving without review is the failure mode
// that matters more here than in any other catalog directory: the cost of being wrong is
// borne by an institution that never agreed to be represented.
func TestTheShippedProfileSetIsTheOneThatWasApproved(t *testing.T) {
	want := []string{
		"stanford-risk-classifications.json",
		"uc-protection-levels.json",
	}
	got := make([]string, 0, len(want))
	for name := range loadShipped(t) {
		got = append(got, name)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the shipped classification profiles are %v, approved set is %v.\n\n"+
			"Adding one is not a data change. Each of these states, under an institution's name, "+
			"what that institution requires; the review is the point, and this test is where it "+
			"is recorded as having happened.", got, want)
	}
}

// TestTheSampleSpansTheLevelCountsAndBothNamingDirections is gate 1 over the shipped set.
//
// The pairing is deliberate and it is the reason these two were chosen out of the
// six-institution sample: four ascending alphanumeric codes against three word names.
// Read together they break any code that assumes a level count, and any code that
// assumes a naming convention.
func TestTheSampleSpansTheLevelCountsAndBothNamingDirections(t *testing.T) {
	shipped := loadShipped(t)

	counts := map[int][]string{}
	for name, p := range shipped {
		counts[len(p.Levels)] = append(counts[len(p.Levels)], name)
	}
	if len(counts) < 2 {
		t.Errorf("every shipped profile has the same level count (%v); the pair exists to span "+
			"widths, and a same-width pair proves nothing a single document would not", counts)
	}

	// The UC scheme's ids are codes that sort correctly; Stanford's are words that do not.
	// Both facts are asserted, because it is the DISAGREEMENT that is load-bearing.
	uc := shipped["uc-protection-levels.json"]
	stanford := shipped["stanford-risk-classifications.json"]

	if got := uc.LevelIDs(); !sortedAscending(got) {
		t.Errorf("the UC profile's ids no longer sort into rank order (%v); it is the fixture "+
			"where id-sorting happens to work, which is what makes the other one instructive", got)
	}
	if got := stanford.LevelIDs(); sortedAscending(got) {
		t.Errorf("the Stanford profile's ids now sort into rank order (%v); with both documents "+
			"agreeing with alphabetical order, nothing shipped would catch code that sorted by id",
			got)
	}
	// Stated positively, since the previous check would also pass if the level list were
	// mangled: high must genuinely outrank low despite sorting before it.
	low, okLow := stanford.LevelByID("low")
	high, okHigh := stanford.LevelByID("high")
	if !okLow || !okHigh {
		t.Fatal(`the Stanford profile no longer has both "low" and "high"`)
	}
	if high.ID >= low.ID || high.Rank <= low.Rank {
		t.Errorf("the Stanford profile's high/low pair no longer inverts: %q rank %d vs %q rank %d",
			high.ID, high.Rank, low.ID, low.Rank)
	}
}

func sortedAscending(xs []string) bool {
	for i := 1; i < len(xs); i++ {
		if xs[i-1] > xs[i] {
			return false
		}
	}
	return true
}

// TestEveryShippedRankIsAnExplicitDenseRun is the half of gate 1 the documents carry.
func TestEveryShippedRankIsAnExplicitDenseRun(t *testing.T) {
	for name, p := range loadShipped(t) {
		t.Run(name, func(t *testing.T) {
			seen := map[int]bool{}
			for _, l := range p.Levels {
				if l.Rank < 1 {
					t.Errorf("level %q has rank %d; rank is an explicit integer because no naming "+
						"convention in the sample encodes order reliably", l.ID, l.Rank)
				}
				if seen[l.Rank] {
					t.Errorf("rank %d appears twice; two levels at one rank have no join",
						l.Rank)
				}
				seen[l.Rank] = true
			}
			for r := 1; r <= len(p.Levels); r++ {
				if !seen[r] {
					t.Errorf("rank %d is missing from a %d-level scheme; a gap renders as a "+
						"complete scheme with one level quietly absent", r, len(p.Levels))
				}
			}
		})
	}
}

// TestNoShippedProfileCarriesAMatcherOrTriggerExpression is gate 2.
//
// The forbidden list is artifact/obligation_profile_test.go's, and it is the same list
// for the same reason: an automated "your data is High Risk" is the worst output this
// tool could produce. Wrong in the permissive direction it tells an institution its data
// needs less protection than it does, and it would be believed, because it came from a
// tool that is right about everything else.
//
// Classification is a HUMAN determination by named roles, which every document in the
// sample says in its own words. So there is no matcher field to constrain — the check is
// that no field has started to become one. A match language arrives one plausible entry
// at a time: an examples list gains `*.dna`, a definition gains `if the dataset contains`,
// and neither commit looks like the one that built a classifier.
func TestNoShippedProfileCarriesAMatcherOrTriggerExpression(t *testing.T) {
	// Operators and sigils that only appear in something meant to be evaluated.
	// Deliberately not "and"/"or"/"if": those are ordinary English, and a policy
	// definition is written in ordinary English.
	forbidden := []string{"&&", "||", "==", "!=", ">=", "<=", "=~", "${", "{{", "regex:", "match:"}

	// Field names that would mean the model had grown an evaluable branch. Checked
	// against the raw JSON rather than the struct, because the struct is the thing that
	// would have changed.
	forbiddenKeys := []string{
		"matcher", "matchers", "match", "pattern", "patterns", "trigger", "triggers",
		"expression", "expr", "predicate", "condition", "conditions", "rule_expression",
		"when", "if", "selector", "selectors", "glob", "globs", "classify", "classifier",
		"auto_classify", "detect", "detection", "infer", "inference",
	}

	fsys := catalogs.FS()
	for name := range loadShipped(t) {
		t.Run(name, func(t *testing.T) {
			raw, err := fs.ReadFile(fsys, classificationDir+"/"+name)
			if err != nil {
				t.Fatal(err)
			}
			var doc any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			walkJSON(doc, "", func(path string, key string, value any) {
				for _, bad := range forbiddenKeys {
					if key == bad {
						t.Errorf("%s is a field named %q.\n\n"+
							"If a match language is taking shape here, stop and flag it. "+
							"Classification is a determination made by the named human roles in "+
							"determination.roles; a field that evaluates is a field that decides.",
							path, key)
					}
				}
				s, ok := value.(string)
				if !ok {
					return
				}
				for _, bad := range forbidden {
					if strings.Contains(s, bad) {
						t.Errorf("%s contains %q, which is predicate syntax: %q\n\n"+
							"If a match language is taking shape here, stop and flag it — having "+
							"no such field rather than a tempting one was the decision.",
							path, bad, s)
					}
				}
			})
		})
	}
}

// walkJSON visits every key and every scalar in a decoded JSON document, reporting a
// dotted path so a failure names the site rather than the value.
func walkJSON(v any, path string, visit func(path, key string, value any)) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			visit(child, k, t[k])
			walkJSON(t[k], child, visit)
		}
	case []any:
		for i, e := range t {
			child := path + "[" + itoa(i) + "]"
			visit(child, "", e)
			walkJSON(e, child, visit)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestNoShippedProfileClaimsAutomatDecides is gate 2's positive half.
func TestNoShippedProfileClaimsAutomatDecides(t *testing.T) {
	for name, p := range loadShipped(t) {
		t.Run(name, func(t *testing.T) {
			if p.Determination.AutomatDetermines {
				t.Error("automat_determines is true")
			}
			if len(p.Determination.Roles) == 0 {
				t.Error("no roles are named as the determiner; naming the human role is the " +
					"whole design, and an unnamed determiner is a gap something will fill")
			}
			if strings.TrimSpace(p.Determination.Process) == "" {
				t.Error("no determination process; an operator holding a level id needs to know " +
					"who to ask, not just that somebody decides")
			}
			for _, l := range p.Levels {
				for _, o := range l.ExternalObligations {
					if !o.DeclaredByOperator {
						t.Errorf("level %q names %q without declared_by_operator; a level "+
							"mentioning a regime is not that regime applying", l.ID, o.Name)
					}
					if o.Relation != RelationInformational {
						t.Errorf("level %q relates %q as %q; the relation is informational "+
							"because the institution's table naming a regime is not a "+
							"determination that the regime applies", l.ID, o.Name, o.Relation)
					}
				}
			}
		})
	}
}

// TestEveryShippedClaimTracesToACitedSection is gate 4 over the shipped documents.
//
// Not "the citations resolve" — Validate already refuses that. This checks the part a
// schema cannot: that a citation's section names something a reader could turn to. A
// section field reading "the policy" resolves fine and cites nothing.
func TestEveryShippedClaimTracesToACitedSection(t *testing.T) {
	for name, p := range loadShipped(t) {
		t.Run(name, func(t *testing.T) {
			sites := map[string]CitationRef{
				"determination.citation": p.Determination.Citation,
				"composition.citation":   p.Composition.Citation,
			}
			for i, l := range p.Levels {
				sites["levels["+itoa(i)+"]("+l.ID+").citation"] = l.Citation
				for j, c := range l.Controls {
					sites["levels["+itoa(i)+"]("+l.ID+").controls["+itoa(j)+"]("+c.ID+").citation"] = c.Citation
				}
				for j, o := range l.ExternalObligations {
					sites["levels["+itoa(i)+"]("+l.ID+").external_obligations["+itoa(j)+"]("+o.Name+").citation"] = o.Citation
				}
			}
			for path, ref := range sites {
				// A section that names no locator is a citation in form only. Every
				// document in the sample publishes numbered sections, named table rows,
				// or titled headings; something from that set has to appear.
				if !namesALocator(ref.Section) {
					t.Errorf("%s cites section %q, which names no locator a reader can turn to.\n\n"+
						"A citation that cannot be checked renders exactly as confidently as one "+
						"that can. Name the section number, the table and row, or the heading.",
						path, ref.Section)
				}
			}
		})
	}
}

// namesALocator is deliberately crude, and the crudeness is the point: it asks whether
// the section text points somewhere INSIDE the source rather than merely at it. The target
// is "the policy" and "see the standard", not citation grammar.
//
// It has to admit three shapes, because the two retrieved sources use all three. The UC
// PDF has numbered sections ("III.2.2"), so a digit is enough. Stanford's pages are
// tabbed HTML with no numbering at all, so its citations name a heading plus a locator
// within it ("Risk Classifications, High Risk definition") — which is why a comma
// followed by something counts, and why the structural vocabulary includes the words a
// dateless web page offers instead of section numbers.
//
// Erring permissive on purpose. A citation this rejects is one a reviewer must rewrite,
// and a check that demanded section numbers of a source that publishes none would push a
// transcriber toward inventing one, which is a worse failure than the one being prevented.
func namesALocator(section string) bool {
	s := strings.TrimSpace(section)
	if len(s) < 8 {
		return false
	}
	lower := strings.ToLower(s)
	// A generic gesture at the whole document, which is what this exists to catch.
	for _, generic := range []string{
		"the policy", "the standard", "see above", "see below", "throughout", "passim",
	} {
		if lower == generic || lower == "see "+generic {
			return false
		}
	}
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	for _, word := range []string{
		"table", "row", "column", "appendix", "heading", "footnote", "definition",
		"paragraph", "note", "item", "step", "tab", "entry", "list", "bullet", "figure",
	} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	// A heading plus a locator within it: the only shape available in a source that
	// numbers nothing.
	if i := strings.Index(s, ","); i > 0 && len(strings.TrimSpace(s[i+1:])) >= 4 {
		return true
	}
	return false
}

// TestWhereTheShippedSourceIsSilentTheShippedProfileIsSilent is gate 4's other half,
// asserted against the actual asymmetry between the two documents.
//
// This is the test that would catch the most tempting mistake available in this package:
// filling UC's empty control lists in from IS-3's control catalog, which automat has not
// retrieved. The UC Standard defines four Protection Levels and defers controls to
// BFB-IS-3; so the shipped UC profile states four levels and no controls, and the
// Stanford profile — whose Minimum Security Standards ARE the retrieved source — states
// controls at every level. The shapes differ because the sources differ.
func TestWhereTheShippedSourceIsSilentTheShippedProfileIsSilent(t *testing.T) {
	shipped := loadShipped(t)

	uc := shipped["uc-protection-levels.json"]
	for _, l := range uc.Levels {
		if len(l.Controls) != 0 {
			t.Errorf("the UC profile now states %d controls at level %q.\n\n"+
				"The retrieved source (the Protection Level Classification Guide) defines levels "+
				"and defers controls to BFB-IS-3, which automat has not retrieved. Controls here "+
				"would be automat's recollection of a document it did not read, published under "+
				"the University of California's name.", len(l.Controls), l.ID)
		}
	}

	stanford := shipped["stanford-risk-classifications.json"]
	total := 0
	for _, l := range stanford.Levels {
		if len(l.Controls) == 0 {
			t.Errorf("the Stanford profile states no controls at level %q, but its Minimum "+
				"Security Standards were retrieved and do state them; dropping them loses the "+
				"only shipped example of a level whose controls came from the source", l.ID)
		}
		total += len(l.Controls)
	}
	if total == 0 {
		t.Fatal("no shipped profile states any controls; the pair no longer demonstrates both " +
			"the silent case and the stated case")
	}

	// And controls must be monotone in count: a higher level requiring fewer controls
	// than a lower one would be either a transcription error or a policy automat has
	// misread, and both are worth failing over.
	for i := 1; i < len(stanford.Levels); i++ {
		lo, hi := stanford.Levels[i-1], stanford.Levels[i]
		if len(hi.Controls) < len(lo.Controls) {
			t.Errorf("level %q (rank %d) states %d controls but %q (rank %d) states %d; the "+
				"Standards are cumulative, so a decrease means a row was dropped in transcription",
				hi.ID, hi.Rank, len(hi.Controls), lo.ID, lo.Rank, len(lo.Controls))
		}
	}
}

// TestEveryShippedProfileIsMarkedAsAnExample is gate 5 over the shipped set.
func TestEveryShippedProfileIsMarkedAsAnExample(t *testing.T) {
	for name, p := range loadShipped(t) {
		t.Run(name, func(t *testing.T) {
			if p.Authorship != AuthorshipDerived {
				t.Errorf("authorship is %q; nothing automat ships was authored by the institution "+
					"it describes, and the day one is, it arrives from that institution rather "+
					"than in this directory", p.Authorship)
			}
			if p.Maintenance != MaintenanceExample {
				t.Errorf("maintenance is %q, not %q.\n\n"+
					"automat is not the upstream for anybody's data classification policy. These "+
					"are starting points an institution forks and corrects; a document marked "+
					"maintained implies a promise to track policy revisions that nobody made.",
					p.Maintenance, MaintenanceExample)
			}
			if p.Interpretation == nil {
				t.Fatal("no interpretation block")
			}
			if missing := MissingNonEndorsementSubstance(
				p.Interpretation.NonEndorsement); len(missing) > 0 {
				t.Errorf("the non-endorsement statement is missing %v", missing)
			}
			if !strings.Contains(
				strings.ToLower(p.Interpretation.NonEndorsement),
				strings.ToLower(p.Issuer.Name)) {
				t.Errorf("the non-endorsement statement does not name %q; a disclaimer that "+
					"names no institution will be attached to whichever one the reader had in "+
					"mind", p.Issuer.Name)
			}
			for i, s := range p.Signatures {
				if s.Role != evidence.RoleInterpretedBy {
					t.Errorf("signatures[%d] is %q; on a derived profile the only admissible "+
						"role is %q, because every other role in the vocabulary implies the "+
						"institution touched the document", i, s.Role, evidence.RoleInterpretedBy)
				}
			}
		})
	}
}

// TestTheShippedAttestationsAreAboutTheShippedContent is the check that makes an
// interpreted-by claim mean something.
//
// LoadFS already verifies this, so the assertion is really about the load options: it
// fails loudly if somebody makes SkipAttestationSubjects the default to get a stale
// document loading again.
func TestTheShippedAttestationsAreAboutTheShippedContent(t *testing.T) {
	for name, p := range loadShipped(t) {
		t.Run(name, func(t *testing.T) {
			if len(p.Signatures) == 0 {
				t.Fatal("no attestation; the reading is unsigned, so nothing records who read " +
					"the source or what they read")
			}
			hash, err := p.ContentHash()
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			for i, s := range p.Signatures {
				if s.ContentSHA256 != hash {
					t.Errorf("signatures[%d] attests to %s but the content hashes to %s; the "+
						"attestation is about a document that is not this one",
						i, s.ContentSHA256[:12], hash[:12])
				}
			}
			if err := p.VerifyAttestationSubjects(); err != nil {
				t.Errorf("VerifyAttestationSubjects:\n%v", err)
			}
		})
	}
}

// TestEveryShippedSourceIsHashedAndDated is the provenance floor.
func TestEveryShippedSourceIsHashedAndDated(t *testing.T) {
	for name, p := range loadShipped(t) {
		t.Run(name, func(t *testing.T) {
			if len(p.Sources) == 0 {
				t.Fatal("no sources; a derived profile with no source is an assertion")
			}
			for _, s := range p.Sources {
				if strings.Count(s.SHA256, "0") == 64 {
					t.Errorf("source %q carries an all-zero hash. A placeholder hash is worse "+
						"than none: it renders as provenance and verifies against nothing.", s.ID)
				}
				if s.RetrievedAt == "" {
					t.Errorf("source %q has no retrieval timestamp; institutional policy is "+
						"published as living web pages, and when it was read is part of what was "+
						"read", s.ID)
				}
			}
			// A retrieved-only citation must point at a source, since the retrieval time
			// is then the ONLY date anchoring the claim.
			for i, c := range p.Citations {
				if c.DateBasis == DateRetrievedOnly && c.SourceID == "" {
					t.Errorf("citations[%d] (%s) is retrieved-only with no source_id; with no "+
						"effective date and no retrieval record, nothing dates the claim",
						i, c.ID)
				}
			}
		})
	}
}

// TestTheShippedPolicyCaveatIsTheOneInTheDocs is the caveat check every document type
// carries.
func TestTheShippedPolicyCaveatIsTheOneInTheDocs(t *testing.T) {
	for name, p := range loadShipped(t) {
		t.Run(name, func(t *testing.T) {
			if missing := missingCaveatSubstance(p.PolicyCaveat); len(missing) > 0 {
				t.Errorf("the policy caveat is missing %v.\n\nChecked in substance rather than "+
					"verbatim so the wording can be improved, but not so it can be softened.",
					missing)
			}
		})
	}
}

// requiredCaveatSubstance is internal/artifact's list, restated rather than shared.
//
// Duplicated on purpose. Exporting it from one document package so another could import
// it would make the two lists one list, and the point of checking it per document type is
// that each type's caveat is independently verified — a change that softened the shared
// list would go green everywhere at once. If these two ever disagree, the disagreement is
// the finding.
var requiredCaveatSubstance = []string{
	"not legal advice",
	"not a compliance determination",
	"governs",
	"sponsored programs",
	"counsel",
	"records the operator's declaration",
	"verify against the primary source",
}

// missingCaveatSubstance reports which required phrases are absent, ignoring how the text
// is wrapped. Blockquote markers are stripped with the whitespace, because the paragraph
// also appears quoted in docs.
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

// TestNoShippedProfileNamesAVendorProduct is CLAUDE.md rule 3 over vendored data.
//
// Worth a test rather than a review pass because this is where the rule is hardest to
// hold: institutional security standards name tools constantly, and the honest
// transcription of "install [tool]" is "deploy host intrusion detection". The rule holds
// here for an additional reason of its own — the sources mark most named tools as
// recommended, so transcribing a tool as the requirement would misstate the policy in
// the stricter direction.
func TestNoShippedProfileNamesAVendorProduct(t *testing.T) {
	// Names that appeared in the retrieved sources' control tables, plus a few
	// adjacent ones. Not a general vendor list; it is the set this transcription had
	// the opportunity to get wrong.
	products := []string{
		"bigfix", "filevault", "bitlocker", "crowdstrike", "qualys", "duo", "splunk",
		"ossec", "tripwire", "jamf", "kerberos", "webauth", "crashplan", "nessus",
		"okta", "sentinelone", "carbon black", "tenable", "sccm", "intune",
	}
	fsys := catalogs.FS()
	for name := range loadShipped(t) {
		t.Run(name, func(t *testing.T) {
			raw, err := fs.ReadFile(fsys, classificationDir+"/"+name)
			if err != nil {
				t.Fatal(err)
			}
			lower := strings.ToLower(string(raw))
			for _, prod := range products {
				if strings.Contains(lower, prod) {
					t.Errorf("the document names %q. Transcribe the obligation rather than the "+
						"tool: the source lists most tools as recommended, so naming one as the "+
						"requirement overstates the policy as well as breaking rule 3.", prod)
				}
			}
		})
	}
}

// TestTheSchemaFileMatchesTheShippedDocuments is the drift check on the published
// contract, run against real documents rather than fixtures.
//
// The fixture-based conformance harness lives in schema_conformance_test.go. This one
// asserts the narrower thing: whatever automat ships must satisfy the schema automat
// publishes, because an institution forking one of these validates it against that file.
func TestTheSchemaFileMatchesTheShippedDocuments(t *testing.T) {
	schema := compileSchema(t)
	fsys := catalogs.FS()
	for name := range loadShipped(t) {
		t.Run(name, func(t *testing.T) {
			raw, err := fs.ReadFile(fsys, classificationDir+"/"+name)
			if err != nil {
				t.Fatal(err)
			}
			var doc any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Errorf("a shipped profile fails the published schema:\n%v\n\n"+
					"An institution forking this file validates it against that schema; a "+
					"document automat ships that the schema rejects tells them their fork is "+
					"broken when it is not.", err)
			}
		})
	}
}
