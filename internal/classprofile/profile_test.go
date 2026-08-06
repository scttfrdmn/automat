// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package classprofile

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/evidence"
)

// The fixtures below are HAND-WRITTEN test data, not readings of anybody's published
// policy. They carry a fake source hash and a citation that names no real section,
// because their job is to exercise the model's shape — level count, naming direction,
// inheritance — rather than to state what an institution requires. The two documents
// that DO make claims about published policy are the vendored ones under
// catalogs/classification/, and they are tested separately (catalog_test.go).
//
// umichFixture and harvardFixture exist for one reason ROADMAP states directly: U-M and
// Harvard sort OPPOSITE by name. Both are here so that a change which orders levels by
// label breaks rather than passing on four schemes out of six.

func sampleProfile(t *testing.T) *Profile {
	t.Helper()
	return &Profile{
		SchemaVersion: SchemaVersion,
		Meta: Meta{
			ID:          "example-levels",
			Title:       "Example Institution Data Levels",
			Description: "A fixture, not a reading of anybody's policy.",
		},
		Issuer:      Issuer{ID: "example-institution", Name: "Example Institution"},
		Status:      StatusInForce,
		ReviewBy:    "2027-01-01",
		Authorship:  AuthorshipDerived,
		Maintenance: MaintenanceExample,
		Interpretation: &Interpretation{
			Interpreter: "automat maintainers",
			SourceID:    "example-policy",
			Attribution: "Example Institution Data Classification Policy, quoted for testing.",
			NonEndorsement: "This is automat's interpretation of a published policy. It was not " +
				"authored, reviewed, or endorsed by Example Institution. The institution's own " +
				"policy governs; verify against it.",
		},
		Determination: Determination{
			Roles:             []string{"Data Stewards", "Unit Security Leads"},
			Process:           "Ask the data steward for the collection in question.",
			AutomatDetermines: false,
			Citation:          CitationRef{SourceID: "example-policy", Section: "Section 2 (page 1)"},
			MayRaise:          PermissionYes,
			MayLower: &MayLower{
				Permitted:        LowerOnlyByException,
				ExceptionProcess: "Policy 1.1, Exceptions",
				Citation:         &CitationRef{SourceID: "example-policy", Section: "Section 2.1"},
			},
		},
		Levels: []Level{
			{
				ID: "public", Label: "Public", Rank: 1,
				Definition: "Intended for public disclosure.",
				Citation:   CitationRef{SourceID: "example-policy", Section: "Section 3, Public row"},
				Examples:   []string{"Press releases"},
			},
			{
				ID: "internal", Label: "Internal", Rank: 2,
				Definition: "Not intended for public release.",
				Citation:   CitationRef{SourceID: "example-policy", Section: "Section 3, Internal row"},
				Controls: []Control{
					{
						ID: "access-review", Title: "Access review",
						Requirement: "Review accounts and privileges quarterly.",
						Citation: CitationRef{
							SourceID: "example-policy",
							Section:  "Section 4, Access review row, Internal column",
						},
						AppliesTo:       "servers",
						AutomatEnforces: EnforcesNo,
					},
				},
			},
			{
				ID: "regulated", Label: "Regulated", Rank: 3,
				Definition: "Protection required by law or regulation.",
				Citation:   CitationRef{SourceID: "example-policy", Section: "Section 3, Regulated row"},
				Controls: []Control{
					{
						ID: "encryption", Title: "Encryption at rest",
						Requirement: "Encrypt stored data.",
						Citation: CitationRef{
							SourceID: "example-policy",
							Section:  "Section 4, Encryption row, Regulated column",
						},
						AutomatEnforces: EnforcesPartially,
					},
				},
				ExternalObligations: []ExternalObligation{
					{
						Name:               "HIPAA",
						Relation:           RelationInformational,
						DeclaredByOperator: true,
						Citation: CitationRef{
							SourceID: "example-policy",
							Section:  "Section 4, Regulated data row",
						},
					},
				},
			},
		},
		Composition: Composition{
			Rule:      RuleHighestWaterMark,
			Statement: "A collection takes the highest level of anything it contains.",
			Citation:  CitationRef{SourceID: "example-policy", Section: "Section 3.1"},
			OverClassification: &OverClassification{
				Permitted:             true,
				DocumentationRequired: true,
				Citation:              &CitationRef{SourceID: "example-policy", Section: "Section 3.2"},
			},
		},
		UnmodeledAxes: []UnmodeledAxis{
			{
				Name:      "Availability",
				Statement: "The policy defines a separate availability axis; this profile omits it.",
				Citation:  CitationRef{SourceID: "example-policy", Section: "Section 3.3"},
			},
		},
		Citations: []Citation{
			{
				ID: "POLICY-1", Title: "Example Institution Data Classification Policy",
				DateBasis: DateEffective, EffectiveDate: "2024-06-01",
				SourceID: "example-policy", Role: CiteDefinesLevels,
			},
		},
		PolicyCaveat: samplePolicyCaveat,
		Sources: []HashedReference{
			{
				ID: "example-policy", Title: "Example Institution Data Classification Policy",
				Version: "1.0", RetrievedAt: "2026-08-06T18:00:00Z",
				MediaType: "application/pdf", SHA256: strings.Repeat("a", 64),
			},
		},
	}
}

// samplePolicyCaveat is docs/policy-caveat.md's paragraph. Held here verbatim so the
// fixture passes the substance check the real profiles are held to; the shipped
// documents' copies are the ones a reader sees.
const samplePolicyCaveat = "automat encodes a technical reading of published policy. It is not " +
	"legal advice and not a compliance determination. The agreement, award terms, or contract " +
	"clause your institution signed governs; your sponsored programs office, contracts office, " +
	"or counsel decides what applies and which revision. Where policy is ambiguous — for " +
	"example the NIH 800-171 revision question — automat records the operator's declaration " +
	"rather than resolving it. Policy citations carry effective dates and change; verify " +
	"against the primary source before relying on them."

// fixtureLevels builds a level list from (id, label, rank) triples with the boilerplate
// every level needs, so a fixture reads as the scheme it is testing.
func fixtureLevels(sourceID string, triples ...[3]string) []Level {
	out := make([]Level, 0, len(triples))
	for i, tr := range triples {
		rank := 0
		for _, c := range tr[2] {
			rank = rank*10 + int(c-'0')
		}
		out = append(out, Level{
			ID:         tr[0],
			Label:      tr[1],
			Rank:       rank,
			Definition: "Fixture level " + tr[1] + "; not a reading of published policy.",
			Citation: CitationRef{
				SourceID: sourceID,
				Section:  "Fixture section " + string(rune('A'+i)),
			},
		})
	}
	return out
}

// fixtureBase returns a minimal valid profile for an issuer, ready for levels.
func fixtureBase(id, issuerID, issuerName, sourceID string) *Profile {
	return &Profile{
		SchemaVersion: SchemaVersion,
		Meta:          Meta{ID: id, Title: issuerName + " fixture scheme"},
		Issuer:        Issuer{ID: issuerID, Name: issuerName},
		Status:        StatusInForce,
		ReviewBy:      "2027-01-01",
		Authorship:    AuthorshipDerived,
		Maintenance:   MaintenanceExample,
		Interpretation: &Interpretation{
			Interpreter: "automat maintainers",
			SourceID:    sourceID,
			Attribution: "Fixture; no document was read.",
			NonEndorsement: "This is automat's interpretation of a published policy. It was not " +
				"authored, reviewed, or endorsed by " + issuerName + ". The institution's own " +
				"policy governs; verify against it.",
		},
		Determination: Determination{
			Roles:    []string{"Data Stewards"},
			Process:  "Ask the data steward.",
			Citation: CitationRef{SourceID: sourceID, Section: "Fixture roles section"},
		},
		Composition: Composition{
			Rule:      RuleHighestWaterMark,
			Statement: "A collection takes the highest level of anything it contains.",
			Citation:  CitationRef{SourceID: sourceID, Section: "Fixture composition section"},
		},
		Citations: []Citation{{
			ID: "FIXTURE-1", Title: issuerName + " fixture policy",
			DateBasis: DateEffective, EffectiveDate: "2024-01-01", SourceID: sourceID,
		}},
		PolicyCaveat: samplePolicyCaveat,
		Sources: []HashedReference{{
			ID: sourceID, Title: issuerName + " fixture policy",
			RetrievedAt: "2026-08-06T18:00:00Z", SHA256: strings.Repeat("b", 64),
		}},
	}
}

// umichFixture is a FOUR-level scheme whose labels run DOWNWARD: Restricted is the top.
//
// Modeled on the shape ROADMAP records for U-M — Restricted / High / Moderate / Low —
// and present for exactly that reason. Sorted by label ascending, this scheme's order is
// High, Low, Moderate, Restricted: the second-most-protective level sorts to the bottom
// of the list and the least protective sorts one above it. Nothing about that ordering
// looks wrong from inside the sorted list — "High, Low, Moderate, Restricted" reads as
// four plausible level names in four plausible positions.
func umichFixture() *Profile {
	p := fixtureBase("fixture-names-descending", "fixture-a", "Fixture University A", "fixture-a-policy")
	p.Levels = fixtureLevels("fixture-a-policy",
		[3]string{"low", "Low", "1"},
		[3]string{"moderate", "Moderate", "2"},
		[3]string{"high", "High", "3"},
		[3]string{"restricted", "Restricted", "4"},
	)
	return p
}

// harvardFixture is a FIVE-level scheme whose labels run UPWARD: DSL 5 is the top.
//
// The counterpart to umichFixture. Sorted by label ascending, this scheme's order is
// exactly its rank order — which is what makes label-sorting look correct to anyone who
// tests one scheme. Also carries an inherits block, because the two-layered-policy case
// (an enterprise policy plus a research overlay sharing one classification table) is what
// that field exists for.
func harvardFixture() *Profile {
	p := fixtureBase("fixture-names-ascending", "fixture-b", "Fixture University B", "fixture-b-policy")
	p.Levels = fixtureLevels("fixture-b-policy",
		[3]string{"dsl1", "DSL 1", "1"},
		[3]string{"dsl2", "DSL 2", "2"},
		[3]string{"dsl3", "DSL 3", "3"},
		[3]string{"dsl4", "DSL 4", "4"},
		[3]string{"dsl5", "DSL 5", "5"},
	)
	p.Inherits = &Inherits{
		ProfileID: "fixture-names-ascending-research-overlay",
		IssuerID:  "fixture-b",
		Relation:  InheritsOverlays,
		Note:      "A research overlay sharing this profile's classification table.",
	}
	return p
}

// threeLevelFixture is the minimum realistic scheme: Low / Moderate / High.
func threeLevelFixture() *Profile {
	p := fixtureBase("fixture-three-levels", "fixture-c", "Fixture University C", "fixture-c-policy")
	p.Levels = fixtureLevels("fixture-c-policy",
		[3]string{"low", "Low", "1"},
		[3]string{"moderate", "Moderate", "2"},
		[3]string{"high", "High", "3"},
	)
	return p
}

func mustValidate(t *testing.T, p *Profile, what string) {
	t.Helper()
	if err := p.Validate(); err != nil {
		t.Fatalf("%s should be valid:\n%v", what, err)
	}
}

// ---------------------------------------------------------------------------
// GATE 1: level count varies, rank is explicit, and label order is never the order.
// ---------------------------------------------------------------------------

// TestLevelCountVariesAcrossTheSample is the "never assume four" check.
//
// Not a stylistic point. The published schemes run three (Stanford, MIT), four (UC, U-M),
// and five (Harvard, Georgia Tech), so any code that indexed a fixed number of levels or
// mapped a scheme onto a four-value enum would be correct on a third of the sample.
func TestLevelCountVariesAcrossTheSample(t *testing.T) {
	counts := map[int]string{}
	for _, f := range []struct {
		name string
		p    *Profile
	}{
		{"three-level scheme", threeLevelFixture()},
		{"four-level scheme with descending labels", umichFixture()},
		{"five-level scheme with ascending labels", harvardFixture()},
	} {
		mustValidate(t, f.p, f.name)
		if prev, dup := counts[len(f.p.Levels)]; dup {
			t.Errorf("%s and %s have the same level count; the fixture set no longer spans 3/4/5",
				f.name, prev)
		}
		counts[len(f.p.Levels)] = f.name
	}
	for _, want := range []int{3, 4, 5} {
		if _, ok := counts[want]; !ok {
			t.Errorf("no fixture has %d levels — the published schemes run 3, 4, and 5, and a model "+
				"exercised on only one of those widths is a model that assumes a width", want)
		}
	}
}

// TestLabelOrderIsNotRankOrder is the reason rank is a required field.
//
// The assertion is about the FIXTURES, not about the code: it proves the two schemes
// really do disagree with label-sorting in opposite directions, so that the tests below
// which rely on them are testing something. If this ever passes trivially, the fixtures
// stopped covering the case.
func TestLabelOrderIsNotRankOrder(t *testing.T) {
	byLabel := func(p *Profile) []string {
		out := make([]string, 0, len(p.Levels))
		for _, l := range p.Levels {
			out = append(out, l.ID)
		}
		sort.Slice(out, func(i, j int) bool {
			li, _ := p.LevelByID(out[i])
			lj, _ := p.LevelByID(out[j])
			return li.Label < lj.Label
		})
		return out
	}

	desc := umichFixture()
	if got, want := byLabel(desc), desc.LevelIDs(); reflect.DeepEqual(got, want) {
		t.Errorf("the descending-label fixture sorts the same by label as by rank (%v); it no "+
			"longer covers the case it exists for", got)
	} else {
		t.Logf("descending-label scheme: by rank %v, by label %v — sorting by label moves the "+
			"second-most-protective level from position %d to position %d of %d",
			want, got, indexOf(want, "high")+1, indexOf(got, "high")+1, len(got))
	}

	asc := harvardFixture()
	if got, want := byLabel(asc), asc.LevelIDs(); !reflect.DeepEqual(got, want) {
		t.Errorf("the ascending-label fixture no longer sorts the same by label as by rank: "+
			"by rank %v, by label %v. The pair only demonstrates the hazard if one scheme agrees "+
			"with label-sorting and the other does not — that is what makes label-sorting look "+
			"correct until it silently is not", want, got)
	}
}

func indexOf(xs []string, want string) int {
	for i, x := range xs {
		if x == want {
			return i
		}
	}
	return -1
}

// TestHighestReadsRanksRatherThanPosition checks the helper against both directions.
func TestHighestReadsRanksRatherThanPosition(t *testing.T) {
	cases := []struct {
		name string
		p    *Profile
		want string
	}{
		{"labels descending", umichFixture(), "restricted"},
		{"labels ascending", harvardFixture(), "dsl5"},
		{"three levels", threeLevelFixture(), "high"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Reversed on purpose: Highest must not depend on Canonicalize having run.
			rev := make([]Level, len(tc.p.Levels))
			for i, l := range tc.p.Levels {
				rev[len(rev)-1-i] = l
			}
			tc.p.Levels = rev
			got := tc.p.Highest()
			if got == nil {
				t.Fatal("Highest returned nil for a profile with levels")
			}
			if got.ID != tc.want {
				t.Errorf("Highest() = %q, want %q — it read position rather than rank",
					got.ID, tc.want)
			}
		})
	}
}

// TestRankMustBeExplicitAndDense covers the check no schema can make.
func TestRankMustBeExplicitAndDense(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Profile)
		want   string
	}{
		{
			name:   "a level with no rank",
			mutate: func(p *Profile) { p.Levels[1].Rank = 0 },
			want:   "explicit integer rank",
		},
		{
			name:   "two levels at one rank",
			mutate: func(p *Profile) { p.Levels[1].Rank = p.Levels[2].Rank },
			want:   "duplicates",
		},
		{
			name: "a gap in the middle",
			mutate: func(p *Profile) {
				// 1, 2, 4 over three levels: reads as a complete scheme, and nothing in
				// the rendering says a level is missing.
				p.Levels[2].Rank = 4
			},
			want: "no gaps",
		},
		{
			name: "a run that starts above one",
			mutate: func(p *Profile) {
				for i := range p.Levels {
					p.Levels[i].Rank += 1
				}
			},
			want: "no gaps",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := sampleProfile(t)
			tc.mutate(p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not mention %q:\n%v", tc.want, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GATE 3: highest-water-mark composition, and the union law it belongs to.
// ---------------------------------------------------------------------------

// TestJoinHoldsTheUnionLaws holds over levels the four properties `compile`'s property
// tests hold over control sets.
//
// The point of asserting all four rather than "join returns the higher one" is the
// cross-reference: DESIGN §9's union law and this join are the same principle on
// different lattices, and a principle claimed in a doc comment and not asserted anywhere
// is a claim about intent.
func TestJoinHoldsTheUnionLaws(t *testing.T) {
	for _, p := range []*Profile{threeLevelFixture(), umichFixture(), harvardFixture()} {
		ids := p.LevelIDs()
		name := p.Meta.ID

		join := func(t *testing.T, a, b string) string {
			t.Helper()
			l, err := p.Join(a, b)
			if err != nil {
				t.Fatalf("Join(%q, %q): %v", a, b, err)
			}
			return l.ID
		}

		t.Run(name+"/idempotent", func(t *testing.T) {
			for _, a := range ids {
				if got := join(t, a, a); got != a {
					t.Errorf("Join(%q, %q) = %q, want %q", a, a, got, a)
				}
			}
		})
		t.Run(name+"/commutative", func(t *testing.T) {
			for _, a := range ids {
				for _, b := range ids {
					if x, y := join(t, a, b), join(t, b, a); x != y {
						t.Errorf("Join(%q, %q) = %q but Join(%q, %q) = %q", a, b, x, b, a, y)
					}
				}
			}
		})
		t.Run(name+"/associative", func(t *testing.T) {
			for _, a := range ids {
				for _, b := range ids {
					for _, c := range ids {
						x := join(t, join(t, a, b), c)
						y := join(t, a, join(t, b, c))
						if x != y {
							t.Errorf("(%s∨%s)∨%s = %q but %s∨(%s∨%s) = %q", a, b, c, x, a, b, c, y)
						}
					}
				}
			}
		})
		t.Run(name+"/monotone", func(t *testing.T) {
			// Raising either input can never lower the result — the property that makes
			// this "the stricter reading wins" rather than merely "a choice".
			rank := func(id string) int {
				l, _ := p.LevelByID(id)
				return l.Rank
			}
			for _, a := range ids {
				for _, b := range ids {
					for _, bb := range ids {
						if rank(bb) < rank(b) {
							continue
						}
						if rank(join(t, a, bb)) < rank(join(t, a, b)) {
							t.Errorf("raising %q to %q lowered the join with %q", b, bb, a)
						}
					}
				}
			}
		})
		t.Run(name+"/never below either input", func(t *testing.T) {
			for _, a := range ids {
				for _, b := range ids {
					la, _ := p.LevelByID(a)
					lb, _ := p.LevelByID(b)
					got, _ := p.LevelByID(join(t, a, b))
					if got.Rank < la.Rank || got.Rank < lb.Rank {
						t.Errorf("Join(%q, %q) = %q, which is below an input — composing relaxed "+
							"a requirement, which is the one thing the union law forbids", a, b, got.ID)
					}
				}
			}
		})
	}
}

// TestJoinRefusesACrossInstitutionComparison records the gap deliberately left open.
//
// UC's P3 and Stanford's Moderate are not comparable, and a tool that answered would be
// asserting an equivalence neither institution published. The error has to name the
// profile's own levels, because the likeliest cause is a value typed from the other
// institution's scheme.
func TestJoinRefusesACrossInstitutionComparison(t *testing.T) {
	p := umichFixture()
	_, err := p.Join("restricted", "dsl3") // dsl3 belongs to the other fixture
	if err == nil {
		t.Fatal("Join accepted a level id from another institution's scheme and returned an " +
			"answer; that answer would be an equivalence neither institution published")
	}
	var unknown *UnknownLevelError
	if !asUnknownLevel(err, &unknown) {
		t.Fatalf("want an *UnknownLevelError, got %T: %v", err, err)
	}
	msg := err.Error()
	for _, want := range []string{"dsl3", "restricted", "not comparable across profiles"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q:\n%s", want, msg)
		}
	}
}

func asUnknownLevel(err error, target **UnknownLevelError) bool {
	if u, ok := err.(*UnknownLevelError); ok {
		*target = u
		return true
	}
	return false
}

// TestCompositionRuleIsPinnedAndCrossReferenced guards both halves of gate 3.
func TestCompositionRuleIsPinnedAndCrossReferenced(t *testing.T) {
	p := sampleProfile(t)
	p.Composition.Rule = "lowest-water-mark"
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted a second composition rule; a lattice with two joins is not " +
			"a lattice, and adding one is a schema version event rather than an enum member")
	}
	if !strings.Contains(err.Error(), "union law") {
		t.Errorf("the refusal does not connect the rule to DESIGN §9's union law, which is where "+
			"a reader learns this is not an arbitrary choice:\n%v", err)
	}

	// The cross-reference itself, asserted rather than trusted to a doc comment: the
	// three operations named together are what make the claim checkable.
	for _, want := range []string{
		"union of controls", "intersection of permitted behavior", "join of classification levels",
	} {
		if !strings.Contains(CompositionRuleAssociates, want) {
			t.Errorf("CompositionRuleAssociates no longer names %q; the sentence exists to put all "+
				"three operations in one place, because that is what shows they are one law", want)
		}
	}
}

// ---------------------------------------------------------------------------
// GATE 4: every claim traces to a cited section, and silence stays silent.
// ---------------------------------------------------------------------------

// TestEveryCitationMustResolveToAHashedSource covers each reference site.
//
// One case per site on purpose: a new citation field added to the document without a
// corresponding line in validateCitationRefsResolve is a claim whose provenance nobody
// checks, and this table is what makes that omission fail.
func TestEveryCitationMustResolveToAHashedSource(t *testing.T) {
	const bogus = "no-such-source"
	cases := []struct {
		name   string
		mutate func(*Profile)
	}{
		{"the interpretation's source", func(p *Profile) { p.Interpretation.SourceID = bogus }},
		{"the determination's citation", func(p *Profile) { p.Determination.Citation.SourceID = bogus }},
		{"the may-lower citation", func(p *Profile) { p.Determination.MayLower.Citation.SourceID = bogus }},
		{"a level's citation", func(p *Profile) { p.Levels[0].Citation.SourceID = bogus }},
		{"a control's citation", func(p *Profile) { p.Levels[1].Controls[0].Citation.SourceID = bogus }},
		{"an external obligation's citation", func(p *Profile) {
			p.Levels[2].ExternalObligations[0].Citation.SourceID = bogus
		}},
		{"the composition citation", func(p *Profile) { p.Composition.Citation.SourceID = bogus }},
		{"the over-classification citation", func(p *Profile) {
			p.Composition.OverClassification.Citation.SourceID = bogus
		}},
		{"an unmodeled axis's citation", func(p *Profile) { p.UnmodeledAxes[0].Citation.SourceID = bogus }},
		{"a document citation's source", func(p *Profile) { p.Citations[0].SourceID = bogus }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := sampleProfile(t)
			tc.mutate(p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s naming a source the document does not carry — "+
					"a citation that resolves to nothing renders exactly as confidently as one "+
					"that resolves to bytes somebody can check", tc.name)
			}
			if !strings.Contains(err.Error(), "names no entry in sources") {
				t.Errorf("the refusal is not the unresolved-source one:\n%v", err)
			}
		})
	}
}

// TestEveryControlCarriesACitation is gate 4 stated as a shape.
func TestEveryControlCarriesACitation(t *testing.T) {
	p := sampleProfile(t)
	p.Levels[1].Controls[0].Citation = CitationRef{}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted a control with no citation; in a derived profile that is " +
			"automat's opinion wearing an institution's name")
	}
	for _, want := range []string{"source_id", "section"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name the missing %s:\n%v", want, err)
		}
	}
}

// TestWhereTheSourceIsSilentTheProfileIsSilent covers the empty-versus-absent rule.
//
// The distinction is not pedantry. An empty controls array claims the source was
// consulted and stated nothing; an absent one is the shape a level takes when the source
// states nothing. They render identically to a reader, so only the unambiguous form is
// admitted — and a level with genuinely no published controls must be REPRESENTABLE,
// which is the other half of the same rule.
func TestWhereTheSourceIsSilentTheProfileIsSilent(t *testing.T) {
	t.Run("a present-but-empty controls array is refused", func(t *testing.T) {
		p := sampleProfile(t)
		p.Levels[0].Controls = []Control{}
		err := p.Validate()
		if err == nil {
			t.Fatal("Validate accepted controls: []")
		}
		if !strings.Contains(err.Error(), "present but empty") {
			t.Errorf("unexpected refusal:\n%v", err)
		}
	})
	t.Run("an absent controls array is the honest rendering", func(t *testing.T) {
		p := sampleProfile(t)
		for i := range p.Levels {
			p.Levels[i].Controls = nil
			p.Levels[i].ExternalObligations = nil
			p.Levels[i].Examples = nil
		}
		mustValidate(t, p, "a scheme whose source defines levels without stating controls")
	})
	t.Run("the same rule for examples and external obligations", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			mutate func(*Profile)
		}{
			{"examples", func(p *Profile) { p.Levels[0].Examples = []string{} }},
			{"external obligations", func(p *Profile) {
				p.Levels[0].ExternalObligations = []ExternalObligation{}
			}},
			{"unmodeled axes", func(p *Profile) { p.UnmodeledAxes = []UnmodeledAxis{} }},
		} {
			p := sampleProfile(t)
			tc.mutate(p)
			if err := p.Validate(); err == nil {
				t.Errorf("Validate accepted an empty %s array", tc.name)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// GATE 5: the provenance rules.
// ---------------------------------------------------------------------------

// TestNonEndorsementIsGuardedInSubstanceAndNamesTheInstitution covers both halves.
//
// The phrase list is the substance; the institution's name is the half a phrase list
// alone would miss. "It was not authored, reviewed, or endorsed by the institution" is a
// grammatically complete disclaimer that disclaims nobody.
func TestNonEndorsementIsGuardedInSubstanceAndNamesTheInstitution(t *testing.T) {
	t.Run("each required phrase is load-bearing", func(t *testing.T) {
		for _, phrase := range NonEndorsementSubstance {
			p := sampleProfile(t)
			p.Interpretation.NonEndorsement = strings.ReplaceAll(
				p.Interpretation.NonEndorsement, phrase, "")
			err := p.Validate()
			if err == nil {
				t.Errorf("Validate accepted a non-endorsement statement with %q removed", phrase)
				continue
			}
			if !strings.Contains(err.Error(), phrase) {
				t.Errorf("the refusal for a missing %q does not name it:\n%v", phrase, err)
			}
		}
	})

	t.Run("a hard wrap is not a defect", func(t *testing.T) {
		p := sampleProfile(t)
		p.Interpretation.NonEndorsement = strings.ReplaceAll(
			p.Interpretation.NonEndorsement, ", or endorsed", ",\nor endorsed")
		mustValidate(t, p, "a wrapped non-endorsement statement")
	})

	t.Run("the statement must name the institution", func(t *testing.T) {
		p := sampleProfile(t)
		p.Interpretation.NonEndorsement = strings.ReplaceAll(
			p.Interpretation.NonEndorsement, "Example Institution", "the institution")
		err := p.Validate()
		if err == nil {
			t.Fatal("Validate accepted a disclaimer that names no institution; a reader will " +
				"attach it to whichever institution they had in mind, which is the opposite of " +
				"what it is for")
		}
		if !strings.Contains(err.Error(), "does not name") {
			t.Errorf("unexpected refusal:\n%v", err)
		}
	})

	t.Run("missing entirely on a derived profile", func(t *testing.T) {
		p := sampleProfile(t)
		p.Interpretation = nil
		err := p.Validate()
		if err == nil {
			t.Fatal("Validate accepted a derived profile with no interpretation block")
		}
		if !strings.Contains(err.Error(), "circulates as the policy") {
			t.Errorf("the refusal does not say what goes wrong:\n%v", err)
		}
	})

	t.Run("present on an issuer-authored profile", func(t *testing.T) {
		p := sampleProfile(t)
		p.Authorship = AuthorshipIssuer
		p.Maintenance = MaintenanceShipped
		err := p.Validate()
		if err == nil {
			t.Fatal("Validate accepted an institution disclaiming its own document")
		}
		if !strings.Contains(err.Error(), "does not disclaim its own document") {
			t.Errorf("unexpected refusal:\n%v", err)
		}
	})
}

// TestADerivedProfileMayOnlyBeInterpreted covers the role restriction and the
// maintenance pairing.
func TestADerivedProfileMayOnlyBeInterpreted(t *testing.T) {
	sig := func(role evidence.Role) Attestation {
		return Attestation{
			Role: role, Identity: "automat maintainers",
			Statement:     "We read the cited source and wrote this reading of it.",
			ContentSHA256: strings.Repeat("0", 64), AttestedAt: "2026-08-06",
		}
	}

	t.Run("interpreted-by is admissible", func(t *testing.T) {
		p := sampleProfile(t)
		p.Signatures = []Attestation{sig(evidence.RoleInterpretedBy)}
		if err := p.Validate(); err != nil {
			t.Fatalf("Validate rejected an interpreted-by attestation:\n%v", err)
		}
	})

	for _, role := range evidence.AllRoles {
		if role == evidence.RoleInterpretedBy {
			continue
		}
		t.Run("refused: "+string(role), func(t *testing.T) {
			p := sampleProfile(t)
			p.Signatures = []Attestation{sig(role)}
			err := p.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a %s attestation on a derived profile. The weaker "+
					"roles are the danger: one inference from `reviewed-by` is \"the institution "+
					"reviewed this\", the single claim a derived profile must never support", role)
			}
			if !strings.Contains(err.Error(), "derived interpretation") {
				t.Errorf("unexpected refusal:\n%v", err)
			}
		})
	}

	t.Run("a derived profile may not claim to be maintained", func(t *testing.T) {
		p := sampleProfile(t)
		p.Maintenance = MaintenanceShipped
		err := p.Validate()
		if err == nil {
			t.Fatal("Validate accepted a derived profile marked shipped-and-maintained")
		}
		if !strings.Contains(err.Error(), "never the maintainer") {
			t.Errorf("the refusal does not say why automat is not the upstream:\n%v", err)
		}
	})
}

// TestAutomatNeverClassifies pins the two const fields pointing opposite ways.
func TestAutomatNeverClassifies(t *testing.T) {
	t.Run("automat_determines cannot be true", func(t *testing.T) {
		p := sampleProfile(t)
		p.Determination.AutomatDetermines = true
		err := p.Validate()
		if err == nil {
			t.Fatal("Validate accepted automat_determines: true")
		}
		if !strings.Contains(err.Error(), "stop and flag it") {
			t.Errorf("the refusal does not tell a contributor to stop:\n%v", err)
		}
	})
	t.Run("declared_by_operator cannot be false", func(t *testing.T) {
		p := sampleProfile(t)
		p.Levels[2].ExternalObligations[0].DeclaredByOperator = false
		err := p.Validate()
		if err == nil {
			t.Fatal("Validate accepted an external obligation not declared by the operator; a " +
				"classification level mentioning a regime does not make that regime apply")
		}
	})
	t.Run("determination roles must name a human role", func(t *testing.T) {
		p := sampleProfile(t)
		p.Determination.Roles = nil
		err := p.Validate()
		if err == nil {
			t.Fatal("Validate accepted a profile naming nobody as the determiner")
		}
		if !strings.Contains(err.Error(), "design rather than an omission") {
			t.Errorf("the refusal does not say why naming the role matters:\n%v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Hash coverage, canonicalization, and the round trip.
// ---------------------------------------------------------------------------

// TestHashCoverageIsADecisionNotADefault asserts the two published lists against the
// struct by reflection.
//
// The device envprofile uses, and for the same reason: adding a field to Profile without
// deciding whether the hash covers it is how a document acquires a field an attestation
// silently does not vouch for. Here the failure is sharper — every field of this document
// is a claim about somebody's published policy.
func TestHashCoverageIsADecisionNotADefault(t *testing.T) {
	declared := map[string]bool{}
	for _, n := range HashCoveredFields {
		declared[n] = true
	}
	for _, n := range HashExcludedFields {
		if declared[n] {
			t.Errorf("%q is listed as both covered and excluded", n)
		}
		declared[n] = true
	}

	pt := reflect.TypeOf(Profile{})
	for i := 0; i < pt.NumField(); i++ {
		name := pt.Field(i).Name
		if !declared[name] {
			t.Errorf("Profile.%s appears in neither HashCoveredFields nor HashExcludedFields. "+
				"Hash coverage is a decision: decide whether an attestation should still verify "+
				"after this field changes, and write it down in one of the two lists", name)
		}
	}

	// And the covered list must match the payload struct exactly, so the lists describe
	// the code rather than the intent.
	payload := map[string]bool{}
	ct := reflect.TypeOf(contentPayload{})
	for i := 0; i < ct.NumField(); i++ {
		payload[ct.Field(i).Name] = true
	}
	for _, n := range HashCoveredFields {
		if !payload[n] {
			t.Errorf("HashCoveredFields names %q but contentPayload has no such field", n)
		}
	}
	for n := range payload {
		if !declared[n] || !containsString(HashCoveredFields, n) {
			t.Errorf("contentPayload has %q but HashCoveredFields does not list it", n)
		}
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestEveryCoveredFieldChangesTheHash is the assertion the field lists imply.
func TestEveryCoveredFieldChangesTheHash(t *testing.T) {
	base := sampleProfile(t)
	want, err := base.ContentHash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	covered := []struct {
		field  string
		mutate func(*Profile)
	}{
		{"Issuer", func(p *Profile) { p.Issuer.ID = "other-institution" }},
		{"Status", func(p *Profile) { p.Status = StatusSuperseded }},
		{"ReviewBy", func(p *Profile) { p.ReviewBy = "2099-01-01" }},
		{"Authorship", func(p *Profile) { p.Authorship = AuthorshipIssuer }},
		{"Maintenance", func(p *Profile) { p.Maintenance = MaintenanceShipped }},
		{"Interpretation", func(p *Profile) { p.Interpretation.NonEndorsement += " Softened." }},
		{"Determination", func(p *Profile) { p.Determination.Roles = []string{"Somebody else"} }},
		{"Levels", func(p *Profile) { p.Levels[0].Definition += " And more." }},
		{"Composition", func(p *Profile) { p.Composition.Statement += " Or the lower." }},
		{"Inherits", func(p *Profile) {
			p.Inherits = &Inherits{
				ProfileID: "other", IssuerID: p.Issuer.ID, Relation: InheritsOverlays,
			}
		}},
		{"UnmodeledAxes", func(p *Profile) { p.UnmodeledAxes = nil }},
		{"Citations", func(p *Profile) { p.Citations[0].EffectiveDate = "1999-01-01" }},
		{"PolicyCaveat", func(p *Profile) { p.PolicyCaveat = "Trust us." }},
		{"Sources", func(p *Profile) { p.Sources[0].SHA256 = strings.Repeat("f", 64) }},
	}
	if len(covered) != len(HashCoveredFields) {
		t.Errorf("this table has %d cases but HashCoveredFields names %d fields; a covered field "+
			"with no case here is one nothing proves is covered", len(covered), len(HashCoveredFields))
	}
	for _, tc := range covered {
		t.Run(tc.field, func(t *testing.T) {
			p := sampleProfile(t)
			tc.mutate(p)
			got, err := p.ContentHash()
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if got == want {
				t.Errorf("changing %s left the content hash unchanged; an attestation over the "+
					"old content would still verify against the new claims", tc.field)
			}
		})
	}

	t.Run("excluded fields do not change it", func(t *testing.T) {
		for _, tc := range []struct {
			field  string
			mutate func(*Profile)
		}{
			// A department forking a profile and retitling it must not invalidate the
			// interpreter's attestation over the reading itself.
			{"Meta", func(p *Profile) {
				p.Meta.ID = "our-fork"
				p.Meta.Title = "Our fork of the example scheme"
				p.Meta.Description = "Retitled locally."
			}},
			{"Signatures", func(p *Profile) {
				p.Signatures = []Attestation{{
					Role: evidence.RoleInterpretedBy, Identity: "someone",
					Statement: "We read it.", ContentSHA256: want, AttestedAt: "2026-08-06",
				}}
			}},
		} {
			p := sampleProfile(t)
			tc.mutate(p)
			got, err := p.ContentHash()
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if got != want {
				t.Errorf("changing %s changed the content hash; %s is documented as excluded",
					tc.field, tc.field)
			}
		}
	})
}

// TestCanonicalizeSortsByRankNotByID is the canonicalization counterpart of gate 1.
func TestCanonicalizeSortsByRankNotByID(t *testing.T) {
	p := umichFixture()
	// Shuffle into label order, which is the wrong order for this scheme.
	p.Levels = []Level{p.Levels[2], p.Levels[0], p.Levels[1], p.Levels[3]}
	p.Canonicalize()
	got := make([]int, 0, len(p.Levels))
	for _, l := range p.Levels {
		got = append(got, l.Rank)
	}
	if !reflect.DeepEqual(got, []int{1, 2, 3, 4}) {
		t.Errorf("Canonicalize left the levels ordered %v; sorting by id would order this "+
			"scheme's labels correctly and the other fixture's exactly backwards, which is why "+
			"rank is the sort key", got)
	}
}

// TestTheHashIgnoresOrderingsThatCarryNoMeaning is the round-trip property.
func TestTheHashIgnoresOrderingsThatCarryNoMeaning(t *testing.T) {
	a := sampleProfile(t)
	want, err := a.ContentHash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	b := sampleProfile(t)
	b.Levels = []Level{b.Levels[2], b.Levels[0], b.Levels[1]}
	b.Levels[2].Controls = append(b.Levels[2].Controls, Control{
		ID: "aaa-sorted-first", Title: "Another requirement",
		Requirement: "Do the other thing.",
		Citation:    CitationRef{SourceID: "example-policy", Section: "Section 4, Other row"},
	})
	a2 := sampleProfile(t)
	a2.Levels[1].Controls = append([]Control{{
		ID: "aaa-sorted-first", Title: "Another requirement",
		Requirement: "Do the other thing.",
		Citation:    CitationRef{SourceID: "example-policy", Section: "Section 4, Other row"},
	}}, a2.Levels[1].Controls...)

	ha, err := a2.ContentHash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// b's extra control went onto the level that sorts to index 1 after canonicalization
	// (rank 2, "internal"), same as a2's — so the two must agree.
	hb, err := b.ContentHash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if ha != hb {
		t.Errorf("two documents describing the same scheme hashed differently (%s vs %s); "+
			"the hash must cover meaning rather than field order", ha[:12], hb[:12])
	}
	if ha == want {
		t.Error("adding a control did not change the hash")
	}
}

// TestCanonicalizeDoesNotSortWhatCarriesMeaning is the other side of the same coin.
func TestCanonicalizeDoesNotSortWhatCarriesMeaning(t *testing.T) {
	p := sampleProfile(t)
	p.Determination.Roles = []string{"Unit Security Leads", "Data Stewards"} // reverse-alphabetical
	p.Levels[0].Examples = []string{"Zebra data", "Aardvark data"}
	p.Canonicalize()

	if p.Determination.Roles[0] != "Unit Security Leads" {
		t.Errorf("Canonicalize alphabetized determination.roles; the order is the institution's, "+
			"roughly the order an operator walks them, got %v", p.Determination.Roles)
	}
	if p.Levels[0].Examples[0] != "Zebra data" {
		t.Errorf("Canonicalize alphabetized a level's examples; they are the source's own "+
			"examples in the source's own order, and a reader checks them by reading down the "+
			"list, got %v", p.Levels[0].Examples)
	}
}

// TestVerifyAttestationSubjectsCatchesAMovedAttestation covers the check Validate
// deliberately does not make.
func TestVerifyAttestationSubjectsCatchesAMovedAttestation(t *testing.T) {
	p := sampleProfile(t)
	hash, err := p.ContentHash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	p.Signatures = []Attestation{{
		Role: evidence.RoleInterpretedBy, Identity: "automat maintainers",
		Statement: "We read the cited source.", ContentSHA256: hash, AttestedAt: "2026-08-06",
	}}
	if verr := p.VerifyAttestationSubjects(); verr != nil {
		t.Fatalf("a matching attestation was rejected:\n%v", verr)
	}

	// Softening the disclaimer under a signature that still names the old hash is the
	// case this check exists for.
	p.Interpretation.NonEndorsement += " But we are confident it is accurate."
	err = p.VerifyAttestationSubjects()
	if err == nil {
		t.Fatal("VerifyAttestationSubjects accepted an attestation over the previous content; " +
			"an interpreted-by signature sitting on a reading it was never made about is the " +
			"defect this check exists for")
	}
	if !strings.Contains(err.Error(), "about something else") {
		t.Errorf("the refusal does not say what a mismatched subject means:\n%v", err)
	}
}

// TestRoundTripThroughDiskPreservesTheHash is the load/write pairing.
func TestRoundTripThroughDiskPreservesTheHash(t *testing.T) {
	p := sampleProfile(t)
	want, err := p.ContentHash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	path := t.TempDir() + "/nested/dir/profile.json"
	if werr := p.Write(path); werr != nil {
		t.Fatalf("write: %v", werr)
	}
	got, err := Load(path, LoadOptions{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	h, err := got.ContentHash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if h != want {
		t.Errorf("a round trip through disk changed the content hash (%s → %s); every reference "+
			"to this document names that hash", want[:12], h[:12])
	}
}

// TestDecodeRefusesTheDocumentsThatAreNotProfiles covers the load-path errors, each of
// which has to say what to do rather than what went wrong.
func TestDecodeRefusesTheDocumentsThatAreNotProfiles(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"empty", "", "the document is empty"},
		{"truncated mid-value", `{"schema_version": "1.0.`, "truncated"},
		{"two documents in one file", `{"schema_version":"1.0.0"} {"schema_version":"1.0.0"}`,
			"exactly one classification profile"},
		{"an unknown field", `{"schema_version":"1.0.0","levles":[]}`, "does not allow unknown fields"},
		{"a rank written as a string", `{"schema_version":"1.0.0","levels":[{"rank":"4"}]}`,
			"rank is an integer, not a string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.data), LoadOptions{})
			if err == nil {
				t.Fatalf("Decode accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error does not mention %q:\n%v", tc.want, err)
			}
		})
	}
}

// TestSignatureFormatsAgreeWithTheOtherDocumentTypes is the promise types.go makes.
//
// Two documents admitting different signature formats would be two trust models, and the
// values are duplicated here rather than imported precisely so this test has something to
// check. envprofile's set is not importable from a test in this package without a
// dependency between two leaf document packages, so the values are restated and compared
// against what the schema admits.
func TestSignatureFormatsAgreeWithTheOtherDocumentTypes(t *testing.T) {
	want := []string{"detached-ed25519", "oidc-identity-bundle"}
	got := make([]string, 0, len(AllSignatureFormats))
	for _, f := range AllSignatureFormats {
		got = append(got, string(f))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllSignatureFormats = %v, want %v. The environment profile admits exactly "+
			"these two; a third here would be a second trust model arriving in one document type",
			got, want)
	}
}

// TestErrorsCarryRemediation is CLAUDE.md rule 7 over this package's validator.
func TestErrorsCarryRemediation(t *testing.T) {
	p := sampleProfile(t)
	// Break several unrelated things at once: the operator should get all of them.
	p.Meta.ID = "Example Levels"
	p.Levels[0].ID = "Public Data"
	p.Issuer.ID = ""
	p.ReviewBy = "2027"

	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted four broken fields")
	}
	ve, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("want a *ValidationError, got %T", err)
	}
	if len(ve.Problems) < 4 {
		t.Errorf("got %d problems for four defects; a validator that stops at the first one makes "+
			"an operator fix a document one round trip at a time:\n%v", len(ve.Problems), err)
	}
	for _, pr := range ve.Problems {
		if pr.Path == "" {
			t.Errorf("a problem with no path: %+v", pr)
		}
		if pr.Fix == "" {
			t.Errorf("%s has no remediation text; a permission or validation failure an operator "+
				"cannot act on is a bug in the validator (CLAUDE.md rule 7)", pr.Path)
		}
	}
}

// TestUntrustedStringsCannotForgeAValidationReport is AUDIT-0's M1 over this package.
func TestUntrustedStringsCannotForgeAValidationReport(t *testing.T) {
	p := sampleProfile(t)
	// A forked profile is attacker-controlled input by design: the whole point of
	// example-and-forkable is that these travel.
	p.Meta.ID = "ok\n  - levels: fine\n  - signatures: verified"
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted an id containing a newline")
	}
	msg := err.Error()
	if strings.Contains(msg, "\n  - levels: fine") {
		t.Errorf("the report reproduced an injected line verbatim; a reviewer reads a clean "+
			"report while the document is anything but:\n%s", msg)
	}
	if !strings.Contains(msg, `\n`) {
		t.Errorf("the newline was not escaped:\n%s", msg)
	}
}
