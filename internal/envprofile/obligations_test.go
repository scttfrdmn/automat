// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package envprofile

import (
	"strings"
	"testing"
)

// matchingSet returns a resolver agreeing with the fixture: both obligations resolve,
// both hashes match, and only nih-cadr-dua leaves the revision to the operator — which
// is the fixture's own shape, so a profile checked against it must pass.
func matchingSet(t *testing.T, p *Profile) ObligationSet {
	t.Helper()
	if len(p.Obligations) != 2 {
		t.Fatalf("the fixture carries %d obligation(s); this resolver is written against 2",
			len(p.Obligations))
	}
	return ObligationSet{
		"dfars-7012": {
			ID:            "dfars-7012",
			ContentSHA256: strings.Repeat("a", 64),
		},
		"nih-cadr-dua": {
			ID:                            "nih-cadr-dua",
			ContentSHA256:                 strings.Repeat("b", 64),
			RequiresRevisionDetermination: true,
		},
	}
}

// TestCheckObligationsAcceptsAProfileThatAgreesWithTheProfilesItNames is the baseline the
// refusals below are deviations from. Written first so that a fixture drifting out of
// agreement with the resolver fails here rather than making every refusal below pass for
// the wrong reason.
func TestCheckObligationsAcceptsAProfileThatAgreesWithTheProfilesItNames(t *testing.T) {
	p := sampleProfile(t)
	if err := p.CheckObligations(matchingSet(t, p)); err != nil {
		t.Fatalf("a profile whose references match the loaded obligation profiles must pass:\n%v", err)
	}
}

// TestCheckObligationsRefusesEveryCrossDocumentDisagreement covers all three checks in
// both directions, and each case names why the refusal is a hard error at plan time
// rather than a note.
func TestCheckObligationsRefusesEveryCrossDocumentDisagreement(t *testing.T) {
	cases := []struct {
		name string
		// why records what the refusal buys, so a future reader deciding to soften one
		// has to argue with the reason rather than with the assertion.
		why      string
		wantPath string
		wantIn   string
		mutate   func(*testing.T, *Profile, ObligationSet)
	}{
		{
			name: "a reference to an obligation profile that is not loaded",
			why: "an unresolvable reference is not a weaker claim than a resolved one; it is a claim " +
				"about a document nobody has read",
			wantPath: "obligations[0].id",
			wantIn:   "which is not loaded",
			mutate: func(_ *testing.T, _ *Profile, s ObligationSet) {
				delete(s, "dfars-7012")
			},
		},
		{
			name: "a hash that does not match the profile on disk",
			why: "the hash is what makes this a reference rather than a label — an obligation profile " +
				"is a reading of policy that moves, and one named by id alone has a subject that can be " +
				"rewritten underneath it",
			wantPath: "obligations[0].content_sha256",
			wantIn:   "hashes to",
			mutate: func(_ *testing.T, _ *Profile, s ObligationSet) {
				f := s["dfars-7012"]
				f.ContentSHA256 = strings.Repeat("c", 64)
				s["dfars-7012"] = f
			},
		},
		{
			name: "a missing determination where the obligation leaves the revision open",
			why: "automat ships no default revision; picking one would make a compliance determination " +
				"on the institution's behalf, routing around the person best placed to make it",
			wantPath: "obligations[1].revision_determination",
			wantIn:   "is missing",
			mutate: func(_ *testing.T, p *Profile, _ ObligationSet) {
				p.Obligations[1].RevisionDetermination = nil
			},
		},
		{
			name: "a determination recorded against a profile that pins the revision itself",
			why: "a determination against a pinned revision is a default wearing a different hat: it " +
				"renders into evidence looking like a decision that was open, and the next reader " +
				"cannot tell which of the two is the claim",
			wantPath: "obligations[0].revision_determination",
			wantIn:   "pins the control catalog revision itself",
			mutate: func(t *testing.T, p *Profile, _ ObligationSet) {
				p.Obligations[0].RevisionDetermination = determination(t, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := sampleProfile(t)
			set := matchingSet(t, p)
			tc.mutate(t, p, set)

			err := p.CheckObligations(set)
			ve, ok := AsValidationError(err)
			if !ok {
				t.Fatalf("CheckObligations accepted %s.\n%s\ngot %T: %v", tc.name, tc.why, err, err)
			}
			var found bool
			for _, prob := range ve.Problems {
				if prob.Path == tc.wantPath && strings.Contains(prob.Message, tc.wantIn) {
					found = true
					if prob.Fix == "" {
						t.Errorf("the problem at %s has no remediation text (CLAUDE.md rule 7): a "+
							"cross-document disagreement an operator cannot act on is a bug in the "+
							"validator", prob.Path)
					}
				}
			}
			if !found {
				t.Errorf("no problem at %s mentioning %q; reported:\n%v", tc.wantPath, tc.wantIn, ve)
			}
		})
	}
}

// TestCheckObligationsReportsEveryDisagreementInOnePass. An operator reconciling a
// profile against a freshly vendored obligation catalog may have several stale
// references; a validator that stops at the first turns one reconciliation into n runs,
// and the last is the one they skip.
func TestCheckObligationsReportsEveryDisagreementInOnePass(t *testing.T) {
	p := sampleProfile(t)
	set := matchingSet(t, p)

	// Three problems across both entries: a wrong hash and a missing determination on
	// one, and an unresolvable reference on the other.
	f := set["nih-cadr-dua"]
	f.ContentSHA256 = strings.Repeat("d", 64)
	set["nih-cadr-dua"] = f
	p.Obligations[1].RevisionDetermination = nil
	delete(set, "dfars-7012")

	err := p.CheckObligations(set)
	ve, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("want a *ValidationError, got %T: %v", err, err)
	}
	if len(ve.Problems) != 3 {
		t.Errorf("reported %d problems, want 3:\n%v", len(ve.Problems), ve)
	}
}

// TestAnUnresolvableReferenceIsReportedOnceRatherThanCascading.
//
// The `continue` after the resolution failure is the whole point: a reference automat
// cannot resolve has no facts to check the hash or the determination against, and
// reporting three problems about one missing document would bury the one an operator can
// actually fix.
func TestAnUnresolvableReferenceIsReportedOnceRatherThanCascading(t *testing.T) {
	p := sampleProfile(t)
	set := matchingSet(t, p)
	delete(set, "nih-cadr-dua") // the entry carrying a determination AND a hash

	err := p.CheckObligations(set)
	ve, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("want a *ValidationError, got %T: %v", err, err)
	}
	if len(ve.Problems) != 1 {
		t.Errorf("reported %d problems about one unresolvable reference; there are no facts to check "+
			"a hash or a determination against, and the extra lines would bury the one an operator can "+
			"fix:\n%v", len(ve.Problems), ve)
	}
}

// TestCheckObligationsRefusesToRunWithNoResolver.
//
// Returning nil here would be the worst available behavior: the pairing this function
// exists to enforce would be silently skipped, and a caller that forgot the argument
// would see a clean check. The refusal names how many references went unchecked.
func TestCheckObligationsRefusesToRunWithNoResolver(t *testing.T) {
	p := sampleProfile(t)
	err := p.CheckObligations(nil)
	if err == nil {
		t.Fatal("CheckObligations returned nil with no resolver. A caller that forgot the argument " +
			"would see a clean check, and the cross-document pairing would be skipped silently.")
	}
	if !strings.Contains(err.Error(), "2 obligation reference(s)") {
		t.Errorf("the refusal does not say how many references went unchecked:\n%v", err)
	}

	t.Run("but a profile with no obligations needs none", func(t *testing.T) {
		q := sampleProfile(t)
		q.Obligations = nil
		if cerr := q.CheckObligations(nil); cerr != nil {
			t.Errorf("a profile naming no obligations has nothing to resolve; demanding a resolver "+
				"would make the argument required for every caller including those with no "+
				"obligations loaded:\n%v", cerr)
		}
	})
}

// TestAResolverWithNoHashDoesNotSilentlyPassTheHashCheck records a real limit rather than
// asserting a behavior nobody wants.
//
// The `facts.ContentSHA256 != ""` guard exists because ObligationFacts is filled in by a
// caller, and a caller that has the document but not its hash should not have its
// references reported as mismatched against the empty string. That means the hash check
// is only as good as the caller — so the guard is narrow (empty means unknown, never
// "matches"), and this test is what says the narrowness was chosen.
func TestAResolverWithNoHashDoesNotSilentlyPassTheHashCheck(t *testing.T) {
	p := sampleProfile(t)
	set := matchingSet(t, p)
	f := set["dfars-7012"]
	f.ContentSHA256 = ""
	set["dfars-7012"] = f

	if err := p.CheckObligations(set); err != nil {
		t.Fatalf("a resolver reporting no hash must not produce a mismatch against the empty "+
			"string:\n%v", err)
	}
	// And the reference's own hash is still required to be well-formed, by Validate —
	// so an unknown-hash resolver cannot be a route to recording a reference with no
	// subject at all.
	q := sampleProfile(t)
	q.Obligations[0].ContentSHA256 = ""
	if err := q.Validate(); err == nil {
		t.Error("Validate accepted an obligation reference with no content hash. If a resolver may " +
			"report no hash, the reference's own must still be well-formed, or a reference with no " +
			"subject would pass both checks.")
	}
}

// TestTheProblemOrderIsStableAcrossRuns.
//
// The resolver is a caller-supplied map, and this error is read by a person comparing two
// runs — a diff that reorders is a diff nobody reads. The references are canonicalized by
// id, but the sort in CheckObligations is what makes the order independent of the
// resolver.
func TestTheProblemOrderIsStableAcrossRuns(t *testing.T) {
	render := func() string {
		p := sampleProfile(t)
		set := matchingSet(t, p)
		for id, f := range set {
			f.ContentSHA256 = strings.Repeat("e", 64)
			set[id] = f
		}
		p.Obligations[1].RevisionDetermination = nil
		err := p.CheckObligations(set)
		if err == nil {
			t.Fatal("test setup: the profile must disagree with the resolver")
		}
		return err.Error()
	}

	first := render()
	for i := 0; i < 8; i++ {
		if got := render(); got != first {
			t.Fatalf("the problem order changed between runs:\n%s\n\nvs\n\n%s", first, got)
		}
	}
	// And it is sorted by path, which is the order the document reads in.
	if strings.Index(first, "obligations[0]") > strings.Index(first, "obligations[1]") {
		t.Errorf("the problems are not in document order:\n%s", first)
	}
}

// TestAnUntrustedObligationIdCannotForgeALineOfTheReport is the same defense as
// validate's, asserted separately because CheckObligations builds its own messages out
// of the same attacker-controlled values.
func TestAnUntrustedObligationIdCannotForgeALineOfTheReport(t *testing.T) {
	p := sampleProfile(t)
	p.Obligations[0].ID = "x\n  - obligations[1].id: resolves fine"
	// Validate would refuse this id; CheckObligations is a separate call and must not
	// depend on having been preceded by one.
	err := p.CheckObligations(matchingSet(t, p))
	if err == nil {
		t.Fatal("CheckObligations resolved an id containing a newline")
	}
	if strings.Contains(err.Error(), "\n  - obligations[1].id: resolves fine") {
		t.Errorf("an obligation id forged a line of the report:\n%s", err.Error())
	}
}

// TestObligationSetReportsAbsenceRatherThanAZeroValue.
//
// "Unknown" and "known, with no facts" are different answers: the first is an
// unresolvable reference and the second would pass every check. A map lookup returning
// only the value would collapse them.
func TestObligationSetReportsAbsenceRatherThanAZeroValue(t *testing.T) {
	set := ObligationSet{"dfars-7012": {ID: "dfars-7012"}}
	if _, ok := set.Obligation("dfars-7012"); !ok {
		t.Error("a loaded profile reported as unknown")
	}
	if _, ok := set.Obligation("absent"); ok {
		t.Error("an absent profile reported as known; a zero-value ObligationFacts passes every " +
			"check, so collapsing unknown into it would turn an unresolvable reference into a clean one")
	}
	var empty ObligationSet
	if _, ok := empty.Obligation("dfars-7012"); ok {
		t.Error("a nil ObligationSet reported a profile as known")
	}
}
