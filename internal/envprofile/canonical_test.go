// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package envprofile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/evidence"
)

// TestTheHashCoversMeaningRatherThanBytes is the property the evidence chain rests on:
// two profiles that vend the same account hash the same.
//
// If a round trip through disk changed the hash, every evidence record naming a profile
// would be unfalsifiable — `verify` years later would report drift on a document nobody
// touched, and an operator who saw that once would stop believing the next report.
func TestTheHashCoversMeaningRatherThanBytes(t *testing.T) {
	hashOf := func(t *testing.T, p *Profile) string {
		t.Helper()
		h, err := p.ContentHash()
		if err != nil {
			t.Fatalf("ContentHash: %v", err)
		}
		return h
	}

	// Both spellings are stated, rather than one mutator against the fixture, because
	// half these cases are about `[]`-versus-absent and the fixture happens to carry a
	// populated value — so "the other spelling" has to be written down explicitly for
	// the comparison to be the one the case name claims.
	cases := []struct {
		name    string
		why     string
		one     func(*Profile)
		another func(*Profile)
	}{
		{
			name: "control sets in a different order",
			why:  "compiling by union has no order, so two spellings of one list are one claim",
			one:  func(p *Profile) { p.ControlSets = []string{"cmmc-l1", "campus-base"} },
			another: func(p *Profile) {
				p.ControlSets = []string{"campus-base", "cmmc-l1"}
			},
		},
		{
			name: "a control set listed twice",
			why: "the union is the same; Validate refuses the document separately, and the hash must " +
				"not be the thing that notices",
			one:     func(p *Profile) { p.ControlSets = []string{"cmmc-l1", "campus-base"} },
			another: func(p *Profile) { p.ControlSets = []string{"cmmc-l1", "campus-base", "cmmc-l1"} },
		},
		{
			name:    "permitted regions in a different order",
			why:     "an allowlist is a set",
			one:     func(p *Profile) { p.Permitted.Regions = []string{"us-east-1", "us-west-2"} },
			another: func(p *Profile) { p.Permitted.Regions = []string{"us-west-2", "us-east-1"} },
		},
		{
			name: "obligations in a different order",
			why:  "two references are two references regardless of which was typed first",
			one:  func(_ *Profile) {},
			another: func(p *Profile) {
				p.Obligations = []ObligationRef{p.Obligations[1], p.Obligations[0]}
			},
		},
		{
			name:    "baseline regions to enable in a different order",
			why:     "the Account Management calls are independent",
			one:     func(p *Profile) { p.Baseline.Regions.Enable = []string{"us-west-2", "eu-west-1"} },
			another: func(p *Profile) { p.Baseline.Regions.Enable = []string{"eu-west-1", "us-west-2"} },
		},
		{
			name: "an empty permitted block rather than an absent one",
			why: "a block asserting nothing is the same document as no block. Distinct from a SET " +
				"inside it being empty, which is a deny-all and is refused",
			one:     func(p *Profile) { p.Permitted = &Permitted{} },
			another: func(p *Profile) { p.Permitted = nil },
		},
		{
			name:    "an empty tag map rather than an absent one",
			why:     "no tags is no tags",
			one:     func(p *Profile) { p.Account.Tags = map[string]string{} },
			another: func(p *Profile) { p.Account.Tags = nil },
		},
		{
			name:    "an empty OU path rather than an absent one",
			why:     "an empty path ensures nothing",
			one:     func(p *Profile) { p.Placement.OUPath = []string{} },
			another: func(p *Profile) { p.Placement.OUPath = nil },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			one, another := sampleProfile(t), sampleProfile(t)
			tc.one(one)
			tc.another(another)

			if got, want := hashOf(t, another), hashOf(t, one); got != want {
				t.Errorf("%s changed the content hash.\n%s\n\nThe hash covers the document's MEANING: "+
					"two profiles that vend the same account must hash the same, or every evidence "+
					"record naming one is unfalsifiable.", tc.name, tc.why)
			}
		})
	}
}

// TestAPresentButEmptyPermittedSetHashesDifferentlyFromAnAbsentOne is the other half.
//
// Normalizing member order is right; normalizing a deny-all into "no boundary" is not.
// `keepEmpty` exists for exactly this, and the reason it is asserted rather than trusted
// is that both fields carry `omitempty` — the clone inside CanonicalContentJSON round
// trips through JSON, so a naive implementation would silently produce the absent form's
// hash for a document that denies everything.
func TestAPresentButEmptyPermittedSetHashesDifferentlyFromAnAbsentOne(t *testing.T) {
	absent := sampleProfile(t)
	absent.Permitted = nil
	absentHash, err := absent.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}

	for _, tc := range []struct {
		name      string
		permitted *Permitted
	}{
		{"an empty region set", &Permitted{Regions: []string{}}},
		{"an empty service set", &Permitted{Services: []string{}}},
		{"both sets empty", &Permitted{Regions: []string{}, Services: []string{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denyAll := sampleProfile(t)
			denyAll.Permitted = tc.permitted
			got, cerr := denyAll.ContentHash()
			if cerr != nil {
				t.Fatalf("ContentHash: %v", cerr)
			}
			if got == absentHash {
				t.Errorf("%s hashes the same as an absent permitted block. Those are opposite claims: "+
					"absent adds no boundary, present-and-empty denies every call in the account. A "+
					"document that bricks an account must not hash as one that constrains nothing.",
					tc.name)
			}
		})
	}
}

// TestCanonicalizePreservesThePresentButEmptyDistinction is the same rule one layer
// down, where it is easiest to lose.
//
// Canonicalization runs BEFORE Write validates, so collapsing empty to nil here would
// launder the error away and produce a document on disk that hashes as one which
// constrained nothing. Load's ordering (validate, then canonicalize) means the refusal
// cannot depend on this — but the two are separate defenses on purpose, and this is the
// one Write depends on.
func TestCanonicalizePreservesThePresentButEmptyDistinction(t *testing.T) {
	p := sampleProfile(t)
	p.Permitted = &Permitted{Regions: []string{}, Services: []string{"s3", "s3"}}
	p.Canonicalize()

	if p.Permitted == nil {
		t.Fatal("Canonicalize dropped a permitted block containing an empty set. That launders a " +
			"deny-all into 'no boundary', and Write would then produce a document nobody wrote.")
	}
	if p.Permitted.Regions == nil {
		t.Error("Canonicalize turned a present-but-empty region set into an absent one")
	}
	if len(p.Permitted.Regions) != 0 {
		t.Errorf("Canonicalize invented %v out of an empty set", p.Permitted.Regions)
	}
	if got := strings.Join(p.Permitted.Services, ","); got != "s3" {
		t.Errorf("services = %q, want the deduped set %q", got, "s3")
	}
	if err := p.Validate(); err == nil {
		t.Error("Validate accepted the canonicalized deny-all; the distinction was preserved for " +
			"nothing if the refusal does not follow it")
	}
}

// TestCanonicalizeDropsABlockThatAssertsNothing distinguishes the block being empty from
// a set inside it being empty. Those are different claims and the first one is harmless.
func TestCanonicalizeDropsABlockThatAssertsNothing(t *testing.T) {
	t.Run("permitted", func(t *testing.T) {
		p := sampleProfile(t)
		p.Permitted = &Permitted{}
		p.Canonicalize()
		if p.Permitted != nil {
			t.Errorf("an empty permitted block survived canonicalization as %+v; `{}` and absent are "+
				"the same document and must hash the same", p.Permitted)
		}
	})
	t.Run("baseline regions", func(t *testing.T) {
		p := sampleProfile(t)
		p.Baseline.Regions = &BaselineRegions{}
		p.Canonicalize()
		if p.Baseline.Regions != nil {
			t.Errorf("an empty baseline.regions block survived as %+v", p.Baseline.Regions)
		}
	})
	t.Run("obligations", func(t *testing.T) {
		p := sampleProfile(t)
		p.Obligations = []ObligationRef{}
		p.Canonicalize()
		if p.Obligations != nil {
			t.Errorf("an empty obligation list survived as %+v", p.Obligations)
		}
	})
}

// TestCanonicalizeDoesNotSortWhatOrderMeans.
//
// An OU path is a path from outermost to innermost, so sorting it rearranges the tree —
// and the account would land somewhere the document does not describe. Obligations sort
// by id rather than by whole value, so two determinations for one obligation cannot be
// reordered into a different reading.
func TestCanonicalizeDoesNotSortWhatOrderMeans(t *testing.T) {
	p := sampleProfile(t)
	p.Placement.OUPath = []string{"Zoology", "Anatomy"}
	before := strings.Join(p.Placement.OUPath, "/")
	p.Canonicalize()
	if got := strings.Join(p.Placement.OUPath, "/"); got != before {
		t.Errorf("Canonicalize reordered the OU path to %q from %q. The order IS the meaning: it is "+
			"a path outermost-first, and sorting it puts the account somewhere the document does not "+
			"describe.", got, before)
	}
	if len(p.Placement.OUPath) != 2 {
		t.Errorf("OU path length changed to %d; a repeated OU name at two levels is a real tree",
			len(p.Placement.OUPath))
	}
}

// TestCanonicalizeIsIdempotent. `vend` canonicalizes, `verify` re-canonicalizes and
// compares hashes; a second pass that moved anything would report drift on a healthy
// account.
func TestCanonicalizeIsIdempotent(t *testing.T) {
	p := sampleProfile(t)
	p.Canonicalize()
	once, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p.Canonicalize()
	twice, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(once) != string(twice) {
		t.Errorf("a second canonicalization changed the document:\n%s\n\nvs\n\n%s", once, twice)
	}
}

// TestCanonicalizeKeepsOneIdentityAttestingTwice.
//
// Deduping on identity would drop the second entry, and the two are different claims:
// "we wrote this" and "we use this" are exactly what the role vocabulary exists to keep
// apart. Only entries identical in EVERY field are one attestation.
func TestCanonicalizeKeepsOneIdentityAttestingTwice(t *testing.T) {
	p := sampleProfile(t)
	first := p.Signatures[0]
	second := first
	second.Role = evidence.RoleAuthoredBy
	second.Statement = "Research Computing wrote this document."
	third := first // identical to first in every field
	p.Signatures = []Attestation{first, second, third}

	p.Canonicalize()

	if len(p.Signatures) != 2 {
		t.Fatalf("canonicalization left %d attestations, want 2: the exact duplicate collapses and "+
			"the second capacity survives", len(p.Signatures))
	}
	roles := map[evidence.Role]bool{}
	for _, a := range p.Signatures {
		roles[a.Role] = true
	}
	if !roles[evidence.RoleAdoptedBy] || !roles[evidence.RoleAuthoredBy] {
		t.Errorf("roles present: %v; one identity attesting in two capacities must keep both — "+
			"'we wrote this' and 'we use this' are the distinction the vocabulary exists for", roles)
	}
}

// TestCanonicalContentJSONExcludesTheDocumentsOwnIdentity is the byte-level check behind
// the exclusion list: the hashed payload must not carry schema_version, the meta block,
// or the signatures.
//
// Asserted on the bytes rather than only through hash equality, because a payload that
// carried a field whose value happened to be stable would pass the hash test and still
// be wrong the first time someone renamed a profile.
func TestCanonicalContentJSONExcludesTheDocumentsOwnIdentity(t *testing.T) {
	p := sampleProfile(t)
	data, err := p.CanonicalContentJSON()
	if err != nil {
		t.Fatalf("CanonicalContentJSON: %v", err)
	}
	var payload map[string]any
	if uerr := json.Unmarshal(data, &payload); uerr != nil {
		t.Fatalf("the canonical payload is not JSON: %v", uerr)
	}

	for _, key := range []string{"schema_version", "environment_profile", "signatures"} {
		if _, present := payload[key]; present {
			t.Errorf("the hashed payload carries %q, which HashExcludedFields says it does not. "+
				"Covering it would mean renaming a profile invalidates every attestation over it, "+
				"or that a second identity cannot attest without breaking the first's signature.", key)
		}
	}
	for _, key := range []string{"review_by", "control_sets", "placement", "baseline"} {
		if _, present := payload[key]; !present {
			t.Errorf("the hashed payload is missing %q, which decides what gets built", key)
		}
	}
}

// TestVerifyAttestationSubjectsAcceptsAFreshlyStampedDocument, and reports every stale
// entry rather than the first.
//
// An operator who re-attested one of three entries wants to know about the other two in
// one run; a validator that stops at the first turns that into three runs, and the third
// is the one they skip.
func TestVerifyAttestationSubjectsAcceptsAFreshlyStampedDocument(t *testing.T) {
	p := sampleProfile(t)
	if err := p.VerifyAttestationSubjects(); err != nil {
		t.Fatalf("a document whose attestations name its own hash must verify:\n%v", err)
	}

	t.Run("no attestations is not a failure", func(t *testing.T) {
		q := sampleProfile(t)
		q.Signatures = nil
		if err := q.VerifyAttestationSubjects(); err != nil {
			t.Errorf("an unsigned profile must verify — automat ships no trust anchor and cosigning "+
				"is optional:\n%v", err)
		}
	})

	t.Run("every stale entry is reported", func(t *testing.T) {
		q := sampleProfile(t)
		base := q.Signatures[0]
		q.Signatures = nil
		for i := 0; i < 3; i++ {
			a := base
			a.Identity = "Office " + string(rune('A'+i))
			a.ContentSHA256 = strings.Repeat(string(rune('a'+i)), 64)
			q.Signatures = append(q.Signatures, a)
		}
		err := q.VerifyAttestationSubjects()
		ve, ok := AsValidationError(err)
		if !ok {
			t.Fatalf("want a *ValidationError, got %T: %v", err, err)
		}
		if len(ve.Problems) != 3 {
			t.Errorf("reported %d problems, want 3; an operator re-attesting wants the whole list in "+
				"one run", len(ve.Problems))
		}
	})
}

// TestEditingAHashedFieldStrandsTheAttestations is the mechanism DESIGN §11a is for,
// asserted end to end rather than field by field.
//
// Extending a review date is the case it was written about: ReviewBy is inside the hash,
// so a document whose review date was pushed out no longer matches the attestation that
// vouched for it, and the operator is told rather than left with a document that reads
// as freshly approved.
func TestEditingAHashedFieldStrandsTheAttestations(t *testing.T) {
	p := sampleProfile(t)
	if err := p.VerifyAttestationSubjects(); err != nil {
		t.Fatalf("test setup: %v", err)
	}

	p.ReviewBy = "2099-01-01"
	if err := p.VerifyAttestationSubjects(); err == nil {
		t.Error("extending review_by left the attestations verifying. The date is inside the hash on " +
			"purpose (DESIGN §11a): a profile whose re-reading was quietly deferred must not keep " +
			"looking like one somebody stood behind.")
	}
}

// TestCloneDoesNotShareStateWithItsSource.
//
// clone round-trips through JSON rather than copying field by field, because a
// hand-written deep copy silently misses a field added later — and the miss here would
// be a canonicalization mutating the CALLER's profile through a shared pointer. Permitted,
// Obligations, Account, and four members of Baseline are all pointers a shallow copy
// would share.
func TestCloneDoesNotShareStateWithItsSource(t *testing.T) {
	p := sampleProfile(t)
	dup, err := p.clone()
	if err != nil {
		t.Fatalf("clone: %v", err)
	}

	dup.Permitted.Regions[0] = "eu-west-1"
	dup.Obligations[0].ID = "rewritten"
	dup.Account.Tags["department"] = "rewritten"
	dup.Baseline.Regions.Enable[0] = "eu-west-1"
	dup.Baseline.AutomationRole.Name = "rewritten"
	dup.Placement.OUPath[0] = "rewritten"
	dup.Signatures[0].Identity = "rewritten"

	if p.Permitted.Regions[0] == "eu-west-1" {
		t.Error("the clone shares the permitted region slice")
	}
	if p.Obligations[0].ID == "rewritten" {
		t.Error("the clone shares the obligation list")
	}
	if p.Account.Tags["department"] == "rewritten" {
		t.Error("the clone shares the tag map")
	}
	if p.Baseline.Regions.Enable[0] == "eu-west-1" {
		t.Error("the clone shares baseline.regions.enable")
	}
	if p.Baseline.AutomationRole.Name == "rewritten" {
		t.Error("the clone shares the automation-role block")
	}
	if p.Placement.OUPath[0] == "rewritten" {
		t.Error("the clone shares the OU path")
	}
	if p.Signatures[0].Identity == "rewritten" {
		t.Error("the clone shares the attestation list")
	}
}

// TestContentHashDoesNotMutateItsReceiver. ContentHash is called by `verify`, by the
// evidence writer, and by Ref's caller, all on a profile someone else is still holding.
// A hash that canonicalized in place would make the second caller see what the first
// produced — and MarshalIndented, which does canonicalize deliberately, is a separate
// method for exactly that reason.
func TestContentHashDoesNotMutateItsReceiver(t *testing.T) {
	p := sampleProfile(t)
	before, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, herr := p.ContentHash(); herr != nil {
		t.Fatalf("ContentHash: %v", herr)
	}
	after, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("ContentHash canonicalized in place:\n%s\n\nvs\n\n%s", before, after)
	}
}
