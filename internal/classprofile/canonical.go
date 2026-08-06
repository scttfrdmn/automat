// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package classprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Canonicalize puts the profile into the form its content hash is defined over.
//
// The hash covers the document's MEANING, not its bytes: two profiles describing the
// same institutional scheme must hash the same, so the orderings that carry no meaning
// are normalized away. That hash is what an environment profile's reference to a level
// will name, and what an attestation is over, so a profile that hashed differently
// after a round trip through disk would make every reference to it unfalsifiable.
//
// What IS sorted: Levels by rank, Controls by id within a level, external obligations
// by name, unmodeled axes by name, and the attestations.
//
// What is NOT sorted, and why each:
//
//   - Determination.Roles. The order is the institution's — UC lists Initiators,
//     Proprietors, Security SMEs, and UISLs in the order its own appendix does, which is
//     roughly the order an operator walks them. Sorting would alphabetize a sequence
//     someone chose.
//   - Level.Examples. These are the source's own examples in the source's own order, and
//     a reader checking them against the policy page reads down the list.
//   - Citations. The field's whole documented purpose is "in the order a reader should
//     follow them".
//   - Sources. Ordered to match Citations for the same reason.
//
// Levels are sorted by RANK rather than by id, which is the same decision Level.Rank
// exists to force: sorting by id would order Harvard's dsl1..dsl5 correctly and U-M's
// restricted/high/moderate/low exactly backwards, and the canonical form would then
// disagree with the document about which level is the top.
func (p *Profile) Canonicalize() {
	p.Levels = byRank(p.Levels)
	for i := range p.Levels {
		l := &p.Levels[i]
		sort.SliceStable(l.Controls, func(a, b int) bool { return l.Controls[a].ID < l.Controls[b].ID })
		if len(l.Controls) == 0 {
			// Absent and empty are the same claim here: a level with no published
			// controls. Unlike an environment profile's permitted sets, an empty control
			// list asserts nothing dangerous — the source was silent — so collapsing it
			// makes `[]` and absent one document.
			l.Controls = nil
		}
		sort.SliceStable(l.ExternalObligations, func(a, b int) bool {
			return l.ExternalObligations[a].Name < l.ExternalObligations[b].Name
		})
		if len(l.ExternalObligations) == 0 {
			l.ExternalObligations = nil
		}
		if len(l.Examples) == 0 {
			l.Examples = nil
		}
	}

	sort.SliceStable(p.UnmodeledAxes, func(a, b int) bool {
		return p.UnmodeledAxes[a].Name < p.UnmodeledAxes[b].Name
	})
	if len(p.UnmodeledAxes) == 0 {
		p.UnmodeledAxes = nil
	}
	if len(p.Determination.Roles) == 0 {
		p.Determination.Roles = nil
	}
	if len(p.Citations) == 0 {
		p.Citations = nil
	}
	if len(p.Sources) == 0 {
		p.Sources = nil
	}
	p.Signatures = canonSignatures(p.Signatures)
}

// byRank returns the levels ordered least protective first, without mutating the input.
func byRank(in []Level) []Level {
	if len(in) == 0 {
		return nil
	}
	out := make([]Level, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rank < out[j].Rank })
	return out
}

// canonSignatures sorts and dedupes the attestation list.
//
// Sorted by the whole entry rather than by identity, for the reason envprofile's
// equivalent gives: one identity may legitimately attest twice in two capacities, and
// keying on identity alone would drop the second. Two entries identical in every field
// are one attestation, which is what Validate's duplicate check reports on.
func canonSignatures(in []Attestation) []Attestation {
	if len(in) == 0 {
		return nil
	}
	out := make([]Attestation, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, a := range in {
		k, err := signatureKey(a)
		if err != nil {
			// Unhashable is not possible for this shape; fall back to keeping the entry
			// rather than silently dropping an attestation.
			out = append(out, a)
			continue
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ki, _ := signatureKey(out[i])
		kj, _ := signatureKey(out[j])
		return ki < kj
	})
	return out
}

func signatureKey(a Attestation) (string, error) {
	b, err := artifact.CanonicalJSON(a)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// contentPayload is the part of a profile the content hash covers.
//
// An explicit struct rather than hashing *Profile with metadata blanked, so that adding
// a field to Profile is a DECISION about hash coverage rather than a default.
// HashCoveredFields and HashExcludedFields, asserted against this struct by reflection
// in the tests, are what make forgetting that decision a build failure rather than a
// silent gap.
type contentPayload struct {
	Issuer         Issuer            `json:"issuer"`
	Status         Status            `json:"status"`
	ReviewBy       string            `json:"review_by"`
	Authorship     Authorship        `json:"authorship"`
	Maintenance    Maintenance       `json:"maintenance"`
	Interpretation *Interpretation   `json:"interpretation,omitempty"`
	Determination  Determination     `json:"determination"`
	Levels         []Level           `json:"levels"`
	Composition    Composition       `json:"composition"`
	Inherits       *Inherits         `json:"inherits,omitempty"`
	UnmodeledAxes  []UnmodeledAxis   `json:"unmodeled_axes,omitempty"`
	Citations      []Citation        `json:"citations"`
	PolicyCaveat   string            `json:"policy_caveat"`
	Sources        []HashedReference `json:"sources"`
}

// HashCoveredFields names the Profile fields ContentHash covers, by Go field name.
//
// Wider than the environment profile's coverage, and deliberately so. That document is
// hashed over what it BUILDS, so its identity block sits outside. This one makes no
// changes to anything; its entire content is a set of claims about a published policy,
// and there is no field here whose alteration leaves the claims intact. Issuer,
// Authorship, Maintenance, Interpretation, and PolicyCaveat are each covered because
// each is a way to change what the document asserts about whose policy this is and what
// kind of claim it makes.
var HashCoveredFields = []string{
	"Issuer", "Status", "ReviewBy", "Authorship", "Maintenance", "Interpretation",
	"Determination", "Levels", "Composition", "Inherits", "UnmodeledAxes",
	"Citations", "PolicyCaveat", "Sources",
}

// HashExcludedFields names the Profile fields the content hash deliberately does NOT
// cover, with the reason each is safe to exclude.
//
//   - SchemaVersion: a version bump that changed the meaning of the covered fields
//     would change their encoding too, and Validate rejects a major this build does not
//     understand before any hash is consulted.
//   - Meta: the id and title identify the document rather than stating what it claims.
//     Excluding them means a department that forks a profile and retitles it does not
//     invalidate the interpreter's attestation over the reading itself — which is the
//     behavior "example-and-forkable" is for. Note that ISSUER is covered, so the fork
//     can be retitled but not reattributed.
//   - Signatures: an attestation is over the content hash, so covering it would make the
//     hash cover itself. This is also what lets a second identity attest without
//     invalidating the first's signature.
var HashExcludedFields = []string{"SchemaVersion", "Meta", "Signatures"}

// CanonicalContentJSON returns the canonical JSON encoding of the profile's hashed
// content: the exact byte sequence ContentHash covers.
//
// Exported because a reference to a level and any future verification path recompute it
// independently of the surrounding document — the whole point is that the same content
// yields the same hash regardless of who is holding it.
func (p *Profile) CanonicalContentJSON() ([]byte, error) {
	dup, err := p.clone()
	if err != nil {
		return nil, err
	}
	dup.Canonicalize()
	return artifact.CanonicalJSON(contentPayload{
		Issuer:         dup.Issuer,
		Status:         dup.Status,
		ReviewBy:       dup.ReviewBy,
		Authorship:     dup.Authorship,
		Maintenance:    dup.Maintenance,
		Interpretation: dup.Interpretation,
		Determination:  dup.Determination,
		Levels:         dup.Levels,
		Composition:    dup.Composition,
		Inherits:       dup.Inherits,
		UnmodeledAxes:  dup.UnmodeledAxes,
		Citations:      dup.Citations,
		PolicyCaveat:   dup.PolicyCaveat,
		Sources:        dup.Sources,
	})
}

// ContentHash returns the SHA-256 of the canonicalized content payload.
//
// There is no SetContentHash and no content_sha256 field on the document, for the
// reason an environment profile has none: a self-declared hash is a field every editor
// has to remember to recompute, which in practice means a field that is wrong. The
// consumers that need it compute it, and an attestation states which hash it is over.
func (p *Profile) ContentHash() (string, error) {
	b, err := p.CanonicalContentJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyAttestationSubjects checks that every attestation names this document's content
// hash as its subject.
//
// Separate from Validate because it is a cross-field consistency check no schema can
// express, and because Validate must be callable on a document whose hash has not been
// computed yet. An attestation over some other hash is an error rather than a warning:
// it is either an attestation moved from a different document, or a document edited
// under an attestation that still looks valid, and neither is something to report as a
// note.
//
// The stakes are higher here than on an environment profile. What a derived
// classification profile's attestation vouches for is the non-endorsement statement and
// the citations — so an attestation that survived an edit would be an `interpreted-by`
// signature sitting on a reading it was never made about.
func (p *Profile) VerifyAttestationSubjects() error {
	if len(p.Signatures) == 0 {
		return nil
	}
	want, err := p.ContentHash()
	if err != nil {
		return err
	}
	var probs problems
	for i, a := range p.Signatures {
		if a.ContentSHA256 == want {
			continue
		}
		probs.add(fmt.Sprintf("signatures[%d].content_sha256", i),
			fmt.Sprintf("is %s but this document's content hashes to %s", safe(a.ContentSHA256), want),
			"the attestation is over a different document — either it was copied from one, or this "+
				"document was edited after it was attested to. Re-attest the current content, or "+
				"remove the entry; an attestation whose subject does not match is not a weaker "+
				"attestation, it is one about something else")
	}
	if len(probs.list) == 0 {
		return nil
	}
	return &ValidationError{Subject: p.subject(), Problems: probs.list}
}

// clone deep-copies the profile.
//
// Round-tripped through JSON rather than field by field, for the reason envprofile's
// clone gives: a hand-written deep copy silently misses a field added later, and here
// that miss would be a canonicalization that mutated the caller's profile through a
// shared pointer. Interpretation, Inherits, and four citation pointers are all
// references a shallow copy would share.
func (p *Profile) clone() (*Profile, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("copy classification profile: %w", err)
	}
	var dup Profile
	if err := json.Unmarshal(raw, &dup); err != nil {
		return nil, fmt.Errorf("copy classification profile: %w", err)
	}
	return &dup, nil
}

// MarshalIndented renders the profile in the human-reviewable indented form, which is
// the only form anyone should be writing one in.
func (p *Profile) MarshalIndented() ([]byte, error) {
	p.Canonicalize()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal classification profile: %w", err)
	}
	return append(data, '\n'), nil
}
