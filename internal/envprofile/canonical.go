// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package envprofile

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
// The hash covers the document's MEANING, not its bytes: two profiles that vend
// the same account must hash the same, so member ordering, duplicate entries, and
// `[]`-versus-absent are all normalized away. That hash goes into the evidence
// manifest and into `verify`'s comparison years later, so a profile that hashed
// differently after a round trip through disk would make every record referencing
// it unfalsifiable.
//
// What is NOT sorted: OUPath, whose order is its meaning — it is a path from
// outermost to innermost, and sorting it would rearrange the tree. Likewise
// Obligations, which are sorted by id rather than by whole value, so that two
// determinations for one obligation cannot be reordered into a different reading.
func (p *Profile) Canonicalize() {
	p.ControlSets = sortedUnique(p.ControlSets)

	if p.Permitted != nil {
		// keepEmpty, not sortedUnique: a present-but-empty permitted set is a
		// DENY-ALL and a different claim from an absent one, and Validate rejects
		// it. Canonicalization runs before Write validates, so collapsing empty to
		// nil here would launder the error away and produce a document that hashes
		// as though it constrained nothing.
		p.Permitted.Regions = keepEmpty(p.Permitted.Regions)
		p.Permitted.Services = keepEmpty(p.Permitted.Services)
		if p.Permitted.Regions == nil && p.Permitted.Services == nil {
			// An empty block asserts nothing; dropping it makes `{}` and absent the
			// same document. Distinct from the case above: this is the BLOCK being
			// empty, not a set inside it being empty.
			p.Permitted = nil
		}
	}

	sort.SliceStable(p.Obligations, func(i, j int) bool { return p.Obligations[i].ID < p.Obligations[j].ID })
	if len(p.Obligations) == 0 {
		p.Obligations = nil
	}

	p.Signatures = canonSignatures(p.Signatures)

	if p.Placement.OUPath != nil && len(p.Placement.OUPath) == 0 {
		p.Placement.OUPath = nil
	}
	if r := p.Baseline.Regions; r != nil {
		r.Enable = sortedUnique(r.Enable)
		r.Disable = sortedUnique(r.Disable)
		if r.Home == "" && r.Enable == nil && r.Disable == nil {
			p.Baseline.Regions = nil
		}
	}
	if len(p.Account.tags()) == 0 && p.Account != nil {
		p.Account.Tags = nil
	}
}

// canonSignatures sorts and dedupes the attestation list.
//
// Sorted by the whole entry rather than by identity: one identity may legitimately
// attest twice in two capacities — authored-by and adopted-by — and keying on
// identity alone would drop the second. Two entries identical in every field are one
// attestation, which is what Validate's duplicate check reports on if any survive.
func canonSignatures(in []Attestation) []Attestation {
	if len(in) == 0 {
		return nil
	}
	out := make([]Attestation, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, a := range in {
		k, err := signatureKey(a)
		if err != nil {
			// Unhashable is not possible for this shape; fall back to keeping the
			// entry rather than silently dropping an attestation.
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

func (a *Account) tags() map[string]string {
	if a == nil {
		return nil
	}
	return a.Tags
}

// sortedUnique returns the input sorted with duplicates removed, or nil if the
// result would be empty — which is what makes `[]` and absent hash identically.
func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// keepEmpty is sortedUnique for the fields where present-but-empty and absent are
// DIFFERENT claims.
//
// A permitted set that is absent says this profile adds no boundary on that axis.
// A permitted set that is present and empty says nothing is permitted, which denies
// every call in the account. Both the schema's minItems and Validate reject the
// second, so canonicalization must not quietly turn it into the first and hide the
// error — the same discipline artifact.sortedUniqueKeepEmpty keeps for
// region_deny_exempt_services, and for the same reason.
func keepEmpty(in []string) []string {
	if in == nil {
		return nil
	}
	if out := sortedUnique(in); out != nil {
		return out
	}
	return []string{}
}

// contentPayload is the part of a profile the content hash covers.
//
// An explicit struct rather than hashing *Profile with metadata blanked, so that
// adding a field to Profile is a DECISION about hash coverage rather than a default.
// HashCoveredFields and HashExcludedFields, asserted against this struct by
// reflection in the tests, are what make forgetting that decision a build failure
// rather than a silent gap.
//
// Everything that decides what gets built is covered, and so is ReviewBy: DESIGN
// §11a requires it to sit inside the hash the attestations cover, so that extending
// a review date is a change no earlier attestation vouches for.
type contentPayload struct {
	ReviewBy    string          `json:"review_by"`
	ControlSets []string        `json:"control_sets"`
	Permitted   *Permitted      `json:"permitted,omitempty"`
	Obligations []ObligationRef `json:"obligations,omitempty"`
	Placement   Placement       `json:"placement"`
	Account     *Account        `json:"account,omitempty"`
	Baseline    Baseline        `json:"baseline"`
}

// HashCoveredFields names the Profile fields ContentHash covers, by Go field name.
var HashCoveredFields = []string{
	"ReviewBy", "ControlSets", "Permitted", "Obligations", "Placement", "Account", "Baseline",
}

// HashExcludedFields names the Profile fields the content hash deliberately does
// NOT cover, with the reason each is safe to exclude.
//
//   - SchemaVersion: a version bump that changed the meaning of the covered fields
//     would change their encoding too, and Validate rejects a major this build does
//     not understand before any hash is consulted.
//   - Meta: the id and title identify the document rather than describing what it
//     builds. Excluding them means renaming a profile does not invalidate the
//     attestations over it, which is the behavior an institution wants when a
//     department retitles a document it did not author. The id is bound to the hash
//     from the other direction anyway — an evidence record carries both.
//   - Signatures: an attestation is over the content hash, so covering it would make
//     the hash cover itself. This is also what lets a second identity attest to a
//     document without invalidating the first's signature.
var HashExcludedFields = []string{"SchemaVersion", "Meta", "Signatures"}

// CanonicalContentJSON returns the canonical JSON encoding of the profile's hashed
// content: the exact byte sequence ContentHash covers.
//
// Exported because `verify` and the evidence chain recompute it independently of the
// surrounding document — the whole point is that the same content yields the same
// hash regardless of who is holding it.
func (p *Profile) CanonicalContentJSON() ([]byte, error) {
	dup, err := p.clone()
	if err != nil {
		return nil, err
	}
	dup.Canonicalize()
	payload := contentPayload{
		ReviewBy:    dup.ReviewBy,
		ControlSets: dup.ControlSets,
		Permitted:   dup.Permitted,
		Obligations: dup.Obligations,
		Placement:   dup.Placement,
		Account:     dup.Account,
		Baseline:    dup.Baseline,
	}
	// Read the permitted sets off the ORIGINAL, for the reason
	// artifact.CanonicalContentJSON reads its exemption list off the original: the
	// clone round-trips through JSON and both fields carry omitempty, so a
	// present-but-empty set would not survive it and a deny-all document would hash
	// as one that constrained nothing.
	//
	// The `either set present` guard is what keeps this from overreaching in the other
	// direction. Canonicalize drops a block in which BOTH sets are absent, because `{}`
	// and no block at all are the same document; restoring a non-nil pointer here would
	// emit `"permitted": {}` and give those two different hashes. The distinction being
	// preserved is a SET that is present and empty, not a block that says nothing.
	if p.Permitted != nil && (p.Permitted.Regions != nil || p.Permitted.Services != nil) {
		payload.Permitted = &Permitted{
			Regions:  keepEmpty(p.Permitted.Regions),
			Services: keepEmpty(p.Permitted.Services),
		}
	}
	return artifact.CanonicalJSON(payload)
}

// ContentHash returns the SHA-256 of the canonicalized content payload.
//
// There is no SetContentHash and no content_sha256 field on the document: unlike a
// control artifact, an environment profile does not carry its own hash. It is a
// hand-written operator input, and a self-declared hash in one would be a field
// every editor has to remember to recompute — which in practice means a field that
// is wrong. The consumers that need the hash compute it: the evidence record names
// it, and an attestation states which hash it is over.
func (p *Profile) ContentHash() (string, error) {
	b, err := p.CanonicalContentJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyAttestationSubjects checks that every attestation names this document's
// content hash as its subject.
//
// Separate from Validate because it is a cross-field consistency check no schema can
// express, and because Validate must be callable on a document whose hash has not
// been computed yet. An attestation over some other hash is an error rather than a
// warning: it is either an attestation moved from a different document, or a
// document edited under an attestation that still looks valid, and neither is
// something to report as a note.
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
				"document was edited after it was attested to. Re-attest the current content, or remove "+
				"the entry; an attestation whose subject does not match is not a weaker attestation, it "+
				"is one about something else")
	}
	if len(probs.list) == 0 {
		return nil
	}
	return &ValidationError{Subject: p.subject(), Problems: probs.list}
}

// clone deep-copies the profile.
//
// Round-tripped through JSON rather than field by field, for the reason
// artifact.clone gives: a hand-written deep copy silently misses a field added
// later, and here that miss would be a canonicalization that mutated the caller's
// profile through a shared pointer. Permitted, Obligations, Account, and four
// members of Baseline are all pointers a shallow copy would share.
func (p *Profile) clone() (*Profile, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("copy environment profile: %w", err)
	}
	var dup Profile
	if err := json.Unmarshal(raw, &dup); err != nil {
		return nil, fmt.Errorf("copy environment profile: %w", err)
	}
	return &dup, nil
}

// MarshalIndented renders the profile in the human-reviewable indented form, which
// is the only form anyone should be writing one in.
func (p *Profile) MarshalIndented() ([]byte, error) {
	p.Canonicalize()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal environment profile: %w", err)
	}
	return append(data, '\n'), nil
}
