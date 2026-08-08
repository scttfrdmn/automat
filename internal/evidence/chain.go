// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrClosed is returned by Append against a manifest whose chain has already been
// ended by a custody-transfer record.
//
// A distinguished error rather than a generic one because the caller's correct
// response is specific: not retry, not park, but stop — the operator handed this
// account's custody to somebody else, and automat writing another record would be
// automat claiming to still manage it.
var ErrClosed = errors.New("the chain has been closed by a custody-transfer record")

// NewManifest starts a manifest with no records.
//
// createdAt is passed in rather than read from the clock: every timestamp in this
// package is a caller's parameter so that a test asserts on a fixed value and a
// golden file is stable. The command layer is the only place that reads a clock.
//
// Meta.GenesisSHA is left empty here and set by the first Append, not here: it is
// records[0].RecordSHA, and there is no records[0] yet. A manifest with zero records
// is not a valid document on its own — the schema requires at least one — so the gap
// between "constructed" and "has a genesis hash" is never externally visible.
func NewManifest(id, accountID, organizationID, createdAt string) *Manifest {
	return &Manifest{
		SchemaVersion: SchemaVersion,
		Meta: Meta{
			ID:             id,
			AccountID:      accountID,
			OrganizationID: organizationID,
			CreatedAt:      createdAt,
		},
	}
}

// Append canonicalizes rec, links it to the chain, hashes it, optionally signs
// it, and appends it.
//
// The caller supplies the record's content; Append owns Sequence, PreviousSHA,
// RecordSHA, and Signature, and overwrites whatever the caller put in them. That
// division is the point: a caller that could set its own sequence number or link
// could produce a chain that validates and lies, and every caller here is code
// that has just failed at something and is recording why.
//
// A record that would not validate is refused BEFORE it is appended. Validating
// after the fact would leave the invalid record in the chain — and since every
// later record's hash covers this one's, the only repair would be rewriting the
// tail, which is exactly the operation the chain exists to make detectable.
//
// signer may be nil, which produces an unsigned record. An unsigned local
// manifest is a valid document (schema/CHANGELOG.md): whether signatures are
// required is a policy decision above this package.
func (m *Manifest) Append(rec Record, signer Signer) (*Record, error) {
	if m.Closed() {
		return nil, fmt.Errorf("cannot append a %s record to manifest %s: %w — custody passed to %s "+
			"on %s. Appending would be automat claiming to still manage an account it handed over; "+
			"if custody came back, that is a new manifest, not a continuation of this one",
			rec.Operation, safe(m.Meta.ID), ErrClosed,
			safe(m.Last().Custody.Transferee), m.Last().Custody.EffectiveDate)
	}

	rec.Sequence = len(m.Records)
	if rec.Sequence == 0 {
		rec.PreviousSHA = ZeroHash
	} else {
		rec.PreviousSHA = m.Records[rec.Sequence-1].RecordSHA
	}
	// Canonicalize the stored record too, not just the copy that gets hashed.
	// Otherwise the record on disk differs from the record that was hashed, and a
	// reload would recanonicalize and agree — which works, and hides the fact that
	// the file and the hash were never the same document.
	dup, err := rec.clone()
	if err != nil {
		return nil, err
	}
	dup.canonicalize()
	rec = dup

	if rerr := m.refuseUnverifiedSignatures(&rec); rerr != nil {
		return nil, rerr
	}

	rec.RecordSHA = ""
	rec.Signature = nil
	h, err := recordHash(rec)
	if err != nil {
		return nil, err
	}
	rec.RecordSHA = h

	if signer != nil {
		sig, serr := signer.Sign([]byte(h))
		if serr != nil {
			return nil, fmt.Errorf("sign record %d of manifest %s: %w", rec.Sequence, safe(m.Meta.ID), serr)
		}
		rec.Signature = sig
	}

	// Validate the candidate in the chain it would join, then commit. The
	// append-then-check order would leave an invalid record behind whose only
	// repair is rewriting the tail.
	//
	// GenesisSHA is set here, on the candidate's Meta, when this is the first
	// record — never recomputed on a later append. Append owns it for the same
	// reason it owns Sequence and the links: a caller that could set its own
	// genesis anchor could produce a chain that validates and lies about where it
	// began (AUDIT-2 H3).
	candidateMeta := m.Meta
	if rec.Sequence == 0 {
		candidateMeta.GenesisSHA = h
	}
	candidate := &Manifest{SchemaVersion: m.SchemaVersion, Meta: candidateMeta,
		Records: append(append([]Record{}, m.Records...), rec)}
	if verr := candidate.Validate(); verr != nil {
		return nil, fmt.Errorf("refusing to append record %d to manifest %s: %w",
			rec.Sequence, safe(m.Meta.ID), verr)
	}

	m.Meta = candidateMeta
	m.Records = append(m.Records, rec)
	return &m.Records[len(m.Records)-1], nil
}

// refuseUnverifiedSignatures holds the writer to DESIGN §11a's honesty rule.
//
// automat performs no signature verification in v1, so it has nothing to put in
// verified_signatures and records the empty set. The schema cannot tell an entry
// automat checked from one written by hand — schema/CHANGELOG.md names that as a
// Go-side obligation of whatever writes records — so this is where the obligation
// is met.
//
// A record listing signatures it did not check manufactures assurance out of a
// document's own claims about itself, which is precisely the failure the role
// vocabulary exists to prevent. Refused at the writer rather than left to caller
// discipline: the tempting bug is a caller that copies the environment profile's
// own signatures list into
// this field because both are lists of the same shape, and it would produce
// records that validate and read exactly like verified ones.
//
// When verification lands, this function is what changes, and its replacement must
// take its input from a verifier rather than from a caller.
func (m *Manifest) refuseUnverifiedSignatures(rec *Record) error {
	if rec.EnvProfile == nil || len(rec.EnvProfile.VerifiedSignatures) == 0 {
		return nil
	}
	return fmt.Errorf("refusing to append record %d to manifest %s: it claims %d verified "+
		"attestation(s) over environment profile %s, and automat verifies nothing in this version — it "+
		"loads no "+
		"trust policy, resolves no key, and ships no trust anchor. The empty set is the honest and "+
		"only correct value here; attestations present in an environment profile but unverified must "+
		"not be copied "+
		"into a record, because a record listing signatures it did not check manufactures assurance "+
		"out of a document's own claims about itself (DESIGN §11a)",
		rec.Sequence, safe(m.Meta.ID), len(rec.EnvProfile.VerifiedSignatures), safe(rec.EnvProfile.ID))
}

// VerifyChain recomputes every record's hash, checks every link, and checks the
// chain-level invariants.
//
// Separate from Validate: Validate checks that the links are *consistent with each
// other*, which a tamperer who rewrites the tail can satisfy. VerifyChain checks
// that each record's stated hash is the hash of its own content, which is what
// makes an edit to a record's middle detectable at all. A manifest that passes
// Validate and fails VerifyChain has been edited in place.
//
// verifier may be nil, in which case signatures are not checked — but their
// presence still is not treated as meaning anything, per the package comment.
func (m *Manifest) VerifyChain(verifier Verifier) error {
	if err := m.Validate(); err != nil {
		return err
	}
	var p problems
	for i := range m.Records {
		r := m.Records[i]
		path := fmt.Sprintf("records[%d]", i)
		want, err := recordHash(r)
		if err != nil {
			return err
		}
		if r.RecordSHA != want {
			p.add(path+".record_sha256", fmt.Sprintf("is %s but the record's content hashes to %s",
				safe(r.RecordSHA), safe(want)),
				"this record was edited after it was written; the operation it describes is not the "+
					"one that was recorded. Compare its canonical form (evidence.CanonicalRecordJSON) "+
					"against the copy in the vended account's bucket or the management-side mirror")
			// Do not check this record's signature: it is over a hash that does not
			// belong to the content, so a "signature invalid" line here would send
			// the reader after the key rather than after the edit.
			continue
		}
		// A record with no signature is skipped rather than flagged, and that is
		// deliberate: an operator who adopts a signing key partway through has a
		// legitimately mixed chain (TestAMixedChainVerifiesTheSignedRecords). The
		// cost is that a DELETED signature is indistinguishable from one that was
		// never written, so an adversary who rewrites the file can also strip the
		// signatures they invalidated. That is why SignatureCoverage exists: the
		// leniency stays here, where it is right, and a caller who needs the stronger
		// property asks for it rather than inferring it from silence (AUDIT-2 H3).
		if verifier == nil || r.Signature == nil {
			continue
		}
		if err := verifier.Verify([]byte(r.RecordSHA), r.Signature); err != nil {
			p.add(path+".signature", fmt.Sprintf("does not verify: %v", err),
				"either the record was replaced wholesale — content and hash together, which the "+
					"chain links alone cannot detect — or this manifest was signed with a different "+
					"key than the one offered")
		}
	}
	if len(p.list) == 0 {
		return nil
	}
	return &ValidationError{
		Subject:  "evidence manifest " + safe(m.Meta.ID) + " chain",
		Problems: p.list,
	}
}

// SignatureCoverage reports how many records in the chain carry a signature, and
// which do not.
//
// # Why a report rather than a rule (AUDIT-2 H3)
//
// VerifyChain skips an unsigned record, for a reason that is right and that is not
// being revisited: a chain signed from record 3 onward is what an operator who adopted
// a key partway through legitimately has, and refusing it would refuse a correct
// document. But the consequence, reproduced during the audit, is that a signature can
// be REMOVED without a word — so a prefix-truncated chain whose now-invalid signatures
// were deleted verifies clean under the real verifier. Signing is offered in doc.go as
// the mitigation for truncation, and that mitigation does not hold if it can be taken
// off one record at a time in silence.
//
// The gap was never the leniency. It was that nothing let a reader ASK. A verifier
// that reports "no signature problems" over a chain with no signatures at all is
// telling the truth and answering a different question than the one being asked.
//
// So this counts. Signed is how many records carry a signature; Unsigned lists the
// indices that do not, in order. A caller that requires full coverage compares Signed
// against len(m.Records) and says which records are missing — that is a policy
// decision about a particular chain, which belongs to the caller, not to the format.
//
// Costs nothing and reads nothing: no hashing, no verification, no key. Whether a
// signature VERIFIES is VerifyChain's question; whether one is THERE is this one.
func (m *Manifest) SignatureCoverage() SignatureCoverageReport {
	rep := SignatureCoverageReport{Total: len(m.Records)}
	for i := range m.Records {
		if m.Records[i].Signature != nil {
			rep.Signed++
			continue
		}
		rep.Unsigned = append(rep.Unsigned, i)
	}
	return rep
}

// SignatureCoverageReport is what SignatureCoverage returns.
type SignatureCoverageReport struct {
	// Total is len(m.Records).
	Total int
	// Signed is how many carry a signature.
	Signed int
	// Unsigned holds the indices that do not, ascending. Nil when all are signed —
	// distinct from empty only in the way Go makes them distinct, and callers should
	// test Complete rather than this.
	Unsigned []int
}

// Complete reports whether every record in the chain carries a signature.
//
// A chain with no records is not complete: an empty manifest is refused by Validate
// anyway, and "vacuously fully signed" is the wrong answer to give a caller who asked
// whether the evidence is signed.
func (r SignatureCoverageReport) Complete() bool { return r.Total > 0 && r.Signed == r.Total }

// Describe renders the report for an operator, naming the unsigned records.
//
// One line, and it names the indices rather than saying "some records": a reader told
// that coverage is partial and not told where has to go count by hand, and the count
// is the thing that was just done for them.
func (r SignatureCoverageReport) Describe() string {
	switch {
	case r.Total == 0:
		return "the chain has no records"
	case r.Signed == 0:
		return fmt.Sprintf("none of the %d records are signed", r.Total)
	case r.Complete():
		return fmt.Sprintf("all %d records are signed", r.Total)
	}
	parts := make([]string, len(r.Unsigned))
	for i, ix := range r.Unsigned {
		parts[i] = strconv.Itoa(ix)
	}
	return fmt.Sprintf("%d of %d records are signed; records %s carry no signature, so nothing "+
		"about them is attested — and a signature that was removed does not read differently from "+
		"one that was never written",
		r.Signed, r.Total, strings.Join(parts, ", "))
}
