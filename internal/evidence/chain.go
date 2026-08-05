// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"errors"
	"fmt"
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
	candidate := &Manifest{SchemaVersion: m.SchemaVersion, Meta: m.Meta,
		Records: append(append([]Record{}, m.Records...), rec)}
	if verr := candidate.Validate(); verr != nil {
		return nil, fmt.Errorf("refusing to append record %d to manifest %s: %w",
			rec.Sequence, safe(m.Meta.ID), verr)
	}

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
// discipline: the tempting bug is a caller that copies profile.signatures into
// this field because both are lists of the same shape, and it would produce
// records that validate and read exactly like verified ones.
//
// When verification lands, this function is what changes, and its replacement must
// take its input from a verifier rather than from a caller.
func (m *Manifest) refuseUnverifiedSignatures(rec *Record) error {
	if rec.Profile == nil || len(rec.Profile.VerifiedSignatures) == 0 {
		return nil
	}
	return fmt.Errorf("refusing to append record %d to manifest %s: it claims %d verified "+
		"attestation(s) over profile %s, and automat verifies nothing in this version — it loads no "+
		"trust policy, resolves no key, and ships no trust anchor. The empty set is the honest and "+
		"only correct value here; attestations present in a profile but unverified must not be copied "+
		"into a record, because a record listing signatures it did not check manufactures assurance "+
		"out of a document's own claims about itself (DESIGN §11a)",
		rec.Sequence, safe(m.Meta.ID), len(rec.Profile.VerifiedSignatures), safe(rec.Profile.ID))
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
