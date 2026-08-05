// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// clone deep-copies a record.
//
// Round-tripped through JSON rather than field by field, for the reason
// artifact.clone gives: a hand-written deep copy silently misses a field added to
// the types later, and here that miss would be a canonicalization that mutated
// the caller's record through a shared pointer. Every pointer member below —
// Target, Artifact, Profile, Enforcement, Err, Custody — is one a shallow copy
// would share, and canonicalize writes through three of them.
func (r Record) clone() (Record, error) {
	raw, err := json.Marshal(&r)
	if err != nil {
		return Record{}, fmt.Errorf("copy record %d: %w", r.Sequence, err)
	}
	var dup Record
	if err := json.Unmarshal(raw, &dup); err != nil {
		return Record{}, fmt.Errorf("copy record %d: %w", r.Sequence, err)
	}
	return dup, nil
}

// canonicalize puts a record into the form its hash is defined over.
//
// The hash covers the record's *meaning*, not its bytes. Two records that say the
// same thing must hash the same, so:
//
//   - `outcome` is filled with its schema default. Without this, a record that
//     omits the field and one that spells out "success" would hash differently
//     while validating identically and reading identically, which makes a
//     mismatch un-diagnosable: the operator is told the chain is broken and every
//     visible field agrees.
//   - Set-valued members are sorted and deduped. The SCP ARNs a vend attached are
//     a set; the order the packer happened to return them in is not evidence.
//   - Empty collections become nil, so `[]` and absent hash the same.
//
// It does not touch RecordSHA or Signature: hashing omits both (see recordHash),
// so canonicalizing before hashing is well defined and a record can be signed
// after it is hashed without invalidating the chain.
func (r *Record) canonicalize() {
	if r.Outcome == "" {
		r.Outcome = OutcomeSuccess
	}
	if r.Enforcement.empty() {
		// An enforcement block asserting nothing is noise a reader has to rule
		// out, and dropping it here is what makes `&Enforcement{}` and nil the
		// same record.
		r.Enforcement = nil
	} else {
		r.Enforcement.SCPARNs = canonStrings(r.Enforcement.SCPARNs)
		r.Enforcement.ConfigRuleNames = canonStrings(r.Enforcement.ConfigRuleNames)
		r.Enforcement.RegionSet = canonStrings(r.Enforcement.RegionSet)
		r.Enforcement.ServiceSet = canonStrings(r.Enforcement.ServiceSet)
		r.Enforcement.AttestationIDs = canonStrings(r.Enforcement.AttestationIDs)
	}
	if r.Profile != nil {
		// Normalized to non-nil rather than to nil: the wire form has no omitempty
		// on this field, so nil would marshal as `null` and fail the schema, which
		// requires an array. The empty set is v1's answer and it must be written
		// as one.
		r.Profile.VerifiedSignatures = canonSignatures(r.Profile.VerifiedSignatures)
	}
	if r.Target != nil && *r.Target == (Target{}) {
		r.Target = nil
	}
}

// canonStrings sorts and dedupes, mapping empty to nil.
func canonStrings(in []string) []string {
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

// canonSignatures sorts by role then identity and dedupes, mapping nil to an
// empty non-nil slice.
//
// Non-nil for the reason ProfileRef.VerifiedSignatures documents: the field has no
// omitempty, so nil marshals as `null` where the schema requires an array. This
// is the one place in automat where an empty collection is deliberately *not*
// normalized to nil, because here the empty set is a recorded answer rather than
// an absent question.
func canonSignatures(in []VerifiedSignature) []VerifiedSignature {
	out := make([]VerifiedSignature, 0, len(in))
	seen := make(map[VerifiedSignature]bool, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		if out[i].Identity != out[j].Identity {
			return out[i].Identity < out[j].Identity
		}
		return out[i].VerifiedAgainst < out[j].VerifiedAgainst
	})
	return out
}

// CanonicalRecordJSON returns the exact bytes a record's hash is taken over: the
// canonicalized record with record_sha256 and signature omitted.
//
// Exported because `verify` recomputes it independently, and because a reader
// diagnosing a chain mismatch needs to be able to see what was hashed rather than
// be told two hex strings differ.
//
// The omissions are not an optimization. record_sha256 cannot cover itself, and
// omitting the signature is what lets a record be signed after it is hashed: the
// signature is over the hash, so including it would be circular.
func CanonicalRecordJSON(r Record) ([]byte, error) {
	// Deep copy: canonicalize writes through Enforcement, Profile, and Target, so
	// a shallow copy would edit the caller's record while claiming not to.
	dup, err := r.clone()
	if err != nil {
		return nil, err
	}
	dup.canonicalize()
	dup.RecordSHA = ""
	dup.Signature = nil
	b, cerr := artifact.CanonicalJSON(&dup)
	if cerr != nil {
		return nil, fmt.Errorf("canonicalize record %d: %w", r.Sequence, cerr)
	}
	return b, nil
}

// recordHash computes a record's record_sha256.
func recordHash(r Record) (string, error) {
	b, err := CanonicalRecordJSON(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ComputeRecordHash returns what a record's record_sha256 should be.
func ComputeRecordHash(r Record) (string, error) { return recordHash(r) }
