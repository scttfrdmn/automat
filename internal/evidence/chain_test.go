// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"strings"
	"testing"
)

// Fixed values throughout. Nothing here reads a clock or a random source: a test
// that did would either be flaky or would assert nothing about the hash it
// computed, and the hashes are the subject.
const (
	ts0       = "2026-08-05T00:00:00Z"
	ts1       = "2026-08-05T01:00:00Z"
	ts2       = "2026-08-05T02:00:00Z"
	acct      = "111122223333"
	operator  = "arn:aws:iam::111122223333:role/automat-operator"
	toolVer   = "0.1.0"
	someHash  = "1111111111111111111111111111111111111111111111111111111111111111"
	otherHash = "2222222222222222222222222222222222222222222222222222222222222222"
)

// newTestManifest is the header every case starts from.
func newTestManifest() *Manifest {
	return NewManifest(acct, acct, "o-abc1234567", ts0)
}

// vendRec is an ordinary successful record with the profile reference every record
// a vend writes must carry.
func vendRec(op Operation, timestamp string) Record {
	return Record{
		Timestamp: timestamp,
		Operation: op,
		Operator:  Operator{ARN: operator, AccountID: acct},
		RequestID: "req-abc123",
		Target:    &Target{AccountID: acct, OUID: "ou-abc1-12345678"},
		Artifact:  &DocRef{ID: "cmmc-l1", ContentSHA256: someHash, SchemaVersion: "1.0.0"},
		Profile: &ProfileRef{
			ID: "research-cui", ContentSHA256: otherHash, SchemaVersion: "1.0.0",
			ReviewBy: "2026-11-10", VerifiedSignatures: []VerifiedSignature{},
		},
		ToolVersion: toolVer,
	}
}

func mustAppend(t *testing.T, m *Manifest, rec Record, signer Signer) *Record {
	t.Helper()
	out, err := m.Append(rec, signer)
	if err != nil {
		t.Fatalf("Append(%s): %v", rec.Operation, err)
	}
	return out
}

func TestAppendLinksAndHashesTheChain(t *testing.T) {
	m := newTestManifest()
	r0 := mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	r1 := mustAppend(t, m, vendRec(OpSCPEnsure, ts1), nil)

	if r0.Sequence != 0 || r1.Sequence != 1 {
		t.Errorf("sequences are %d and %d, want 0 and 1", r0.Sequence, r1.Sequence)
	}
	if r0.PreviousSHA != ZeroHash {
		t.Errorf("records[0].previous_sha256 = %q, want 64 zeros: the first record links to nothing "+
			"and must say so distinguishably", r0.PreviousSHA)
	}
	if r1.PreviousSHA != r0.RecordSHA {
		t.Errorf("records[1].previous_sha256 = %q, want records[0].record_sha256 %q",
			r1.PreviousSHA, r0.RecordSHA)
	}
	if r0.RecordSHA == r1.RecordSHA {
		t.Error("two different records hash the same")
	}
	if err := m.VerifyChain(nil); err != nil {
		t.Errorf("a chain automat just wrote must verify:\n%v", err)
	}
}

// TestAppendOwnsTheLinkFields is the division of labour between caller and
// package, and it is a security property rather than a convenience: a caller that
// could set its own sequence number or previous hash could produce a chain that
// validates and lies, and every caller in Phase 2 is code that has just failed at
// something and is recording why.
func TestAppendOwnsTheLinkFields(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)

	lying := vendRec(OpSCPEnsure, ts1)
	lying.Sequence = 47
	lying.PreviousSHA = someHash
	lying.RecordSHA = otherHash

	got := mustAppend(t, m, lying, nil)
	if got.Sequence != 1 {
		t.Errorf("sequence = %d, want 1: Append owns it, and a caller-set sequence is a caller "+
			"that can renumber a chain", got.Sequence)
	}
	if got.PreviousSHA != m.Records[0].RecordSHA {
		t.Errorf("previous_sha256 = %q, want the predecessor's hash %q: a caller-set link is a "+
			"caller that can detach a record from its history", got.PreviousSHA, m.Records[0].RecordSHA)
	}
	if got.RecordSHA == otherHash {
		t.Error("record_sha256 was taken from the caller; a caller-supplied hash is a record " +
			"whose content and hash need never have matched")
	}
	if err := m.VerifyChain(nil); err != nil {
		t.Errorf("the chain must be sound despite the caller's values:\n%v", err)
	}
}

// TestAppendRefusesBeforeItCommits is why the validate-then-append order matters.
//
// Appending first and validating after would leave the invalid record in the
// chain, and since every later record's hash covers this one's, the only repair
// would be rewriting the tail — which is exactly the operation the chain exists to
// make detectable.
func TestAppendRefusesBeforeItCommits(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)

	bad := vendRec(OpSCPEnsure, "yesterday")
	if _, err := m.Append(bad, nil); err == nil {
		t.Fatal("Append accepted a record with a malformed timestamp")
	}
	if len(m.Records) != 1 {
		t.Errorf("the chain has %d records after a refused append, want 1: a refused record must "+
			"not be in the chain, because removing it later means rewriting every hash after it",
			len(m.Records))
	}
	if err := m.VerifyChain(nil); err != nil {
		t.Errorf("the chain must still verify after a refused append:\n%v", err)
	}
}

func TestAppendDoesNotMutateTheCallersRecord(t *testing.T) {
	m := newTestManifest()
	rec := vendRec(OpSCPEnsure, ts0)
	rec.Enforcement = &Enforcement{SCPARNs: []string{"arn:b", "arn:a", "arn:b"}}

	before := append([]string{}, rec.Enforcement.SCPARNs...)
	mustAppend(t, m, rec, nil)

	// Canonicalization sorts and dedupes the ARN list. If it did so through the
	// caller's pointer, a caller reusing the struct for a second record — which is
	// exactly what a resumed vend does — would find its own data rearranged.
	if len(rec.Enforcement.SCPARNs) != len(before) {
		t.Errorf("Append rewrote the caller's slice: %v, want %v", rec.Enforcement.SCPARNs, before)
	}
	if got := m.Records[0].Enforcement.SCPARNs; len(got) != 2 || got[0] != "arn:a" || got[1] != "arn:b" {
		t.Errorf("stored SCP ARNs = %v, want sorted and deduped [arn:a arn:b]", got)
	}
}

// TestTheStoredRecordIsTheRecordThatWasHashed catches a subtle version of the same
// bug: canonicalizing only the copy that gets hashed, and storing the caller's
// form. That works — a reload recanonicalizes and agrees — while leaving the file
// and the hash as different documents, which is a property a chain cannot afford
// to have "work by accident".
func TestTheStoredRecordIsTheRecordThatWasHashed(t *testing.T) {
	m := newTestManifest()
	rec := vendRec(OpBaselineApply, ts0)
	rec.Outcome = "" // omitted; the schema default is success
	rec.Enforcement = &Enforcement{}
	rec.Target = &Target{}
	stored := mustAppend(t, m, rec, nil)

	if stored.Outcome != OutcomeSuccess {
		t.Errorf("stored outcome = %q, want the filled default: the hash is over the canonical form, "+
			"so the stored form must be canonical too", stored.Outcome)
	}
	if stored.Enforcement != nil {
		t.Error("an enforcement block asserting nothing was stored; it perturbs nothing and is " +
			"noise a reader has to rule out")
	}
	if stored.Target != nil {
		t.Error("an empty target was stored")
	}
	// The load path is the real assertion: bytes out, bytes in, same hash.
	data, err := m.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	back, err := Decode(data, nil)
	if err != nil {
		t.Fatalf("a manifest automat just wrote must load: %v", err)
	}
	if back.Records[0].RecordSHA != stored.RecordSHA {
		t.Errorf("hash changed across a write and a read: %q then %q",
			stored.RecordSHA, back.Records[0].RecordSHA)
	}
}

// TestOmittingOutcomeAndSpellingItOutHashTheSame is the meaning-not-bytes property
// stated directly. Two documents that say the same thing must verify the same; a
// byte-level hash would report a mismatch on a record whose every visible field
// agrees, which is a diagnosis nobody can act on.
func TestOmittingOutcomeAndSpellingItOutHashTheSame(t *testing.T) {
	omitted := vendRec(OpVerify, ts0)
	omitted.Sequence, omitted.PreviousSHA = 0, ZeroHash

	explicit := omitted
	explicit.Outcome = OutcomeSuccess

	h1, err := ComputeRecordHash(omitted)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h2, err := ComputeRecordHash(explicit)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if h1 != h2 {
		t.Errorf("a record omitting outcome hashes to %s and one spelling out success hashes to %s; "+
			"they are the same record, and a mismatch here is one no operator could diagnose", h1, h2)
	}
}

// TestEnforcementSetOrderIsNotEvidence: the SCP ARNs a vend attached are a set.
// The order the packer happened to return them in is not part of what was
// recorded, and two runs that attached the same policies must produce the same
// hash.
func TestEnforcementSetOrderIsNotEvidence(t *testing.T) {
	a := vendRec(OpSCPEnsure, ts0)
	a.Sequence, a.PreviousSHA = 0, ZeroHash
	a.Enforcement = &Enforcement{
		SCPARNs:   []string{"arn:x", "arn:y", "arn:z"},
		RegionSet: []string{"us-east-1", "us-west-2"},
	}
	b := a
	b.Enforcement = &Enforcement{
		SCPARNs:   []string{"arn:z", "arn:x", "arn:y", "arn:x"},
		RegionSet: []string{"us-west-2", "us-east-1"},
	}

	h1, err := ComputeRecordHash(a)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h2, err := ComputeRecordHash(b)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if h1 != h2 {
		t.Errorf("the same attachments in a different order hash differently (%s vs %s)", h1, h2)
	}
}

// TestVerifyChainCatchesAnEditedRecord is the whole point of the structure.
//
// Note what is being tested: Validate checks that the links are consistent with
// each other, which an in-place edit does not disturb. VerifyChain recomputes each
// record's hash from its own content, which is what makes the edit visible.
func TestVerifyChainCatchesAnEditedRecord(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts1), nil)
	mustAppend(t, m, vendRec(OpBaselineApply, ts2), nil)

	// Change the artifact a middle record claims to have enforced, leaving every
	// link untouched. This is the interesting attack: the operator is told the
	// account was vended under a hash it was not.
	m.Records[1].Artifact.ContentSHA256 = otherHash

	if err := m.Validate(); err != nil {
		t.Fatalf("Validate must still pass — the links were not touched, and that is exactly why "+
			"VerifyChain has to exist separately:\n%v", err)
	}
	err := m.VerifyChain(nil)
	if err == nil {
		t.Fatal("VerifyChain accepted a record whose content was edited after it was hashed")
	}
	for _, want := range []string{"records[1].record_sha256", "edited after it was written"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must name the record and say what happened; %q missing from:\n%v",
				want, err)
		}
	}
}

func TestVerifyChainCatchesABrokenLink(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts1), nil)
	mustAppend(t, m, vendRec(OpBaselineApply, ts2), nil)

	// Remove the middle record and renumber, which is what dropping an
	// inconvenient operation from the record would look like.
	m.Records = []Record{m.Records[0], m.Records[2]}
	m.Records[1].Sequence = 1

	err := m.VerifyChain(nil)
	if err == nil {
		t.Fatal("VerifyChain accepted a chain with a record removed from the middle")
	}
	if !strings.Contains(err.Error(), "the chain is broken here") {
		t.Errorf("the error must say the chain is broken at that point:\n%v", err)
	}
}

func TestVerifyChainRefusesANonZeroFirstLink(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	m.Records[0].PreviousSHA = someHash

	err := m.VerifyChain(nil)
	if err == nil {
		t.Fatal("VerifyChain accepted a first record claiming a predecessor")
	}
	if !strings.Contains(err.Error(), "claims a predecessor this manifest does not contain") {
		t.Errorf("the error must say what the non-zero link claims:\n%v", err)
	}
}

// TestSequenceGapsAreRefused covers what the schema cannot: it constrains each
// sequence number in isolation, so it accepts a chain numbered 0, 0, 7.
func TestSequenceGapsAreRefused(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts1), nil)
	m.Records[1].Sequence = 7

	err := m.Validate()
	if err == nil {
		t.Fatal("Validate accepted a sequence number that does not match the record's position")
	}
	if !strings.Contains(err.Error(), "sequence numbers run 0..n-1") {
		t.Errorf("the error must state the rule:\n%v", err)
	}
}

// TestClockStepsBackwardsAreNotTampering: an NTP correction between two vends
// moves a timestamp backwards, and a validator that refused it would make archived
// manifests unreadable for a reason unrelated to their integrity. Order comes from
// the links, not the clock.
func TestClockStepsBackwardsAreNotTampering(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts2), nil)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts0), nil)

	if err := m.VerifyChain(nil); err != nil {
		t.Errorf("a chain whose second record carries an earlier timestamp must still verify — "+
			"order is the links, and a clock correction is not an edit:\n%v", err)
	}
}
