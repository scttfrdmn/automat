// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The manifest header bound to the records it labels (AUDIT-2 H4, M1).
//
// Three attacks and one misfiling: header relabelling, signed-record transplant, prefix
// truncation, and LoadOrNew adopting another account's chain. Each also asserts the
// legitimate shape still loads, because a validator that refuses everything is not a
// fix. TestPrefixTruncationIsRefused documents an OPEN finding rather than a closed one
// — read its comment before changing it.

// tempDir opens an evidence Dir under a fresh temp base, returning both because the
// tests here plant files by path as well as going through the Dir.
func tempDir(t *testing.T) (string, *Dir) {
	t.Helper()
	base := t.TempDir()
	dir, err := OpenDir(base, "evidence")
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return base, dir
}

const otherAcct = "999988887777"

// H4a — relabelling. The whole manifest is renamed to a different account without
// touching a single record, hash, or signature.
func TestHeaderRelabellingIsRefused(t *testing.T) {
	signer := testSigner(t)
	m := storeManifest(t, signer)
	before := m.Records[len(m.Records)-1].RecordSHA

	m.Meta.ID = otherAcct
	m.Meta.AccountID = otherAcct
	m.Meta.OrganizationID = "o-zzz9999999"

	if got := m.Records[len(m.Records)-1].RecordSHA; got != before {
		t.Fatalf("the relabelling disturbed a record hash (%s -> %s), so this is not the attack "+
			"the finding describes", before, got)
	}
	raw, err := m.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := Decode(raw, signer.Verifier()); err == nil {
		t.Fatal("a manifest relabelled to another account was accepted, with every hash and every " +
			"signature intact")
	} else {
		if !strings.Contains(err.Error(), otherAcct) {
			t.Errorf("the refusal does not name the header's account: %v", err)
		}
		t.Logf("refused: %v", err)
	}
}

// H4b — transplant. records[0] of one manifest, signed, moved into another manifest
// whose header names a different account. The signature is over bytes that never
// mentioned an account, so it verifies; the header binding is what refuses it.
func TestSignedRecordTransplantIsRefused(t *testing.T) {
	signer := testSigner(t)
	donor := storeManifest(t, signer)

	host := NewManifest(otherAcct, otherAcct, "o-zzz9999999", ts0)
	host.Records = []Record{donor.Records[0]}
	host.Records[0].Sequence = 0
	host.Records[0].PreviousSHA = ZeroHash

	raw, err := host.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := Decode(raw, signer.Verifier()); err == nil {
		t.Fatal("a signed record transplanted into another account's manifest was accepted")
	} else {
		t.Logf("refused: %v", err)
	}
	// And the signature really does still verify, which is the point: this is not
	// caught by any amount of key hygiene.
	if verr := host.VerifyChain(signer.Verifier()); verr != nil {
		t.Logf("note: VerifyChain also objects (%v) — the header binding is not the only guard here", verr)
	} else {
		t.Log("confirmed: the transplanted signature verifies; only the header binding refuses it")
	}
}

// H4c — prefix truncation. FIXED for the case where the header survives unedited,
// via manifest.genesis_sha256 (AUDIT-2 H3's resolution); NOT fixed against a rewrite
// that edits the header alongside the records. Four parts:
//
//  1. An unsigned truncated chain, header UNCHANGED, is now refused: the genesis
//     anchor no longer matches the re-anchored records[0].
//  2. created_at does NOT catch it on its own — the hoped-for anchor before
//     genesis_sha256 existed — because after the truncation created_at still
//     precedes the surviving first record. Kept as a fact about that field, not as
//     the mechanism that closes this.
//  3. A SIGNED truncated chain is caught by the links alone, and stripping the
//     signatures defeats THAT, which is what SignatureCoverage is for noticing.
//  4. The residual: an unsigned chain whose header is rewritten ALONGSIDE the
//     truncation — genesis_sha256 recomputed to match the new records[0] — still
//     loads. The header sits outside every record hash by design (H4), so an editor
//     who touches both is internally consistent again. This is the gap Q21 names.
func TestPrefixTruncationIsRefused(t *testing.T) {
	m := storeManifest(t, nil)
	mustAppend(t, m, vendRec(OpBaselineApply, "2026-08-05T02:00:00Z"), nil)
	if len(m.Records) != 3 {
		t.Fatalf("setup wanted 3 records, got %d", len(m.Records))
	}

	m.Records = m.Records[1:]
	relink(t, m)

	// The chain-level checks pass on their own — sequence density, links, and
	// terminality are all intact after the re-anchor. Head truncation was never a
	// chain-level defect; it is a header-level one, which is why closing it needed a
	// header field rather than a chain-level check.
	var chainOnly problems
	m.validateChain(&chainOnly)
	if len(chainOnly.list) != 0 {
		t.Fatalf("the truncated chain fails a chain-level check (%v), so created_at is not the only "+
			"thing standing between it and acceptance — the counter-check is not exercising the finding",
			chainOnly.list)
	}
	t.Log("confirmed: sequence, links, and terminality all pass on the truncated chain")

	raw, err := m.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, derr := Decode(raw, nil); derr == nil {
		t.Fatal("a prefix-truncated chain with its ORIGINAL header was accepted; genesis_sha256 " +
			"should no longer match the re-anchored records[0]")
	} else if !strings.Contains(derr.Error(), "genesis_sha256") {
		t.Fatalf("truncation was refused, but not by the genesis anchor — check what actually caught "+
			"it: %v", derr)
	} else {
		t.Logf("FIXED: header-unchanged truncation refused: %v", derr)
	}

	t.Logf("still true, and not what closes this: created_at is %s and the surviving records[0] is "+
		"%s, so the created_at bound alone is satisfied by construction", m.Meta.CreatedAt, m.Records[0].Timestamp)

	// The residual: rewrite the header's anchor to match the truncated chain, the
	// same motion an attacker who edits both would make. This is the gap that
	// remains — covering Meta in the record hash is the wrong fix (see H4's doc
	// comment), so the header stays outside the chain and a rewriter who touches
	// both together is internally consistent.
	rewritten := *m
	rewritten.Meta.GenesisSHA = m.Records[0].RecordSHA
	rraw, err := rewritten.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal rewritten: %v", err)
	}
	if _, derr := Decode(rraw, nil); derr != nil {
		t.Fatalf("this test documents the RESIDUAL open finding (Q21); if a header rewritten "+
			"alongside the truncation is now refused (%v), doc.go and audits/AUDIT-2.md must be "+
			"updated to say so", derr)
	}
	t.Log("OPEN (residual, Q21): a prefix-truncated chain whose header was rewritten to match still " +
		"loads — the anchor only catches a truncation the header does not also cover for")

	// Signed, the same truncation IS caught — and to isolate the SIGNATURE-specific
	// mechanism from the genesis-anchor mechanism above, the header's anchor is
	// rewritten to match here too, the same way the residual case above does. What
	// this part shows is that the link-and-signature check catches the truncation
	// independently of the anchor.
	signer := testSigner(t)
	signed := storeManifest(t, signer)
	mustAppend(t, signed, vendRec(OpBaselineApply, "2026-08-05T02:00:00Z"), signer)
	signed.Records = signed.Records[1:]
	relink(t, signed)
	signed.Meta.GenesisSHA = signed.Records[0].RecordSHA
	sraw, err := signed.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal signed: %v", err)
	}
	if _, derr := Decode(sraw, signer.Verifier()); derr == nil {
		t.Error("a SIGNED prefix-truncated chain, header rewritten to match, was accepted; " +
			"re-anchoring must invalidate the signatures, because previous_sha256 is inside record_sha256")
	} else {
		t.Logf("signed truncation refused: %v", derr)
	}

	// ...and stripping the signatures defeats that, which is why SignatureCoverage
	// exists. This is the composition the evidence lens reported.
	for i := range signed.Records {
		signed.Records[i].Signature = nil
	}
	stripped, err := signed.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal stripped: %v", err)
	}
	back, err := Decode(stripped, signer.Verifier())
	if err != nil {
		t.Fatalf("the stripped chain was refused (%v) — if verification now requires signatures, "+
			"TestAMixedChainVerifiesTheSignedRecords should have failed too", err)
	}
	cov := back.SignatureCoverage()
	if cov.Complete() {
		t.Fatal("SignatureCoverage reports complete coverage over a chain with no signatures")
	}
	t.Logf("stripped chain verifies under the real verifier; SignatureCoverage answers what the "+
		"verifier's silence does not: %s", cov.Describe())
}

// SignatureCoverage over the three shapes it exists to distinguish.
func TestSignatureCoverageDistinguishesTheThreeShapes(t *testing.T) {
	signer := testSigner(t)

	full := storeManifest(t, signer)
	if cov := full.SignatureCoverage(); !cov.Complete() || cov.Signed != 2 {
		t.Errorf("a fully signed chain: %+v (%s)", cov, cov.Describe())
	}

	none := storeManifest(t, nil)
	cov := none.SignatureCoverage()
	if cov.Complete() || cov.Signed != 0 || len(cov.Unsigned) != 2 {
		t.Errorf("an unsigned chain: %+v (%s)", cov, cov.Describe())
	}
	if !strings.Contains(cov.Describe(), "none of the 2") {
		t.Errorf("the description does not read as a total absence: %s", cov.Describe())
	}

	// Mixed: the legitimate shape, adopting a key partway through.
	mixed := NewManifest(acct, acct, "o-abc1234567", ts0)
	mustAppend(t, mixed, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, mixed, vendRec(OpSCPEnsure, ts1), signer)
	cov = mixed.SignatureCoverage()
	if cov.Complete() || cov.Signed != 1 || len(cov.Unsigned) != 1 || cov.Unsigned[0] != 0 {
		t.Errorf("a mixed chain: %+v (%s)", cov, cov.Describe())
	}
	if !strings.Contains(cov.Describe(), "records 0 carry no signature") {
		t.Errorf("the description does not name the unsigned index: %s", cov.Describe())
	}
	// And it must still verify, because that shape is deliberate.
	if err := mixed.VerifyChain(signer.Verifier()); err != nil {
		t.Errorf("a mixed chain must still verify: %v", err)
	}

	empty := NewManifest(acct, acct, "o-abc1234567", ts0)
	if cov := empty.SignatureCoverage(); cov.Complete() {
		t.Error("an empty chain must not report complete coverage: vacuously-fully-signed is the " +
			"wrong answer to give a caller who asked whether the evidence is signed")
	}
}

// M1 — misfiling. A valid, verified chain for account A, in a file named for account B.
func TestLoadOrNewRefusesAnotherAccountsChain(t *testing.T) {
	base, dir := tempDir(t)

	// Account acct's real manifest, written under otherAcct's name.
	m := storeManifest(t, nil)
	raw, merr := m.MarshalIndented()
	if merr != nil {
		t.Fatalf("marshal: %v", merr)
	}
	path := filepath.Join(base, "evidence", otherAcct+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}

	got, err := dir.LoadOrNew(otherAcct, otherAcct, "o-zzz9999999", ts0, nil)
	if err == nil {
		t.Fatalf("LoadOrNew adopted account %s's chain as %s's; a record for %s would now be appended "+
			"to it (loaded id=%s account=%s)", acct, otherAcct, otherAcct, got.Meta.ID, got.Meta.AccountID)
	}
	for _, want := range []string{acct, otherAcct, "another account's chain"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	t.Logf("refused: %v", err)
}

// The must-still-work half. An ordinary manifest round-trips through Dir, twice, and
// a first vend against an account with no file is not an error.
func TestOrdinaryHeaderStillLoads(t *testing.T) {
	_, dir := tempDir(t)

	fresh, err := dir.LoadOrNew(acct, acct, "o-abc1234567", ts0, nil)
	if err != nil {
		t.Fatalf("a first vend must not be an error: %v", err)
	}
	if len(fresh.Records) != 0 {
		t.Fatalf("a first vend produced %d records", len(fresh.Records))
	}
	mustAppend(t, fresh, vendRec(OpAccountCreate, ts0), nil)
	if werr := dir.Write(fresh, acct); werr != nil {
		t.Fatalf("Write: %v", werr)
	}
	again, err := dir.LoadOrNew(acct, acct, "o-abc1234567", ts0, nil)
	if err != nil {
		t.Fatalf("the second vend must load what the first wrote: %v", err)
	}
	if len(again.Records) != 1 {
		t.Errorf("loaded %d records, want 1", len(again.Records))
	}
	mustAppend(t, again, vendRec(OpSCPEnsure, ts1), nil)
	if werr := dir.Write(again, acct); werr != nil {
		t.Fatalf("second Write: %v", werr)
	}
}

// A manifest with no organization_id at all must still load — the field is optional
// and STANDALONE has no organization to name.
func TestAManifestWithNoOrganizationStillLoads(t *testing.T) {
	m := NewManifest(acct, acct, "", ts0)
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	raw, err := m.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("the document is not JSON: %v", err)
	}
	if _, err := Decode(raw, nil); err != nil {
		t.Fatalf("a manifest with no organization_id must load: %v", err)
	}

	_, dir := tempDir(t)
	if err := dir.Write(m, acct); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// And a run that DOES have an organization must still be able to read it, rather
	// than being told the manifest belongs to a different org.
	if _, err := dir.LoadOrNew(acct, acct, "o-abc1234567", ts0, nil); err != nil {
		t.Errorf("a manifest with no organization must be readable from a run that has one: %v", err)
	}
}

// A later record that steps BACKWARDS in time must still be accepted: an NTP
// correction between two vends is not tampering, and the existing conformance test
// pins that decision. Only records[0] is bound to created_at.
func TestALaterBackwardsTimestampStillLoads(t *testing.T) {
	m := storeManifest(t, nil)
	m.Records[1].Timestamp = "2026-08-04T00:00:00Z"
	relink(t, m)
	raw, err := m.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := Decode(raw, nil); err != nil {
		t.Fatalf("a later record predating created_at must still load (NTP correction): %v", err)
	}
}
