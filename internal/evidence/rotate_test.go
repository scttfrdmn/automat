// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"errors"
	"strings"
	"testing"
)

// rotateRec is a well-formed terminal rotate record, the rotation-side
// counterpart to custody_test.go's transferRec.
func rotateRec(timestamp string) Record {
	return Record{
		Timestamp: timestamp,
		Operation: OpRotate,
		Operator:  Operator{ARN: operator, AccountID: acct},
		Rotation: &RotationInfo{
			SuccessorManifestID: acct + "-2",
			Reason:              "reached 2000 records",
			RecordCount:         2,
		},
		ToolVersion: toolVer,
	}
}

// TestRotateClosesTheOldManifestAndOpensANewOne is the ordinary case: a
// manifest that has grown too large is rotated to a fresh one, and both sides
// of that operation are checked (Q23, docs/open-questions.md).
func TestRotateClosesTheOldManifestAndOpensANewOne(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts1), nil)

	const successorID = acct + "-2"
	terminal, successor, err := m.Rotate(successorID, "reached 2000 records", ts2, nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// The old manifest.
	if terminal.Operation != OpRotate {
		t.Errorf("terminal.Operation = %q, want %q", terminal.Operation, OpRotate)
	}
	if !m.Closed() {
		t.Error("Closed() = false after Rotate")
	}
	if m.Records[len(m.Records)-1].RecordSHA != terminal.RecordSHA {
		t.Error("the terminal record returned by Rotate is not the one appended to m")
	}
	if terminal.Rotation == nil {
		t.Fatal("terminal.Rotation is nil")
	}
	if terminal.Rotation.SuccessorManifestID != successorID {
		t.Errorf("SuccessorManifestID = %q, want %q", terminal.Rotation.SuccessorManifestID, successorID)
	}
	if terminal.Rotation.RecordCount != 3 {
		t.Errorf("RecordCount = %d, want 3 (2 prior records plus this terminal one)",
			terminal.Rotation.RecordCount)
	}
	if err := m.VerifyChain(nil); err != nil {
		t.Errorf("the rotated manifest must still verify:\n%v", err)
	}

	// The new manifest.
	if successor == nil {
		t.Fatal("successor is nil")
	}
	if successor.Meta.ID != successorID {
		t.Errorf("successor.Meta.ID = %q, want %q", successor.Meta.ID, successorID)
	}
	if successor.Meta.AccountID != m.Meta.AccountID {
		t.Errorf("successor.Meta.AccountID = %q, want %q (carried over from the predecessor)",
			successor.Meta.AccountID, m.Meta.AccountID)
	}
	if successor.Meta.OrganizationID != m.Meta.OrganizationID {
		t.Errorf("successor.Meta.OrganizationID = %q, want %q", successor.Meta.OrganizationID, m.Meta.OrganizationID)
	}
	if len(successor.Records) != 0 {
		t.Errorf("successor has %d records, want 0: Rotate only opens the manifest, it does not "+
			"seed it with a first record", len(successor.Records))
	}
	if successor.Meta.GenesisSHA != "" {
		t.Error("successor.Meta.GenesisSHA is set before any record was appended to it — " +
			"Rotate must not invent a genesis anchor; Append sets it when the successor's own " +
			"first record lands, same as NewManifest")
	}

	// The successor is a normal, independent manifest: it accepts its own first
	// record through the ordinary Append path, with no special-casing for having
	// come from a rotation.
	next := mustAppend(t, successor, vendRec(OpBaselineApply, ts2), nil)
	if next.Sequence != 0 {
		t.Errorf("successor's first appended record has sequence %d, want 0", next.Sequence)
	}
	if successor.Meta.GenesisSHA != next.RecordSHA {
		t.Errorf("successor.Meta.GenesisSHA = %q, want %q (records[0].record_sha256)",
			successor.Meta.GenesisSHA, next.RecordSHA)
	}
}

// TestRotateDoesNotLinkTheSuccessorsGenesisToThePredecessor pins the design
// choice ROADMAP.md's Q23 entry states explicitly: the two manifests are
// connected only by the named pointer (RotationInfo.SuccessorManifestID), not
// by a cryptographic link. A Meta.PredecessorSHA field is a distinct, later,
// separately-approved change this function must not build.
func TestRotateDoesNotLinkTheSuccessorsGenesisToThePredecessor(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)

	_, successor, err := m.Rotate(acct+"-2", "reached 2000 records", ts1, nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// The successor's Meta carries only what NewManifest itself sets — nothing
	// about the predecessor's final hash. This is really a compile-time /
	// documentation assertion: Meta has no such field to check, and adding one
	// would be the thing this test is pinning against.
	if successor.Meta.GenesisSHA != "" {
		t.Error("successor carries a genesis anchor before its own first record; " +
			"Rotate must not pre-seed it from the predecessor's terminal hash")
	}
}

// TestAppendRefusesToContinueARotatedManifest is the generalized terminal
// check enforced at the write end, mirroring
// TestAppendRefusesToReopenAClosedChain for the custody-transfer case. A
// rotated manifest is closed for the same reason a custody-transferred one is:
// nothing may follow its terminal record.
func TestAppendRefusesToContinueARotatedManifest(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	if _, _, err := m.Rotate(acct+"-2", "reached 2000 records", ts1, nil); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if !m.Closed() {
		t.Fatal("Closed() = false after Rotate")
	}
	_, err := m.Append(vendRec(OpSCPEnsure, ts2), nil)
	if err == nil {
		t.Fatal("Append wrote a record to a rotated manifest")
	}
	if !errors.Is(err, ErrClosed) {
		t.Errorf("the error must be ErrClosed: %v", err)
	}
	for _, want := range []string{acct + "-2", "reached 2000 records"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must name the successor and the reason; %q missing from:\n%v", want, err)
		}
	}
}

// TestVerifyChainRejectsARecordAfterARotateRecord is VerifyChain's half of
// the same generalized check, mirroring
// TestTheGoValidatorEnforcesCustodyTransferTerminality: a hand-edited file
// that appends past a rotate record is caught the same way a hand-edited file
// appending past a custody transfer is, because both are IsTerminal().
func TestVerifyChainRejectsARecordAfterARotateRecord(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	if _, _, err := m.Rotate(acct+"-2", "reached 2000 records", ts1, nil); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	after := vendRec(OpSCPEnsure, ts2)
	after.Sequence = 2
	after.PreviousSHA = m.Records[1].RecordSHA
	h, err := ComputeRecordHash(after)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	after.RecordSHA = h
	m.Records = append(m.Records, after)

	verr := m.VerifyChain(nil)
	if verr == nil {
		t.Fatal("VerifyChain accepted a record after a rotate record")
	}
	if !strings.Contains(verr.Error(), "JSON Schema cannot state this") {
		t.Errorf("the error must say why the rule lives here: %v", verr)
	}
}

// TestARotateRecordMustCarryItsPayload is the positive/negative pairing test
// for rotation, mirroring TestACustodyTransferMustCarryItsPayload.
func TestARotateRecordMustCarryItsPayload(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Record)
		want string
	}{
		{"no rotation at all", func(r *Record) { r.Rotation = nil }, "is absent on a rotate record"},
		{"no successor manifest id", func(r *Record) { r.Rotation.SuccessorManifestID = "" },
			"successor_manifest_id"},
		{"no reason", func(r *Record) { r.Rotation.Reason = "" },
			"indistinguishable from one that was truncated"},
		{"a zero record count", func(r *Record) { r.Rotation.RecordCount = 0 }, "record_count"},
		{"a failed rotation", func(r *Record) { r.Outcome = OutcomeFailure },
			"a rotation that did not happen does not end a chain"},
		{"an artifact alongside rotation", func(r *Record) {
			r.Artifact = &DocRef{ID: "cmmc-l1", ContentSHA256: someHash}
		}, "a rotation enforces nothing"},
		{"an enforcement block", func(r *Record) {
			r.Enforcement = &Enforcement{ConformancePackARN: "arn:aws:config:us-east-1:1:pack/x"}
		}, "a rotation deploys nothing"},
		{"an environment-profile reference", func(r *Record) {
			r.EnvProfile = &EnvProfileRef{ID: "research-cui", ContentSHA256: otherHash,
				VerifiedSignatures: []VerifiedSignature{}}
		}, "a rotation runs under no environment profile"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManifest()
			mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
			rec := rotateRec(ts1)
			tc.mut(&rec)
			_, err := m.Append(rec, nil)
			if err == nil {
				t.Fatalf("Append accepted a rotate record with %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error must explain the rule; %q missing from:\n%v", tc.want, err)
			}
		})
	}
}

// TestOnlyARotateRecordMayCarryRotation is the negative half: a rotation
// block cannot ride along on an ordinary record, mirroring
// TestOnlyACustodyTransferRecordMayCarryACustodyTransfer.
func TestOnlyARotateRecordMayCarryRotation(t *testing.T) {
	m := newTestManifest()
	smuggled := vendRec(OpAccountMove, ts0)
	smuggled.Rotation = &RotationInfo{SuccessorManifestID: acct + "-2", Reason: "x", RecordCount: 1}

	_, err := m.Append(smuggled, nil)
	if err == nil {
		t.Fatal("Append accepted rotation on an account-move record")
	}
	if !strings.Contains(err.Error(), "not a passenger on one") {
		t.Errorf("the error must say a rotation must be the operation:\n%v", err)
	}
}

// TestARotatedThenCustodyTransferredManifestIsRejectedAtTheSecondTerminalRecord
// checks that a manifest cannot carry two terminal records of different kinds
// either — IsTerminal generalizes over both, and "at most one terminal record,
// and it must be last" applies regardless of which kind came first.
func TestASecondTerminalRecordOfADifferentKindIsRefused(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	if _, _, err := m.Rotate(acct+"-2", "reached 2000 records", ts1, nil); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, err := m.Append(transferRec(ts2), nil); err == nil {
		t.Error("Append wrote a custody-transfer record onto an already-rotated manifest")
	}
}
