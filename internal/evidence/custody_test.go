// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"errors"
	"strings"
	"testing"
)

// transferRec is a well-formed terminal record.
func transferRec(timestamp string) Record {
	return Record{
		Timestamp: timestamp,
		Operation: OpCustodyTransfer,
		Operator:  Operator{ARN: operator, AccountID: acct},
		Custody: &Custody{
			Transferee:    "Research Computing, under the FY27 shared-services agreement",
			EffectiveDate: "2026-09-01",
			Reason:        "The account moves to central IT operation; automat stops managing its baseline.",
			FinalArtifact: DocRef{ID: "cmmc-l1", ContentSHA256: someHash, SchemaVersion: "1.0.0"},
		},
		ToolVersion: toolVer,
	}
}

// TestTheGoValidatorEnforcesCustodyTransferTerminality is the other half of
// artifact.TestTheSchemaCannotSayCustodyTransferIsLast, and the reason this package
// has a chain validator at all.
//
// JSON Schema cannot refer to an array's final position, so "nothing follows a
// custody-transfer record" is not expressible in schema/. The schema enforces the
// half it can — at most one — and this is where the other half lives. The two tests
// are deliberately a pair: if the schema ever gains the ability to say it, that one
// fails and points here.
//
// The document constructed below is the exact one the schema accepts.
func TestTheGoValidatorEnforcesCustodyTransferTerminality(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, m, transferRec(ts1), nil)

	// Hand-append past Append's refusal, which is what an editor with a text
	// editor and a hash calculator would do — and note that this chain's links and
	// hashes are all sound, so nothing but the terminality rule catches it.
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
		t.Fatal("VerifyChain accepted a record after a custody-transfer record; the schema cannot " +
			"express terminality, so this validator is the only thing standing there")
	}
	for _, want := range []string{
		"records[1]",
		"custody passes out of automat's hands once",
		"JSON Schema cannot state this",
	} {
		if !strings.Contains(verr.Error(), want) {
			t.Errorf("the error must name the transfer record and why the rule lives here; %q "+
				"missing from:\n%v", want, verr)
		}
	}
}

// TestAppendRefusesToReopenAClosedChain is the same rule enforced at the write end,
// where it is a different failure: not a tampered document but automat continuing
// to manage an account whose custody it gave away.
func TestAppendRefusesToReopenAClosedChain(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, m, transferRec(ts1), nil)

	if !m.Closed() {
		t.Fatal("Closed() = false after a custody transfer")
	}
	_, err := m.Append(vendRec(OpSCPEnsure, ts2), nil)
	if err == nil {
		t.Fatal("Append wrote a record to a closed chain")
	}
	if !errors.Is(err, ErrClosed) {
		t.Errorf("the error must be ErrClosed so a caller can tell 'stop' from 'retry': %v", err)
	}
	if len(m.Records) != 2 {
		t.Errorf("the chain grew to %d records", len(m.Records))
	}
	// The operator needs to know who has it now, or the message tells them to stop
	// without telling them where to go.
	for _, want := range []string{"Research Computing", "2026-09-01"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must name the transferee and the effective date; %q missing from:\n%v",
				want, err)
		}
	}
	// A second transfer is refused by the same rule: it means either the first was
	// false or the chain was reopened after it closed.
	if _, err := m.Append(transferRec(ts2), nil); err == nil {
		t.Error("Append wrote a second custody-transfer record")
	}
}

func TestACustodyTransferMustCarryItsPayload(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Record)
		want string
	}{
		{
			"no custody_transfer at all",
			func(r *Record) { r.Custody = nil },
			"is absent on a custody-transfer record",
		},
		{
			"no transferee",
			func(r *Record) { r.Custody.Transferee = "" },
			"transferee",
		},
		{
			"no reason",
			func(r *Record) { r.Custody.Reason = "" },
			"indistinguishable from one that was truncated",
		},
		{
			// A timestamp is an event time; a date is a policy fact. Confusing the
			// two in the one record whose job is to say when responsibility moved
			// would make it claim the transfer happened when the command ran.
			"effective_date carrying a timestamp",
			func(r *Record) { r.Custody.EffectiveDate = ts1 },
			"custody passing is a policy fact",
		},
		{
			"final_artifact without a content hash",
			func(r *Record) { r.Custody.FinalArtifact.ContentSHA256 = "" },
			"final_artifact.content_sha256",
		},
		{
			// The reason is printed back in reports. A newline in it forges a line.
			"reason containing a newline",
			func(r *Record) { r.Custody.Reason = "Approved\n- account-move: 111122223333 -> r-root" },
			"reason",
		},
		{
			"a failed transfer",
			func(r *Record) { r.Outcome = OutcomeFailure },
			"a transfer that did not happen does not end a chain",
		},
		{
			"an artifact alongside final_artifact",
			func(r *Record) { r.Artifact = &DocRef{ID: "cmmc-l1", ContentSHA256: otherHash} },
			"the baseline being handed over is custody_transfer.final_artifact",
		},
		{
			"an enforcement block claiming a deployment",
			func(r *Record) {
				r.Enforcement = &Enforcement{ConformancePackARN: "arn:aws:config:us-east-1:1:pack/x"}
			},
			"a transfer deploys nothing",
		},
		{
			// Added with the cosigning fields, for the same reason artifact and
			// enforcement were already forbidden.
			"an environment-profile reference",
			func(r *Record) {
				r.EnvProfile = &EnvProfileRef{ID: "research-cui", ContentSHA256: otherHash,
					VerifiedSignatures: []VerifiedSignature{}}
			},
			"a transfer runs under no environment profile",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManifest()
			mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
			rec := transferRec(ts1)
			tc.mut(&rec)
			_, err := m.Append(rec, nil)
			if err == nil {
				t.Fatalf("Append accepted a custody-transfer record with %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error must explain the rule; %q missing from:\n%v", tc.want, err)
			}
		})
	}
}

// TestOnlyACustodyTransferRecordMayCarryACustodyTransfer is the negative half of
// the pairing. Without it a transfer could ride along on an ordinary account-move
// record, ending the chain where no reader looks for an ending.
func TestOnlyACustodyTransferRecordMayCarryACustodyTransfer(t *testing.T) {
	m := newTestManifest()
	smuggled := transferRec(ts0)
	smuggled.Operation = OpAccountMove

	_, err := m.Append(smuggled, nil)
	if err == nil {
		t.Fatal("Append accepted custody_transfer on an account-move record")
	}
	if !strings.Contains(err.Error(), "not a passenger on one") {
		t.Errorf("the error must say a transfer must be the operation:\n%v", err)
	}
}

// TestAManifestOfOnlyATransferIsValid: custody of an account automat vended before
// manifests existed, handed on. The terminal record does not require a history.
func TestAManifestOfOnlyATransferIsValid(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, transferRec(ts0), nil)
	if err := m.VerifyChain(nil); err != nil {
		t.Errorf("a manifest consisting of one custody-transfer record must verify:\n%v", err)
	}
}
