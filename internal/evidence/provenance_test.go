// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"strings"
	"testing"
)

// TestAppendRefusesUnverifiedSignatures is the Go-side obligation
// schema/CHANGELOG.md names: the manifest schema cannot distinguish a
// verified_signatures entry automat checked from one written by hand, so whatever
// writes records has to be the thing that refuses.
//
// The tempting bug is specific and worth naming: a caller copies
// profile.signatures into record.profile.verified_signatures because both are
// lists of the same shape, and the result is records that validate, read exactly
// like verified ones, and manufacture assurance out of a document's own claims
// about itself. automat verifies nothing in this version — it loads no trust
// policy, resolves no key, ships no trust anchor — so the empty set is the only
// honest value.
func TestAppendRefusesUnverifiedSignatures(t *testing.T) {
	m := newTestManifest()
	rec := vendRec(OpSCPEnsure, ts0)
	rec.EnvProfile.VerifiedSignatures = []VerifiedSignature{
		{Role: RoleAdoptedBy, Identity: "Research Computing"},
	}

	_, err := m.Append(rec, nil)
	if err == nil {
		t.Fatal("Append wrote a record claiming a verified attestation, and automat verifies nothing")
	}
	if len(m.Records) != 0 {
		t.Error("the record was appended anyway")
	}
	for _, want := range []string{
		"automat verifies nothing in this version",
		"loads no trust policy",
		"ships no trust anchor",
		"manufactures assurance",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must say why rather than just no; %q missing from:\n%v", want, err)
		}
	}
}

// TestTheEmptySetIsTheNormalValue is the other side, and it is not a formality: the
// field is required rather than optional precisely so an empty set is a recorded
// answer rather than an absent question, and a writer that dropped it on
// marshalling would turn "nothing was verified" back into "the question was never
// asked".
func TestTheEmptySetIsTheNormalValue(t *testing.T) {
	m := newTestManifest()
	rec := vendRec(OpSCPEnsure, ts0)
	rec.EnvProfile.VerifiedSignatures = nil // the shape a caller that never touched it produces
	stored := mustAppend(t, m, rec, nil)

	if stored.EnvProfile.VerifiedSignatures == nil {
		t.Error("verified_signatures is nil after Append; it must be an empty slice, because nil " +
			"marshals to null where the schema requires an array")
	}
	data, err := m.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"verified_signatures": []`) {
		t.Errorf("the written manifest must carry an explicit empty array — an absent or null field "+
			"reads as 'unknown', and the difference between 'nothing was verified' and 'the question "+
			"was never asked' is the one an evidence record must not blur:\n%s", data)
	}
}

// TestAVendRecordNamesItsEnvProfileByHash: a record naming only the environment
// profile id is a
// record whose subject can be edited afterwards.
func TestAVendRecordNamesItsEnvProfileByHash(t *testing.T) {
	m := newTestManifest()
	rec := vendRec(OpSCPEnsure, ts0)
	rec.EnvProfile.ContentSHA256 = ""

	_, err := m.Append(rec, nil)
	if err == nil {
		t.Fatal("Append accepted a profile reference with no content hash")
	}
	if !strings.Contains(err.Error(), "checkable rather than a label") {
		t.Errorf("the error must say what the hash is for:\n%v", err)
	}
}

// TestReviewByIsCopiedNotComputed pins the field's shape: a date, verbatim from the
// profile. An evidence record has to be readable years later without its inputs —
// an auditor should be able to see that the environment profile behind an account was already
// past review when it was vended, without needing the file.
func TestReviewByIsCopiedNotComputed(t *testing.T) {
	m := newTestManifest()
	rec := vendRec(OpSCPEnsure, ts0)
	stored := mustAppend(t, m, rec, nil)
	if stored.EnvProfile.ReviewBy != "2026-11-10" {
		t.Errorf("review_by = %q, want the environment profile's own value verbatim", stored.EnvProfile.ReviewBy)
	}

	// A lapsed date is not a validation failure — Phase 4's verify warns. A
	// validator with a clock would make every archived manifest invalid.
	stale := newTestManifest()
	old := vendRec(OpSCPEnsure, ts0)
	old.EnvProfile.ReviewBy = "1999-01-01"
	if _, err := stale.Append(old, nil); err != nil {
		t.Errorf("a long-lapsed review date must still be recordable — lapse is a verify warning "+
			"about the document, not a statement about the account:\n%v", err)
	}

	// A timestamp where a date belongs is refused, for the reason
	// custody_transfer.effective_date is: the two are different kinds of claim.
	bad := newTestManifest()
	wrong := vendRec(OpSCPEnsure, ts0)
	wrong.EnvProfile.ReviewBy = ts0
	if _, err := bad.Append(wrong, nil); err == nil {
		t.Error("Append accepted a timestamp in review_by")
	}
}

// TestTheRoleVocabularyIsClosedInGoToo mirrors
// artifact.TestTheAttestationRoleVocabularyIsClosed on the Go side. The five-value
// set is what stops the field degrading into a list of names a reader takes for
// approval, and a sixth role must be a reviewed decision rather than a typo that
// validated.
func TestTheRoleVocabularyIsClosedInGoToo(t *testing.T) {
	if len(AllRoles) != 5 {
		t.Fatalf("AllRoles has %d entries, want 5. Adding a role is a reviewed decision: no role "+
			"may mean approved, certified, or compliant, and the vocabulary's whole value is that "+
			"the weakest claim cannot be read as the strongest (DESIGN §11a)", len(AllRoles))
	}
	want := map[Role]bool{
		RoleAuthoredBy: true, RoleAdoptedBy: true, RoleReviewedBy: true,
		RoleInterpretedBy: true, RoleFormatValidatedBy: true,
	}
	for _, r := range AllRoles {
		if !want[r] {
			t.Errorf("unexpected role %q", r)
		}
		delete(want, r)
	}
	for r := range want {
		t.Errorf("role %q is missing from AllRoles", r)
	}

	// Once verification exists the field must be usable, so the shape has to
	// validate — checked here rather than through Append, which refuses any
	// non-empty set in v1 by design.
	pr := &EnvProfileRef{ID: "research-cui", ContentSHA256: someHash,
		VerifiedSignatures: []VerifiedSignature{
			{Role: RoleAdoptedBy, Identity: "Research Computing"},
			{Role: RoleAuthoredBy, Identity: "Office of the CISO", VerifiedAgainst: "trust.toml"},
		}}
	var p problems
	pr.validate("environment_profile", &p)
	if len(p.list) != 0 {
		t.Errorf("an identity-and-role pair must validate; the field has to be usable once "+
			"verification exists:\n%v", p.list)
	}

	bad := []struct {
		name string
		sig  VerifiedSignature
	}{
		// A bare list of names reads as approval; the role is what stops it.
		{"an identity with no role", VerifiedSignature{Identity: "Research Computing"}},
		{"a role with no identity", VerifiedSignature{Role: RoleAdoptedBy}},
		{"a role outside the vocabulary", VerifiedSignature{Role: "approved-by", Identity: "X"}},
		{"an identity that forges a report line",
			VerifiedSignature{Role: RoleAdoptedBy, Identity: "Research Computing\nreviewed-by: NIST"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			var p problems
			(&EnvProfileRef{ID: "research-cui", ContentSHA256: someHash,
				VerifiedSignatures: []VerifiedSignature{tc.sig}}).validate("environment_profile", &p)
			if len(p.list) == 0 {
				t.Errorf("the validator accepted %s", tc.name)
			}
		})
	}
}

// TestAParkedRecordCarriesItsRemediation is CLAUDE.md rule 7 applied where it
// matters most.
//
// A parked account exists in AWS. A parked record with no error names it and says
// nothing about why it stopped — which is a worse artifact than no record at all,
// because it proves something was left behind and withholds what. The operator
// reading this six weeks later has only this record.
func TestAParkedRecordCarriesItsRemediation(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)

	bare := vendRec(OpSCPEnsure, ts1)
	bare.Outcome = OutcomeParked
	_, err := m.Append(bare, nil)
	if err == nil {
		t.Fatal("Append accepted a parked record with no error block")
	}
	if !strings.Contains(err.Error(), "the only thing an operator has to act on") {
		t.Errorf("the error must say why the block is required:\n%v", err)
	}

	// The whole shape, which is what `vend` writes when step 4 fails after the
	// account exists (ROADMAP Phase 2).
	parked := vendRec(OpSCPEnsure, ts1)
	parked.Outcome = OutcomeParked
	parked.Err = &RecordError{
		Message: "attaching automat-cmmc-l1-baseline-protection to ou-abc1-12345678 was denied",
		Action:  "organizations:AttachPolicy",
		Resource: "arn:aws:organizations::111122223333:policy/o-abc1234567/service_control_policy/" +
			"p-example",
		Remediation: "add organizations:AttachPolicy on the destination OU to the delegation policy, " +
			"then re-run `automat vend --resume req-abc123`",
	}
	stored := mustAppend(t, m, parked, nil)
	if stored.Err.Remediation == "" {
		t.Error("the remediation text was dropped")
	}

	// And the inverse: an error on a success is a record annotating an outcome it
	// does not have.
	odd := vendRec(OpBaselineApply, ts2)
	odd.Err = &RecordError{Message: "something went slightly wrong"}
	if _, err := m.Append(odd, nil); err == nil {
		t.Error("Append accepted an error block on a successful record")
	}
}

// TestParkedRecordsAreFindable is the query `list` and `vend --resume` need. The
// record is the only thing standing between an operator and an account nothing
// points at.
func TestParkedRecordsAreFindable(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)

	parked := vendRec(OpSCPEnsure, ts1)
	parked.Outcome = OutcomeParked
	parked.Err = &RecordError{Message: "quota reached", Action: "organizations:AttachPolicy"}
	mustAppend(t, m, parked, nil)

	got := m.Parked()
	if len(got) != 1 || got[0].Operation != OpSCPEnsure {
		t.Fatalf("Parked() = %+v, want the one scp-ensure record", got)
	}
	if n := len(m.ForRequest("req-abc123")); n != 2 {
		t.Errorf("ForRequest returned %d records, want 2", n)
	}
	// A caller asking for "" is asking a question with no answer; returning the
	// un-attributed records would answer a different one.
	if n := len(m.ForRequest("")); n != 0 {
		t.Errorf("ForRequest(\"\") returned %d records, want 0", n)
	}
}
