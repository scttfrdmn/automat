// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Cosigning and freshness (DESIGN §11a): `review_by` on both profile document
// types, an optional `signatures[]` array of attestation predicates, and the
// evidence record's `environment_profile` block naming the document that was vended
// under and
// the attestations that verified.
//
// No Go types and no verification — that scope was explicitly excluded, and a
// struct here would be building what that decision said not to build. Everything
// below reads raw JSON against the published schemas, which is the whole point:
// these fields exist to be written by hand and read by a consumer that is not
// automat, and a constraint nobody has fed a document to is a constraint nobody
// has checked.
//
// The rules are expressed with a nested if/then/else inside an enum'd object and
// three separate required lists, which are easy to write so that they accept
// everything. Every case below was verified to fire by deleting the constraint it
// covers and confirming the case fails.

// The two profile document types — environment and obligation — share the
// attestation vocabulary, so most cases below run against both. Held as a list
// rather than duplicated per file.
var profileSchemaFiles = []string{
	"environment-profile-v1.schema.json",
	"obligation-profile-v1.schema.json",
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// minimalEnvironmentProfile is the smallest document environment-profile-v1
// accepts, as a map so a case can add or delete one key without restating the
// rest.
func minimalEnvironmentProfile() map[string]any {
	return map[string]any{
		"schema_version":      "1.0.0",
		"environment_profile": map[string]any{"id": "example", "title": "Example"},
		"review_by":           "2027-01-01",
		"control_sets":        []any{"cmmc-l1"},
		"placement":           map[string]any{"target_ou": "ou-abcd-11111111"},
		"baseline": map[string]any{
			"config_recorder": map[string]any{"enabled": true},
		},
	}
}

// minimalObligationProfile is loaded from a shipped profile rather than
// hand-written: obligation-profile-v1 requires fourteen top-level members and a
// hand-rolled fixture would be a second, drifting definition of a valid profile.
// cmmc-l1 is the one with no weight table and a pinned revision, so it is the
// simplest of the three.
func minimalObligationProfile(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(obligationDir, "cmmc-l1.json")) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc map[string]any
	if uerr := json.Unmarshal(data, &doc); uerr != nil {
		t.Fatalf("parse: %v", uerr)
	}
	return doc
}

// profileFixture returns a valid document for whichever schema is under test, so
// a case written once runs against both.
func profileFixture(t *testing.T, schemaFile string) map[string]any {
	t.Helper()
	if schemaFile == "environment-profile-v1.schema.json" {
		return minimalEnvironmentProfile()
	}
	return minimalObligationProfile(t)
}

// attestation is a valid entry: a role, an identity, a statement in the
// attester's own words, the hash it is over, and a date. No signature block —
// which is itself the point of one of the cases below.
func attestation() map[string]any {
	return map[string]any{
		"role":     "adopted-by",
		"identity": "Research Computing, Example University",
		"statement": "Research Computing adopted this profile for its own use on the date below. " +
			"This says nothing about whether it suits anyone else, and nothing about whether the " +
			"policy reading in it is correct.",
		"content_sha256": strings.Repeat("a", 64),
		"attested_at":    "2026-08-05",
	}
}

func validate(t *testing.T, sch *jsonschema.Schema, doc map[string]any) error {
	t.Helper()
	return sch.Validate(asGeneric(t, doc))
}

// ---------------------------------------------------------------------------
// review_by
// ---------------------------------------------------------------------------

// TestReviewByIsRequiredOnEveryProfileDocument is the freshness half.
//
// Signed does not mean current, and a durable-looking stale artifact is worse
// than an unsigned one: a superseded citation renders exactly as well as a
// current one. The date is required with no default, because an optional
// freshness date is absent from precisely the documents whose freshness nobody
// thought about.
func TestReviewByIsRequiredOnEveryProfileDocument(t *testing.T) {
	for _, name := range profileSchemaFiles {
		t.Run(name, func(t *testing.T) {
			sch := compileSchema(t, name)

			doc := profileFixture(t, name)
			if err := validate(t, sch, doc); err != nil {
				t.Fatalf("the fixture must be valid before a case mutates it:\n%v", err)
			}

			delete(doc, "review_by")
			if err := validate(t, sch, doc); err == nil {
				t.Error("the schema accepted a profile with no review_by. A profile is a reading of " +
					"policy an institution acts on, and policy moves; a document with no review date " +
					"cannot be checked for staleness, which is the failure mode that is silent and " +
					"confident. See DESIGN §11a.")
			}
		})
	}
}

// TestReviewByIsADateAndNotATimestamp keeps it a policy fact rather than an event
// time — the same distinction custody_transfer.effective_date makes, and for the
// same reason: a review is scheduled on a calendar, and a timestamp here would
// invite a renderer to compare it against a clock.
func TestReviewByIsADateAndNotATimestamp(t *testing.T) {
	for _, name := range profileSchemaFiles {
		t.Run(name, func(t *testing.T) {
			sch := compileSchema(t, name)
			for _, bad := range []string{
				"2027-01-01T00:00:00Z", // a timestamp
				"2027-1-1",             // unpadded
				"January 2027",         // prose
				"",
				"2027-01-01 ", // trailing space, which a naive parser accepts
			} {
				doc := profileFixture(t, name)
				doc["review_by"] = bad
				if err := validate(t, sch, doc); err == nil {
					t.Errorf("review_by accepted %q", bad)
				}
			}
		})
	}
}

// TestTheSchemaCannotSayReviewByIsInTheFuture records a limit rather than
// asserting a behaviour, because a limit stated only in a comment is one that gets
// forgotten.
//
// A schema has no clock. It could not reject a past date even in principle, and a
// schema that somehow did would make every archived document retroactively
// invalid — which is exactly wrong for evidence. Lapse is a `verify` WARNING
// (DESIGN §12), not a validation error: the account is as compliant as it was
// yesterday, and what has expired is anyone's assurance that the document
// describing it still reads policy correctly.
func TestTheSchemaCannotSayReviewByIsInTheFuture(t *testing.T) {
	for _, name := range profileSchemaFiles {
		t.Run(name, func(t *testing.T) {
			sch := compileSchema(t, name)
			doc := profileFixture(t, name)
			doc["review_by"] = "1999-01-01"
			if err := validate(t, sch, doc); err != nil {
				t.Fatalf("this document is expected to pass the schema and be WARNED about by "+
					"verify instead; if the schema now rejects a lapsed review date, that is a "+
					"behaviour change to argue for rather than discover:\n%v", err)
			}
			t.Log("recorded: the schema accepts a review_by in the past. Warning on lapse is " +
				"Phase 4's verify, not the schema.")
		})
	}
}

// TestEveryShippedProfileScheduleItsOwnReReading checks the dates rather than the
// field, since a required field satisfied by a date in 2099 is a field satisfied
// by nothing.
//
// The bound is each profile's own citations: a profile that cites a phase-in date
// and then schedules its re-reading for after that date is a profile predicting
// its own obsolescence and sleeping through it. dfars-7012 names CMMC Phase 2 at
// 2026-11-10; a profile may not have a review date later than the latest future
// date it cites.
//
// # AUDIT-2 M1: the horizon was a hardcoded date, and dates arrive
//
// This test used to skip any citation effective on or before a literal
// `"2026-08-05"`, reasoning that a citation already in force says nothing about
// when a reading goes stale. Correct on the day it was written, and it decayed
// without a code change: by 2026-08-06 every one of the thirteen citations across
// the three shipped profiles had passed that literal, so the inner comparison
// executed zero times and the test asserted only that `review_by` was non-empty —
// which the schema already requires. A scratch probe counted it: 13 citations, 0
// through the gate.
//
// The lesson is more general than the date. A test that hardcodes "now" does not
// fail when it goes stale; it silently narrows to a tautology, and it keeps
// reporting PASS in a suite the audit ritual treats as evidence. So the horizon is
// the build clock, and the profiles are also checked from the other side: a review
// date already behind us is a lapsed reading, which is the condition this test's
// own name promises to catch and previously could not.
func TestEveryShippedProfileSchedulesItsOwnReReading(t *testing.T) {
	type doc struct {
		Profile struct {
			ID string `json:"id"`
		} `json:"profile"`
		ReviewBy  string `json:"review_by"`
		Citations []struct {
			ID            string `json:"id"`
			EffectiveDate string `json:"effective_date"`
		} `json:"citations"`
	}

	// today, not a literal. Lexical ISO-8601, matching the schema's pattern, so
	// string comparison is date comparison.
	today := time.Now().UTC().Format("2006-01-02")

	entries, err := os.ReadDir(obligationDir)
	if err != nil {
		t.Fatalf("read %s: %v", obligationDir, err)
	}
	var checked, compared int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			data, rerr := os.ReadFile(filepath.Join(obligationDir, e.Name())) //nolint:gosec // fixed dir
			if rerr != nil {
				t.Fatalf("read: %v", rerr)
			}
			var d doc
			if uerr := json.Unmarshal(data, &d); uerr != nil {
				t.Fatalf("parse: %v", uerr)
			}
			if d.ReviewBy == "" {
				t.Fatal("no review_by")
			}
			checked++

			// The lapse check. A review date in the past is the failure the
			// freshness field exists to prevent, and it is the one a suite that
			// only compared review dates to citation dates could never see: a
			// profile whose citations are all historical passed while its own
			// re-reading deadline slid by.
			if d.ReviewBy < today {
				t.Errorf("profile %q was to be re-read by %s and today is %s — the reading is LAPSED. "+
					"A profile renders its citations exactly as confidently after its review date as "+
					"before, so this is not a scheduling nit: re-verify the citations against the "+
					"primary sources, then move review_by forward with the audit that did it. "+
					"Moving the date alone is the one repair that makes this worse",
					d.Profile.ID, d.ReviewBy, today)
			}

			// The comparison is lexical, which is correct for zero-padded ISO
			// dates and is why the pattern requires that form.
			for _, c := range d.Citations {
				// Only dates the profile itself treats as still ahead of it
				// matter. A citation effective in 2017 says nothing about when
				// this reading goes stale.
				if c.EffectiveDate <= today {
					continue
				}
				compared++
				if d.ReviewBy > c.EffectiveDate {
					t.Errorf("profile %q reviews by %s but cites %q as effective %s — the profile "+
						"schedules its own re-reading for AFTER a change it already knows about, "+
						"which is the one case where a review date is worse than none: it reads as "+
						"a considered judgment that nothing will change before then",
						d.Profile.ID, d.ReviewBy, c.ID, c.EffectiveDate)
				}
			}
		})
	}
	if checked == 0 {
		t.Error("no profile was checked, so this test verified nothing")
	}
	// Reported, not asserted, and the distinction is the finding's whole point.
	//
	// Zero forward-looking citations is a legitimate state — every date a profile
	// cites can genuinely be in force — so failing here would break the build for
	// the passage of time. But zero is also exactly what the vacuous version
	// reported while claiming to check the ordering, so it is logged: a run
	// showing 0 has verified the lapse half and nothing else, and a reader of the
	// audit needs to be able to tell those apart.
	t.Logf("forward-looking citations compared against their profile's review date: %d "+
		"(0 is valid and means only the lapse check ran)", compared)
}

// ---------------------------------------------------------------------------
// signatures[]
// ---------------------------------------------------------------------------

// TestAnAttestationIsOptionalButNeverBare is the shape rule.
//
// automat ships no trust anchor, so an unsigned document must remain perfectly
// valid — a profile nobody has cosigned is the normal case and always will be. But
// an entry that IS present may not be bare: the role and the statement are what
// make it an attestation rather than a tick, and the whole design rests on a
// reader evaluating a sentence instead of a checkmark.
func TestAnAttestationIsOptionalButNeverBare(t *testing.T) {
	for _, name := range profileSchemaFiles {
		t.Run(name, func(t *testing.T) {
			sch := compileSchema(t, name)

			// Absent: valid. This is the case that must never break.
			base := profileFixture(t, name)
			if err := validate(t, sch, base); err != nil {
				t.Fatalf("a profile with no signatures must be valid — automat ships no trust "+
					"anchor and cosigning is optional:\n%v", err)
			}

			// Present and complete: valid.
			withSig := profileFixture(t, name)
			withSig["signatures"] = []any{attestation()}
			if err := validate(t, sch, withSig); err != nil {
				t.Fatalf("a complete attestation must be valid:\n%v", err)
			}

			for _, field := range []string{"role", "identity", "statement", "content_sha256", "attested_at"} {
				doc := profileFixture(t, name)
				a := attestation()
				delete(a, field)
				doc["signatures"] = []any{a}
				if err := validate(t, sch, doc); err == nil {
					t.Errorf("the schema accepted an attestation with no %s", field)
				}
			}
		})
	}
}

// TestTheAttestationRoleVocabularyIsClosed pins the set and, more importantly, the
// reason it is that set.
//
// Roles exist precisely so that "X authored this", "Y adopted it", "Z reviewed
// it" and "the format validated" cannot collapse into one checkmark. A reader
// shown a single undifferentiated tick learns nothing and infers the strongest
// available claim, which is how "the JSON parsed" becomes "the university
// approved this". So a sixth role is a reviewed decision, not a data change — and
// in particular no role may mean approved, certified, or compliant.
func TestTheAttestationRoleVocabularyIsClosed(t *testing.T) {
	want := []string{
		"adopted-by",
		"authored-by",
		"format-validated-by",
		"interpreted-by",
		"reviewed-by",
	}

	for _, name := range profileSchemaFiles {
		t.Run(name, func(t *testing.T) {
			got := attestationRoles(t, name)
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s declares roles %v, want %v.\n\nThe vocabulary's whole value is that "+
					"the weakest claim cannot be read as the strongest. Adding a role — especially "+
					"one that reads as approval — is a decision to argue for in the same change, "+
					"not a data addition. See DESIGN §11a.", name, got, want)
			}

			// And the enum actually bites. A role outside the set is the shape an
			// approval claim would arrive in.
			sch := compileSchema(t, name)
			for _, bad := range []string{"approved-by", "certified-by", "compliant", "signed-by", ""} {
				doc := profileFixture(t, name)
				a := attestation()
				a["role"] = bad
				doc["signatures"] = []any{a}
				if err := validate(t, sch, doc); err == nil {
					t.Errorf("the schema accepted role %q. No role in this vocabulary may mean "+
						"approved, certified, or compliant: a signature attests PROVENANCE ONLY.", bad)
				}
			}
		})
	}
}

// attestationRoles reads the enum straight out of the published file rather than
// probing the compiled schema, so the failure message names what a consumer would
// read.
func attestationRoles(t *testing.T, schemaFile string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(schemaDir, schemaFile)) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc struct {
		Defs struct {
			Attestation struct {
				Properties struct {
					Role struct {
						Enum []string `json:"enum"`
					} `json:"role"`
				} `json:"properties"`
			} `json:"attestation"`
		} `json:"$defs"`
	}
	if uerr := json.Unmarshal(data, &doc); uerr != nil {
		t.Fatalf("parse: %v", uerr)
	}
	roles := doc.Defs.Attestation.Properties.Role.Enum
	if len(roles) == 0 {
		t.Fatalf("%s has no $defs.attestation.properties.role.enum — the definition moved, and "+
			"this test now checks nothing", schemaFile)
	}
	return roles
}

// TestAnAttestationStatementCannotBeEmptyOrForged covers the field that makes
// these attestations rather than signatures. It is rendered into reports, so it
// carries the same control-character rule the rest of the prose fields do — except
// that newlines are permitted, because a statement is a paragraph.
func TestAnAttestationStatementCannotBeEmptyOrForged(t *testing.T) {
	for _, name := range profileSchemaFiles {
		t.Run(name, func(t *testing.T) {
			sch := compileSchema(t, name)

			for _, bad := range []string{
				"",
				"Adopted.\x00 by Research Computing",    // a NUL
				"Adopted\x07",                           // a bell
				"Adopted\x1b[31m by Research Computing", // an ANSI escape, which forges terminal output
			} {
				doc := profileFixture(t, name)
				a := attestation()
				a["statement"] = bad
				doc["signatures"] = []any{a}
				if err := validate(t, sch, doc); err == nil {
					t.Errorf("the schema accepted statement %q", bad)
				}
			}

			// A multi-line statement is legitimate: this is where an institution
			// explains what it is and is not claiming, and that rarely fits on one
			// line.
			doc := profileFixture(t, name)
			a := attestation()
			a["statement"] = "Research Computing adopted this profile.\n\nThis is not an endorsement " +
				"of the policy reading in it, and not advice to anyone else."
			doc["signatures"] = []any{a}
			if err := validate(t, sch, doc); err != nil {
				t.Errorf("a multi-line statement must be valid — it is where the attester says what "+
					"they are NOT claiming:\n%v", err)
			}
		})
	}
}

// TestASignatureBlockIsSubordinateToItsClaim asserts the direction of the
// dependency.
//
// The claim is the attestation; the bytes are evidence for it, never the other way
// round. So an entry with no signature block is valid — an institution asserting
// authorship of a file it publishes itself is a real attestation — while bytes with
// no role and no statement must not be expressible at all.
func TestASignatureBlockIsSubordinateToItsClaim(t *testing.T) {
	for _, name := range profileSchemaFiles {
		t.Run(name, func(t *testing.T) {
			sch := compileSchema(t, name)

			// No cryptographic material: still an attestation.
			unsigned := profileFixture(t, name)
			unsigned["signatures"] = []any{attestation()}
			if err := validate(t, sch, unsigned); err != nil {
				t.Fatalf("an attestation with no signature block must be valid:\n%v", err)
			}

			// Bytes alone: not expressible. Both required-field paths and
			// additionalProperties have to hold for this, which is why it is
			// asserted rather than assumed.
			bare := profileFixture(t, name)
			bare["signatures"] = []any{map[string]any{
				"signature": map[string]any{
					"format": "detached-ed25519",
					"value":  "QUFBQQ==",
					"key_id": "local-key-1",
				},
			}}
			if err := validate(t, sch, bare); err == nil {
				t.Error("the schema accepted a signature with no role, identity, or statement. " +
					"A bare signature invites the reader to supply the claim themselves, and they " +
					"supply the strongest one available.")
			}
		})
	}
}

// TestEachSignatureFormatRequiresWhatMakesItVerifiable is the if/then/else pair.
//
// A detached signature nobody can locate a key for is unverifiable in a way that
// LOOKS verifiable, which is worse than absent. And in the keyless model the
// issuer is the whole of what the identity means: "signed by security@example.edu"
// is a different claim depending on who vouched for that address. Each form
// therefore requires its own field and forbids the other's, so a document cannot
// carry a keyless signature with a key id and let a reader guess which model
// applies.
func TestEachSignatureFormatRequiresWhatMakesItVerifiable(t *testing.T) {
	detached := func(extra map[string]any) map[string]any {
		s := map[string]any{"format": "detached-ed25519", "value": "QUFBQQ==", "key_id": "local-key-1"}
		for k, v := range extra {
			s[k] = v
		}
		return s
	}
	keyless := func(extra map[string]any) map[string]any {
		s := map[string]any{
			"format":          "oidc-identity-bundle",
			"value":           "QUFBQQ==",
			"identity_issuer": "https://accounts.example.edu",
		}
		for k, v := range extra {
			s[k] = v
		}
		return s
	}

	cases := []struct {
		name  string
		sig   map[string]any
		valid bool
	}{
		{"detached with a key id", detached(nil), true},
		{"keyless with an issuer", keyless(nil), true},
		{
			// Unverifiable, and unverifiable in the direction that looks fine.
			"detached with no key id",
			map[string]any{"format": "detached-ed25519", "value": "QUFBQQ=="},
			false,
		},
		{
			// The issuer is what makes the identity mean anything.
			"keyless with no issuer",
			map[string]any{"format": "oidc-identity-bundle", "value": "QUFBQQ=="},
			false,
		},
		{
			// Two trust models in one block; a reader cannot tell which applies.
			"detached carrying an issuer",
			detached(map[string]any{"identity_issuer": "https://accounts.example.edu"}),
			false,
		},
		{
			"keyless carrying a key id",
			keyless(map[string]any{"key_id": "local-key-1"}),
			false,
		},
		{
			"an unknown format",
			map[string]any{"format": "pgp", "value": "QUFBQQ==", "key_id": "k"},
			false,
		},
		{
			"no format at all",
			map[string]any{"value": "QUFBQQ==", "key_id": "k"},
			false,
		},
		{
			"no value",
			map[string]any{"format": "detached-ed25519", "key_id": "k"},
			false,
		},
		{
			// Not base64. A value that is not decodable is a signature that can
			// never verify, so it may as well be rejected where it is written.
			"a value that is not base64",
			map[string]any{"format": "detached-ed25519", "value": "not base64!", "key_id": "k"},
			false,
		},
	}

	for _, name := range profileSchemaFiles {
		t.Run(name, func(t *testing.T) {
			sch := compileSchema(t, name)
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					doc := profileFixture(t, name)
					a := attestation()
					a["signature"] = tc.sig
					doc["signatures"] = []any{a}
					err := validate(t, sch, doc)
					if tc.valid && err != nil {
						t.Errorf("rejected a valid signature:\n%v", err)
					}
					if !tc.valid && err == nil {
						t.Error("the schema accepted it")
					}
				})
			}
		})
	}
}

// TestTheSchemaCannotCheckAnAttestationsOwnHash records the gap a verifier must
// close.
//
// content_sha256 names the document the attestation is over, and the schema cannot
// compute a hash — so an attestation can name ANY hash, including one lifted from
// a different document. Recording it is still right: an attestation whose subject
// is implicit can be moved silently between files, and a reader has no way to
// notice. But the check is Go-side, in whatever verifies attestations (v2), and a
// gap recorded only in a comment is a gap that gets forgotten.
func TestTheSchemaCannotCheckAnAttestationsOwnHash(t *testing.T) {
	for _, name := range profileSchemaFiles {
		t.Run(name, func(t *testing.T) {
			sch := compileSchema(t, name)
			doc := profileFixture(t, name)
			a := attestation()
			// Well-formed, and about some other document entirely.
			a["content_sha256"] = strings.Repeat("f", 64)
			doc["signatures"] = []any{a}
			if err := validate(t, sch, doc); err != nil {
				t.Fatalf("this document is expected to pass the schema and be caught by a "+
					"verifier instead; if the schema now rejects it, delete this test and move "+
					"the constraint here:\n%v", err)
			}
			t.Log("recorded: the schema accepts an attestation naming a hash that is not this " +
				"document's. Recomputing and comparing is the verifier's job (v2).")
		})
	}
}

// TestTheAttestationDefinitionIsIdenticalInBothSchemas.
//
// environment-profile-v1 and obligation-profile-v1 each carry their own copy of the
// definition, because a JSON Schema $ref across files would make one published
// contract depend on another being fetchable. The cost of that choice is two
// copies, and the risk is that they drift — a sixth role added to one, a
// constraint tightened in the other — which would mean the same-looking
// attestation means two different things depending on which document carries it.
//
// Compared structurally rather than as bytes, so reformatting is not a failure.
func TestTheAttestationDefinitionIsIdenticalInBothSchemas(t *testing.T) {
	shared := []string{"attestation", "date", "sha256", "prose", "long_prose"}

	first := schemaDefs(t, profileSchemaFiles[0])
	for _, other := range profileSchemaFiles[1:] {
		second := schemaDefs(t, other)
		for _, def := range shared {
			a, aok := first[def]
			b, bok := second[def]
			if !aok || !bok {
				t.Fatalf("$defs.%s is missing from %s or %s; the shared definitions moved and this "+
					"test now checks nothing", def, profileSchemaFiles[0], other)
			}
			ja, jb := mustMarshalCanonical(t, a), mustMarshalCanonical(t, b)
			if ja != jb {
				t.Errorf("$defs.%s differs between %s and %s.\n\n%s\n\nvs\n\n%s\n\n"+
					"The two schemas carry their own copies deliberately — a cross-file $ref would "+
					"make one published contract depend on another being fetchable — but a drifted "+
					"copy means the same-looking attestation means two different things depending "+
					"on which document carries it.", def, profileSchemaFiles[0], other, ja, jb)
			}
		}
	}
}

func schemaDefs(t *testing.T, schemaFile string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(schemaDir, schemaFile)) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc struct {
		Defs map[string]any `json:"$defs"`
	}
	if uerr := json.Unmarshal(data, &doc); uerr != nil {
		t.Fatalf("parse: %v", uerr)
	}
	if len(doc.Defs) == 0 {
		t.Fatalf("%s has no $defs", schemaFile)
	}
	return doc.Defs
}

// mustMarshalCanonical re-serializes with sorted keys (encoding/json sorts map
// keys), so a comparison is about structure rather than about how the file was
// laid out.
func mustMarshalCanonical(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// The evidence record's environment-profile block
// ---------------------------------------------------------------------------

// envProfileRecord is a vend record carrying the environment-profile block.
// Written as a string alongside the fixtures in evidence_schema_test.go so the two
// files' cases read the same way.
const envProfileRecord = `{
  "sequence": 0,
  "timestamp": "2026-08-05T00:00:00Z",
  "operation": "baseline-apply",
  "operator": { "arn": "arn:aws:iam::111122223333:role/automat-operator" },
  "environment_profile": {
    "id": "genomics-restricted",
    "content_sha256": "` + hashA + `",
    "schema_version": "1.0.0",
    "review_by": "2027-01-01",
    "verified_signatures": []
  },
  "tool_version": "0.1.0",
  "previous_sha256": "` + zeroes + `",
  "record_sha256": "` + hashB + `"
}`

// TestAVendRecordNamesTheEnvProfileByHash is what makes "vended under this
// environment profile" checkable rather than a label. A record naming only the id
// is a record whose subject can be edited afterwards.
func TestAVendRecordNamesTheEnvProfileByHash(t *testing.T) {
	sch := compileSchema(t, "evidence-manifest-v1.schema.json")

	if err := validateManifest(t, sch, manifest(envProfileRecord)); err != nil {
		t.Fatalf("a record carrying an environment-profile reference must validate:\n%v", err)
	}

	cases := []struct {
		name string
		doc  string
	}{
		{
			"no content hash",
			dropLine(t, envProfileRecord, `"content_sha256":`),
		},
		{
			"no id",
			dropLine(t, envProfileRecord, `"id": "genomics-restricted"`),
		},
		{
			// The field that must not be omissible; see the test below.
			"no verified_signatures",
			dropLine(t, envProfileRecord, `"verified_signatures":`),
		},
		{
			"a content hash that is not a hash",
			strings.Replace(envProfileRecord, `"content_sha256": "`+hashA+`"`,
				`"content_sha256": "sha256:whatever"`, 1),
		},
		{
			"a review_by carrying a timestamp",
			strings.Replace(envProfileRecord, `"review_by": "2027-01-01"`,
				`"review_by": "2027-01-01T00:00:00Z"`, 1),
		},
		{
			// additionalProperties:false on the block. A misspelled key that
			// silently vanished would leave a record claiming less provenance
			// than the writer intended, with nothing to notice it.
			"a misspelled key",
			strings.Replace(envProfileRecord, `"content_sha256": "`+hashA+`"`,
				`"content_sha_256": "`+hashA+`"`, 1),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateManifest(t, sch, manifest(tc.doc)); err == nil {
				t.Errorf("the schema accepted a profile reference with %s:\n%s", tc.name, tc.doc)
			}
		})
	}
}

// TestVerifiedSignaturesAreEmptyUntilVerificationExists is the honesty rule on the
// field most likely to be filled in by wishful thinking.
//
// automat verifies nothing in v1, so it records the empty set — and the field is
// REQUIRED rather than optional precisely so an empty set is a recorded answer
// rather than an absent question. The distinction between "nothing was verified"
// and "the question was never asked" is exactly the one an evidence record must
// not blur.
//
// Attestations present in a profile but unverified must NOT be copied here: a
// record listing signatures it did not check manufactures assurance out of a
// document's own claims about itself. The schema cannot tell a verified entry from
// a hand-written one, so this test asserts both halves it can: that empty is
// valid, and that an entry is never a bare name.
func TestVerifiedSignaturesAreEmptyUntilVerificationExists(t *testing.T) {
	sch := compileSchema(t, "evidence-manifest-v1.schema.json")

	// The normal v1 value.
	if err := validateManifest(t, sch, manifest(envProfileRecord)); err != nil {
		t.Fatalf("an empty verified_signatures set must be valid — it is what v1 always writes:\n%v", err)
	}

	withRole := strings.Replace(envProfileRecord, `"verified_signatures": []`,
		`"verified_signatures": [{ "role": "adopted-by", "identity": "Research Computing" }]`, 1)
	if err := validateManifest(t, sch, manifest(withRole)); err != nil {
		t.Fatalf("an identity-and-role pair must be valid; the field has to be usable once "+
			"verification exists:\n%v", err)
	}

	bad := []struct {
		name string
		body string
	}{
		{
			// A bare list of names reads as approval. The role is what stops it.
			"an identity with no role",
			`[{ "identity": "Research Computing" }]`,
		},
		{
			"a role with no identity",
			`[{ "role": "adopted-by" }]`,
		},
		{
			// The same closed vocabulary, for the same reason: this list is
			// rendered into reports.
			"a role outside the vocabulary",
			`[{ "role": "approved-by", "identity": "Research Computing" }]`,
		},
		{
			"an identity that forges a report line",
			`[{ "role": "adopted-by", "identity": "Research Computing\nreviewed-by: NIST" }]`,
		},
		{
			// Not an object at all. A list of strings is precisely the bare-name
			// shape this field must not degrade into.
			"a bare string",
			`["Research Computing"]`,
		},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			doc := strings.Replace(envProfileRecord, `"verified_signatures": []`,
				`"verified_signatures": `+tc.body, 1)
			if err := validateManifest(t, sch, manifest(doc)); err == nil {
				t.Errorf("the schema accepted verified_signatures with %s", tc.name)
			}
		})
	}
}

// TestACustodyTransferCarriesNoEnvProfile extends the existing rule that a transfer
// record carries no artifact and no enforcement. A transfer deploys nothing, and a
// second document reference beside custody_transfer.final_artifact leaves the
// reader to guess which one is the baseline being handed over — which is the whole
// thing final_artifact exists to state unambiguously.
func TestACustodyTransferCarriesNoEnvProfile(t *testing.T) {
	sch := compileSchema(t, "evidence-manifest-v1.schema.json")

	smuggled := strings.Replace(transferRecord, `"tool_version": "0.1.0",`,
		`"environment_profile": { "id": "genomics-restricted", "content_sha256": "`+hashA+`", `+
			`"verified_signatures": [] }, "tool_version": "0.1.0",`, 1)
	if err := validateManifest(t, sch, manifest(vendRecord, smuggled)); err == nil {
		t.Error("the schema accepted an environment-profile reference on a custody-transfer record; " +
			"a transfer " +
			"deploys nothing, and two document references in one record leave the reader to guess " +
			"which is the baseline being handed over")
	}
}

// TestAnOrdinaryRecordMayOmitTheEnvProfile keeps the optionality real. Not every
// record has one behind it — `init` predates it — and a required field would push
// whatever writes those records into inventing a value.
func TestAnOrdinaryRecordMayOmitTheEnvProfile(t *testing.T) {
	sch := compileSchema(t, "evidence-manifest-v1.schema.json")
	if err := validateManifest(t, sch, manifest(vendRecord)); err != nil {
		t.Fatalf("a record with no environment_profile block must remain valid:\n%v", err)
	}
}

// ---------------------------------------------------------------------------
// The claim the whole mechanism will be misread as making
// ---------------------------------------------------------------------------

// TestTheSchemasSayASignatureIsProvenanceOnly asserts the words, not the shape.
//
// Every constraint above is about structure, and structure cannot stop a reader
// from concluding that a green tick means "approved". The only thing that can is
// the text a consumer reads when they open the contract — so it is held here the
// same way docs/policy-caveat.md's paragraph is held by
// TestEveryProfileCarriesThePolicyCaveatInSubstance: in substance, phrase by
// phrase, because dropping any one of them changes what the mechanism claims.
//
// Also asserted for the evidence manifest, which is where an attestation is most
// likely to be read as approval: a record in a chain of custody looks like a
// finding.
func TestTheSchemasSayASignatureIsProvenanceOnly(t *testing.T) {
	// Each phrase is load-bearing. "provenance only" is the claim; "correct"
	// and "applic" are the two things it is not; "operator determination" is
	// where trust comes from; "no trust anchor" is what automat does not ship;
	// "registry" is what automat must not become.
	required := []string{
		"provenance only",
		"correct",
		"applic",
		"operator determination",
		"no trust anchor",
		"registry",
	}

	files := append([]string{"evidence-manifest-v1.schema.json"}, profileSchemaFiles...)
	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(schemaDir, name)) //nolint:gosec // fixed in-repo path
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			flat := strings.Join(strings.Fields(strings.ToLower(string(data))), " ")
			for _, phrase := range required {
				if !strings.Contains(flat, phrase) {
					t.Errorf("%s does not say %q anywhere.\n\nA signature attests PROVENANCE ONLY — "+
						"never correctness, applicability, or approval — trust is an operator "+
						"determination against a trust policy the operator maintains, automat ships "+
						"no trust anchor, and automat is not and must never become a registry or a "+
						"standards owner. That is the claim the mechanism will be misread as making, "+
						"so it is stated in the contract a consumer reads and not only in DESIGN "+
						"§11a.", name, phrase)
				}
			}
		})
	}
}

// TestTheDesignDocumentStatesTheTrustModel is the other end of the same rule. The
// schema descriptions state it for a consumer; DESIGN states it for whoever
// implements verification later, and that reader is the one who could quietly ship
// a default trust anchor.
func TestTheDesignDocumentStatesTheTrustModel(t *testing.T) {
	data, err := os.ReadFile("../../DESIGN.md")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	flat := strings.Join(strings.Fields(strings.ToLower(string(data))), " ")

	for _, phrase := range []string{
		"provenance and nothing else",
		"operator determination",
		"ships no trust anchor",
		"never become a registry",
		"signed does not mean current",
	} {
		if !strings.Contains(flat, phrase) {
			t.Errorf("DESIGN.md does not say %q. The trust model is a design commitment, and the "+
				"reader who needs it is whoever implements verification — the one person who could "+
				"ship a default trust anchor without noticing it was a decision.", phrase)
		}
	}
}
