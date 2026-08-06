// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schema/evidence-manifest-v1.schema.json is the published compatibility contract;
// the Go types and Validate() in this package are the implementation. Until this
// commit the schema had no Go types at all — schema/CHANGELOG.md says so twice — so
// this is the first time the two can disagree, and therefore the first time drift
// is possible.
//
// The failure mode that matters: an external consumer trusting schema/ would accept
// documents automat rejects, or automat would write a manifest that violates the
// published contract. For an evidence document the second is worse than usual,
// because the consumer is whatever an institution ingests its compliance record
// into, and a manifest it silently drops fields from is a chain of custody with
// holes nobody sees.
//
// Mirrors internal/artifact/schema_conformance_test.go, deliberately: one pattern
// for both, so a maintainer who has read one knows what this is.

const (
	schemaDir  = "../../schema"
	schemaFile = "evidence-manifest-v1.schema.json"
)

func compileManifestSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join(schemaDir, schemaFile)
	f, err := os.Open(path) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	c := jsonschema.NewCompiler()
	if aerr := c.AddResource(schemaFile, doc); aerr != nil {
		t.Fatalf("add %s: %v", path, aerr)
	}
	sch, err := c.Compile(schemaFile)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return sch
}

// asGeneric round-trips a manifest through JSON into the shape the schema validator
// expects, so the schema sees exactly the bytes automat would write — not a
// convenient reconstruction of them.
func asGeneric(t *testing.T, m *Manifest) any {
	t.Helper()
	raw, err := m.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// TestWhatThisPackageWritesSatisfiesThePublishedSchema is the direction that would
// break consumers. The golden manifest is the subject because it is the widest
// document automat can produce.
func TestWhatThisPackageWritesSatisfiesThePublishedSchema(t *testing.T) {
	sch := compileManifestSchema(t)
	m := goldenManifest(t)
	if err := sch.Validate(asGeneric(t, m)); err != nil {
		data, _ := m.MarshalIndented()
		t.Errorf("a manifest this package considers valid violates the published schema:\n%v\n\n"+
			"document:\n%s", err, data)
	}
}

// TestTheCommittedGoldenFileSatisfiesThePublishedSchema checks the bytes rather than
// the struct. Belt and braces on purpose: the golden file is what a reviewer reads
// and what a consumer would be handed as an example, and it could go stale
// independently of the code that generated it.
func TestTheCommittedGoldenFileSatisfiesThePublishedSchema(t *testing.T) {
	sch := compileManifestSchema(t)
	data, err := os.ReadFile(goldenPath) //nolint:gosec // fixed testdata path
	if err != nil {
		t.Fatalf("read %s: %v", goldenPath, err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse %s: %v", goldenPath, err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Errorf("%s violates the published schema:\n%v", goldenPath, err)
	}
}

// validManifest is the base document the rejection cases mutate: two ordinary
// records, every optional block absent, so each case introduces exactly one defect.
func validManifest(t *testing.T) *Manifest {
	t.Helper()
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts1), nil)
	return m
}

// relink recomputes the sequence numbers, links, and hashes after a case has
// rewritten a record's content.
//
// Needed because these cases mutate records directly rather than going through
// Append, which is the only way to reach the constraints Append itself enforces.
// Without it every case would also break the chain, and both validators would
// reject the document for that instead of for the thing under test — the Go one via
// validateChain and the schema not at all, which would make the pairing meaningless.
func relink(t *testing.T, m *Manifest) {
	t.Helper()
	for i := range m.Records {
		m.Records[i].Sequence = i
		if i == 0 {
			m.Records[i].PreviousSHA = ZeroHash
		} else {
			m.Records[i].PreviousSHA = m.Records[i-1].RecordSHA
		}
		m.Records[i].RecordSHA = ""
		h, err := recordHash(m.Records[i])
		if err != nil {
			t.Fatalf("hash records[%d]: %v", i, err)
		}
		m.Records[i].RecordSHA = h
	}
}

// TestGoAndSchemaAgreeOnRejection is the drift detector: for each way of breaking a
// manifest, both the hand-written Go validator and the published JSON Schema must
// reject it. A case only one of them catches is drift, and the failure message says
// which side is missing the check.
func TestGoAndSchemaAgreeOnRejection(t *testing.T) {
	sch := compileManifestSchema(t)

	cases := []struct {
		name   string
		mutate func(*testing.T, *Manifest)
	}{
		// Header.
		{"missing schema version", func(_ *testing.T, m *Manifest) { m.SchemaVersion = "" }},
		{"non-semver schema version", func(_ *testing.T, m *Manifest) { m.SchemaVersion = "1.0" }},
		{"empty manifest id", func(_ *testing.T, m *Manifest) { m.Meta.ID = "" }},
		{"a manifest id containing a space", func(_ *testing.T, m *Manifest) {
			m.Meta.ID = "physics cui enclave"
		}},
		{"a manifest id containing a shell metacharacter", func(_ *testing.T, m *Manifest) {
			m.Meta.ID = "444455556666`whoami`"
		}},
		{"bad account id in the header", func(_ *testing.T, m *Manifest) { m.Meta.AccountID = "4444" }},
		{"bad organization id", func(_ *testing.T, m *Manifest) { m.Meta.OrganizationID = "org-1" }},
		{"missing created_at", func(_ *testing.T, m *Manifest) { m.Meta.CreatedAt = "" }},
		{"sub-second created_at", func(_ *testing.T, m *Manifest) {
			m.Meta.CreatedAt = "2026-08-05T00:00:00.5Z"
		}},
		{"created_at with an offset", func(_ *testing.T, m *Manifest) {
			m.Meta.CreatedAt = "2026-08-05T00:00:00+00:00"
		}},
		{"an empty chain", func(_ *testing.T, m *Manifest) { m.Records = nil }},

		// Record scalars.
		{"a negative sequence number", func(t *testing.T, m *Manifest) {
			m.Records[0].Sequence = -1
			m.Records[1].Sequence = 0
		}},
		{"a malformed timestamp", func(t *testing.T, m *Manifest) {
			m.Records[1].Timestamp = "yesterday"
			relink(t, m)
		}},
		{"an operation outside the vocabulary", func(t *testing.T, m *Manifest) {
			m.Records[1].Operation = "delete-everything"
			relink(t, m)
		}},
		{"an outcome outside the vocabulary", func(t *testing.T, m *Manifest) {
			m.Records[1].Outcome = "mostly-fine"
			relink(t, m)
		}},
		{"no operator arn", func(t *testing.T, m *Manifest) {
			m.Records[1].Operator.ARN = ""
			relink(t, m)
		}},
		{"a bad operator account id", func(t *testing.T, m *Manifest) {
			m.Records[1].Operator.AccountID = "not-an-account"
			relink(t, m)
		}},
		{"no tool version", func(t *testing.T, m *Manifest) {
			m.Records[1].ToolVersion = ""
			relink(t, m)
		}},
		{"a previous_sha256 that is not a hash", func(_ *testing.T, m *Manifest) {
			m.Records[1].PreviousSHA = "unknown"
		}},
		{"an uppercase record_sha256", func(_ *testing.T, m *Manifest) {
			// Both sides pin lowercase hex. Uppercase is the same digest to a human and
			// a different string to every comparison in this package, so a manifest
			// carrying one would fail VerifyChain for a reason that looks like tampering.
			m.Records[1].RecordSHA = strings.ToUpper(m.Records[1].RecordSHA)
		}},
		// A request id is the one field an operator retypes, as
		// `vend --resume <request-id>`. Whitespace and metacharacters are refused for
		// that reason and not for tidiness.
		{"a request id that is only a space", func(t *testing.T, m *Manifest) {
			m.Records[1].RequestID = " "
			relink(t, m)
		}},
		{"a request id containing a shell metacharacter", func(t *testing.T, m *Manifest) {
			m.Records[1].RequestID = "req-abc123; rm -rf /"
			relink(t, m)
		}},
		{"a request id containing a quote", func(t *testing.T, m *Manifest) {
			m.Records[1].RequestID = `req-"abc123"`
			relink(t, m)
		}},
		{"a request id longer than the cap", func(t *testing.T, m *Manifest) {
			m.Records[1].RequestID = "req-" + strings.Repeat("a", 128)
			relink(t, m)
		}},

		// Target.
		{"a bad target account id", func(t *testing.T, m *Manifest) {
			m.Records[1].Target.AccountID = "44445555666"
			relink(t, m)
		}},
		{"a bad OU id", func(t *testing.T, m *Manifest) {
			m.Records[1].Target.OUID = "ou-toplevel"
			relink(t, m)
		}},
		{"a bad region", func(t *testing.T, m *Manifest) {
			m.Records[1].Target.Region = "US-East-1"
			relink(t, m)
		}},

		// Artifact and profile references.
		{"an artifact id that is not an id", func(t *testing.T, m *Manifest) {
			m.Records[1].Artifact.ID = "CMMC L1"
			relink(t, m)
		}},
		{"an artifact with no content hash", func(t *testing.T, m *Manifest) {
			m.Records[1].Artifact.ContentSHA256 = ""
			relink(t, m)
		}},
		{"a profile with no content hash", func(t *testing.T, m *Manifest) {
			m.Records[1].Profile.ContentSHA256 = ""
			relink(t, m)
		}},
		{"a profile review_by carrying a timestamp", func(t *testing.T, m *Manifest) {
			m.Records[1].Profile.ReviewBy = ts0
			relink(t, m)
		}},
		{"an attestation role outside the vocabulary", func(t *testing.T, m *Manifest) {
			m.Records[1].Profile.VerifiedSignatures = []VerifiedSignature{
				{Role: "approved-by", Identity: "Research Computing"},
			}
			relink(t, m)
		}},
		{"an attestation with no identity", func(t *testing.T, m *Manifest) {
			m.Records[1].Profile.VerifiedSignatures = []VerifiedSignature{{Role: RoleAdoptedBy}}
			relink(t, m)
		}},
		{"an attestation identity containing a newline", func(t *testing.T, m *Manifest) {
			m.Records[1].Profile.VerifiedSignatures = []VerifiedSignature{
				{Role: RoleAdoptedBy, Identity: "Research Computing\nreviewed-by: NIST"},
			}
			relink(t, m)
		}},
		{"the same attestation twice", func(t *testing.T, m *Manifest) {
			vs := VerifiedSignature{Role: RoleAdoptedBy, Identity: "Research Computing"}
			m.Records[1].Profile.VerifiedSignatures = []VerifiedSignature{vs, vs}
			relink(t, m)
		}},
		{"more attestations than the cap", func(t *testing.T, m *Manifest) {
			var vs []VerifiedSignature
			for i := 0; i <= maxVerifiedSignatures; i++ {
				vs = append(vs, VerifiedSignature{
					Role:     RoleAdoptedBy,
					Identity: "Signer " + string(rune('a'+i%26)) + strings.Repeat("x", i),
				})
			}
			m.Records[1].Profile.VerifiedSignatures = vs
			relink(t, m)
		}},

		// Enforcement.
		{"a bad region in the enforcement set", func(t *testing.T, m *Manifest) {
			m.Records[1].Enforcement = &Enforcement{RegionSet: []string{"us_east_1"}}
			relink(t, m)
		}},
		{"a bad service namespace", func(t *testing.T, m *Manifest) {
			m.Records[1].Enforcement = &Enforcement{ServiceSet: []string{"Amazon S3"}}
			relink(t, m)
		}},
		{"an empty SCP arn", func(t *testing.T, m *Manifest) {
			m.Records[1].Enforcement = &Enforcement{SCPARNs: []string{"arn:a", ""}}
			relink(t, m)
		}},
		// The enforcement lists are sets in the schema (uniqueItems). A repeated
		// member makes a record read as more enforcement than was applied, and an
		// enforcement list is the part of a record an auditor counts.
		{"a duplicated SCP arn", func(t *testing.T, m *Manifest) {
			m.Records[1].Enforcement = &Enforcement{SCPARNs: []string{"arn:a", "arn:a"}}
			relink(t, m)
		}},
		{"a duplicated config rule", func(t *testing.T, m *Manifest) {
			m.Records[1].Enforcement = &Enforcement{
				ConfigRuleNames: []string{"IAM_PASSWORD_POLICY", "IAM_PASSWORD_POLICY"},
			}
			relink(t, m)
		}},
		{"a duplicated region", func(t *testing.T, m *Manifest) {
			m.Records[1].Enforcement = &Enforcement{RegionSet: []string{"us-east-1", "us-east-1"}}
			relink(t, m)
		}},
		{"a duplicated attestation id", func(t *testing.T, m *Manifest) {
			m.Records[1].Enforcement = &Enforcement{
				AttestationIDs: []string{"MP.L1-b.1.vii", "MP.L1-b.1.vii"},
			}
			relink(t, m)
		}},

		// Errors.
		{"an error block with no message", func(t *testing.T, m *Manifest) {
			m.Records[1].Outcome = OutcomeParked
			m.Records[1].Err = &RecordError{Action: "organizations:AttachPolicy"}
			relink(t, m)
		}},

		// Custody transfer. Both validators express these; the Go side duplicates
		// them because automat's writer never round-trips through the schema.
		{"a custody transfer on an ordinary record", func(t *testing.T, m *Manifest) {
			m.Records[1].Custody = &Custody{
				Transferee: "Research Computing", EffectiveDate: "2026-09-01",
				Reason:        "Handed over.",
				FinalArtifact: DocRef{ID: "cmmc-l1", ContentSHA256: someHash},
			}
			relink(t, m)
		}},
		{"a custody-transfer record with no payload", func(t *testing.T, m *Manifest) {
			m.Records[1] = Record{
				Timestamp: ts1, Operation: OpCustodyTransfer,
				Operator: Operator{ARN: operator}, ToolVersion: toolVer,
			}
			relink(t, m)
		}},
		{"a custody transfer with no transferee", func(t *testing.T, m *Manifest) {
			r := transferRec(ts1)
			r.Custody.Transferee = ""
			m.Records[1] = r
			relink(t, m)
		}},
		{"a custody transfer with a reason containing a newline", func(t *testing.T, m *Manifest) {
			r := transferRec(ts1)
			r.Custody.Reason = "Approved\n- account-move: 111122223333 -> r-root"
			m.Records[1] = r
			relink(t, m)
		}},
		{"a custody transfer whose successor id is not typeable", func(t *testing.T, m *Manifest) {
			// Rule 8's longest fuse: the reader of this pointer is a successor auditor
			// years from now holding nothing but the record.
			r := transferRec(ts1)
			r.Custody.SuccessorManifestID = "rc central 444455556666; rm -rf ."
			m.Records[1] = r
			relink(t, m)
		}},
		{"a custody transfer whose effective_date is a timestamp", func(t *testing.T, m *Manifest) {
			r := transferRec(ts1)
			r.Custody.EffectiveDate = ts1
			m.Records[1] = r
			relink(t, m)
		}},
		{"a failed custody transfer", func(t *testing.T, m *Manifest) {
			r := transferRec(ts1)
			r.Outcome = OutcomeFailure
			r.Err = &RecordError{Message: "the transfer did not happen"}
			m.Records[1] = r
			relink(t, m)
		}},
		{"a custody transfer carrying an artifact", func(t *testing.T, m *Manifest) {
			r := transferRec(ts1)
			r.Artifact = &DocRef{ID: "cmmc-l1", ContentSHA256: otherHash}
			m.Records[1] = r
			relink(t, m)
		}},
		{"a custody transfer carrying enforcement", func(t *testing.T, m *Manifest) {
			r := transferRec(ts1)
			r.Enforcement = &Enforcement{ConformancePackARN: "arn:aws:config:us-east-1:1:pack/x"}
			m.Records[1] = r
			relink(t, m)
		}},
		{"a custody transfer carrying a profile", func(t *testing.T, m *Manifest) {
			r := transferRec(ts1)
			r.Profile = &ProfileRef{ID: "research-cui", ContentSHA256: otherHash,
				VerifiedSignatures: []VerifiedSignature{}}
			m.Records[1] = r
			relink(t, m)
		}},
		{"two custody transfers", func(t *testing.T, m *Manifest) {
			m.Records[0] = transferRec(ts0)
			m.Records[1] = transferRec(ts1)
			relink(t, m)
		}},

		// Signature.
		{"a signature with an unknown algorithm", func(t *testing.T, m *Manifest) {
			relink(t, m)
			m.Records[1].Signature = &Signature{Algorithm: "rot13", KeyID: "k1", Value: "AAAA"}
		}},
		{"a signature with no key id", func(t *testing.T, m *Manifest) {
			relink(t, m)
			m.Records[1].Signature = &Signature{
				Algorithm: string(AlgEd25519), KeyID: "", Value: "AAAA",
			}
		}},
		{"a signature key id containing whitespace", func(t *testing.T, m *Manifest) {
			// The verifier's own remediation text tells the operator to supply the key
			// the record names, so a key id has to be a thing they can type.
			relink(t, m)
			m.Records[1].Signature = &Signature{
				Algorithm: string(AlgEd25519), KeyID: "my signing key", Value: "AAAA",
			}
		}},
		{"a signature key id containing a shell metacharacter", func(t *testing.T, m *Manifest) {
			relink(t, m)
			m.Records[1].Signature = &Signature{
				Algorithm: string(AlgEd25519), KeyID: "k1;curl evil.example", Value: "AAAA",
			}
		}},
		{"a signature value that is not base64", func(t *testing.T, m *Manifest) {
			relink(t, m)
			m.Records[1].Signature = &Signature{
				Algorithm: string(AlgEd25519), KeyID: "k1", Value: "not base64!",
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest(t)
			tc.mutate(t, m)

			goErr := m.Validate()
			schemaErr := sch.Validate(asGeneric(t, m))

			switch {
			case goErr == nil && schemaErr == nil:
				t.Errorf("neither the Go validator nor the published schema rejected %q", tc.name)
			case goErr == nil:
				t.Errorf("the published schema rejects %q but internal/evidence accepts it — "+
					"Validate() is missing a check:\n%v", tc.name, schemaErr)
			case schemaErr == nil:
				t.Errorf("internal/evidence rejects %q but the published schema accepts it — "+
					"schema/%s is missing a constraint:\n%v", tc.name, schemaFile, goErr)
			}
		})
	}
}

// TestTheSchemaAcceptsWhatGoAccepts is the other direction, on documents that should
// pass. A Go validator stricter than the published schema is a different bug from
// drift and just as real: it means automat refuses a manifest it told consumers was
// valid — including, eventually, one written by an older automat.
func TestTheSchemaAcceptsWhatGoAccepts(t *testing.T) {
	sch := compileManifestSchema(t)

	cases := []struct {
		name   string
		mutate func(*testing.T, *Manifest)
	}{
		{"a chain of one record", func(t *testing.T, m *Manifest) {
			m.Records = m.Records[:1]
		}},
		{"no optional header fields", func(t *testing.T, m *Manifest) {
			m.Meta.AccountID = ""
			m.Meta.OrganizationID = ""
		}},
		{"no target, artifact, or profile", func(t *testing.T, m *Manifest) {
			// The shape an `init` record has: it predates any profile, and it acts on
			// the organization rather than on an account.
			m.Records[1].Operation = OpInit
			m.Records[1].Target = nil
			m.Records[1].Artifact = nil
			m.Records[1].Profile = nil
			m.Records[1].RequestID = ""
			relink(t, m)
		}},
		{"an outcome spelled out rather than defaulted", func(t *testing.T, m *Manifest) {
			m.Records[1].Outcome = OutcomeSuccess
			relink(t, m)
		}},
		{"a parked record with its full remediation", func(t *testing.T, m *Manifest) {
			m.Records[1].Outcome = OutcomeParked
			m.Records[1].Err = &RecordError{
				Message:     "attaching the policy was denied",
				Action:      "organizations:AttachPolicy",
				Resource:    "arn:aws:organizations::111122223333:ou/o-abc1234567/ou-abc1-12345678",
				Remediation: "grant organizations:AttachPolicy on the destination OU",
			}
			relink(t, m)
		}},
		{"a failure record", func(t *testing.T, m *Manifest) {
			m.Records[1].Outcome = OutcomeFailure
			m.Records[1].Err = &RecordError{Message: "the API call timed out"}
			relink(t, m)
		}},
		{"an error with only a message", func(t *testing.T, m *Manifest) {
			// Not every failure is a permission failure; a timeout has no action or
			// resource to name, and requiring them would make the record dishonest.
			m.Records[1].Outcome = OutcomeFailure
			m.Records[1].Err = &RecordError{Message: "the API call timed out"}
			relink(t, m)
		}},
		{"every enforcement field at once", func(t *testing.T, m *Manifest) {
			m.Records[1].Enforcement = &Enforcement{
				SCPARNs:            []string{"arn:aws:organizations::1:policy/o-a/service_control_policy/p-1"},
				ConformancePackARN: "arn:aws:config:us-east-1:444455556666:conformance-pack/p/abcd1234",
				ConfigRuleNames:    []string{"IAM_PASSWORD_POLICY"},
				RegionSet:          []string{"us-east-1", "us-gov-west-1"},
				ServiceSet:         []string{"organizations", "config"},
				AttestationIDs:     []string{"MP.L1-b.1.vii"},
			}
			relink(t, m)
		}},
		{"a root id as the target", func(t *testing.T, m *Manifest) {
			m.Records[1].Target.OUID = "r-abc1"
			relink(t, m)
		}},
		{"an operator with every optional field", func(t *testing.T, m *Manifest) {
			m.Records[1].Operator = Operator{
				ARN:         "arn:aws:sts::111122223333:assumed-role/automat-operator/session",
				AccountID:   acct,
				UserID:      "AROAEXAMPLEEXAMPLE:session",
				AssumedRole: "automat-operator",
			}
			relink(t, m)
		}},
		{"a custody transfer closing the chain", func(t *testing.T, m *Manifest) {
			m.Records[1] = transferRec(ts1)
			relink(t, m)
		}},
		{"a custody transfer with no successor manifest", func(t *testing.T, m *Manifest) {
			// A transfer out of automat's scope entirely has no successor, and
			// inventing one would be a false claim of continuity.
			r := transferRec(ts1)
			r.Custody.SuccessorManifestID = ""
			m.Records[1] = r
			relink(t, m)
		}},
		{"a signed record", func(t *testing.T, m *Manifest) {
			signer := testSigner(t)
			relink(t, m)
			sig, err := signer.Sign([]byte(m.Records[1].RecordSHA))
			if err != nil {
				t.Fatal(err)
			}
			m.Records[1].Signature = sig
		}},
		{"a record signed by KMS", func(t *testing.T, m *Manifest) {
			// This package cannot produce one, but the algorithms are named in the
			// schema so adopting one is not a schema version event (DESIGN §11) — and
			// a manifest a future automat writes must load in this one.
			relink(t, m)
			m.Records[1].Signature = &Signature{
				Algorithm: string(AlgKMSRSAPSS256),
				KeyID:     "arn:aws:kms:us-east-1:111122223333:key/abcd1234-0000-0000-0000-000000000000",
				Value:     "QUJDREVG",
			}
		}},
		{"a KMS key ARN as the key id", func(t *testing.T, m *Manifest) {
			// The reason round_trip_ref is a separate $def from round_trip_id: a key id
			// automat does not mint cannot be reduced to a plain id, and a pattern that
			// rejected the colons and slashes of an ARN would make rule 8 unimplementable
			// for the KMS signer rather than enforced.
			relink(t, m)
			m.Records[1].Signature = &Signature{
				Algorithm: string(AlgKMSECDSA256),
				KeyID: "arn:aws:kms:us-gov-west-1:111122223333:key/" +
					"abcd1234-0000-0000-0000-000000000000",
				Value: "QUJDREVG",
			}
		}},
		{"a key id that is a bare KMS alias", func(t *testing.T, m *Manifest) {
			relink(t, m)
			m.Records[1].Signature = &Signature{
				Algorithm: string(AlgKMSECDSA256), KeyID: "alias/automat-evidence", Value: "QUJDREVG",
			}
		}},
		{"a lapsed review date", func(t *testing.T, m *Manifest) {
			// Lapse is a `verify` warning about the document, not a validation
			// error: a validator with a clock would make every archived manifest
			// invalid.
			m.Records[1].Profile.ReviewBy = "1999-01-01"
			relink(t, m)
		}},
		{"no review date at all", func(t *testing.T, m *Manifest) {
			m.Records[1].Profile.ReviewBy = ""
			relink(t, m)
		}},
		{"attestations at the cap", func(t *testing.T, m *Manifest) {
			// Not reachable through Append in v1 by design, but the schema admits it
			// and a future automat will write it, so this package must load it.
			var vs []VerifiedSignature
			for i := 0; i < maxVerifiedSignatures; i++ {
				vs = append(vs, VerifiedSignature{
					Role:     AllRoles[i%len(AllRoles)],
					Identity: "Signer " + strings.Repeat("x", i+1),
				})
			}
			m.Records[1].Profile.VerifiedSignatures = vs
			relink(t, m)
		}},
		{"a timestamp that steps backwards", func(t *testing.T, m *Manifest) {
			// An NTP correction between two vends. Order comes from the links.
			m.Records[1].Timestamp = "2026-08-04T00:00:00Z"
			relink(t, m)
		}},
		{"an account name with punctuation", func(t *testing.T, m *Manifest) {
			m.Records[1].Target.AccountName = "Physics & Astronomy (CUI) — shared"
			relink(t, m)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest(t)
			tc.mutate(t, m)

			if err := m.Validate(); err != nil {
				t.Fatalf("internal/evidence rejects a manifest that should be valid: %v", err)
			}
			if err := sch.Validate(asGeneric(t, m)); err != nil {
				data, _ := m.MarshalIndented()
				t.Errorf("the published schema rejects a manifest internal/evidence accepts — "+
					"schema/%s is too strict:\n%v\n\ndocument:\n%s", schemaFile, err, data)
			}
		})
	}
}

// TestTheGoVocabulariesMatchTheSchemaEnums reads the enums out of the published
// schema and holds the Go constants against them.
//
// A case-by-case test cannot catch a value the schema gained and Go did not: nothing
// would fail, and automat would reject a document the contract admits. This compares
// the sets directly, so adding an operation, outcome, role, or algorithm to either
// side alone fails here.
func TestTheGoVocabulariesMatchTheSchemaEnums(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(schemaDir, schemaFile)) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}

	cases := []struct {
		name string
		at   []string
		got  []string
	}{
		{"operation", []string{"$defs", "record", "properties", "operation", "enum"},
			stringsOf(AllOperations)},
		{"outcome", []string{"$defs", "record", "properties", "outcome", "enum"},
			stringsOf(AllOutcomes)},
		{"role", []string{"$defs", "verified_signature", "properties", "role", "enum"},
			stringsOf(AllRoles)},
		{"algorithm", []string{"$defs", "record", "properties", "signature", "properties",
			"algorithm", "enum"}, stringsOf(AllAlgorithms)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := enumAt(t, doc, tc.at)
			if len(want) == 0 {
				t.Fatalf("no enum at %s; the schema moved and this test is now checking nothing",
					strings.Join(tc.at, "."))
			}
			if strings.Join(want, ",") != strings.Join(tc.got, ",") {
				t.Errorf("the %s vocabulary differs between the schema and Go.\n  schema: %v\n  Go:     %v\n"+
					"Order matters here on purpose: the Go slice is documented as being in the schema's "+
					"order, and a value in one and not the other means automat and its published "+
					"contract disagree about what a manifest may say.", tc.name, want, tc.got)
			}
		})
	}
}

// enumAt walks a parsed schema to an enum and returns its members as strings.
func enumAt(t *testing.T, doc any, path []string) []string {
	t.Helper()
	cur := doc
	for _, key := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = obj[key]
		if !ok {
			return nil
		}
	}
	list, ok := cur.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("enum at %s has a non-string member %v", strings.Join(path, "."), v)
		}
		out = append(out, s)
	}
	return out
}

// stringsOf renders a slice of a string-kinded named type as plain strings.
func stringsOf[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// TestTheSchemaStillCannotSayCustodyTransferIsLast is the pair to
// artifact.TestTheSchemaCannotSayCustodyTransferIsLast, from this side.
//
// That test asserts the schema accepts a document with a record after a transfer.
// This one asserts the Go validator rejects the same document — so the two together
// state the whole invariant: the schema cannot say it, and this package does. If
// JSON Schema ever gains the ability to refer to an array's final position, the
// artifact-side test fails and points here.
func TestTheSchemaStillCannotSayCustodyTransferIsLast(t *testing.T) {
	sch := compileManifestSchema(t)
	m := validManifest(t)
	m.Records[0] = transferRec(ts0)
	relink(t, m)

	if err := sch.Validate(asGeneric(t, m)); err != nil {
		t.Fatalf("the published schema now rejects a record after a custody transfer. That is an "+
			"improvement, not a failure — update this test and "+
			"artifact.TestTheSchemaCannotSayCustodyTransferIsLast together:\n%v", err)
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("internal/evidence accepted a record after a custody transfer, which the schema " +
			"structurally cannot catch — this is the only thing standing there")
	}
	if !strings.Contains(err.Error(), "JSON Schema cannot state this") {
		t.Errorf("the error must say why the rule lives in Go:\n%v", err)
	}
}
