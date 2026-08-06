// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The golden manifest is named in CLAUDE.md's quality bar, and it is here for a
// stronger reason than regression.
//
// Every hash in the file is a commitment. A record's record_sha256 is computed over
// its canonical form, so any change to how a record is canonicalized — a field added
// to Record, a default filled differently, a set normalized in a new way — changes
// the hash of every record automat has ever written. Manifests already on disk would
// then fail VerifyChain, and an operator would be told their evidence was tampered
// with by a release note. That is the failure this file catches: it turns a
// canonicalization change from a silent break into a diff a human has to approve.
//
// So the golden file is not a snapshot of the layout. It is a record of the hash
// function, pinned to bytes.
//
// Update with AUTOMAT_UPDATE_GOLDEN=1, the same convention internal/bundle and gen/
// use (a flag defined in one package makes `go test ./...` fail in every other).
const updateGoldenEnv = "AUTOMAT_UPDATE_GOLDEN"

func updateGolden() bool { return os.Getenv(updateGoldenEnv) == "1" }

// goldenManifest builds the widest manifest automat can write: every optional block
// occupied at least once, a parked record with its remediation, a signed record, and
// a custody transfer closing the chain.
//
// Fixed values throughout — no clock, no random source, and a fixed signing key —
// because a golden file that varies between runs becomes noise and gets ignored,
// which is the failure mode that matters here.
func goldenManifest(t *testing.T) *Manifest {
	t.Helper()
	signer := testSigner(t)
	// The manifest is about the VENDED account, not the management account the
	// operator ran from — a per-account manifest found on its own has to say which
	// account it is about, and the operator's account is already in every record.
	const vended = "444455556666"
	m := NewManifest(vended, vended, "o-abc1234567", "2026-08-05T00:00:00Z")

	// 1. The account exists. Signed, because the record that says an account was
	// created is the one an operator is least able to reconstruct from AWS.
	create := Record{
		Timestamp: "2026-08-05T00:00:01Z",
		Operation: OpAccountCreate,
		Operator: Operator{
			ARN:         "arn:aws:sts::111122223333:assumed-role/automat-operator/session",
			AccountID:   "111122223333",
			UserID:      "AROAEXAMPLEEXAMPLE:session",
			AssumedRole: "automat-operator",
		},
		RequestID: "req-abc123",
		Target: &Target{
			AccountID:   "444455556666",
			AccountName: "Physics CUI Enclave",
			OUID:        "ou-abc1-12345678",
			Region:      "us-east-1",
		},
		Artifact: &DocRef{ID: "cmmc-l1", ContentSHA256: someHash, SchemaVersion: "1.0.0"},
		EnvProfile: &EnvProfileRef{
			ID: "research-cui", ContentSHA256: otherHash, SchemaVersion: "1.0.0",
			ReviewBy:           "2026-11-10",
			VerifiedSignatures: []VerifiedSignature{},
		},
		ToolVersion: "0.1.0",
	}
	mustAppend(t, m, create, signer)

	// 2. The baseline goes on. Enforcement carries what was actually attached, with
	// the sets deliberately supplied out of order so the golden file records that
	// canonicalization sorts them.
	apply := Record{
		Timestamp:  "2026-08-05T00:00:02Z",
		Operation:  OpBaselineApply,
		Operator:   create.Operator,
		RequestID:  "req-abc123",
		Target:     &Target{AccountID: "444455556666", Region: "us-east-1"},
		Artifact:   create.Artifact,
		EnvProfile: create.EnvProfile,
		Enforcement: &Enforcement{
			SCPARNs: []string{
				"arn:aws:organizations::111122223333:policy/o-abc1234567/service_control_policy/p-region2",
				"arn:aws:organizations::111122223333:policy/o-abc1234567/service_control_policy/p-protect1",
			},
			ConformancePackARN: "arn:aws:config:us-east-1:444455556666:conformance-pack/automat-cmmc-l1/abcd1234",
			ConfigRuleNames:    []string{"IAM_PASSWORD_POLICY", "ACCESS_KEYS_ROTATED"},
			RegionSet:          []string{"us-west-2", "us-east-1"},
			ServiceSet:         []string{"organizations", "config", "iam"},
			AttestationIDs:     []string{"MP.L1-b.1.vii"},
		},
		ToolVersion: "0.1.0",
	}
	mustAppend(t, m, apply, signer)

	// 3. A parked step. This is the record ROADMAP Phase 2 exists to produce and the
	// one an operator reads six weeks later, so the golden file pins its whole shape
	// including the remediation text (CLAUDE.md rule 7).
	parked := Record{
		Timestamp:  "2026-08-05T00:00:03Z",
		Operation:  OpSCPEnsure,
		Outcome:    OutcomeParked,
		Operator:   create.Operator,
		RequestID:  "req-abc123",
		Target:     &Target{AccountID: "444455556666", OUID: "ou-abc1-12345678"},
		Artifact:   create.Artifact,
		EnvProfile: create.EnvProfile,
		Err: &RecordError{
			Message: "attaching the baseline-protection policy to ou-abc1-12345678 was denied",
			Action:  "organizations:AttachPolicy",
			Resource: "arn:aws:organizations::111122223333:policy/o-abc1234567/" +
				"service_control_policy/p-protect1",
			Remediation: "grant organizations:AttachPolicy on ou-abc1-12345678 to the delegated " +
				"administrator role, then re-run: automat vend --resume req-abc123",
		},
		ToolVersion: "0.1.0",
	}
	mustAppend(t, m, parked, signer)

	// 4. Custody leaves. Unsigned deliberately: an operator who adopts a key partway
	// through, or stops using one, produces a mixed chain, and that is a permanent and
	// correct outcome rather than something to be repaired by rewriting records.
	transfer := Record{
		Timestamp: "2026-08-05T00:00:04Z",
		Operation: OpCustodyTransfer,
		Operator:  create.Operator,
		Custody: &Custody{
			Transferee:    "Research Computing, under the FY27 shared-services agreement",
			EffectiveDate: "2026-09-01",
			Reason: "The account moves to central IT operation; automat stops managing its " +
				"baseline and this chain ends here.",
			FinalArtifact:       DocRef{ID: "cmmc-l1", ContentSHA256: someHash, SchemaVersion: "1.0.0"},
			SuccessorManifestID: "rc-central-444455556666",
		},
		ToolVersion: "0.1.0",
	}
	mustAppend(t, m, transfer, nil)

	return m
}

const goldenPath = "testdata/golden/manifest.json"

// reMailbox matches something that could be a mailbox: a local part of at least two
// characters, an @, and a dotted domain with a plausible TLD. The same shape
// internal/bundle's golden test uses — loose enough to catch a real address that got
// into a record, tight enough not to fire on ARN punctuation.
var reMailbox = regexp.MustCompile(`[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

func TestManifestMatchesGolden(t *testing.T) {
	m := goldenManifest(t)
	got, err := m.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if updateGolden() {
		if derr := os.MkdirAll(filepath.Dir(goldenPath), 0o755); derr != nil {
			t.Fatal(derr)
		}
		// 0644: a golden file is a committed, reviewed artifact meant to be read by
		// anyone reviewing a canonicalization change, and it carries no secret — the
		// signing key behind it is a fixed test key in a public repository.
		if werr := os.WriteFile(goldenPath, got, 0o644); werr != nil { //nolint:gosec // reviewed, committed fixture
			t.Fatalf("write %s: %v", goldenPath, werr)
		}
		t.Logf("updated %s (%d bytes)", goldenPath, len(got))
		return
	}

	want, err := os.ReadFile(goldenPath) //nolint:gosec // fixed testdata path
	if err != nil {
		t.Fatalf("read %s: %v — run `AUTOMAT_UPDATE_GOLDEN=1 go test ./internal/evidence/`",
			goldenPath, err)
	}
	if string(got) != string(want) {
		t.Errorf("the manifest does not match %s.\n%s\n"+
			"If a record_sha256 changed, canonicalization changed, and every manifest already on "+
			"disk now fails VerifyChain — an operator would be told their evidence was tampered with "+
			"by a release note. Decide that deliberately, then run "+
			"`AUTOMAT_UPDATE_GOLDEN=1 go test ./internal/evidence/` and review the diff.",
			goldenPath, firstDiff(string(want), string(got)))
	}
}

// TestTheGoldenManifestVerifies is the assertion the golden file cannot make about
// itself: the committed bytes must load, and the chain in them must check out under
// the key that signed it. Without this the golden test would happily pin a broken
// chain forever.
func TestTheGoldenManifestVerifies(t *testing.T) {
	data, err := os.ReadFile(goldenPath) //nolint:gosec // fixed testdata path
	if err != nil {
		t.Fatalf("read %s: %v", goldenPath, err)
	}
	m, err := Decode(data, testSigner(t).Verifier())
	if err != nil {
		t.Fatalf("the committed golden manifest does not load and verify: %v", err)
	}
	if !m.Closed() {
		t.Error("the golden manifest does not end with a custody transfer, so it no longer " +
			"exercises the terminal record")
	}
	if len(m.Parked()) != 1 {
		t.Errorf("the golden manifest has %d parked records, want 1: the parked shape is the one "+
			"ROADMAP Phase 2 exists to produce", len(m.Parked()))
	}
	// Every optional block is occupied somewhere, or the golden file stops covering
	// the thing it is for.
	var sawEnforcement, sawSignature, sawError, sawCustody bool
	for i := range m.Records {
		r := &m.Records[i]
		sawEnforcement = sawEnforcement || r.Enforcement != nil
		sawSignature = sawSignature || r.Signature != nil
		sawError = sawError || r.Err != nil
		sawCustody = sawCustody || r.Custody != nil
	}
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"enforcement", sawEnforcement},
		{"signature", sawSignature},
		{"error", sawError},
		{"custody_transfer", sawCustody},
	} {
		if !c.ok {
			t.Errorf("no record in the golden manifest carries %s; the file is meant to pin the "+
				"hash of every block automat can write", c.name)
		}
	}
}

// TestTheGoldenManifestLeaksNothing. The manifest is the document an auditor is
// shown, and it is also the artifact most likely to be pasted into a ticket. What
// must never appear in one is key material — the test key here has a public seed, so
// a bug that wrote the private key into a record would be invisible in review
// without this check.
func TestTheGoldenManifestLeaksNothing(t *testing.T) {
	data, err := os.ReadFile(goldenPath) //nolint:gosec // fixed testdata path
	if err != nil {
		t.Fatalf("read %s: %v", goldenPath, err)
	}
	text := string(data)

	priv := testKey()
	// The seed half is the secret; the public half legitimately could appear in a
	// key reference, so only the seed is searched for.
	if strings.Contains(text, hex.EncodeToString(priv.Seed())) {
		t.Error("the manifest contains the signing key's seed")
	}
	// No mailbox: DESIGN §11 keeps the account email out of the record, since an
	// account email is a credential-reset path and a manifest is a shared document.
	if reMailbox.MatchString(text) {
		t.Errorf("the manifest contains something shaped like an email address: %q",
			reMailbox.FindString(text))
	}
	// No product references (DESIGN §15). The manifest is CLI-adjacent output and
	// the rule covers it.
	for _, bad := range []string{"control tower", "landing zone", "account factory"} {
		if strings.Contains(strings.ToLower(text), bad) {
			t.Errorf("the manifest mentions %q, which DESIGN §15 forbids", bad)
		}
	}
}

// firstDiff renders the first differing line with a little context, so a failure
// names the change rather than printing two whole manifests.
func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return fmt.Sprintf("first difference at line %d:\n  want: %s\n  got:  %s", i+1, w, g)
		}
	}
	return "the files differ only in trailing bytes"
}
