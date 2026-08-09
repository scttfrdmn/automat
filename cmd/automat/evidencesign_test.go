// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/scttfrdmn/automat/internal/evidence"
)

const testKMSKeyID = "arn:aws:kms:us-east-1:111111111111:key/test-key-1"

func writeKMSSigningConfig(t *testing.T, g *globals) {
	t.Helper()
	writeConfig(t, g, `
[context.c]
org = "`+testOrg+`"
evidence_kms_key_id = "`+testKMSKeyID+`"
evidence_kms_algorithm = "aws-kms-rsassa-pss-sha-256"
`)
}

// TestVendSignsWithKMSWhenConfigured is the end-to-end proof that
// evidence_kms_key_id/evidence_kms_algorithm actually reach Manifest.Append
// — DESIGN §11's "KMS later" half landing as a real, working drop-in
// alongside the local ed25519 signer, not just a config field nobody reads.
func TestVendSignsWithKMSWhenConfigured(t *testing.T) {
	g, f := vendWorld(t)
	writeKMSSigningConfig(t, g)
	profile := vendProfileJSON(t, nil)

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend: %v", err)
	}
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("vend produced %d accounts, want 1", len(accounts))
	}
	accountID := accounts[0]

	manifestPath := "evidence/" + accountID + ".json"
	m, err := evidence.LoadOrNew(manifestPath, accountID, accountID, "", "", nil)
	if err != nil {
		t.Fatalf("load the evidence manifest: %v", err)
	}
	if len(m.Records) == 0 {
		t.Fatal("manifest has no records")
	}
	for _, rec := range m.Records {
		if rec.Signature == nil {
			t.Errorf("record %s has no signature, want one signed with the configured KMS key",
				rec.Operation)
			continue
		}
		if rec.Signature.KeyID != testKMSKeyID {
			t.Errorf("record %s signed by key %q, want %q", rec.Operation, rec.Signature.KeyID, testKMSKeyID)
		}
		if rec.Signature.Algorithm != string(evidence.AlgKMSRSAPSS256) {
			t.Errorf("record %s signature algorithm = %q, want %q",
				rec.Operation, rec.Signature.Algorithm, evidence.AlgKMSRSAPSS256)
		}
	}
	for _, call := range f.KMS.Calls() {
		if call != "Sign" {
			t.Errorf("KMS fake saw unexpected call %s", call)
		}
	}
	if err := m.VerifyChain(&evidence.KMSVerifier{API: f.KMS, KeyID: testKMSKeyID}); err != nil {
		t.Errorf("the KMS-signed chain does not verify against its own key:\n%v", err)
	}
}

// TestReclaimSignsWithKMSWhenConfigured is the same proof for the
// destructive command — the one place a wrong signer wiring would be
// hardest to notice, since reclaim's own record is small.
func TestReclaimSignsWithKMSWhenConfigured(t *testing.T) {
	g, f := vendWorld(t)
	// Configured before any command runs: globals caches the parsed config
	// on first load (g.loaded), so writing it after vendThenVerify's own
	// runCLI calls would be silently ignored.
	writeKMSSigningConfig(t, g)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	if _, _, err := runCLI(t, g, reclaimArgs(accountID, "--yes")...); err != nil {
		t.Fatalf("reclaim --yes: %v", err)
	}

	manifestPath := "evidence/" + accountID + ".json"
	m, err := evidence.LoadOrNew(manifestPath, accountID, accountID, "", "", nil)
	if err != nil {
		t.Fatalf("load the evidence manifest: %v", err)
	}
	var found bool
	for _, rec := range m.Records {
		if rec.Operation != evidence.OpReclaim {
			continue
		}
		found = true
		if rec.Signature == nil {
			t.Error("OpReclaim record has no signature, want one signed with the configured KMS key")
		} else if rec.Signature.KeyID != testKMSKeyID {
			t.Errorf("OpReclaim record signed by key %q, want %q", rec.Signature.KeyID, testKMSKeyID)
		}
	}
	if !found {
		t.Fatal("manifest has no OpReclaim record")
	}
}

// TestVendLeavesRecordsUnsignedByDefault confirms the opt-in half: with no
// evidence_kms_* config, records stay unsigned exactly as before this
// feature existed — Signer's own doc comment calls that a valid document.
func TestVendLeavesRecordsUnsignedByDefault(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend: %v", err)
	}
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("vend produced %d accounts, want 1", len(accounts))
	}
	manifestPath := "evidence/" + accounts[0] + ".json"
	m, err := evidence.LoadOrNew(manifestPath, accounts[0], accounts[0], "", "", nil)
	if err != nil {
		t.Fatalf("load the evidence manifest: %v", err)
	}
	for _, rec := range m.Records {
		if rec.Signature != nil {
			t.Errorf("record %s is signed with no evidence_kms_* config set", rec.Operation)
		}
	}
	for _, call := range f.KMS.Calls() {
		t.Errorf("KMS fake saw a call (%s) with no evidence_kms_* config set", call)
	}
}
