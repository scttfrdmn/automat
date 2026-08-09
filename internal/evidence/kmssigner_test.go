// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"testing"

	"github.com/scttfrdmn/automat/internal/awsfake"
)

func testKMSSigner(t *testing.T, fake *awsfake.KMS, keyID string) *KMSSigner {
	t.Helper()
	s, err := NewKMSSigner(fake, keyID, AlgKMSRSAPSS256)
	if err != nil {
		t.Fatalf("NewKMSSigner: %v", err)
	}
	return s
}

// TestKMSSignAndVerifyRoundTrip is the KMS-backed sibling of
// TestSignAndVerifyRoundTrip: a chain signed with a KMSSigner must verify
// against a KMSVerifier over the same key.
func TestKMSSignAndVerifyRoundTrip(t *testing.T) {
	fake := awsfake.NewKMS()
	signer := testKMSSigner(t, fake, "arn:aws:kms:us-east-1:111122223333:key/test-key-1")
	m := newTestManifest()
	r0 := mustAppend(t, m, vendRec(OpAccountCreate, ts0), signer)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts1), signer)

	if r0.Signature == nil {
		t.Fatal("Append with a KMS signer produced an unsigned record")
	}
	if r0.Signature.Algorithm != string(AlgKMSRSAPSS256) {
		t.Errorf("signature algorithm = %q, want %q", r0.Signature.Algorithm, AlgKMSRSAPSS256)
	}
	if r0.Signature.KeyID != signer.KeyID {
		t.Errorf("signature key id = %q, want %q", r0.Signature.KeyID, signer.KeyID)
	}

	verifier := &KMSVerifier{API: fake, KeyID: signer.KeyID}
	if err := m.VerifyChain(verifier); err != nil {
		t.Errorf("a chain automat just signed with KMS must verify:\n%v", err)
	}
}

// TestKMSSignerReportsTheKeyKMSActuallyUsed is the alias case
// KMSSigner.Sign's own doc comment names: a caller may configure an alias,
// and the record must carry the ARN KMS reports back, not the value the
// caller gave.
func TestKMSSignerReportsTheKeyKMSActuallyUsed(t *testing.T) {
	fake := awsfake.NewKMS()
	fake.ResolvedKeyID = "arn:aws:kms:us-east-1:111122223333:key/resolved-from-alias"
	signer := testKMSSigner(t, fake, "alias/automat-evidence")

	sig, err := signer.Sign([]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.KeyID != fake.ResolvedKeyID {
		t.Errorf("Signature.KeyID = %q, want the KMS-resolved %q, not the caller's alias",
			sig.KeyID, fake.ResolvedKeyID)
	}
}

// TestKMSVerifierRefusesASignatureFromADifferentKey is the security
// assertion: a signature made under one key must not verify under another,
// even though this fake's HMAC stand-in is not real asymmetric crypto.
func TestKMSVerifierRefusesASignatureFromADifferentKey(t *testing.T) {
	fake := awsfake.NewKMS()
	signerA := testKMSSigner(t, fake, "arn:aws:kms:us-east-1:111122223333:key/key-a")
	message := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd")
	sig, err := signerA.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Splice in a different key id, the way a tampered record might: the
	// signature bytes are unchanged, only the claimed key is different.
	tampered := &Signature{Algorithm: sig.Algorithm, KeyID: "arn:aws:kms:us-east-1:111122223333:key/key-b", Value: sig.Value}
	verifier := &KMSVerifier{API: fake}
	if err := verifier.Verify(message, tampered); err == nil {
		t.Fatal("KMSVerifier accepted a signature under a key id it was not actually made with")
	}
}

// TestKMSVerifierRefusesAMismatchedKeyIDRatherThanFailingSilently mirrors
// TestAKeyIDMismatchIsRefusedNotFailed's reasoning for LocalVerifier: a
// verifier holding one key must refuse a record signed by a different one
// it was simply not given, rather than reporting "signature invalid" for a
// perfectly sound chain.
func TestKMSVerifierRefusesAMismatchedKeyIDRatherThanFailingSilently(t *testing.T) {
	fake := awsfake.NewKMS()
	signer := testKMSSigner(t, fake, "arn:aws:kms:us-east-1:111122223333:key/the-actual-key")
	message := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifier := &KMSVerifier{API: fake, KeyID: "arn:aws:kms:us-east-1:111122223333:key/a-different-key"}
	err = verifier.Verify(message, sig)
	if err == nil {
		t.Fatal("KMSVerifier accepted a record signed by a key it was not given")
	}
	if !contains(err.Error(), "supply the key the record names") {
		t.Errorf("error does not explain the mismatch: %v", err)
	}
}

func TestNewKMSSignerRefusesAnEd25519Algorithm(t *testing.T) {
	fake := awsfake.NewKMS()
	if _, err := NewKMSSigner(fake, "arn:aws:kms:us-east-1:111122223333:key/x", AlgEd25519); err == nil {
		t.Fatal("NewKMSSigner accepted AlgEd25519, which is LocalSigner's algorithm, not a KMS one")
	}
}

func TestNewKMSSignerRefusesAnEmptyKeyID(t *testing.T) {
	fake := awsfake.NewKMS()
	if _, err := NewKMSSigner(fake, "", AlgKMSRSAPSS256); err == nil {
		t.Fatal("NewKMSSigner accepted an empty key id")
	}
}

func TestNewKMSSignerRefusesAKeyIDWithAControlCharacter(t *testing.T) {
	fake := awsfake.NewKMS()
	if _, err := NewKMSSigner(fake, "arn:aws:kms:us-east-1:111122223333:key/x\n", AlgKMSRSAPSS256); err == nil {
		t.Fatal("NewKMSSigner accepted a key id containing a newline")
	}
}

func TestKMSSignerReportsADeniedSignCallWithRemediation(t *testing.T) {
	fake := awsfake.NewKMS()
	fake.SignErr = &awsfake.APIError{Code: "AccessDeniedException", Message: "denied"}
	signer := testKMSSigner(t, fake, "arn:aws:kms:us-east-1:111122223333:key/x")
	_, err := signer.Sign([]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"))
	if err == nil {
		t.Fatal("Sign succeeded despite the fake reporting AccessDenied")
	}
	if !contains(err.Error(), "kms:Sign") {
		t.Errorf("error does not name the denied action: %v", err)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
