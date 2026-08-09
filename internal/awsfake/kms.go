// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// KMS fakes awsapi.KMSAPI.
//
// Not real asymmetric cryptography — an HMAC over each key id's own secret
// stands in for it, which is enough to test that Sign and Verify agree with
// each other and that a signature made under one key id does not verify
// under another. What this fake exists to exercise is the wiring
// (evidence.KMSSigner/KMSVerifier calling the right KMS operations with the
// right inputs), not KMS's own cryptographic guarantees.
type KMS struct {
	Recorder

	// SignErr and VerifyErr, when set, fail the respective call — the
	// kms:Sign/kms:Verify denial path evidence.KMSSigner/KMSVerifier report
	// remediation text for.
	SignErr, VerifyErr error

	// ResolvedKeyID overrides what Sign reports as the key it used — the
	// case docs/reclaim-design.md-style reasoning calls out on
	// evidence.KMSSigner's own doc comment: a caller may configure an
	// alias, and KMS reports the actual key ARN back. Empty means echo the
	// caller's own KeyId, the ordinary case where the caller already named
	// a real key rather than an alias.
	ResolvedKeyID string

	secrets map[string][]byte
}

// NewKMS returns a KMS fake with no keys seeded.
func NewKMS() *KMS { return &KMS{secrets: map[string][]byte{}} }

// SeedKey ensures a deterministic per-key-id secret exists, so a test can
// seed a key before ever calling Sign against it (e.g. to construct a
// signature under a DIFFERENT caller's key and confirm Verify refuses it).
func (f *KMS) SeedKey(keyID string) {
	if _, ok := f.secrets[keyID]; !ok {
		f.secrets[keyID] = keySecret(keyID)
	}
}

func keySecret(keyID string) []byte {
	sum := sha256.Sum256([]byte("awsfake-kms-secret:" + keyID))
	return sum[:]
}

// Sign implements awsapi.KMSAPI.
func (f *KMS) Sign(_ context.Context, in *kms.SignInput,
	_ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.Record("Sign")
	if f.SignErr != nil {
		return nil, f.SignErr
	}
	keyID := aws.ToString(in.KeyId)
	f.SeedKey(keyID)
	mac := hmac.New(sha256.New, f.secrets[keyID])
	mac.Write(in.Message)

	reportedKeyID := f.ResolvedKeyID
	if reportedKeyID == "" {
		reportedKeyID = keyID
	}
	return &kms.SignOutput{
		KeyId:            aws.String(reportedKeyID),
		Signature:        mac.Sum(nil),
		SigningAlgorithm: in.SigningAlgorithm,
	}, nil
}

// Verify implements awsapi.KMSAPI.
func (f *KMS) Verify(_ context.Context, in *kms.VerifyInput,
	_ ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	f.Record("Verify")
	if f.VerifyErr != nil {
		return nil, f.VerifyErr
	}
	keyID := aws.ToString(in.KeyId)
	f.SeedKey(keyID)
	mac := hmac.New(sha256.New, f.secrets[keyID])
	mac.Write(in.Message)
	valid := hmac.Equal(mac.Sum(nil), in.Signature)
	if !valid {
		return nil, &kmstypes.KMSInvalidSignatureException{
			Message: aws.String("The signature could not be verified with the specified key or " +
				"signing algorithm."),
		}
	}
	return &kms.VerifyOutput{
		KeyId:            aws.String(keyID),
		SignatureValid:   valid,
		SigningAlgorithm: in.SigningAlgorithm,
	}, nil
}

var _ awsapi.KMSAPI = (*KMS)(nil)
