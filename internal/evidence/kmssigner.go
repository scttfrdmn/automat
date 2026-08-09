// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// KMSSigner signs with an asymmetric AWS KMS key — DESIGN §11's "KMS later"
// half of the local-key-now-KMS-later drop-in Signer's own doc comment
// describes. Nothing here reads or exports key material: Sign hands KMS the
// record's hex-encoded hash and gets bytes back, exactly the shape the
// Signer interface was chosen for.
//
// KeyID is required at construction — a KMS key ARN or alias, whichever the
// caller's kms:Sign grant is scoped to — because KMS's own Sign call needs
// one and there is no way to discover it (this package never lists keys).
// Algorithm selects which of the two pre-committed KMS algorithms to sign
// with; it must match the key's own KeyUsage/KeySpec or KMS refuses the
// call, and this package does not call DescribeKey to check in advance —
// the caller configuring a signer already knows what kind of key they made.
type KMSSigner struct {
	API       awsapi.KMSAPI
	KeyID     string
	Algorithm Algorithm
}

// NewKMSSigner validates its arguments and returns a signer.
//
// Algorithm must be one of the two KMS forms AllAlgorithms already commits
// to (AlgKMSRSAPSS256, AlgKMSECDSA256) — not AlgEd25519, which is
// LocalSigner's algorithm and not a KMS SigningAlgorithmSpec at all.
func NewKMSSigner(api awsapi.KMSAPI, keyID string, algorithm Algorithm) (*KMSSigner, error) {
	if api == nil {
		return nil, errors.New("a KMS signer needs a client")
	}
	if keyID == "" {
		return nil, errors.New("a KMS signer needs a key id: a signature nobody can locate a key " +
			"for is unverifiable in a way that looks verifiable, so key_id is not optional")
	}
	if !reRoundTripRef.MatchString(keyID) {
		return nil, fmt.Errorf("KMS key id %s is not a value this package will round-trip: it is "+
			"written into every record and printed back in reports (CLAUDE.md rule 8)", safe(keyID))
	}
	if _, err := kmsSigningAlgorithm(algorithm); err != nil {
		return nil, err
	}
	return &KMSSigner{API: api, KeyID: keyID, Algorithm: algorithm}, nil
}

// Sign implements Signer.
//
// KeyID on the returned Signature is the ARN KMS reports having used
// (out.KeyId), never the value the caller configured — the same reasoning
// Signer's own doc comment gives: a caller may have configured an alias,
// and the record should name what actually signed it rather than what the
// caller assumed, in case the two ever diverge (an alias repointed to a new
// key between signings, say).
func (s *KMSSigner) Sign(message []byte) (*Signature, error) {
	spec, err := kmsSigningAlgorithm(s.Algorithm)
	if err != nil {
		return nil, err
	}
	out, err := s.API.Sign(context.Background(), &kms.SignInput{
		KeyId:            aws.String(s.KeyID),
		Message:          message,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: spec,
	})
	if err != nil {
		return nil, awsapi.Denied(err, "kms:Sign", s.KeyID, "",
			"grant kms:Sign on "+s.KeyID+" to the identity running this command; the key policy, "+
				"not just an IAM policy, must also permit it — a KMS key's own policy is a second "+
				"gate an IAM Allow does not bypass")
	}
	return &Signature{
		Algorithm: string(s.Algorithm),
		KeyID:     aws.ToString(out.KeyId),
		Value:     base64.StdEncoding.EncodeToString(out.Signature),
	}, nil
}

// KMSVerifier checks a detached signature against an asymmetric AWS KMS key,
// using KMS's own Verify call rather than a locally held public key — this
// package has no code path that downloads or caches a KMS public key, so
// verification always makes a live call.
type KMSVerifier struct {
	API   awsapi.KMSAPI
	KeyID string
}

// Verify implements Verifier.
func (v *KMSVerifier) Verify(message []byte, sig *Signature) error {
	if sig == nil {
		return errors.New("no signature to verify")
	}
	algo := Algorithm(sig.Algorithm)
	spec, err := kmsSigningAlgorithm(algo)
	if err != nil {
		return fmt.Errorf("record is signed with %s, which this verifier does not recognize as a "+
			"KMS algorithm; supply the matching verifier rather than treating the mismatch as a bad "+
			"signature: %w", safe(sig.Algorithm), err)
	}
	if v.KeyID != "" && sig.KeyID != v.KeyID {
		// Refused rather than attempted, mirroring LocalVerifier.Verify's own
		// reasoning: checking against a key the record does not name would
		// report "signature invalid" for a manifest that is perfectly sound
		// and simply signed by a different key than the one supplied.
		return fmt.Errorf("record is signed by key %s and this verifier holds key %s; "+
			"supply the key the record names", safe(sig.KeyID), safe(v.KeyID))
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("signature value is not base64: %w", err)
	}
	out, err := v.API.Verify(context.Background(), &kms.VerifyInput{
		KeyId:            aws.String(sig.KeyID),
		Message:          message,
		MessageType:      types.MessageTypeRaw,
		Signature:        raw,
		SigningAlgorithm: spec,
	})
	if err != nil {
		return awsapi.Denied(err, "kms:Verify", sig.KeyID, "",
			"grant kms:Verify on "+sig.KeyID+" to the identity running verify, or use the KMS "+
				"GetPublicKey/console path if this key's policy does not permit Verify to this caller")
	}
	if !out.SignatureValid {
		return errors.New("the signature does not match this record's hash under the named key")
	}
	return nil
}

// kmsSigningAlgorithm maps automat's own algorithm identifiers to the KMS
// SigningAlgorithmSpec value they mean, refusing anything else — including
// AlgEd25519, which is LocalSigner's algorithm and not one KMS's Sign/Verify
// calls accept at all today (KMS does support ED25519_SHA_512 for some key
// types, but automat's schema names only the two forms below, and widening
// that mapping is a schema-vocabulary decision, not a code change here).
func kmsSigningAlgorithm(a Algorithm) (types.SigningAlgorithmSpec, error) {
	switch a {
	case AlgKMSRSAPSS256:
		return types.SigningAlgorithmSpecRsassaPssSha256, nil
	case AlgKMSECDSA256:
		return types.SigningAlgorithmSpecEcdsaSha256, nil
	default:
		return "", fmt.Errorf("%s is not a KMS signing algorithm this package supports; use %s or %s",
			safe(string(a)), AlgKMSRSAPSS256, AlgKMSECDSA256)
	}
}

var (
	_ Signer   = (*KMSSigner)(nil)
	_ Verifier = (*KMSVerifier)(nil)
)
