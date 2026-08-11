// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// Mirror uploads a manifest's current bytes to a second, remote location —
// DESIGN §11's "in-account S3 (created at vend) and/or the vending account"
// compensating control against a rewritten local manifest.
//
// One method, following Signer's own minimalism (evidence/signer.go): most
// manifests have zero Mirrors configured today (envprofile.OutputTargets'
// InAccountBucket and ManagementMirrorBucket are both optional and, absent a
// profile naming them, this is simply not built), and the interface a caller
// holds when there is nothing to do should not be larger than one no-op
// method.
//
// Write-only, deliberately — this is ROADMAP.md's "Remote evidence mirror"
// slice 1. There is no Fetch or Diff here: slice 2 (read-and-diff in
// `verify`) needs a SEPARATE interface method for the same reason
// Signer/Verifier are two interfaces rather than one (Signer's own doc
// comment) — a writer never needs read access, and bundling the two would
// make a write-only caller ask for a grant it does not need.
type Mirror interface {
	Upload(ctx context.Context, m *Manifest) error
}

// S3Mirror is Mirror's one implementation: an S3 object holding the same
// bytes Dir.Write puts on disk locally.
//
// The local write always happens first and unconditionally (Dir.Write); a
// Mirror is an ADDITIONAL step a caller runs afterward, never a substitute —
// see cmd/automat's evidenceMirror and its call sites for the "local always,
// mirror best-effort" sequencing this type does not itself enforce (Upload
// has no opinion about when it is called; the caller's discipline is what
// keeps the priority DESIGN §11 states).
type S3Mirror struct {
	// API is the client this mirror uploads through.
	API awsapi.S3MirrorAPI
	// Bucket is the destination bucket — either envprofile.OutputTargets'
	// InAccountBucket or ManagementMirrorBucket, already validated against
	// reBucket by envprofile's own Validate before this type ever sees it.
	Bucket string
	// Prefix is an optional key prefix, joined with "/" ahead of
	// "<account_id>.json". Empty means no prefix, matching Dir.Path's own
	// convention of a bare "<account_id>.json" name with nothing ahead of
	// it.
	Prefix string
}

// NewS3Mirror validates its arguments and returns a mirror.
func NewS3Mirror(api awsapi.S3MirrorAPI, bucket, prefix string) (*S3Mirror, error) {
	if api == nil {
		return nil, fmt.Errorf("a remote evidence mirror needs a client")
	}
	if bucket == "" {
		return nil, fmt.Errorf("a remote evidence mirror needs a bucket name")
	}
	return &S3Mirror{API: api, Bucket: bucket, Prefix: prefix}, nil
}

// key is the S3 object key for accountID's manifest, mirroring Dir.Path's own
// "<account_id>.json" naming so the same account resolves to the same
// basename in both places.
func (s *S3Mirror) key(accountID string) string {
	if s.Prefix == "" {
		return accountID + ".json"
	}
	return strings.TrimSuffix(s.Prefix, "/") + "/" + accountID + ".json"
}

// Upload implements Mirror.
//
// The bytes uploaded are exactly what Dir.Write already wrote locally —
// m.MarshalIndented's output, the on-disk form — so the two copies are
// byte-for-byte comparable without a JSON parser, the same property
// MarshalCanonical's own doc comment states as the reason it exists (that
// method is for the golden test and for a future read-and-diff comparator;
// this uses the indented form because that is what the local file this is a
// mirror OF actually contains).
func (s *S3Mirror) Upload(ctx context.Context, m *Manifest) error {
	if m == nil {
		return fmt.Errorf("no manifest to upload")
	}
	accountID := m.Meta.AccountID
	if accountID == "" {
		return fmt.Errorf("manifest has no account_id; refusing to upload it under an unnamed key")
	}
	data, err := m.MarshalIndented()
	if err != nil {
		return err
	}
	key := s.key(accountID)
	_, err = s.API.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return awsapi.Denied(err, "s3:PutObject", "arn:aws:s3:::"+s.Bucket+"/"+key, "",
			"grant s3:PutObject on "+s.Bucket+" to the identity running this command; the mirror "+
				"is additive, so this failure is reported as a warning rather than failing the "+
				"command that produced the manifest")
	}
	return nil
}

var _ Mirror = (*S3Mirror)(nil)
