// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
// `verify`, MirrorReader below) needs a SEPARATE interface method for the
// same reason Signer/Verifier are two interfaces rather than one (Signer's
// own doc comment) — a writer never needs read access, and bundling the two
// would make a write-only caller ask for a grant it does not need.
//
// # key, not just the manifest's own account id (closed alongside slice 2)
//
// key is the same filename stem Dir.WriteNamed/Dir.Path use — ordinarily the
// account id, but "<account_id>-2", "-3", and so on once rotation (Q23,
// docs/open-questions.md) has closed the account's original manifest and
// moved its active chain to a successor file. Slice 1 shipped taking no key
// at all and deriving the S3 object name purely from m.Meta.AccountID
// (S3Mirror.key's old signature), which is correct only for an account that
// has never rotated: m.Meta.AccountID does not change across a rotation, so
// every mirror upload for a rotated account — the successor's, and any
// later one — would land at the SAME object key the pre-rotation manifest
// was mirrored under, silently overwriting the mirrored copy of the closed
// original with the successor's unrelated content. That is exactly the kind
// of disagreement slice 2 exists to detect, self-inflicted by the write
// side never reaching the successor's own key. Threading key through, the
// same way LoadOrNewNamed/WriteNamed generalized the local write path for
// this same reason, is this slice's fix.
type Mirror interface {
	Upload(ctx context.Context, key string, m *Manifest) error
}

// MirrorReader fetches a mirrored manifest back, for slice 2's read-and-diff
// (ROADMAP.md's "Remote evidence mirror", item 2; docs/open-questions.md
// Q21) — the compensating control Q21's own residual names actually being
// read, not just written.
//
// A SEPARATE interface from Mirror, not an added method on it, for the exact
// reason Signer and Verifier are two interfaces rather than one
// (evidence/signer.go's own doc comment): "a verifying operator has a
// public key and no authority to sign, and an interface bundling both would
// make verify ask for a signing grant it must not have." The same sentence
// applies here word for word with s/sign/write/ and s/verify/upload/ — every
// command that only ever calls Mirror.Upload (vend, reclaim, assess) must
// never be handed a grant to read the mirror back, and a caller holding only
// Mirror cannot accidentally reach for one.
type MirrorReader interface {
	// Fetch returns the mirrored manifest stored at key (the same filename
	// stem Dir.Path/WriteNamed use — ordinarily the account id, "<account_id>-N"
	// once rotated), or an error if it cannot be read — including "no object
	// exists there yet", which is not specially distinguished at this layer
	// (the caller, cmd/automat/verify.go, is where "never uploaded" and
	// "denied" and "network error" get told apart, because only the caller
	// knows which distinction its report needs to draw).
	Fetch(ctx context.Context, key string) (*Manifest, error)
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
	// API is the client this mirror uploads through and reads back from.
	API awsapi.S3MirrorAPI
	// Bucket is the destination bucket — either envprofile.OutputTargets'
	// InAccountBucket or ManagementMirrorBucket, already validated against
	// reBucket by envprofile's own Validate before this type ever sees it.
	Bucket string
	// Prefix is an optional key prefix, joined with "/" ahead of
	// "<key>.json". Empty means no prefix, matching Dir.Path's own
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

// key is the S3 object key for the given filename stem, mirroring Dir.Path's
// own "<key>.json" naming so the same local file resolves to the same
// basename in both places — including post-rotation, where the stem is
// "<account_id>-2" rather than "<account_id>" (see the Mirror doc comment's
// "key, not just the manifest's own account id" section).
func (s *S3Mirror) key(stem string) string {
	if s.Prefix == "" {
		return stem + ".json"
	}
	return strings.TrimSuffix(s.Prefix, "/") + "/" + stem + ".json"
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
func (s *S3Mirror) Upload(ctx context.Context, key string, m *Manifest) error {
	if m == nil {
		return fmt.Errorf("no manifest to upload")
	}
	if key == "" {
		return fmt.Errorf("no key to upload the manifest under")
	}
	if m.Meta.AccountID == "" {
		return fmt.Errorf("manifest has no account_id; refusing to upload it under an unnamed key")
	}
	data, err := m.MarshalIndented()
	if err != nil {
		return err
	}
	objKey := s.key(key)
	_, err = s.API.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objKey),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return awsapi.Denied(err, "s3:PutObject", "arn:aws:s3:::"+s.Bucket+"/"+objKey, "",
			"grant s3:PutObject on "+s.Bucket+" to the identity running this command; the mirror "+
				"is additive, so this failure is reported as a warning rather than failing the "+
				"command that produced the manifest")
	}
	return nil
}

// Fetch implements MirrorReader.
//
// The bytes read back are decoded through Decode with a nil verifier — the
// same reason VerifyChain's own verifier parameter is optional (chain.go): a
// mirrored copy may be unsigned even when the local one is not, or signed with
// a key this caller does not hold, and a signature check has nothing to add
// here anyway. What Fetch's caller (MirrorDrift, mirrordrift.go) compares is
// Meta and the leading records' own bytes-level content, not their
// signatures — Decode's chain-verification step (every record's hash matches
// its own content) still runs, so a mirrored copy that is itself internally
// inconsistent is reported as a fetch failure rather than silently compared
// as if it were sound.
//
// Bounded by MaxManifestBytes, the same bound Dir's own reads use: an S3
// object under attacker or operator control should not be read without limit
// just because it arrived over the network rather than off local disk.
func (s *S3Mirror) Fetch(ctx context.Context, key string) (*Manifest, error) {
	if key == "" {
		return nil, fmt.Errorf("cannot fetch a mirrored manifest: no key was given")
	}
	objKey := s.key(key)
	out, err := s.API.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objKey),
	})
	if err != nil {
		return nil, awsapi.Denied(err, "s3:GetObject", "arn:aws:s3:::"+s.Bucket+"/"+objKey, "",
			"grant s3:GetObject on "+s.Bucket+" to the identity running this command; if the object "+
				"simply does not exist yet, this account has never had a manifest uploaded to this "+
				"mirror and there is nothing to compare against")
	}
	defer func() { _ = out.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(out.Body, MaxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the mirrored manifest at %s/%s: %w", s.Bucket, objKey, err)
	}
	if int64(len(data)) > MaxManifestBytes {
		return nil, fmt.Errorf("the mirrored manifest at %s/%s is larger than %d bytes, so it is not "+
			"the manifest automat expected — a chain of real operations does not reach that size",
			s.Bucket, objKey, MaxManifestBytes)
	}
	m, err := Decode(data, nil)
	if err != nil {
		return nil, fmt.Errorf("the mirrored manifest at %s/%s does not decode as a valid evidence "+
			"manifest: %w", s.Bucket, objKey, err)
	}
	return m, nil
}

var (
	_ Mirror       = (*S3Mirror)(nil)
	_ MirrorReader = (*S3Mirror)(nil)
)
