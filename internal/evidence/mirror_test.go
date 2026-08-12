// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/awsfake"
)

// TestS3MirrorUploadWritesTheSameBytesTheLocalFileHas is Upload's core
// promise: the object PutObject writes is byte-for-byte what
// Manifest.MarshalIndented — the same method Dir.Write uses for the local
// copy — produces, so the two are comparable without a JSON parser.
func TestS3MirrorUploadWritesTheSameBytesTheLocalFileHas(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}

	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)

	if uerr := mirror.Upload(context.Background(), acct, m); uerr != nil {
		t.Fatalf("Upload: %v", uerr)
	}

	want, err := m.MarshalIndented()
	if err != nil {
		t.Fatalf("MarshalIndented: %v", err)
	}
	got, ok := fake.Object("automat-evidence-mirror", acct+".json")
	if !ok {
		t.Fatalf("fake holds no object at %s.json", acct)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("uploaded bytes differ from MarshalIndented's own output:\ngot:  %s\nwant: %s", got, want)
	}
	if fake.CallCount("PutObject") != 1 {
		t.Errorf("PutObject called %d times, want 1", fake.CallCount("PutObject"))
	}
	if fake.CallCount("GetObject") != 0 {
		t.Errorf("Upload (write-only) called GetObject %d times, want 0", fake.CallCount("GetObject"))
	}
}

// TestS3MirrorUploadWithPrefix confirms the key is <prefix>/<key>.json when a
// prefix is configured, and a bare <key>.json when it is not — Dir.Path's
// own local-file naming, mirrored.
func TestS3MirrorUploadWithPrefix(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "manifests")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)

	if err := mirror.Upload(context.Background(), acct, m); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if _, ok := fake.Object("automat-evidence-mirror", "manifests/"+acct+".json"); !ok {
		t.Errorf("expected an object at manifests/%s.json", acct)
	}
}

// TestS3MirrorUploadUsesTheGivenKeyNotTheAccountID is the rotation-safety
// property this task's own audit found missing in slice 1: a caller
// uploading a rotated successor manifest (Q23, docs/open-questions.md) must
// land at the successor's OWN object key ("<account_id>-2"), never at the
// account-id-only key the pre-rotation manifest was mirrored under — the two
// manifests share the same Meta.AccountID but are different files with
// different content, and a shared key would make the second Upload silently
// overwrite the first's mirrored copy.
func TestS3MirrorUploadUsesTheGivenKeyNotTheAccountID(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	successorKey := acct + "-2"
	m := NewManifest(successorKey, acct, "o-abc1234567", ts0)
	mustAppend(t, m, vendRec(OpVerify, ts0), nil)

	if err := mirror.Upload(context.Background(), successorKey, m); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if _, ok := fake.Object("automat-evidence-mirror", successorKey+".json"); !ok {
		t.Errorf("expected an object at %s.json, the successor's own key", successorKey)
	}
	if _, ok := fake.Object("automat-evidence-mirror", acct+".json"); ok {
		t.Errorf("an object landed at %s.json — the pre-rotation account-id-only key — "+
			"when the caller asked for %s", acct, successorKey)
	}
}

// TestS3MirrorUploadDeniedWrapsAsPermissionError is the s3:PutObject denial
// path: a caller with the wrong grant must be told which action, which
// resource, and (at minimum) that a grant is what is missing — CLAUDE.md
// rule 7, the same shape KMSSigner.Sign's own denial path holds.
func TestS3MirrorUploadDeniedWrapsAsPermissionError(t *testing.T) {
	fake := awsfake.NewS3()
	fake.PutObjectErr = awsfake.AccessDenied("s3:PutObject")
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)

	uerr := mirror.Upload(context.Background(), acct, m)
	if uerr == nil {
		t.Fatal("Upload with a denied PutObject returned no error")
	}
	pe, ok := awsapi.AsPermissionError(uerr)
	if !ok {
		t.Fatalf("Upload's error does not unwrap to a *awsapi.PermissionError: %v", uerr)
	}
	if pe.Action != "s3:PutObject" {
		t.Errorf("PermissionError.Action = %q, want s3:PutObject", pe.Action)
	}
	if pe.Grant == "" {
		t.Error("PermissionError.Grant is empty; CLAUDE.md rule 7 requires remediation text")
	}
}

// TestS3MirrorUploadRefusesAManifestWithNoAccountID: an unnamed key is not a
// key this package will construct — see Upload's own guard.
func TestS3MirrorUploadRefusesAManifestWithNoAccountID(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	m := &Manifest{SchemaVersion: SchemaVersion}
	if err := mirror.Upload(context.Background(), acct, m); err == nil {
		t.Error("Upload with no account_id succeeded; want a refusal")
	}
	if fake.CallCount("PutObject") != 0 {
		t.Error("Upload with no account_id still called PutObject")
	}
}

// TestS3MirrorUploadRefusesAnEmptyKey.
func TestS3MirrorUploadRefusesAnEmptyKey(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	if err := mirror.Upload(context.Background(), "", m); err == nil {
		t.Error("Upload with an empty key succeeded; want a refusal")
	}
}

// TestNewS3MirrorRefusesAMissingClientOrBucket.
func TestNewS3MirrorRefusesAMissingClientOrBucket(t *testing.T) {
	fake := awsfake.NewS3()
	if _, err := NewS3Mirror(nil, "bucket", ""); err == nil {
		t.Error("NewS3Mirror with a nil client succeeded")
	}
	if _, err := NewS3Mirror(fake, "", ""); err == nil {
		t.Error("NewS3Mirror with an empty bucket succeeded")
	}
}

// TestS3MirrorImplementsMirror is a compile-time-shaped sanity check kept as
// a test so a future refactor that breaks it fails loudly.
func TestS3MirrorImplementsMirror(t *testing.T) {
	var (
		_ Mirror       = (*S3Mirror)(nil)
		_ MirrorReader = (*S3Mirror)(nil)
	)
}

// TestS3MirrorFetchReadsBackWhatWasUploaded is Fetch's core round trip: a
// manifest uploaded through Upload comes back from Fetch equal to the
// original, decoded and chain-verified.
func TestS3MirrorFetchReadsBackWhatWasUploaded(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	if err := mirror.Upload(context.Background(), acct, m); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	got, ferr := mirror.Fetch(context.Background(), acct)
	if ferr != nil {
		t.Fatalf("Fetch: %v", ferr)
	}
	if got.Meta.GenesisSHA != m.Meta.GenesisSHA {
		t.Errorf("fetched Meta.GenesisSHA = %q, want %q", got.Meta.GenesisSHA, m.Meta.GenesisSHA)
	}
	if len(got.Records) != len(m.Records) {
		t.Errorf("fetched %d records, want %d", len(got.Records), len(m.Records))
	}
}

// TestS3MirrorFetchUsesTheGivenKey mirrors TestS3MirrorUploadUsesTheGivenKeyNotTheAccountID
// on the read side: a caller fetching a rotated successor's mirrored copy
// must read the successor's own key.
func TestS3MirrorFetchUsesTheGivenKey(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	successorKey := acct + "-2"
	m := NewManifest(successorKey, acct, "o-abc1234567", ts0)
	mustAppend(t, m, vendRec(OpVerify, ts0), nil)
	if uerr := mirror.Upload(context.Background(), successorKey, m); uerr != nil {
		t.Fatalf("Upload: %v", uerr)
	}

	if _, ferr := mirror.Fetch(context.Background(), acct); ferr == nil {
		t.Error("Fetch(acct) succeeded against a mirror holding only the successor's key; want a NoSuchKey-shaped failure")
	}
	got, err := mirror.Fetch(context.Background(), successorKey)
	if err != nil {
		t.Fatalf("Fetch(successorKey): %v", err)
	}
	if got.Meta.ID != successorKey {
		t.Errorf("fetched Meta.ID = %q, want %q", got.Meta.ID, successorKey)
	}
}

// TestS3MirrorFetchDeniedWrapsAsPermissionError is the s3:GetObject denial
// path, the read-side twin of TestS3MirrorUploadDeniedWrapsAsPermissionError.
func TestS3MirrorFetchDeniedWrapsAsPermissionError(t *testing.T) {
	fake := awsfake.NewS3()
	fake.GetObjectErr = awsfake.AccessDenied("s3:GetObject")
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}

	_, ferr := mirror.Fetch(context.Background(), acct)
	if ferr == nil {
		t.Fatal("Fetch with a denied GetObject returned no error")
	}
	pe, ok := awsapi.AsPermissionError(ferr)
	if !ok {
		t.Fatalf("Fetch's error does not unwrap to a *awsapi.PermissionError: %v", ferr)
	}
	if pe.Action != "s3:GetObject" {
		t.Errorf("PermissionError.Action = %q, want s3:GetObject", pe.Action)
	}
	if pe.Grant == "" {
		t.Error("PermissionError.Grant is empty; CLAUDE.md rule 7 requires remediation text")
	}
}

// TestS3MirrorFetchNoSuchKeyIsAnOrdinaryError: an account that has never had
// anything uploaded must fail Fetch plainly rather than panicking or
// returning a zero-value manifest a caller might mistake for "clean".
func TestS3MirrorFetchNoSuchKeyIsAnOrdinaryError(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	m, ferr := mirror.Fetch(context.Background(), acct)
	if ferr == nil {
		t.Fatal("Fetch against an empty mirror succeeded; want an error")
	}
	if m != nil {
		t.Error("Fetch returned a non-nil manifest alongside an error")
	}
}

// TestS3MirrorFetchRefusesAnEmptyKey.
func TestS3MirrorFetchRefusesAnEmptyKey(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	if _, err := mirror.Fetch(context.Background(), ""); err == nil {
		t.Error("Fetch with an empty key succeeded; want a refusal")
	}
}

// TestS3MirrorFetchRejectsAnUndecodableObject: a mirror is only as trustworthy
// as its own content, and a mirrored blob that is not a valid evidence
// manifest (corrupted upload, unrelated object landed under this key) must be
// reported as a fetch failure, never silently treated as "no drift".
func TestS3MirrorFetchRejectsAnUndecodableObject(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	// Seed the fake with something that is not a manifest, via a manifest
	// Upload followed by direct corruption of the stored bytes would need
	// fake internals; instead, upload a well-formed manifest and confirm the
	// happy path, then use a manifest whose chain is broken to prove Decode's
	// verification runs on the fetch path too.
	broken := newTestManifest()
	mustAppend(t, broken, vendRec(OpAccountCreate, ts0), nil)
	broken.Records[0].RecordSHA = otherHash // corrupt the stored hash
	data, merr := broken.MarshalIndented()
	if merr != nil {
		t.Fatalf("MarshalIndented: %v", merr)
	}
	if _, err := fake.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("automat-evidence-mirror"),
		Key:    aws.String(acct + ".json"),
		Body:   bytes.NewReader(data),
	}); err != nil {
		t.Fatalf("seed PutObject: %v", err)
	}

	if _, err := mirror.Fetch(context.Background(), acct); err == nil {
		t.Error("Fetch against a corrupted manifest succeeded; want a decode/verify failure")
	}
}
