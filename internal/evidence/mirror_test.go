// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"context"
	"testing"

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

	if uerr := mirror.Upload(context.Background(), m); uerr != nil {
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
		t.Errorf("Upload (slice 1, write-only) called GetObject %d times, want 0", fake.CallCount("GetObject"))
	}
}

// TestS3MirrorUploadWithPrefix confirms the key is <prefix>/<account_id>.json
// when a prefix is configured, and a bare <account_id>.json when it is not —
// Dir.Path's own local-file naming, mirrored.
func TestS3MirrorUploadWithPrefix(t *testing.T) {
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, "automat-evidence-mirror", "manifests")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)

	if err := mirror.Upload(context.Background(), m); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if _, ok := fake.Object("automat-evidence-mirror", "manifests/"+acct+".json"); !ok {
		t.Errorf("expected an object at manifests/%s.json", acct)
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

	uerr := mirror.Upload(context.Background(), m)
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
	if err := mirror.Upload(context.Background(), m); err == nil {
		t.Error("Upload with no account_id succeeded; want a refusal")
	}
	if fake.CallCount("PutObject") != 0 {
		t.Error("Upload with no account_id still called PutObject")
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
	var _ Mirror = (*S3Mirror)(nil)
}
