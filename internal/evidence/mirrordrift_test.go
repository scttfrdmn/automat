// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"context"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsfake"
)

// mirrorFor builds an S3Mirror over a fresh fake bucket, for tests that need
// a real MirrorReader rather than compareManifests directly.
func mirrorFor(t *testing.T, bucket string) (*S3Mirror, *awsfake.S3) {
	t.Helper()
	fake := awsfake.NewS3()
	mirror, err := NewS3Mirror(fake, bucket, "")
	if err != nil {
		t.Fatalf("NewS3Mirror: %v", err)
	}
	return mirror, fake
}

// TestMirrorDriftAgreement is the clean case: a manifest fetched back
// unmodified from its own mirror reports Checked true, Drifted false.
func TestMirrorDriftAgreement(t *testing.T) {
	mirror, _ := mirrorFor(t, "automat-evidence-mirror")
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, m, vendRec(OpVerify, ts1), nil)
	if err := mirror.Upload(context.Background(), acct, m); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	report := MirrorDrift(context.Background(), mirror, "automat-evidence-mirror", acct, m)
	if !report.Checked {
		t.Fatalf("report.Checked = false, want true: %+v", report)
	}
	if report.Drifted {
		t.Errorf("report.Drifted = true against an untouched mirror: %+v", report)
	}
	if report.DriftKind != "" {
		t.Errorf("report.DriftKind = %q, want empty", report.DriftKind)
	}
}

// TestMirrorDriftDisagreement is Q21's headline case: the mirrored copy's
// header disagrees with the local one — the genesis anchor was rewritten to
// match a truncated chain, exactly the residual DESIGN §11's external anchor
// exists to catch.
func TestMirrorDriftDisagreement(t *testing.T) {
	local := newTestManifest()
	mustAppend(t, local, vendRec(OpAccountCreate, ts0), nil)

	mirrored := newTestManifest()
	mustAppend(t, mirrored, vendRec(OpAccountCreate, ts0), nil)
	mirrored.Meta.GenesisSHA = otherHash // simulate a rewritten header

	report := compareManifests("automat-evidence-mirror", local, mirrored)
	if !report.Checked {
		t.Fatal("report.Checked = false, want true")
	}
	if !report.Drifted {
		t.Fatal("report.Drifted = false against a rewritten genesis anchor, want true")
	}
	if report.DriftKind != DriftKindDisagreement {
		t.Errorf("report.DriftKind = %q, want %q", report.DriftKind, DriftKindDisagreement)
	}
	if !strings.Contains(report.Detail, "genesis_sha256") {
		t.Errorf("report.Detail does not name the field that disagreed: %q", report.Detail)
	}
}

// TestMirrorDriftRecordDisagreement is a disagreement inside the records
// themselves, not the header — the same failure mode, a different location,
// and the report must still name it a disagreement rather than a truncation.
func TestMirrorDriftRecordDisagreement(t *testing.T) {
	local := newTestManifest()
	mustAppend(t, local, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, local, vendRec(OpVerify, ts1), nil)

	mirrored := newTestManifest()
	mustAppend(t, mirrored, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, mirrored, vendRec(OpVerify, ts1), nil)
	mirrored.Records[1].RequestID = "req-edited99"

	report := compareManifests("automat-evidence-mirror", local, mirrored)
	if !report.Drifted || report.DriftKind != DriftKindDisagreement {
		t.Fatalf("report = %+v, want a disagreement", report)
	}
	if !strings.Contains(report.Detail, "records[1]") {
		t.Errorf("report.Detail does not name the differing record: %q", report.Detail)
	}
}

// TestMirrorDriftTruncationShape is the OTHER failure shape, kept distinct
// from disagreement per the task's own instruction: the mirror (or the
// local file) is a strict prefix of the other, with every record the two
// share agreeing exactly — the shape a tail truncation leaves, as opposed
// to an edited record.
func TestMirrorDriftTruncationShape(t *testing.T) {
	longer := newTestManifest()
	mustAppend(t, longer, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, longer, vendRec(OpVerify, ts1), nil)
	mustAppend(t, longer, vendRec(OpVerify, ts2), nil)

	shorter := newTestManifest()
	mustAppend(t, shorter, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, shorter, vendRec(OpVerify, ts1), nil)

	// local is the longer chain, mirror is the truncated one.
	report := compareManifests("automat-evidence-mirror", longer, shorter)
	if !report.Drifted {
		t.Fatal("report.Drifted = false against a truncated mirror, want true")
	}
	if report.DriftKind != DriftKindTruncation {
		t.Errorf("report.DriftKind = %q, want %q (a shared prefix with a missing tail is not a "+
			"content disagreement)", report.DriftKind, DriftKindTruncation)
	}
	if !strings.Contains(report.Detail, "prefix") {
		t.Errorf("report.Detail does not describe the truncation shape: %q", report.Detail)
	}

	// And the mirror direction: local is the short one, mirror is longer —
	// still a truncation, from the opposite side.
	reversed := compareManifests("automat-evidence-mirror", shorter, longer)
	if reversed.DriftKind != DriftKindTruncation {
		t.Errorf("reversed report.DriftKind = %q, want %q", reversed.DriftKind, DriftKindTruncation)
	}
}

// TestMirrorDriftBothEmpty: two manifests with identical headers and zero
// records agree — the edge case named explicitly in the task. In practice a
// zero-record manifest never reaches this comparison (Validate refuses one,
// so neither Fetch nor a real local load can produce it), but the comparison
// function itself must not divide by zero or panic on the boundary.
func TestMirrorDriftBothEmpty(t *testing.T) {
	local := newTestManifest()
	mirrored := newTestManifest()

	report := compareManifests("automat-evidence-mirror", local, mirrored)
	if !report.Checked {
		t.Fatal("report.Checked = false, want true")
	}
	if report.Drifted {
		t.Errorf("report.Drifted = true for two identical empty-record manifests: %+v", report)
	}
}

// TestMirrorDriftUnreachableOnFetchFailure is the third state: a configured
// mirror that cannot be read must not be reported as clean or as drifted.
func TestMirrorDriftUnreachableOnFetchFailure(t *testing.T) {
	mirror, fake := mirrorFor(t, "automat-evidence-mirror")
	fake.GetObjectErr = awsfake.AccessDenied("s3:GetObject")

	local := newTestManifest()
	mustAppend(t, local, vendRec(OpAccountCreate, ts0), nil)

	report := MirrorDrift(context.Background(), mirror, "automat-evidence-mirror", acct, local)
	if report.Checked {
		t.Error("report.Checked = true against a denied Fetch, want false")
	}
	if report.Drifted {
		t.Error("report.Drifted = true against a denied Fetch; an unreachable mirror is not a drift finding")
	}
	if report.DriftKind != DriftKindUnreachable {
		t.Errorf("report.DriftKind = %q, want %q", report.DriftKind, DriftKindUnreachable)
	}
	if report.Detail == "" {
		t.Error("report.Detail is empty; an unreachable mirror must still say why")
	}
}

// TestMirrorDriftUnreachableWhenNeverUploaded: the ordinary "this account has
// never had anything uploaded" case must read the same as any other fetch
// failure — unreachable, not a drift finding and not a clean pass.
func TestMirrorDriftUnreachableWhenNeverUploaded(t *testing.T) {
	mirror, _ := mirrorFor(t, "automat-evidence-mirror")
	local := newTestManifest()
	mustAppend(t, local, vendRec(OpAccountCreate, ts0), nil)

	report := MirrorDrift(context.Background(), mirror, "automat-evidence-mirror", acct, local)
	if report.Checked {
		t.Error("report.Checked = true against a mirror nothing was ever uploaded to, want false")
	}
	if report.DriftKind != DriftKindUnreachable {
		t.Errorf("report.DriftKind = %q, want %q", report.DriftKind, DriftKindUnreachable)
	}
}

// TestMirrorDriftNilLocalIsUnreachable: MirrorDrift must not panic on a nil
// local manifest, and must not report it as clean.
func TestMirrorDriftNilLocalIsUnreachable(t *testing.T) {
	mirror, _ := mirrorFor(t, "automat-evidence-mirror")
	report := MirrorDrift(context.Background(), mirror, "automat-evidence-mirror", acct, nil)
	if report.Checked {
		t.Error("report.Checked = true with a nil local manifest, want false")
	}
	if report.DriftKind != DriftKindUnreachable {
		t.Errorf("report.DriftKind = %q, want %q", report.DriftKind, DriftKindUnreachable)
	}
}
