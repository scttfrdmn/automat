// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/evidence"
)

// buildS3Mirrors is the single place that resolves an environment profile's
// baseline.evidence output targets to zero, one, or two *evidence.S3Mirror
// instances — the bucket-resolution logic evidenceMirror (the write side) and
// evidenceMirrorReaders (slice 2's read side, verify.go) both build on, so
// there is exactly one reading of InAccountBucket/ManagementMirrorBucket in
// this binary rather than two that could drift apart.
//
// targets is in.Profile.Baseline.Evidence (vend) or in.profile.Baseline.Evidence
// (verify) — envprofile.OutputTargets.InAccountBucket and
// ManagementMirrorBucket are both optional and already validated against
// reBucket by envprofile's own Validate, so the only new failure mode here is
// the S3 client itself. nil targets, or a targets with neither field set, is
// the common case today and returns zero mirrors, exactly the way
// evidenceSigner returns nil, nil when no KMS key is configured.
//
// Both fields are honored independently rather than one taking priority: the
// "and/or" in DESIGN §11's own text is deliberate, and an operator who
// configured both wants both uploaded to (and, on the read side, both
// checked for drift).
func buildS3Mirrors(ctx context.Context, g *globals, region, profile string,
	targets *envprofile.OutputTargets) ([]*evidence.S3Mirror, error) {
	if targets == nil || (targets.InAccountBucket == "" && targets.ManagementMirrorBucket == "") {
		return nil, nil
	}
	api, err := g.s3MirrorClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	var mirrors []*evidence.S3Mirror
	if targets.InAccountBucket != "" {
		m, merr := evidence.NewS3Mirror(api, targets.InAccountBucket, "")
		if merr != nil {
			return nil, fmt.Errorf("baseline.evidence.in_account_bucket in the environment profile: %w", merr)
		}
		mirrors = append(mirrors, m)
	}
	if targets.ManagementMirrorBucket != "" {
		m, merr := evidence.NewS3Mirror(api, targets.ManagementMirrorBucket, "")
		if merr != nil {
			return nil, fmt.Errorf("baseline.evidence.management_mirror_bucket in the environment profile: %w", merr)
		}
		mirrors = append(mirrors, m)
	}
	return mirrors, nil
}

// evidenceMirror builds zero, one, or two evidence.Mirror instances — the
// write-only half of ROADMAP.md's "Remote evidence mirror" backlog item
// (DESIGN §11's "in-account S3 (created at vend) and/or the vending
// account"). See buildS3Mirrors for the actual bucket resolution.
func evidenceMirror(ctx context.Context, g *globals, region, profile string,
	targets *envprofile.OutputTargets) ([]evidence.Mirror, error) {
	built, err := buildS3Mirrors(ctx, g, region, profile, targets)
	if err != nil {
		return nil, err
	}
	mirrors := make([]evidence.Mirror, len(built))
	for i, m := range built {
		mirrors[i] = m
	}
	return mirrors, nil
}

// mirrorReader pairs a MirrorReader with the bucket name it reads from, so a
// caller reporting drift (cmd/automat/verify.go) can name which mirror it
// checked.
type mirrorReader struct {
	bucket string
	reader evidence.MirrorReader
}

// evidenceMirrorReaders is evidenceMirror's read-side twin: slice 2's
// "read-and-diff in verify" (ROADMAP.md's "Remote evidence mirror", item 2;
// docs/open-questions.md Q21). Built over the SAME bucket resolution
// evidenceMirror uses (buildS3Mirrors) so the two sides can never disagree
// about which buckets a profile names — the same S3MirrorAPI client and the
// same *evidence.S3Mirror values are simply exposed through their other
// interface, MirrorReader, which they already implement (evidence/mirror.go's
// own doc comment: "one struct, two interfaces").
func evidenceMirrorReaders(ctx context.Context, g *globals, region, profile string,
	targets *envprofile.OutputTargets) ([]mirrorReader, error) {
	built, err := buildS3Mirrors(ctx, g, region, profile, targets)
	if err != nil {
		return nil, err
	}
	readers := make([]mirrorReader, len(built))
	for i, m := range built {
		readers[i] = mirrorReader{bucket: m.Bucket, reader: m}
	}
	return readers, nil
}

// uploadToMirrors uploads m, under key, to every configured mirror, returning
// a warning string per failed upload rather than an error.
//
// key is the same filename stem the local write just used — ordinarily the
// account id, "<account_id>-N" once evidence.Manifest.Rotate (Q23,
// docs/open-questions.md) has closed the account's original manifest and
// moved its active chain to a successor file. Every call site derives it
// from the path writeVendEvidence/writeVerifyEvidence/writeReclaimEvidence/
// writeAssessEvidence already returned (evidenceManifestKey), rather than
// from m.Meta.AccountID: passing the account id unconditionally is exactly
// the bug this task's own audit found and fixed — a rotated successor's
// mirror upload landing at the SAME object key as the pre-rotation
// manifest's, silently overwriting the mirrored copy of the closed original.
//
// A mirror upload failure must never fail the command that produced the
// manifest and must never block on the local write, which always happens
// first (Dir.Write, unconditionally, before this is ever called) — DESIGN
// §11's "local copy always" priority. This is why the return type is a
// slice of warning strings rather than an error: the caller's job is to
// surface these through whatever warnings channel it already has (vend's
// renderVendWarnings) or a plain stderr line (verify, reclaim, assess),
// never to fail on them.
func uploadToMirrors(ctx context.Context, mirrors []evidence.Mirror, key string, m *evidence.Manifest) []string {
	var warnings []string
	for _, mirror := range mirrors {
		if err := mirror.Upload(ctx, key, m); err != nil {
			warnings = append(warnings, fmt.Sprintf("evidence mirror upload failed: %v", err))
		}
	}
	return warnings
}

// evidenceManifestKey recovers the filename stem (no ".json") that a
// manifest was just written under, from the path writeVendEvidence and its
// siblings return — the same stem Dir.Path/WriteNamed used, so a caller that
// needs to upload the manifest under the SAME key the local write just used
// does not have to re-derive it from m.Meta.AccountID, which is wrong after
// a rotation (see uploadToMirrors's own doc comment).
func evidenceManifestKey(manifestPath string) string {
	return strings.TrimSuffix(filepath.Base(manifestPath), ".json")
}
