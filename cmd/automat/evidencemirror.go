// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/evidence"
)

// evidenceMirror builds zero, one, or two evidence.Mirror instances from an
// environment profile's baseline.evidence output targets — the write-only
// half of ROADMAP.md's "Remote evidence mirror" backlog item (DESIGN §11's
// "in-account S3 (created at vend) and/or the vending account").
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
// configured both wants both uploaded to.
func evidenceMirror(ctx context.Context, g *globals, region, profile string,
	targets *envprofile.OutputTargets) ([]evidence.Mirror, error) {
	if targets == nil || (targets.InAccountBucket == "" && targets.ManagementMirrorBucket == "") {
		return nil, nil
	}
	api, err := g.s3MirrorClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	var mirrors []evidence.Mirror
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

// uploadToMirrors uploads m to every configured mirror, returning a warning
// string per failed upload rather than an error.
//
// A mirror upload failure must never fail the command that produced the
// manifest and must never block on the local write, which always happens
// first (Dir.Write, unconditionally, before this is ever called) — DESIGN
// §11's "local copy always" priority. This is why the return type is a
// slice of warning strings rather than an error: the caller's job is to
// surface these through whatever warnings channel it already has (vend's
// renderVendWarnings) or a plain stderr line (verify, reclaim, assess),
// never to fail on them.
func uploadToMirrors(ctx context.Context, mirrors []evidence.Mirror, m *evidence.Manifest) []string {
	var warnings []string
	for _, mirror := range mirrors {
		if err := mirror.Upload(ctx, m); err != nil {
			warnings = append(warnings, fmt.Sprintf("evidence mirror upload failed: %v", err))
		}
	}
	return warnings
}
