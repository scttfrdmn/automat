// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// mirrorProfileJSON is vendProfileJSON with a management mirror bucket named,
// for the tests below — vend uploads the birth-certificate manifest to it,
// and verify's own read-and-diff (ROADMAP.md's "Remote evidence mirror"
// slice 2) reads it back.
func mirrorProfileJSON(t *testing.T, bucket string, mutate func(map[string]any)) string {
	t.Helper()
	return vendProfileJSON(t, func(doc map[string]any) {
		baseline := doc["baseline"].(map[string]any)
		baseline["evidence"] = map[string]any{
			"management_mirror_bucket": bucket,
		}
		if mutate != nil {
			mutate(doc)
		}
	})
}

// TestVerifyReportsCleanWhenMirrorAgrees is slice 2's happy path end to end:
// vend uploads the manifest to the configured mirror, and a `verify` run
// immediately afterward — nothing else touched either copy — reports the
// mirror as matching, not merely silent about it.
func TestVerifyReportsCleanWhenMirrorAgrees(t *testing.T) {
	g, f := vendWorld(t)
	const bucket = "automat-evidence-mirror"
	profile := mirrorProfileJSON(t, bucket, nil)
	accountID := vendThenVerify(t, g, f, profile)

	out, _, err := runCLI(t, g, verifyArgs(profile, accountID)...)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out, "Evidence mirror layer:") {
		t.Fatalf("verify's report does not have a mirror-drift section:\n%s", out)
	}
	if !strings.Contains(out, "matches the local manifest") {
		t.Errorf("verify's report does not say the mirror matches:\n%s", out)
	}
	if strings.Contains(out, "DISAGREES") || strings.Contains(out, "TRUNCATED") {
		t.Errorf("verify reported mirror drift against an untouched mirror:\n%s", out)
	}
}

// TestVerifyReportsDriftWhenMirrorBytesDiffer is the tampering signal Q21
// exists to catch: the fake mirror's stored bytes are deliberately different
// from what vend wrote locally (simulating a local-file rewrite the mirror
// did not receive, or vice versa), and verify must say so, fail, and exit
// exitVerifyDrift.
func TestVerifyReportsDriftWhenMirrorBytesDiffer(t *testing.T) {
	g, f := vendWorld(t)
	const bucket = "automat-evidence-mirror"
	profile := mirrorProfileJSON(t, bucket, nil)
	accountID := vendThenVerify(t, g, f, profile)

	// Corrupt the mirrored copy's stored bytes directly, simulating a
	// tampered mirror (or, symmetrically, a tampered local file compared
	// against an honest mirror — MirrorDrift's comparison is agnostic to
	// which side changed).
	tampered, ok := f.S3.Object(bucket, accountID+".json")
	if !ok {
		t.Fatalf("vend did not upload a manifest to %s/%s.json", bucket, accountID)
	}
	// Flip a digit inside manifest.organization_id's value: a field Validate
	// checks only for its own character class (org.SameDocument-style
	// internal consistency does not cover it), so the corrupted document
	// still decodes and chain-verifies cleanly — the mirrored copy is
	// internally sound on its own, and only a second, independently-held
	// copy (the local manifest) reveals the disagreement, exactly the
	// property docs/open-questions.md Q21 is about.
	corrupted := flipFirstDigit(string(tampered), "organization_id")
	f.S3.SetObject(bucket, accountID+".json", []byte(corrupted))

	out, _, err := runCLI(t, g, verifyArgs(profile, accountID)...)
	if err == nil {
		t.Fatal("verify succeeded against a tampered mirror, want a non-zero exit for drift")
	}
	if code := exitCodeOf(err); code != exitVerifyDrift {
		t.Errorf("exit code = %d, want %d (exitVerifyDrift)", code, exitVerifyDrift)
	}
	if !strings.Contains(out, "DISAGREES with the local manifest") {
		t.Errorf("verify's output does not report the mirror disagreement:\n%s", out)
	}
	if !strings.Contains(out, "organization_id") {
		t.Errorf("verify's output does not name which field disagreed:\n%s", out)
	}
}

// TestVerifyMirrorUnreachableIsNotDriftOrClean is the third, distinct state
// the task calls out explicitly: a mirror configured but not readable
// (denied, or nothing ever uploaded) must not be reported as either a drift
// finding or a clean pass, and must move the exit code to exitVerifyUnknown
// rather than exitVerifyDrift or a clean 0.
func TestVerifyMirrorUnreachableIsNotDriftOrClean(t *testing.T) {
	g, f := vendWorld(t)
	const bucket = "automat-evidence-mirror-unreachable"
	// This profile names a DIFFERENT bucket than the one vend uploads to —
	// simplest way to reproduce "nothing was ever uploaded here" without
	// needing a denial-shaped fake error.
	vendProfile := mirrorProfileJSON(t, "automat-evidence-mirror", nil)
	accountID := vendThenVerify(t, g, f, vendProfile)

	verifyProfile := mirrorProfileJSON(t, bucket, nil)

	out, _, err := runCLI(t, g, verifyArgs(verifyProfile, accountID)...)
	if err == nil {
		t.Fatal("verify against an unreachable mirror succeeded, want a non-zero exit")
	}
	if code := exitCodeOf(err); code != exitVerifyUnknown {
		t.Errorf("exit code = %d, want %d (exitVerifyUnknown)", code, exitVerifyUnknown)
	}
	if strings.Contains(out, "DISAGREES with the local manifest") || strings.Contains(out, "TRUNCATED") {
		t.Errorf("an unreachable mirror was reported as a drift finding:\n%s", out)
	}
	if !strings.Contains(out, "could not verify") {
		t.Errorf("verify's output does not say the mirror could not be verified:\n%s", out)
	}
}

// TestVerifyWithNoMirrorConfiguredOmitsTheSection is the common,
// today's-default case unaffected by slice 2: a profile naming no mirror
// bucket at all must print no "Evidence mirror layer:" section — absence of
// the section is "nothing to check", not "checked and clean" (renderVerifyReport's
// own doc comment).
func TestVerifyWithNoMirrorConfiguredOmitsTheSection(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	out, _, err := runCLI(t, g, verifyArgs(profile, accountID)...)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if strings.Contains(out, "Evidence mirror layer:") {
		t.Errorf("verify printed a mirror-drift section with no mirror configured:\n%s", out)
	}
}

// flipFirstDigit finds `"<field>": "o-<value>"` in raw (manifest.organization_id's
// own "o-" + [a-z0-9]{10,32} shape) and changes the first character AFTER
// that fixed "o-" prefix to a different lowercase letter, producing a
// still-valid JSON document that still matches evidence's own
// reOrgID pattern, whose named field's value differs from the original by
// exactly one character — enough for evidence.MirrorDrift's Meta comparison
// to catch, without needing a JSON library in this small test helper.
func flipFirstDigit(raw, field string) string {
	marker := `"` + field + `": "o-`
	i := strings.Index(raw, marker)
	if i < 0 {
		return raw
	}
	start := i + len(marker)
	if start >= len(raw) {
		return raw
	}
	flipped := byte('a')
	if raw[start] == 'a' {
		flipped = 'b'
	}
	return raw[:start] + string(flipped) + raw[start+1:]
}
