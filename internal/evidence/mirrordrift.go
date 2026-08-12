// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"context"
	"fmt"
	"reflect"
)

// MirrorDriftReport is MirrorDrift's result: the structured value a caller's
// printed report renders from, following this project's own "the result is a
// structured value; the printed report renders from it" convention
// (internal/verify.PolicyReport, verify.StructuralHonestyReport).
//
// # Three outcomes, not two
//
// A caller must be able to tell "nothing to check" (no mirror configured —
// established entirely above this type, by the caller never invoking
// MirrorDrift at all), "checked, clean" (Checked true, Drifted false), and
// "checked, could not complete" (Checked false — the mirror is configured but
// Fetch failed) apart. Collapsing the third into either of the other two is
// exactly the failure mode DESIGN §11's own compensating control would
// silently defeat: a network error or a permission denial read as "clean"
// tells an operator their evidence was cross-checked when it was not, and
// read as "drifted" sends them chasing tampering that may not exist.
type MirrorDriftReport struct {
	// Bucket is the mirror's own bucket name, for a report naming which
	// mirror was checked when more than one is configured.
	Bucket string
	// Checked is true only when Fetch succeeded and a comparison actually
	// ran. False means "could not verify" — see the type's own doc comment.
	Checked bool
	// Drifted is true when Checked and the two copies disagree. Meaningless
	// when Checked is false.
	Drifted bool
	// DriftKind names which of the three states this report is in, for a
	// caller that wants to branch on it without re-deriving the same
	// Checked/Drifted logic: "" (checked, clean), "disagreement",
	// "truncation" (Drifted's two distinct shapes — see MirrorDrift's own
	// doc comment for why they are kept apart), or "unreachable" (Checked is
	// false).
	DriftKind string
	// Detail is the human-readable explanation: which field of Meta
	// disagreed, which record index first differed, which side is the
	// shorter prefix, or the Fetch error's own text when DriftKind is
	// "unreachable". Empty when the report is checked and clean.
	Detail string
}

// Drift kinds. A closed, small vocabulary — like evidence.Operation's own —
// because a caller branches on these strings and a typo in a literal would
// silently fall through to the empty-string ("clean") case.
const (
	DriftKindDisagreement = "disagreement"
	DriftKindTruncation   = "truncation"
	DriftKindUnreachable  = "unreachable"
)

// MirrorDrift fetches key's mirrored manifest through reader and compares it
// against local — the read-and-diff half of ROADMAP.md's "Remote evidence
// mirror" backlog item, item 2, and the half of docs/open-questions.md's Q21
// that actually closes the residual rather than narrowing it: DESIGN §11's
// external anchor exists to be READ, not merely written to (evidence/mirror.go's
// own Upload has been doing the writing since slice 1).
//
// key is the same filename stem the local manifest was loaded/written under
// (ordinarily the account id, "<account_id>-N" post-rotation — see
// evidence.Mirror's own doc comment on why key matters). local is the
// caller's already-loaded, already-verified copy; MirrorDrift does not
// re-verify it, because a caller checking drift already holds a manifest it
// trusts enough to compare against.
//
// A Fetch failure — network error, permission denial, or simply "this
// account has never had anything uploaded to this mirror" — is reported as
// Checked: false, DriftKindUnreachable, never as a drift finding and never as
// a clean pass. See MirrorDriftReport's own doc comment for why that third
// state must stay distinct.
func MirrorDrift(ctx context.Context, reader MirrorReader, bucket, key string, local *Manifest) *MirrorDriftReport {
	report := &MirrorDriftReport{Bucket: bucket}
	if local == nil {
		report.DriftKind = DriftKindUnreachable
		report.Detail = "no local manifest was given to compare against"
		return report
	}
	mirrored, err := reader.Fetch(ctx, key)
	if err != nil {
		report.DriftKind = DriftKindUnreachable
		report.Detail = err.Error()
		return report
	}
	return compareManifests(bucket, local, mirrored)
}

// compareManifests is MirrorDrift's pure comparison, split out so a unit test
// can exercise agreement/disagreement/truncation/both-empty directly against
// two in-memory manifests without a fake S3 in the loop.
func compareManifests(bucket string, local, mirrored *Manifest) *MirrorDriftReport {
	report := &MirrorDriftReport{Bucket: bucket, Checked: true}

	if diff := metaDiff(local.Meta, mirrored.Meta); diff != "" {
		report.Drifted = true
		report.DriftKind = DriftKindDisagreement
		report.Detail = diff
		return report
	}

	n := min(len(local.Records), len(mirrored.Records))
	for i := 0; i < n; i++ {
		if !reflect.DeepEqual(local.Records[i], mirrored.Records[i]) {
			report.Drifted = true
			report.DriftKind = DriftKindDisagreement
			report.Detail = fmt.Sprintf("records[%d] differs between the local manifest and the "+
				"mirror at %s: the two copies of this record are not byte-for-byte the same, which "+
				"either the local file or the mirrored one has been edited since it was written",
				i, bucket)
			return report
		}
	}

	if len(local.Records) != len(mirrored.Records) {
		report.Drifted = true
		report.DriftKind = DriftKindTruncation
		shorter, longer, shorterName := "mirror", "local", "the mirror"
		shorterN, longerN := len(mirrored.Records), len(local.Records)
		if len(local.Records) < len(mirrored.Records) {
			shorter, longer, shorterName = "local", "mirror", "the local manifest"
			shorterN, longerN = len(local.Records), len(mirrored.Records)
		}
		report.Detail = fmt.Sprintf("the first %d records agree, but %s has only %d record(s) while "+
			"%s has %d: %s is a strict prefix of %s, which is the shape a tail truncation leaves — "+
			"distinct from a disagreement in content, because nothing in the range both copies hold "+
			"has been edited",
			n, shorterName, shorterN, longer, longerN, shorter, longer)
		return report
	}

	return report
}

// metaDiff names the first Meta field that disagrees between local and
// mirrored, or "" if every field agrees. Meta is a flat struct of comparable
// fields, so this could be a bare == — spelled out field by field instead so
// the report can say WHICH field disagreed, matching CLAUDE.md rule 7's
// "which field" discipline for every other kind of finding in this codebase.
func metaDiff(local, mirrored Meta) string {
	switch {
	case local.ID != mirrored.ID:
		return fmt.Sprintf("manifest.id: local is %q, mirror is %q", local.ID, mirrored.ID)
	case local.AccountID != mirrored.AccountID:
		return fmt.Sprintf("manifest.account_id: local is %q, mirror is %q", local.AccountID, mirrored.AccountID)
	case local.OrganizationID != mirrored.OrganizationID:
		return fmt.Sprintf("manifest.organization_id: local is %q, mirror is %q",
			local.OrganizationID, mirrored.OrganizationID)
	case local.CreatedAt != mirrored.CreatedAt:
		return fmt.Sprintf("manifest.created_at: local is %q, mirror is %q", local.CreatedAt, mirrored.CreatedAt)
	case local.GenesisSHA != mirrored.GenesisSHA:
		return fmt.Sprintf("manifest.genesis_sha256: local is %s, mirror is %s — this is exactly the "+
			"disagreement docs/open-questions.md Q21 exists to catch: a rewrite that truncates "+
			"records and recomputes the genesis anchor to match is internally consistent on its own, "+
			"and only a second, independently-held copy of the header can tell the two apart",
			safe(local.GenesisSHA), safe(mirrored.GenesisSHA))
	default:
		return ""
	}
}
