// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/awsfake"
	"github.com/scttfrdmn/automat/internal/compilesets"
	"github.com/scttfrdmn/automat/internal/org"
)

const testTarget = "ou-exam-00000001"

func ownerTag() map[string]string {
	return map[string]string{org.OwnerTagKey: org.OwnerTagValue}
}

func TestCheckPolicyMatching(t *testing.T) {
	state := awsfake.NewOrgState("o-exam", "111111111111")
	api := awsfake.NewOrgVerify(state)
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Deny","Action":"iam:*","Resource":"*"}]}`
	id := state.SeedPolicy("automat-web-1", doc, ownerTag())
	state.SeedAttachment(id, testTarget)

	packed := &compilesets.Packed{Policies: []compilesets.Policy{{Name: "automat-web-1", Document: doc}}}

	report, err := CheckPolicy(context.Background(), api, testTarget, packed)
	if err != nil {
		t.Fatalf("CheckPolicy: %v", err)
	}
	if !report.Clean() {
		t.Errorf("Clean() = false, want true: %+v", report)
	}
	if len(report.Expected) != 1 {
		t.Fatalf("Expected has %d entries, want 1", len(report.Expected))
	}
	got := report.Expected[0]
	if !got.Attached || !got.Matches || !got.Owned || got.PolicyID != id {
		t.Errorf("got %+v", got)
	}
}

func TestCheckPolicyDrifted(t *testing.T) {
	state := awsfake.NewOrgState("o-exam", "111111111111")
	api := awsfake.NewOrgVerify(state)
	attachedDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Deny","Action":"iam:*","Resource":"*"}]}`
	expectedDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Deny","Action":"ec2:*","Resource":"*"}]}`
	id := state.SeedPolicy("automat-web-1", attachedDoc, ownerTag())
	state.SeedAttachment(id, testTarget)

	packed := &compilesets.Packed{Policies: []compilesets.Policy{{Name: "automat-web-1", Document: expectedDoc}}}

	report, err := CheckPolicy(context.Background(), api, testTarget, packed)
	if err != nil {
		t.Fatalf("CheckPolicy: %v", err)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: content differs")
	}
	got := report.Expected[0]
	if !got.Attached || got.Matches || !got.Owned {
		t.Errorf("got %+v, want attached and owned but not matching", got)
	}
}

func TestCheckPolicyReformattedByServiceStillMatches(t *testing.T) {
	// The same property org.SameDocument's own tests hold: a document AWS
	// returns reformatted (different whitespace, same structure) must not
	// read as drift, or verify would report every real account as failing.
	state := awsfake.NewOrgState("o-exam", "111111111111")
	api := awsfake.NewOrgVerify(state)
	compact := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Deny","Action":"iam:*","Resource":"*"}]}`
	reformatted := "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\"Sid\":\"A\",\"Effect\":\"Deny\",\"Action\":\"iam:*\",\"Resource\":\"*\"}\n  ]\n}"
	id := state.SeedPolicy("automat-web-1", reformatted, ownerTag())
	state.SeedAttachment(id, testTarget)

	packed := &compilesets.Packed{Policies: []compilesets.Policy{{Name: "automat-web-1", Document: compact}}}

	report, err := CheckPolicy(context.Background(), api, testTarget, packed)
	if err != nil {
		t.Fatalf("CheckPolicy: %v", err)
	}
	if !report.Clean() {
		t.Errorf("Clean() = false, want true: a service-side reformat must not read as drift: %+v", report)
	}
}

func TestCheckPolicyNotAttached(t *testing.T) {
	state := awsfake.NewOrgState("o-exam", "111111111111")
	api := awsfake.NewOrgVerify(state)
	packed := &compilesets.Packed{Policies: []compilesets.Policy{{Name: "automat-web-1", Document: `{"Version":"2012-10-17","Statement":[]}`}}}

	report, err := CheckPolicy(context.Background(), api, testTarget, packed)
	if err != nil {
		t.Fatalf("CheckPolicy: %v", err)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: nothing is attached")
	}
	got := report.Expected[0]
	if got.Attached {
		t.Errorf("Attached = true, want false")
	}
}

func TestCheckPolicyNameCollisionNotAutomats(t *testing.T) {
	// A policy present under the right name but without the owner tag is a
	// name collision, not drift automat caused, and CheckPolicy must say so
	// rather than reporting it as a content mismatch.
	state := awsfake.NewOrgState("o-exam", "111111111111")
	api := awsfake.NewOrgVerify(state)
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Deny","Action":"iam:*","Resource":"*"}]}`
	id := state.SeedPolicy("automat-web-1", doc, nil) // no owner tag
	state.SeedAttachment(id, testTarget)

	packed := &compilesets.Packed{Policies: []compilesets.Policy{{Name: "automat-web-1", Document: doc}}}

	report, err := CheckPolicy(context.Background(), api, testTarget, packed)
	if err != nil {
		t.Fatalf("CheckPolicy: %v", err)
	}
	got := report.Expected[0]
	if !got.Attached || got.Owned || got.Matches {
		t.Errorf("got %+v, want attached=true owned=false matches=false", got)
	}
}

func TestCheckPolicyOrphan(t *testing.T) {
	state := awsfake.NewOrgState("o-exam", "111111111111")
	api := awsfake.NewOrgVerify(state)
	leftoverDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"Old","Effect":"Deny","Action":"s3:*","Resource":"*"}]}`
	id := state.SeedPolicy("automat-web-1", leftoverDoc, ownerTag())
	state.SeedAttachment(id, testTarget)

	// The current compile no longer names automat-web-1 at all — a narrowed
	// artifact, the case org.EnsurePolicySet's own orphan check exists for.
	packed := &compilesets.Packed{Policies: nil}

	report, err := CheckPolicy(context.Background(), api, testTarget, packed)
	if err != nil {
		t.Fatalf("CheckPolicy: %v", err)
	}
	if len(report.Orphans) != 1 {
		t.Fatalf("Orphans = %v, want exactly one entry", report.Orphans)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: an orphan is present")
	}
}

func TestCheckPolicyIgnoresUnownedNonMatchingName(t *testing.T) {
	// A policy with an unrelated name and no owner tag is neither expected nor
	// an orphan — it is somebody else's policy and must not appear in either
	// list.
	state := awsfake.NewOrgState("o-exam", "111111111111")
	api := awsfake.NewOrgVerify(state)
	id := state.SeedPolicy("institutional-floor", `{"Version":"2012-10-17","Statement":[]}`, nil)
	state.SeedAttachment(id, testTarget)

	packed := &compilesets.Packed{Policies: nil}
	report, err := CheckPolicy(context.Background(), api, testTarget, packed)
	if err != nil {
		t.Fatalf("CheckPolicy: %v", err)
	}
	if len(report.Orphans) != 0 {
		t.Errorf("Orphans = %v, want none: this policy is not automat's", report.Orphans)
	}
	if !report.Clean() {
		t.Errorf("Clean() = false, want true: nothing automat's is drifted or orphaned")
	}
}

func TestCheckPolicyPagination(t *testing.T) {
	// PageSize defaults to 2, so five attached policies force multiple pages
	// through ListPoliciesForTarget and ListTagsForResource both — the same
	// truncated-read bug internal/org's own tests guard against.
	state := awsfake.NewOrgState("o-exam", "111111111111")
	api := awsfake.NewOrgVerify(state)
	packed := &compilesets.Packed{}
	for i := 0; i < 5; i++ {
		name := "automat-web-" + string(rune('1'+i))
		doc := `{"Version":"2012-10-17","Statement":[{"Sid":"S` + string(rune('1'+i)) + `","Effect":"Deny","Action":"iam:*","Resource":"*"}]}`
		id := state.SeedPolicy(name, doc, ownerTag())
		state.SeedAttachment(id, testTarget)
		packed.Policies = append(packed.Policies, compilesets.Policy{Name: name, Document: doc})
	}

	report, err := CheckPolicy(context.Background(), api, testTarget, packed)
	if err != nil {
		t.Fatalf("CheckPolicy: %v", err)
	}
	if len(report.Expected) != 5 {
		t.Fatalf("Expected has %d entries, want 5", len(report.Expected))
	}
	if !report.Clean() {
		t.Errorf("Clean() = false, want true: %+v", report.Expected)
	}
}

func TestCheckPolicyNoTarget(t *testing.T) {
	state := awsfake.NewOrgState("o-exam", "111111111111")
	api := awsfake.NewOrgVerify(state)
	if _, err := CheckPolicy(context.Background(), api, "", &compilesets.Packed{}); err == nil {
		t.Fatal("CheckPolicy with no target succeeded, want an error")
	}
}

func TestCheckPolicyDenied(t *testing.T) {
	state := awsfake.NewOrgState("o-exam", "111111111111")
	state.Errs["ListPoliciesForTarget"] = awsfake.AccessDenied("organizations:ListPoliciesForTarget")
	api := awsfake.NewOrgVerify(state)

	_, err := CheckPolicy(context.Background(), api, testTarget, &compilesets.Packed{})
	if err == nil {
		t.Fatal("CheckPolicy succeeded despite a denied read, want an error")
	}
	if pe, ok := awsapi.AsPermissionError(err); !ok || pe.Action != "organizations:ListPoliciesForTarget" {
		t.Errorf("error = %v, want a *awsapi.PermissionError naming ListPoliciesForTarget", err)
	}
}
