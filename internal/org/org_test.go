// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/awsfake"
)

// Shared fixtures. The ids match internal/awsfake's own test constants so a
// failure in either place reads against the same organization.
const (
	testOrgID    = "o-exampleorg"
	testMgmtAcct = "111111111111"
	testRoot     = "r-exam"
	testEmail    = "lab-alpha@example.edu"

	// scpDoc and scpDocReformatted are the same policy. The second is what a
	// service that normalizes whitespace and key order could return, and the
	// difference between comparing bytes and comparing structure is the whole
	// run-twice property.
	scpDoc            = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`
	scpDocReformatted = "{\n  \"Statement\": [\n    {\n      \"Action\": \"s3:*\",\n" +
		"      \"Effect\": \"Deny\",\n      \"Resource\": \"*\"\n    }\n  ],\n" +
		"  \"Version\": \"2012-10-17\"\n}\n"
	scpDocOther = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:*","Resource":"*"}]}`
)

func ctx() context.Context { return context.Background() }

// fixture is one organization plus an Ensurer over it.
type fixture struct {
	State  *awsfake.OrgState
	Vend   *awsfake.OrgVend
	Policy *awsfake.OrgPolicy
	Init   *awsfake.OrgInit
	Read   *awsfake.Org
	E      *Ensurer
}

// newFixture returns an apply-mode Ensurer over an organization with SCPs
// enabled. Sleep is a no-op so the poll loop does not take wall-clock time; the
// fake's CreateAccountPolls default of 2 still means every create is polled more
// than once, which is what keeps the asynchronous path honest.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := awsfake.NewOrgState(testOrgID, testMgmtAcct)
	f := &fixture{
		State:  st,
		Vend:   awsfake.NewOrgVend(st),
		Policy: awsfake.NewOrgPolicy(st),
		Init:   awsfake.NewOrgInit(st),
		Read:   awsfake.NewOrg(testOrgID, testMgmtAcct),
	}
	f.E = &Ensurer{
		Vend:   f.Vend,
		Policy: f.Policy,
		Init:   f.Init,
		Mode:   ModeApply,
		Sleep:  func(context.Context, time.Duration) error { return nil },
	}
	return f
}

// resetCalls clears every recorder, for the second half of a run-twice check.
func (f *fixture) resetCalls() {
	f.Vend.Reset()
	f.Policy.Reset()
	f.Init.Reset()
	f.Read.Reset()
	f.E.ResetActions()
}

// writeCalls returns the mutating calls every recorder saw, sorted.
//
// The list is derived from the awsapi write interfaces rather than from what the
// code under test happens to call, so an operation added later is covered by
// TestPlanTouchesNothing without anybody remembering to extend this.
func (f *fixture) writeCalls() []string {
	writes := map[string]bool{
		"CreateAccount": true, "MoveAccount": true, "CreateOrganizationalUnit": true,
		"TagResource": true, "CreatePolicy": true, "UpdatePolicy": true,
		"AttachPolicy": true, "CreateOrganization": true, "EnablePolicyType": true,
	}
	var out []string
	for _, r := range []interface{ Calls() []string }{f.Vend, f.Policy, f.Init, f.Read} {
		for _, c := range r.Calls() {
			if writes[c] {
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (f *fixture) seedOwnedPolicy(name, content string) string {
	return f.State.SeedPolicy(name, content, map[string]string{OwnerTagKey: OwnerTagValue})
}

func mustErr(t *testing.T, err error, wants ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	for _, w := range wants {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error text is missing %q:\n%v", w, err)
		}
	}
}

// -----------------------------------------------------------------------------
// The plan/apply split.
// -----------------------------------------------------------------------------

// TestPlanTouchesNothing is the plan/apply split held against the fakes' call log
// rather than by inspection (CLAUDE.md rule 5).
//
// Every operation in the package runs against an organization where nothing it
// wants exists yet — the case with the most to create and therefore the most to
// get wrong — and the assertion is that no mutating call was made at all. An
// operation added later that forgets the mode check fails here without anybody
// extending the test, because the write list is the interface's rather than the
// caller's.
func TestPlanTouchesNothing(t *testing.T) {
	f := newFixture(t)
	f.E.Mode = ModePlan
	ou := f.State.SeedOU("Research", testRoot)

	if _, _, err := f.E.EnsureOU(ctx(), testRoot, "Regulated"); err != nil {
		t.Fatalf("EnsureOU: %v", err)
	}
	if _, _, err := f.E.EnsureOUPath(ctx(), testRoot, []string{"Regulated", "CUI"}); err != nil {
		t.Fatalf("EnsureOUPath: %v", err)
	}
	if _, _, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "lab-alpha", Email: testEmail,
		Tags:          map[string]string{"automat:vended-by": "automat"},
		SearchParents: []string{testRoot, ou},
	}); err != nil {
		t.Fatalf("EnsureAccount: %v", err)
	}
	acct := f.State.SeedAccount("existing", "other@example.edu", testRoot)
	if _, err := f.E.EnsurePlacement(ctx(), acct, ou); err != nil {
		t.Fatalf("EnsurePlacement: %v", err)
	}
	if _, _, err := f.E.EnsurePolicy(ctx(), PolicySpec{Name: "automat-x-1", Document: scpDoc}); err != nil {
		t.Fatalf("EnsurePolicy: %v", err)
	}
	if _, err := f.E.EnsurePolicySet(ctx(), ou, []PolicySpec{
		{Name: "automat-x-1", Document: scpDoc},
		{Name: "automat-x-region", Document: scpDocOther},
	}); err != nil {
		t.Fatalf("EnsurePolicySet: %v", err)
	}
	if _, _, err := f.E.EnsureOrganization(ctx(), f.Read); err != nil {
		t.Fatalf("EnsureOrganization: %v", err)
	}
	if _, err := f.E.EnsureSCPEnabled(ctx(), testRoot, f.Read); err != nil {
		t.Fatalf("EnsureSCPEnabled: %v", err)
	}

	if got := f.writeCalls(); len(got) != 0 {
		t.Errorf("a plan issued mutating calls: %v", got)
	}
	if f.E.Changed() {
		t.Error("a plan reported Changed() = true")
	}
	for _, a := range f.E.Actions() {
		if a.Applied {
			t.Errorf("a plan produced an applied action: %s", a)
		}
	}
	// Every planned creation must leave ID empty rather than invent one.
	for _, a := range f.E.Actions() {
		if a.Verb == VerbCreate && a.ID != "" {
			t.Errorf("a planned creation carries an id it cannot know: %s", a)
		}
	}
}

// TestVerbUnchangedIsNeverApplied holds the one invariant a reader of the
// evidence manifest depends on: Applied distinguishes a real change from a
// prediction, and an unchanged action wrote nothing in either mode. If they ever
// diverge, every "run twice = no diff" assertion in this package becomes
// unfalsifiable at once.
func TestVerbUnchangedIsNeverApplied(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Research", testRoot)
	acct := f.State.SeedAccount("lab", testEmail, ou)
	f.seedOwnedPolicy("automat-x-1", scpDoc)

	if _, _, err := f.E.EnsureOU(ctx(), testRoot, "Research"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.E.EnsurePlacement(ctx(), acct, ou); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.E.EnsurePolicy(ctx(), PolicySpec{Name: "automat-x-1", Document: scpDoc}); err != nil {
		t.Fatal(err)
	}
	acts := f.E.Actions()
	if len(acts) != 3 {
		t.Fatalf("expected 3 actions, got %d: %v", len(acts), acts)
	}
	for _, a := range acts {
		if a.Verb != VerbUnchanged {
			t.Errorf("expected unchanged, got %s", a)
		}
		if a.Applied {
			t.Errorf("unchanged action reports Applied: %s", a)
		}
	}
	if f.E.Changed() {
		t.Error("Changed() is true when everything was already in place")
	}
}

// -----------------------------------------------------------------------------
// Parkable.
// -----------------------------------------------------------------------------

// TestParkable pins the classification, negative cases included.
//
// The negatives are the point. ROADMAP Phase 2 requires a policy failure after a
// successful create to be a resumable parked state, and the obvious
// over-correction is to park on everything — which would record a throttle or a
// dropped connection as an account needing manual attention and fill an
// operator's inventory with accounts that are fine.
func TestParkable(t *testing.T) {
	cvWith := func(r orgtypes.ConstraintViolationExceptionReason) error {
		return &orgtypes.ConstraintViolationException{Reason: r}
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"access denied", awsfake.AccessDenied("organizations:AttachPolicy"), true},
		{"malformed document", &awsfake.APIError{Code: "MalformedPolicyDocumentException"}, true},
		{"policy type not enabled", &orgtypes.PolicyTypeNotEnabledException{}, true},
		{"attachment limit", cvWith(orgtypes.ConstraintViolationExceptionReasonMaxPolicyTypeAttachmentLimitExceeded), true},
		{"policy content limit", cvWith(orgtypes.ConstraintViolationExceptionReasonPolicyContentLimitExceeded), true},
		{"policy number limit", cvWith(orgtypes.ConstraintViolationExceptionReasonPolicyNumberLimitExceeded), true},
		{"ou number limit", cvWith(orgtypes.ConstraintViolationExceptionReasonOuNumberLimitExceeded), true},
		{"ou depth limit", cvWith(orgtypes.ConstraintViolationExceptionReasonOuDepthLimitExceeded), true},

		// Retries, not states.
		{"throttled", awsfake.Throttled(), false},
		{"network failure", errors.New("dial tcp: connection reset by peer"), false},
		{"duplicate policy", &orgtypes.DuplicatePolicyException{}, false},
		{"account quota", cvWith(orgtypes.ConstraintViolationExceptionReasonAccountNumberLimitExceeded), false},
		{"wrapped access denied", fmt.Errorf("attaching: %w",
			awsfake.AccessDenied("organizations:AttachPolicy")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Parkable(tt.err); got != tt.want {
				t.Errorf("Parkable = %v, want %v", got, tt.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// sameDocument.
// -----------------------------------------------------------------------------

func TestSameDocument(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", scpDoc, scpDoc, true},
		{
			// The case the run-twice property depends on: nothing documents that
			// Organizations returns a document byte-for-byte as submitted, so a
			// byte comparison would call UpdatePolicy on every single run.
			"reformatted by the service", scpDoc, scpDocReformatted, true,
		},
		{"different action", scpDoc, scpDocOther, false},
		{
			// UseNumber, so a policy that says 1 and one that says 1.0 are not
			// silently the same document.
			"number formatting", `{"A":1}`, `{"A":1.0}`, false,
		},
		{"unparseable left", "not json", scpDoc, false},
		{"unparseable right", scpDoc, "not json", false},
		{
			// Both unparseable is still "different", so automat overwrites. A
			// policy under automat's name that is not valid JSON enforces
			// nothing, and leaving it because it could not be read is the quiet
			// failure.
			"both unparseable", "not json", "not json", false,
		},
		{"trailing content", scpDoc, scpDoc + scpDoc, false},
		{"empty both", "", "", false},
		{
			// Statement order is preserved rather than smoothed over: it does not
			// change meaning to IAM, but the packer's order is deterministic and a
			// reordering is worth noticing.
			"statement order",
			`{"Statement":[{"Sid":"A"},{"Sid":"B"}]}`,
			`{"Statement":[{"Sid":"B"},{"Sid":"A"}]}`,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameDocument(tt.a, tt.b); got != tt.want {
				t.Errorf("sameDocument = %v, want %v", got, tt.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Remediation text.
// -----------------------------------------------------------------------------

// TestDeniedSendsTheOperatorToTheRightOwner is CLAUDE.md rule 7 as a test.
//
// The rule asks which action, which resource, and what grant would fix it. The
// third answer differs by credential AND, within Brokered, by whether the action
// is a policy operation — those go to a delegation policy document, and account
// and OU operations to the vendor role, which are two different files owned by the
// same person and requested in two different sentences. A generic message would
// send half the operators to the wrong place, which is the failure the rule exists
// to prevent.
func TestDeniedSendsTheOperatorToTheRightOwner(t *testing.T) {
	tests := []struct {
		name       string
		credential Credential
		action     string
		resource   string
		wants      []string
		notWants   []string
	}{
		{
			name: "native identity policy", credential: Native,
			action: "organizations:CreateAccount", resource: "the organization",
			wants:    []string{"grant organizations:CreateAccount", "your own identity policy"},
			notWants: []string{"delegation-policy.json", "vendor-role"},
		},
		{
			name: "brokered policy action goes to the delegation policy", credential: Brokered,
			action: "organizations:CreatePolicy", resource: "a new service control policy",
			wants:    []string{"delegation-policy.json", "management account"},
			notWants: []string{"vendor-role.cfn.yaml"},
		},
		{
			name: "brokered attach goes to the delegation policy", credential: Brokered,
			action: "organizations:AttachPolicy", resource: "ou-exam-1",
			wants:    []string{"delegation-policy.json"},
			notWants: []string{"vendor-role.cfn.yaml"},
		},
		{
			name: "brokered account action goes to the vendor role", credential: Brokered,
			action: "organizations:CreateAccount", resource: "the organization",
			wants:    []string{"vendor-role.cfn.yaml", "cannot be delegated to a member account"},
			notWants: []string{"delegation-policy.json"},
		},
		{
			name: "brokered tag on a policy goes to the delegation policy", credential: Brokered,
			action: "organizations:TagResource", resource: "p-auto0001",
			wants:    []string{"delegation-policy.json"},
			notWants: []string{"vendor-role.cfn.yaml"},
		},
		{
			name: "brokered tag on an account goes to the vendor role", credential: Brokered,
			action: "organizations:TagResource", resource: "123456789012",
			wants:    []string{"vendor-role.cfn.yaml"},
			notWants: []string{"delegation-policy.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Ensurer{Credential: tt.credential, Principal: "arn:aws:iam::111111111111:role/automat"}
			err := e.denied(awsfake.AccessDenied(tt.action), tt.action, tt.resource)
			var pe *awsapi.PermissionError
			if !errors.As(err, &pe) {
				t.Fatalf("expected a PermissionError, got %T: %v", err, err)
			}
			if pe.Action != tt.action {
				t.Errorf("Action = %q, want %q", pe.Action, tt.action)
			}
			if pe.Resource != tt.resource {
				t.Errorf("Resource = %q, want %q", pe.Resource, tt.resource)
			}
			if pe.Grant == "" {
				t.Error("no remediation text: rule 7 requires what grant would fix it")
			}
			for _, w := range tt.wants {
				if !strings.Contains(pe.Grant, w) {
					t.Errorf("remediation is missing %q:\n%s", w, pe.Grant)
				}
			}
			for _, w := range tt.notWants {
				if strings.Contains(pe.Grant, w) {
					t.Errorf("remediation sends the operator to %q, which is the wrong owner:\n%s", w, pe.Grant)
				}
			}
		})
	}
}

// TestDeniedPassesThroughNonDenials keeps denied from dressing up an error it
// does not understand: a throttle wrapped in "here is the grant you need" would
// send an operator to ask for a permission they already have.
func TestDeniedPassesThroughNonDenials(t *testing.T) {
	e := &Ensurer{Credential: Brokered}
	in := awsfake.Throttled()
	if got := e.denied(in, "organizations:AttachPolicy", "ou-exam-1"); got != error(in) {
		t.Errorf("denied altered a non-denial: %v", got)
	}
	if e.denied(nil, "a", "b") != nil {
		t.Error("denied turned nil into an error")
	}
}
