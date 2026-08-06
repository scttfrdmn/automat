// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsapi

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
)

type apiErr struct {
	code string
	msg  string
}

func (e *apiErr) Error() string                 { return "api error " + e.code + ": " + e.msg }
func (e *apiErr) ErrorCode() string             { return e.code }
func (e *apiErr) ErrorMessage() string          { return e.msg }
func (e *apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestIsAccessDeniedRecognizesEverySpelling(t *testing.T) {
	// AWS spells authorization failure differently across services and even
	// across operations within Organizations. Each of these is a real code.
	denied := []string{
		"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
		"AuthorizationError", "AccessDeniedForDependencyException",
	}
	for _, code := range denied {
		if !IsAccessDenied(&apiErr{code: code}) {
			t.Errorf("%s not recognized as a denial", code)
		}
	}
}

// TestNonDenialsAreNotDenials. Labeling a throttle or a validation error as
// "you need a grant" sends the operator to their security team for nothing, and
// they come back a week later with the same error.
func TestNonDenialsAreNotDenials(t *testing.T) {
	notDenied := []string{
		"TooManyRequestsException", "ThrottlingException", "ValidationException",
		"OrganizationalUnitNotFoundException", "AWSOrganizationsNotInUseException",
		"ServiceException", "ConcurrentModificationException",
		// Near-misses that must not be swept in by a prefix match.
		"AccessDeniedNot", "NotAccessDenied", "",
	}
	for _, code := range notDenied {
		if IsAccessDenied(&apiErr{code: code}) {
			t.Errorf("%s misclassified as a permission failure", code)
		}
	}
	if IsAccessDenied(errors.New("connection reset by peer")) {
		t.Error("a plain error was classified as a permission failure")
	}
	if IsAccessDenied(nil) {
		t.Error("nil was classified as a permission failure")
	}
}

// TestClassificationSeesThroughWrapping: automat wraps SDK errors with fmt.Errorf
// on the way up, and a classifier that only inspected the outermost error would
// report every wrapped denial as a generic failure.
func TestClassificationSeesThroughWrapping(t *testing.T) {
	wrapped := fmt.Errorf("describe organization: %w",
		fmt.Errorf("operation error: %w", &apiErr{code: "AccessDeniedException"}))
	if !IsAccessDenied(wrapped) {
		t.Error("a wrapped denial was not recognized")
	}
	if got := APIErrorCode(wrapped); got != "AccessDeniedException" {
		t.Errorf("APIErrorCode = %q", got)
	}
	if !IsNotInOrganization(fmt.Errorf("x: %w", &apiErr{code: "AWSOrganizationsNotInUseException"})) {
		t.Error("a wrapped not-in-organization was not recognized")
	}
}

func TestDeniedOnlyWrapsDenials(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		if err := Denied(nil, "a", "r", "p", "g"); err != nil {
			t.Errorf("= %v", err)
		}
	})
	t.Run("a throttle passes through unchanged", func(t *testing.T) {
		orig := &apiErr{code: "TooManyRequestsException", msg: "Rate exceeded"}
		got := Denied(orig, "organizations:MoveAccount", "ou-exam-research1", "arn:…", "grant it")
		if got != error(orig) {
			t.Errorf("a throttle was rewritten as a permission failure: %v", got)
		}
		if _, ok := AsPermissionError(got); ok {
			t.Error("AsPermissionError matched a throttle")
		}
	})
	t.Run("a denial becomes actionable", func(t *testing.T) {
		orig := &apiErr{code: "AccessDeniedException", msg: "not authorized"}
		err := Denied(orig, "organizations:MoveAccount", "ou-exam-research1",
			"arn:aws:sts::222222222222:assumed-role/operator/session",
			"the management account must add MoveAccount to the vendor role")

		pe, ok := AsPermissionError(err)
		if !ok {
			t.Fatalf("want a *PermissionError, got %T", err)
		}
		// Rule 7 is three parts, and the third is the one AWS never provides.
		for _, want := range []string{
			"organizations:MoveAccount", "ou-exam-research1",
			"arn:aws:sts::222222222222:assumed-role/operator/session",
			"the management account must add MoveAccount",
		} {
			if !strings.Contains(pe.Error(), want) {
				t.Errorf("rendered error omits %q:\n%s", want, pe.Error())
			}
		}
		if !strings.Contains(pe.Error(), "to fix:") {
			t.Errorf("the remediation is not labeled, so it reads as more error text:\n%s", pe.Error())
		}
		// The cause must survive so a caller can still switch on the AWS code.
		if !errors.Is(err, error(orig)) {
			t.Error("Denied dropped the underlying SDK error")
		}
		if got := APIErrorCode(err); got != "AccessDeniedException" {
			t.Errorf("APIErrorCode through a PermissionError = %q", got)
		}
	})
}

// TestAWSMessageSurvivesSoAConditionFailureIsDistinguishable is AUDIT-2's second
// automat:ou finding.
//
// A missing action and a matched-but-failed condition are the same error code. The
// Grant sentence is written at the call site before the call, so it always describes
// the first — and when the cause is the second, that advice is confidently wrong:
// "grant organizations:CreateAccount in the management account" to an operator who
// already has it. AWS's message is the only thing that names the real cause
// ("…with the request tags provided"), and Error() used to drop it.
func TestAWSMessageSurvivesSoAConditionFailureIsDistinguishable(t *testing.T) {
	orig := &apiErr{
		code: "AccessDeniedException",
		msg: "User: arn:aws:sts::111111111111:assumed-role/automat-vendor/session is not " +
			"authorized to perform: organizations:CreateAccount because no identity-based " +
			"policy allows the organizations:CreateAccount action with the request tags provided",
	}
	err := Denied(orig, "organizations:CreateAccount", "the organization",
		"arn:aws:sts::111111111111:assumed-role/automat-vendor/session",
		"grant organizations:CreateAccount on the organization")

	got := err.Error()
	if !strings.Contains(got, "with the request tags provided") {
		t.Errorf("the AWS message is not in the rendered error, so an operator holding the "+
			"action sees only remediation advice for a permission they already have:\n%s", got)
	}
	if !strings.Contains(got, "AWS said:") {
		t.Errorf("the AWS text is unattributed. automat's remediation is an inference and this "+
			"is evidence; a reader who cannot tell them apart cannot weigh them:\n%s", got)
	}

	// A non-AWS cause adds nothing about authorization and must not produce a
	// dangling label.
	plain := &PermissionError{Action: "sts:GetCallerIdentity", Cause: errors.New("dial tcp: timeout")}
	if strings.Contains(plain.Error(), "AWS said:") {
		t.Errorf("a non-API cause was rendered as an AWS message:\n%s", plain.Error())
	}
}

// TestErrorRendersWithMissingParts. Not every call site knows a resource — some
// AWS operations do not report one — and the error must still read as a sentence
// rather than as "not authorized to  on  as ".
func TestErrorRendersWithMissingParts(t *testing.T) {
	cases := []struct {
		name string
		err  *PermissionError
		want string
	}{
		{"action only", &PermissionError{Action: "sts:GetCallerIdentity"},
			"not authorized to sts:GetCallerIdentity"},
		{"no resource", &PermissionError{
			Action: "organizations:DescribeOrganization", Principal: "arn:p", Grant: "g",
		}, "not authorized to organizations:DescribeOrganization as arn:p\n  to fix: g"},
		{"no principal", &PermissionError{
			Action: "organizations:AttachPolicy", Resource: "ou-exam-research1", Grant: "g",
		}, "not authorized to organizations:AttachPolicy on ou-exam-research1\n  to fix: g"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}
