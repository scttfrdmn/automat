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
