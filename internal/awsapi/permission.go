// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsapi

import (
	"errors"
	"strings"

	"github.com/aws/smithy-go"
)

// PermissionError is an AWS authorization failure rewritten as something an
// operator can act on.
//
// CLAUDE.md rule 7: every permission failure must say which action, which
// resource, and what grant would fix it. AWS's own message — "User: arn:… is not
// authorized to perform: organizations:MoveAccount" — names the first two and
// never the third, which leaves the operator to guess whether they need an
// identity policy, a delegation policy, a role trust edit, or a different
// account entirely. Those four have completely different owners at a university,
// so guessing wrong costs days.
//
// The Grant field is automat's contribution: the sentence the operator forwards
// to whoever can actually make the change.
//
// # Why AWS's own message is reprinted rather than replaced
//
// Rule 7's three parts are what automat OWES the operator; they are not the whole
// of what is diagnostically load-bearing. A denial has two quite different causes
// that produce the same error code: the principal lacks the action, or the
// principal has the action under a condition that did not match. Only the second
// is visible in AWS's message ("…with the request tags provided"), and automat
// cannot know which happened — Grant is written at the call site, before the call.
//
// AUDIT-2 found this the hard way: a request-tag mismatch on CreateAccount
// rendered as "grant organizations:CreateAccount … in the management account",
// advice for a permission the operator already had. The grant sentence was
// confidently wrong, and the sentence that would have identified the real cause was
// in Cause, which Error() dropped. So both are printed, labeled by who is speaking:
// automat's remediation is a claim automat is making, and AWS's text is evidence.
type PermissionError struct {
	// Action is the API action that was denied, e.g. "organizations:MoveAccount".
	Action string
	// Resource is what it was denied on: an ARN, an OU id, or a description when
	// the API does not report one.
	Resource string
	// Principal is the identity automat was speaking as, from the credential
	// chain or an assumed role.
	Principal string
	// Grant is what would fix it, in the imperative, naming who must act.
	Grant string
	// Cause is the underlying SDK error.
	Cause error
}

func (e *PermissionError) Error() string {
	var b strings.Builder
	b.WriteString("not authorized to ")
	b.WriteString(e.Action)
	if e.Resource != "" {
		b.WriteString(" on ")
		b.WriteString(e.Resource)
	}
	if e.Principal != "" {
		b.WriteString(" as ")
		b.WriteString(e.Principal)
	}
	if e.Grant != "" {
		b.WriteString("\n  to fix: ")
		b.WriteString(e.Grant)
	}
	// Last, and attributed. A condition failure is indistinguishable from a missing
	// action by code alone, and this line is the only place the difference appears.
	// Attributed because the two sentences have different authors and different
	// reliabilities: the fix is automat's inference, this is what AWS said.
	if msg := causeMessage(e.Cause); msg != "" {
		b.WriteString("\n  AWS said: ")
		b.WriteString(msg)
	}
	return b.String()
}

// causeMessage is the AWS API message from err, or "" when there is nothing worth
// printing.
//
// Only a smithy.APIError's message is reprinted, not any wrapped error's text: a
// transport or context error adds noise to a sentence about authorization, and the
// caller already sees it through Unwrap. An empty or duplicate-of-Action message is
// dropped rather than rendered as a dangling label.
func causeMessage(err error) string {
	var ae smithy.APIError
	if err == nil || !errors.As(err, &ae) {
		return ""
	}
	return strings.TrimSpace(ae.ErrorMessage())
}

func (e *PermissionError) Unwrap() error { return e.Cause }

// APIErrorCode returns the AWS error code from err, or "" if it is not an AWS
// API error. Callers switch on the code rather than on the message text, which
// AWS changes without notice.
func APIErrorCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// IsAccessDenied reports whether err is an authorization failure.
//
// AWS spells this several ways across services and even across operations within
// Organizations, so the set is matched explicitly. An unrecognized code is
// treated as *not* a permission problem: mislabeling a throttle or a validation
// error as "you need a grant" sends the operator to their security team for
// nothing, which is worse than a generic error.
func IsAccessDenied(err error) bool {
	switch APIErrorCode(err) {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
		"AuthorizationError", "AccessDeniedForDependencyException":
		return true
	}
	return false
}

// IsNotInOrganization reports whether err means the caller's account is not part
// of an organization. This is a preflight *answer*, not a failure: it is how the
// STANDALONE state is detected (DESIGN §4).
func IsNotInOrganization(err error) bool {
	return APIErrorCode(err) == "AWSOrganizationsNotInUseException"
}

// Denied wraps err as a PermissionError when it is an authorization failure, and
// returns it unchanged otherwise.
//
// Call it at the point that knows what the call was for, because that is the
// only place the remediation sentence can be written honestly — a generic
// interceptor would produce generic advice, which is the failure mode rule 7
// exists to prevent.
func Denied(err error, action, resource, principal, grant string) error {
	if err == nil {
		return nil
	}
	if !IsAccessDenied(err) {
		return err
	}
	return &PermissionError{
		Action: action, Resource: resource, Principal: principal, Grant: grant, Cause: err,
	}
}

// AsPermissionError extracts a *PermissionError from err, if there is one.
func AsPermissionError(err error) (*PermissionError, bool) {
	var pe *PermissionError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}
