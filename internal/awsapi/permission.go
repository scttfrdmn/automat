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
	return b.String()
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
