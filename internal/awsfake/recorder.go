// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"sync"

	"github.com/aws/smithy-go"
)

// Recorder logs the calls made to a fake.
//
// Embedded in every fake so a test can assert what did *not* happen, which is
// the harder and more valuable assertion: a plan-only run must issue no
// mutating call, and re-running an idempotent step must not repeat its writes.
type Recorder struct {
	mu    sync.Mutex
	calls []string
}

// Record notes one call by operation name.
func (r *Recorder) Record(op string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, op)
}

// Calls returns the operations called, in order.
func (r *Recorder) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// CallCount returns how many times op was called.
func (r *Recorder) CallCount(op string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int
	for _, c := range r.calls {
		if c == op {
			n++
		}
	}
	return n
}

// Reset clears the log, for the second half of a run-twice idempotency test.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = nil
}

// APIError is a fake AWS API error carrying a code, so tests can produce the
// exact failures automat classifies on: AccessDeniedException,
// AWSOrganizationsNotInUseException, ThrottlingException.
//
// It implements smithy.APIError rather than wrapping a service-specific type
// because the codes automat switches on are shared across services, and a fake
// that could only produce one service's spelling would let a classification bug
// hide behind it.
type APIError struct {
	Code    string
	Message string
	Fault   smithy.ErrorFault
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return "api error " + e.Code
	}
	return "api error " + e.Code + ": " + e.Message
}

// ErrorCode implements smithy.APIError.
func (e *APIError) ErrorCode() string { return e.Code }

// ErrorMessage implements smithy.APIError.
func (e *APIError) ErrorMessage() string { return e.Message }

// ErrorFault implements smithy.APIError.
func (e *APIError) ErrorFault() smithy.ErrorFault { return e.Fault }

// AccessDenied returns an AccessDeniedException naming the action, in the shape
// AWS actually returns it.
func AccessDenied(action string) *APIError {
	return &APIError{
		Code:    "AccessDeniedException",
		Message: "User: arn:aws:sts::111111111111:assumed-role/test/session is not authorized to perform: " + action,
		Fault:   smithy.FaultClient,
	}
}

// NotInOrganization returns the error DescribeOrganization returns for a
// standalone account. This is a preflight answer, not a failure (DESIGN §4).
func NotInOrganization() *APIError {
	return &APIError{
		Code:    "AWSOrganizationsNotInUseException",
		Message: "Your account is not a member of an organization.",
		Fault:   smithy.FaultClient,
	}
}

// Throttled returns a throttling error, so tests can confirm automat does not
// report a rate limit as a missing permission.
func Throttled() *APIError {
	return &APIError{
		Code:    "TooManyRequestsException",
		Message: "Rate exceeded",
		Fault:   smithy.FaultClient,
	}
}
