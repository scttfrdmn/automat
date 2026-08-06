// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// Mode is the plan/apply split (CLAUDE.md rule 5).
type Mode string

const (
	// ModePlan reads the organization and reports what would change. No
	// operation issues a mutating call in this mode, which
	// TestPlanTouchesNothing checks against the fakes' call log.
	ModePlan Mode = "plan"
	// ModeApply reads and then writes.
	ModeApply Mode = "apply"
)

// Verb is what an operation did, or would do.
type Verb string

const (
	// VerbUnchanged means the desired state was already true. This is the verb a
	// second run of every operation must produce; it is the observable form of
	// CLAUDE.md rule 4.
	VerbUnchanged Verb = "unchanged"
	// VerbCreate means something was brought into existence.
	VerbCreate Verb = "create"
	// VerbUpdate means an existing thing's content was changed.
	VerbUpdate Verb = "update"
	// VerbMove means an account changed parent.
	VerbMove Verb = "move"
	// VerbAttach means a policy was attached to a target.
	VerbAttach Verb = "attach"
	// VerbTag means tags were written.
	VerbTag Verb = "tag"
	// VerbEnable means an organization-level setting was turned on.
	VerbEnable Verb = "enable"
	// VerbWait means an asynchronous operation is still in flight. Only
	// EnsureAccount produces it, and only in ModePlan: an apply waits.
	VerbWait Verb = "wait"
	// VerbUnknown means a plan could not determine the current state, because
	// reading it depends on something the plan would have had to create first.
	// Reported rather than guessed — a plan that invents an id is a plan an
	// operator will compare against reality and disbelieve.
	VerbUnknown Verb = "unknown"
)

// Action is one operation's outcome, in plan or apply.
//
// The same type for both halves of the split on purpose: a plan that is a
// different shape from the apply it predicts is a plan nobody can diff against
// what happened. `vend` records these into the evidence manifest, so the fields
// are what a reader of the manifest needs rather than what was convenient.
type Action struct {
	// Verb is what happened, or would.
	Verb Verb
	// Kind is the sort of thing acted on, in the words an operator uses:
	// "organizational unit", "account placement", "service control policy".
	Kind string
	// Name identifies the thing by the name automat chose for it. Empty when the
	// thing has no name (an account placement).
	Name string
	// ID is the AWS id. EMPTY for a planned creation, because a plan cannot know
	// the id of something that does not exist; see the package doc.
	ID string
	// Target is what the action was against: the parent OU for a create, the
	// destination for a move, the attachment target for an attach.
	Target string
	// Detail is one line of explanation, including where a value came from when
	// that is the interesting part ("already under ou-exam-1", "content differs
	// from the compiled artifact").
	Detail string
	// Applied distinguishes a real change from a predicted one. False for every
	// action produced in ModePlan, and false for VerbUnchanged in either mode:
	// nothing was written, so nothing was applied.
	Applied bool
}

func (a Action) String() string {
	var b strings.Builder
	b.WriteString(string(a.Verb))
	b.WriteString(" ")
	b.WriteString(a.Kind)
	if a.Name != "" {
		fmt.Fprintf(&b, " %q", a.Name)
	}
	if a.ID != "" {
		b.WriteString(" (")
		b.WriteString(a.ID)
		b.WriteString(")")
	}
	if a.Target != "" {
		b.WriteString(" -> ")
		b.WriteString(a.Target)
	}
	if a.Detail != "" {
		b.WriteString(": ")
		b.WriteString(a.Detail)
	}
	return b.String()
}

// Credential says which instrument carries these calls, and it exists only to
// make remediation text correct.
//
// CLAUDE.md rule 7 asks what grant would fix a denial. The answer is a different
// sentence in each state and the two go to different people: in MANAGEMENT the
// operator edits their own identity policy, and in MEMBER they email central IT
// to widen a role or a delegation policy they cannot see. A single generic
// message would send half the users to the wrong place, which is the failure the
// rule exists to prevent.
type Credential string

const (
	// Native means the caller's own credentials in the management account
	// (DESIGN §4, MANAGEMENT).
	Native Credential = "native"
	// Brokered means the vendor role plus the delegation policy (DESIGN §5,
	// MEMBER).
	Brokered Credential = "brokered"
)

// OwnerTagKey and OwnerTagValue mark a resource as automat's (DESIGN §14).
//
// Load-bearing beyond bookkeeping: no ARN pattern separates automat's service
// control policies from central IT's — `policy/<org>/service_control_policy/*`
// matches all of them — so the delegation policy gates update, attach, and tag
// on this exact tag (internal/bundle's scpModifyActions). Every policy automat
// creates carries it at creation, through the request tag; a policy that lacks
// it is not automat's, and EnsurePolicy refuses to adopt one by tagging it.
const (
	OwnerTagKey   = "automat:managed-by"
	OwnerTagValue = "automat"
)

// tagNamespace bounds every tag key automat writes.
//
// The same bound the delegation policy places with aws:TagKeys. Writing outside
// it would be refused in the MEMBER state anyway, but refusing here means the
// MANAGEMENT path — where nothing stops it — cannot do something the MEMBER path
// cannot, and the two states stay comparable.
const tagNamespace = "automat:"

// MaxOUDepth is the OU nesting limit below the root (DESIGN §3, fact 10).
const MaxOUDepth = 5

// listPageCap bounds every pagination loop.
//
// Not a quota: a stop against a service that returns the same NextToken forever,
// or a fake with a paging bug. An ensure operation that hangs during a vend is
// worse than one that fails, because the account already exists and the operator
// has no record of how far it got. The loops also refuse a repeated token, which
// catches the same fault one page earlier.
const listPageCap = 500

// Ensurer performs the Organizations half of a vend.
//
// The three API fields mirror the three-way interface split in
// internal/awsapi: in the MEMBER state Vend and Policy are backed by DIFFERENT
// CLIENTS on different credentials, so they are separate fields rather than one.
// Init is only used by `automat init` and is nil elsewhere.
type Ensurer struct {
	// Vend carries account and OU operations.
	Vend awsapi.OrgVendAPI
	// Policy carries service control policy operations.
	Policy awsapi.OrgPolicyAPI
	// Init carries `automat init`, and is nil for every other command.
	Init awsapi.OrgInitAPI

	// Mode is plan or apply. The zero value is ModePlan, deliberately: a
	// forgotten field must not mutate an organization.
	Mode Mode
	// Credential selects the remediation wording. The zero value is Native.
	Credential Credential
	// Principal is the identity automat is speaking as, for error text.
	Principal string

	// PollInterval and MaxPolls bound the wait for asynchronous account
	// creation. Zero means the defaults below.
	PollInterval time.Duration
	MaxPolls     int

	// Sleep is how the poll loop waits. Injected so tests do not, and so a
	// cancelled context ends a vend promptly rather than after the current
	// interval. Nil means a context-aware sleep.
	Sleep func(context.Context, time.Duration) error

	// actions accumulates every Action this Ensurer produced, in order, for the
	// plan printout and the evidence record.
	actions []Action
}

// Default poll bounds: five minutes of five-second polls. Account creation
// normally completes in well under a minute; the ceiling is generous because
// giving up early on a create that then succeeds leaves an account nobody
// recorded, which is the expensive failure.
const (
	defaultPollInterval = 5 * time.Second
	defaultMaxPolls     = 60
)

// Actions returns every action produced so far, in order.
func (e *Ensurer) Actions() []Action { return append([]Action(nil), e.actions...) }

// Changed reports whether any action wrote anything. The "run twice = no diff"
// acceptance criterion for Phase 2 is exactly !Changed() on the second run.
func (e *Ensurer) Changed() bool {
	for _, a := range e.actions {
		if a.Applied {
			return true
		}
	}
	return false
}

// ResetActions clears the log, for the second half of a run-twice check.
func (e *Ensurer) ResetActions() { e.actions = nil }

// planning reports whether writes are suppressed.
func (e *Ensurer) planning() bool { return e.Mode != ModeApply }

// record appends an action and returns a pointer to it.
func (e *Ensurer) record(a Action) *Action {
	e.actions = append(e.actions, a)
	return &e.actions[len(e.actions)-1]
}

// RecordUnknown notes a step a plan could not check, so the plan still lists it.
//
// The exported counterpart of what EnsureOUPath does per level when a parent it
// would create does not exist yet: once a plan's first step is a creation,
// nothing below it can be read, and the honest report is "cannot be checked"
// rather than either silence or a guess. `automat init` needs it because its
// first step may be creating the organization itself, after which the root, the
// policy type, and the OU are all unreadable — and a plan that simply omitted
// them would show one line for a command that does three things.
//
// Only ever VerbUnknown, and Applied is therefore always false: this records the
// absence of knowledge, so there is no mode in which it may claim a change.
func (e *Ensurer) RecordUnknown(kind, detail string) *Action {
	return e.record(Action{Verb: VerbUnknown, Kind: kind, Detail: detail})
}

func (e *Ensurer) pollInterval() time.Duration {
	if e.PollInterval > 0 {
		return e.PollInterval
	}
	return defaultPollInterval
}

func (e *Ensurer) maxPolls() int {
	if e.MaxPolls > 0 {
		return e.MaxPolls
	}
	return defaultMaxPolls
}

func (e *Ensurer) sleep(ctx context.Context, d time.Duration) error {
	if e.Sleep != nil {
		return e.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// denied wraps an authorization failure with the remediation for this
// credential, and returns anything else unchanged.
//
// The grant sentence is assembled here rather than at each call site so that
// adding an operation cannot produce a denial with no remediation — the only
// input is the action and the resource, and both are always known.
func (e *Ensurer) denied(err error, action, resource string) error {
	if err == nil || !awsapi.IsAccessDenied(err) {
		return err
	}
	var grant string
	switch e.Credential {
	case Brokered:
		switch {
		case strings.HasPrefix(action, "organizations:Create") && strings.Contains(action, "Policy"),
			strings.HasPrefix(action, "organizations:Update"),
			strings.HasPrefix(action, "organizations:Attach"),
			action == "organizations:TagResource" && strings.HasPrefix(resource, "p-"):
			grant = "ask the organization's management account to add " + action + " on " + resource +
				" to the delegation policy it applied for this account — the file is " +
				"delegation-policy.json in the onboarding bundle (`automat setup --request`), and " +
				"policy operations travel through that document rather than through the vendor role"
		default:
			grant = "ask the organization's management account to add " + action + " on " + resource +
				" to the vendor role this account assumes — the file is vendor-role.cfn.yaml (or " +
				"vendor-role.tf) in the onboarding bundle (`automat setup --request`); account and OU " +
				"operations cannot be delegated to a member account and must travel through that role"
		}
	default:
		grant = "grant " + action + " on " + resource + " to " + principalOr(e.Principal, "the calling identity") +
			" in the management account; automat is running natively rather than through a broker, so " +
			"this is your own identity policy rather than a delegation somebody else owns"
	}
	return awsapi.Denied(err, action, resource, e.Principal, grant)
}

func principalOr(p, fallback string) string {
	if p == "" {
		return fallback
	}
	return p
}

// Parkable reports whether err leaves the organization mid-change, so that
// `vend` must record a resumable parked state rather than exiting.
//
// ROADMAP Phase 2 states this as an ordering requirement rather than an
// error-handling preference: the account exists from the create onward, so
// exiting non-zero without recording it strands a real AWS account with no OU,
// no policies, and nothing in the manifest pointing at it. The four failures
// named there are exactly the four below, and each is recoverable by
// `vend --resume <request-id>` once the cause is fixed — and none is recoverable
// by re-running `vend` from the top, which would try to create a second account.
//
// Deliberately not "every error": a throttle or a network failure is a retry,
// not a state, and treating it as a parked state would fill an operator's
// inventory with accounts that are fine.
func Parkable(err error) bool {
	if err == nil {
		return false
	}
	if awsapi.IsAccessDenied(err) {
		return true
	}
	switch awsapi.APIErrorCode(err) {
	case "MalformedPolicyDocumentException", "PolicyTypeNotEnabledException":
		return true
	}
	var cv *orgtypes.ConstraintViolationException
	if errors.As(err, &cv) {
		switch cv.Reason {
		case orgtypes.ConstraintViolationExceptionReasonMaxPolicyTypeAttachmentLimitExceeded,
			orgtypes.ConstraintViolationExceptionReasonPolicyContentLimitExceeded,
			orgtypes.ConstraintViolationExceptionReasonPolicyNumberLimitExceeded,
			orgtypes.ConstraintViolationExceptionReasonOuNumberLimitExceeded,
			orgtypes.ConstraintViolationExceptionReasonOuDepthLimitExceeded:
			return true
		}
	}
	return false
}

// isCode reports whether err is the named AWS error code.
func isCode(err error, code string) bool { return awsapi.APIErrorCode(err) == code }

// sameDocument compares two policy documents for equal meaning.
//
// Not a byte comparison, and the difference decides whether automat is
// idempotent. The packer emits canonical bytes, but nothing documents that
// Organizations returns a policy document byte-for-byte as submitted — it may
// normalize whitespace, and it is entitled to. An ensure operation that compared
// bytes would then find a difference on every single run, call UpdatePolicy
// every time, and fail the "run twice = no diff" criterion while looking
// correct. Comparing parsed structure is immune to that, and is strictly
// stronger in the direction that matters: two documents that parse the same ARE
// the same policy to IAM.
//
// Statement ORDER is preserved by this comparison, because encoding/json keeps
// array order and only sorts object keys. That is deliberate: statement order in
// an SCP does not change its meaning, but the packer's order is deterministic
// and a reordering is worth noticing rather than smoothing over.
//
// An unparseable document compares as different, so automat overwrites it. That
// is the right direction: a policy under automat's name that is not valid JSON
// is not enforcing anything, and leaving it in place because it could not be
// read would be the quiet failure.
func sameDocument(a, b string) bool {
	ca, aok := canonicalizeDocument(a)
	cb, bok := canonicalizeDocument(b)
	if !aok || !bok {
		return false
	}
	return ca == cb
}

func canonicalizeDocument(s string) (string, bool) {
	var v any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber() // 1 and 1.0 are not the same policy document
	if err := dec.Decode(&v); err != nil {
		return "", false
	}
	if err := ensureEOF(dec); err != nil {
		return "", false
	}
	out, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	return string(out), true
}

// ensureEOF rejects trailing content after a JSON value: `{...}{...}` parses as
// one document plus junk, and a policy with junk after it is not a policy
// automat should call equal to anything.
func ensureEOF(dec *json.Decoder) error {
	var extra any
	switch err := dec.Decode(&extra); {
	case err == nil:
		return errors.New("trailing content after the JSON document")
	case errors.Is(err, io.EOF):
		return nil
	default:
		return err
	}
}
