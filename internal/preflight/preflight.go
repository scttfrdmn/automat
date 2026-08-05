// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package preflight classifies the caller's organization and reports what
// automat can and cannot do from where it stands.
//
// Its role in the vend pipeline is to be the gate every other command reads
// first: the three-state machine of DESIGN §4 decides whether `vend` runs
// natively, runs through a broker, or is replaced by an onboarding request.
// Getting the state wrong does not produce a clean failure — it produces a
// half-vended account, so the classification is deliberately conservative and
// every uncertain answer is reported as uncertain rather than assumed.
//
// # What a preflight pass does not mean
//
// iam:SimulatePrincipalPolicy does not evaluate service control policies
// (DESIGN §3, fact 9). From a member account — the state where preflight matters
// most — an SCP attached above the account can deny a call the simulator reports
// as allowed, and automat has no way to see it. So a permission check here is
// evidence, not authorization: it reliably tells you that a grant is *missing*,
// and it cannot tell you that a call will *succeed*. Every Check carries that
// distinction in its Certainty field, and Report.String prints the caveat rather
// than burying it in docs, because an operator who reads "allowed" and plans
// around it has been misled by the tool.
package preflight

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// State is the caller's position in an organization (DESIGN §4).
type State string

// The three states. There is no UNKNOWN: a state that cannot be determined is a
// hard error, because every downstream decision branches on it and a
// "probably MANAGEMENT" would be acted on as MANAGEMENT.
const (
	// StateStandalone means the account is not in an organization. It can become
	// the management account of its own org via `automat init`.
	StateStandalone State = "STANDALONE"
	// StateManagement means the caller is the organization's management account.
	StateManagement State = "MANAGEMENT"
	// StateMember means the caller is in an organization but is not the
	// management account. It cannot create accounts or OUs natively
	// (DESIGN §3, facts 1 and 2).
	StateMember State = "MEMBER"
)

// Certainty qualifies a check's result.
//
// The three values exist because AWS gives automat three genuinely different
// kinds of answer, and collapsing them into pass/fail is how a report starts
// lying: an SCP-shadowed "allowed" and an observed success are not the same
// claim.
type Certainty string

const (
	// Observed means automat saw the actual state — a successful API call, a
	// role it assumed, a value it read.
	Observed Certainty = "observed"
	// Simulated means iam:SimulatePrincipalPolicy answered. A simulated allow
	// does not account for SCPs; a simulated deny is reliable.
	Simulated Certainty = "simulated"
	// Undetermined means automat could not find out — usually because it lacks
	// permission to check, which is itself worth reporting.
	Undetermined Certainty = "undetermined"
)

// Result is a check's outcome.
type Result string

const (
	// Pass means the capability is present.
	Pass Result = "pass"
	// Fail means it is absent, and Check.Grant says what would fix it.
	Fail Result = "fail"
	// Unknown means the check could not be completed.
	Unknown Result = "unknown"
)

// Check is one thing preflight looked at.
type Check struct {
	// Name is a short label, e.g. "vendor role assumable".
	Name string
	// Result is pass, fail, or unknown.
	Result Result
	// Certainty says how much the result is worth.
	Certainty Certainty
	// Detail explains the finding in one line.
	Detail string
	// Grant is the remediation: what to grant, and who must grant it. Required
	// on every Fail (CLAUDE.md rule 7); enforced by a test.
	Grant string
}

// Report is preflight's whole answer.
type Report struct {
	// State is the classification. Everything else qualifies it.
	State State
	// AccountID and CallerARN identify who automat is speaking as.
	AccountID string
	CallerARN string

	// OrgID, ManagementAccountID, FeatureSet describe the organization; empty in
	// STANDALONE.
	OrgID               string
	ManagementAccountID string
	FeatureSet          string

	// TargetOU is the configured OU, and OUFound whether automat could confirm
	// it exists. A member account often cannot describe an OU it is allowed to
	// move accounts into, so "not found" here is not proof of absence.
	TargetOU string
	OUFound  Result

	// VendorRoleARN is the configured broker role, and VendorRoleAssumable
	// whether automat actually assumed it. This one is always Observed: automat
	// tries the assumption rather than simulating it, because it is the single
	// check that decides between a brokered vend and an onboarding request, and
	// a simulated answer would be shadowed by exactly the SCPs that matter.
	VendorRoleARN        string
	VendorRoleAssumable  Result
	VendorRoleExternalID bool

	// AccountQuota is the accounts-per-organization service quota, and
	// AccountQuotaKnown whether automat could read it.
	AccountQuota      float64
	AccountQuotaKnown bool

	// DelegationVisible reports whether automat could read the org's delegation
	// policy. In MEMBER state this is usually Unknown — see DESIGN §16, still an
	// open question pending live testing.
	DelegationVisible Result

	// Checks are the individual findings, in the order they were made.
	Checks []Check

	// CanVend is the bottom line: whether a vend can proceed from here, and
	// CanVendVia how.
	CanVend    bool
	CanVendVia string
}

// Add appends a check.
func (r *Report) Add(c Check) { r.Checks = append(r.Checks, c) }

// Failures returns the checks that failed, for a caller that wants to print only
// what needs fixing.
func (r *Report) Failures() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Result == Fail {
			out = append(out, c)
		}
	}
	return out
}

// Runner performs preflight. Every field is an interface so this runs entirely
// against fakes (CLAUDE.md rule 1).
type Runner struct {
	STS   awsapi.STSAPI
	Org   awsapi.OrgAPI
	IAM   awsapi.IAMAPI
	Quota awsapi.QuotaAPI

	// TargetOU, VendorRoleARN, ExternalID come from configuration. ExternalID is
	// a resolved live value: it is used and dropped, never stored in the Report.
	TargetOU      string
	VendorRoleARN string
	ExternalID    string

	// ExpectOrg, when set, is the organization id the config claims. A mismatch
	// is a hard error: it means the credentials in this shell belong to a
	// different organization than the config describes, and continuing would
	// apply one org's plan to another.
	ExpectOrg string
}

// The accounts-per-organization quota. Codes rather than names because names are
// localized and change; this pair is stable.
const (
	quotaServiceOrganizations = "organizations"
	quotaCodeAccountsPerOrg   = "L-29A0C5DF"
)

// Run classifies the caller and builds the report.
//
// Ordering is deliberate: identify, then classify, then check capabilities. A
// capability check made before the state is known would have to guess which
// remediation to suggest, and the suggestion differs completely between a member
// account (ask central IT) and a management account (fix your own policy).
func (r *Runner) Run(ctx context.Context) (*Report, error) {
	rep := &Report{}

	ident, err := r.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		// No identity means no classification, and every later check would be
		// nonsense. This is the one unrecoverable preflight failure.
		return nil, awsapi.Denied(err, "sts:GetCallerIdentity", "", "",
			"run `automat login`, or set AWS_PROFILE to a profile with valid credentials; "+
				"automat cannot classify an organization without knowing which account it is calling as")
	}
	rep.AccountID = aws.ToString(ident.Account)
	rep.CallerARN = aws.ToString(ident.Arn)

	if err := r.classify(ctx, rep); err != nil {
		return nil, err
	}

	r.checkFeatureSet(rep)
	r.checkTargetOU(ctx, rep)
	r.checkVendorRole(ctx, rep)
	r.checkDelegationVisibility(ctx, rep)
	r.checkQuota(ctx, rep)
	r.checkPermissions(ctx, rep)
	r.decide(rep)

	return rep, nil
}

// classify determines the state from DescribeOrganization plus the caller's
// account id.
func (r *Runner) classify(ctx context.Context, rep *Report) error {
	out, err := r.Org.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	switch {
	case err == nil:
		// fall through
	case awsapi.IsNotInOrganization(err):
		rep.State = StateStandalone
		rep.Add(Check{
			Name: "organization", Result: Pass, Certainty: Observed,
			Detail: "account " + rep.AccountID + " is not in an organization, so it can create its own",
		})
		return nil
	case awsapi.IsAccessDenied(err):
		// Denied is not the same as standalone, and guessing either way is
		// unsafe: treating it as STANDALONE would offer `init` to an account
		// already in an org, and CreateOrganization would fail — or worse, an
		// operator would go looking for why their org "disappeared".
		return awsapi.Denied(err, "organizations:DescribeOrganization", "", rep.CallerARN,
			"grant organizations:DescribeOrganization to "+rep.CallerARN+"; automat cannot tell a "+
				"standalone account from a member account without it, and the two need opposite advice")
	default:
		return fmt.Errorf("describe organization: %w", err)
	}

	org := out.Organization
	if org == nil {
		return errors.New("describe organization: the API returned no organization and no error")
	}
	rep.OrgID = aws.ToString(org.Id)
	rep.ManagementAccountID = aws.ToString(org.MasterAccountId)
	rep.FeatureSet = string(org.FeatureSet)

	if r.ExpectOrg != "" && r.ExpectOrg != rep.OrgID {
		return fmt.Errorf("the configured context names organization %s but these credentials are in %s — "+
			"refusing to continue, because a plan written for one organization must not be applied to "+
			"another; select the right context with --context, or correct `org` in the config file",
			r.ExpectOrg, rep.OrgID)
	}

	if rep.AccountID == rep.ManagementAccountID {
		rep.State = StateManagement
		rep.Add(Check{
			Name: "organization", Result: Pass, Certainty: Observed,
			Detail: "account " + rep.AccountID + " is the management account of " + rep.OrgID,
		})
		return nil
	}
	rep.State = StateMember
	rep.Add(Check{
		Name: "organization", Result: Pass, Certainty: Observed,
		Detail: "account " + rep.AccountID + " is a member of " + rep.OrgID +
			", managed by " + rep.ManagementAccountID,
	})
	return nil
}

// checkFeatureSet reports whether SCPs can be used at all.
//
// A consolidated-billing-only org cannot attach SCPs (DESIGN §3, fact 8), which
// means every preventive control in every catalog is inert. That is not a
// warning: it invalidates the tool's central claim for that org, so it is
// reported as a failure even though nothing has been attempted yet.
func (r *Runner) checkFeatureSet(rep *Report) {
	if rep.State == StateStandalone {
		rep.Add(Check{
			Name: "feature set", Result: Pass, Certainty: Observed,
			Detail: "no organization yet; `automat init` creates one with FeatureSet=ALL",
		})
		return
	}
	if rep.FeatureSet == string(orgtypes.OrganizationFeatureSetAll) {
		rep.Add(Check{
			Name: "feature set", Result: Pass, Certainty: Observed,
			Detail: "ALL — service control policies can be attached",
		})
		return
	}
	rep.Add(Check{
		Name: "feature set", Result: Fail, Certainty: Observed,
		Detail: "the organization is " + rep.FeatureSet + ", so service control policies cannot be " +
			"attached and every preventive control would be inert",
		Grant: "the management account must enable all features " +
			"(Organizations console, or organizations:EnableAllFeatures); until then automat can " +
			"deploy detective controls but cannot enforce a single preventive one",
	})
}

// checkTargetOU confirms the configured OU exists.
//
// A member account is frequently denied DescribeOrganizationalUnit for an OU it
// is nonetheless allowed to move accounts into, so a denial here is Undetermined
// rather than Fail — reporting "your OU does not exist" to someone whose OU
// exists would send them to central IT with a false problem.
func (r *Runner) checkTargetOU(ctx context.Context, rep *Report) {
	if r.TargetOU == "" {
		rep.OUFound = Unknown
		rep.Add(Check{
			Name: "target OU", Result: Unknown, Certainty: Undetermined,
			Detail: "no target OU configured",
			Grant: "set `ou` in the config file, or pass --ou; vending needs a destination OU because " +
				"a new account always lands under the root first and must be moved (DESIGN §3, fact 4)",
		})
		return
	}
	rep.TargetOU = r.TargetOU
	_, err := r.Org.DescribeOrganizationalUnit(ctx, &organizations.DescribeOrganizationalUnitInput{
		OrganizationalUnitId: aws.String(r.TargetOU),
	})
	switch {
	case err == nil:
		rep.OUFound = Pass
		rep.Add(Check{
			Name: "target OU", Result: Pass, Certainty: Observed,
			Detail: r.TargetOU + " exists",
		})
	case awsapi.IsAccessDenied(err):
		rep.OUFound = Unknown
		rep.Add(Check{
			Name: "target OU", Result: Unknown, Certainty: Undetermined,
			Detail: "not permitted to describe " + r.TargetOU + ", which does not mean it is absent — " +
				"a member account is often allowed to move accounts into an OU it cannot read",
			Grant: "optional: ask for organizations:DescribeOrganizationalUnit on " + r.TargetOU +
				" so automat can confirm the destination before vending rather than during",
		})
	case awsapi.APIErrorCode(err) == "OrganizationalUnitNotFoundException":
		rep.OUFound = Fail
		rep.Add(Check{
			Name: "target OU", Result: Fail, Certainty: Observed,
			Detail: "no OU with id " + r.TargetOU + " exists in " + rep.OrgID,
			Grant: "correct `ou` in the config file, or ask central IT to create the OU and send you " +
				"its id; see the ou.md file in the onboarding bundle",
		})
	default:
		rep.OUFound = Unknown
		rep.Add(Check{
			Name: "target OU", Result: Unknown, Certainty: Undetermined,
			Detail: "could not check " + r.TargetOU + ": " + err.Error(),
			Grant:  "retry; if this persists it is an AWS-side error rather than a missing grant",
		})
	}
}

// checkVendorRole tries the assumption rather than simulating it.
//
// This is the check that decides between a brokered vend and an onboarding
// request, so it must be Observed. Simulation would be worthless here twice
// over: it does not evaluate SCPs, and it does not evaluate the role's trust
// policy — which is where the ExternalId requirement lives, and the most likely
// thing to be wrong.
func (r *Runner) checkVendorRole(ctx context.Context, rep *Report) {
	if r.VendorRoleARN == "" {
		rep.VendorRoleAssumable = Unknown
		detail := "no vendor role configured"
		grant := "not needed in this state: this account can call organizations:CreateAccount directly"
		if rep.State == StateMember {
			detail = "no vendor role configured, and a member account cannot create accounts natively " +
				"(DESIGN §3, fact 1)"
			grant = "run `automat setup --request` to generate the onboarding bundle, and send it to " +
				"whoever operates the management account"
		}
		rep.Add(Check{
			Name: "vendor role", Result: Unknown, Certainty: Undetermined, Detail: detail, Grant: grant,
		})
		return
	}
	rep.VendorRoleARN = r.VendorRoleARN
	rep.VendorRoleExternalID = r.ExternalID != ""

	in := &sts.AssumeRoleInput{
		RoleArn:         aws.String(r.VendorRoleARN),
		RoleSessionName: aws.String("automat-preflight"),
	}
	if r.ExternalID != "" {
		in.ExternalId = aws.String(r.ExternalID)
	}
	_, err := r.STS.AssumeRole(ctx, in)
	switch {
	case err == nil:
		rep.VendorRoleAssumable = Pass
		detail := "assumed " + r.VendorRoleARN
		if r.ExternalID == "" {
			detail += " without an ExternalId"
		} else {
			detail += " with an ExternalId"
		}
		rep.Add(Check{
			Name: "vendor role", Result: Pass, Certainty: Observed, Detail: detail,
		})
		if r.ExternalID == "" {
			// Assumable without an ExternalId is a working configuration and a
			// weak one: any account that learns the role ARN can assume it. Not
			// a Fail, because the vend will work; reported because central IT
			// approved this role on the understanding that it was constrained.
			rep.Add(Check{
				Name: "vendor role ExternalId", Result: Fail, Certainty: Observed,
				Detail: "the role assumed without an ExternalId, so its trust policy does not require " +
					"one — anyone who learns the role ARN can assume it",
				Grant: "ask the management account to add a sts:ExternalId condition to the role's " +
					"trust policy, then set external_id_ref in the config; the vendor-role templates " +
					"in the onboarding bundle include the condition",
			})
		}
	case awsapi.IsAccessDenied(err):
		rep.VendorRoleAssumable = Fail
		detail := "cannot assume " + r.VendorRoleARN
		if r.ExternalID == "" {
			detail += "; no ExternalId was sent, and the role may require one"
		} else {
			detail += " even with an ExternalId; AWS does not say which of the trust policy, the " +
				"ExternalId, or the caller's permissions was wrong"
		}
		rep.Add(Check{
			Name: "vendor role", Result: Fail, Certainty: Observed, Detail: detail,
			Grant: "the management account must (1) trust " + rep.CallerARN + " in the role's trust " +
				"policy and (2) require the same sts:ExternalId you have configured; " +
				"`automat setup --request` emits both, ready to apply",
		})
	default:
		rep.VendorRoleAssumable = Unknown
		rep.Add(Check{
			Name: "vendor role", Result: Unknown, Certainty: Undetermined,
			Detail: "could not assume " + r.VendorRoleARN + ": " + err.Error(),
			Grant:  "retry; this is an error from STS rather than a denial",
		})
	}
}

// checkDelegationVisibility reports whether the delegation policy can be read.
//
// Whether a member account can see the resource policy that grants it is an open
// question pending live testing (DESIGN §16), so this check is written to be
// honest about not knowing. It never reports Fail: "I cannot see your delegation"
// is not evidence that you lack one, and a preflight that claimed otherwise would
// send operators to central IT to re-grant something they already have.
func (r *Runner) checkDelegationVisibility(ctx context.Context, rep *Report) {
	if rep.State == StateStandalone {
		rep.DelegationVisible = Unknown
		return
	}
	_, err := r.Org.DescribeResourcePolicy(ctx, &organizations.DescribeResourcePolicyInput{})
	switch {
	case err == nil:
		rep.DelegationVisible = Pass
		rep.Add(Check{
			Name: "delegation policy", Result: Pass, Certainty: Observed,
			Detail: "the organization has a resource policy and this account can read it",
		})
	case awsapi.APIErrorCode(err) == "ResourcePolicyNotFoundException":
		rep.DelegationVisible = Fail
		detail := "the organization has no resource policy, so no policy management is delegated"
		grant := "not needed in this state: the management account manages policies directly"
		if rep.State == StateMember {
			grant = "the management account must attach a delegation policy scoped to your OU subtree; " +
				"delegation-policy.json in the onboarding bundle is the statement to apply"
		}
		rep.Add(Check{
			Name: "delegation policy", Result: Fail, Certainty: Observed, Detail: detail, Grant: grant,
		})
	case awsapi.IsAccessDenied(err):
		rep.DelegationVisible = Unknown
		rep.Add(Check{
			Name: "delegation policy", Result: Unknown, Certainty: Undetermined,
			Detail: "not permitted to read the organization's resource policy, which says nothing about " +
				"whether one grants this account — automat cannot confirm a delegation it cannot read",
			Grant: "optional: ask for organizations:DescribeResourcePolicy so preflight can confirm the " +
				"delegation instead of discovering its absence during a vend",
		})
	default:
		rep.DelegationVisible = Unknown
		rep.Add(Check{
			Name: "delegation policy", Result: Unknown, Certainty: Undetermined,
			Detail: "could not read the organization's resource policy: " + err.Error(),
			Grant:  "retry; this is an error from Organizations rather than a denial",
		})
	}
}

// checkQuota reads the accounts-per-organization quota.
//
// Reported because the default is low and raising it is a support request with
// lead time (DESIGN §3, fact 11) — a fact worth learning while planning rather
// than three accounts into a vend. An unreadable quota stays unknown; inventing
// the documented default would be a confident wrong number.
func (r *Runner) checkQuota(ctx context.Context, rep *Report) {
	if r.Quota == nil {
		return
	}
	out, err := r.Quota.GetServiceQuota(ctx, &servicequotas.GetServiceQuotaInput{
		ServiceCode: aws.String(quotaServiceOrganizations),
		QuotaCode:   aws.String(quotaCodeAccountsPerOrg),
	})
	if err != nil {
		rep.Add(Check{
			Name: "accounts-per-organization quota", Result: Unknown, Certainty: Undetermined,
			Detail: "could not read the quota: " + err.Error(),
			Grant: "optional: grant servicequotas:GetServiceQuota so automat can warn you before a vend " +
				"hits the account limit; the default limit is low and raising it takes a support request",
		})
		return
	}
	if out.Quota == nil || out.Quota.Value == nil {
		rep.Add(Check{
			Name: "accounts-per-organization quota", Result: Unknown, Certainty: Undetermined,
			Detail: "the quota API returned no value",
			Grant:  "retry; if this persists, check the quota in the Service Quotas console",
		})
		return
	}
	rep.AccountQuota = *out.Quota.Value
	rep.AccountQuotaKnown = true
	rep.Add(Check{
		Name: "accounts-per-organization quota", Result: Pass, Certainty: Observed,
		Detail: fmt.Sprintf("%.0f accounts; raising it is a Service Quotas request with lead time",
			rep.AccountQuota),
	})
}

// vendActions are the Organizations actions a vend needs, paired with which
// half of the delegation model provides them (DESIGN §5).
var vendActions = []struct {
	action string
	half   string
}{
	{"organizations:CreateAccount", "brokered role (not delegable — DESIGN §3, fact 1)"},
	{"organizations:MoveAccount", "brokered role, scoped to the target OU as destination"},
	{"organizations:CreateOrganizationalUnit", "brokered role (not delegable — DESIGN §3, fact 2)"},
	{"organizations:CreatePolicy", "delegation policy"},
	{"organizations:AttachPolicy", "delegation policy, scoped to the target OU subtree"},
}

// checkPermissions simulates the actions a vend needs.
//
// Every result is marked Simulated, and the report's caveat explains what that
// is worth. The asymmetry is the whole point: a simulated deny means the grant is
// genuinely missing and is worth acting on, while a simulated allow means only
// that the caller's identity policies do not object — an SCP above the account
// can still deny it, invisibly (DESIGN §3, fact 9).
func (r *Runner) checkPermissions(ctx context.Context, rep *Report) {
	if r.IAM == nil || rep.CallerARN == "" {
		return
	}
	actions := make([]string, 0, len(vendActions))
	for _, a := range vendActions {
		actions = append(actions, a.action)
	}
	out, err := r.IAM.SimulatePrincipalPolicy(ctx, &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(rep.CallerARN),
		ActionNames:     actions,
	})
	if err != nil {
		// Being unable to simulate is common and not itself a problem: it means
		// preflight is less informative, not that the vend will fail.
		rep.Add(Check{
			Name: "permission simulation", Result: Unknown, Certainty: Undetermined,
			Detail: "could not simulate the vend actions: " + err.Error(),
			Grant: "optional: grant iam:SimulatePrincipalPolicy so preflight can name missing grants " +
				"before a vend instead of failing partway through one",
		})
		return
	}

	provider := map[string]string{}
	for _, a := range vendActions {
		provider[a.action] = a.half
	}
	for _, res := range out.EvaluationResults {
		action := aws.ToString(res.EvalActionName)
		allowed := res.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed
		c := Check{Name: action, Certainty: Simulated}
		if allowed {
			c.Result = Pass
			c.Detail = "the caller's identity policies allow it; an SCP above this account could still deny it"
		} else {
			c.Result = Fail
			c.Detail = "the caller's identity policies do not allow it (" + string(res.EvalDecision) + ")"
			c.Grant = grantFor(action, provider[action], rep)
		}
		rep.Add(c)
	}
}

// grantFor writes the remediation sentence for a missing action, naming who must
// act — which differs entirely by state, and is the part operators actually need.
func grantFor(action, half string, rep *Report) string {
	switch rep.State {
	case StateMember:
		return "in MEMBER state this comes from the " + half + "; run `automat setup --request` and " +
			"send the bundle to whoever operates management account " + rep.ManagementAccountID
	case StateManagement:
		return "grant " + action + " to " + rep.CallerARN +
			"; you are in the management account, so this is your own identity policy to fix"
	default:
		return "grant " + action + " to " + rep.CallerARN +
			"; after `automat init` this account will be its own management account"
	}
}

// decide sets the bottom line.
//
// It fails closed: anything short of a positively established path is "cannot
// vend". An optimistic reading here would produce the half-vended account the
// whole state machine exists to prevent — an account created, sitting in the
// root, with no controls attached.
func (r *Runner) decide(rep *Report) {
	// A CONSOLIDATED_BILLING org can never enforce a preventive control, so
	// vending into it would produce accounts automat cannot claim are compliant.
	if rep.State != StateStandalone && rep.FeatureSet != string(orgtypes.OrganizationFeatureSetAll) {
		rep.CanVend = false
		rep.CanVendVia = "blocked: the organization is " + rep.FeatureSet +
			", so no service control policy can be attached"
		return
	}

	switch rep.State {
	case StateStandalone:
		rep.CanVend = false
		rep.CanVendVia = "not yet: run `automat init` to create an organization with all features " +
			"enabled, then vend directly"
	case StateManagement:
		rep.CanVend = true
		rep.CanVendVia = "directly, using this account's own credentials"
	case StateMember:
		if rep.VendorRoleAssumable == Pass {
			rep.CanVend = true
			rep.CanVendVia = "through the vendor role " + rep.VendorRoleARN +
				" for account creation, with this account's delegated credentials for policies"
			return
		}
		rep.CanVend = false
		rep.CanVendVia = "not yet: a member account cannot create accounts natively, and the vendor " +
			"role is not assumable — run `automat setup --request` to generate the onboarding bundle"
	}
}

// String renders the report for a terminal.
//
// The SCP caveat is printed whenever any check is Simulated, in the body of the
// report rather than as a footnote, because a reader who acts on a simulated
// allow without knowing what it excludes has been misled by this tool.
func (r *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "state:    %s\n", r.State)
	fmt.Fprintf(&b, "account:  %s\n", r.AccountID)
	fmt.Fprintf(&b, "caller:   %s\n", r.CallerARN)
	if r.OrgID != "" {
		fmt.Fprintf(&b, "org:      %s (management %s, feature set %s)\n",
			r.OrgID, r.ManagementAccountID, r.FeatureSet)
	}
	b.WriteString("\nchecks:\n")

	var simulated bool
	for _, c := range r.Checks {
		if c.Certainty == Simulated {
			simulated = true
		}
		fmt.Fprintf(&b, "  [%-7s] %s (%s)\n", c.Result, c.Name, c.Certainty)
		if c.Detail != "" {
			fmt.Fprintf(&b, "            %s\n", c.Detail)
		}
		if c.Grant != "" {
			fmt.Fprintf(&b, "            to fix: %s\n", c.Grant)
		}
	}

	if simulated {
		b.WriteString("\nOn simulated results: iam:SimulatePrincipalPolicy does not evaluate service\n" +
			"control policies. A simulated denial is reliable — the grant really is missing. A\n" +
			"simulated allow only means the caller's identity policies permit the call; an SCP\n" +
			"attached above this account can still deny it, and automat cannot see that from here.\n")
	}

	b.WriteString("\nvend: ")
	if r.CanVend {
		b.WriteString("yes — " + r.CanVendVia + "\n")
	} else {
		b.WriteString("no — " + r.CanVendVia + "\n")
	}
	return b.String()
}
