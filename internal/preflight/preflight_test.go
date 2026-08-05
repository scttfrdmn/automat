// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/awsfake"
)

const (
	memberAccount     = "222222222222"
	managementAccount = "111111111111"
	testOrg           = "o-exampleorgid"
	testOU            = "ou-exam-research1"
	vendorRole        = "arn:aws:iam::111111111111:role/automat-vendor"
	testExternalID    = "not-a-real-external-id"
)

// allVendActions is every action checkPermissions simulates, for the cases that
// want a caller whose identity policies allow the lot.
func allVendActions() []string {
	out := make([]string, 0, len(vendActions))
	for _, a := range vendActions {
		out = append(out, a.action)
	}
	return out
}

func run(t *testing.T, r *Runner) *Report {
	t.Helper()
	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

func find(t *testing.T, rep *Report, name string) Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q; got %v", name, checkNames(rep))
	return Check{}
}

func checkNames(rep *Report) []string {
	out := make([]string, 0, len(rep.Checks))
	for _, c := range rep.Checks {
		out = append(out, c.Name)
	}
	return out
}

// TestClassifiesTheThreeStates covers the ROADMAP Phase 1 accept criterion:
// all three states plus the "member with vendor role" variant, which is the one
// that decides between a brokered vend and an onboarding request.
func TestClassifiesTheThreeStates(t *testing.T) {
	cases := []struct {
		name        string
		runner      func() *Runner
		wantState   State
		wantCanVend bool
		wantVia     string // substring
	}{
		{
			name: "standalone",
			runner: func() *Runner {
				return &Runner{
					STS:   awsfake.NewSTS(memberAccount),
					Org:   &awsfake.Org{}, // zero value: not in an organization
					IAM:   awsfake.NewIAM(),
					Quota: awsfake.NewQuota(),
				}
			},
			wantState:   StateStandalone,
			wantCanVend: false,
			wantVia:     "automat init",
		},
		{
			name: "management",
			runner: func() *Runner {
				org := awsfake.NewOrg(testOrg, managementAccount).AddOU(testOU, "Research", "r-exam")
				return &Runner{
					STS:      awsfake.NewSTS(managementAccount),
					Org:      org,
					IAM:      awsfake.NewIAM(allVendActions()...),
					Quota:    awsfake.NewQuota(),
					TargetOU: testOU,
				}
			},
			wantState:   StateManagement,
			wantCanVend: true,
			wantVia:     "directly",
		},
		{
			name: "member without a vendor role",
			runner: func() *Runner {
				org := awsfake.NewOrg(testOrg, managementAccount)
				org.Errs["DescribeOrganizationalUnit"] = awsfake.AccessDenied(
					"organizations:DescribeOrganizationalUnit")
				org.ResourcePolicyErr = awsfake.AccessDenied("organizations:DescribeResourcePolicy")
				return &Runner{
					STS:      awsfake.NewSTS(memberAccount),
					Org:      org,
					IAM:      awsfake.NewIAM(),
					Quota:    awsfake.NewQuota(),
					TargetOU: testOU,
				}
			},
			wantState:   StateMember,
			wantCanVend: false,
			wantVia:     "setup --request",
		},
		{
			name: "member with an assumable vendor role",
			runner: func() *Runner {
				org := awsfake.NewOrg(testOrg, managementAccount).AddOU(testOU, "Research", "r-exam")
				org.ResourcePolicy = `{"Version":"2012-10-17","Statement":[]}`
				stsFake := awsfake.NewSTS(memberAccount)
				stsFake.Assumable[vendorRole] = testExternalID
				return &Runner{
					STS:           stsFake,
					Org:           org,
					IAM:           awsfake.NewIAM(allVendActions()...),
					Quota:         awsfake.NewQuota(),
					TargetOU:      testOU,
					VendorRoleARN: vendorRole,
					ExternalID:    testExternalID,
				}
			},
			wantState:   StateMember,
			wantCanVend: true,
			wantVia:     vendorRole,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := run(t, tc.runner())
			if rep.State != tc.wantState {
				t.Errorf("State = %q, want %q", rep.State, tc.wantState)
			}
			if rep.CanVend != tc.wantCanVend {
				t.Errorf("CanVend = %v, want %v (via %q)", rep.CanVend, tc.wantCanVend, rep.CanVendVia)
			}
			if !strings.Contains(rep.CanVendVia, tc.wantVia) {
				t.Errorf("CanVendVia = %q, want it to mention %q", rep.CanVendVia, tc.wantVia)
			}
		})
	}
}

// TestEveryFailureNamesItsRemediation is CLAUDE.md rule 7 as a test: a failing
// check that does not say what would fix it is a bug report addressed to nobody.
func TestEveryFailureNamesItsRemediation(t *testing.T) {
	// A deliberately broken member account: consolidated billing, a missing OU,
	// an unassumable role, no delegation, no permissions, no quota access.
	org := awsfake.NewOrg(testOrg, managementAccount)
	org.FeatureSet = "CONSOLIDATED_BILLING"
	quota := awsfake.NewQuota()
	quota.Err = awsfake.AccessDenied("servicequotas:GetServiceQuota")

	rep := run(t, &Runner{
		STS:           awsfake.NewSTS(memberAccount),
		Org:           org,
		IAM:           awsfake.NewIAM(),
		Quota:         quota,
		TargetOU:      testOU,
		VendorRoleARN: vendorRole,
	})

	var failures int
	for _, c := range rep.Checks {
		if c.Result != Fail {
			continue
		}
		failures++
		if strings.TrimSpace(c.Grant) == "" {
			t.Errorf("check %q failed with no remediation text; CLAUDE.md rule 7 requires one", c.Name)
		}
		if strings.TrimSpace(c.Detail) == "" {
			t.Errorf("check %q failed with no detail", c.Name)
		}
	}
	if failures == 0 {
		t.Fatal("this account was constructed to fail several checks; none did, so the test proves nothing")
	}
	if got := len(rep.Failures()); got != failures {
		t.Errorf("Failures() returned %d checks, but %d failed", got, failures)
	}
}

// TestNoIdentityIsFatal: without a caller identity there is no classification,
// and every later check would be built on a guess.
func TestNoIdentityIsFatal(t *testing.T) {
	stsFake := awsfake.NewSTS(memberAccount)
	stsFake.IdentityErr = awsfake.AccessDenied("sts:GetCallerIdentity")

	_, err := (&Runner{STS: stsFake, Org: awsfake.NewOrg(testOrg, managementAccount)}).
		Run(context.Background())
	if err == nil {
		t.Fatal("expected preflight to refuse to continue without an identity")
	}
	perr, ok := awsapi.AsPermissionError(err)
	if !ok {
		t.Fatalf("want a *awsapi.PermissionError so the remediation is structured, got %T: %v", err, err)
	}
	if !strings.Contains(perr.Grant, "automat login") {
		t.Errorf("remediation %q does not mention how to get credentials", perr.Grant)
	}
}

// TestDeniedDescribeOrganizationIsNotStandalone is the classification trap.
//
// A denial and an absent organization look similar and need opposite advice:
// offering `automat init` to an account that is already a member sends the
// operator to run CreateOrganization, which fails, after which they go looking
// for why their organization "disappeared".
func TestDeniedDescribeOrganizationIsNotStandalone(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount)
	org.Errs["DescribeOrganization"] = awsfake.AccessDenied("organizations:DescribeOrganization")

	rep, err := (&Runner{STS: awsfake.NewSTS(memberAccount), Org: org}).Run(context.Background())
	if err == nil {
		t.Fatalf("a denied DescribeOrganization was classified as %q instead of failing", rep.State)
	}
	if !strings.Contains(err.Error(), "opposite advice") {
		t.Errorf("the error should explain why guessing is unsafe, got: %v", err)
	}
}

// TestThrottlingIsNotReportedAsAMissingPermission: a rate limit is a retry, and
// telling an operator to go ask central IT for a grant they already hold wastes a
// week of somebody's time.
func TestThrottlingIsNotReportedAsAMissingPermission(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount)
	org.Errs["DescribeOrganizationalUnit"] = awsfake.Throttled()
	org.ResourcePolicyErr = awsfake.Throttled()
	quota := awsfake.NewQuota()
	quota.Err = awsfake.Throttled()
	iamFake := awsfake.NewIAM()
	iamFake.Err = awsfake.Throttled()

	rep := run(t, &Runner{
		STS: awsfake.NewSTS(memberAccount), Org: org, IAM: iamFake, Quota: quota,
		TargetOU: testOU,
	})

	for _, name := range []string{"target OU", "delegation policy", "accounts-per-organization quota",
		"permission simulation"} {
		c := find(t, rep, name)
		if c.Result != Unknown || c.Certainty != Undetermined {
			t.Errorf("check %q under throttling: got %s/%s, want unknown/undetermined — "+
				"a rate limit is not a denial", name, c.Result, c.Certainty)
		}
	}
	if got := len(rep.Failures()); got != 0 {
		t.Errorf("throttling produced %d failures: %v", got, rep.Failures())
	}
}

// TestDeniedOUDescribeIsUndeterminedNotAbsent. A member account is routinely
// allowed to move accounts into an OU it may not read, so "I cannot see it" must
// not be printed as "it does not exist".
func TestDeniedOUDescribeIsUndeterminedNotAbsent(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount)
	org.Errs["DescribeOrganizationalUnit"] = awsfake.AccessDenied(
		"organizations:DescribeOrganizationalUnit")

	rep := run(t, &Runner{
		STS: awsfake.NewSTS(memberAccount), Org: org, TargetOU: testOU,
	})
	c := find(t, rep, "target OU")
	if c.Result != Unknown {
		t.Errorf("target OU result = %s, want unknown", c.Result)
	}
	if !strings.Contains(c.Detail, "does not mean it is absent") {
		t.Errorf("detail should say a denial is not an absence, got %q", c.Detail)
	}
	if rep.OUFound == Fail {
		t.Error("OUFound = fail on a denial, which would send the operator to fix a working OU")
	}
}

// TestMissingOUIsReportedAsMissing is the other half: when Organizations says
// the OU does not exist, that *is* an answer and preflight must state it.
func TestMissingOUIsReportedAsMissing(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount) // no OUs registered
	rep := run(t, &Runner{STS: awsfake.NewSTS(managementAccount), Org: org, TargetOU: testOU})

	if rep.OUFound != Fail {
		t.Fatalf("OUFound = %s, want fail", rep.OUFound)
	}
	c := find(t, rep, "target OU")
	if c.Certainty != Observed {
		t.Errorf("certainty = %s, want observed: OrganizationalUnitNotFoundException is a definite answer",
			c.Certainty)
	}
}

// TestVendorRoleIsAssumedNotSimulated. The assumption is the check: simulation
// evaluates neither SCPs nor the trust policy, and the trust policy is where the
// ExternalId condition lives — the single most likely thing to be misconfigured.
func TestVendorRoleIsAssumedNotSimulated(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount)
	stsFake := awsfake.NewSTS(memberAccount)
	stsFake.Assumable[vendorRole] = testExternalID

	rep := run(t, &Runner{
		STS: stsFake, Org: org, VendorRoleARN: vendorRole, ExternalID: testExternalID,
	})

	if n := stsFake.CallCount("AssumeRole"); n != 1 {
		t.Fatalf("AssumeRole called %d times, want 1: the check must be observed, not simulated", n)
	}
	if got := aws.ToString(stsFake.LastAssumeRole.ExternalId); got != testExternalID {
		t.Errorf("ExternalId sent = %q, want %q — a trust policy requiring one only protects the role "+
			"if the caller actually supplies it", got, testExternalID)
	}
	c := find(t, rep, "vendor role")
	if c.Result != Pass || c.Certainty != Observed {
		t.Errorf("vendor role check = %s/%s, want pass/observed", c.Result, c.Certainty)
	}
	if rep.VendorRoleAssumable != Pass || !rep.VendorRoleExternalID {
		t.Errorf("VendorRoleAssumable = %s, VendorRoleExternalID = %v; want pass, true",
			rep.VendorRoleAssumable, rep.VendorRoleExternalID)
	}
}

// TestAssumableWithoutExternalIDIsAFinding.
//
// This configuration works, so it is tempting to pass it silently. It must not
// be: central IT approved the role believing it was constrained to one account,
// and a role that assumes without an ExternalId can be assumed by anyone who
// learns its ARN. The vend will succeed; the security property central IT signed
// off on does not hold, and preflight is the only place that will ever notice.
func TestAssumableWithoutExternalIDIsAFinding(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount)
	stsFake := awsfake.NewSTS(memberAccount)
	stsFake.Assumable[vendorRole] = "" // trust policy requires no ExternalId

	rep := run(t, &Runner{STS: stsFake, Org: org, VendorRoleARN: vendorRole})

	if rep.VendorRoleAssumable != Pass {
		t.Fatalf("VendorRoleAssumable = %s, want pass: the role did assume", rep.VendorRoleAssumable)
	}
	if !rep.CanVend {
		t.Error("CanVend = false; the configuration is weak but functional, and blocking it would be wrong")
	}
	c := find(t, rep, "vendor role ExternalId")
	if c.Result != Fail {
		t.Errorf("ExternalId check = %s, want fail", c.Result)
	}
	if !strings.Contains(c.Grant, "sts:ExternalId") {
		t.Errorf("remediation %q does not name the condition to add", c.Grant)
	}
}

// TestOrgMismatchRefusesToContinue. Credentials for one organization and a config
// written for another is the shape of a plan applied to the wrong org, which in
// Phase 2 means accounts created somewhere nobody expected them.
func TestOrgMismatchRefusesToContinue(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount)
	_, err := (&Runner{
		STS: awsfake.NewSTS(managementAccount), Org: org, ExpectOrg: "o-someotherorgid",
	}).Run(context.Background())
	if err == nil {
		t.Fatal("expected a refusal when the config's org does not match the credentials'")
	}
	for _, want := range []string{"o-someotherorgid", testOrg, "--context"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q so the operator can see both sides: %v", want, err)
		}
	}
}

// TestConsolidatedBillingBlocksVending. Every preventive control in every catalog
// is inert in a consolidated-billing org (DESIGN §3 fact 8). Vending there would
// produce accounts automat cannot honestly call compliant, so it is a block and
// not a warning.
func TestConsolidatedBillingBlocksVending(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount)
	org.FeatureSet = "CONSOLIDATED_BILLING"

	rep := run(t, &Runner{
		STS: awsfake.NewSTS(managementAccount), Org: org,
		IAM: awsfake.NewIAM(allVendActions()...), Quota: awsfake.NewQuota(),
	})

	if rep.State != StateManagement {
		t.Fatalf("State = %s, want MANAGEMENT", rep.State)
	}
	if rep.CanVend {
		t.Error("CanVend = true in a consolidated-billing org, where no SCP can be attached")
	}
	if !strings.Contains(rep.CanVendVia, "CONSOLIDATED_BILLING") {
		t.Errorf("CanVendVia = %q, want it to name the feature set as the blocker", rep.CanVendVia)
	}
	c := find(t, rep, "feature set")
	if c.Result != Fail || !strings.Contains(c.Grant, "EnableAllFeatures") {
		t.Errorf("feature set check = %s with grant %q; want fail naming the API that fixes it",
			c.Result, c.Grant)
	}
}

// TestSimulatedResultsAreMarkedSimulated, and the report says what that is worth.
// An operator who reads "allowed" and plans around it has been misled, because
// iam:SimulatePrincipalPolicy does not evaluate SCPs (DESIGN §3 fact 9).
func TestSimulatedResultsAreMarkedSimulated(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount)
	rep := run(t, &Runner{
		STS: awsfake.NewSTS(memberAccount), Org: org,
		IAM: awsfake.NewIAM("organizations:CreatePolicy"),
	})

	var sawPass, sawFail bool
	for _, c := range rep.Checks {
		if c.Name == "organizations:CreatePolicy" {
			sawPass = true
			if c.Result != Pass || c.Certainty != Simulated {
				t.Errorf("allowed action = %s/%s, want pass/simulated", c.Result, c.Certainty)
			}
			if !strings.Contains(c.Detail, "SCP") {
				t.Errorf("a simulated allow must state what it excludes, got %q", c.Detail)
			}
		}
		if c.Name == "organizations:CreateAccount" {
			sawFail = true
			if c.Result != Fail || c.Certainty != Simulated {
				t.Errorf("denied action = %s/%s, want fail/simulated", c.Result, c.Certainty)
			}
		}
	}
	if !sawPass || !sawFail {
		t.Fatalf("expected both a simulated allow and a simulated deny; checks were %v", checkNames(rep))
	}

	out := rep.String()
	if !strings.Contains(out, "does not evaluate service") {
		t.Error("Report.String must print the SCP caveat inline when any result is simulated; " +
			"a footnote in the docs is not where the operator is looking")
	}
}

// TestNoSimulationCaveatWhenNothingWasSimulated: the caveat is load-bearing text,
// and printing it on a report with no simulated results trains readers to skip it.
func TestNoSimulationCaveatWhenNothingWasSimulated(t *testing.T) {
	rep := run(t, &Runner{STS: awsfake.NewSTS(memberAccount), Org: &awsfake.Org{}})
	if strings.Contains(rep.String(), "does not evaluate service") {
		t.Errorf("caveat printed with no simulated check:\n%s", rep.String())
	}
}

// TestGrantForNamesWhoMustAct. In MEMBER state the operator cannot fix their own
// identity policy, and telling them to is the single least useful thing preflight
// could say.
func TestGrantForNamesWhoMustAct(t *testing.T) {
	cases := []struct {
		state State
		want  string
	}{
		{StateMember, "setup --request"},
		{StateManagement, "your own identity policy"},
		{StateStandalone, "automat init"},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			rep := &Report{
				State: tc.state, CallerARN: "arn:aws:sts::222222222222:assumed-role/operator/session",
				ManagementAccountID: managementAccount,
			}
			got := grantFor("organizations:CreateAccount", "brokered role", rep)
			if !strings.Contains(got, tc.want) {
				t.Errorf("grantFor in %s = %q, want it to mention %q", tc.state, got, tc.want)
			}
		})
	}
}

// TestPreflightIssuesNoMutatingCall. Preflight runs before an operator has
// decided anything; a classification pass that changed the organization would be
// a surprise with a blast radius. OrgAPI is read-only by construction, so this
// asserts the property the interface was shaped to give: the recorder shows only
// reads.
func TestPreflightIssuesNoMutatingCall(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount).AddOU(testOU, "Research", "r-exam")
	stsFake := awsfake.NewSTS(managementAccount)
	stsFake.Assumable[vendorRole] = testExternalID

	run(t, &Runner{
		STS: stsFake, Org: org, IAM: awsfake.NewIAM(allVendActions()...), Quota: awsfake.NewQuota(),
		TargetOU: testOU, VendorRoleARN: vendorRole, ExternalID: testExternalID,
	})

	readOnly := map[string]bool{
		"DescribeOrganization": true, "ListRoots": true, "ListParents": true,
		"DescribeOrganizationalUnit": true, "DescribeResourcePolicy": true,
		"GetCallerIdentity": true, "AssumeRole": true, "SimulatePrincipalPolicy": true,
		"GetServiceQuota": true,
	}
	for _, calls := range [][]string{org.Calls(), stsFake.Calls()} {
		for _, c := range calls {
			if !readOnly[c] {
				t.Errorf("preflight called %q, which is not a read", c)
			}
		}
	}
}

// TestExternalIDIsNotStoredInTheReport. The Report is printed, and in later
// phases quoted into an evidence manifest. A live ExternalId must reach
// AssumeRole and go no further.
func TestExternalIDIsNotStoredInTheReport(t *testing.T) {
	const secret = "unmistakable-external-id-value"
	org := awsfake.NewOrg(testOrg, managementAccount)
	stsFake := awsfake.NewSTS(memberAccount)
	stsFake.Assumable[vendorRole] = secret

	rep := run(t, &Runner{
		STS: stsFake, Org: org, VendorRoleARN: vendorRole, ExternalID: secret,
	})
	if strings.Contains(rep.String(), secret) {
		t.Errorf("the rendered report contains the ExternalId:\n%s", rep.String())
	}
	for _, c := range rep.Checks {
		if strings.Contains(c.Detail, secret) || strings.Contains(c.Grant, secret) {
			t.Errorf("check %q leaks the ExternalId", c.Name)
		}
	}
}

// TestFailedAssumptionWithExternalIDDoesNotGuess. AWS returns AccessDenied
// without saying whether the trust policy, the ExternalId, or the caller's
// permissions was wrong. Preflight must not invent an answer, because sending an
// operator to change the wrong one of three things costs another round trip
// through central IT.
func TestFailedAssumptionWithExternalIDDoesNotGuess(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount)
	stsFake := awsfake.NewSTS(memberAccount)
	stsFake.Assumable[vendorRole] = "the-right-value"

	rep := run(t, &Runner{
		STS: stsFake, Org: org, VendorRoleARN: vendorRole, ExternalID: "the-wrong-value",
	})
	c := find(t, rep, "vendor role")
	if c.Result != Fail {
		t.Fatalf("vendor role = %s, want fail", c.Result)
	}
	if !strings.Contains(c.Detail, "AWS does not say which") {
		t.Errorf("detail %q should admit the ambiguity rather than pick a cause", c.Detail)
	}
	if strings.Contains(c.Detail, "the-wrong-value") {
		t.Error("the failing detail echoes the ExternalId that was tried")
	}
}

// TestUnknownQuotaIsNotTheDocumentedDefault. The default is 10 and is documented;
// filling it in when the API refused would be a confident wrong number that gets
// a vend planned against a limit nobody verified.
func TestUnknownQuotaIsNotTheDocumentedDefault(t *testing.T) {
	quota := awsfake.NewQuota()
	quota.Err = awsfake.AccessDenied("servicequotas:GetServiceQuota")

	rep := run(t, &Runner{
		STS: awsfake.NewSTS(managementAccount), Org: awsfake.NewOrg(testOrg, managementAccount),
		Quota: quota,
	})
	if rep.AccountQuotaKnown {
		t.Error("AccountQuotaKnown = true after the quota API denied the call")
	}
	if rep.AccountQuota != 0 {
		t.Errorf("AccountQuota = %v; an unread quota must stay zero-and-unknown, not be guessed",
			rep.AccountQuota)
	}
}

// TestMissingDelegationPolicyIsReportedPerState. The same API answer means
// different things in MANAGEMENT (nothing is delegated, which is normal) and
// MEMBER (nothing is delegated *to you*, which is the blocker), and the
// remediation differs accordingly.
func TestMissingDelegationPolicyIsReportedPerState(t *testing.T) {
	t.Run("member", func(t *testing.T) {
		rep := run(t, &Runner{
			STS: awsfake.NewSTS(memberAccount), Org: awsfake.NewOrg(testOrg, managementAccount),
		})
		c := find(t, rep, "delegation policy")
		if c.Result != Fail || !strings.Contains(c.Grant, "delegation-policy.json") {
			t.Errorf("member: %s / %q; want fail naming the bundle file to apply", c.Result, c.Grant)
		}
	})
	t.Run("management", func(t *testing.T) {
		rep := run(t, &Runner{
			STS: awsfake.NewSTS(managementAccount), Org: awsfake.NewOrg(testOrg, managementAccount),
		})
		c := find(t, rep, "delegation policy")
		if !strings.Contains(c.Grant, "not needed in this state") {
			t.Errorf("management: %q; a management account manages policies directly", c.Grant)
		}
	})
}

// TestUnreadableDelegationIsNeverAFailure. "I cannot see your delegation" is not
// evidence that you lack one (DESIGN §16 is still open on how much is visible
// from the member side), and reporting it as a failure would send operators to
// re-request a grant they already hold.
func TestUnreadableDelegationIsNeverAFailure(t *testing.T) {
	org := awsfake.NewOrg(testOrg, managementAccount)
	org.ResourcePolicyErr = awsfake.AccessDenied("organizations:DescribeResourcePolicy")

	rep := run(t, &Runner{STS: awsfake.NewSTS(memberAccount), Org: org})
	c := find(t, rep, "delegation policy")
	if c.Result == Fail {
		t.Errorf("an unreadable resource policy was reported as a failure: %q", c.Detail)
	}
	if c.Certainty != Undetermined {
		t.Errorf("certainty = %s, want undetermined", c.Certainty)
	}
	if rep.DelegationVisible != Unknown {
		t.Errorf("DelegationVisible = %s, want unknown", rep.DelegationVisible)
	}
}

// TestNilOptionalClientsAreSkipped: `automat preflight` should degrade rather
// than crash when an operator has no quota or simulation access configured.
func TestNilOptionalClientsAreSkipped(t *testing.T) {
	rep := run(t, &Runner{
		STS: awsfake.NewSTS(managementAccount), Org: awsfake.NewOrg(testOrg, managementAccount),
	})
	for _, c := range rep.Checks {
		if strings.Contains(c.Name, "quota") || c.Name == "permission simulation" {
			t.Errorf("check %q was emitted with no client configured", c.Name)
		}
	}
}
