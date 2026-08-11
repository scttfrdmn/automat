// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build smoke

package smoke

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/org"
)

// Harness is the real-AWS session every smoke subtest shares: one set of
// clients, one verified sandbox org, one account-cleanup list.
//
// Built once per TestSmokeChecklist run rather than once per subtest,
// deliberately: docs/smoke.md's checklist shares vended accounts across
// Q9 through Q13, and a harness scoped to the whole test is what makes
// that sharing a compile-time fact rather than something each subtest has
// to remember to do.
type Harness struct {
	// Region and Profile are what every client below was built with, kept
	// for error messages naming which credential a denial came from.
	Region, Profile string

	// OrgID is the organization id AUTOMAT_SMOKE_ORG named, verified
	// against the real DescribeOrganization response in newHarness — never
	// trusted from the environment alone (docs/smoke.md rule 2).
	OrgID string
	// CallerARN is the identity running the suite, for Finding context and
	// for the same remediation-text reasoning cmd/automat's own commands
	// use.
	CallerARN string

	// Org, Vend, Policy, Reclaim, IAMRole satisfy the same interfaces
	// cmd/automat builds from globals — real aws-sdk-go-v2 clients, backed
	// by the compile-time assertions in internal/awsapi/api.go
	// (organizations.Client already satisfies OrgAPI/OrgVendAPI/
	// OrgPolicyAPI/OrgReclaimAPI simultaneously; one client, four
	// interface views). IAMRole (not IAMAPI, which is SimulatePrincipalPolicy
	// only) is what Q13 needs for PutRolePolicy against automat-automation.
	Org     awsapi.OrgAPI
	Vend    awsapi.OrgVendAPI
	Policy  awsapi.OrgPolicyAPI
	Reclaim awsapi.OrgReclaimAPI
	IAMRole awsapi.IAMRoleAPI

	// OrgClient is the concrete client Org/Vend/Policy/Reclaim are all
	// views of, exposed directly for the one call this suite needs that
	// no awsapi interface names: DescribeAccount, which Q24's status-poll
	// reads and no production Ensurer/Reclaimer method ever had reason to
	// call (they observe a move or a close succeeding, never poll the
	// account's own resting status afterward).
	OrgClient *organizations.Client

	// vendedAccounts tracks every account this run created, for the
	// cleanup registered in newHarness — a subtest that fails partway
	// through must not leave an account nobody will ever reclaim, which is
	// a safeguard docs/smoke.md's manual checklist has no equivalent for.
	vendedAccounts []string
}

// newHarness reads AUTOMAT_SMOKE_PROFILE and AUTOMAT_SMOKE_ORG, builds real
// clients, and verifies the resolved organization actually is the named
// sandbox before returning — the hard gate docs/smoke.md rule 2 requires.
// Registers cleanup of every account TrackVendedAccount records, run
// regardless of whether the calling test failed.
func newHarness(t testingT) *Harness {
	t.Helper()

	profile := os.Getenv("AUTOMAT_SMOKE_PROFILE")
	if profile == "" {
		t.Fatal("AUTOMAT_SMOKE_PROFILE is not set. This suite calls real AWS and refuses to run " +
			"against ambient credentials — see docs/smoke.md rule 1")
	}
	wantOrg := os.Getenv("AUTOMAT_SMOKE_ORG")
	if wantOrg == "" {
		t.Fatal("AUTOMAT_SMOKE_ORG is not set. This suite mutates a real organization and refuses " +
			"to run without an operator-named sandbox to check its own credentials against — see " +
			"docs/smoke.md rule 2")
	}
	region := os.Getenv("AUTOMAT_SMOKE_REGION")

	// Checked once, up front, the same as the two env vars above (AUDIT-7
	// L2): recordFinding's own errors are discarded at every call site
	// because a findings-write failure should not fail a subtest that
	// already did real, mutating AWS work — but that means an unwritable
	// AUTOMAT_SMOKE_FINDINGS path would otherwise let an entire run
	// complete, having mutated a real organization, with zero findings
	// recorded and no diagnostic anywhere. Probing here turns that into a
	// loud failure before anything is created.
	if err := probeFindingsWritable(); err != nil {
		t.Fatalf("AUTOMAT_SMOKE_FINDINGS path is not writable: %v — every recordFinding call this run "+
			"would make discards its own error, so a bad path here would otherwise let the whole run "+
			"complete with no findings recorded and nothing to show for the accounts it mutated", err)
	}

	ctx := context.Background()
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithSharedConfigProfile(profile)}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		t.Fatalf("resolve AWS credentials for profile %q: %v", profile, err)
	}

	stsClient := sts.NewFromConfig(cfg)
	ident, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatalf("sts:GetCallerIdentity against profile %q: %v", profile, err)
	}

	orgClient := organizations.NewFromConfig(cfg)
	out, err := orgClient.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		t.Fatalf("organizations:DescribeOrganization against profile %q: %v — this suite refuses to "+
			"guess whether it is in the sandbox and stops here rather than falling through to any "+
			"write call", profile, err)
	}
	gotOrg := aws.ToString(out.Organization.Id)
	if gotOrg != wantOrg {
		t.Fatalf("AUTOMAT_SMOKE_ORG names %q, but profile %q actually resolves to organization %q. "+
			"Refusing to run: docs/smoke.md rule 2 requires the check happen against what the "+
			"credentials actually resolve to, not a flag asserting it. This is very likely to be the "+
			"safeguard working as intended, not a bug in it — double check AUTOMAT_SMOKE_PROFILE "+
			"before assuming otherwise", wantOrg, profile, gotOrg)
	}

	h := &Harness{
		Region:    region,
		Profile:   profile,
		OrgID:     gotOrg,
		CallerARN: aws.ToString(ident.Arn),
		Org:       orgClient,
		Vend:      orgClient,
		Policy:    orgClient,
		Reclaim:   orgClient,
		IAMRole:   iam.NewFromConfig(cfg),
		OrgClient: orgClient,
	}
	t.Cleanup(func() { h.reclaimAllTrackedAccounts(t) })
	return h
}

// TrackVendedAccount records an account id for end-of-run cleanup. Called
// immediately after a real CreateAccount succeeds — before any further
// step — so that a panic or a t.Fatal three lines later still leaves the
// account in the cleanup list.
func (h *Harness) TrackVendedAccount(accountID string) {
	h.vendedAccounts = append(h.vendedAccounts, accountID)
}

// reclaimAllTrackedAccounts is the harness's t.Cleanup body. It logs and
// continues past a single account's cleanup failure rather than stopping,
// because a cleanup routine that gives up after the first error is one
// that abandons every account after it.
func (h *Harness) reclaimAllTrackedAccounts(t testingT) {
	for _, id := range h.vendedAccounts {
		if err := h.reclaimAccount(id); err != nil {
			t.Logf("cleanup: could not reclaim account %s: %v — this account may need manual "+
				"closure in the sandbox organization", id, err)
		}
	}
}

// reclaimAccount detaches and closes accountID via org.Reclaimer, the same
// production detach-then-close path Q24_ReclaimDetachThenClose
// (smoke_test.go) already builds — not a hand-rolled duplicate (AUDIT-7
// H1): an earlier version of this function re-implemented
// DetachOwnedPolicies/CloseAccount by hand and, in doing so, dropped the
// sibling-active-account check (internal/org/reclaim.go's activeSiblings)
// that AUDIT-6 C1 added to production code specifically because an SCP is
// attached at the OU, not the account (DESIGN §5, §8), so detaching it to
// reclaim one account can silently strip guardrails from another account
// still sitting under the same OU. Using org.Reclaimer here inherits that
// check instead of re-omitting it. Always applies, with no plan/apply gate
// or --yes prompt: a cleanup routine that stopped for a confirmation nobody
// is present to give would abandon the account, which is worse than closing
// it without one.
func (h *Harness) reclaimAccount(accountID string) error {
	ctx := context.Background()
	parents, err := h.Org.ListParents(ctx, &organizations.ListParentsInput{ChildId: aws.String(accountID)})
	if err != nil {
		return fmt.Errorf("list parents of %s: %w", accountID, err)
	}
	if len(parents.Parents) == 0 {
		return fmt.Errorf("account %s reports no parent; cannot locate its policies to detach", accountID)
	}
	target := aws.ToString(parents.Parents[0].Id)

	r := &org.Reclaimer{Policy: h.Reclaim, Close: h.Reclaim, Mode: org.ModeApply, Credential: org.Native}
	if _, err := r.DetachOwnedPolicies(ctx, target, accountID); err != nil {
		return fmt.Errorf("detach automat's policies from %s: %w", target, err)
	}
	if _, err := r.CloseAccount(ctx, accountID); err != nil {
		return fmt.Errorf("close account %s: %w", accountID, err)
	}
	return nil
}

// testingT is the subset of *testing.T (and *testing.T within a subtest)
// this package needs, named so newHarness can be exercised the same way
// from TestSmokeChecklist's top level and from any subtest that wants its
// own scoped harness.
type testingT interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Cleanup(func())
	Logf(format string, args ...any)
}
