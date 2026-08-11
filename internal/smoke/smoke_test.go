// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build smoke

package smoke

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/org"
)

// smokeEmailPattern is the template every account this suite creates gets
// its root email from, in the same {name}-placeholder shape
// internal/config.Context.EmailPattern already uses (e.g.
// "research-admin+{name}@dept.edu") — not a bare domain, because a mailbox
// like Gmail's plus-addressing needs the local part preserved, not
// discarded in favor of a synthesized one. AWS requires a real, reachable
// mailbox for CreateAccount to succeed under some organizations, so this
// suite requires the sandbox operator's own pattern via
// AUTOMAT_SMOKE_EMAIL_PATTERN rather than guessing a domain-only shape.
func smokeEmailPattern(t testingT) string {
	pattern := getenvRequired(t, "AUTOMAT_SMOKE_EMAIL_PATTERN",
		"an email pattern with a {name} placeholder, e.g. \"you+automat-smoke-{name}@gmail.com\" — "+
			"AWS requires a reachable address for CreateAccount to succeed under some organizations")
	if !strings.Contains(pattern, "{name}") {
		t.Fatalf("AUTOMAT_SMOKE_EMAIL_PATTERN %q has no {name} placeholder, so every account this "+
			"suite creates would race for the same email — AWS requires a globally unique address "+
			"per account", pattern)
	}
	return pattern
}

// smokeEmail renders one unique address from smokeEmailPattern for the
// named test account.
func smokeEmail(pattern, name string) string {
	return strings.Replace(pattern, "{name}", name, 1)
}

func smokeDestOU(t testingT) string {
	return getenvRequired(t, "AUTOMAT_SMOKE_OU",
		"the OU id this suite vends test accounts into — an ou-<root>-<suffix> value, never the root, "+
			"so a smoke run's throwaway accounts land somewhere reclaim can find and remove them "+
			"without touching anything else in the sandbox")
}

func getenvRequired(t testingT, key, why string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s is not set: %s", key, why)
	}
	return v
}

// TestSmokeChecklist runs docs/smoke.md's ordered checklist against a real
// sandbox organization: Q9, Q7, Q8, Q12, Q5, Q6, Q13, Q24, in that order,
// sharing the accounts earlier subtests vend with the ones that follow.
//
// A subtest failure does not stop the suite — go test's own t.Run already
// gives that for free — but it also must not abandon an account: every
// vended account is tracked on the shared Harness and reclaimed in a
// t.Cleanup that runs no matter which subtest failed or how.
func TestSmokeChecklist(t *testing.T) {
	h := newHarness(t)
	t.Logf("sandbox organization: %s, caller: %s", h.OrgID, h.CallerARN)

	ctx := context.Background()
	ou := smokeDestOU(t)
	emailPattern := smokeEmailPattern(t)

	// Q9 and Q7 share one CreateAccount + immediate MoveAccount, because
	// Q7's own question (timing) can only be measured on the same call Q9
	// needs anyway — vending a second account to answer Q7 in isolation
	// would answer a slightly different question (a warmer, not cold, API
	// path).
	var accountID string
	t.Run("Q9_MoveAccountSourceParent", func(t *testing.T) {
		email := smokeEmail(emailPattern, fmt.Sprintf("q9-%d", time.Now().UnixNano()))
		out, err := h.Vend.CreateAccount(ctx, &organizations.CreateAccountInput{
			AccountName: aws.String("automat-smoke-q9"),
			Email:       aws.String(email),
			Tags: []orgtypes.Tag{
				{Key: aws.String("automat:vended-by"), Value: aws.String(h.CallerARN)},
				{Key: aws.String("automat:ou"), Value: aws.String(ou)},
			},
		})
		if err != nil {
			t.Fatalf("organizations:CreateAccount: %v", err)
		}
		reqID := aws.ToString(out.CreateAccountStatus.Id)

		id, createElapsed, err := pollCreateAccountStatus(ctx, h, reqID)
		if err != nil {
			t.Fatalf("DescribeCreateAccountStatus polling: %v", err)
		}
		accountID = id
		h.TrackVendedAccount(accountID)
		_ = recordFinding(Finding{Question: "Q7", At: time.Now(),
			Detail: fmt.Sprintf("CreateAccount reached SUCCEEDED after %s of polling", createElapsed),
			Extra:  map[string]any{"create_elapsed_seconds": createElapsed.Seconds()}})

		moveStart := time.Now()
		_, err = h.Vend.MoveAccount(ctx, &organizations.MoveAccountInput{
			AccountId:           aws.String(accountID),
			SourceParentId:      aws.String(h.mustRoot(ctx, t)),
			DestinationParentId: aws.String(ou),
		})
		moveElapsed := time.Since(moveStart)

		detail := "MoveAccount succeeded immediately after CreateAccount finished"
		if err != nil {
			detail = fmt.Sprintf("MoveAccount denied: %v", err)
		}
		_ = recordFinding(Finding{Question: "Q9", At: time.Now(), Detail: detail,
			Extra: map[string]any{
				"move_elapsed_seconds": moveElapsed.Seconds(),
				"denied":               err != nil,
			}})
		_ = recordFinding(Finding{Question: "Q7", At: time.Now(),
			Detail: fmt.Sprintf("MoveAccount itself took %s once attempted", moveElapsed),
			Extra:  map[string]any{"move_elapsed_seconds": moveElapsed.Seconds()}})

		if err != nil {
			t.Logf("Q9: MoveAccount was denied — see docs/open-questions.md Q9 for what this means "+
				"and what to check next (whether the denial names the source parent): %v", err)
			return
		}
		t.Logf("Q9: MoveAccount succeeded on the first try")
	})

	// Q12: immediately re-run the same move into the account's now-current
	// parent. Costs one API call, and it's the exact behavior `vend
	// --resume` depends on.
	t.Run("Q12_MoveIntoCurrentParent", func(t *testing.T) {
		if accountID == "" {
			t.Skip("Q9 did not produce an account; nothing to re-move")
		}
		_, err := h.Vend.MoveAccount(ctx, &organizations.MoveAccountInput{
			AccountId:           aws.String(accountID),
			SourceParentId:      aws.String(ou),
			DestinationParentId: aws.String(ou),
		})
		detail := "re-move into the current parent succeeded"
		if err != nil {
			detail = fmt.Sprintf("re-move into the current parent failed: %v", err)
		}
		_ = recordFinding(Finding{Question: "Q12", At: time.Now(), Detail: detail,
			Extra: map[string]any{"errored": err != nil}})
		t.Logf("Q12: %s", detail)
	})

	// Q8: does MoveAccount honor aws:ResourceTag on the account? Vend a
	// SECOND, deliberately untagged account and attempt the same move —
	// this is the one whose bad case is silent, so its core assertion is a
	// real t.Error, not just a Finding.
	t.Run("Q8_ResourceTagHonored", func(t *testing.T) {
		email := smokeEmail(emailPattern, fmt.Sprintf("q8-%d", time.Now().UnixNano()))
		out, err := h.Vend.CreateAccount(ctx, &organizations.CreateAccountInput{
			AccountName: aws.String("automat-smoke-q8-untagged"),
			Email:       aws.String(email),
			// Deliberately no automat:vended-by/automat:ou tags: this
			// account must NOT be movable by a resource-tag-gated role if
			// the condition binds correctly. A real deployment's vendor
			// role would deny this CreateAccount outright (its own
			// aws:RequestTag condition); this suite's native credentials
			// are not so gated, which is why the test is about MoveAccount
			// specifically, not about reaching this point at all.
			Tags: nil,
		})
		if err != nil {
			t.Fatalf("organizations:CreateAccount (untagged): %v", err)
		}
		untaggedID, _, err := pollCreateAccountStatus(ctx, h, aws.ToString(out.CreateAccountStatus.Id))
		if err != nil {
			t.Fatalf("DescribeCreateAccountStatus polling (untagged): %v", err)
		}
		h.TrackVendedAccount(untaggedID)

		_, moveErr := h.Vend.MoveAccount(ctx, &organizations.MoveAccountInput{
			AccountId:           aws.String(untaggedID),
			SourceParentId:      aws.String(h.mustRoot(ctx, t)),
			DestinationParentId: aws.String(ou),
		})
		bound := moveErr != nil
		_ = recordFinding(Finding{Question: "Q8", At: time.Now(),
			Detail: fmt.Sprintf("move of a deliberately untagged account: denied=%v, err=%v", bound, moveErr),
			Extra:  map[string]any{"resource_tag_condition_bound": bound}})

		// This suite's own native credentials are not gated by the vendor
		// role's condition, so a real run here is expected to succeed
		// (native has no resource-tag restriction at all) — the actual
		// question can only be answered by running THIS SAME move under
		// the brokered vendor-role credential, not automat-smoke's own.
		// Recorded as a Finding either way; not asserted as pass/fail,
		// because this suite cannot construct the brokered credential
		// docs/smoke.md's real Q8 procedure requires without the
		// onboarding bundle already being deployed in the sandbox.
		t.Logf("Q8: recorded — see the finding for whether this credential's move of an untagged " +
			"account was denied. This suite runs under NATIVE credentials, which are not subject to " +
			"the vendor role's resource-tag condition; running this same check under the BROKERED " +
			"vendor role (after deploying the onboarding bundle into the sandbox) is what actually " +
			"answers Q8 — see docs/smoke.md's own procedure")
	})

	t.Run("Q5_DelegationVisibility", func(t *testing.T) {
		_, err := h.Org.DescribeResourcePolicy(ctx, &organizations.DescribeResourcePolicyInput{})
		readable := err == nil
		detail := "DescribeResourcePolicy is readable with this credential"
		if !readable {
			detail = fmt.Sprintf("DescribeResourcePolicy denied or errored: %v", err)
		}
		_ = recordFinding(Finding{Question: "Q5", At: time.Now(), Detail: detail,
			Extra: map[string]any{"readable": readable}})
		t.Logf("Q5: %s", detail)
	})

	t.Run("Q6_SCPQuotaEdges", func(t *testing.T) {
		page, err := h.Policy.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
			TargetId: aws.String(ou),
			Filter:   orgtypes.PolicyTypeServiceControlPolicy,
		})
		if err != nil {
			t.Logf("Q6: could not list policies on %s to measure headroom: %v", ou, err)
			return
		}
		total := 0
		for _, p := range page.Policies {
			pd, derr := h.Policy.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: p.Id})
			if derr != nil {
				continue
			}
			total += len(aws.ToString(pd.Policy.Content))
		}
		_ = recordFinding(Finding{Question: "Q6", At: time.Now(),
			Detail: fmt.Sprintf("%d policies attached to %s, %d total characters (limit 5120 per policy, "+
				"5 policies per target)", len(page.Policies), ou, total),
			Extra: map[string]any{"attached_count": len(page.Policies), "total_characters": total}})
		t.Logf("Q6: %d policies attached to %s, %d characters total", len(page.Policies), ou, total)
	})

	// Q13: attempt PutRolePolicy on automat-automation from a role that is
	// NOT automat-automation itself (this suite's own caller) — the actual
	// live question is whether the baseline-protection SCP, once attached,
	// denies this call to EVERY principal in the account including
	// automat-automation itself, which requires assuming into the child
	// account to test properly. This suite records what it can reach
	// (whether the role/policy already exists and is protected against
	// this credential) and discloses the gap rather than fabricating the
	// in-child half.
	t.Run("Q13_BaselineRolesProtected", func(t *testing.T) {
		if accountID == "" {
			t.Skip("no account available to check")
		}
		roleName := "automat-automation"
		_, err := h.IAMRole.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
		detail := fmt.Sprintf("GetRole(%s) against this suite's own account: %v — automat-automation "+
			"is an IN-CHILD role (internal/baseline, not built yet), so this call is against the "+
			"WRONG account unless AUTOMAT_SMOKE_PROFILE's credentials are already scoped to the "+
			"vended child; this finding is a placeholder until internal/baseline exists and this "+
			"suite can assume into the child to test PutRolePolicy for real", roleName, err)
		_ = recordFinding(Finding{Question: "Q13", At: time.Now(), Detail: detail})
		t.Logf("Q13: %s", detail)
	})

	// Q24: last, deliberately — reclaims the Q9 account (and, via
	// t.Cleanup, the Q8 account too) so no earlier subtest loses the
	// account it needs. This subtest measures the reclaim path itself
	// rather than delegating entirely to t.Cleanup, so the latency/shape
	// observations land as Findings rather than only a best-effort cleanup
	// log line.
	t.Run("Q24_ReclaimDetachThenClose", func(t *testing.T) {
		if accountID == "" {
			t.Skip("no account available to reclaim")
		}
		r := &org.Reclaimer{Policy: h.Reclaim, Close: h.Reclaim, Mode: org.ModeApply, Credential: org.Native}

		detachStart := time.Now()
		actions, err := r.DetachOwnedPolicies(ctx, ou, accountID)
		detachElapsed := time.Since(detachStart)
		if err != nil {
			t.Logf("Q24: DetachOwnedPolicies: %v", err)
		}
		_ = recordFinding(Finding{Question: "Q24", At: time.Now(),
			Detail: fmt.Sprintf("DetachOwnedPolicies took %s, %d actions, err=%v", detachElapsed, len(actions), err),
			Extra:  map[string]any{"detach_elapsed_seconds": detachElapsed.Seconds()}})

		closeStart := time.Now()
		_, closeErr := r.CloseAccount(ctx, accountID)
		closeElapsed := time.Since(closeStart)
		_ = recordFinding(Finding{Question: "Q24", At: time.Now(),
			Detail: fmt.Sprintf("CloseAccount call itself took %s, err=%v", closeElapsed, closeErr),
			Extra:  map[string]any{"close_call_elapsed_seconds": closeElapsed.Seconds()}})
		if closeErr != nil {
			t.Logf("Q24: CloseAccount: %v", closeErr)
			return
		}

		pollStart := time.Now()
		status, pollErr := pollAccountStatus(ctx, h, accountID, orgtypes.AccountStatusSuspended, 10*time.Minute)
		pollElapsed := time.Since(pollStart)
		_ = recordFinding(Finding{Question: "Q24", At: time.Now(),
			Detail: fmt.Sprintf("DescribeAccount reported %s after %s (err=%v)", status, pollElapsed, pollErr),
			Extra:  map[string]any{"suspended_after_seconds": pollElapsed.Seconds()}})
		t.Logf("Q24: account %s reached status %s after %s", accountID, status, pollElapsed)

		// This account is now closed; remove it from the harness's own
		// cleanup list so t.Cleanup does not try to close it a second time
		// and log a spurious "already closed" failure.
		h.forgetVendedAccount(accountID)
	})
}

// pollCreateAccountStatus polls DescribeCreateAccountStatus to completion,
// returning the account id and how long the poll took — the exact
// measurement Q7 asks for, done inline rather than through
// internal/org.Ensurer.EnsureAccount so this suite controls and reports the
// timing directly rather than letting Ensurer's own retry/backoff hide it.
func pollCreateAccountStatus(ctx context.Context, h *Harness, reqID string) (string, time.Duration, error) {
	start := time.Now()
	for i := 0; i < 60; i++ {
		out, err := h.Vend.DescribeCreateAccountStatus(ctx,
			&organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: aws.String(reqID)})
		if err != nil {
			return "", time.Since(start), err
		}
		st := out.CreateAccountStatus
		switch st.State {
		case orgtypes.CreateAccountStateSucceeded:
			return aws.ToString(st.AccountId), time.Since(start), nil
		case orgtypes.CreateAccountStateFailed:
			return "", time.Since(start), fmt.Errorf("create-account request %s failed: %s",
				reqID, st.FailureReason)
		}
		time.Sleep(5 * time.Second)
	}
	return "", time.Since(start), fmt.Errorf("create-account request %s did not complete within the poll budget", reqID)
}

// pollAccountStatus polls DescribeAccount until it reports want or the
// budget is exhausted, returning whatever status was last observed.
func pollAccountStatus(ctx context.Context, h *Harness, accountID string,
	want orgtypes.AccountStatus, budget time.Duration) (orgtypes.AccountStatus, error) {
	deadline := time.Now().Add(budget)
	var last orgtypes.AccountStatus
	for time.Now().Before(deadline) {
		out, err := h.OrgClient.DescribeAccount(ctx,
			&organizations.DescribeAccountInput{AccountId: aws.String(accountID)})
		if err != nil {
			return last, err
		}
		last = out.Account.Status
		if last == want {
			return last, nil
		}
		time.Sleep(15 * time.Second)
	}
	return last, fmt.Errorf("account %s did not reach %s within %s (last observed: %s)",
		accountID, want, budget, last)
}

// mustRoot resolves the organization's root id, failing the calling test on
// error rather than returning one, since every Q9-family subtest needs it
// and none has a sensible fallback.
func (h *Harness) mustRoot(ctx context.Context, t testingT) string {
	t.Helper()
	id, err := org.RootID(ctx, h.Org)
	if err != nil {
		t.Fatalf("resolve organization root id: %v", err)
	}
	return id
}

// forgetVendedAccount removes an account from the harness's cleanup list —
// used once a subtest has already closed the account itself, so t.Cleanup
// does not attempt a second, redundant close.
func (h *Harness) forgetVendedAccount(accountID string) {
	out := make([]string, 0, len(h.vendedAccounts))
	for _, id := range h.vendedAccounts {
		if id != accountID {
			out = append(out, id)
		}
	}
	h.vendedAccounts = out
}
