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

	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/compilesets"
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

// smokeScratchOU returns AUTOMAT_SMOKE_SCRATCH_OU if set, or falls back to
// smokeDestOU otherwise.
//
// Q20_ControlCharacterInResourceARN is the one subtest in this suite that
// attaches a policy whose behavior is, by construction, the thing being
// investigated — the risk the task that added it flagged is that a
// worse-than-expected outcome (AWS silently normalizing the control
// character into something that matches real resources) would land on
// AUTOMAT_SMOKE_OU, the same OU every other subtest's accounts share.
// AUTOMAT_SMOKE_SCRATCH_OU lets an operator name a second, empty OU to take
// that risk instead, mirroring the reasoning internal/org/reclaim.go's
// activeSiblings check applies to a different operation: an OU-scoped
// mutation should not land somewhere else's accounts live if a place that
// is nobody's can be used instead. Falling back to the shared OU when no
// scratch OU is configured is still an acceptable choice, not a silent
// downgrade: cleanup for this subtest is unconditional (t.Cleanup-registered
// detach-then-delete) and runs whether or not the test itself failed, so the
// blast radius is bounded to "briefly attached, then removed" either way.
func smokeScratchOU(t testingT) string {
	if v := os.Getenv("AUTOMAT_SMOKE_SCRATCH_OU"); v != "" {
		return v
	}
	return smokeDestOU(t)
}

// TestSmokeChecklist runs docs/smoke.md's ordered checklist against a real
// sandbox organization: Q9, Q7, Q8, Q12, Q5, Q6, Q20, Q13, Q24, in that
// order, sharing the accounts earlier subtests vend with the ones that
// follow.
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

	// Q20: does real IAM refuse, silently accept, or silently normalize a
	// control character embedded in an SCP statement's resource ARN? Placed
	// here — after Q6, before Q13 — because it needs no vended account
	// (independent of accountID, the same reason Q5 and Q6 run before Q13
	// asks for one) and it is the only remaining unattempted item from
	// docs/smoke.md's table at the point this subtest was added.
	//
	// docs/open-questions.md's Q20 entry has the full history: automat's OWN
	// validation now refuses this value at both the JSON Schema and the Go
	// validator (a fix that shipped separately, is not touched here, and is
	// not what this subtest exercises). What remains open is what happens if
	// such a value reaches AWS by some path other than automat's validated
	// pipeline — a hand-edited catalog loaded with SkipValidate, or a future
	// artifact field that grows a resource list without inheriting the
	// pattern. This subtest constructs that statement directly as Go data,
	// bypassing artifact.Validate entirely, and asks AWS the question
	// automat's own validator can no longer ask it.
	t.Run("Q20_ControlCharacterInResourceARN", func(t *testing.T) {
		q20ControlCharacterInResourceARN(ctx, t, h)
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

// q20ControlCharacterInResourceARN is docs/open-questions.md Q20, the
// live-AWS half of AUDIT-2 finding L4 that the validation fix (already
// shipped, not touched here) explicitly left open: what happens when a
// resource ARN carrying a raw control byte reaches AttachPolicy by some path
// other than automat's own validated pipeline.
//
// Three outcomes, matching Q20's own text exactly:
//
//  1. CreatePolicy itself refuses the document (almost certainly
//     MalformedPolicyDocumentException, the same exception
//     internal/org/policy.go already recognizes for createPolicy/
//     updatePolicy). SAFE: the value never reaches an attached policy at all.
//  2. CreatePolicy and AttachPolicy both succeed, and DescribePolicy reads
//     back byte-identical content. This is the outcome Q20 calls the more
//     concerning of the two "succeeded" branches: a control character cannot
//     appear in a real bucket ARN, so the Deny this statement renders can
//     never match anything, and a Deny that never fires looks in the console
//     exactly like one that does.
//  3. CreatePolicy and AttachPolicy both succeed, but DescribePolicy's
//     content differs from what was sent — AWS normalized or stripped the
//     byte, so the statement now matches something OTHER than what was
//     written.
//
// Every branch is recorded as a Finding (Q20 is not a boolean question; see
// findings.go's own doc comment on why Finding exists) and none is asserted
// as pass/fail — a live run's raw observation is what a human folds into
// docs/open-questions.md by hand, per docs/smoke.md rule 4.
func q20ControlCharacterInResourceARN(ctx context.Context, t *testing.T, h *Harness) {
	// Hand-built directly as compilesets input, NOT through artifact.Validate
	// or artifact.Decode — the point of this subtest is what happens when
	// such a value arrives WITHOUT going through the validated pipeline (a
	// hand-edited catalog loaded with SkipValidate, or a future field that
	// does not inherit rule 8's character-class pattern). Constructing it as
	// Go data feeding compilesets.Pack directly is the minimal way to get a
	// deliberately malformed statement rendered into a policy document
	// without needing a second, unvalidated catalog file on disk.
	//
	// encoding/json.Marshal (which compilesets.Pack's renderer uses) escapes
	// the raw 0x01 byte as the six-character sequence backslash-u-0-0-0-1 in
	// the JSON text it sends — expected and correct. JSON has no way to
	// carry a literal control byte, so this is not an attempt to put a raw
	// byte on the wire; it is exercising what AWS does with the
	// escaped-but-still-anomalous value, which is the shape any such value
	// would actually take by the time it reached CreatePolicy.
	evilResource := "arn:aws:s3:::automat-smoke-q20-bucket" + "\x01" + "evil"
	m := &compilesets.Merged{Statements: []compilesets.Statement{
		{
			SCPStatement: artifact.SCPStatement{
				Sid:      "AutomatSmokeQ20ControlCharacter",
				Effect:   "Deny",
				Action:   []string{"s3:DeleteObject"},
				Resource: []string{evilResource},
			},
			Origins: []string{"smoke:Q20"},
		},
	}}
	packed, err := compilesets.Pack(m, compilesets.PackOptions{NamePrefix: "automat-smoke-q20"})
	if err != nil {
		t.Fatalf("compilesets.Pack of a deliberately malformed statement: %v — this is a failure of this "+
			"subtest's own setup, not an AWS observation", err)
	}
	if len(packed.Policies) != 1 {
		t.Fatalf("expected exactly one packed policy from a single statement, got %d", len(packed.Policies))
	}
	doc := packed.Policies[0].Document
	if !strings.Contains(doc, `\u0001`) {
		t.Fatalf("the rendered document does not contain the escaped control byte (\\u0001) this subtest "+
			"exists to test — compilesets.Pack's rendering may have changed underneath this subtest: %s", doc)
	}

	policyName := fmt.Sprintf("automat-smoke-q20-%d", time.Now().UnixNano())
	createOut, createErr := h.Policy.CreatePolicy(ctx, &organizations.CreatePolicyInput{
		Name:    aws.String(policyName),
		Content: aws.String(doc),
		Description: aws.String("automat smoke Q20: throwaway policy carrying a control character in a " +
			"resource ARN, created to observe real AWS behavior; safe to delete if found outside a run"),
		Type: orgtypes.PolicyTypeServiceControlPolicy,
	})
	if createErr != nil {
		safe := awsapi.APIErrorCode(createErr) == "MalformedPolicyDocumentException"
		detail := fmt.Sprintf("CreatePolicy with a control character in the resource ARN was refused "+
			"(code=%s, safe=%v): %v", awsapi.APIErrorCode(createErr), safe, createErr)
		_ = recordFinding(Finding{Question: "Q20", At: time.Now(), Detail: detail,
			Extra: map[string]any{"outcome": "create_refused", "error_code": awsapi.APIErrorCode(createErr), "safe": safe}})
		t.Logf("Q20: %s", detail)
		return
	}

	policyID := aws.ToString(createOut.Policy.PolicySummary.Id)
	t.Cleanup(func() {
		q20Cleanup(context.Background(), t, h, policyID)
	})

	// Risk-bounding (per the task that scoped this subtest, mirroring the
	// reasoning internal/org/reclaim.go's activeSiblings applies to a
	// different operation): prefer a dedicated/empty scratch OU over the
	// shared destination OU other subtests' accounts live under, so that a
	// worst-case silent normalization does not affect a sibling account. If
	// no scratch OU is configured, smokeScratchOU falls back to the shared
	// one — still acceptable given cleanup always runs, but noted here so a
	// reader does not mistake the fallback for the intended path.
	target := smokeScratchOU(t)
	if before, err := q20ActiveAccountCount(ctx, h, target); err == nil && before > 0 {
		t.Logf("Q20: attaching to %s, which has %d active account(s) under it — set "+
			"AUTOMAT_SMOKE_SCRATCH_OU to a dedicated empty OU to avoid this", target, before)
	}

	_, attachErr := h.Policy.AttachPolicy(ctx, &organizations.AttachPolicyInput{
		PolicyId: aws.String(policyID),
		TargetId: aws.String(target),
	})
	if attachErr != nil {
		detail := fmt.Sprintf("CreatePolicy succeeded (id=%s) but AttachPolicy to %s was refused: %v",
			policyID, target, attachErr)
		_ = recordFinding(Finding{Question: "Q20", At: time.Now(), Detail: detail,
			Extra: map[string]any{"outcome": "attach_refused", "policy_id": policyID}})
		t.Logf("Q20: %s", detail)
		return
	}
	describeOut, describeErr := h.Policy.DescribePolicy(ctx, &organizations.DescribePolicyInput{
		PolicyId: aws.String(policyID),
	})
	if describeErr != nil {
		detail := fmt.Sprintf("CreatePolicy and AttachPolicy both succeeded (id=%s), but DescribePolicy "+
			"afterward failed: %v — cannot tell whether the content round-tripped", policyID, describeErr)
		_ = recordFinding(Finding{Question: "Q20", At: time.Now(), Detail: detail,
			Extra: map[string]any{"outcome": "describe_failed", "policy_id": policyID}})
		t.Logf("Q20: %s", detail)
		return
	}

	got := aws.ToString(describeOut.Policy.Content)
	if got == doc {
		detail := fmt.Sprintf("CreatePolicy and AttachPolicy both succeeded, and DescribePolicy reports "+
			"the content round-tripped byte-identical (policy=%s, target=%s) — the Deny attached but its "+
			"resource ARN cannot match anything real, so this guard can never fire; a Deny that never "+
			"fires looks in the console exactly like one that does", policyID, target)
		_ = recordFinding(Finding{Question: "Q20", At: time.Now(), Detail: detail,
			Extra: map[string]any{"outcome": "silent_deny_never_fires", "policy_id": policyID, "target": target}})
		t.Logf("Q20: %s", detail)
		return
	}

	detail := fmt.Sprintf("CreatePolicy and AttachPolicy both succeeded, but DescribePolicy's content "+
		"DIFFERS from what was sent (policy=%s, target=%s) — AWS normalized or stripped something; sent "+
		"%d characters, read back %d characters", policyID, target, len(doc), len(got))
	_ = recordFinding(Finding{Question: "Q20", At: time.Now(), Detail: detail,
		Extra: map[string]any{
			"outcome": "content_normalized", "policy_id": policyID, "target": target,
			"sent": doc, "read_back": got,
		}})
	t.Logf("Q20: %s", detail)
}

// q20ActiveAccountCount reports how many ACTIVE accounts sit directly under
// target, best-effort — used only to warn when smokeScratchOU fell back to
// the shared destination OU, never to gate the attach itself (this subtest's
// safety comes from guaranteed cleanup, not from this count).
func q20ActiveAccountCount(ctx context.Context, h *Harness, target string) (int, error) {
	page, err := h.OrgClient.ListAccountsForParent(ctx,
		&organizations.ListAccountsForParentInput{ParentId: aws.String(target)})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range page.Accounts {
		if a.Status == orgtypes.AccountStatusActive {
			n++
		}
	}
	return n, nil
}

// q20Cleanup detaches (if attached) and deletes the throwaway policy Q20
// created, registered via t.Cleanup so it runs regardless of which branch of
// q20ControlCharacterInResourceARN returned or whether the subtest failed —
// the same unconditional-cleanup discipline newHarness's own t.Cleanup
// applies to vended accounts.
//
// DeletePolicy is reached through h.OrgClient directly, not through
// awsapi.OrgReclaimAPI: that interface deliberately has no DeletePolicy
// method (docs/reclaim-design.md — reclaim detaches but never deletes, to
// preserve an audit trail across every account it reclaims). A throwaway
// policy created solely to answer Q20 has no such trail worth preserving, so
// this subtest reaches past the narrow interface for its own cleanup only,
// the same pattern pollAccountStatus already uses h.OrgClient.DescribeAccount
// for a call no narrow interface exposes.
func q20Cleanup(ctx context.Context, t *testing.T, h *Harness, policyID string) {
	if policyID == "" {
		return
	}
	// Detach from every target still holding it. ListPoliciesForTarget is
	// per-target, not per-policy, so this walks the one target this subtest
	// could have attached to (smokeScratchOU) plus the shared destination OU
	// as a defensive second check, in case smokeScratchOU's env var changed
	// between setup and cleanup in some future refactor. A detach against a
	// target that never had the policy attached fails with
	// PolicyNotAttachedException, which is expected and logged, not fatal.
	targets := map[string]bool{}
	if v := os.Getenv("AUTOMAT_SMOKE_SCRATCH_OU"); v != "" {
		targets[v] = true
	}
	if v := os.Getenv("AUTOMAT_SMOKE_OU"); v != "" {
		targets[v] = true
	}
	for target := range targets {
		_, err := h.OrgClient.DetachPolicy(ctx, &organizations.DetachPolicyInput{
			PolicyId: aws.String(policyID), TargetId: aws.String(target),
		})
		if err != nil && awsapi.APIErrorCode(err) != "PolicyNotAttachedException" {
			t.Logf("Q20 cleanup: DetachPolicy(%s, %s): %v", policyID, target, err)
		}
	}
	if _, err := h.OrgClient.DeletePolicy(ctx, &organizations.DeletePolicyInput{
		PolicyId: aws.String(policyID),
	}); err != nil {
		t.Logf("Q20 cleanup: DeletePolicy(%s): %v — this throwaway policy may need manual deletion in "+
			"the sandbox organization", policyID, err)
	}
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
