// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/config"
	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/evidence"
	"github.com/scttfrdmn/automat/internal/org"
	"github.com/scttfrdmn/automat/internal/version"
)

// newReclaimCmd builds `automat reclaim` — docs/reclaim-design.md.
//
// A vended account is durable by default (that design page's own decision),
// so this command is deliberately the heaviest-gated one in the tree:
// --yes is required UNCONDITIONALLY to apply, not gated on one particularly
// dangerous step the way `init`'s org-creation gate is. Every apply here
// closes an AWS account.
//
// Two AWS-side actions, in the order docs/reclaim-design.md fixes: detach
// automat's own service control policies first (delegable, DESIGN §3 fact
// 3), then close the account (not delegable — the same class as
// CreateAccount, needing the brokered vendor role in MEMBER). A failed close
// after a successful detach leaves a known, resumable state; the reverse
// order could not produce that guarantee.
func newReclaimCmd(g *globals) *cobra.Command {
	var (
		accountID   string
		dryRun      bool
		yes         bool
		evidenceDir string
	)

	cmd := &cobra.Command{
		Use:   "reclaim",
		Short: "Close a vended account (destructive; requires --yes)",
		Long: "Detaches automat's own service control policies from the account's OU\n" +
			"placement, then closes the account. Read the plan before applying: this is\n" +
			"the one command in this tool that destroys something AWS provides no call\n" +
			"to undo.\n\n" +
			"A vended account is durable by default (docs/reclaim-design.md) — reclaim is a\n" +
			"rare, deliberate event, not routine teardown. --yes is required " +
			"unconditionally to apply; there is no lighter-weight path.\n\n" +
			"Only a policy carrying automat's own owner tag is detached. A policy present\n" +
			"but not automat's — the institution's own floor — is reported and left alone.\n\n" +
			"AWS closes accounts asynchronously and holds a closed account in SUSPENDED\n" +
			"status for a 90-day grace window, reinstatable by contacting AWS Support;\n" +
			"after that it cannot be reopened. There is no programmatic pre-check against\n" +
			"AWS's closure rate limit (the higher of 250 or 20% of member accounts per\n" +
			"rolling 30 days, up to 1,000) — a rejection is reported with that limit named.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgCtx, err := g.orgContext()
			if err != nil {
				return err
			}
			ctx := cmd.Context()

			if accountID == "" {
				return fmt.Errorf("no account was given: pass --account <id>")
			}
			if !reVerifyAccountID.MatchString(accountID) {
				return fmt.Errorf("--account %q is not a 12-digit AWS account id", accountID)
			}

			region, profile := orgCtx.Region, orgCtx.Profile
			stsAPI, err := g.stsClient(ctx, region, profile)
			if err != nil {
				return err
			}
			readAPI, err := g.orgClient(ctx, region, profile)
			if err != nil {
				return err
			}

			ident, err := stsAPI.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return awsapi.Denied(err, "sts:GetCallerIdentity", "", "",
					"run `automat login`, or set AWS_PROFILE to a profile with valid credentials; "+
						"the evidence record reclaim writes names the identity that ran it")
			}
			caller := &callerIdentity{
				AccountID: aws.ToString(ident.Account),
				ARN:       aws.ToString(ident.Arn),
			}

			policyAPI, closeAPI, credential, orgInfo, err := reclaimOrgClients(ctx, g, readAPI, caller, region, profile, orgCtx)
			if err != nil {
				return err
			}

			target, err := verifyParentOf(ctx, readAPI, accountID)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()

			// Plan first, always (CLAUDE.md rule 5) — a real run of the same code
			// in ModePlan, so the plan cannot drift from the apply that follows it.
			plan := &org.Reclaimer{Policy: policyAPI, Close: closeAPI, Mode: org.ModePlan,
				Credential: credential, Principal: caller.ARN}
			if _, err := plan.DetachOwnedPolicies(ctx, target); err != nil {
				return err
			}
			if _, err := plan.CloseAccount(ctx, accountID); err != nil {
				return err
			}
			if err := renderActions(out, "Plan:", plan.Actions()); err != nil {
				return err
			}
			if dryRun {
				if _, werr := fmt.Fprintln(out, "\nNothing was applied (--dry-run)."); werr != nil {
					return fmt.Errorf("write the plan: %w", werr)
				}
				return nil
			}
			if !yes {
				return fmt.Errorf("this would close account %s — AWS holds it in SUSPENDED status for a "+
					"90-day grace window, reinstatable only by contacting AWS Support, and after that it "+
					"cannot be reopened. The plan above is what would happen. Re-run with --yes to apply it",
					accountID)
			}

			apply := &org.Reclaimer{Policy: policyAPI, Close: closeAPI, Mode: org.ModeApply,
				Credential: credential, Principal: caller.ARN}
			if _, err := apply.DetachOwnedPolicies(ctx, target); err != nil {
				return reclaimPartialError(apply, target, err)
			}
			if _, err := apply.CloseAccount(ctx, accountID); err != nil {
				return reclaimPartialError(apply, target, err)
			}
			if err := renderActions(out, "\nApplied:", apply.Actions()); err != nil {
				return err
			}

			manifestPath, werr := writeReclaimEvidence(accountID, target, caller.ARN, time.Now(),
				apply.Actions(), orgInfo, evidenceDir)
			if werr != nil {
				return werr
			}
			if _, perr := fmt.Fprintf(out, "\nEvidence: %s\n", manifestPath); perr != nil {
				return fmt.Errorf("write the result: %w", perr)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&accountID, "account", "", "the account to close (required)")
	f.BoolVar(&dryRun, "dry-run", false, "print the plan and stop")
	f.BoolVar(&yes, "yes", false, "required to apply — reclaim is destructive with no gated half")
	f.StringVar(&evidenceDir, "evidence-dir", envprofile.DefaultEvidenceDir,
		"local directory to write the evidence record into, relative to the working directory — "+
			"match the environment profile's baseline.evidence.local_dir if it was customized, or "+
			"the OpReclaim record lands in a different manifest than vend and verify wrote to")
	return cmd
}

// reclaimOrgInfo is the organization identity reclaim needs to render an
// ARN for what it detached (evidence.Enforcement.SCPARNs, the same shape
// vend.go's vendState.policyARNs renders from).
type reclaimOrgInfo struct {
	OrgID               string
	ManagementAccountID string
	Partition           string
}

// reclaimOrgClients resolves the two credentials reclaim needs, mirroring
// vendOrgClient's own MANAGEMENT/MEMBER classification exactly: DetachPolicy
// is delegable (the same credential orgPolicyClient already uses), while
// CloseAccount is not and needs the brokered vendor role in MEMBER
// (docs/reclaim-design.md).
func reclaimOrgClients(ctx context.Context, g *globals, read awsapi.OrgAPI, caller *callerIdentity,
	region, profile string, orgCtx config.Context) (policyAPI, closeAPI awsapi.OrgReclaimAPI,
	cred org.Credential, info reclaimOrgInfo, err error) {
	policyAPI, err = g.orgReclaimClient(ctx, region, profile)
	if err != nil {
		return nil, nil, org.Native, info, err
	}

	out, derr := read.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	switch {
	case derr == nil:
		// fall through
	case awsapi.IsNotInOrganization(derr):
		return nil, nil, org.Native, info, fmt.Errorf("account %s is not in an organization, so there "+
			"is nothing to reclaim it from", caller.AccountID)
	default:
		return nil, nil, org.Native, info, awsapi.Denied(derr, "organizations:DescribeOrganization", "",
			caller.ARN, "grant organizations:DescribeOrganization to "+caller.ARN+"; automat cannot "+
				"tell whether this account can close accounts natively or must broker through a "+
				"vendor role without it")
	}
	if out.Organization == nil {
		return nil, nil, org.Native, info, fmt.Errorf("describing the organization: AWS returned no " +
			"organization and no error")
	}
	info = reclaimOrgInfo{
		OrgID:               aws.ToString(out.Organization.Id),
		ManagementAccountID: aws.ToString(out.Organization.MasterAccountId),
		Partition:           partitionOf(caller.ARN),
	}
	if caller.AccountID == info.ManagementAccountID {
		closeAPI, err = g.orgReclaimClient(ctx, region, profile)
		return policyAPI, closeAPI, org.Native, info, err
	}

	if orgCtx.VendorRoleARN == "" {
		return nil, nil, org.Brokered, info, fmt.Errorf("account %s is a member of an organization "+
			"managed by %s, and no vendor_role_arn is configured. Account closure cannot be delegated "+
			"to a member account (DESIGN §3, facts 1-2, the same class as CreateAccount); the vendor "+
			"role needs organizations:CloseAccount added to it — see docs/reclaim-design.md",
			caller.AccountID, info.ManagementAccountID)
	}
	closeAPI, err = g.brokeredOrgReclaimClient(ctx, region, profile, orgCtx.VendorRoleARN, orgCtx.ExternalIDRef)
	return policyAPI, closeAPI, org.Brokered, info, err
}

// reclaimPartialError reports a mid-apply failure with what already
// happened, the same discipline vend.go's partialBundleError follows: an
// operator reading this needs to know the account may already have had its
// SCPs detached even though the close itself failed (or the reverse is
// impossible by construction — detach runs first).
func reclaimPartialError(r *org.Reclaimer, target string, cause error) error {
	actions := r.Actions()
	if len(actions) == 0 {
		return cause
	}
	msg := fmt.Sprintf("%v\n\nActions already applied against %s before this failure:", cause, target)
	for _, a := range actions {
		if a.Applied {
			msg += "\n  " + a.String()
		}
	}
	return fmt.Errorf("%s", msg)
}

// writeReclaimEvidence appends an OpReclaim record, following the same
// OpenDir/LoadOrNew/Append/Write sequence writeVerifyEvidence
// (verify.go) and writeAssessEvidence (assess.go) both use.
//
// Always evidence.OutcomeSuccess: docs/reclaim-design.md decided this
// operation's own outcome is whether the closure request was accepted, not
// a claim about the account's compliance — there is nothing here for
// success/failure to disagree with the way verify's drift-vs-clean split
// does.
func writeReclaimEvidence(accountID, target, callerARN string, now time.Time, actions []org.Action,
	info reclaimOrgInfo, evidenceDir string) (string, error) {
	if evidenceDir == "" {
		evidenceDir = envprofile.DefaultEvidenceDir
	}
	dir, err := evidence.OpenDir(".", evidenceDir)
	if err != nil {
		return "", err
	}
	defer func() { _ = dir.Close() }()
	path := dir.Path(accountID)

	m, err := dir.LoadOrNew(accountID, accountID, "", now.UTC().Format(time.RFC3339), nil)
	if err != nil {
		return "", fmt.Errorf("cannot open the evidence manifest for account %s: %w\n"+
			"automat refuses to continue a chain it cannot read, because a manifest rewritten from "+
			"scratch over a damaged one is the one failure the hash chain exists to make visible",
			accountID, err)
	}

	// ARNs, not bare policy ids, the same rendering vend.go's vendState.policyARNs
	// uses — evidence.Enforcement.SCPARNs is documented as ARNs.
	var detached []string
	if info.OrgID != "" && info.ManagementAccountID != "" {
		for _, a := range actions {
			if a.Verb == org.VerbDetach && a.Applied && a.ID != "" {
				detached = append(detached, "arn:"+info.Partition+":organizations::"+info.ManagementAccountID+
					":policy/"+info.OrgID+"/service_control_policy/"+a.ID)
			}
		}
	}

	rec := evidence.Record{
		Timestamp:   now.UTC().Format(time.RFC3339),
		Operation:   evidence.OpReclaim,
		Outcome:     evidence.OutcomeSuccess,
		Operator:    evidence.Operator{ARN: callerARN},
		Target:      &evidence.Target{AccountID: accountID, OUID: target},
		Enforcement: &evidence.Enforcement{SCPARNs: detached},
		ToolVersion: version.Version,
	}
	if _, err := m.Append(rec, nil); err != nil {
		return "", fmt.Errorf("cannot append the reclaim record for account %s: %w", accountID, err)
	}
	if err := dir.Write(m, accountID); err != nil {
		return "", err
	}
	return path, nil
}
