// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/bundle"
	"github.com/scttfrdmn/automat/internal/config"
	"github.com/scttfrdmn/automat/internal/org"
	"github.com/scttfrdmn/automat/internal/version"
)

// newSetupCmd builds `automat setup` (DESIGN §13).
//
// Phase 1 built --request: the MEMBER-state path that generates the onboarding
// bundle central IT reviews. Phase 3 (task 3) adds the MANAGEMENT half —
// applying the delegation policy and creating the vendor role directly, in
// runSetupApply — so the two halves now share this command exactly the way
// DESIGN §13 always described it, rather than one being a placeholder error.
//
// The two halves are not symmetric in what they accept. --request permits a
// placeholder OU (--ou-name) because the bundle has a later step, ou.md, where
// central IT replaces it after creating the real one. Apply has no later step —
// the OU id is baked into a role and a policy the moment they are written to
// AWS — so it requires --ou and refuses --ou-name outright.
func newSetupCmd(g *globals) *cobra.Command {
	var (
		request       bool
		memberAcct    string
		mgmtAcct      string
		orgID         string
		targetOU      string
		ouName        string
		memberRole    string
		roleName      string
		contact       string
		outDir        string
		externalIDRef string
		dryRun        bool
		force         bool
	)

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up the delegation and vendor role, or request them from central IT",
		Long: "With --request, generates the onboarding bundle a member account sends to whoever\n" +
			"runs the organization: the delegation policy, the vendor role as CloudFormation\n" +
			"and Terraform, a cover note that states the blast radius, and instructions for\n" +
			"creating the target OU if it does not exist yet.\n\n" +
			"Nothing is applied to AWS and no AWS call is made: this writes five files. The\n" +
			"bundle is meant to be read in full by the person who approves it, which is why it\n" +
			"is short and why it contains no free-text field.\n\n" +
			"Without --request, applies the delegation policy and creates the vendor role\n" +
			"directly, from a management account. Requires --ou (a real OU id, not\n" +
			"--ou-name) and --external-id-ref (automat does not generate an ExternalId;\n" +
			"generate your own and point the flag at where it lives). Ensure-semantics, so a\n" +
			"second run corrects drift rather than failing on \"already exists\".",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !request {
				return runSetupApply(cmd, g, setupApplyFlags{
					memberAcct: memberAcct, mgmtAcct: mgmtAcct, orgID: orgID, targetOU: targetOU,
					ouName: ouName, memberRole: memberRole, roleName: roleName, contact: contact,
					externalIDRef: externalIDRef, dryRun: dryRun,
				})
			}

			orgCtx, err := g.orgContext()
			if err != nil {
				return err
			}
			// Config supplies what it knows; flags override, because a bundle is
			// often generated for an OU that is not in the config yet.
			if orgID == "" {
				orgID = orgCtx.Org
			}
			if targetOU == "" {
				targetOU = orgCtx.OU
			}

			// No ExternalId is generated here, and there is no flag to supply one.
			// The templates declare it as a deploy-time input, so the management
			// account chooses it and tells the requester out of band. automat sees
			// it only later, through external_id_ref at assume time.
			req := &bundle.Request{
				MemberAccountID:     memberAcct,
				MemberRoleARN:       memberRole,
				ManagementAccountID: mgmtAcct,
				OrgID:               orgID,
				TargetOU:            targetOU,
				TargetOUName:        ouName,
				VendorRoleName:      roleName,
				RequesterContact:    contact,
				// Truncated to the second and forced to UTC: a bundle is a
				// document two organizations compare, and a local-time stamp in
				// it is a question nobody should have to ask.
				GeneratedAt: time.Now().UTC().Format(time.RFC3339),
				ToolVersion: version.Version,
			}

			opts := bundle.Options{Dir: outDir, Force: force}
			out := cmd.OutOrStdout()

			// Plan first, always (CLAUDE.md rule 5). --dry-run stops here; a
			// normal run prints the same plan and then does it, so the operator
			// sees the same list either way.
			plan, err := bundle.Plan(req, opts)
			if err != nil {
				return err
			}
			if dryRun {
				if _, werr := fmt.Fprint(out, plan.String()); werr != nil {
					return fmt.Errorf("write the plan: %w", werr)
				}
				if _, werr := fmt.Fprintln(out, "\nNothing was written (--dry-run)."); werr != nil {
					return fmt.Errorf("write the plan: %w", werr)
				}
				return nil
			}

			res, err := bundle.Write(req, opts)
			if err != nil {
				return err
			}
			// Checked, because this is the only place the operator is told where the
			// bundle went and what to do with it. Exiting 0 after failing to print
			// that leaves a directory holding an ExternalId that nobody was told
			// about — including the instruction not to commit it.
			if _, werr := fmt.Fprint(out, res.String()); werr != nil {
				return fmt.Errorf("write the result (the bundle was written to %s): %w", res.Dir, werr)
			}
			if _, werr := fmt.Fprint(out, nextSteps(req, res)); werr != nil {
				return fmt.Errorf("write the next steps (the bundle was written to %s): %w", res.Dir, werr)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVar(&request, "request", false,
		"generate the onboarding bundle to send to whoever runs the organization")
	f.StringVar(&memberAcct, "member-account", "",
		"the 12-digit account that will vend (the one asking)")
	f.StringVar(&mgmtAcct, "management-account", "",
		"the 12-digit management account that owns the organization")
	f.StringVar(&orgID, "org", "", "organization id (o-...); defaults to the config context")
	f.StringVar(&targetOU, "ou", "",
		"target OU id (ou-...); omit if it does not exist yet and use --ou-name")
	f.StringVar(&ouName, "ou-name", "", "proposed name for an OU that does not exist yet")
	f.StringVar(&memberRole, "member-role-arn", "",
		"narrow the trust to one role in the member account rather than the whole account (recommended)")
	f.StringVar(&roleName, "vendor-role-name", "automat-vendor",
		"name for the role to create in the management account")
	f.StringVar(&contact, "contact", "", "address central IT should reply to")
	// There is deliberately no --external-id, for --request. The flag existed when
	// automat generated the value and wrote it into the bundle, which made the
	// requester the party choosing the management account's confused-deputy
	// defense. The templates now take it as a deploy-time input, so there is
	// nothing for --request to supply: a flag here could only put the value back
	// into a file that is meant not to carry one.
	//
	// --external-id-ref is the opposite command's flag, below, and exists for a
	// different reason: without --request, this call creates the role directly —
	// there is no template parameter to defer the value to, so the operator
	// APPLYING the role (not the requester) must supply where their own chosen
	// value lives, the same env:/file: reference form vend's config already uses.
	f.StringVar(&externalIDRef, "external-id-ref", "",
		"where the ExternalId this role will require lives (env:VAR or file:/path); required "+
			"without --request, ignored with it")
	f.StringVar(&outDir, "out", "automat-onboarding", "directory to write the bundle into")
	f.BoolVar(&dryRun, "dry-run", false, "print what would be written and stop")
	f.BoolVar(&force, "force", false, "overwrite files that were edited by hand")

	return cmd
}

// setupApplyFlags is the subset of newSetupCmd's flags the apply half reads.
// A separate type rather than passing each flag through as its own parameter,
// because runSetupApply's signature would otherwise repeat newSetupCmd's flag
// list verbatim and the two would drift the day one gained a flag the other did
// not need.
type setupApplyFlags struct {
	memberAcct, mgmtAcct, orgID, targetOU, ouName, memberRole, roleName, contact, externalIDRef string
	dryRun                                                                                      bool
}

// runSetupApply is `automat setup` without --request: DESIGN §5 applied
// directly from the management account, rather than rendered for a human to
// deploy.
//
// # What this requires that --request does not
//
// A REAL target OU. --request's whole reason for allowing --ou-name is that the
// bundle can name a placeholder and ask central IT to replace it after creating
// the OU (ou.md). Apply has no such second step: the OU id is baked into the
// policies at the moment they are written to AWS, so a placeholder here would
// scope a live role and a live delegation policy to an OU that does not exist.
// --ou-name is refused outright rather than silently ignored.
//
// A real ExternalId, via --external-id-ref. See the flag's own help text and
// internal/bundle/externalid.go for why automat does not generate one:
// AUDIT-1 decided the party granting the role must choose its own
// confused-deputy defense, and that party is whoever runs this command.
//
// # What it does not do
//
// Create the OU. That is `vend`'s or `init`'s job (DESIGN §5's own accounting
// puts OU creation on the vending side, and this command is the granting side);
// setup only scopes the role and the policy to an OU id it is given.
func runSetupApply(cmd *cobra.Command, g *globals, f setupApplyFlags) error {
	if f.ouName != "" {
		return fmt.Errorf("--ou-name names a placeholder for a bundle central IT edits after creating " +
			"the OU (see ou.md); applying directly has no later step to fix a placeholder, so this " +
			"needs the real OU id. Create the OU first (`automat init` if none exists yet), then " +
			"pass its id with --ou")
	}
	if f.targetOU == "" {
		return fmt.Errorf("--ou is required without --request: the vendor role and the delegation " +
			"policy are scoped to an OU at the moment they are applied, and there is no placeholder " +
			"step afterward the way the bundle has")
	}
	if f.externalIDRef == "" {
		return fmt.Errorf("--external-id-ref is required without --request: this role's trust policy " +
			"requires an ExternalId, and automat does not generate one — generate your own " +
			"(`openssl rand -hex 24`), store it where env:VAR or file:/path names, and pass that " +
			"reference here. automat resolves it at apply time and never stores the value")
	}
	externalID, err := config.ResolveExternalID(f.externalIDRef)
	if err != nil {
		return err
	}

	orgCtx, err := g.orgContext()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	region, profile := orgCtx.Region, orgCtx.Profile

	stsAPI, err := g.stsClient(ctx, region, profile)
	if err != nil {
		return err
	}
	setupAPI, err := g.orgSetupClient(ctx, region, profile)
	if err != nil {
		return err
	}
	roleAPI, err := g.iamRoleClient(ctx, region, profile)
	if err != nil {
		return err
	}

	ident, err := stsAPI.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return awsapi.Denied(err, "sts:GetCallerIdentity", "", "",
			"run `automat login`, or set AWS_PROFILE to a profile with valid credentials; automat "+
				"will not apply a delegation without knowing which account it is granting from")
	}
	callerARN := aws.ToString(ident.Arn)
	// mgmtAcct defaults to the caller's own account: apply runs IN the
	// management account, so that is the right default in the ordinary case.
	// --management-account exists for the unusual one, a delegated
	// administrator applying on the management account's behalf.
	mgmtAcct := firstNonEmpty(f.mgmtAcct, aws.ToString(ident.Account))
	orgID := firstNonEmpty(f.orgID, orgCtx.Org)

	req := &bundle.Request{
		MemberAccountID:     f.memberAcct,
		MemberRoleARN:       f.memberRole,
		ManagementAccountID: mgmtAcct,
		OrgID:               orgID,
		TargetOU:            f.targetOU,
		VendorRoleName:      f.roleName,
		RequesterContact:    f.contact,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		ToolVersion:         version.Version,
	}

	e := &org.Ensurer{
		Setup: setupAPI, Role: roleAPI,
		Mode: org.ModePlan, Credential: org.Native, Principal: callerARN,
	}
	if _, err := e.EnsureDelegationPolicy(ctx, req); err != nil {
		return err
	}
	if _, err := e.EnsureVendorRole(ctx, req, externalID); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if err := renderActions(out, "Plan:", e.Actions()); err != nil {
		return err
	}
	if f.dryRun {
		if _, werr := fmt.Fprintln(out, "\nNothing was applied (--dry-run)."); werr != nil {
			return fmt.Errorf("write the plan: %w", werr)
		}
		return nil
	}

	e.ResetActions()
	e.Mode = org.ModeApply
	if _, err := e.EnsureDelegationPolicy(ctx, req); err != nil {
		return err
	}
	if _, err := e.EnsureVendorRole(ctx, req, externalID); err != nil {
		return err
	}
	if err := renderActions(out, "Applied:", e.Actions()); err != nil {
		return err
	}
	if _, werr := fmt.Fprintf(out, "\nSet vendor_role_arn = %q and external_id_ref = %q in %s's "+
		"config context, then run `automat preflight` from account %s to confirm it can assume "+
		"the role.\n", "arn:"+partitionOf(callerARN)+":iam::"+mgmtAcct+":role/"+f.roleName,
		f.externalIDRef, f.memberAcct, f.memberAcct); werr != nil {
		return fmt.Errorf("write the next steps: %w", werr)
	}
	return nil
}

// nextSteps tells the operator what to do with the directory they just got. A
// generator that produces five files and says nothing leaves the most likely
// failure — nobody sends it — entirely to chance.
func nextSteps(req *bundle.Request, res *bundle.Result) string {
	var b strings.Builder
	b.WriteString("\nNext: send this directory to whoever runs your organization.\n")
	b.WriteString("  " + bundle.FileREADME + " is the cover note; it is written for them, not for you.\n")
	if req.TargetOU == "" {
		b.WriteString("  " + bundle.FileOU + " asks them to create the OU first — the bundle " +
			"names a placeholder until they do.\n")
	}
	// The operator's most likely wrong assumption at this moment is that the bundle
	// contains everything both sides need. It does not, on purpose, and the value it
	// leaves out is the one that makes assuming the role work — so an operator who is
	// not told this discovers it as an opaque AccessDenied from STS.
	b.WriteString("\nThe bundle contains no secret; you can send it however you like.\n")
	b.WriteString("The ExternalId is not in it: whoever deploys the role generates that value\n" +
		"and sends it to you separately. When it arrives, keep it outside the config file\n" +
		"and set `external_id_ref` to point at it (`env:AUTOMAT_EXTERNAL_ID`, or\n" +
		"`file:~/.config/automat/external-id`) — automat resolves it at assume time and\n" +
		"never stores the value itself.\n")
	b.WriteString("\nWhen they reply with the role ARN and the ExternalId, run `automat preflight` " +
		"to\ncheck it from this side.\n")
	return b.String()
}
