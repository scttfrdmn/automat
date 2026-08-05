// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/bundle"
	"github.com/scttfrdmn/automat/internal/version"
)

// newSetupCmd builds `automat setup` (DESIGN §13).
//
// Phase 1 implements the --request half: the MEMBER-state path that generates the
// onboarding bundle central IT reviews. The MANAGEMENT half — applying the
// delegation and creating the vendor role directly — is Phase 2, and the command
// says so rather than failing with a bare "unknown flag", because an operator in
// MANAGEMENT state running `automat setup` needs to know which half of the tool
// they are waiting on.
func newSetupCmd(g *globals) *cobra.Command {
	var (
		request    bool
		memberAcct string
		mgmtAcct   string
		orgID      string
		targetOU   string
		ouName     string
		memberRole string
		roleName   string
		contact    string
		outDir     string
		dryRun     bool
		force      bool
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
			"Without --request, setup applies the delegation directly from a management\n" +
			"account. That half arrives in Phase 2.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !request {
				return fmt.Errorf("`automat setup` without --request applies the delegation from a " +
					"management account, which is not implemented yet (Phase 2).\n" +
					"If you are in a member account, you want --request: it generates the bundle " +
					"to send to whoever runs your organization.\n" +
					"If you are in the management account, `automat preflight` will tell you so, " +
					"and you can apply a member's bundle by hand in the meantime — it is exactly " +
					"the two documents this tool would apply")
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
	// There is deliberately no --external-id. The flag existed when automat generated
	// the value and wrote it into the bundle, which made the requester the party
	// choosing the management account's confused-deputy defense. The templates now take
	// it as a deploy-time input, so there is nothing for this command to supply: a flag
	// here could only put the value back into a file that is meant not to carry one.
	f.StringVar(&outDir, "out", "automat-onboarding", "directory to write the bundle into")
	f.BoolVar(&dryRun, "dry-run", false, "print what would be written and stop")
	f.BoolVar(&force, "force", false, "overwrite files that were edited by hand")

	return cmd
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
