// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/org"
)

// defaultResearchOU is the name of the OU `init` creates below the root.
//
// DESIGN §4's STANDALONE row and §13 both say "research OU", which is the name
// this audience uses for it. It is a default rather than a constant because the OU
// name is the only handle automat has on an OU between runs (there is no state
// file), so an institution that already calls it something else must be able to
// say so — and must be able to say so *before* the first vend, since renaming it
// afterwards means automat creates a second one.
const defaultResearchOU = "Research"

// newInitCmd builds `automat init` (DESIGN §13: "STANDALONE only:
// CreateOrganization(ALL) + research OU").
//
// # Which states it runs in, and why that is not quite §13's sentence
//
// §13 says STANDALONE only. This command refuses the MEMBER state and permits
// both STANDALONE and MANAGEMENT, which is a difference worth stating rather than
// quietly implementing — it is listed as a line item in docs/cli-surface.md, per
// the audit ritual.
//
// The reason is that "STANDALONE only" and CLAUDE.md rule 4 cannot both hold
// literally. Rule 4 requires every mutating command to be safely re-runnable, and
// after `init` succeeds the account is no longer standalone: the idempotent second
// run is *necessarily* from MANAGEMENT. A command that refused it would be a
// mutating command with no safe second run, which is the rule this whole package
// is built around.
//
// The second reason is the one with a security consequence. An operator who
// created their organization in the console is MANAGEMENT and was never
// STANDALONE from automat's point of view, and their root may well have the
// service control policy type disabled — the state in which CreatePolicy
// succeeds, AttachPolicy succeeds, and nothing is enforced. `init` is the command
// that fixes that. Refusing to run it there would send exactly the operator who
// needs it to the console for the one call that decides whether every control
// automat later attaches enforces anything.
//
// MEMBER is refused, and it is the state §13's "only" is really about: a member
// account cannot create an organization, cannot enable a policy type on somebody
// else's root, and cannot create a root-level OU. What it needs is the onboarding
// bundle, so the refusal says so.
func newInitCmd(g *globals) *cobra.Command {
	var (
		ouName string
		dryRun bool
		yes    bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Make an organization exist with all features, SCPs on, and a research OU",
		Long: "Prepares an organization to vend into: creates one with FeatureSet=ALL if this\n" +
			"account is not in an organization yet, enables the service control policy type on\n" +
			"the root, and ensures an OU below the root to vend accounts into.\n\n" +
			"Enabling the policy type is the step worth understanding. A new organization has\n" +
			"the service control policy type DISABLED on its root, and in that state creating a\n" +
			"policy succeeds, attaching it succeeds, and nothing is enforced. An organization\n" +
			"prepared by hand is often in exactly that state, which is why this command is\n" +
			"worth running against an organization automat did not create.\n\n" +
			"Every step is create-or-verify, so running this twice writes nothing the second\n" +
			"time. --dry-run prints the plan and stops. Creating an organization makes this\n" +
			"account a management account permanently and needs --yes; the rest does not.\n\n" +
			"Run it from the account that will own the organization. A member account cannot\n" +
			"do any of this and should run `automat setup --request` instead.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			readAPI, err := g.orgClient(ctx, region, profile)
			if err != nil {
				return err
			}
			initAPI, err := g.orgInitClient(ctx, region, profile)
			if err != nil {
				return err
			}
			vendAPI, err := g.orgVendClient(ctx, region, profile)
			if err != nil {
				return err
			}

			// The caller's identity, first. Everything below either needs it (the
			// MEMBER refusal compares it against the management account) or is
			// better for having it (rule 7's remediation text names the principal
			// that was denied, and "the calling identity" is a worse sentence to
			// forward to a security team than an ARN).
			ident, err := stsAPI.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return awsapi.Denied(err, "sts:GetCallerIdentity", "", "",
					"run `automat login`, or set AWS_PROFILE to a profile with valid credentials; "+
						"automat will not create an organization without knowing which account it "+
						"would be creating one for")
			}
			caller := &callerIdentity{
				AccountID: aws.ToString(ident.Account),
				ARN:       aws.ToString(ident.Arn),
			}

			out := cmd.OutOrStdout()

			// Plan first, always (CLAUDE.md rule 5), and the plan is a real run of
			// the same code in ModePlan rather than a separate description of it.
			// The reads happen twice as a result, which is the price of a plan that
			// cannot drift from the apply that follows it.
			plan := newInitEnsurer(initAPI, vendAPI, org.ModePlan, caller.ARN)
			if err := runInitSteps(ctx, plan, readAPI, caller, ouName); err != nil {
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

			// The one step in this command that re-running cannot undo. Everything
			// else here is create-or-verify against a resource automat can look at
			// again; an account that has become a management account cannot stop
			// being one without removing every member first, and automat has no
			// interface method that could (see internal/awsapi/api.go).
			if plansOrgCreation(plan.Actions()) && !yes {
				return fmt.Errorf("this would create a new organization, making account %s its "+
					"management account permanently — AWS has no call that undoes it, and automat holds "+
					"no interface that could.\n"+
					"The plan above is what would happen. Re-run with --yes to apply it.\n"+
					"If you expected to join an existing organization instead, you are in the wrong "+
					"account: whoever runs that organization invites this account into it, and then "+
					"`automat setup --request` is the command you want", caller.AccountID)
			}

			apply := newInitEnsurer(initAPI, vendAPI, org.ModeApply, caller.ARN)
			if err := runInitSteps(ctx, apply, readAPI, caller, ouName); err != nil {
				// Actions taken before the failure are printed anyway. A partial
				// init leaves an organization that exists with its policy type off,
				// or on with no OU, and an operator who is told only the error has
				// to rediscover which of those they are in before re-running.
				if rerr := renderActions(cmd.ErrOrStderr(), "Applied before the failure:",
					apply.Actions()); rerr != nil {
					return fmt.Errorf("%w (and the partial-progress report could not be "+
						"written: %v)", err, rerr)
				}
				return err
			}
			if err := renderActions(out, "Applied:", apply.Actions()); err != nil {
				return err
			}
			if !apply.Changed() {
				// Said explicitly, because this is the successful second run and it
				// should not read as a command that failed to do anything.
				if _, werr := fmt.Fprintln(out,
					"\nNothing needed changing; the organization was already prepared."); werr != nil {
					return fmt.Errorf("write the result: %w", werr)
				}
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&ouName, "ou-name", defaultResearchOU,
		"name for the OU below the root to vend accounts into")
	f.BoolVar(&dryRun, "dry-run", false, "print the plan and stop")
	f.BoolVar(&yes, "yes", false,
		"apply a plan that creates a new organization (permanent; not needed otherwise)")

	return cmd
}

// callerIdentity is who automat is speaking as.
type callerIdentity struct {
	AccountID string
	ARN       string
}

// newInitEnsurer builds the Ensurer for one pass.
//
// Credential is Native: `init` runs as the caller's own identity in the account
// that owns the organization, never through the broker. That is not a detail —
// it selects which remediation sentence a denial produces, and the two go to
// different people (see org.Credential).
func newInitEnsurer(initAPI awsapi.OrgInitAPI, vendAPI awsapi.OrgVendAPI,
	mode org.Mode, principal string) *org.Ensurer {
	return &org.Ensurer{
		Init:       initAPI,
		Vend:       vendAPI,
		Mode:       mode,
		Credential: org.Native,
		Principal:  principal,
	}
}

// runInitSteps is the whole command, in the order DESIGN §4 and §13 give it, run
// identically in plan and apply mode.
//
// The ordering is load-bearing at one place: the policy type is enabled BEFORE the
// OU is created, so that an init which fails halfway leaves an organization whose
// root enforces policy and has no OU — rather than one with an OU that policies can
// be attached to and silently not enforced. Of the two partial states, the second
// is the one that looks finished.
func runInitSteps(ctx context.Context, e *org.Ensurer, read awsapi.OrgAPI,
	caller *callerIdentity, ouName string) error {
	info, _, err := e.EnsureOrganization(ctx, read)
	if err != nil {
		return err
	}

	// The MEMBER refusal. Placed after EnsureOrganization deliberately: that call
	// reads before it writes and only creates when the account is in no
	// organization at all, so a member account reaches here having had nothing
	// mutated. Doing it the other way round would mean a second
	// DescribeOrganization for a guarantee already in hand.
	if info.MasterAccountID != "" && info.MasterAccountID != caller.AccountID {
		return fmt.Errorf("account %s is a member of organization %s, which is managed by account %s — "+
			"`automat init` cannot run from a member account.\n"+
			"None of what it does is available to you here: creating an organization, enabling a "+
			"policy type on a root you do not own, and creating an OU below that root are all "+
			"management-account operations, and AWS does not delegate them.\n"+
			"What you want is `automat setup --request`, which generates the bundle to send to "+
			"whoever runs %s. `automat preflight` reports the same classification with the full "+
			"capability list",
			caller.AccountID, info.ID, info.MasterAccountID, info.ID)
	}

	// A plan for an organization that does not exist yet cannot read anything
	// below it. Report that, per level, rather than guessing — the same honesty
	// EnsureOUPath's plan applies, and for the same reason: a plan that invented a
	// root id is a plan the operator would compare against reality and disbelieve.
	if info.ID == "" {
		e.RecordUnknown("service control policy type",
			"cannot be checked: the organization does not exist yet, so it has no root to read — "+
				"a new organization always has this type DISABLED, so it would be enabled")
		e.RecordUnknown("organizational unit "+ouName,
			"cannot be checked: the organization does not exist yet, so its root cannot be listed — "+
				"it would be created below the root")
		return nil
	}

	rootID, err := org.RootID(ctx, read)
	if err != nil {
		return awsapi.Denied(err, "organizations:ListRoots", "organization "+info.ID,
			caller.ARN, "grant organizations:ListRoots to "+caller.ARN+"; automat cannot enable a "+
				"policy type or create an OU without knowing the root's id, and it will not guess one")
	}

	// The read client is passed, so a root that already has the type on is left
	// alone rather than written to and forgiven: without it the second run of this
	// command issues an EnablePolicyType it knows will be refused, and "run twice
	// writes nothing" would be false at the API even though the organization is
	// unchanged.
	if _, err := e.EnsureSCPEnabled(ctx, rootID, read); err != nil {
		return err
	}
	if _, _, err := e.EnsureOU(ctx, rootID, ouName); err != nil {
		return err
	}
	return nil
}

// plansOrgCreation reports whether the plan includes bringing an organization into
// existence, which is the step --yes gates.
//
// Keyed to the Kind and Verb rather than to a boolean threaded out of
// runInitSteps, so the gate reads the same list the operator was just shown. A
// gate that consulted a different source than the printed plan could refuse for a
// reason the plan does not mention, or wave through something it does.
func plansOrgCreation(actions []org.Action) bool {
	for _, a := range actions {
		if a.Kind == "organization" && a.Verb == org.VerbCreate {
			return true
		}
	}
	return false
}
