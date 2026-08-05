// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/config"
	"github.com/scttfrdmn/automat/internal/preflight"
)

// Exit codes. DESIGN §12 wants a richer taxonomy for `verify`; preflight needs
// only enough for a cron job to distinguish "not ready" from "could not tell".
const (
	// exitPreflightNotReady: at least one check failed. Something is missing and
	// the report says which grant would fix it.
	exitPreflightNotReady = 2
	// exitPreflightUnknown: nothing failed, but a check could not be completed,
	// so "ready" would be a stronger claim than the evidence supports.
	exitPreflightUnknown = 3
)

// newPreflightCmd builds `automat preflight` (DESIGN §4, §13).
//
// The command's whole job is to report, so it prints the report and chooses an
// exit code from it. Notably it does not fail on a failed check: "you are in
// MEMBER state and the vendor role is not there yet" is preflight working, and an
// operator running it to find out what to ask for should not be handed an error
// instead of an answer.
func newPreflightCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Report where automat stands and what it can and cannot do here",
		Long: "Classifies the caller's position in an organization — standalone, management, or\n" +
			"member — and reports every capability automat needs, with the exact grant that\n" +
			"would fix anything missing.\n\n" +
			"Read the certainty column. A permission check is evidence, not authorization:\n" +
			"iam:SimulatePrincipalPolicy does not evaluate service control policies, so from a\n" +
			"member account a call reported as allowed can still be denied by an SCP attached\n" +
			"above you. A check reliably tells you a grant is missing; it cannot promise a\n" +
			"call will succeed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgCtx, err := g.orgContext()
			if err != nil {
				return err
			}
			runner, err := g.preflightRunner(cmd, orgCtx)
			if err != nil {
				return err
			}
			rep, err := runner.Run(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), rep.String())

			// A report is a successful run whatever it says, so the exit code
			// carries the answer rather than an error. Codes are for cron and CI;
			// the human reads the report above.
			//
			// A failure outranks an undetermined check: if something is definitely
			// missing, that is the actionable answer even when something else could
			// not be read. There is deliberately no code for an unknown STATE --
			// DESIGN §4 has three states and no fourth, because every downstream
			// decision branches on it and a "probably MANAGEMENT" would be acted on
			// as MANAGEMENT. A state that cannot be determined is an error from
			// Run, not a report.
			switch {
			case len(rep.Failures()) > 0:
				return &exitError{code: exitPreflightNotReady}
			case len(rep.Undetermined()) > 0:
				return &exitError{code: exitPreflightUnknown}
			}
			return nil
		},
	}
	return cmd
}

// preflightRunner assembles the runner from config and clients.
//
// The ExternalId is resolved here and handed over as a live value that the Report
// never records (DESIGN §13). Resolution failure is not fatal: preflight's job
// includes telling an operator that their ExternalId reference is broken, and it
// can still classify the org and check everything else without it.
func (g *globals) preflightRunner(cmd *cobra.Command, orgCtx config.Context) (*preflight.Runner, error) {
	ctx := cmd.Context()
	region, profile := orgCtx.Region, orgCtx.Profile

	stsAPI, err := g.stsClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	orgAPI, err := g.orgClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	iamAPI, err := g.iamClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	quotaAPI, err := g.quotaClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}

	var externalID string
	if orgCtx.ExternalIDRef != "" {
		externalID, err = config.ResolveExternalID(orgCtx.ExternalIDRef)
		if err != nil {
			// Reported, not returned: an unresolvable ExternalId means the vendor
			// role check will fail, and preflight exists to say so with the
			// reason attached.
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not resolve the ExternalId: %v\n"+
				"The vendor role check below will fail for that reason rather than a "+
				"permission one.\n\n", err)
		}
	}

	return &preflight.Runner{
		STS:           stsAPI,
		Org:           orgAPI,
		IAM:           iamAPI,
		Quota:         quotaAPI,
		TargetOU:      orgCtx.OU,
		VendorRoleARN: orgCtx.VendorRoleARN,
		ExternalID:    externalID,
		ExpectOrg:     orgCtx.Org,
	}, nil
}

// exitError carries an exit code without a message, for the case where the
// command has already printed everything the operator needs.
type exitError struct {
	code int
}

func (e *exitError) Error() string { return "" }

// ExitCode is read by main.
func (e *exitError) ExitCode() int { return e.code }
