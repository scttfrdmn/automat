// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Command automat vends compliant AWS sub-accounts.
//
// Each subcommand of DESIGN §13 lives in its own file here. Phase 1 provided
// login, preflight, and setup --request; Phase 2 adds init and vend; the rest
// arrive with their phases.
//
// `vend` performs DESIGN §7 steps 1 to 4 and step 6 — resolve, create, place,
// attach the service control policies, and write the evidence manifest. It does NOT
// perform step 5, the in-child baseline work, and it reports that in every plan and
// in every manifest rather than omitting it. See newVendCmd.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/version"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		// A command that has already printed everything the operator needs
		// carries its exit code rather than a message: `preflight` reporting
		// "not ready" is a successful run with a non-zero answer, and printing
		// an error after the report would suggest the tool failed.
		var ex *exitError
		if errors.As(err, &ex) {
			os.Exit(ex.ExitCode())
		}
		// cobra has already printed the error; exit non-zero for cron and CI.
		// DESIGN §12 wants a richer exit-code taxonomy; it arrives with `verify`.
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	return newRootCmdWith(&globals{})
}

// newRootCmdWith builds the root command around a caller-supplied globals.
//
// The seam exists for the same reason globals' client constructors are fields: a test
// that cannot substitute fakes ends up either reaching AWS or not testing the command
// at all, and CLAUDE.md rule 1 forbids the first. Registering the persistent flags
// against a second globals from a test is not an alternative — pflag panics on a
// redefined flag, which is how this function came to exist.
func newRootCmdWith(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "automat",
		Short: "Vend compliant AWS accounts from an org you already control",
		Long: "automat vends AWS member accounts with compliance controls attached at birth,\n" +
			"driven by a compiled control artifact rather than a landing-zone deployment.\n\n" +
			"Start with `automat preflight`: it reports where you stand in an organization and\n" +
			"what automat can and cannot do from there. If you are in a member account, it\n" +
			"will point you at `automat setup --request`. If you own the organization,\n" +
			"`automat init` prepares it. Then `automat vend` creates accounts.\n\n" +
			"Phase 2 build: preflight, onboarding, `init`, and `vend` work. `vend` attaches\n" +
			"preventive controls (service control policies) but performs no in-child baseline\n" +
			"work — no Config recorder, no conformance pack, no in-account roles (DESIGN §7\n" +
			"step 5). Every plan and every evidence manifest says so.",
		SilenceUsage:  true,
		SilenceErrors: false,
		// Print help rather than an opaque error when invoked bare.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	cmd.Version = version.Version

	cmd.PersistentFlags().StringVar(&g.configPath, "config", g.configPath,
		"config file (default ~/.config/automat/config.toml)")
	cmd.PersistentFlags().StringVar(&g.contextName, "context", g.contextName,
		"named context in the config file to use")

	cmd.AddCommand(
		newVersionCmd(),
		newLoginCmd(g),
		newPreflightCmd(g),
		newSetupCmd(g),
		newInitCmd(g),
		newVendCmd(g),
		newVerifyCmd(g),
		newListCmd(g),
		newAssessCmd(g),
	)
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the tool version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "automat %s\n", version.Version)
			return err
		},
	}
}
