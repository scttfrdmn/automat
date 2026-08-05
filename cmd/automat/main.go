// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Command automat vends compliant AWS sub-accounts.
//
// This is the Phase 0 stub: the root command and version reporting only. The
// subcommands of DESIGN §13 land in later phases, each in its own file here.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/version"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		// cobra has already printed the error; exit non-zero for cron and CI.
		// DESIGN §12 wants a richer exit-code taxonomy; it arrives with `verify`.
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "automat",
		Short: "Vend compliant AWS accounts from an org you already control",
		Long: "automat vends AWS member accounts with compliance controls attached at birth,\n" +
			"driven by a compiled control artifact rather than a landing-zone deployment.\n\n" +
			"Phase 0 build: the control artifact schema and vendored catalogs exist; the\n" +
			"vend pipeline does not yet.",
		SilenceUsage:  true,
		SilenceErrors: false,
		// Print help rather than an opaque error when invoked bare.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	cmd.Version = version.Version
	cmd.AddCommand(newVersionCmd())
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
