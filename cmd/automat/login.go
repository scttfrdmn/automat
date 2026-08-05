// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/login"
)

// newLoginCmd builds `automat login` (DESIGN §13).
//
// The help text is explicit that this command is a convenience over the AWS
// credential chain rather than a way in. That is not modesty: an operator who
// believes automat needs its own credentials is one who will look for somewhere to
// put them, and DESIGN §13's "never store secrets" only holds if the tool never
// implies otherwise.
func newLoginCmd(g *globals) *cobra.Command {
	var startURL, ssoRegion string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in through AWS SSO and cache the token for every AWS tool",
		Long: "Runs the AWS SSO device authorization flow: automat prints a URL and a code, you\n" +
			"confirm them in a browser, and the resulting token is cached in ~/.aws/sso/cache —\n" +
			"the same place the AWS CLI and the AWS SDKs read it from. `aws sso logout` clears\n" +
			"it.\n\n" +
			"You do not need this command if credentials already reach automat some other way.\n" +
			"A shared-config profile, an instance or task role, environment variables, or an\n" +
			"existing SSO session all work, because every automat command reads the standard\n" +
			"AWS credential chain. automat keeps no credential store of its own.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgCtx, err := g.orgContext()
			if err != nil {
				return err
			}
			// A flag beats the file: it is what the operator typed just now.
			if startURL == "" {
				startURL = orgCtx.SSOStartURL
			}
			if ssoRegion == "" {
				ssoRegion = orgCtx.SSORegion
			}
			if startURL == "" {
				return fmt.Errorf("no SSO start URL. Pass --start-url, or set sso_start_url in a "+
					"context in %s. It looks like https://example.awsapps.com/start; whoever "+
					"administers your identity provider knows the exact value", g.configPath)
			}
			if ssoRegion == "" {
				return fmt.Errorf("no SSO region. Pass --sso-region, or set sso_region in a "+
					"context in %s. This is the region your identity store lives in, which is "+
					"not necessarily the region you vend accounts into", g.configPath)
			}

			api, err := g.ssooidcClient(cmd.Context(), ssoRegion)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			res, err := login.Login(cmd.Context(), api, login.Options{
				StartURL: startURL,
				Region:   ssoRegion,
				// Printed as it arrives rather than returned at the end: the
				// operator is the slow part of this flow, and a terminal that has
				// told them nothing looks like a hang.
				Prompt: func(p login.Prompt) { fmt.Fprint(out, p.String()) },
			})
			if err != nil {
				return err
			}
			fmt.Fprintln(out)
			_, err = res.WriteTo(out)
			return err
		},
	}
	cmd.Flags().StringVar(&startURL, "start-url", "",
		"SSO start URL, e.g. https://example.awsapps.com/start")
	cmd.Flags().StringVar(&ssoRegion, "sso-region", "",
		"region the identity store lives in (not necessarily where accounts are vended)")
	return cmd
}
