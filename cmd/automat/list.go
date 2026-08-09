// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/config"
	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/evidence"
	"github.com/scttfrdmn/automat/internal/org"
)

// newListCmd builds `automat list` — DESIGN §13: "vended accounts (by tags),
// parked accounts, OUs".
//
// Two independent data sources, read separately and printed together:
//
//   - The OU tree and every account in it, via org.WalkTree over the same
//     awsapi.OrgVendAPI vend reads and writes through (native or brokered,
//     DESIGN §5) — a read, so it travels the vend client for consistency
//     with what vend itself sees, not because this call could mutate.
//   - Parked accounts, from the local evidence manifests under
//     --evidence-dir. Purely local file reading, no AWS call.
//
// "By tags" (DESIGN §13's own wording) is not implemented for the live tree:
// awsapi.OrgVendAPI has no ListTagsForResource for account resources
// (docs/open-questions.md Q19 — the vendor role bundle does not grant it, for
// reasons recorded there), so an account's automat:vended-by, automat:ou, and
// other tags cannot be read back through this client. Every account in the
// walked subtree is listed regardless of tag, and each parked entry is
// cross-referenced against the walked tree by account id — the local
// manifest is the only place a tag-like distinction ("automat vended this")
// is actually available today.
func newListCmd(g *globals) *cobra.Command {
	var (
		evidenceDir string
		ouID        string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "Inventory the organization: OUs, accounts, and parked accounts",
		Long: "Lists the organizational units and accounts under the configured OU (or the\n" +
			"root, if none is configured), and separately lists every account a local\n" +
			"evidence manifest records as parked — left mid-vend, recoverable with\n" +
			"`automat vend --resume <request-id>`.\n\n" +
			"Read-only: this command holds no write grant on anything it inspects.\n\n" +
			"Tag-based filtering (DESIGN §13) is not available: the vendor role bundle\n" +
			"grants no organizations:ListTagsForResource on account resources\n" +
			"(docs/open-questions.md Q19), so an account's automat:* tags cannot be read\n" +
			"back through this client. Every account under the walked root is listed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgCtx, err := g.orgContext()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			if ouID != "" {
				if !reVendOUID.MatchString(ouID) {
					return fmt.Errorf("--ou %q is not an OU or root id: OU ids look like "+
						"ou-abc1-12345678 and roots like r-abc1", ouID)
				}
				orgCtx.OU = ouID
			}
			tree, err := listTree(ctx, g, orgCtx)
			if err != nil {
				return err
			}
			parked, err := listParked(evidenceDir)
			if err != nil {
				return err
			}

			return renderListReport(out, orgCtx, tree, parked)
		},
	}

	cmd.Flags().StringVar(&evidenceDir, "evidence-dir", envprofile.DefaultEvidenceDir,
		"local directory to scan for evidence manifests, relative to the working directory")
	cmd.Flags().StringVar(&ouID, "ou", "",
		"root OU or root id to inventory, overriding the config file's `ou`")
	return cmd
}

// listTree resolves the caller's identity and the org client the same way
// `vend` does (vendOrgClient, cmd/automat/vend.go), then walks the tree
// rooted at the configured OU or, absent one, the organization root.
func listTree(ctx context.Context, g *globals, orgCtx config.Context) (*org.Tree, error) {
	region, profile := orgCtx.Region, orgCtx.Profile
	stsAPI, err := g.stsClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	readAPI, err := g.orgClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}

	ident, err := stsAPI.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, awsapi.Denied(err, "sts:GetCallerIdentity", "", "",
			"run `automat login`, or set AWS_PROFILE to a profile with valid credentials")
	}
	caller := &callerIdentity{AccountID: aws.ToString(ident.Account), ARN: aws.ToString(ident.Arn)}

	vendAPI, credential, err := vendOrgClient(ctx, g, readAPI, caller, region, profile, orgCtx)
	if err != nil {
		return nil, err
	}

	root := orgCtx.OU
	if root == "" {
		roots, rerr := readAPI.ListRoots(ctx, &organizations.ListRootsInput{})
		if rerr != nil {
			return nil, awsapi.Denied(rerr, "organizations:ListRoots", "", caller.ARN,
				"grant organizations:ListRoots to "+caller.ARN+
					"; automat needs it to find the organization root when no `ou` is configured")
		}
		if len(roots.Roots) == 0 {
			return nil, fmt.Errorf("no `ou` is configured and the organization reports no root; " +
				"pass --ou or set `ou` in the config file")
		}
		root = aws.ToString(roots.Roots[0].Id)
	}

	e := &org.Ensurer{Vend: vendAPI, Mode: org.ModePlan, Credential: credential, Principal: caller.ARN}
	return e.WalkTree(ctx, root)
}

// listParked scans dir for evidence manifests and returns every parked
// account it names, most-recently-parked first within each manifest.
//
// Local file reading only; a directory that does not exist yet (no vend has
// run) is not an error — it is the state before the first vend, and `list`
// reports zero parked accounts rather than refusing.
func listParked(dir string) ([]parkedAccount, error) {
	d, err := evidence.OpenDir(".", dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()

	ids, err := d.ListAccountIDs()
	if err != nil {
		return nil, err
	}

	var out []parkedAccount
	for _, id := range ids {
		m, lerr := evidence.Load(d.Path(id), nil)
		if lerr != nil {
			return nil, fmt.Errorf("reading the evidence manifest for account %s: %w", id, lerr)
		}
		for _, rec := range m.Parked() {
			out = append(out, parkedAccount{AccountID: id, Record: rec})
		}
	}
	return out, nil
}

type parkedAccount struct {
	AccountID string
	Record    evidence.Record
}

func renderListReport(w io.Writer, orgCtx config.Context, tree *org.Tree, parked []parkedAccount) error {
	p := func(format string, args ...any) error {
		_, err := fmt.Fprintf(w, format, args...)
		return err
	}

	if err := p("Organizational units:\n"); err != nil {
		return err
	}
	sort.Slice(tree.OUs, func(i, j int) bool { return tree.OUs[i].ID < tree.OUs[j].ID })
	if len(tree.OUs) == 0 {
		if err := p("  none\n"); err != nil {
			return err
		}
	}
	for _, ou := range tree.OUs {
		if err := p("  %s %q (under %s)\n", ou.ID, ou.Name, ou.ParentID); err != nil {
			return err
		}
	}

	if err := p("\nAccounts:\n"); err != nil {
		return err
	}
	sort.Slice(tree.Accounts, func(i, j int) bool { return tree.Accounts[i].ID < tree.Accounts[j].ID })
	if len(tree.Accounts) == 0 {
		if err := p("  none\n"); err != nil {
			return err
		}
	}
	for _, a := range tree.Accounts {
		if err := p("  %s %q <%s> (under %s)\n", a.ID, a.Name, a.Email, a.ParentOUID); err != nil {
			return err
		}
	}

	if err := p("\nParked accounts (from local evidence manifests):\n"); err != nil {
		return err
	}
	if len(parked) == 0 {
		if err := p("  none\n"); err != nil {
			return err
		}
	}
	for _, pa := range parked {
		detail := "no error recorded"
		if pa.Record.Err != nil {
			detail = pa.Record.Err.Message
		}
		if err := p("  %s: %s at %s — %s\n", pa.AccountID, pa.Record.Operation, pa.Record.Timestamp, detail); err != nil {
			return err
		}
	}

	return nil
}
