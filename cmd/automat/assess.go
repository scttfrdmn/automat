// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/catalogs"
	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/assess"
	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/evidence"
	"github.com/scttfrdmn/automat/internal/safeio"
	"github.com/scttfrdmn/automat/internal/version"
)

// reAssessAccountID matches the same class verify.go's own account-id
// pattern does: a bare 12-digit AWS account id.
var reAssessAccountID = regexp.MustCompile(`^[0-9]{12}$`)

// assessResultFile and assessSummaryFile are the two files a run writes into
// --out: the canonical result document every human-facing render draws from,
// and the CMMC L1 summary rendered from it (docs/assessment-reporting.md,
// "Outputs" — human-facing forms are never authored independently).
const (
	assessResultFile  = "assessment-result.json"
	assessSummaryFile = "l1-summary.txt"
)

// newAssessCmd builds `automat assess` — docs/assessment-reporting.md's
// Stage 3: the CMMC L1 MET/NOT MET summary. `--profile` accepts only
// cmmc-l1: the other two shipped obligation profiles (dfars-7012,
// nih-cadr-dua) have no Stage 3 renderer, since Stages 1 and 2 (the
// 800-171A worksheet, DFARS scoring) are not built in this pass.
//
// Read-only against AWS beyond one sts:GetCallerIdentity call, for evidence
// attribution — there is no --yes, and assess writes an evidence record
// rather than any AWS resource.
//
// Today's honest limit, stated here because it shapes the whole command:
// cmmc-l1's catalog carries no SCP fragments and no AWS Config read path
// exists in this build, so assess contributes zero machine evidence for any
// of the fifteen L1 practices. Every objective's evidence class is
// `operator`, and the rendered summary says so (internal/assess's own
// package doc).
func newAssessCmd(g *globals) *cobra.Command {
	var (
		accountID   string
		profileID   string
		scopeStmt   string
		determPath  string
		outDir      string
		evidenceDir string
	)

	cmd := &cobra.Command{
		Use:   "assess",
		Short: "Render a CMMC L1 MET/NOT MET summary for an account",
		Long: "Computes a canonical assessment-result document and the human-facing CMMC\n" +
			"Level 1 MET/NOT MET summary rendered from it, against the fifteen L1\n" +
			"practices in catalogs/cmmc-l1.json.\n\n" +
			"Every rendered page is marked DRAFT — NOT A SUBMISSION and carries the\n" +
			"policy caveat: automat generates the packet an affirming official reads,\n" +
			"never the thing they sign.\n\n" +
			"This build contributes NO machine evidence for any of the fifteen L1\n" +
			"practices: catalogs/cmmc-l1.json carries no SCP fragments, and no AWS\n" +
			"Config read path exists yet. Every objective's evidence class is\n" +
			"`operator`, and with no --determinations file, every practice renders NOT\n" +
			"MET — CMMC Level 1 permits no partial credit and no plan of action, so\n" +
			"silence is not a pending state, it is a fail with a work list.\n\n" +
			"--profile accepts only cmmc-l1 today; the other two shipped obligation\n" +
			"profiles (dfars-7012, nih-cadr-dua) need the 800-171A worksheet and DFARS\n" +
			"scoring this build does not render.\n\n" +
			"Read-only against AWS beyond one sts:GetCallerIdentity call, for evidence\n" +
			"attribution. No --yes: this command writes no AWS resource.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if accountID == "" {
				return fmt.Errorf("no account was given: pass --account <id>")
			}
			if !reAssessAccountID.MatchString(accountID) {
				return fmt.Errorf("--account %q is not a 12-digit AWS account id", accountID)
			}
			if profileID != "cmmc-l1" {
				return fmt.Errorf("--profile %q is not supported: this build renders only cmmc-l1's "+
					"Stage 3 summary (docs/assessment-reporting.md); dfars-7012 and nih-cadr-dua need "+
					"the 800-171A worksheet and DFARS scoring, neither built yet", profileID)
			}
			if scopeStmt == "" {
				return fmt.Errorf("no scope statement was given: pass --scope-statement \"<text>\". " +
					"Whether this AWS account equals the system boundary the assessment concerns is " +
					"your assertion, not automat's inference (docs/assessment-reporting.md, \"Scope is " +
					"an input, not an inference\"), and it is recorded on every rendered page")
			}
			if outDir == "" {
				return fmt.Errorf("no output directory was given: pass --out <dir>")
			}

			profile, err := assess.LoadProfileFS(catalogs.FS(), "obligations/cmmc-l1.json", assess.LoadOptions{})
			if err != nil {
				return fmt.Errorf("load the cmmc-l1 obligation profile: %w", err)
			}
			art, err := artifact.LoadFS(catalogs.FS(), "cmmc-l1.json", artifact.LoadOptions{})
			if err != nil {
				return fmt.Errorf("load the cmmc-l1 control artifact: %w", err)
			}

			var det *assess.Determinations
			if determPath != "" {
				det, err = assess.LoadDeterminations(determPath, assess.LoadOptions{})
				if err != nil {
					return err
				}
				if verr := det.ValidateAgainst(profile); verr != nil {
					return verr
				}
			}

			orgCtx, err := g.orgContext()
			if err != nil {
				return err
			}
			stsAPI, err := g.stsClient(ctx, orgCtx.Region, orgCtx.Profile)
			if err != nil {
				return err
			}
			ident, err := stsAPI.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return awsapi.Denied(err, "sts:GetCallerIdentity", "", "",
					"run `automat login`, or set AWS_PROFILE to a profile with valid credentials; "+
						"the evidence record assess writes names the identity that ran it")
			}
			callerARN := aws.ToString(ident.Arn)

			now := time.Now()
			account := assess.ResultAccount{ID: accountID, ScopeStatement: scopeStmt}
			result, err := assess.SummarizeL1(profile, art, det, account, version.Version,
				now.UTC().Format(time.RFC3339))
			if err != nil {
				return err
			}

			resultJSON, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("encode the assessment result: %w", err)
			}
			summaryText, err := assess.RenderL1Summary(result)
			if err != nil {
				return err
			}

			root, err := safeio.EnsureDir(outDir, 0o700)
			if err != nil {
				return fmt.Errorf("prepare --out %s: %w", outDir, err)
			}
			defer func() { _ = root.Close() }()
			if err := writeAssessOutputFile(root, assessResultFile, outDir, resultJSON); err != nil {
				return err
			}
			if err := writeAssessOutputFile(root, assessSummaryFile, outDir, summaryText); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if _, err := fmt.Fprintf(out, "%s\n", outDir); err != nil {
				return err
			}
			if _, err := out.Write(summaryText); err != nil {
				return err
			}

			signer, serr := evidenceSigner(ctx, g, orgCtx.Region, orgCtx.Profile, orgCtx)
			if serr != nil {
				return serr
			}
			manifestPath, writtenManifest, werr := writeAssessEvidence(profile, det, result, accountID, callerARN,
				evidenceDir, now, signer)
			if werr != nil {
				return werr
			}
			if _, perr := fmt.Fprintf(out, "\nEvidence: %s\n", manifestPath); perr != nil {
				return fmt.Errorf("write the result: %w", perr)
			}

			// Additive and best-effort, after the local write above has already
			// succeeded unconditionally (DESIGN §11's "local copy always"
			// priority). assess takes no --environment-profile (AUDIT-5, this
			// command's own doc comment) — the account is named directly — so
			// there is no envprofile.OutputTargets here to read a mirror bucket
			// out of, and evidenceMirror(nil) always resolves to zero configured
			// mirrors; this call site keeps assess's evidence path wired the
			// same shape vend's and verify's do.
			if writtenManifest != nil {
				mirrors, merr := evidenceMirror(ctx, g, orgCtx.Region, orgCtx.Profile, nil)
				if merr != nil {
					if _, perr := fmt.Fprintf(cmd.ErrOrStderr(),
						"warning: could not build the evidence mirror: %v\n", merr); perr != nil {
						return fmt.Errorf("write the warning: %w", perr)
					}
				} else {
					for _, warn := range uploadToMirrors(ctx, mirrors, writtenManifest) {
						if _, perr := fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warn); perr != nil {
							return fmt.Errorf("write the warning: %w", perr)
						}
					}
				}
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&accountID, "account", "", "the account this assessment is about (required)")
	f.StringVar(&profileID, "profile", "", "the obligation profile to assess under (required; only cmmc-l1 today)")
	f.StringVar(&scopeStmt, "scope-statement", "",
		"your own statement of what this account covers (required) — never automat's inference")
	f.StringVar(&determPath, "determinations", "",
		"path to an operator-determinations file; omit to render every practice as NOT MET")
	f.StringVar(&outDir, "out", "", "directory to write the assessment result and summary into (required)")
	f.StringVar(&evidenceDir, "evidence-dir", envprofile.DefaultEvidenceDir,
		"local directory the account's evidence manifest lives in, relative to the working "+
			"directory — must match the value `vend`/`verify` used (baseline.evidence.local_dir in "+
			"the environment profile), or this command appends to a second, disconnected manifest "+
			"instead of the account's real chain. assess takes no --environment-profile (list's own "+
			"reasoning, docs/cli-surface.md D5): the account was named directly, not resolved from a "+
			"profile, so there is nothing here to read local_dir out of")
	return cmd
}

// writeAssessOutputFile writes one file into the already-rooted --out
// directory, through safeio.CreateChecked so a symlink standing where the
// file belongs is refused rather than followed (the same discipline
// internal/bundle's ensureFile applies to every file it writes) and so an
// existing file from a prior run is overwritten in place rather than left to
// disagree with a fresh render (CLAUDE.md rule 4: ensure semantics).
func writeAssessOutputFile(root *os.Root, name, shownDir string, data []byte) error {
	shown := filepath.Join(shownDir, name)
	f, err := safeio.CreateChecked(root, name, shown, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("write %s: %w", shown, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", shown, err)
	}
	return nil
}

// writeAssessEvidence appends an OpAssess record to the account's evidence
// manifest, following the same OpenDir/LoadOrNew/Append/Write sequence
// writeVerifyEvidence (verify.go) uses.
//
// evidenceDir defaults to envprofile.DefaultEvidenceDir but is a flag
// (--evidence-dir), not a constant: `vend` and `verify` both resolve the
// directory they write into from the environment profile's own
// baseline.evidence.local_dir, and a profile that customizes it vends and
// verifies into a directory other than "evidence". assess has no
// --environment-profile to read that override from — the account is named
// directly (AUDIT-5) — so without this flag every assess run would file its
// OpAssess record into the default directory regardless of where the
// account's real chain lives, starting a second, disconnected manifest for
// the same account rather than appending to the one `vend`/`verify` built.
//
// Always evidence.OutcomeSuccess: rendering a summary — even one where every
// practice is NOT MET — is the operation succeeding at telling the truth,
// not the operation failing. Contrast writeVerifyEvidence, where a drifted
// account IS the check failing; assess makes no claim of its own to fail.
func writeAssessEvidence(profile *assess.Profile, det *assess.Determinations, result *assess.Result,
	accountID, callerARN, evidenceDir string, now time.Time, signer evidence.Signer) (string, *evidence.Manifest, error) {
	if evidenceDir == "" {
		evidenceDir = envprofile.DefaultEvidenceDir
	}
	dir, err := evidence.OpenDir(".", evidenceDir)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = dir.Close() }()
	path := dir.Path(accountID)

	m, err := dir.LoadOrNew(accountID, accountID, "", now.UTC().Format(time.RFC3339), nil)
	if err != nil {
		return "", nil, fmt.Errorf("cannot open the evidence manifest for account %s: %w\n"+
			"automat refuses to continue a chain it cannot read, because a manifest rewritten from "+
			"scratch over a damaged one is the one failure the hash chain exists to make visible",
			accountID, err)
	}

	rec := evidence.Record{
		Timestamp:   now.UTC().Format(time.RFC3339),
		Operation:   evidence.OpAssess,
		Outcome:     evidence.OutcomeSuccess,
		Operator:    evidence.Operator{ARN: callerARN},
		Target:      &evidence.Target{AccountID: accountID},
		Artifact:    &evidence.DocRef{ID: result.Artifact.ID, ContentSHA256: result.Artifact.ContentSHA256},
		ToolVersion: version.Version,
	}
	if result.Determinations != nil {
		// schema/CHANGELOG.md named this reference while `operation` gained
		// `assess`, ahead of internal/assess existing to produce the hash:
		// "a reference to the operator-determinations file it read,
		// following evidence.DocRef's existing id + content_sha256 shape."
		// Absent, matching Result.Determinations itself, when assess ran
		// with no --determinations file.
		rec.Determinations = &evidence.DocRef{
			ID:            result.Determinations.ID,
			ContentSHA256: result.Determinations.ContentSHA256,
		}
	}
	if _, err := m.Append(rec, signer); err != nil {
		return "", nil, fmt.Errorf("cannot append the assess record for account %s: %w", accountID, err)
	}
	if err := dir.Write(m, accountID); err != nil {
		return "", nil, err
	}
	return path, m, nil
}
